//! Opening tunnels with the real library: [`OpenConnect`] as a
//! [`TunnelEngine`].
//!
//! Each tunnel gets a thread of its own, which makes a fresh handle, opens
//! the tunnel on it and owns it until the tunnel is closed: a handle is used
//! only on the thread that made it. The rules this follows are in the crate
//! documentation. There is no `unsafe` here: every call into the library
//! goes through the `ffi` module.
//!
//! The tunnel device is created on Windows only for now. On macOS and Linux
//! the library never closes a device it opened itself when no script is set
//! (`os_shutdown_tun` in `tun.c` closes the descriptor only when there is a
//! script), so the device would outlive the tunnel. There the engine will
//! open the device itself and hand it over with `openconnect_setup_tun_fd`;
//! until that is written, opening refuses at the device step.
//!
//! Once the tunnel is open, the thread runs the library's main loop until
//! the tunnel ends: closed through a command on the command pipe, refused by
//! the gateway, or lost. The loop removes the device as it ends; the thread
//! then frees the handle, waits for the device to be gone, and sends the
//! tunnel's one event.

use std::cell::Cell;
use std::ffi::{CString, c_int};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::ops::RangeInclusive;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
#[cfg(windows)]
use std::time::{Duration, Instant};

use ubc_vpn_core::protocol::is_plausible_gateway_addr;
use ubc_vpn_core::redact::Secret;
use ubc_vpn_core::routes::{Ipv4Net, MIN_PREFIX_LEN, RouteSet};

use crate::ffi::{Callbacks, FormAnswer, Handle, IpInfoCopy, Library, Stopper};
use crate::login::{HTTPS, deliver, pin_matches};
use crate::{
    Assigned, Cancel, CloseMode, Gateway, LogSink, OpenConnect, Session, Tunnel, TunnelEngine,
    TunnelError, TunnelEvent, check_cookie, check_gateway_addr,
};

/// What the library answers when the gateway refuses the cookie.
const REFUSED: c_int = -EPERM;

/// The errno values the main loop's result is read by. `EINTR` (4), `EPERM`
/// (1) and `EPIPE` (32) are the same on all three systems; `ECONNABORTED`
/// is not, and on Windows it is the MinGW C runtime's, which the library is
/// built against.
const EINTR: c_int = 4;
const EPERM: c_int = 1;
const EPIPE: c_int = 32;
#[cfg(windows)]
const ECONNABORTED: c_int = 106;
#[cfg(target_os = "macos")]
const ECONNABORTED: c_int = 53;
#[cfg(all(unix, not(target_os = "macos")))]
const ECONNABORTED: c_int = 103;

/// How a tunnel ended, from what the main loop returned and whether the
/// caller closed it. `-EINTR` after a cancel and `-ECONNABORTED` after a
/// detach are the caller's close only when the caller did close it; without
/// a close they are a lost connection, like anything else unexpected.
/// `-EPERM` (the cookie expired) and `-EPIPE` (the gateway ended the
/// session) mean logging in again.
fn ended(result: c_int, closing: bool) -> TunnelEvent {
    match result.checked_neg() {
        Some(EINTR | ECONNABORTED) if closing => TunnelEvent::Closed,
        Some(EPERM | EPIPE) => TunnelEvent::LoginNeeded,
        _ => TunnelEvent::ConnectionLost,
    }
}

/// The packet sizes a tunnel may have. 576 is the least every IPv4 host
/// must take; more than 1500 does not fit an Ethernet frame.
const MTU: RangeInclusive<c_int> = 576..=1500;

/// How long the main loop goes on trying to reconnect, in seconds, and how
/// long it waits between tries.
const RECONNECT_TIMEOUT: c_int = 30;
const RECONNECT_INTERVAL: c_int = 10;

/// Where the session's gateway is to be reached: the session's address, on
/// port 443. A gateway with a test endpoint accepts exactly one address, the
/// endpoint's own, in place of [`check_gateway_addr`], which refuses
/// loopback; any other address is refused.
fn target(gateway: &Gateway, addr: Ipv4Addr) -> Result<SocketAddrV4, TunnelError> {
    match gateway.test_endpoint() {
        Some(endpoint) if *endpoint.ip() == addr => Ok(endpoint),
        Some(_) => Err(TunnelError::BadAddress),
        None => check_gateway_addr(addr).map(|()| SocketAddrV4::new(addr, HTTPS)),
    }
}

/// The resolver's answer: `target` for the policy's host on port 443, and
/// nothing for any other host or port.
fn resolve(gateway: &Gateway, target: SocketAddrV4, host: &str, port: u16) -> Option<SocketAddrV4> {
    (host.eq_ignore_ascii_case(gateway.host()) && port == HTTPS).then_some(target)
}

/// Whether a tunnel handle is alive in this process. On Windows the library
/// keeps one handle in a global for the tunnel driver's log, so there is
/// never more than one.
static TUNNEL_HANDLE: AtomicBool = AtomicBool::new(false);

/// The right to have the process's one tunnel handle. Taken before the
/// handle is made, and given back when it is dropped, after the handle.
struct Slot(());

impl Slot {
    fn take() -> Option<Self> {
        let free = TUNNEL_HANDLE.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst);
        free.ok().map(|_| Self(()))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        TUNNEL_HANDLE.store(false, Ordering::SeqCst);
    }
}

/// What the callbacks of one tunnel note while it is being opened.
#[derive(Default)]
struct Notes {
    /// A certificate was shown, so something answered at the address.
    judged: Cell<bool>,
    /// A certificate was shown that no pin matches.
    refused: Cell<bool>,
    /// The gateway answered the cookie with a login form.
    form: Cell<bool>,
}

/// The tunnel side's form callback. A gateway that answers a cookie with a
/// login form has refused the session, and nothing here may log in.
fn refuse_form(notes: &Notes) -> FormAnswer {
    notes.form.set(true);
    FormAnswer::Cancel
}

/// How making the tunnel's connection ended.
struct Connected {
    /// What `openconnect_make_cstp_connection` returned. Zero is success.
    result: c_int,
    /// Whether the certificate callback ran and accepted on this connection.
    accepted: bool,
    judged: bool,
    refused: bool,
    form: bool,
    cancelled: bool,
}

/// Turns the end of the connection into the tunnel's result.
///
/// A success is believed only with a certificate the pin check accepted on
/// this connection: a library that reused a connection, or trusted a
/// certificate by itself, judged nothing, and the cookie may have gone
/// to whoever answered.
fn conclude(connected: &Connected) -> Result<(), TunnelError> {
    if connected.refused {
        return Err(TunnelError::PinMismatch);
    }
    if connected.cancelled {
        return Err(TunnelError::Cancelled);
    }
    if connected.form || connected.result == REFUSED {
        return Err(TunnelError::LoginNeeded);
    }
    if connected.result != 0 {
        return Err(match connected.judged {
            true => TunnelError::Failed,
            false => TunnelError::GatewayUnreachable,
        });
    }
    if !connected.accepted {
        return Err(TunnelError::Failed);
    }
    Ok(())
}

/// An IPv4 address written plainly, or `None`.
fn ipv4(text: Option<&str>) -> Option<Ipv4Addr> {
    text?.parse().ok()
}

/// The prefix length of a netmask, or `None` if its ones are not all at the
/// front.
fn prefix_len(mask: Ipv4Addr) -> Option<u8> {
    let mask = u32::from(mask);
    let ones = mask.leading_ones();
    (ones + mask.trailing_zeros() == 32).then_some(ones as u8)
}

/// A route as the library gives it: `10.0.0.0/255.0.0.0`, or
/// `10.0.0.0/8`. Host bits set beyond the prefix make it no route.
fn route(text: &str) -> Option<Ipv4Net> {
    let (addr, mask) = text.split_once('/')?;
    match mask.parse::<Ipv4Addr>() {
        Ok(mask) => Ipv4Net::new(addr.parse().ok()?, prefix_len(mask)?).ok(),
        Err(_) => text.parse().ok(),
    }
}

/// Checks everything the gateway assigned before anything uses it, and the
/// address the connection went to, which must be the session's. All of it
/// but `gateway_addr` is the gateway's say. The interface is filled in once
/// the device exists.
///
/// - The address and netmask make one IPv4 network, no wider than the
///   widest route ([`MIN_PREFIX_LEN`]), that touches no reserved range and
///   does not contain the gateway's address, which must stay reachable
///   outside the tunnel.
/// - The MTU is in [`MTU`].
/// - Each DNS server is an IPv4 address outside the reserved ranges.
/// - The split routes pass the service's route rules. None means
///   everything, which is only advice: the service routes what the user
///   chose.
fn assignment(info: &IpInfoCopy, gateway_addr: Ipv4Addr) -> Result<Assigned, TunnelError> {
    const BAD: TunnelError = TunnelError::Failed;
    if ipv4(info.gateway_addr.as_deref()) != Some(gateway_addr) {
        return Err(BAD);
    }
    let address = ipv4(info.address.as_deref()).ok_or(BAD)?;
    let netmask = ipv4(info.netmask.as_deref()).ok_or(BAD)?;
    let len = prefix_len(netmask).filter(|len| *len >= MIN_PREFIX_LEN);
    let len = len.ok_or(BAD)?;
    let network = Ipv4Addr::from(u32::from(address) & u32::from(netmask));
    let network = Ipv4Net::new(network, len).map_err(|_| BAD)?;
    if network.is_reserved() || network.contains_addr(gateway_addr) {
        return Err(BAD);
    }
    if !MTU.contains(&info.mtu) {
        return Err(BAD);
    }
    let mtu = u16::try_from(info.mtu).map_err(|_| BAD)?;
    let mut dns = Vec::new();
    for server in &info.dns {
        let server = ipv4(Some(server)).filter(|server| is_plausible_gateway_addr(*server));
        dns.push(server.ok_or(BAD)?);
    }
    let mut subnets = Vec::new();
    for text in &info.split_includes {
        subnets.push(route(text).ok_or(BAD)?);
    }
    let routes = RouteSet {
        subnets,
        dns_domains: Vec::new(),
    };
    if !routes.subnets.is_empty() {
        routes.check(None).map_err(|_| BAD)?;
    }
    Ok(Assigned {
        interface: String::new(),
        address,
        netmask,
        gateway_addr,
        dns,
        mtu,
        split_includes: routes.subnets,
    })
}

/// The cookie as the tunnel hands it to the library: `webvpn=` and the value
/// a login returned.
///
/// A login returns the value of the gateway's `webvpn` cookie alone. Given a
/// cookie, the library splits it at the first `=` into a name and a value
/// and sends only the one named `webvpn`. A value with an `=` in it, such as
/// base64 padding, which ocserv's has, would be split inside the value and
/// the tunnel would send no session at all. Named, it is split after the
/// name and kept whole. A cookie that already carries the name is left as
/// it is.
fn named_cookie(cookie: &Secret) -> Secret {
    const NAME: &str = "webvpn=";
    if cookie.expose().starts_with(NAME) {
        cookie.clone()
    } else {
        // Sized up front, so the string is never moved while it is filled
        // and leaves no unwiped copy of the cookie behind.
        let mut named = String::with_capacity(NAME.len() + cookie.expose().len());
        named.push_str(NAME);
        named.push_str(cookie.expose());
        Secret::new(named)
    }
}

/// What the tunnel's thread tells the `open` that started it.
enum Report {
    /// What stops the handle while it is being opened.
    Stopper(Stopper),
    /// How opening ended. Nothing follows.
    Opened(Result<Assigned, TunnelError>),
}

/// What `open` tells the tunnel's thread once the tunnel has opened.
enum Word {
    /// The caller has the tunnel: run it.
    Keep,
    /// Opening was cancelled as the tunnel opened: remove it, logged off,
    /// and send no event, as for any opening that did not succeed.
    Abandon,
}

/// Everything the tunnel's thread needs, moved to it.
struct Job {
    library: Library,
    gateway: Gateway,
    session: Session,
    target: SocketAddrV4,
    cancel: Cancel,
    logs: LogSink,
    events: Sender<TunnelEvent>,
    /// Set by the first close, before it writes to the command pipe.
    closing: Arc<AtomicBool>,
    /// Given back after the handle is dropped.
    slot: Slot,
}

impl Job {
    /// The body of the tunnel's thread.
    fn run(self, report: Sender<Report>, words: Receiver<Word>) {
        let Self {
            library,
            gateway,
            session,
            target,
            cancel,
            logs,
            events,
            closing,
            slot,
        } = self;
        // Before the library holds it, so no line of the library's can.
        logs.hide(&session.cookie);
        let notes = Rc::new(Notes::default());
        let (judging, refusing) = (notes.clone(), notes.clone());
        let (pinned, sought, sink) = (gateway.clone(), gateway.clone(), logs.clone());
        let callbacks = Callbacks {
            lines: Box::new(move |level, line, state| deliver(&sink, level, line, state)),
            certificate: Box::new(move |hash| {
                let matches = pin_matches(&pinned, hash);
                judging.judged.set(true);
                judging.refused.set(judging.refused.get() || !matches);
                matches
            }),
            form: Box::new(move |_| refuse_form(&refusing)),
            resolve: Box::new(move |host, port| resolve(&sought, target, host, port)),
        };
        // A fresh handle for every tunnel: a handle that has connected
        // before reuses that connection without judging it again.
        let Some(handle) = Handle::new(library, callbacks) else {
            let _ = report.send(Report::Opened(Err(TunnelError::Failed)));
            return;
        };
        let _ = report.send(Report::Stopper(handle.stopper()));
        let opened = open_on(&handle, &gateway, &session, &notes, &cancel);
        let device = opened
            .as_ref()
            .ok()
            .map(|assigned| assigned.interface.clone());
        let _ = report.send(Report::Opened(opened));
        drop(report);
        let Some(device) = device else {
            return;
        };
        // Nothing runs until `open` has decided. A cancel that reached the
        // pipe after the device was made would otherwise end the loop and be
        // reported as the caller's close, of a tunnel `open` calls cancelled.
        let keep = matches!(words.recv(), Ok(Word::Keep));
        if !keep {
            handle.stopper().cancel();
        }
        // The tunnel runs here until it ends. A close writes its command to
        // the pipe, and the loop removes the device as it returns.
        let result = handle.mainloop(RECONNECT_TIMEOUT, RECONNECT_INTERVAL);
        drop(handle);
        wait_until_gone(&device);
        drop(slot);
        if keep {
            let _ = events.send(ended(result, closing.load(Ordering::SeqCst)));
        }
    }
}

/// Opens the tunnel on a fresh handle, in the order the rules ask: the
/// cookie, the connection, the checks of what came back, and the device.
fn open_on(
    handle: &Handle<'_>,
    gateway: &Gateway,
    session: &Session,
    notes: &Notes,
    cancel: &Cancel,
) -> Result<Assigned, TunnelError> {
    // The host name is all the library is told. Where it is, the resolver
    // says.
    let url = CString::new(format!("https://{}", gateway.host()));
    let url = url.map_err(|_| TunnelError::Failed)?;
    if handle.parse_url(&url) != 0 || !handle.set_cookie(&named_cookie(&session.cookie)) {
        return Err(TunnelError::Failed);
    }
    if !handle.disable_dtls() {
        return Err(TunnelError::Failed);
    }
    // On this thread too, right before anything is contacted: a cancel is
    // not left to the library's reading of the command pipe alone.
    if cancel.is_cancelled() {
        return Err(TunnelError::Cancelled);
    }
    let result = handle.make_cstp_connection();
    conclude(&Connected {
        result,
        accepted: handle.certificate_accepted(),
        judged: notes.judged.get(),
        refused: notes.refused.get(),
        form: notes.form.get(),
        cancelled: cancel.is_cancelled(),
    })?;
    let info = handle.ip_info().ok_or(TunnelError::Failed)?;
    let assigned = assignment(&info, session.gateway_addr)?;
    device(handle, assigned, cancel)
}

/// Creates the tunnel device, with no script, and names it in `assigned`.
#[cfg(windows)]
fn device(
    handle: &Handle<'_>,
    mut assigned: Assigned,
    cancel: &Cancel,
) -> Result<Assigned, TunnelError> {
    if cancel.is_cancelled() {
        return Err(TunnelError::Cancelled);
    }
    if handle.setup_tun_device() != 0 {
        return Err(TunnelError::Failed);
    }
    match handle.ifname() {
        Some(name) if !name.is_empty() => {
            assigned.interface = name;
            Ok(assigned)
        }
        _ => {
            // Removed as a close removes it: the loop reads the cancel at
            // once, quits and shuts the device down.
            handle.stopper().cancel();
            handle.mainloop(RECONNECT_TIMEOUT, RECONNECT_INTERVAL);
            Err(TunnelError::Failed)
        }
    }
}

/// Not yet: see the module documentation. The library would leave the
/// device behind when the tunnel ends.
#[cfg(not(windows))]
fn device(
    _handle: &Handle<'_>,
    _assigned: Assigned,
    _cancel: &Cancel,
) -> Result<Assigned, TunnelError> {
    Err(TunnelError::Failed)
}

/// The longest a closed device is waited for to disappear.
#[cfg(windows)]
const DEVICE_GONE_LIMIT: Duration = Duration::from_secs(5);

/// Waits until the system no longer has the device `name`. On Windows a
/// Wintun adapter the library has closed stays visible for some tens of
/// milliseconds, and a tunnel is closed only once its device is gone. The
/// wait is bounded, so a system that never says gone cannot hold a close
/// for ever.
#[cfg(windows)]
fn wait_until_gone(name: &str) {
    let start = Instant::now();
    while crate::ffi::interface_exists(name) == Some(true) && start.elapsed() < DEVICE_GONE_LIMIT {
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(not(windows))]
fn wait_until_gone(_name: &str) {
    // Nothing yet: no device is made here (see the module documentation).
}

/// An open tunnel: what it was assigned, and the thread that owns it.
struct OpenTunnel {
    assigned: Assigned,
    /// Writes to the handle's command pipe while the handle lives, and
    /// does nothing once the tunnel has ended.
    stopper: Stopper,
    /// Whether a close has decided how the tunnel ends. The thread reads it
    /// too: only then is the loop's end the caller's close.
    closing: Arc<AtomicBool>,
    /// Joined by whichever close gets it; the others wait on the lock.
    thread: Mutex<Option<JoinHandle<()>>>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl OpenTunnel {
    /// Waits for the tunnel's thread to end: by then the device is gone and
    /// the one event has been sent.
    fn join(&self) {
        let mut thread = lock(&self.thread);
        if let Some(thread) = thread.take() {
            let _ = thread.join();
        }
    }
}

impl Tunnel for OpenTunnel {
    fn assigned(&self) -> &Assigned {
        &self.assigned
    }

    fn close(&self, how: CloseMode) {
        // The first close decides. On a tunnel that has already ended the
        // handle is gone, and the stopper writes nothing.
        if !self.closing.swap(true, Ordering::SeqCst) {
            match how {
                CloseMode::LogOff => self.stopper.cancel(),
                CloseMode::KeepSession => self.stopper.detach(),
            };
        }
        self.join();
    }
}

impl Drop for OpenTunnel {
    fn drop(&mut self) {
        self.close(CloseMode::KeepSession);
    }
}

impl TunnelEngine for OpenConnect {
    fn open(
        &self,
        gateway: &Gateway,
        session: &Session,
        cancel: &Cancel,
        events: Sender<TunnelEvent>,
        logs: LogSink,
    ) -> Result<Box<dyn Tunnel>, TunnelError> {
        // The address comes from an unprivileged program: checked first.
        let target = target(gateway, session.gateway_addr)?;
        // So does the cookie, which goes into a header the service sends.
        check_cookie(&session.cookie)?;
        if cancel.is_cancelled() {
            return Err(TunnelError::Cancelled);
        }
        let slot = Slot::take().ok_or(TunnelError::Failed)?;
        let (report, reports) = mpsc::channel();
        let (word, words) = mpsc::channel();
        let closing = Arc::new(AtomicBool::new(false));
        let job = Job {
            library: self.library,
            gateway: gateway.clone(),
            session: session.clone(),
            target,
            cancel: cancel.clone(),
            logs,
            events,
            closing: Arc::clone(&closing),
            slot,
        };
        let thread = std::thread::Builder::new()
            .name("tunnel".to_string())
            .spawn(move || job.run(report, words))
            .map_err(|_| TunnelError::Failed)?;
        // A cancel from another thread wakes the library through the
        // handle's command pipe. The hook is armed only while this call
        // lasts; a cancel that comes later reaches nothing.
        let (mut armed, mut stopper) = (None, None);
        let opened = loop {
            match reports.recv() {
                Ok(Report::Stopper(stops)) => {
                    let wakes = stops.clone();
                    armed = Some(cancel.on_cancel(move || {
                        wakes.cancel();
                    }));
                    stopper = Some(stops);
                }
                Ok(Report::Opened(opened)) => break opened,
                Err(_) => break Err(TunnelError::Failed),
            }
        };
        drop(armed);
        let failed = match (opened, stopper) {
            (Ok(assigned), Some(stopper)) if !cancel.is_cancelled() => {
                let _ = word.send(Word::Keep);
                return Ok(Box::new(OpenTunnel {
                    assigned,
                    stopper,
                    closing,
                    thread: Mutex::new(Some(thread)),
                }));
            }
            (Ok(_), _) => {
                // Opened as it was cancelled: given up by the thread.
                let _ = word.send(Word::Abandon);
                TunnelError::Cancelled
            }
            (Err(error), _) => error,
        };
        // Nothing is left behind: the thread removes a device it made and
        // ends, and the handle and its slot are gone before this returns.
        let _ = thread.join();
        Err(failed)
    }
}

#[cfg(test)]
mod tests {
    use ubc_vpn_core::policy::{Pin, Policy};

    use super::*;

    const A_PIN: &str = "pin-sha256:fTzrkd+T2QOdSW5oSF7vp4M6JCp1hHMbYY2Q+IX4x5o=";
    const GATEWAY: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

    fn policy() -> Policy {
        Policy {
            gateway: "vpn.example.test".to_string(),
            pins: vec![Pin::try_from(A_PIN.to_string()).expect("a full pin")],
            allowed_routes: None,
        }
    }

    fn shipped() -> Gateway {
        Gateway::from_policy(&policy()).expect("a valid policy")
    }

    fn local(port: u16) -> Gateway {
        let endpoint = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
        Gateway::for_test(&policy(), endpoint).expect("a local endpoint")
    }

    // Security rule: the session's address is checked before anything else.
    // Without a test endpoint that is `check_gateway_addr`, and the port is
    // always 443; with one, only the endpoint's own address passes.
    #[test]
    fn the_target_is_the_checked_session_address() {
        let target = target(&shipped(), GATEWAY);
        assert_eq!(target, Ok(SocketAddrV4::new(GATEWAY, 443)));
        for bad in [
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
        ] {
            assert_eq!(super::target(&shipped(), bad), Err(TunnelError::BadAddress));
        }
        let test = local(8443);
        let endpoint = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8443);
        assert_eq!(super::target(&test, Ipv4Addr::LOCALHOST), Ok(endpoint));
        for other in [Ipv4Addr::new(127, 0, 0, 2), GATEWAY] {
            assert_eq!(super::target(&test, other), Err(TunnelError::BadAddress));
        }
    }

    // Security rule: the resolver answers with the one checked address for
    // the policy's host on port 443, and refuses every other host and port,
    // an address written as numbers included.
    #[test]
    fn the_resolver_answers_only_for_the_policy_host_on_443() {
        let to = SocketAddrV4::new(GATEWAY, 443);
        let gateway = shipped();
        assert_eq!(resolve(&gateway, to, "vpn.example.test", 443), Some(to));
        assert_eq!(resolve(&gateway, to, "VPN.Example.Test", 443), Some(to));
        for (host, port) in [
            ("vpn.example.test", 8443),
            ("other.example.test", 443),
            ("192.0.2.1", 443),
            ("vpn.example.test.evil.test", 443),
        ] {
            assert_eq!(resolve(&gateway, to, host, port), None, "{host}:{port}");
        }
    }

    // Security rule: one tunnel handle in the process at a time.
    #[test]
    fn there_is_one_slot_for_a_tunnel_handle() {
        let first = Slot::take().expect("no tunnel yet");
        assert!(Slot::take().is_none());
        drop(first);
        assert!(Slot::take().is_some());
    }

    // Security rule: a login form in answer to the cookie is a refused
    // session, and the form is cancelled, never filled.
    #[test]
    fn a_login_form_is_cancelled_and_means_login_needed() {
        let notes = Notes::default();
        assert_eq!(refuse_form(&notes), FormAnswer::Cancel);
        let connected = Connected {
            form: notes.form.get(),
            ..good()
        };
        assert_eq!(conclude(&connected), Err(TunnelError::LoginNeeded));
    }

    fn good() -> Connected {
        Connected {
            result: 0,
            accepted: true,
            judged: true,
            refused: false,
            form: false,
            cancelled: false,
        }
    }

    // Security rule: a connection the pin check did not accept is refused,
    // though the library says it succeeded. A handle that logged in reuses
    // that connection for a tunnel and judges nothing.
    #[test]
    fn a_connection_without_an_accepted_certificate_is_refused() {
        assert_eq!(conclude(&good()), Ok(()));
        let unjudged = Connected {
            accepted: false,
            ..good()
        };
        assert_eq!(conclude(&unjudged), Err(TunnelError::Failed));
    }

    #[test]
    fn what_stopped_the_connection_decides_the_error() {
        let ended = |change: fn(&mut Connected)| {
            let mut connected = good();
            change(&mut connected);
            conclude(&connected)
        };
        let refused = ended(|c| (c.refused, c.result) = (true, -5));
        assert_eq!(refused, Err(TunnelError::PinMismatch));
        let cancelled = ended(|c| c.cancelled = true);
        assert_eq!(cancelled, Err(TunnelError::Cancelled));
        let expired = ended(|c| c.result = REFUSED);
        assert_eq!(expired, Err(TunnelError::LoginNeeded));
        let unreachable = ended(|c| (c.result, c.judged) = (-5, false));
        assert_eq!(unreachable, Err(TunnelError::GatewayUnreachable));
        assert_eq!(ended(|c| c.result = -5), Err(TunnelError::Failed));
    }

    /// What the stand-in gateway assigns, as the library copies it.
    fn info() -> IpInfoCopy {
        let text = |text: &str| Some(text.to_string());
        IpInfoCopy {
            address: text("10.11.12.13"),
            netmask: text("255.255.255.0"),
            dns: vec!["10.11.0.1".to_string(), "10.11.0.2".to_string()],
            mtu: 1300,
            split_includes: vec![
                "192.0.2.0/255.255.255.0".to_string(),
                "10.0.0.0/255.0.0.0".to_string(),
            ],
            gateway_addr: text("192.0.2.1"),
        }
    }

    fn changed(change: impl FnOnce(&mut IpInfoCopy)) -> Result<Assigned, TunnelError> {
        let mut info = info();
        change(&mut info);
        assignment(&info, GATEWAY)
    }

    #[test]
    fn a_good_assignment_is_read_whole() {
        let net = |text: &str| text.parse::<Ipv4Net>().unwrap();
        let expected = Assigned {
            interface: String::new(),
            address: Ipv4Addr::new(10, 11, 12, 13),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            gateway_addr: GATEWAY,
            dns: vec![Ipv4Addr::new(10, 11, 0, 1), Ipv4Addr::new(10, 11, 0, 2)],
            mtu: 1300,
            split_includes: vec![net("192.0.2.0/24"), net("10.0.0.0/8")],
        };
        assert_eq!(assignment(&info(), GATEWAY), Ok(expected));
        // No routes means everything, and no DNS server is no DNS server.
        let bare = changed(|info| (info.split_includes, info.dns) = (Vec::new(), Vec::new()));
        assert!(bare.is_ok_and(|bare| bare.split_includes.is_empty() && bare.dns.is_empty()));
        // A route may also come as a prefix length.
        let short = changed(|info| info.split_includes = vec!["10.0.0.0/8".to_string()]);
        assert_eq!(short.unwrap().split_includes, [net("10.0.0.0/8")]);
    }

    // Security rule: the connection went to the session's address, which the
    // service routes outside the tunnel.
    #[test]
    fn the_connected_address_must_be_the_sessions() {
        for other in [None, Some("192.0.2.2"), Some("192.0.2.1 "), Some("")] {
            let moved = changed(|info| info.gateway_addr = other.map(str::to_string));
            assert_eq!(moved, Err(TunnelError::Failed), "{other:?}");
        }
    }

    // Security rule: the address and netmask make one IPv4 network that is
    // not reserved and not wider than any route may be.
    #[test]
    fn a_bad_address_or_netmask_is_refused() {
        let bad = [
            (None, Some("255.255.255.0")),
            (Some("10.11.12.13"), None),
            (Some("not-an-address"), Some("255.255.255.0")),
            (Some("10.11.12.13"), Some("255.0.255.0")),
            (Some("10.11.12.13"), Some("0.0.0.0")),
            (Some("10.11.12.13"), Some("254.0.0.0")),
            (Some("10.11.12.13"), Some("24")),
            (Some("127.0.0.2"), Some("255.255.255.0")),
            (Some("169.254.1.1"), Some("255.255.0.0")),
            (Some("224.0.0.1"), Some("255.255.255.255")),
            (Some("192.0.2.1"), Some("255.255.255.0")),
            (Some("010.11.12.13"), Some("255.255.255.0")),
        ];
        for (address, netmask) in bad {
            let assigned = changed(|info| {
                info.address = address.map(str::to_string);
                info.netmask = netmask.map(str::to_string);
            });
            assert_eq!(
                assigned,
                Err(TunnelError::Failed),
                "{address:?} {netmask:?}"
            );
        }
        let widest = changed(|info| info.netmask = Some("255.0.0.0".to_string()));
        assert!(widest.is_ok());
        let host = changed(|info| info.netmask = Some("255.255.255.255".to_string()));
        assert!(host.is_ok());
    }

    // Security rule: the gateway stays reachable outside the tunnel. A
    // network that holds its address, not only one whose address is it,
    // would take the route to the gateway into the tunnel.
    #[test]
    fn a_network_that_holds_the_gateway_is_refused() {
        for (address, netmask) in [
            ("192.0.2.5", "255.255.255.0"),
            ("192.0.2.2", "255.255.255.252"),
            ("192.0.0.1", "255.255.0.0"),
            ("192.200.1.1", "255.0.0.0"),
        ] {
            let assigned = changed(|info| {
                info.address = Some(address.to_string());
                info.netmask = Some(netmask.to_string());
                info.split_includes.clear();
            });
            assert_eq!(assigned, Err(TunnelError::Failed), "{address}/{netmask}");
        }
        // Next to it, but not around it.
        let beside = changed(|info| {
            info.address = Some("192.0.2.200".to_string());
            info.netmask = Some("255.255.255.128".to_string());
            info.split_includes.clear();
        });
        assert!(beside.is_ok());
        let apart = changed(|info| {
            info.address = Some("192.0.3.5".to_string());
            info.split_includes.clear();
        });
        assert!(apart.is_ok());
    }

    // A login's cookie reaches the library named, so the library keeps a
    // value with an `=` in it whole; one already named is not named twice.
    #[test]
    fn the_cookie_is_handed_over_named() {
        let named = |cookie: &str| named_cookie(&Secret::new(cookie)).expose().to_string();
        assert_eq!(named("FAKE-VALUE-abc=="), "webvpn=FAKE-VALUE-abc==");
        assert_eq!(named("FAKE@VALUE@123"), "webvpn=FAKE@VALUE@123");
        assert_eq!(named("webvpn=FAKE-VALUE=="), "webvpn=FAKE-VALUE==");
    }

    // The main loop's result is the tunnel's one event: the caller's close,
    // a refused session, or a lost connection.
    #[test]
    fn the_main_loop_result_decides_the_event() {
        assert_eq!(ended(-EINTR, true), TunnelEvent::Closed);
        assert_eq!(ended(-ECONNABORTED, true), TunnelEvent::Closed);
        for closing in [false, true] {
            assert_eq!(ended(-EPERM, closing), TunnelEvent::LoginNeeded);
            assert_eq!(ended(-EPIPE, closing), TunnelEvent::LoginNeeded);
        }
        for other in [-5, -110, -104, 0, 1, EINTR, c_int::MIN] {
            assert_eq!(ended(other, true), TunnelEvent::ConnectionLost, "{other}");
        }
    }

    // A cancel or detach the caller did not ask for, such as one that
    // reached the command pipe from somewhere else, never looks like the
    // caller's close: the tunnel ended unasked, which is a lost connection.
    #[test]
    fn only_a_close_makes_the_end_a_close() {
        assert_eq!(ended(-EINTR, false), TunnelEvent::ConnectionLost);
        assert_eq!(ended(-ECONNABORTED, false), TunnelEvent::ConnectionLost);
    }

    // Security rule: a cancel is looked at on the tunnel's own thread right
    // before the connection is made, not left to the library reading the
    // command pipe. Here nothing is written to the pipe, as when the cancel
    // comes after `open` looked and before its hook was armed: the gateway
    // is still not contacted.
    #[test]
    fn a_cancel_is_seen_on_the_tunnel_thread_before_connecting() {
        let Some(stand_in) = crate::login::stand_in::Gateway::start("accept") else {
            return;
        };
        let endpoint = SocketAddrV4::new(Ipv4Addr::LOCALHOST, stand_in.port);
        let mut callbacks = Callbacks::refusing(Box::new(|_, _, _| {}));
        callbacks.certificate = Box::new(|_| true);
        callbacks.resolve = Box::new(move |_, _| Some(endpoint));
        let library = crate::login::test_library();
        let handle = Handle::new(library, callbacks).expect("the library makes a handle");
        let session = Session {
            cookie: ubc_vpn_core::redact::Secret::new("webvpn=FAKE-COOKIE-0123456789"),
            gateway_addr: Ipv4Addr::LOCALHOST,
        };
        let cancel = Cancel::new();
        cancel.cancel();
        let opened = open_on(
            &handle,
            &local(stand_in.port),
            &session,
            &Notes::default(),
            &cancel,
        );
        assert_eq!(opened, Err(TunnelError::Cancelled));
        assert_eq!(stand_in.requests(), Vec::<String>::new());
    }

    #[test]
    fn an_mtu_outside_576_to_1500_is_refused() {
        for mtu in [-1, 0, 575, 1501, 65536] {
            assert_eq!(
                changed(|info| info.mtu = mtu),
                Err(TunnelError::Failed),
                "{mtu}"
            );
        }
        for mtu in [576, 1500] {
            assert!(changed(|info| info.mtu = mtu).is_ok_and(|a| a.mtu == mtu as u16));
        }
    }

    #[test]
    fn a_dns_server_must_be_a_usable_ipv4_address() {
        for server in [
            "",
            "dns.example.test",
            "::1",
            "127.0.0.1",
            "0.0.0.0",
            "10.11.0.1/32",
        ] {
            let assigned = changed(|info| info.dns = vec![server.to_string()]);
            assert_eq!(assigned, Err(TunnelError::Failed), "{server:?}");
        }
    }

    // Security rule: the gateway's routes pass the same rules as the
    // user's: no default route, nothing wider than /8, nothing reserved.
    #[test]
    fn a_route_the_route_rules_refuse_is_refused() {
        for bad in [
            "0.0.0.0/0.0.0.0",
            "0.0.0.0/0",
            "128.0.0.0/128.0.0.0",
            "10.0.0.0/254.0.0.0",
            "127.0.0.0/255.0.0.0",
            "224.0.0.0/240.0.0.0",
            "10.1.2.3/255.0.0.0",
            "10.0.0.0/255.0.255.0",
            "10.0.0.0",
            "10.0.0.0/08",
            "",
        ] {
            let assigned = changed(|info| info.split_includes.push(bad.to_string()));
            assert_eq!(assigned, Err(TunnelError::Failed), "{bad:?}");
        }
        let many = changed(|info| {
            info.split_includes = (0..=256)
                .map(|n| format!("10.{}.{}.0/24", n / 256, n % 256))
                .collect();
        });
        assert_eq!(many, Err(TunnelError::Failed));
    }
}
