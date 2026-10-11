//! The VPN engine interface.
//!
//! An engine speaks the AnyConnect protocol to the gateway. This crate defines
//! what the rest of the workspace may ask of one. The `fake` module, behind
//! the `fake` Cargo feature, is a scripted engine for tests and for the
//! service's dev mode. The real engine, a binding to `libopenconnect`, will
//! live behind the `libopenconnect` feature. That feature is off by default
//! and enables nothing yet, so ordinary builds and tests need no native
//! library.
//!
//! There are two capabilities, because they run in two processes:
//!
//! - [`LoginEngine`], for the unprivileged command-line client. It asks the
//!   user what the gateway wants to know and returns a [`Session`].
//! - [`TunnelEngine`], for the privileged service. It turns a [`Session`] into
//!   a tunnel device and reports what the gateway assigned. It never sees a
//!   password and never logs in.
//!
//! All calls block, and nothing here needs an async runtime.
//!
//! # What the types enforce
//!
//! [`Gateway`], [`Prompts`] and [`LogSink`] each live in a file of their own
//! with private fields, so not even code inside this crate can get round
//! them. No engine may ever be added to those three files.
//!
//! - **Pins.** Both capabilities take a [`Gateway`], which cannot exist
//!   without a valid host name and at least one pin. There is no way to
//!   accept any certificate.
//! - **No blind retries.** An engine can reach the user only through
//!   [`Prompts`], which refuses to ask for the username or the password a
//!   second time and reports [`LoginError::WrongPassword`] instead.
//! - **Secrets.** Cookies and answers are [`Secret`]s. Errors and events are
//!   `Copy` enums, so they cannot own text and cannot carry a secret. Log
//!   lines reach the caller only through [`LogSink`], which filters them by
//!   level, removes registered secrets and redacts what is left.
//! - **Session expiry.** A tunnel that the gateway ends or refuses reports
//!   "login needed", which is distinct from a network failure. Nothing on the
//!   tunnel side can prompt, so it cannot log in again.
//!
//! # Rules for the real engine
//!
//! The fake cannot enforce these. The `libopenconnect` binding must:
//!
//! **Process and library setup**
//!
//! - Clear `SSLKEYLOGFILE`, `GNUTLS_SYSTEM_PRIORITY_FILE` and
//!   `GNUTLS_DEBUG_LEVEL` from the environment of the privileged process
//!   before the library is first used. GnuTLS honours all three.
//! - Never set a vpnc-script, a CSD wrapper or a proxy. The tunnel device is
//!   created with a null script; routes and DNS belong to the service.
//! - Keep to IPv4, which takes two steps. `openconnect_disable_ipv6` only
//!   stops IPv6 inside the tunnel, and must be called before anything is
//!   sent. The connection to the gateway still resolves both families, so
//!   also install `openconnect_override_getaddrinfo` with a callback that
//!   asks for `AF_INET` only, or fail when the peer turns out to be IPv6.
//!   Without this a login cannot fill [`Session::gateway_addr`].
//! - Never enable a software-token mode, an external-browser or
//!   single-sign-on login, or a client certificate.
//! - Let one thread own the library handle and make every library call on
//!   it. Other threads touch only the write end of the command pipe from
//!   `openconnect_setup_cmd_pipe`. On Windows that end is a socket, written
//!   with `send`.
//!
//! **Certificates**
//!
//! - Turn system trust off (`openconnect_set_system_trust(v, 0)`) and make the
//!   pin check the only judge: the certificate callback accepts a peer only
//!   when its `pin-sha256:` hash satisfies [`Gateway::accepts`], and anything
//!   else is a pin mismatch. Do not hand pins to the library for matching; it
//!   accepts prefixes.
//! - Reject inside the certificate callback, so that nothing, the cookie
//!   least of all, is sent before the pin check has passed.
//!
//! **Login**
//!
//! - Map form fields to prompt kinds by field type and field name only: the
//!   text field named `username` is the username; the password field named
//!   `password` is the password; any other password field is a one-time
//!   code; any other text field is free text. Skip hidden fields and fields
//!   flagged `OC_FORM_OPT_IGNORE`. Put the form's message or error text in
//!   [`Prompt::message`].
//! - Read the cookie with `openconnect_get_cookie` after
//!   `openconnect_obtain_cookie` succeeds, and register it with
//!   [`LogSink::hide`] at once.
//! - Treat a form shown again with its error set as a rejection: ask again
//!   through [`Prompts::ask`], which stops the login, and never answer from
//!   memory. Fill each field from one `ask` call and keep no copy of the
//!   answer.
//! - Fail with [`LoginError::Failed`] on a form that needs a choice of group
//!   or realm. Group selection is out of scope for v0.1.0, on the working
//!   assumption that UBC selects the MFA method through the username. The
//!   first login probe against the real gateway must confirm this.
//! - Register an [`on_cancel`](Cancel::on_cancel) hook that writes
//!   `OC_CMD_CANCEL` to the command pipe, so a login waiting for an MFA
//!   approval, or a tunnel being opened, stops at once. Hold the returned
//!   guard only for the duration of that one call and drop it before
//!   returning, so a late cancel can never write to a live tunnel's pipe or
//!   to a freed handle.
//!
//! **Tunnel**
//!
//! - Treat [`Session::gateway_addr`] as untrusted: it comes from an
//!   unprivileged program. Call [`check_gateway_addr`] before anything else.
//!   Reach the address through `openconnect_override_getaddrinfo`, with a
//!   callback that answers with that one address, while still using the
//!   policy's host name for TLS and HTTP. Never build a URL from client
//!   input. After connecting, check that the address the tunnel is connected
//!   to equals the session's and report it in [`Assigned::gateway_addr`].
//! - Hand the cookie to the library with `openconnect_set_cookie`, after
//!   registering it with [`LogSink::hide`].
//! - Make the tunnel side's own auth-form callback cancel. A gateway that
//!   answers a cookie with a login form has refused the session, which is
//!   [`TunnelError::LoginNeeded`].
//! - Start one thread per tunnel to run `openconnect_mainloop`. That thread
//!   sends the tunnel's one [`TunnelEvent`], and [`Tunnel::close`] and drop
//!   return only after it has ended and the device is gone. The fake has no
//!   such thread and cannot show either rule.
//! - Stop with the command that matches the [`CloseMode`]: `OC_CMD_CANCEL`
//!   for [`CloseMode::LogOff`], which logs the session off and makes the main
//!   loop return `-EINTR`; `OC_CMD_DETACH` for [`CloseMode::KeepSession`],
//!   which leaves the cookie valid and returns `-ECONNABORTED`. Both are
//!   [`TunnelEvent::Closed`].
//! - Read every other result of the main loop like this: `-EPERM` (the
//!   cookie expired) and `-EPIPE` (the gateway ended the session) are
//!   [`TunnelEvent::LoginNeeded`]; any other negative result is
//!   [`TunnelEvent::ConnectionLost`].
//! - Bound the library's own silent reconnects with a short reconnect
//!   timeout in the main loop, so a dead tunnel is reported and not hidden.
//! - Never retry after a pin mismatch or a refused session, and never try to
//!   log in.
//!
//! **Logs**
//!
//! - Send every line the library logs through [`LogSink::log`] and nowhere
//!   else, and register the cookie and each answer with [`LogSink::hide`] as
//!   soon as it is held. The library logs the session cookie at debug level,
//!   so its debug output is dropped in release builds (see
//!   [`DEBUG_LINES`]), and the library must never be asked to dump request
//!   or response bodies.

#![cfg_attr(not(feature = "libopenconnect"), forbid(unsafe_code))]

use std::fmt;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, PoisonError};

use ubc_vpn_core::login::LoginErrorCode;
use ubc_vpn_core::protocol::{ErrorCode, is_plausible_gateway_addr};
use ubc_vpn_core::redact::Secret;
use ubc_vpn_core::routes::Ipv4Net;

#[cfg(any(test, feature = "fake"))]
pub mod fake;
mod gateway;
mod log;
mod prompts;
#[cfg(test)]
mod tests;

pub use gateway::Gateway;
pub use log::{DEBUG_LINES, LogLevel, LogSink, MIN_HIDDEN_LEN};

type Hooks = (u64, Vec<(u64, Hook)>);
pub use prompts::{Prompt, Prompts};

type Hook = Box<dyn Fn() + Send + Sync>;

#[derive(Default)]
struct CancelState {
    cancelled: AtomicBool,
    /// The armed hooks, each with the number its guard knows it by.
    hooks: Mutex<Hooks>,
}

/// Lets another thread ask one login or one tunnel opening to stop. Clones
/// share one flag. Make a new one for every call.
///
/// Cancelling is a request, not a guarantee. The call normally returns
/// `Cancelled` promptly, but it may already have finished its work and
/// return success instead. A caller that cancelled and still gets a tunnel
/// must close it, and one that still gets a session must discard it.
#[derive(Clone, Default)]
pub struct Cancel(Arc<CancelState>);

impl Cancel {
    /// A flag that is not yet set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Asks the call to stop. Safe from any thread, any number of times,
    /// before or during the call.
    pub fn cancel(&self) {
        let hooks = self.hooks();
        if !self.0.cancelled.swap(true, Ordering::SeqCst) {
            hooks.1.iter().for_each(|(_, hook)| hook());
        }
    }

    /// For engines: whether the caller asked to stop.
    pub fn is_cancelled(&self) -> bool {
        self.0.cancelled.load(Ordering::SeqCst)
    }

    /// For engines: runs `hook` once if the caller cancels while the returned
    /// guard is alive, on the cancelling thread, or at once if the caller
    /// already has. An engine blocked inside its library uses this to wake
    /// itself, with no polling.
    ///
    /// Dropping the guard disarms the hook: it will not start afterwards, and
    /// if it is running the drop waits for it. Hold the guard only for the
    /// duration of the call, so a late cancel touches nothing. The hook must
    /// be quick and must not use this `Cancel` or drop the guard.
    #[must_use = "the hook is disarmed as soon as the guard is dropped"]
    pub fn on_cancel(&self, hook: impl Fn() + Send + Sync + 'static) -> CancelHook {
        let mut hooks = self.hooks();
        hooks.0 += 1;
        let number = hooks.0;
        if self.is_cancelled() {
            drop(hooks);
            hook();
        } else {
            hooks.1.push((number, Box::new(hook)));
        }
        CancelHook(self.clone(), number)
    }

    fn hooks(&self) -> std::sync::MutexGuard<'_, Hooks> {
        self.0.hooks.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Keeps a [`Cancel::on_cancel`] hook armed. Dropping it disarms the hook.
pub struct CancelHook(Cancel, u64);

impl Drop for CancelHook {
    fn drop(&mut self) {
        self.0.hooks().1.retain(|(number, _)| *number != self.1);
    }
}

/// What a successful login yields. The whole value is secret-bearing: its
/// `Debug` output hides the cookie, and it has no `Display`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    /// The session cookie the gateway issued.
    pub cookie: Secret,
    /// The address the login actually connected to. A host name may resolve
    /// to several gateways, and the cookie is only good at this one.
    ///
    /// On the tunnel side this value arrives from an unprivileged program
    /// and is a hint, not authority: see [`check_gateway_addr`].
    pub gateway_addr: Ipv4Addr,
}

/// Why a login failed. None of these is retried by the engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginError {
    /// The gateway rejected the login: it asked again for something already
    /// answered. Nothing was sent twice.
    ///
    /// This also covers a rejected one-time code, because the gateway simply
    /// shows the form again and does not say which answer was wrong. Use
    /// [`Prompts::asked`] to tell whether a code was involved.
    WrongPassword,
    /// The gateway's key matched none of the pins. Nothing was sent to it.
    PinMismatch,
    /// The caller cancelled.
    Cancelled,
    /// The gateway could not be reached.
    GatewayUnreachable,
    /// Anything else, such as a login step this client does not support.
    Failed,
}

impl fmt::Display for LoginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::WrongPassword => "The gateway rejected the username, password or code.",
            Self::PinMismatch => {
                "The gateway's certificate is not the expected one. Nothing was sent to it."
            }
            Self::Cancelled => "Login was cancelled.",
            Self::GatewayUnreachable => "The gateway could not be reached.",
            Self::Failed => "Login failed unexpectedly.",
        })
    }
}

impl std::error::Error for LoginError {}

impl From<LoginError> for LoginErrorCode {
    fn from(e: LoginError) -> Self {
        match e {
            LoginError::WrongPassword => Self::WrongPassword,
            LoginError::PinMismatch => Self::PinMismatch,
            LoginError::Cancelled => Self::Cancelled,
            LoginError::GatewayUnreachable => Self::GatewayUnreachable,
            LoginError::Failed => Self::Internal,
        }
    }
}

/// Logging in. Used by the unprivileged command-line client.
pub trait LoginEngine: Send + Sync {
    /// Logs in to `gateway` and returns the session.
    ///
    /// Blocks until the login succeeds, fails or is cancelled, either by the
    /// prompt callback returning `None` or through `cancel`. The gateway is
    /// checked against the pins before anything is asked or sent. Each answer
    /// is sent to the gateway at most once. A cancelled login never returns
    /// a session.
    fn login(
        &self,
        gateway: &Gateway,
        prompts: &mut Prompts<'_>,
        cancel: &Cancel,
        logs: &LogSink,
    ) -> Result<Session, LoginError>;
}

/// What the gateway assigned to a tunnel. Nothing here has been applied to
/// the system except the device itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assigned {
    /// The tunnel device's name, such as `utun4`.
    pub interface: String,
    /// This machine's address inside the tunnel.
    pub address: Ipv4Addr,
    /// The netmask that goes with `address`.
    pub netmask: Ipv4Addr,
    /// The gateway address the tunnel is connected to, always equal to the
    /// session's. The service routes this one address through the physical
    /// network.
    pub gateway_addr: Ipv4Addr,
    /// The DNS servers the gateway offers.
    pub dns: Vec<Ipv4Addr>,
    /// The largest packet the tunnel carries.
    pub mtu: u16,
    /// The routes the gateway asked to have tunnelled. Advice only: the
    /// service routes what the user chose. Empty means "everything".
    pub split_includes: Vec<Ipv4Net>,
}

/// Why a tunnel could not be opened. The engine retries none of these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelError {
    /// The gateway's key matched none of the service's pins. Nothing was
    /// sent to it.
    PinMismatch,
    /// The gateway refused the session cookie. The user must log in again.
    LoginNeeded,
    /// The gateway could not be reached.
    GatewayUnreachable,
    /// The caller cancelled. No device was left behind.
    Cancelled,
    /// The session's gateway address is not one a gateway can have. Nothing
    /// was contacted.
    BadAddress,
    /// Anything else, such as the tunnel device not being created.
    Failed,
}

impl fmt::Display for TunnelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::PinMismatch => "The gateway's certificate is not the expected one.",
            Self::LoginNeeded => "The session is no longer valid. Log in again.",
            Self::GatewayUnreachable => "The gateway could not be reached.",
            Self::Cancelled => "Connecting was cancelled.",
            Self::BadAddress => "The gateway address is not a usable address.",
            Self::Failed => "The tunnel could not be opened.",
        })
    }
}

impl std::error::Error for TunnelError {}

impl From<TunnelError> for ErrorCode {
    fn from(e: TunnelError) -> Self {
        match e {
            TunnelError::PinMismatch => Self::PinMismatch,
            TunnelError::LoginNeeded => Self::LoginNeeded,
            TunnelError::BadAddress => Self::BadRequest,
            TunnelError::GatewayUnreachable => Self::GatewayUnreachable,
            // The service cancels its own connect and normally reports
            // "disconnected" instead of an error.
            TunnelError::Cancelled | TunnelError::Failed => Self::EngineFailed,
        }
    }
}

/// Checks a gateway address that came from an unprivileged client before
/// anything connects to it. Every tunnel engine calls this first.
///
/// It applies [`is_plausible_gateway_addr`], the rule shared with the
/// service, which refuses "this network", loopback, link-local, multicast and
/// reserved addresses, broadcast included. Such an address could point the
/// privileged service at a local program. Whatever passes still has to
/// present a pinned key before the cookie is sent.
pub fn check_gateway_addr(addr: Ipv4Addr) -> Result<(), TunnelError> {
    if is_plausible_gateway_addr(addr) {
        Ok(())
    } else {
        Err(TunnelError::BadAddress)
    }
}

/// How an open tunnel ended. Exactly one is sent per tunnel, and nothing
/// follows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelEvent {
    /// The caller closed it.
    Closed,
    /// The gateway ended or refused the session. The user must log in again;
    /// the engine does not.
    LoginNeeded,
    /// The connection to the gateway was lost for a network reason. The
    /// session may still be good.
    ConnectionLost,
}

/// What closing a tunnel does to the session at the gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseMode {
    /// Log the session off, so the cookie stops working. For when the user
    /// disconnects.
    ///
    /// This is best effort. It logs nothing off when the tunnel had already
    /// ended, and the gateway may never hear it. The service must forget the
    /// cookie itself and not count on the gateway refusing it.
    LogOff,
    /// Detach and leave the session alive, so the same cookie can open a new
    /// tunnel. For teardown before a reconnect, such as after sleep or a
    /// network change.
    KeepSession,
}

/// Opening tunnels. Used by the privileged service.
pub trait TunnelEngine: Send + Sync {
    /// Connects to the gateway with the session's cookie and creates the
    /// tunnel device, running no script and changing no routes or DNS.
    ///
    /// `gateway` must come from the service's own policy, never from a
    /// client. The session does come from a client: its address is checked
    /// with [`check_gateway_addr`] before anything is contacted, and the
    /// cookie is sent only after the gateway's key has matched a pin.
    ///
    /// Blocks until the device exists, opening fails, or `cancel` stops it.
    /// A `cancel` that is already set stops it before anything is contacted.
    /// On success the tunnel runs by itself until it ends, and then sends its
    /// one [`TunnelEvent`] on `events`; no event is sent when opening fails.
    ///
    /// A real engine runs the tunnel on a thread it starts and owns, and the
    /// event is sent from that thread. The fake starts no thread.
    fn open(
        &self,
        gateway: &Gateway,
        session: &Session,
        cancel: &Cancel,
        events: Sender<TunnelEvent>,
        logs: LogSink,
    ) -> Result<Box<dyn Tunnel>, TunnelError>;
}

/// An open tunnel. Dropping it closes it with [`CloseMode::KeepSession`].
pub trait Tunnel: Send + Sync {
    /// What the gateway assigned. Fixed for the life of the tunnel.
    fn assigned(&self) -> &Assigned;

    /// Closes the tunnel and removes its device.
    ///
    /// Safe from any thread and more than once. Only the first call on a
    /// live tunnel does anything: it decides the mode and causes
    /// [`TunnelEvent::Closed`]. On a tunnel that has already ended it sends
    /// nothing, whatever the mode.
    ///
    /// With a real engine every call, and a drop, returns only after the
    /// engine's tunnel thread has ended and the device is gone, so the caller
    /// may clean up routes or open a new tunnel straight away. That is a rule
    /// for the real engine; the fake has no thread or device to show it.
    fn close(&self, how: CloseMode);
}
