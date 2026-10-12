//! The OS seam.
//!
//! Everything that differs between Windows, macOS and Linux sits behind the
//! traits in this file: [`Routes`], [`Dns`], [`NetworkEvents`] and
//! [`Transport`], plus the well-known [`Paths`]. [`Platform`] bundles them.
//! Each OS gets a real implementation. The `fake` feature adds an in-memory
//! one (`fake`) for tests and for the service's dev mode, and the checks every
//! implementation must pass (`suite`). No other crate contains OS-specific
//! code.
//!
//! The rules every implementation keeps. The suite checks those that can be
//! observed from outside; the rest are promises each implementation's own
//! tests must cover.
//!
//! - **Teardown is always safe.** Every `add_*` or `set_*` has a `remove_*` or
//!   `clear_*` that succeeds when there is nothing to remove, and
//!   [`Routes::remove_all`] and [`Dns::clear_split_dns`] undo everything this
//!   product applied, even in an earlier run that crashed.
//! - **The physical network is captured once,** before the tunnel exists, as a
//!   [`PhysicalNetwork`] the caller holds and passes back. Nothing here looks
//!   it up again from a routing table that may already contain the tunnel.
//! - **Checks answer three ways.** A [`Verified`] of anything but `Yes` is a
//!   failure; `Unknown` is never a "probably fine".
//! - **Nothing polls and nothing is async.** Calls block; events are pushed by
//!   the OS and arrive on a standard channel. Blocking channel calls can be
//!   ended from another thread or by a timeout.
//! - **The line limit cannot be skipped.** An implementation supplies raw
//!   bytes ([`RawConnection`]); [`Connection`], which this crate owns, turns
//!   them into lines.
//! - **Error messages never contain a secret.**
//!
//! The tunnel device itself is created by the VPN engine. This crate only
//! ever receives its interface name.

use std::fmt;
use std::io;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use ubc_vpn_core::protocol::MAX_LINE_BYTES;
use ubc_vpn_core::routes::Ipv4Net;

#[cfg(any(test, feature = "fake"))]
pub mod fake;
#[cfg(any(test, feature = "fake"))]
pub mod suite;
mod unsupported;

#[cfg(target_os = "linux")]
#[path = "linux/mod.rs"]
mod os;
#[cfg(target_os = "macos")]
#[path = "macos/mod.rs"]
mod os;
#[cfg(target_os = "windows")]
#[path = "windows/mod.rs"]
mod os;

/// Why an operation did not happen. The set is closed, so a caller can match
/// on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// This OS, or this build, cannot do it.
    Unsupported,
    /// The OS refused: the process lacks the rights, or the caller is not the
    /// user a channel was narrowed to.
    PermissionDenied,
    /// The thing acted on does not exist, such as a channel nobody listens on.
    NotFound,
    /// The name is taken, such as a channel another process already holds.
    AlreadyExists,
    /// Something listens on the channel, but it is not the service. Nothing
    /// was sent to it. Trying again will not help until the real service
    /// holds the name.
    NotTheService,
    /// A line was longer than [`MAX_LINE_BYTES`]. Drop the connection.
    LineTooLong,
    /// A whole line did not arrive within the read timeout, or the peer did
    /// not take a line within the write timeout. What a read had received so
    /// far is kept; a write that timed out closes the connection.
    TimedOut,
    /// The connection or listener was closed, by this side or the other.
    Closed,
    /// Anything else. The message is for a log or the user and never contains
    /// a secret.
    Failed(String),
}

/// The result of an operation in this crate.
pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unsupported => "not supported on this system",
            Self::PermissionDenied => "permission denied",
            Self::NotFound => "not found",
            Self::AlreadyExists => "already exists",
            Self::NotTheService => "the channel is held by a program that is not the service",
            Self::LineTooLong => "line too long",
            Self::TimedOut => "timed out",
            Self::Closed => "closed",
            Self::Failed(message) => message,
        })
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        use io::ErrorKind as Kind;
        match error.kind() {
            Kind::PermissionDenied => Self::PermissionDenied,
            Kind::NotFound => Self::NotFound,
            Kind::AlreadyExists | Kind::AddrInUse => Self::AlreadyExists,
            Kind::Unsupported => Self::Unsupported,
            Kind::TimedOut | Kind::WouldBlock => Self::TimedOut,
            Kind::BrokenPipe | Kind::ConnectionReset | Kind::ConnectionAborted => Self::Closed,
            kind => Self::Failed(kind.to_string()),
        }
    }
}

/// The answer to "is this in effect?". Only `Yes` means yes: the service
/// treats both other answers as failure.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verified {
    /// The OS confirmed it.
    Yes,
    /// The OS reported something else.
    No,
    /// The OS could not be asked, or its answer could not be understood.
    Unknown,
}

/// The network the machine uses without the tunnel: an interface and the next
/// hop on it.
///
/// Only [`Routes::capture_physical`] produces one. There is deliberately no
/// other way to build it and no way to store it: the caller captures it before
/// the tunnel exists and passes the same value back for the life of the
/// connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhysicalNetwork {
    pub(crate) interface: String,
    pub(crate) next_hop: Option<Ipv4Addr>,
}

impl PhysicalNetwork {
    /// The interface's name.
    pub fn interface(&self) -> &str {
        &self.interface
    }

    /// The router traffic is handed to, or `None` when destinations are
    /// reached directly on the link.
    pub fn next_hop(&self) -> Option<Ipv4Addr> {
        self.next_hop
    }
}

/// The routing table. IPv4 only; IPv6 is never touched.
///
/// An implementation must mark or record every route **when it adds it**, so
/// that [`Routes::remove_all`] can find it later, even from a new process
/// after a crash: a private route protocol value on Linux, a route flag on
/// macOS, an admin-only journal in the state folder on Windows.
pub trait Routes: Send + Sync {
    /// Records how the OS reaches `gateway` right now. Call it once, before
    /// the tunnel device exists: called later it could describe the tunnel,
    /// so an implementation may refuse when it can tell.
    fn capture_physical(&self, gateway: Ipv4Addr) -> Result<PhysicalNetwork>;

    /// Routes the one address `gateway` through the physical network, so
    /// traffic to the gateway never enters its own tunnel. Succeeds if the
    /// route is already there.
    fn add_gateway_route(&self, gateway: Ipv4Addr, via: &PhysicalNetwork) -> Result<()>;

    /// Removes that route. Succeeds if it is not there, and when the physical
    /// interface no longer exists.
    fn remove_gateway_route(&self, gateway: Ipv4Addr, via: &PhysicalNetwork) -> Result<()>;

    /// Routes `subnets` through the interface named `tunnel`. Never disturbs a
    /// gateway route, even when a subnet contains the gateway. Succeeds for
    /// routes already there. On error some may have been added: remove them.
    fn add_tunnel_routes(&self, tunnel: &str, subnets: &[Ipv4Net]) -> Result<()>;

    /// Removes those routes and nothing else; a gateway route stays. Succeeds
    /// for any that are not there, and when the interface no longer exists.
    fn remove_tunnel_routes(&self, tunnel: &str, subnets: &[Ipv4Net]) -> Result<()>;

    /// Removes every route this product added, in this run or an earlier one.
    /// Succeeds when there are none. The service calls it at start-up and as
    /// the last step of every teardown.
    fn remove_all(&self) -> Result<()>;

    /// Asks the OS which interface it would really use to reach `dest`, and
    /// whether that is `interface`.
    fn uses_interface(&self, dest: Ipv4Addr, interface: &str) -> Verified;
}

/// Resolvers that answer for some domains only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitDns {
    /// The resolvers. They are reached by ordinary routing, so the caller
    /// must route them through the tunnel and check that with
    /// [`Routes::uses_interface`].
    pub resolvers: Vec<Ipv4Addr>,
    /// The domains they answer for, such as `ece.ubc.ca`. Every other name
    /// keeps using the system's resolvers.
    pub domains: Vec<String>,
}

/// Split DNS. There is at most one tunnel, so at most one setting.
pub trait Dns: Send + Sync {
    /// Sends lookups for `dns.domains` to `dns.resolvers`, replacing whatever
    /// this product set before. `tunnel` tells an OS that attaches DNS to an
    /// interface where to attach it; Windows has no such notion and ignores
    /// it.
    fn set_split_dns(&self, tunnel: &str, dns: &SplitDns) -> Result<()>;

    /// Removes any split DNS this product set, including what an earlier run
    /// of the process left behind. Succeeds when nothing is set, so teardown
    /// and crash recovery call it unconditionally.
    fn clear_split_dns(&self) -> Result<()>;

    /// Whether the split DNS this product set is in effect and is exactly
    /// `dns`: these domains, these resolvers, nothing more. The interface is
    /// not part of the question, so the answer means the same on every OS.
    fn split_dns_matches(&self, dns: &SplitDns) -> Verified;
}

/// Something the OS reported about the machine's network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkEvent {
    /// The physical network being watched changed or went away. The
    /// [`PhysicalNetwork`] is no longer valid.
    PhysicalChanged,
    /// The system is about to sleep.
    Sleeping,
    /// The system woke up.
    Woke,
}

/// Notifications pushed by the OS. There is no way to poll.
pub trait NetworkEvents: Send + Sync {
    /// Starts delivering events about `watching`. Dropping the receiver ends
    /// the subscription.
    ///
    /// [`NetworkEvent::PhysicalChanged`] is sent only for a change to
    /// `watching` itself. It is never sent for a route this product added or
    /// removed, nor for anything that happens to the tunnel interface.
    fn subscribe(&self, watching: &PhysicalNetwork) -> Result<Receiver<NetworkEvent>>;
}

/// An OS user, as text in one canonical form: the decimal user ID with no
/// leading zeros on macOS and Linux (`1001`), the upper-case SID string on
/// Windows (`S-1-5-21-…`).
///
/// Values are compared as text. Implementations only ever produce the
/// canonical form, so the same user always compares equal; any other spelling
/// of the same user compares unequal, which refuses rather than admits.
///
/// A `UserId` must only come from [`Listener::accept`] or from the service's
/// own state file. Never build one from anything a client sent.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UserId(String);

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for UserId {
    type Err = Error;

    /// Reads back a value written with `to_string`. Accepts printable ASCII
    /// only, with no spaces, so no two values can look alike.
    fn from_str(s: &str) -> Result<Self> {
        if s.is_empty() || !s.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(Error::Failed("not a user identity".to_string()));
        }
        Ok(Self(s.to_string()))
    }
}

/// The channel's transport: a named pipe on Windows, a Unix socket elsewhere.
///
/// A transport is built for one [`Mode`] by [`Platform::native`], which is how
/// it knows what [`Transport::connect`] has to verify.
pub trait Transport: Send + Sync {
    /// Claims `name` and starts listening. The claim is exclusive: it fails
    /// with [`Error::AlreadyExists`] while any other listener holds the name.
    /// Only programs on this machine can connect; remote clients are refused.
    fn listen(&self, name: &str) -> Result<Box<dyn Listener>>;

    /// Connects to the service listening on `name`. Fails with
    /// [`Error::NotFound`] when nothing listens there and with
    /// [`Error::PermissionDenied`] when the channel is narrowed to another
    /// user.
    ///
    /// In [`Mode::Installed`] it must also refuse a listener that is not the
    /// privileged service, such as another local user who claimed the name
    /// while the service was down, with [`Error::NotTheService`] and before
    /// anything is sent. It must never lend the caller's identity to the
    /// listener. On Windows that means checking the pipe's owner and
    /// allowing identification-level impersonation only; elsewhere, a socket
    /// in a folder only root can write.
    fn connect(&self, name: &str) -> Result<Connection>;
}

/// The service's end of the channel. Dropping it closes it.
pub trait Listener: Send + Sync {
    /// Waits for the next connection and reports who is calling. The identity
    /// comes from the OS, not from anything the caller sent. Fails with
    /// [`Error::Closed`] once the listener is closed.
    fn accept(&self) -> Result<(Connection, UserId)>;

    /// Narrows the channel so the OS itself refuses every user but `owner`,
    /// replacing any earlier narrowing. May be called while another thread
    /// waits in [`Listener::accept`].
    ///
    /// The system's own administrative accounts are never shut out by this:
    /// on Windows, SYSTEM and Administrators can still connect. Before any
    /// narrowing, Windows admits users who are logged on interactively, which
    /// leaves out sessions such as SSH, services and scheduled tasks; the
    /// first claim cannot come from one of those.
    ///
    /// It only affects connections made afterwards. One already accepted, or
    /// already waiting to be accepted, stays attached whoever made it. So the
    /// service must still compare the caller's [`UserId`] with the owner on
    /// every request, and close other users' connections once an owner
    /// exists.
    fn restrict_to(&self, owner: &UserId) -> Result<()>;

    /// Stops listening and releases the name. An [`Listener::accept`] waiting
    /// on another thread returns [`Error::Closed`]. Closing twice is fine.
    ///
    /// Connections already accepted may be closed too: Windows cannot
    /// release the name while they are open. So close the listener only when
    /// shutting down, never to turn new callers away while keeping old ones.
    fn close(&self);
}

/// The bytes of one channel connection, as an OS implementation provides
/// them. Only [`Connection`] calls this; nothing else reads or writes a
/// channel. Dropping it closes it.
pub trait RawConnection: Send + Sync {
    /// Waits for bytes and copies up to `buf.len()` of them. `Ok(0)` means
    /// the peer closed. Fails with [`Error::TimedOut`] when the read timeout
    /// passes first.
    fn read(&self, buf: &mut [u8]) -> Result<usize>;

    /// Sends all of `bytes`. Fails with [`Error::TimedOut`] when the peer
    /// has not taken them all within the write timeout.
    fn write_all(&self, bytes: &[u8]) -> Result<()>;

    /// Sets how long each later [`RawConnection::read`] waits; `None` waits
    /// for ever. Never called with zero.
    fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<()>;

    /// Sets how long each later [`RawConnection::write_all`] may take as a
    /// whole; `None` waits for ever. Never called with zero.
    fn set_write_timeout(&self, timeout: Option<Duration>) -> Result<()>;

    /// Closes both directions. A `read` or `write_all` waiting on another
    /// thread returns promptly, with any result, and one started afterwards
    /// returns at once. Closing twice is fine.
    fn close(&self);
}

/// One end of a channel connection, carrying whole lines of text.
///
/// Any number of threads may share it: one line is read at a time, and lines
/// written from different threads never mix.
pub struct Connection {
    raw: Box<dyn RawConnection>,
    reading: Mutex<Reading>,
    writing: Mutex<()>,
    read_timeout: Mutex<Option<Duration>>,
    write_timeout: Mutex<Option<Duration>>,
    closed: AtomicBool,
}

#[derive(Default)]
struct Reading {
    /// Bytes received and not yet returned. Never more than the line limit.
    pending: Vec<u8>,
    too_long: bool,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Refuses a timeout of zero, which could only ever fail.
fn nonzero(timeout: Option<Duration>) -> Result<Option<Duration>> {
    match timeout {
        Some(Duration::ZERO) => Err(Error::Failed("a timeout cannot be zero".to_string())),
        timeout => Ok(timeout),
    }
}

impl Connection {
    /// Wraps an implementation's bytes. Every [`Transport`] and [`Listener`]
    /// hands out connections made here, so none can skip the line rules.
    pub fn new(raw: Box<dyn RawConnection>) -> Self {
        Self {
            raw,
            reading: Mutex::default(),
            writing: Mutex::default(),
            read_timeout: Mutex::default(),
            write_timeout: Mutex::default(),
            closed: AtomicBool::new(false),
        }
    }

    /// Waits for the next line and returns it without its newline, or `None`
    /// when the peer closed the connection.
    ///
    /// A line longer than [`MAX_LINE_BYTES`], newline included, fails with
    /// [`Error::LineTooLong`]: at most the limit is buffered before it is
    /// refused, and nothing beyond. Every read after it fails the same way,
    /// so the rest of that line is never mistaken for a message.
    ///
    /// Fails with [`Error::TimedOut`] when no whole line arrives within the
    /// read timeout; the part that did arrive is kept for the next call.
    /// Fails with [`Error::Closed`] after [`Connection::close`], even when
    /// lines had already arrived.
    pub fn read_line(&self) -> Result<Option<String>> {
        let mut reading = lock(&self.reading);
        if self.closed.load(Ordering::SeqCst) {
            return Err(Error::Closed);
        }
        if reading.too_long {
            return Err(Error::LineTooLong);
        }
        let deadline = lock(&self.read_timeout).map(|timeout| Instant::now() + timeout);
        let mut searched = 0;
        loop {
            let unsearched = &reading.pending[searched..];
            if let Some(at) = unsearched.iter().position(|byte| *byte == b'\n') {
                let mut line: Vec<u8> = reading.pending.drain(..=searched + at).collect();
                line.pop();
                let text = String::from_utf8(line);
                return text
                    .map(Some)
                    .map_err(|_| Error::Failed("line is not UTF-8".to_string()));
            }
            searched = reading.pending.len();
            if searched >= MAX_LINE_BYTES {
                *reading = Reading {
                    pending: Vec::new(),
                    too_long: true,
                };
                return Err(Error::LineTooLong);
            }
            let left = deadline.map(|at| at.saturating_duration_since(Instant::now()));
            if left.is_some_and(|left| left.is_zero()) {
                return Err(Error::TimedOut);
            }
            self.raw.set_read_timeout(left)?;
            let mut chunk = [0; 4096];
            let room = chunk.len().min(MAX_LINE_BYTES - searched);
            let read = self.raw.read(&mut chunk[..room]);
            if self.closed.load(Ordering::SeqCst) {
                return Err(Error::Closed);
            }
            match read? {
                0 if reading.pending.is_empty() => return Ok(None),
                0 => {
                    reading.pending.clear();
                    return Err(Error::Closed);
                }
                n => reading.pending.extend_from_slice(&chunk[..n]),
            }
        }
    }

    /// Sends one line, whole: lines from other threads go before or after it,
    /// never inside it. Refuses a line that is too long or contains a
    /// newline, and sends nothing in that case. Any other failure, including
    /// [`Error::TimedOut`] when the peer does not take the line within the
    /// write timeout, closes the connection, because part of the line may
    /// have been sent.
    pub fn write_line(&self, line: &str) -> Result<()> {
        let bytes = encode_line(line)?;
        let _writing = lock(&self.writing);
        if self.closed.load(Ordering::SeqCst) {
            return Err(Error::Closed);
        }
        let timeout = *lock(&self.write_timeout);
        let ready = self.raw.set_write_timeout(timeout);
        let sent = ready.and_then(|()| self.raw.write_all(&bytes));
        sent.inspect_err(|_| self.close())
    }

    /// Limits how long each later [`Connection::read_line`] waits for a whole
    /// line, however slowly its bytes arrive. `None`, the default, waits for
    /// ever. Zero is refused. The service sets one so a silent client cannot
    /// hold it up.
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        *lock(&self.read_timeout) = nonzero(timeout)?;
        Ok(())
    }

    /// Limits how long each later [`Connection::write_line`] waits for the
    /// peer to take the line. `None`, the default, waits for ever. Zero is
    /// refused. The service sets one so a client that never reads cannot hold
    /// a writer, and every writer waiting behind it, for ever.
    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        *lock(&self.write_timeout) = nonzero(timeout)?;
        Ok(())
    }

    /// Closes the connection. A [`Connection::read_line`] or
    /// [`Connection::write_line`] waiting on another thread returns
    /// [`Error::Closed`], and the peer sees the end of the stream. Closing
    /// twice is fine.
    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.raw.close();
    }

    /// For the suite only: lets it send bytes no `write_line` would.
    #[cfg(any(test, feature = "fake"))]
    pub(crate) fn raw(&self) -> &dyn RawConnection {
        &*self.raw
    }
}

/// The bytes sent for `line`: the line and one newline. Refuses a line the
/// peer would reject.
fn encode_line(line: &str) -> Result<Vec<u8>> {
    if line.len() >= MAX_LINE_BYTES {
        return Err(Error::LineTooLong);
    }
    if line.contains('\n') {
        return Err(Error::Failed("line contains a newline".to_string()));
    }
    Ok([line.as_bytes(), b"\n"].concat())
}

/// Whether the program runs as the installed product or in dev mode.
///
/// Dev mode exists only when the crate is built with the `dev-mode` feature,
/// which a release build never enables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// The installed service and its clients.
    Installed,
    /// A developer's unprivileged run. Everything lives in per-user places
    /// that can never collide with the installed product's.
    #[cfg(feature = "dev-mode")]
    Dev,
}

/// Where the product's files and its channel live.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    /// The folder holding `policy.json`.
    pub policy_dir: PathBuf,
    /// The folder holding `state.json`.
    pub state_dir: PathBuf,
    /// The current user's folder holding `settings.json`.
    pub settings_dir: PathBuf,
    /// The pipe or socket name to pass to [`Transport`].
    pub channel_name: String,
}

/// Everything the service needs from the OS, in one value.
///
/// The parts are separate so dev mode can combine real ones with fakes.
#[derive(Clone)]
pub struct Platform {
    /// The routing table.
    pub routes: Arc<dyn Routes>,
    /// Split DNS.
    pub dns: Arc<dyn Dns>,
    /// Network change notifications.
    pub events: Arc<dyn NetworkEvents>,
    /// The channel's transport.
    pub transport: Arc<dyn Transport>,
    /// Well-known locations.
    pub paths: Paths,
}

impl Platform {
    /// The real implementation for the OS this was built for, set up for
    /// `mode`.
    pub fn native(mode: Mode) -> Result<Self> {
        os::native(mode)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Condvar;
    use std::sync::atomic::AtomicUsize;
    use std::thread;

    use super::*;

    /// A raw connection that plays back `input` at most `step` bytes at a
    /// time, counts what was taken from it, and keeps what was written. Its
    /// writes can be made to fail, or to wait as for a peer that never reads.
    #[derive(Default)]
    struct Script {
        input: Mutex<VecDeque<u8>>,
        step: usize,
        delay: Duration,
        taken: AtomicUsize,
        written: Mutex<Vec<u8>>,
        write_error: Option<Error>,
        stalled: bool,
        write_timeout: Mutex<Option<Duration>>,
        closed: Mutex<bool>,
        closing: Condvar,
    }

    fn script(input: &[u8], step: usize, delay: Duration) -> Arc<Script> {
        Arc::new(Script {
            input: Mutex::new(input.iter().copied().collect()),
            step,
            delay,
            ..Script::default()
        })
    }

    /// A connection whose peer never reads.
    fn stalled() -> Connection {
        Connection::new(Box::new(Arc::new(Script {
            stalled: true,
            ..Script::default()
        })))
    }

    fn connection(script: &Arc<Script>) -> Connection {
        Connection::new(Box::new(script.clone()))
    }

    impl RawConnection for Arc<Script> {
        fn read(&self, buf: &mut [u8]) -> Result<usize> {
            thread::sleep(self.delay);
            let mut input = lock(&self.input);
            let n = buf.len().min(self.step).min(input.len());
            for (slot, byte) in buf.iter_mut().zip(input.drain(..n)) {
                *slot = byte;
            }
            self.taken.fetch_add(n, Ordering::SeqCst);
            Ok(n)
        }

        // One byte at a time, so unguarded writers would interleave.
        fn write_all(&self, bytes: &[u8]) -> Result<()> {
            if let Some(error) = &self.write_error {
                return Err(error.clone());
            }
            if self.stalled {
                let timeout = lock(&self.write_timeout).unwrap_or(Duration::from_secs(5));
                let open = |closed: &mut bool| !*closed;
                let waited = self
                    .closing
                    .wait_timeout_while(lock(&self.closed), timeout, open);
                let (closed, _) = waited.unwrap();
                return Err(if *closed {
                    Error::Closed
                } else {
                    Error::TimedOut
                });
            }
            for byte in bytes {
                lock(&self.written).push(*byte);
                thread::yield_now();
            }
            Ok(())
        }

        fn set_read_timeout(&self, _timeout: Option<Duration>) -> Result<()> {
            Ok(())
        }

        fn set_write_timeout(&self, timeout: Option<Duration>) -> Result<()> {
            *lock(&self.write_timeout) = timeout;
            Ok(())
        }

        fn close(&self) {
            *lock(&self.closed) = true;
            self.closing.notify_all();
        }
    }

    // Closing means no more messages, even ones that had already arrived.
    #[test]
    fn a_closed_connection_returns_no_buffered_line() {
        let raw = script(b"first\nsecond\n", usize::MAX, Duration::ZERO);
        let connection = connection(&raw);
        assert_eq!(connection.read_line(), Ok(Some("first".to_string())));
        connection.close();
        assert_eq!(connection.read_line(), Err(Error::Closed));
    }

    // Part of a line may have gone out, so nothing more may follow it.
    #[test]
    fn a_failed_write_closes_the_connection() {
        let broken = Error::Failed("broken".to_string());
        let connection = Connection::new(Box::new(Arc::new(Script {
            input: Mutex::new(b"waiting\n".iter().copied().collect()),
            step: usize::MAX,
            write_error: Some(broken.clone()),
            ..Script::default()
        })));
        assert_eq!(connection.write_line("{}"), Err(broken));
        assert_eq!(connection.read_line(), Err(Error::Closed));
        assert_eq!(connection.write_line("{}"), Err(Error::Closed));
    }

    // Security rule: a client that never reads cannot hold a writer, or the
    // writers queued behind it, for ever.
    #[test]
    fn a_write_nobody_takes_times_out_and_closes() {
        let connection = stalled();
        let timeout = Some(Duration::from_millis(50));
        connection.set_write_timeout(timeout).unwrap();
        let started = Instant::now();
        assert_eq!(connection.write_line("{}"), Err(Error::TimedOut));
        assert!(started.elapsed() < Duration::from_secs(2), "not passed on");
        assert_eq!(connection.write_line("{}"), Err(Error::Closed));
    }

    #[test]
    fn close_ends_a_blocked_write_and_those_queued_behind_it() {
        let connection = stalled();
        thread::scope(|scope| {
            let writers = [(); 2].map(|()| scope.spawn(|| connection.write_line("{}")));
            thread::sleep(Duration::from_millis(50));
            connection.close();
            for writer in writers {
                assert_eq!(writer.join().unwrap(), Err(Error::Closed));
            }
        });
    }

    // A zero timeout could only ever fail, so it is refused, not stored.
    #[test]
    fn a_zero_timeout_is_refused() {
        let connection = connection(&script(b"waiting\n", usize::MAX, Duration::ZERO));
        let zero = Some(Duration::ZERO);
        assert!(matches!(
            connection.set_read_timeout(zero),
            Err(Error::Failed(_))
        ));
        assert!(matches!(
            connection.set_write_timeout(zero),
            Err(Error::Failed(_))
        ));
        assert_eq!(connection.read_line(), Ok(Some("waiting".to_string())));
        assert_eq!(connection.write_line("{}"), Ok(()));
    }

    // Security rule: the rest of an oversized line is never read as the next
    // message, and no more than the limit is taken in to find that out.
    #[test]
    fn an_oversized_line_poisons_the_connection() {
        let input = [vec![b'a'; MAX_LINE_BYTES], b"{\"smuggled\":1}\n".to_vec()].concat();
        let raw = script(&input, usize::MAX, Duration::ZERO);
        let connection = connection(&raw);
        assert_eq!(connection.read_line(), Err(Error::LineTooLong));
        assert_eq!(connection.read_line(), Err(Error::LineTooLong));
        assert_eq!(raw.taken.load(Ordering::SeqCst), MAX_LINE_BYTES);
    }

    #[test]
    fn reads_lines_up_to_the_limit_however_they_are_split() {
        let longest = "a".repeat(MAX_LINE_BYTES - 1);
        let input = format!("one\ntwo\n{longest}\nthr");
        for step in [1, 7, usize::MAX] {
            let connection = connection(&script(input.as_bytes(), step, Duration::ZERO));
            assert_eq!(connection.read_line(), Ok(Some("one".to_string())));
            assert_eq!(connection.read_line(), Ok(Some("two".to_string())));
            assert_eq!(connection.read_line(), Ok(Some(longest.clone())));
            // The peer went away in the middle of a line.
            assert_eq!(connection.read_line(), Err(Error::Closed));
            assert_eq!(connection.read_line(), Ok(None));
        }
    }

    // Security rule: nothing is sent that the peer's limit would reject, and
    // one call can never smuggle a second message.
    #[test]
    fn refuses_to_write_an_oversized_or_multi_line_message() {
        let raw = script(b"", 1, Duration::ZERO);
        let connection = connection(&raw);
        let longest = "a".repeat(MAX_LINE_BYTES - 1);
        assert_eq!(connection.write_line(&longest), Ok(()));
        assert_eq!(lock(&raw.written).len(), MAX_LINE_BYTES);
        let too_long = format!("{longest}a");
        assert_eq!(connection.write_line(&too_long), Err(Error::LineTooLong));
        assert!(matches!(
            connection.write_line("{}\n{}"),
            Err(Error::Failed(_))
        ));
        assert_eq!(lock(&raw.written).len(), MAX_LINE_BYTES);
    }

    // A reply and a pushed event are written by different threads. Neither
    // may land inside the other.
    #[test]
    fn lines_written_by_two_threads_never_interleave() {
        let raw = script(b"", 1, Duration::ZERO);
        let connection = connection(&raw);
        thread::scope(|scope| {
            for letter in ["a", "b"] {
                let connection = &connection;
                scope.spawn(move || {
                    for _ in 0..50 {
                        connection.write_line(&letter.repeat(200)).unwrap();
                    }
                });
            }
        });
        let written = String::from_utf8(lock(&raw.written).clone()).unwrap();
        assert_eq!(written.lines().count(), 100);
        for line in written.lines() {
            assert!(line == "a".repeat(200) || line == "b".repeat(200), "{line}");
        }
    }

    // Security rule: the timeout covers the whole line, so a client cannot
    // hold the service by sending one byte at a time.
    #[test]
    fn a_slow_line_times_out_as_a_whole() {
        let raw = script(&[b'a'; 1000], 1, Duration::from_millis(5));
        let connection = connection(&raw);
        let timeout = Some(Duration::from_millis(50));
        connection.set_read_timeout(timeout).unwrap();
        assert_eq!(connection.read_line(), Err(Error::TimedOut));
        assert!(raw.taken.load(Ordering::SeqCst) < 100);
    }

    #[test]
    fn a_closed_connection_refuses_reads_and_writes() {
        let connection = connection(&script(b"waiting\n", 1, Duration::ZERO));
        connection.close();
        assert_eq!(connection.read_line(), Err(Error::Closed));
        assert_eq!(connection.write_line("late"), Err(Error::Closed));
    }

    // Security rule: an identity is one exact piece of text. Anything that
    // could be confused with another spelling of it is refused or unequal.
    #[test]
    fn user_ids_round_trip_and_refuse_odd_text() {
        let id: UserId = "S-1-5-21-1-2-3-1001".parse().unwrap();
        assert_eq!(id.to_string().parse::<UserId>().unwrap(), id);
        assert_ne!("1001".parse::<UserId>(), "01001".parse::<UserId>());
        // Empty, spaces, controls, no-break space, zero-width space, a
        // right-to-left override, and full-width digits.
        let odd = [
            "",
            " 1001",
            "1001\n",
            "10 01",
            "1001\0",
            "1001\u{a0}",
            "1001\u{200b}",
            "\u{202e}1001",
            "\u{ff11}\u{ff10}\u{ff10}\u{ff11}",
        ];
        for odd in odd {
            assert!(odd.parse::<UserId>().is_err(), "{odd:?}");
        }
    }

    // Until an OS is implemented it must say so, not pretend to succeed, and
    // its checks must fail closed. Every method is listed.
    #[test]
    fn the_unimplemented_os_reports_unsupported() {
        use unsupported::Native;

        let unsupported = Some(Error::Unsupported);
        #[cfg(not(windows))]
        assert_eq!(Platform::native(Mode::Installed).err(), unsupported);
        #[cfg(all(not(windows), feature = "dev-mode"))]
        assert_eq!(Platform::native(Mode::Dev).err(), unsupported);
        let gateway = Ipv4Addr::new(192, 0, 2, 1);
        let physical = PhysicalNetwork {
            interface: "eth0".to_string(),
            next_hop: None,
        };
        let subnets = ["192.0.2.0/24".parse().unwrap()];
        let dns = SplitDns {
            resolvers: vec![gateway],
            domains: vec!["ece.example".to_string()],
        };

        assert_eq!(Native.capture_physical(gateway).err(), unsupported);
        let results = [
            Native.add_gateway_route(gateway, &physical),
            Native.remove_gateway_route(gateway, &physical),
            Native.add_tunnel_routes("tun0", &subnets),
            Native.remove_tunnel_routes("tun0", &subnets),
            Native.remove_all(),
            Native.set_split_dns("tun0", &dns),
            Native.clear_split_dns(),
        ];
        assert_eq!(results, [const { Err(Error::Unsupported) }; 7]);
        assert_eq!(Native.uses_interface(gateway, "tun0"), Verified::Unknown);
        assert_eq!(Native.split_dns_matches(&dns), Verified::Unknown);
        assert_eq!(Native.subscribe(&physical).err(), unsupported);
        assert_eq!(Native.listen("ubc-vpn-test").err(), unsupported);
        assert_eq!(Native.connect("ubc-vpn-test").err(), unsupported);
    }

    // Windows has a real channel and real paths. Everything else there must
    // still say it is unsupported, and its checks must still fail closed.
    #[cfg(windows)]
    #[test]
    fn windows_implements_the_channel_and_nothing_else_yet() {
        let unsupported = Some(Error::Unsupported);
        let gateway = Ipv4Addr::new(192, 0, 2, 1);
        let physical = PhysicalNetwork {
            interface: "eth0".to_string(),
            next_hop: None,
        };
        let dns = SplitDns {
            resolvers: vec![gateway],
            domains: vec!["ece.example".to_string()],
        };
        let modes = [
            Mode::Installed,
            #[cfg(feature = "dev-mode")]
            Mode::Dev,
        ];
        for mode in modes {
            let native = Platform::native(mode).expect("a platform");
            assert_eq!(native.routes.capture_physical(gateway).err(), unsupported);
            assert_eq!(native.routes.remove_all().err(), unsupported);
            let routed = native.routes.uses_interface(gateway, "tun0");
            assert_eq!(routed, Verified::Unknown);
            assert_eq!(native.dns.clear_split_dns().err(), unsupported);
            assert_eq!(native.dns.split_dns_matches(&dns), Verified::Unknown);
            assert_eq!(native.events.subscribe(&physical).err(), unsupported);
            // Nothing listens on this name, and the transport can tell.
            let absent = native.transport.connect("ubc-vpn-test-nobody-listens");
            assert_eq!(absent.err(), Some(Error::NotFound));
        }
    }
}
