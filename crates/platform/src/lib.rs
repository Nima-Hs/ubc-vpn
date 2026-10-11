//! The OS seam.
//!
//! Everything that differs between Windows, macOS and Linux sits behind the
//! traits in this file: [`Routes`], [`Dns`], [`NetworkEvents`] and
//! [`Transport`], plus the well-known [`Paths`]. [`Platform`] bundles them.
//! Each OS gets a real implementation; [`fake`] is an in-memory one for tests
//! and for the service's dev mode. No other crate contains OS-specific code.
//!
//! The rules every implementation keeps (the shared checks are in [`suite`]):
//!
//! - **Teardown is always safe.** Every `add_*` or `set_*` has a `remove_*` or
//!   `clear_*` that succeeds when there is nothing to remove.
//! - **The physical network is captured once,** before the tunnel exists, as a
//!   [`PhysicalNetwork`] the caller holds and passes back. Nothing here looks
//!   it up again from a routing table that may already contain the tunnel.
//! - **Checks answer three ways.** A [`Verified`] of anything but `Yes` is a
//!   failure; `Unknown` is never a "probably fine".
//! - **Nothing polls and nothing is async.** Calls block; events are pushed by
//!   the OS and arrive on a standard channel.
//! - **Error messages never contain a secret.**
//!
//! The tunnel device itself is created by the VPN engine. This crate only
//! ever receives its interface name.

use std::fmt;
use std::io::{self, BufRead, Read};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::mpsc::Receiver;

use ubc_vpn_core::protocol::MAX_LINE_BYTES;
use ubc_vpn_core::routes::Ipv4Net;

pub mod fake;
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
    /// A line was longer than [`MAX_LINE_BYTES`]. Drop the connection.
    LineTooLong,
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
            Self::LineTooLong => "line too long",
            Self::Failed(message) => message,
        })
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::PermissionDenied => Self::PermissionDenied,
            io::ErrorKind::NotFound => Self::NotFound,
            io::ErrorKind::AlreadyExists | io::ErrorKind::AddrInUse => Self::AlreadyExists,
            io::ErrorKind::Unsupported => Self::Unsupported,
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
/// Only [`Routes::capture_physical`] produces one, and there is deliberately
/// no other way to build it: the caller captures it before the tunnel exists
/// and passes the same value back for the life of the connection.
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
pub trait Routes: Send + Sync {
    /// Records how the OS reaches `gateway` right now. Call it once, before
    /// the tunnel device exists; called later it could describe the tunnel.
    fn capture_physical(&self, gateway: Ipv4Addr) -> Result<PhysicalNetwork>;

    /// Routes the one address `gateway` through the physical network, so
    /// traffic to the gateway never enters its own tunnel. Succeeds if the
    /// route is already there.
    fn add_gateway_route(&self, gateway: Ipv4Addr, via: &PhysicalNetwork) -> Result<()>;

    /// Removes that route. Succeeds if it is not there.
    fn remove_gateway_route(&self, gateway: Ipv4Addr, via: &PhysicalNetwork) -> Result<()>;

    /// Routes `subnets` through the interface named `tunnel`. Never disturbs a
    /// gateway route, even when a subnet contains the gateway. Succeeds for
    /// routes already there. On error some may have been added: remove them.
    fn add_tunnel_routes(&self, tunnel: &str, subnets: &[Ipv4Net]) -> Result<()>;

    /// Removes those routes. Succeeds for any that are not there, and when
    /// the interface no longer exists.
    fn remove_tunnel_routes(&self, tunnel: &str, subnets: &[Ipv4Net]) -> Result<()>;

    /// Asks the OS which interface it would really use to reach `dest`, and
    /// whether that is `interface`.
    fn uses_interface(&self, dest: Ipv4Addr, interface: &str) -> Verified;
}

/// Resolvers that answer for some domains only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitDns {
    /// The resolvers, reached through the tunnel.
    pub resolvers: Vec<Ipv4Addr>,
    /// The domains they answer for, such as `ece.ubc.ca`. Every other name
    /// keeps using the system's resolvers.
    pub domains: Vec<String>,
}

/// Split DNS. There is at most one tunnel, so at most one setting.
pub trait Dns: Send + Sync {
    /// Sends lookups for `dns.domains` to `dns.resolvers` on the interface
    /// named `tunnel`, replacing whatever this app set before.
    fn set_split_dns(&self, tunnel: &str, dns: &SplitDns) -> Result<()>;

    /// Removes any split DNS this app set, including what an earlier run of
    /// the process left behind. Succeeds when nothing is set, so teardown and
    /// crash recovery call it unconditionally.
    fn clear_split_dns(&self) -> Result<()>;

    /// Whether exactly `dns` is in effect on `tunnel`.
    fn split_dns_matches(&self, tunnel: &str, dns: &SplitDns) -> Verified;
}

/// Something the OS reported about the machine's network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkEvent {
    /// The physical network changed. A [`PhysicalNetwork`] captured earlier
    /// is no longer valid.
    PhysicalChanged,
    /// The system is about to sleep.
    Sleeping,
    /// The system woke up.
    Woke,
}

/// Notifications pushed by the OS. There is no way to poll.
pub trait NetworkEvents: Send + Sync {
    /// Starts delivering events. Dropping the receiver ends the subscription.
    fn subscribe(&self) -> Result<Receiver<NetworkEvent>>;
}

/// An OS user: a SID on Windows, a numeric user ID elsewhere.
///
/// Opaque. Two values are equal exactly when they name the same user. It
/// converts to and from a string so the owner can be kept in `state.json`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UserId(String);

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for UserId {
    type Err = Error;

    /// Refuses an empty string, which could never name a user.
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "" => Err(Error::Failed("empty user identity".to_string())),
            _ => Ok(Self(s.to_string())),
        }
    }
}

/// The channel's transport: a named pipe on Windows, a Unix socket elsewhere.
pub trait Transport: Send + Sync {
    /// Claims `name` and starts listening. The claim is exclusive: it fails
    /// with [`Error::AlreadyExists`] while any other process holds the name.
    /// Only programs on this machine can connect; remote clients are refused.
    fn listen(&self, name: &str) -> Result<Box<dyn Listener>>;

    /// Connects to the service listening on `name`. Fails with
    /// [`Error::NotFound`] when nothing listens there and with
    /// [`Error::PermissionDenied`] when the channel is narrowed to another
    /// user.
    fn connect(&self, name: &str) -> Result<Box<dyn Connection>>;
}

/// The service's end of the channel. Dropping it releases the name.
pub trait Listener: Send + Sync {
    /// Waits for the next connection and reports who is calling. The identity
    /// comes from the OS, not from anything the caller sent.
    fn accept(&self) -> Result<(Box<dyn Connection>, UserId)>;

    /// Narrows the channel so the OS itself refuses every user but `owner`.
    /// Applies to connections made from now on. May be called while another
    /// thread waits in [`Listener::accept`].
    fn restrict_to(&self, owner: &UserId) -> Result<()>;
}

/// One end of a channel connection, carrying whole lines of text.
///
/// One thread may read while another writes.
pub trait Connection: Send + Sync {
    /// Waits for the next line and returns it without its newline, or `None`
    /// when the peer closed the connection. Fails with [`Error::LineTooLong`]
    /// past [`MAX_LINE_BYTES`], without buffering the rest; the connection is
    /// then unusable and must be dropped.
    fn read_line(&self) -> Result<Option<String>>;

    /// Sends one line. Refuses a line that is too long or contains a newline,
    /// and sends nothing in that case.
    fn write_line(&self, line: &str) -> Result<()>;
}

/// Reads one line the way every [`Connection`] must: at most
/// [`MAX_LINE_BYTES`] are taken from `reader`, newline included.
pub fn read_line(reader: &mut impl BufRead) -> Result<Option<String>> {
    let mut line = Vec::new();
    let read = reader
        .take(MAX_LINE_BYTES as u64)
        .read_until(b'\n', &mut line)?;
    match line.pop() {
        None => Ok(None),
        Some(b'\n') => String::from_utf8(line)
            .map(Some)
            .map_err(|_| Error::Failed("line is not UTF-8".to_string())),
        Some(_) if read == MAX_LINE_BYTES => Err(Error::LineTooLong),
        Some(_) => Err(Error::Failed("connection closed mid-line".to_string())),
    }
}

/// Turns `line` into the bytes every [`Connection`] must send for it: the
/// line and one newline. Refuses a line the peer would reject.
pub fn encode_line(line: &str) -> Result<Vec<u8>> {
    if line.len() >= MAX_LINE_BYTES {
        return Err(Error::LineTooLong);
    }
    if line.contains('\n') {
        return Err(Error::Failed("line contains a newline".to_string()));
    }
    Ok([line.as_bytes(), b"\n"].concat())
}

/// Whether the program runs as the installed product or in dev mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// The installed service and its clients.
    Installed,
    /// A developer's unprivileged run. Everything lives in per-user places
    /// that can never collide with the installed product's.
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
    /// The real implementation for the OS this was built for.
    pub fn native(mode: Mode) -> Result<Self> {
        Ok(Self {
            routes: Arc::new(os::Native),
            dns: Arc::new(os::Native),
            events: Arc::new(os::Native),
            transport: Arc::new(os::Native),
            paths: os::paths(mode)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line_of(len: usize) -> Vec<u8> {
        [vec![b'a'; len - 1], vec![b'\n']].concat()
    }

    // Security rule: a line over the limit is rejected, and no more than the
    // limit is taken from the reader to find that out.
    #[test]
    fn an_oversized_line_is_rejected_without_reading_it_all() {
        let mut at_limit = &line_of(MAX_LINE_BYTES)[..];
        let line = read_line(&mut at_limit).unwrap().unwrap();
        assert_eq!(line.len(), MAX_LINE_BYTES - 1);

        let bytes = line_of(2 * MAX_LINE_BYTES);
        let mut over = &bytes[..];
        assert_eq!(read_line(&mut over), Err(Error::LineTooLong));
        assert_eq!(over.len(), bytes.len() - MAX_LINE_BYTES);
    }

    #[test]
    fn reads_lines_then_end_of_stream() {
        let mut input = &b"one\ntwo\nthr"[..];
        assert_eq!(read_line(&mut input), Ok(Some("one".to_string())));
        assert_eq!(read_line(&mut input), Ok(Some("two".to_string())));
        assert!(matches!(read_line(&mut input), Err(Error::Failed(_))));
        assert_eq!(read_line(&mut input), Ok(None));
    }

    // Security rule: nothing is sent that the peer's limit would reject, and
    // one call can never smuggle a second message.
    #[test]
    fn refuses_to_encode_an_oversized_or_multi_line_message() {
        assert_eq!(encode_line("{}"), Ok(b"{}\n".to_vec()));
        let longest = "a".repeat(MAX_LINE_BYTES - 1);
        assert_eq!(encode_line(&longest).unwrap().len(), MAX_LINE_BYTES);
        assert_eq!(encode_line(&format!("{longest}a")), Err(Error::LineTooLong));
        assert!(matches!(encode_line("{}\n{}"), Err(Error::Failed(_))));
    }

    #[test]
    fn user_ids_round_trip_through_strings() {
        let id: UserId = "S-1-5-21-1-2-3-1001".parse().unwrap();
        assert_eq!(id.to_string().parse::<UserId>().unwrap(), id);
        assert_ne!(id, "1001".parse().unwrap());
        assert!("".parse::<UserId>().is_err());
    }

    // Until an OS is implemented it must say so, not pretend to succeed, and
    // its checks must fail closed.
    #[test]
    fn the_unimplemented_os_reports_unsupported() {
        let gateway = Ipv4Addr::new(192, 0, 2, 1);
        assert_eq!(Platform::native(Mode::Dev).err(), Some(Error::Unsupported));
        assert_eq!(
            os::Native.capture_physical(gateway),
            Err(Error::Unsupported)
        );
        assert_eq!(os::Native.clear_split_dns(), Err(Error::Unsupported));
        assert_eq!(
            os::Native.uses_interface(gateway, "tun0"),
            Verified::Unknown
        );
        assert!(os::Native.subscribe().is_err());
        assert!(os::Native.listen("ubc-vpn-test").is_err());
    }
}
