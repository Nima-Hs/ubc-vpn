//! The OS seam.
//!
//! Everything that differs between Windows, macOS and Linux sits behind the
//! traits in this crate: [`Routes`], [`Dns`], [`NetworkEvents`] and
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
//! - **Checks fail closed.** A [`Verified`] of anything but `Yes` is a
//!   failure; `Unknown` is never a "probably fine". The one exception is
//!   [`Verified::Unobservable`], which only [`Dns::split_dns_matches`] may
//!   answer and the service accepts for DNS alone.
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
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

#[cfg(doc)]
use ubc_vpn_core::protocol::MAX_LINE_BYTES;

mod channel;
#[cfg(any(test, feature = "fake"))]
pub mod fake;
pub mod interrupt;
mod network;
mod on_link;
#[cfg(feature = "secrets")]
pub mod secrets;
mod state_dir;
mod state_plain;
#[cfg(any(test, feature = "fake"))]
pub mod suite;
pub mod terminal;
#[cfg(unix)]
mod unix;
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

/// Registering the service and making its data folder, on Windows.
#[cfg(windows)]
pub use os::install;

/// Running as a Windows service, started by the service manager.
#[cfg(windows)]
pub use os::service;

/// The installed service's check of the folder it runs from, on Windows.
#[cfg(windows)]
pub use os::program;

pub use channel::{Connection, Listener, RawConnection, Transport, UserId};
pub use network::{
    Dns, FULL_TUNNEL_V4, FULL_TUNNEL_V6, Ipv6Block, LINUX_ROUTE_PROTOCOL, NetworkEvent,
    NetworkEvents, PhysicalNetwork, Routes, SplitDns, Subscription, SubscriptionEnd, TUNNEL_MTU,
};
pub use state_dir::{Mode, Paths, StateDir};

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
    /// The name is taken, such as a channel another process already holds,
    /// or the destination is: a route to it exists through another
    /// interface or next hop.
    AlreadyExists,
    /// An argument is outside the range the operation accepts, such as a
    /// packet size. Nothing was changed.
    InvalidInput,
    /// Something listens on the channel, but it is not the service. Nothing
    /// was sent to it. Trying again will not help until the real service
    /// holds the name.
    NotTheService,
    /// There is no terminal to ask the user in: input is redirected and the
    /// program has no terminal of its own, as in a service or under CI.
    NotATerminal,
    /// The user pressed Ctrl-C at a question asked in the terminal.
    Interrupted,
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
            Self::InvalidInput => "a value is out of range",
            Self::NotTheService => "the channel is held by a program that is not the service",
            Self::NotATerminal => "there is no terminal to ask in",
            Self::Interrupted => "the user pressed Ctrl-C at a question",
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
/// treats `No` and `Unknown` as failure, and `Unobservable` as failure for
/// everything but split DNS.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verified {
    /// The OS confirmed it.
    Yes,
    /// The OS reported something else.
    No,
    /// The OS could not be asked, or its answer could not be understood.
    Unknown,
    /// For [`Dns::split_dns_matches`] only: this product's rules read back
    /// exactly as set, no rules from group policy exist, and the OS has no
    /// way to show whether its resolver took them in. Only Windows answers
    /// this, where another OS would answer `Yes`; Linux and macOS never do
    /// (see [`Dns::split_dns_matches`]). An implementation that could not
    /// read its rules back answers `Unknown`; one whose rules differ, or that
    /// finds rules from group policy, answers `No`. No route check ever
    /// answers it.
    Unobservable,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
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
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    // Until an OS is implemented it must say so, not pretend to succeed, and
    // its checks must fail closed. Every method is listed.
    #[test]
    fn the_unimplemented_os_reports_unsupported() {
        use unsupported::Native;

        let unsupported = Some(Error::Unsupported);
        let gateway = Ipv4Addr::new(192, 0, 2, 1);
        let physical = PhysicalNetwork {
            interface: "eth0".to_string(),
            next_hop: None,
            own_addresses: Vec::new(),
            on_link: Vec::new(),
        };
        let subnets = ["192.0.2.0/24".parse().unwrap()];
        let dns = SplitDns {
            resolvers: vec![gateway],
            domains: vec!["dept.example".to_string()],
        };

        assert_eq!(Native.capture_physical(gateway).err(), unsupported);
        let results = [
            Native.configure_tunnel("tun0", gateway, 1300),
            Native.add_gateway_route(gateway, &physical),
            Native.remove_gateway_route(gateway, &physical),
            Native.add_tunnel_routes("tun0", &subnets),
            Native.remove_tunnel_routes("tun0", &subnets),
            Native.remove_all(),
            Native.set_split_dns("tun0", &dns),
            Native.clear_split_dns(),
            Native.remove_full_tunnel("tun0"),
            Native.set_catch_all_dns(&[gateway]),
            Native.clear_catch_all_dns(),
        ];
        assert_eq!(results, [const { Err(Error::Unsupported) }; 11]);
        assert_eq!(Native.add_full_tunnel("tun0").err(), unsupported);
        assert_eq!(Native.full_tunnel_ipv6("tun0").err(), unsupported);
        assert_eq!(Native.foreign_full_tunnel("tun0").err(), unsupported);
        assert_eq!(Native.foreign_catch_all().err(), unsupported);
        assert_eq!(Native.uses_interface(gateway, "tun0"), Verified::Unknown);
        let v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        assert_eq!(Native.uses_interface_v6(v6, "tun0"), Verified::Unknown);
        assert_eq!(Native.split_dns_matches(&dns), Verified::Unknown);
        assert_eq!(Native.catch_all_dns_matches(&[gateway]), Verified::Unknown);
        assert_eq!(Native.subscribe(&physical).err(), unsupported);
        // Full mode is refused where IPv6 changes cannot be watched.
        assert!(!Native.reports_ipv6_changes());
        assert_eq!(Native.listen("ubc-vpn-test").err(), unsupported);
        assert_eq!(Native.connect("ubc-vpn-test").err(), unsupported);
    }

    // Windows has a real channel and real paths. Everything else there must
    // still say it is unsupported, and its checks must still fail closed.
    #[cfg(windows)]
    #[test]
    fn windows_implements_the_channel_routes_dns_and_events() {
        let gateway = Ipv4Addr::new(192, 0, 2, 1);
        let physical = PhysicalNetwork {
            interface: "eth0".to_string(),
            next_hop: None,
            own_addresses: Vec::new(),
            on_link: Vec::new(),
        };
        let dns = SplitDns {
            resolvers: vec![gateway],
            domains: vec!["dept.example".to_string()],
        };
        let modes = [
            Mode::Installed,
            #[cfg(feature = "dev-mode")]
            Mode::Dev,
        ];
        for mode in modes {
            let native = Platform::native(mode).expect("a platform");
            // Routes are real: reading the table needs no rights. A device
            // that does not exist is not used.
            assert!(native.routes.capture_physical(gateway).is_ok());
            // Full mode needs IPv6 changes reported, which Windows does.
            assert!(native.events.reports_ipv6_changes());
            let routed = native.routes.uses_interface(gateway, "ubc-vpn-no-such0");
            assert_eq!(routed, Verified::No);
            // Split DNS is real: nothing of ours is set, and reading that
            // needs no rights.
            assert_eq!(native.dns.split_dns_matches(&dns), Verified::No);
            // Full mode is real: a device that does not exist cannot take
            // it, and the read-only checks need no rights. Nothing here
            // writes anything.
            assert_eq!(
                native.routes.add_full_tunnel("ubc-vpn-no-such0").err(),
                Some(Error::NotFound)
            );
            assert_eq!(
                native.routes.full_tunnel_ipv6("ubc-vpn-no-such0").err(),
                Some(Error::NotFound)
            );
            assert!(
                native
                    .routes
                    .foreign_full_tunnel("ubc-vpn-no-such0")
                    .is_ok()
            );
            assert!(native.dns.foreign_catch_all().is_ok());
            let v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
            let routed = native.routes.uses_interface_v6(v6, "ubc-vpn-no-such0");
            assert_eq!(routed, Verified::No);
            assert_eq!(native.dns.catch_all_dns_matches(&[gateway]), Verified::No);
            // Events are real: an interface that does not exist cannot be
            // watched.
            assert_eq!(
                native.events.subscribe(&physical).err(),
                Some(Error::NotFound)
            );
            // Nothing listens on this name, and the transport can tell.
            let absent = native.transport.connect("ubc-vpn-test-nobody-listens");
            assert_eq!(absent.err(), Some(Error::NotFound));
        }
    }
}
