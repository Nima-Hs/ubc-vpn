//! The routing table and the tunnel's address on macOS, through a routing
//! socket and the interface ioctls (`route_socket.rs`). Full mode is not
//! written yet: its operations report [`Error::Unsupported`] and its check
//! answers [`Verified::Unknown`].
//!
//! # Which routes count
//!
//! The kernel's table holds more than the routes that decide where traffic
//! goes, and every reading of it here leaves those out:
//!
//! - **Interface-scoped routes** (`RTF_IFSCOPE`), such as the default route
//!   every network service keeps for itself. Only a program that binds to
//!   an interface uses them.
//! - **Cloned routes** (`RTF_WASCLONED`): host routes the kernel makes from
//!   a route the first time a destination is used, to cache things about
//!   it. They follow the route they came from, may outlive a change to it
//!   for a moment, and the kernel deletes one by itself when a route is
//!   added in its place.
//! - **Neighbour entries** (`RTF_LLINFO`): the link-layer addresses of
//!   machines on the local network, which say whether a neighbour answered
//!   lately, not where traffic goes.
//!
//! What is left is matched as the kernel does: the longest prefix wins.
//! Without scoping and cloning there is one route per destination and
//! prefix, so there are no metrics to compare. A route out of an interface
//! that is not up and running never counts.
//!
//! # Which routes are ours
//!
//! As "Which routes are ours" in `network.rs` says, macOS marks each route
//! it adds and also writes it to the journal first. A route is removed only
//! when it matches a journal row exactly and carries the mark, [`OURS`].
//! The journal's LUID column holds the interface's index here. The kernel
//! refuses a second route to the same destination and prefix (`EEXIST`), so
//! an add reads the table first only to tell an identical route, which is
//! left alone and not ours, from one elsewhere, which is
//! [`Error::AlreadyExists`].
//!
//! # The boot the journal belongs to
//!
//! Two edge cases make the journal look like another boot's, or like this
//! one's, when it is not. Both fail safe:
//!
//! - A restart of the machine so fast that it starts again within the
//!   journal's slack of the last start (120 seconds), and has been up longer
//!   by the next read than when the journal was written, reads as the same
//!   boot. Its rows are kept, but a row removes a route only when an
//!   identical route also carries the mark, which only this product adds,
//!   so nothing of anybody else's is removed.
//! - A change of the clock by more than the slack while a connection is up
//!   moves the start time the kernel reports, so the journal reads as
//!   another boot's and its rows are dropped without removing anything. The
//!   tunnel's routes go with the device when the engine closes it; what is
//!   left is the gateway's host route through the router of that time, which
//!   is left in place until the machine restarts. Nothing is removed that is
//!   not ours.

use std::io;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
#[cfg(test)]
use std::path::Path;
use std::ptr;
use std::sync::Mutex;

use libc::c_int;
use ubc_vpn_core::routes::Ipv4Net;

use super::route_socket::{self, Change, Interface, Route};
use crate::journal::{Boot, Journal, Prefix, Row, Store};
use crate::on_link::{AddressRow, DadState, usable_networks};
use crate::{
    Error, Ipv6Block, Mode, Paths, PhysicalNetwork, Result, Routes, TUNNEL_MTU, Verified, lock,
};

/// The route flag that marks a route this product added.
///
/// It is `RTF_PROTO1`, a flag the kernel keeps for a protocol's own use and
/// leaves alone on IPv4 routes (it once meant "use trailers", which nothing
/// does now). It never changes, so a later version finds an earlier one's
/// routes.
///
/// Not `RTF_PROTO3`: on macOS that is the kernel's own `RTPRF_OURS`, which
/// marks a cloned IPv4 route as due to expire. The kernel clears it from
/// any route the first time the route is looked up, and deletes routes that
/// carry it when they expire or memory runs short, so a route marked with it
/// would lose the mark as soon as traffic used it, or be deleted.
pub(super) const OURS: c_int = libc::RTF_PROTO1;

/// The boot this process runs in.
///
/// The start time is the kernel's own (`kern.boottime`), which it moves with
/// the clock when the clock is set. The time since then is the monotonic
/// clock, which keeps counting while the machine sleeps, as Windows' does.
/// See "The boot the journal belongs to" above for how that fails safe.
pub(super) fn boot() -> Result<Boot> {
    let mut started = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let mut size = size_of::<libc::timeval>();
    let mut name = [libc::CTL_KERN, libc::KERN_BOOTTIME];
    // SAFETY: `name` holds the two numbers named by the length passed, and
    // `started` and `size` are live and describe a buffer of `size` bytes
    // that the call fills. Nothing new is set.
    let status = unsafe {
        libc::sysctl(
            name.as_mut_ptr(),
            2,
            (&raw mut started).cast(),
            &mut size,
            ptr::null_mut(),
            0,
        )
    };
    if status != 0 {
        return Err(io::Error::last_os_error().into());
    }
    let started = u64::try_from(started.tv_sec)
        .ok()
        .filter(|_| size == size_of::<libc::timeval>());
    let started =
        started.ok_or_else(|| Error::Failed("the boot time cannot be read".to_string()))?;

    let mut since = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `since` is a live `timespec` for the call to fill.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut since) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    let uptime = u64::try_from(since.tv_sec)
        .map_err(|_| Error::Failed("the time since boot cannot be read".to_string()))?;
    Ok(Boot { started, uptime })
}

/// Whether a route of the table is one that decides where traffic goes:
/// see "Which routes count".
pub(super) fn counts(route: &Route) -> bool {
    let left_out = [libc::RTF_IFSCOPE, libc::RTF_WASCLONED, libc::RTF_LLINFO];
    left_out.iter().all(|flag| route.flags & flag == 0)
}

/// The routes the kernel would choose between for `dest`: of those that
/// count, are up, and go out of an interface that is up, the ones with the
/// longest prefix that holds it.
pub(super) fn winners<'a>(
    table: &'a [Route],
    interfaces: &[Interface],
    dest: Ipv4Addr,
) -> Vec<&'a Route> {
    let up = |index: u16| interfaces.iter().any(|i| i.index == index && i.is_up());
    let matching: Vec<&Route> = table
        .iter()
        .filter(|r| counts(r) && r.flags & libc::RTF_UP != 0)
        .filter(|r| r.dest.contains_addr(dest) && up(r.index))
        .collect();
    let longest = matching.iter().map(|r| r.dest.prefix_len()).max();
    matching
        .into_iter()
        .filter(|r| Some(r.dest.prefix_len()) == longest)
        .collect()
}

fn name_of(interfaces: &[Interface], index: u16) -> Option<&str> {
    let found = interfaces.iter().find(|i| i.index == index);
    found.map(|i| i.name.as_str())
}

/// [`Routes::uses_interface`] on what was read: `Unknown` when the table or
/// the interfaces could not be read, or a winning route's interface has no
/// name; `Yes` when every winning route goes out of `interface`; `No` when
/// none does or nothing matches.
pub(super) fn through(
    read: Result<(Vec<Route>, Vec<Interface>)>,
    dest: Ipv4Addr,
    interface: &str,
) -> Verified {
    let Ok((table, interfaces)) = read else {
        return Verified::Unknown;
    };
    let names: Option<Vec<&str>> = winners(&table, &interfaces, dest)
        .into_iter()
        .map(|route| name_of(&interfaces, route.index))
        .collect();
    let Some(names) = names else {
        return Verified::Unknown;
    };
    // No winner at all is `No` too.
    if names.iter().all(|name| *name != interface) {
        Verified::No
    } else if names.iter().all(|name| *name == interface) {
        Verified::Yes
    } else {
        Verified::Unknown
    }
}

fn read() -> Result<(Vec<Route>, Vec<Interface>)> {
    Ok((route_socket::table()?, route_socket::interfaces()?))
}

/// What is there already for one route.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Present {
    None,
    /// A route identical to it: the same destination, interface and next
    /// hop. `ours` says whether it carries [`OURS`].
    Identical {
        ours: bool,
    },
    /// A route to the same destination through another interface or next
    /// hop.
    Elsewhere,
}

/// The next hop of a journal row as the table would show it.
fn router_of(row: &Row) -> Option<Ipv4Addr> {
    match row.next_hop {
        IpAddr::V4(hop) if !hop.is_unspecified() => Some(hop),
        _ => None,
    }
}

pub(super) fn present(table: &[Route], row: &Row) -> Present {
    let Prefix::V4(dest) = row.dest else {
        return Present::None;
    };
    let mut found = Present::None;
    for route in table.iter().filter(|r| counts(r) && r.dest == dest) {
        let same = u64::from(route.index) == row.luid && route.router == router_of(row);
        if !same {
            return Present::Elsewhere;
        }
        found = Present::Identical {
            ours: route.flags & OURS != 0,
        };
    }
    found
}

#[cfg(test)]
thread_local! {
    /// Runs on this thread between writing an add's journal row and adding
    /// its route, where a crash would stop it.
    pub(super) static BEFORE_ADD: std::cell::Cell<Option<fn()>> = const { std::cell::Cell::new(None) };
}

/// The routing table, with the journal of the routes this product added.
pub(crate) struct MacRoutes {
    journal: Mutex<Journal>,
}

impl MacRoutes {
    /// Routes whose journal is in the service's state folder for `mode`.
    pub(crate) fn new(mode: Mode, paths: &Paths) -> Self {
        let store = Store::Checked(mode, paths.clone());
        Self {
            journal: Mutex::new(Journal::new(store)),
        }
    }

    /// Routes whose journal is in `dir`, with no checks on the folder.
    #[cfg(test)]
    pub(crate) fn unchecked(dir: &Path) -> Self {
        let store = Store::Unchecked(dir.to_path_buf());
        Self {
            journal: Mutex::new(Journal::new(store)),
        }
    }

    /// Adds one route the exclusive way the contract asks for: the row goes
    /// into the journal first, then the route, marked.
    fn add(&self, row: Row) -> Result<()> {
        let Prefix::V4(dest) = row.dest else {
            return Err(Error::Unsupported);
        };
        let index = u16::try_from(row.luid).map_err(|_| Error::NotFound)?;
        let mut journal = lock(&self.journal);
        match present(&route_socket::table()?, &row) {
            Present::Identical { .. } => return Ok(()),
            Present::Elsewhere => return Err(Error::AlreadyExists),
            Present::None => {}
        }
        let now = boot()?;
        let mut rows = journal.rows(now)?;
        if !rows.contains(&row) {
            rows.push(row.clone());
        }
        // The row goes in first, so a crash never leaves a route of ours
        // that the journal does not name.
        journal.write(now, &rows)?;
        #[cfg(test)]
        if let Some(hook) = BEFORE_ADD.with(std::cell::Cell::get) {
            hook();
        }
        let added = route_socket::change(Change::Add, dest, index, router_of(&row), OURS);
        if added.is_err() {
            rows.retain(|kept| *kept != row);
            journal.write(now, &rows)?;
        }
        match added {
            // Somebody added a route there in the meantime: it is theirs.
            Err(Error::AlreadyExists) => match present(&route_socket::table()?, &row) {
                Present::Identical { .. } => Ok(()),
                _ => Err(Error::AlreadyExists),
            },
            other => other,
        }
    }

    /// Removes the rows `which` picks out, and their routes where the table
    /// still has them, identical and marked. A row whose route is gone, or
    /// is there but not marked as ours, is dropped and nothing is removed.
    fn remove(&self, which: impl Fn(&Row) -> bool) -> Result<()> {
        let mut journal = lock(&self.journal);
        let now = boot()?;
        let rows = journal.rows(now)?;
        let table = route_socket::table()?;
        let mut kept = Vec::new();
        let mut failed = None;
        for row in rows {
            if !which(&row) {
                kept.push(row);
                continue;
            }
            let (Prefix::V4(dest), Ok(index)) = (row.dest, u16::try_from(row.luid)) else {
                continue;
            };
            if present(&table, &row) != (Present::Identical { ours: true }) {
                continue;
            }
            match route_socket::change(Change::Delete, dest, index, router_of(&row), 0) {
                // Gone already, or with its interface.
                Ok(()) | Err(Error::NotFound) => {}
                Err(error) => {
                    failed = Some(error);
                    kept.push(row);
                }
            }
        }
        journal.write(now, &kept)?;
        failed.map_or(Ok(()), Err)
    }
}

/// Whether `name` is a name the kernel gives a `utun` device, the only kind
/// of tunnel device a program can make on macOS.
pub(super) fn is_utun_name(name: &str) -> bool {
    let number = name.strip_prefix("utun");
    number.is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// The tunnel device named `name`, checked to be a `utun`, a point-to-point
/// device, and not a physical one.
pub(super) fn tunnel<'a>(interfaces: &'a [Interface], name: &str) -> Result<&'a Interface> {
    let device = interfaces.iter().find(|i| i.name == name);
    let device = device.ok_or(Error::NotFound)?;
    if !is_utun_name(name) || device.flags & libc::IFF_POINTOPOINT == 0 {
        return Err(Error::Failed(format!("{name} is not a tunnel device")));
    }
    Ok(device)
}

/// Removes the device's IPv6 addresses. macOS gives a `utun` none of its
/// own accord: only a program that starts IPv6 on it does, and nothing
/// does on this product's device. Its tests check that none appears.
fn quiet_ipv6(device: &Interface) -> Result<()> {
    for address in &device.v6 {
        match route_socket::remove_ipv6(&device.name, address) {
            Ok(()) | Err(Error::NotFound) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

impl Routes for MacRoutes {
    fn capture_physical(&self, gateway: Ipv4Addr) -> Result<PhysicalNetwork> {
        let (table, interfaces) = read()?;
        // There is one route per destination and prefix, so two winners
        // would be a table this code does not understand.
        let [route] = winners(&table, &interfaces, gateway)[..] else {
            return Err(Error::NotFound);
        };
        let interface = name_of(&interfaces, route.index).ok_or(Error::NotFound)?;
        let own_addresses = interfaces
            .iter()
            .flat_map(|i| i.v4.iter().map(|a| a.addr))
            .collect();
        // macOS lists no duplicate-address state for IPv4 here: every
        // address of an interface that is up and running is in use.
        let rows = interfaces.iter().flat_map(|i| {
            i.v4.iter().map(|a| AddressRow {
                addr: a.addr,
                prefix_len: a.prefix_len,
                state: DadState::Preferred,
                interface_up: i.is_up(),
            })
        });
        let mut on_link = usable_networks(rows);
        on_link.sort_by_key(|net| (net.addr(), net.prefix_len()));
        on_link.dedup();
        Ok(PhysicalNetwork {
            interface: interface.to_string(),
            next_hop: route.router,
            own_addresses,
            on_link,
        })
    }

    fn configure_tunnel(&self, tunnel: &str, address: Ipv4Addr, mtu: u16) -> Result<()> {
        if !TUNNEL_MTU.contains(&mtu) {
            return Err(Error::InvalidInput);
        }
        let interfaces = route_socket::interfaces()?;
        let device = self::tunnel(&interfaces, tunnel)?;
        quiet_ipv6(device)?;
        for other in device.v4.iter().filter(|a| a.addr != address) {
            match route_socket::remove_address(tunnel, other.addr) {
                Ok(()) | Err(Error::NotFound) => {}
                Err(error) => return Err(error),
            }
        }
        // A single host: the address with itself as the other end, and a
        // mask of all ones. The kernel routes only that one address to the
        // device for it. Set again when it is there, which changes an
        // address left with another mask or other end.
        route_socket::add_address(tunnel, address, 32, Some(address))?;
        // Setting an address brings a `utun` up: the kernel does so for
        // every address set, one set again included.
        route_socket::set_mtu(tunnel, mtu)
    }

    fn add_gateway_route(&self, gateway: Ipv4Addr, via: &PhysicalNetwork) -> Result<()> {
        let dest = Ipv4Net::new(gateway, 32).map_err(|e| Error::Failed(e.to_string()))?;
        let interfaces = route_socket::interfaces()?;
        let wire = interfaces.iter().find(|i| i.name == via.interface);
        let wire = wire.ok_or(Error::NotFound)?;
        self.add(Row {
            dest: Prefix::V4(dest),
            luid: u64::from(wire.index),
            next_hop: IpAddr::V4(via.next_hop.unwrap_or(Ipv4Addr::UNSPECIFIED)),
            interface: via.interface.clone(),
        })
    }

    fn remove_gateway_route(&self, gateway: Ipv4Addr, via: &PhysicalNetwork) -> Result<()> {
        let next_hop = IpAddr::V4(via.next_hop.unwrap_or(Ipv4Addr::UNSPECIFIED));
        let dest = Ipv4Net::new(gateway, 32).map_err(|e| Error::Failed(e.to_string()))?;
        self.remove(|row| {
            row.dest == Prefix::V4(dest)
                && row.interface == via.interface
                && row.next_hop == next_hop
        })
    }

    fn add_tunnel_routes(&self, tunnel: &str, subnets: &[Ipv4Net]) -> Result<()> {
        let interfaces = route_socket::interfaces()?;
        let index = self::tunnel(&interfaces, tunnel)?.index;
        for dest in subnets {
            self.add(Row {
                dest: Prefix::V4(*dest),
                luid: u64::from(index),
                next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                interface: tunnel.to_string(),
            })?;
        }
        Ok(())
    }

    fn remove_tunnel_routes(&self, tunnel: &str, subnets: &[Ipv4Net]) -> Result<()> {
        self.remove(|row| {
            let listed = matches!(row.dest, Prefix::V4(net) if subnets.contains(&net));
            row.interface == tunnel && row.next_hop.is_unspecified() && listed
        })
    }

    fn remove_all(&self) -> Result<()> {
        self.remove(|_| true)
    }

    fn uses_interface(&self, dest: Ipv4Addr, interface: &str) -> Verified {
        through(read(), dest, interface)
    }

    fn full_tunnel_ipv6(&self, _tunnel: &str) -> Result<Ipv6Block> {
        Err(Error::Unsupported)
    }

    fn add_full_tunnel(&self, _tunnel: &str) -> Result<Ipv6Block> {
        Err(Error::Unsupported)
    }

    fn remove_full_tunnel(&self, _tunnel: &str) -> Result<()> {
        Err(Error::Unsupported)
    }

    fn foreign_full_tunnel(&self, _tunnel: &str) -> Result<bool> {
        Err(Error::Unsupported)
    }

    fn uses_interface_v6(&self, _dest: Ipv6Addr, _interface: &str) -> Verified {
        Verified::Unknown
    }
}
