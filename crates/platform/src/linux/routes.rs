//! The routing table and the tunnel's address on Linux, through route
//! netlink. Full mode's routes are not written yet: those operations report
//! [`Error::Unsupported`] and their check answers [`Verified::Unknown`].
//!
//! Interfaces are named by their name, which is looked up again on every
//! call. A route is identified by its destination, its interface and its
//! next hop, in the main table.
//!
//! Every route added here carries the route protocol number
//! [`LINUX_ROUTE_PROTOCOL`], and removing removes only routes that carry it,
//! so a new process finds what an earlier one added without a journal.
//! Linux keeps routes to one destination with different metrics side by
//! side, so every add first reads the table and fails with
//! [`Error::AlreadyExists`] when the destination is routed elsewhere.
//!
//! The kernel answers ARP on every interface for every address the machine
//! holds, the tunnel's included (issue #146). A tunnel address inside a
//! network the machine is on would draw a neighbour's traffic to this
//! machine, so it is refused.

#[path = "netlink.rs"]
pub(super) mod netlink;

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ubc_vpn_core::routes::Ipv4Net;

use self::netlink::{
    AF_INET, AF_INET6, AF_UNSPEC, Address, IFA_F_DADFAILED, IFA_F_DEPRECATED, IFA_F_TENTATIVE,
    Link, RT_SCOPE_LINK, RT_SCOPE_UNIVERSE, RT_TABLE_MAIN, RTN_UNICAST, RTNH_F_DEAD,
    RTNH_F_LINKDOWN, Route,
};
use crate::on_link::{AddressRow, DadState, usable_networks};
use crate::unsupported::Native;
use crate::{
    Error, Ipv6Block, LINUX_ROUTE_PROTOCOL, PhysicalNetwork, Result, Routes, TUNNEL_MTU, Verified,
};

/// What the kernel makes a tunnel device as.
const TUN: &str = "tun";

/// Linux routes.
pub(super) struct LinuxRoutes;

/// An OS error as this crate's.
fn os(error: io::Error) -> Error {
    match error.raw_os_error() {
        Some(libc::EEXIST) => Error::AlreadyExists,
        Some(libc::ENODEV) => Error::NotFound,
        Some(libc::EPERM | libc::EACCES) => Error::PermissionDenied,
        _ => Error::Failed(error.to_string()),
    }
}

/// Whether removing something failed only because it is gone already.
fn gone(error: &io::Error) -> bool {
    let codes = [libc::ESRCH, libc::ENOENT, libc::ENODEV, libc::EADDRNOTAVAIL];
    error
        .raw_os_error()
        .is_some_and(|code| codes.contains(&code))
}

/// Whether the kernel has no IPv6 for this, as when it is turned off.
fn no_ipv6(error: &io::Error) -> bool {
    error.raw_os_error() == Some(libc::EAFNOSUPPORT)
}

fn links() -> Result<Vec<Link>> {
    netlink::links().map_err(os)
}

/// The interface named `name`.
fn link(name: &str) -> Result<Link> {
    let links = links()?;
    links
        .into_iter()
        .find(|link| link.name == name)
        .ok_or(Error::NotFound)
}

/// The interface named `name`, checked to be a tunnel device and not a
/// physical one.
fn tunnel(name: &str) -> Result<Link> {
    let link = link(name)?;
    if link.kind.as_deref() != Some(TUN) {
        let kind = link.kind.as_deref().unwrap_or("none given");
        let message = format!("{name} is not a tunnel device (kind {kind})");
        return Err(Error::Failed(message));
    }
    Ok(link)
}

/// The network `addr` is on with a prefix of `prefix_len` bits: the host
/// bits cleared. A prefix longer than 32 is taken as 32.
fn network(addr: Ipv4Addr, prefix_len: u8) -> Option<Ipv4Net> {
    let len = prefix_len.min(32);
    let mask = u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0);
    Ipv4Net::new(Ipv4Addr::from(u32::from(addr) & mask), len).ok()
}

/// The issue #146 rule: the network, among those of the IPv4 addresses on
/// every interface but the tunnel's (numbered `tunnel`), that holds
/// `address`. An address that is not in use counts too: its interface may
/// come up, and the kernel would then answer for the tunnel's address on
/// that network.
pub(super) fn local_network_holding(
    address: Ipv4Addr,
    tunnel: u32,
    addresses: &[Address],
) -> Option<Ipv4Net> {
    addresses
        .iter()
        .filter(|row| row.index != tunnel)
        .filter_map(|row| network(row.v4()?, row.prefix_len))
        .find(|net| net.contains_addr(address))
}

/// An IPv4 address as [`usable_networks`] reads it. Its interface counts
/// as up when it is up and its link works.
pub(super) fn address_row(row: &Address, links: &[Link]) -> Option<AddressRow> {
    let state = if row.flags & IFA_F_DADFAILED != 0 {
        DadState::Duplicate
    } else if row.flags & IFA_F_TENTATIVE != 0 {
        DadState::Tentative
    } else if row.flags & IFA_F_DEPRECATED != 0 {
        DadState::Deprecated
    } else {
        DadState::Preferred
    };
    let link = links.iter().find(|link| link.index == row.index);
    Some(AddressRow {
        addr: row.v4()?,
        prefix_len: row.prefix_len,
        state,
        interface_up: link.is_some_and(Link::running),
    })
}

/// What is there already for one route.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Present {
    None,
    Identical,
    Elsewhere,
}

/// What `table` holds for a route to `dest` through the interface numbered
/// `oif`, by `gateway` or straight onto the link. Only the main table
/// counts, and every metric: a route to `dest` with another interface or
/// next hop, at whatever metric, is somebody else's way there.
pub(super) fn present(
    table: &[Route],
    dest: Ipv4Net,
    oif: u32,
    gateway: Option<Ipv4Addr>,
) -> Present {
    let same_dest = table.iter().filter(|route| {
        route.family == AF_INET
            && route.table == RT_TABLE_MAIN
            && route.dst == IpAddr::V4(dest.addr())
            && route.dst_len == dest.prefix_len()
    });
    let mut found = Present::None;
    for route in same_dest {
        let identical = !route.multipath
            && !route.via
            && route.oif == Some(oif)
            && route.gateway == gateway.map(IpAddr::V4);
        match identical {
            true => found = Present::Identical,
            false => return Present::Elsewhere,
        }
    }
    found
}

/// Whether this product added `route`: it carries the product's mark.
pub(super) fn is_ours(route: &Route) -> bool {
    route.protocol == LINUX_ROUTE_PROTOCOL
}

/// The route this product adds to `dest` through the interface numbered
/// `oif`, by `gateway` or straight onto the link.
fn our_route(dest: Ipv4Net, oif: u32, gateway: Option<Ipv4Addr>) -> Route {
    Route {
        family: AF_INET,
        dst: IpAddr::V4(dest.addr()),
        dst_len: dest.prefix_len(),
        tos: 0,
        table: RT_TABLE_MAIN,
        protocol: LINUX_ROUTE_PROTOCOL,
        scope: match gateway {
            Some(_) => RT_SCOPE_UNIVERSE,
            None => RT_SCOPE_LINK,
        },
        kind: RTN_UNICAST,
        flags: 0,
        oif: Some(oif),
        gateway: gateway.map(IpAddr::V4),
        priority: None,
        multipath: false,
        via: false,
    }
}

/// Adds one route the exclusive way the contract asks for: read the table
/// first, since the kernel would add a route beside one with another
/// metric.
fn add(dest: Ipv4Net, oif: u32, gateway: Option<Ipv4Addr>) -> Result<()> {
    let read = || netlink::routes(AF_INET).map_err(os);
    match present(&read()?, dest, oif, gateway) {
        Present::Identical => return Ok(()),
        Present::Elsewhere => return Err(Error::AlreadyExists),
        Present::None => {}
    }
    match netlink::add_route(&our_route(dest, oif, gateway)) {
        Ok(()) => Ok(()),
        // Somebody added one in the meantime: if identical, it is theirs.
        Err(error) if error.raw_os_error() == Some(libc::EEXIST) => {
            match present(&read()?, dest, oif, gateway) {
                Present::Identical => Ok(()),
                _ => Err(Error::AlreadyExists),
            }
        }
        Err(error) => Err(os(error)),
    }
}

/// Removes the routes of this product's that `which` picks out, IPv4 or
/// IPv6, in any table.
fn remove(which: impl Fn(&Route) -> bool) -> Result<()> {
    let table = netlink::routes(AF_UNSPEC).map_err(os)?;
    let mut failed = None;
    for route in table.iter().filter(|route| is_ours(route) && which(route)) {
        match netlink::delete_route(route) {
            Ok(()) => {}
            Err(error) if gone(&error) => {}
            Err(error) => failed = Some(os(error)),
        }
    }
    failed.map_or(Ok(()), Err)
}

/// Whether `route` is the IPv4 route in the main table to `dest`, through
/// the interface numbered `oif`, by `gateway` or straight onto the link.
fn is_route(route: &Route, dest: Ipv4Net, oif: u32, gateway: Option<Ipv4Addr>) -> bool {
    route.family == AF_INET
        && route.table == RT_TABLE_MAIN
        && route.dst == IpAddr::V4(dest.addr())
        && route.dst_len == dest.prefix_len()
        && route.oif == Some(oif)
        && route.gateway == gateway.map(IpAddr::V4)
}

/// Turns off the IPv6 addresses the kernel would give the interface
/// numbered `index` of its own accord, link-local included, and removes
/// those it has. Nothing to do where it has no IPv6.
fn quiet_ipv6(index: u32) -> Result<()> {
    match netlink::set_addr_gen_mode(index, netlink::ADDR_GEN_MODE_NONE) {
        Ok(()) => {}
        Err(error) if no_ipv6(&error) => return Ok(()),
        Err(error) => return Err(os(error)),
    }
    let addresses = match netlink::addresses(AF_INET6) {
        Ok(addresses) => addresses,
        Err(error) if no_ipv6(&error) => return Ok(()),
        Err(error) => return Err(os(error)),
    };
    for address in addresses.iter().filter(|a| a.index == index) {
        match netlink::delete_address(address) {
            Ok(()) => {}
            Err(error) if gone(&error) => {}
            Err(error) => return Err(os(error)),
        }
    }
    Ok(())
}

/// The answer to "would the kernel send a packet by the interface numbered
/// `wanted`?", from its own choice of route, `lookup`, and the interfaces.
///
/// It fails closed: an error asking is `Unknown`, except the kernel's
/// answer that no route reaches the address, which is `No`. A route on an
/// interface that is down, or whose link does not work, never counts: it
/// carries nothing.
pub(super) fn verdict(lookup: io::Result<Route>, wanted: u32, links: &[Link]) -> Verified {
    let route = match lookup {
        Ok(route) => route,
        Err(error) => {
            let unreachable = [libc::ENETUNREACH, libc::EHOSTUNREACH];
            return match error.raw_os_error() {
                Some(code) if unreachable.contains(&code) => Verified::No,
                _ => Verified::Unknown,
            };
        }
    };
    let Some(oif) = route.oif else {
        return Verified::Unknown;
    };
    if oif != wanted {
        return Verified::No;
    }
    let running = links
        .iter()
        .find(|link| link.index == oif)
        .is_some_and(Link::running);
    let dead = route.flags & (RTNH_F_DEAD | RTNH_F_LINKDOWN) != 0;
    match running && !dead && route.kind == RTN_UNICAST {
        true => Verified::Yes,
        false => Verified::No,
    }
}

impl Routes for LinuxRoutes {
    fn capture_physical(&self, gateway: Ipv4Addr) -> Result<PhysicalNetwork> {
        let route = netlink::route_to(gateway).map_err(os)?;
        let no_way = || Error::Failed(format!("no interface reaches {gateway}"));
        let oif = route.oif.ok_or_else(no_way)?;
        if route.multipath || route.via {
            let message = format!("the route to {gateway} has a next hop this cannot follow");
            return Err(Error::Failed(message));
        }
        let links = links()?;
        let interface = links
            .iter()
            .find(|link| link.index == oif)
            .ok_or_else(no_way)?
            .name
            .clone();
        let next_hop = match route.gateway {
            Some(IpAddr::V4(hop)) if !hop.is_unspecified() => Some(hop),
            _ => None,
        };
        let addresses = netlink::addresses(AF_INET).map_err(os)?;
        let own_addresses = addresses.iter().filter_map(Address::v4).collect();
        let rows = addresses.iter().filter_map(|row| address_row(row, &links));
        let mut on_link = usable_networks(rows);
        on_link.sort_by_key(|net| (net.addr(), net.prefix_len()));
        on_link.dedup();
        Ok(PhysicalNetwork {
            interface,
            next_hop,
            own_addresses,
            on_link,
        })
    }

    fn configure_tunnel(&self, tunnel: &str, address: Ipv4Addr, mtu: u16) -> Result<()> {
        if !TUNNEL_MTU.contains(&mtu) {
            return Err(Error::InvalidInput);
        }
        let device = self::tunnel(tunnel)?;
        let addresses = netlink::addresses(AF_INET).map_err(os)?;
        // Issue #146: refused as outside what the operation accepts, before
        // anything changes.
        if local_network_holding(address, device.index, &addresses).is_some() {
            return Err(Error::InvalidInput);
        }
        // The kernel gives a device that is up an IPv6 address of its own the
        // moment IPv6 starts on it, as it does afresh when the device grows
        // past 1280 bytes: before `addr_gen_mode` could be set. So a device
        // that is up goes down while its size changes, which also takes the
        // routes through it; the service configures before it routes.
        if device.mtu != Some(u32::from(mtu)) {
            if device.flags & netlink::IFF_UP != 0 {
                netlink::set_down(device.index).map_err(os)?;
            }
            quiet_ipv6(device.index)?;
            netlink::set_mtu(device.index, mtu).map_err(os)?;
        }
        // Before the device comes up, which is when the kernel would give it
        // an IPv6 address.
        quiet_ipv6(device.index)?;
        let mut ours = false;
        for row in addresses.iter().filter(|row| row.index == device.index) {
            if row.v4() == Some(address) && row.prefix_len == 32 {
                ours = true;
                continue;
            }
            match netlink::delete_address(row) {
                Ok(()) => {}
                Err(error) if gone(&error) => {}
                Err(error) => return Err(os(error)),
            }
        }
        if !ours {
            // A single host, never the gateway's netmask: see the trait.
            match netlink::add_address(device.index, address, 32) {
                Ok(()) => {}
                Err(error) if error.raw_os_error() == Some(libc::EEXIST) => {}
                Err(error) => return Err(os(error)),
            }
        }
        netlink::set_up(device.index).map_err(os)
    }

    fn add_gateway_route(&self, gateway: Ipv4Addr, via: &PhysicalNetwork) -> Result<()> {
        let dest = network(gateway, 32).ok_or(Error::InvalidInput)?;
        add(dest, link(&via.interface)?.index, via.next_hop)
    }

    fn remove_gateway_route(&self, gateway: Ipv4Addr, via: &PhysicalNetwork) -> Result<()> {
        let dest = network(gateway, 32).ok_or(Error::InvalidInput)?;
        let oif = match link(&via.interface) {
            Ok(link) => link.index,
            // Its routes went with it.
            Err(Error::NotFound) => return Ok(()),
            Err(error) => return Err(error),
        };
        remove(|route| is_route(route, dest, oif, via.next_hop))
    }

    fn add_tunnel_routes(&self, tunnel: &str, subnets: &[Ipv4Net]) -> Result<()> {
        let oif = self::tunnel(tunnel)?.index;
        for dest in subnets {
            add(*dest, oif, None)?;
        }
        Ok(())
    }

    fn remove_tunnel_routes(&self, tunnel: &str, subnets: &[Ipv4Net]) -> Result<()> {
        let oif = match link(tunnel) {
            Ok(link) => link.index,
            Err(Error::NotFound) => return Ok(()),
            Err(error) => return Err(error),
        };
        remove(|route| subnets.iter().any(|dest| is_route(route, *dest, oif, None)))
    }

    fn remove_all(&self) -> Result<()> {
        remove(|_| true)
    }

    /// The kernel's own choice of route (`RTM_GETROUTE`), which depends on
    /// the routes and rules alone, not on which neighbours answered.
    fn uses_interface(&self, dest: Ipv4Addr, interface: &str) -> Verified {
        let Ok(links) = netlink::links() else {
            return Verified::Unknown;
        };
        let Some(wanted) = links.iter().find(|link| link.name == interface) else {
            // An interface that does not exist is not the one used.
            return Verified::No;
        };
        verdict(netlink::route_to(dest), wanted.index, &links)
    }

    fn full_tunnel_ipv6(&self, tunnel: &str) -> Result<Ipv6Block> {
        Native.full_tunnel_ipv6(tunnel)
    }

    fn add_full_tunnel(&self, tunnel: &str) -> Result<Ipv6Block> {
        Native.add_full_tunnel(tunnel)
    }

    fn remove_full_tunnel(&self, tunnel: &str) -> Result<()> {
        Native.remove_full_tunnel(tunnel)
    }

    fn foreign_full_tunnel(&self, tunnel: &str) -> Result<bool> {
        Native.foreign_full_tunnel(tunnel)
    }

    fn uses_interface_v6(&self, dest: Ipv6Addr, interface: &str) -> Verified {
        Native.uses_interface_v6(dest, interface)
    }
}
