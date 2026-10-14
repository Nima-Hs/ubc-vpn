//! The routing table and the tunnel device, through rtnetlink.
//!
//! Every route this adds carries [`LINUX_ROUTE_PROTOCOL`], and every removal
//! names it, so the kernel itself refuses to remove a route of anyone else's,
//! even one identical in every other way. Adds are exclusive: a route already
//! at the destination is never replaced. Nothing is remembered between
//! calls, so a new process after a crash knows everything this one did.

use std::fs;
use std::io;
use std::net::Ipv4Addr;

use ubc_vpn_core::routes::Ipv4Net;

use super::netlink::consts::*;
use super::netlink::{Body, as_ipv4, as_text, as_u32, attrs, request};
use crate::{Error, LINUX_ROUTE_PROTOCOL, PhysicalNetwork, Result, Routes, TUNNEL_MTU, Verified};

pub(crate) struct LinuxRoutes;

/// An interface, as the kernel describes it.
struct Link {
    index: u32,
    name: String,
    /// Made by the tun driver, as the VPN engine's device is.
    tun: bool,
}

/// A route in the main table, as the kernel lists it.
struct Route {
    dst: Ipv4Addr,
    len: u8,
    tos: u8,
    protocol: u8,
    priority: u32,
    oif: Option<u32>,
    gateway: Option<Ipv4Addr>,
    multipath: bool,
}

fn ifinfomsg(index: u32, flags: u32, change: u32) -> [u8; 16] {
    let mut header = [0; 16];
    header[0] = AF_UNSPEC;
    header[4..8].copy_from_slice(&index.to_ne_bytes());
    header[8..12].copy_from_slice(&flags.to_ne_bytes());
    header[12..16].copy_from_slice(&change.to_ne_bytes());
    header
}

fn ifaddrmsg(prefix: u8, index: u32) -> [u8; 8] {
    let mut header = [0; 8];
    header[0] = AF_INET;
    header[1] = prefix;
    header[3] = RT_SCOPE_UNIVERSE;
    header[4..8].copy_from_slice(&index.to_ne_bytes());
    header
}

/// The fixed header of a route message: family, destination length, source
/// length, type of service, table, protocol, scope, type, flags.
fn rtmsg(len: u8, protocol: u8, scope: u8, kind: u8) -> [u8; 12] {
    [
        AF_INET,
        len,
        0,
        0,
        RT_TABLE_MAIN,
        protocol,
        scope,
        kind,
        0,
        0,
        0,
        0,
    ]
}

fn parse_link(body: &[u8]) -> Option<Link> {
    let index = u32::from_ne_bytes(body.get(4..8)?.try_into().ok()?);
    let found = attrs(body.get(16..)?);
    let name = found.iter().find(|(kind, _)| *kind == IFLA_IFNAME);
    let name = as_text(name?.1)?.to_string();
    let info = found.iter().find(|(kind, _)| *kind == IFLA_LINKINFO);
    let kind = info.and_then(|(_, info)| {
        let inner = attrs(info);
        let kind = inner.iter().find(|(kind, _)| *kind == IFLA_INFO_KIND)?;
        as_text(kind.1).map(str::to_string)
    });
    Some(Link {
        index,
        name,
        tun: kind.as_deref() == Some("tun"),
    })
}

fn one_link(body: Body) -> Result<Link> {
    let replies = match request(RTM_GETLINK, 0, &body) {
        Err(error) if error.raw_os_error() == Some(libc::ENODEV) => return Err(Error::NotFound),
        replies => replies?,
    };
    let link = replies.iter().find(|reply| reply.kind == RTM_NEWLINK);
    link.and_then(|link| parse_link(&link.body))
        .ok_or_else(|| Error::Failed("the kernel described no interface".to_string()))
}

/// The interface named `name`. [`Error::NotFound`] when there is none.
fn link_named(name: &str) -> Result<Link> {
    // The kernel's names are shorter than 16 bytes and hold no NUL.
    if name.is_empty() || name.len() > 15 || name.contains('\0') {
        return Err(Error::NotFound);
    }
    let name = [name.as_bytes(), b"\0"].concat();
    one_link(Body::new(&ifinfomsg(0, 0, 0)).attr(IFLA_IFNAME, &name))
}

fn link_numbered(index: u32) -> Result<Link> {
    one_link(Body::new(&ifinfomsg(index, 0, 0)))
}

/// The tunnel device named `name`: found again on every call, and refused
/// unless the tun driver made it.
fn tunnel(name: &str) -> Result<Link> {
    let link = link_named(name)?;
    if !link.tun {
        return Err(Error::Failed(format!("{name} is not a tunnel device")));
    }
    Ok(link)
}

/// Asks which way the kernel would send a packet to `dest`: the interface's
/// number and the next hop. `None` when it has no way there.
fn lookup(dest: Ipv4Addr) -> io::Result<Option<(u32, Option<Ipv4Addr>)>> {
    let body = Body::new(&rtmsg(32, 0, 0, 0)).ipv4(RTA_DST, dest);
    let replies = match request(RTM_GETROUTE, 0, &body) {
        Err(error)
            if matches!(
                error.raw_os_error(),
                Some(libc::ENETUNREACH | libc::EHOSTUNREACH)
            ) =>
        {
            return Ok(None);
        }
        replies => replies?,
    };
    let Some(reply) = replies.iter().find(|reply| reply.kind == RTM_NEWROUTE) else {
        return Ok(None);
    };
    let found = attrs(reply.body.get(12..).unwrap_or_default());
    let get = |want: u16| {
        found
            .iter()
            .find(|(kind, _)| *kind == want)
            .map(|(_, v)| *v)
    };
    let oif = get(RTA_OIF).and_then(as_u32);
    let gateway = get(RTA_GATEWAY).and_then(as_ipv4);
    Ok(oif.map(|oif| (oif, gateway)))
}

/// Every IPv4 route in the main table.
fn main_routes() -> io::Result<Vec<Route>> {
    let replies = request(RTM_GETROUTE, NLM_F_DUMP, &Body::new(&rtmsg(0, 0, 0, 0)))?;
    let mut routes = Vec::new();
    for reply in replies.iter().filter(|reply| reply.kind == RTM_NEWROUTE) {
        let body = &reply.body;
        if body.len() < 12 || body[0] != AF_INET {
            continue;
        }
        let found = attrs(&body[12..]);
        let get = |want: u16| {
            found
                .iter()
                .find(|(kind, _)| *kind == want)
                .map(|(_, v)| *v)
        };
        let table = get(RTA_TABLE)
            .and_then(as_u32)
            .unwrap_or(u32::from(body[4]));
        if table != u32::from(RT_TABLE_MAIN) {
            continue;
        }
        routes.push(Route {
            dst: get(RTA_DST)
                .and_then(as_ipv4)
                .unwrap_or(Ipv4Addr::UNSPECIFIED),
            len: body[1],
            tos: body[3],
            protocol: body[5],
            priority: get(RTA_PRIORITY).and_then(as_u32).unwrap_or(0),
            oif: get(RTA_OIF).and_then(as_u32),
            gateway: get(RTA_GATEWAY).and_then(as_ipv4),
            multipath: get(RTA_MULTIPATH).is_some(),
        });
    }
    Ok(routes)
}

/// Adds a route of ours to `net` through interface `oif`, by `via` when it is
/// given. Exclusive: when a route to the same destination is there, the add
/// succeeds only if that route is identical, and it stays somebody else's.
fn add_route(net: Ipv4Net, oif: u32, via: Option<Ipv4Addr>) -> Result<()> {
    let scope = if via.is_some() {
        RT_SCOPE_UNIVERSE
    } else {
        RT_SCOPE_LINK
    };
    let header = rtmsg(net.prefix_len(), LINUX_ROUTE_PROTOCOL, scope, RTN_UNICAST);
    let mut body = Body::new(&header)
        .ipv4(RTA_DST, net.addr())
        .u32(RTA_OIF, oif);
    if let Some(via) = via {
        body = body.ipv4(RTA_GATEWAY, via);
    }
    match request(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, &body) {
        Err(error) if error.raw_os_error() == Some(libc::EEXIST) => {}
        added => return Ok(added.map(drop)?),
    }
    // The kernel compares destination, type of service and priority; the
    // contract compares interface and next hop as well.
    let identical = main_routes()?.into_iter().any(|route| {
        route.dst == net.addr()
            && route.len == net.prefix_len()
            && route.tos == 0
            && route.priority == 0
            && !route.multipath
            && route.oif == Some(oif)
            && route.gateway == via
    });
    match identical {
        true => Ok(()),
        false => Err(Error::AlreadyExists),
    }
}

/// Removes our route to `net`, through `oif` and by `via` when they are
/// given. The kernel removes only a route that carries our protocol number.
/// Not there is fine.
fn remove_route(net: Ipv4Net, oif: Option<u32>, via: Option<Ipv4Addr>) -> Result<()> {
    let header = rtmsg(net.prefix_len(), LINUX_ROUTE_PROTOCOL, RT_SCOPE_NOWHERE, 0);
    let mut body = Body::new(&header).ipv4(RTA_DST, net.addr());
    if let Some(oif) = oif {
        body = body.u32(RTA_OIF, oif);
    }
    if let Some(via) = via {
        body = body.ipv4(RTA_GATEWAY, via);
    }
    match request(RTM_DELROUTE, 0, &body) {
        Err(error) if error.raw_os_error() == Some(libc::ESRCH) => Ok(()),
        removed => Ok(removed.map(drop)?),
    }
}

fn host(address: Ipv4Addr) -> Ipv4Net {
    Ipv4Net::new(address, 32).expect("a host is a network")
}

/// The network of `address` with a prefix of `len`.
fn network(address: Ipv4Addr, len: u8) -> Option<Ipv4Net> {
    let mask = match len {
        0 => 0,
        1..=32 => u32::MAX << (32 - u32::from(len)),
        _ => return None,
    };
    Ipv4Net::new(Ipv4Addr::from(u32::from(address) & mask), len).ok()
}

/// The IPv4 addresses on the machine: interface, prefix, own address, and
/// the address the prefix belongs to (the peer's on a point-to-point link).
fn addresses() -> io::Result<Vec<(u32, u8, Ipv4Addr, Ipv4Addr)>> {
    let header = ifaddrmsg(0, 0);
    let replies = request(RTM_GETADDR, NLM_F_DUMP, &Body::new(&header))?;
    let mut found = Vec::new();
    for reply in replies.iter().filter(|reply| reply.kind == RTM_NEWADDR) {
        let body = &reply.body;
        if body.len() < 8 || body[0] != AF_INET {
            continue;
        }
        let index = u32::from_ne_bytes(body[4..8].try_into().expect("four bytes"));
        let list = attrs(&body[8..]);
        let get = |want: u16| list.iter().find(|(kind, _)| *kind == want).map(|(_, v)| *v);
        let address = get(IFA_ADDRESS).and_then(as_ipv4);
        let local = get(IFA_LOCAL).and_then(as_ipv4).or(address);
        if let (Some(local), Some(address)) = (local, address.or(local)) {
            found.push((index, body[1], local, address));
        }
    }
    Ok(found)
}

/// Turns off the IPv6 address the kernel would give the device when it
/// comes up. Nothing to do on a kernel without IPv6.
fn no_ipv6(link: &Link) -> Result<()> {
    let setting = format!("/proc/sys/net/ipv6/conf/{}/disable_ipv6", link.name);
    match fs::write(setting, "1") {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        written => Ok(written?),
    }
}

impl Routes for LinuxRoutes {
    fn capture_physical(&self, gateway: Ipv4Addr) -> Result<PhysicalNetwork> {
        let way = lookup(gateway)?;
        let (oif, next_hop) =
            way.ok_or_else(|| Error::Failed("there is no route to the gateway".to_string()))?;
        let link = link_numbered(oif)?;
        let mut own_addresses = Vec::new();
        let mut on_link = Vec::new();
        for (_, len, local, address) in addresses()? {
            if !own_addresses.contains(&local) {
                own_addresses.push(local);
            }
            if let Some(net) = network(address, len).filter(|net| !on_link.contains(net)) {
                on_link.push(net);
            }
        }
        Ok(PhysicalNetwork {
            interface: link.name,
            next_hop,
            own_addresses,
            on_link,
        })
    }

    fn configure_tunnel(&self, tunnel_name: &str, address: Ipv4Addr, mtu: u16) -> Result<()> {
        if !TUNNEL_MTU.contains(&mtu) {
            return Err(Error::InvalidInput);
        }
        let link = tunnel(tunnel_name)?;
        no_ipv6(&link)?;
        // This one address as a single host, and no other.
        let mut present = false;
        for (index, len, local, peer) in addresses()? {
            if index != link.index {
                continue;
            }
            if (len, local, peer) == (32, address, address) {
                present = true;
                continue;
            }
            let body = Body::new(&ifaddrmsg(len, link.index))
                .ipv4(IFA_LOCAL, local)
                .ipv4(IFA_ADDRESS, peer);
            match request(RTM_DELADDR, 0, &body) {
                Err(error) if error.raw_os_error() == Some(libc::EADDRNOTAVAIL) => {}
                removed => drop(removed?),
            }
        }
        if !present {
            let body = Body::new(&ifaddrmsg(32, link.index))
                .ipv4(IFA_LOCAL, address)
                .ipv4(IFA_ADDRESS, address);
            match request(RTM_NEWADDR, NLM_F_CREATE | NLM_F_EXCL, &body) {
                Err(error) if error.raw_os_error() == Some(libc::EEXIST) => {}
                added => drop(added?),
            }
        }
        let up = Body::new(&ifinfomsg(link.index, IFF_UP, IFF_UP)).u32(IFLA_MTU, mtu.into());
        request(RTM_SETLINK, 0, &up)?;
        Ok(())
    }

    fn add_gateway_route(&self, gateway: Ipv4Addr, via: &PhysicalNetwork) -> Result<()> {
        let link = link_named(&via.interface)?;
        add_route(host(gateway), link.index, via.next_hop)
    }

    fn remove_gateway_route(&self, gateway: Ipv4Addr, via: &PhysicalNetwork) -> Result<()> {
        match link_named(&via.interface) {
            Ok(link) => remove_route(host(gateway), Some(link.index), via.next_hop),
            // Its routes went with it.
            Err(Error::NotFound) => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn add_tunnel_routes(&self, tunnel_name: &str, subnets: &[Ipv4Net]) -> Result<()> {
        let link = tunnel(tunnel_name)?;
        subnets
            .iter()
            .try_for_each(|subnet| add_route(*subnet, link.index, None))
    }

    fn remove_tunnel_routes(&self, tunnel_name: &str, subnets: &[Ipv4Net]) -> Result<()> {
        let link = match tunnel(tunnel_name) {
            Ok(link) => link,
            Err(Error::NotFound) => return Ok(()),
            Err(error) => return Err(error),
        };
        subnets
            .iter()
            .try_for_each(|subnet| remove_route(*subnet, Some(link.index), None))
    }

    fn remove_all(&self) -> Result<()> {
        let ours = main_routes()?
            .into_iter()
            .filter(|route| route.protocol == LINUX_ROUTE_PROTOCOL);
        for route in ours {
            let net = Ipv4Net::new(route.dst, route.len)
                .map_err(|_| Error::Failed("the kernel listed a malformed route".to_string()))?;
            remove_route(net, route.oif, route.gateway)?;
        }
        Ok(())
    }

    fn uses_interface(&self, dest: Ipv4Addr, interface: &str) -> Verified {
        let link = match link_named(interface) {
            Ok(link) => link,
            Err(Error::NotFound) => return Verified::No,
            Err(_) => return Verified::Unknown,
        };
        match lookup(dest) {
            Ok(Some((oif, _))) if oif == link.index => Verified::Yes,
            Ok(_) => Verified::No,
            Err(_) => Verified::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_network_is_the_address_with_its_host_bits_cleared() {
        let at = |a, b, c, d| Ipv4Addr::new(a, b, c, d);
        let net = |text: &str| text.parse::<Ipv4Net>().ok();
        assert_eq!(network(at(10, 1, 3, 199), 20), net("10.1.0.0/20"));
        assert_eq!(network(at(10, 1, 3, 199), 32), net("10.1.3.199/32"));
        assert_eq!(network(at(10, 1, 3, 199), 0), net("0.0.0.0/0"));
        assert_eq!(network(at(10, 1, 3, 199), 33), None);
    }
}
