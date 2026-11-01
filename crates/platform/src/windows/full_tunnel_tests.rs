//! Full mode against a real Wintun adapter: the halves, what the OS then
//! picks for every kind of destination, and the IPv6 decision. Like the
//! other routing tests they need an elevated process and the Wintun library,
//! and are skipped without them unless CI requires them.
//!
//! While the halves are in place every connection of the machine goes to an
//! adapter nobody reads, so each test keeps them for as short a time as it
//! can.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ubc_vpn_core::routes::Ipv4Net;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry2, DeleteIpForwardEntry2, DeleteIpNetEntry2, GetIpNetEntry2,
    InitializeIpForwardEntry, MIB_IPFORWARD_ROW2, MIB_IPNET_ROW2,
};
use windows_sys::Win32::Networking::WinSock::{NlnsIncomplete, NlnsUnreachable};

use super::routes::{WinRoutes, best_route, checked, luid, v4, v6, value};
use super::routes_tests::{Cleanup, Outsider, ran, state_dir, step, turn, wintun};
use crate::suite::Foreign;
use crate::{Error, Ipv6Block, Routes, Verified};

/// The gateway the tests reach by the physical network.
const GATEWAY: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

/// An IPv6 route through `interface` that is not the product's.
pub(super) fn foreign_v6(interface: &str, dest: Ipv6Addr, len: u8) -> MIB_IPFORWARD_ROW2 {
    // SAFETY: plain data for which all zeroes is valid; then initialised.
    let mut row: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
    // SAFETY: the pointer is to a valid row.
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceLuid.Value = luid(interface).expect("the interface");
    row.DestinationPrefix.Prefix = v6(dest);
    row.DestinationPrefix.PrefixLength = len;
    row.NextHop = v6(Ipv6Addr::UNSPECIFIED);
    row
}

/// Turns IPv6 on or off for an adapter, as an administrator would.
fn bind_ipv6(adapter: &str, on: bool) {
    let verb = if on { "Enable" } else { "Disable" };
    let script = format!("{verb}-NetAdapterBinding -Name '{adapter}' -ComponentID ms_tcpip6");
    let done = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .expect("powershell");
    assert!(
        done.status.success(),
        "{verb} IPv6 on {adapter}: {}",
        String::from_utf8_lossy(&done.stderr)
    );
}

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

/// Whether the OS would take `dest` through `interface`.
fn through(routes: &WinRoutes, dest: &str, interface: &str) -> Verified {
    match ip(dest) {
        IpAddr::V4(dest) => routes.uses_interface(dest, interface),
        IpAddr::V6(dest) => routes.uses_interface_v6(dest, interface),
    }
}

// Full mode on the device that ships: the halves take every IPv4 address
// and block every IPv6 one, while the gateway, the router and the local
// network stay on the physical network; and every half is removed again,
// by the call for it and by the start-up clear.
#[test]
fn full_mode_takes_everything_but_the_gateway_and_the_local_network() {
    let _turn = turn();
    let Some(wintun) = wintun() else { return };
    let tunnel = "ubc-vpn-full0";
    let dir = state_dir("full");
    let _adapter = wintun.adapter(tunnel);
    let _cleanup = Cleanup(vec![dir.clone()]);
    let routes = WinRoutes::unchecked(&dir);
    routes
        .configure_tunnel(tunnel, Ipv4Addr::new(198, 18, 0, 2), 1400)
        .unwrap();
    let physical = routes.capture_physical(GATEWAY).unwrap();
    let lan = physical.interface().to_string();
    let router = physical.next_hop().expect("the runner has a router");
    assert!(physical.router_is_on_link(), "{physical:?}");
    let neighbour = physical
        .on_link()
        .iter()
        .find(|net| net.contains_addr(router))
        // The last address but one: neither the router nor the broadcast.
        .map(|net| {
            let size = 1u32 << (32 - u32::from(net.prefix_len()));
            Ipv4Addr::from(u32::from(net.addr()) + size - 2)
        })
        .expect("the router's network");
    routes.add_gateway_route(GATEWAY, &physical).unwrap();
    assert_eq!(routes.foreign_full_tunnel(tunnel), Ok(false));

    step("adding the halves");
    assert_eq!(routes.add_full_tunnel(tunnel), Ok(Ipv6Block::Blocked));
    let seen = [
        ("1.1.1.1", tunnel),
        ("200.1.1.1", tunnel),
        ("2001:db8::1", tunnel),
        ("a000::1", tunnel),
        (&GATEWAY.to_string(), lan.as_str()),
        (&router.to_string(), lan.as_str()),
        (&neighbour.to_string(), lan.as_str()),
    ]
    .map(|(dest, interface)| (dest.to_string(), through(&routes, dest, interface)));
    // Added again, nothing changes; the halves are not somebody else's.
    let again = routes.add_full_tunnel(tunnel);
    let foreign = routes.foreign_full_tunnel(tunnel);
    let elsewhere = routes.foreign_full_tunnel("ubc-vpn-no-such0");
    let journal = std::fs::read_to_string(dir.join("routes.journal")).unwrap();
    routes.remove_full_tunnel(tunnel).unwrap();
    step("the halves are gone");

    println!("FULL {seen:?}");
    for (dest, verified) in &seen {
        assert_eq!(*verified, Verified::Yes, "{dest}");
    }
    assert_eq!(again, Ok(Ipv6Block::Blocked));
    assert_eq!(foreign, Ok(false));
    assert_eq!(elsewhere, Ok(true));
    for half in ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"] {
        assert!(journal.contains(&format!("route {half} ")), "{journal}");
    }
    for dest in ["1.1.1.1", "200.1.1.1", "2001:db8::1", "a000::1"] {
        assert_eq!(through(&routes, dest, tunnel), Verified::No, "{dest}");
    }
    // The gateway route is not a half, and stays.
    assert_eq!(through(&routes, &GATEWAY.to_string(), &lan), Verified::Yes);

    step("the start-up clear");
    assert_eq!(routes.add_full_tunnel(tunnel), Ok(Ipv6Block::Blocked));
    WinRoutes::unchecked(&dir).remove_all().unwrap();
    for dest in ["1.1.1.1", "2001:db8::1"] {
        assert_eq!(through(&routes, dest, tunnel), Verified::No, "{dest}");
    }
    ran("full tunnel");
}

/// A neighbour cache entry the test made, removed again when dropped.
struct Neighbour(MIB_IPNET_ROW2);

impl Neighbour {
    /// Makes the cache mark `addr` on the interface `luid` as not answering
    /// the way a scan of the network does: by sending to it while nothing
    /// answers there. An entry made by hand is kept as permanent instead.
    /// The runner's cache keeps it incomplete while sends go on, and may
    /// not reach unreachable before the deadline; either state is enough.
    fn unreachable(luid: u64, addr: Ipv4Addr) -> Self {
        // SAFETY: plain data for which all zeroes is valid.
        let mut row: MIB_IPNET_ROW2 = unsafe { std::mem::zeroed() };
        row.Address = v4(addr);
        row.InterfaceLuid.Value = luid;
        // SAFETY: the row names an entry; a missing one is fine.
        let _ = unsafe { DeleteIpNetEntry2(&row) };
        let entry = Self(row);
        let socket = std::net::UdpSocket::bind("0.0.0.0:0").expect("a socket");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            let _ = socket.send_to(b"probe", (addr, 9));
            if entry.state() == Some(NlnsUnreachable) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        entry
    }

    /// The state the cache holds for it now.
    fn state(&self) -> Option<i32> {
        let mut row = self.0;
        // SAFETY: the row names the entry and is valid for the call.
        checked(unsafe { GetIpNetEntry2(&mut row) }).ok()?;
        Some(row.State)
    }
}

impl Drop for Neighbour {
    fn drop(&mut self) {
        // SAFETY: the row names the entry the test made.
        let _ = unsafe { DeleteIpNetEntry2(&self.0) };
    }
}

// The neighbour-unreachable case, on the runner's own network: an address
// on the local network that did not answer, which the neighbour cache marks
// incomplete and then unreachable. Windows'
// best-route lookup then skips the on-link route and answers with a half of
// full mode. The check judges the routing table, where the on-link route is
// more specific than the halves, so the address stays on the local network.
#[test]
fn an_unreachable_neighbour_stays_on_the_local_network_in_full_mode() {
    let _turn = turn();
    let Some(wintun) = wintun() else { return };
    let tunnel = "ubc-vpn-nbr0";
    let dir = state_dir("neighbour");
    let _adapter = wintun.adapter(tunnel);
    let _cleanup = Cleanup(vec![dir.clone()]);
    let routes = WinRoutes::unchecked(&dir);
    routes
        .configure_tunnel(tunnel, Ipv4Addr::new(198, 18, 0, 5), 1400)
        .unwrap();
    let physical = routes.capture_physical(GATEWAY).unwrap();
    let lan = physical.interface().to_string();
    let router = physical.next_hop().expect("the runner has a router");
    // The last address but two of the router's network: not the router,
    // not the broadcast, and not the machine's own.
    let neighbour = physical
        .on_link()
        .iter()
        .find(|net| net.contains_addr(router))
        .map(|net| {
            let size = 1u32 << (32 - u32::from(net.prefix_len()));
            Ipv4Addr::from(u32::from(net.addr()) + size - 3)
        })
        .expect("the router's network");
    assert_ne!(neighbour, router);
    assert!(
        !physical.own_addresses().contains(&neighbour),
        "{physical:?}"
    );
    let (lan_luid, tunnel_luid) = (luid(&lan).unwrap(), luid(tunnel).unwrap());

    step("adding the halves beside an unreachable neighbour");
    let entry = Neighbour::unreachable(lan_luid, neighbour);
    assert_eq!(routes.add_full_tunnel(tunnel), Ok(Ipv6Block::Blocked));
    let state = entry.state();
    let looked_up = best_route(neighbour).map(|route| value(&route.InterfaceLuid));
    let on_lan = routes.uses_interface(neighbour, &lan);
    let on_tunnel = routes.uses_interface(neighbour, tunnel);
    routes.remove_full_tunnel(tunnel).unwrap();
    drop(entry);
    step("the halves and the entry are gone");

    println!(
        "NEIGHBOUR state {state:?}, best route {looked_up:?}, \
         local network {lan_luid}, tunnel {tunnel_luid}"
    );
    // Still being resolved, or given up on: either way nothing answered.
    let unanswered = [Some(NlnsIncomplete), Some(NlnsUnreachable)];
    assert!(unanswered.contains(&state), "the neighbour answered");
    assert_eq!(
        looked_up,
        Ok(tunnel_luid),
        "the best-route lookup kept the on-link route, so this does not test the case"
    );
    assert_eq!(on_lan, Verified::Yes);
    assert_eq!(on_tunnel, Verified::No);
    ran("full tunnel unreachable neighbour");
}

// Security rule: with no IPv6 on the tunnel the IPv6 halves cannot be
// added. Then full mode is refused, with nothing added, when IPv6 could
// leave by another interface; and goes on without them when it could not.
#[test]
fn full_mode_without_ipv6_on_the_tunnel_is_refused_only_where_ipv6_could_leak() {
    let _turn = turn();
    let Some(wintun) = wintun() else { return };
    let tunnel = "ubc-vpn-nov6-0";
    let other = "ubc-vpn-leak0";
    let dir = state_dir("nov6");
    let _adapter = wintun.adapter(tunnel);
    let _other = wintun.adapter(other);
    let _cleanup = Cleanup(vec![dir.clone()]);
    let routes = WinRoutes::unchecked(&dir);
    routes
        .configure_tunnel(tunnel, Ipv4Addr::new(198, 18, 0, 3), 1400)
        .unwrap();
    assert_eq!(routes.full_tunnel_ipv6(tunnel), Ok(Ipv6Block::Blocked));
    bind_ipv6(tunnel, false);
    // The runner has no IPv6 beyond link-local.
    assert_eq!(
        routes.full_tunnel_ipv6(tunnel),
        Ok(Ipv6Block::NothingToBlock)
    );
    let leak = foreign_v6(other, Ipv6Addr::new(0x2001, 0xdb8, 0x1, 0, 0, 0, 0, 0), 48);
    // SAFETY: the row is valid and initialised.
    checked(unsafe { CreateIpForwardEntry2(&leak) }).expect("a route IPv6 could leave by");

    step("refused with a way out for IPv6");
    let decided = routes.full_tunnel_ipv6(tunnel);
    let refused = routes.add_full_tunnel(tunnel);
    let added = through(&routes, "1.1.1.1", tunnel);
    let journal = std::fs::read_to_string(dir.join("routes.journal")).unwrap_or_default();
    // SAFETY: as above.
    checked(unsafe { DeleteIpForwardEntry2(&leak) }).expect("remove the route");
    assert_eq!(decided, Err(Error::Unsupported));
    assert_eq!(refused, Err(Error::Unsupported));
    assert_eq!(added, Verified::No, "a half was added before the refusal");
    assert!(!journal.contains("0.0.0.0/1"), "{journal}");

    step("no IPv6 anywhere to leak");
    let nothing = routes.add_full_tunnel(tunnel);
    let taken = through(&routes, "1.1.1.1", tunnel);
    routes.remove_full_tunnel(tunnel).unwrap();
    bind_ipv6(tunnel, true);
    assert_eq!(nothing, Ok(Ipv6Block::NothingToBlock));
    assert_eq!(taken, Verified::Yes);
    ran("full tunnel no ipv6");
}

// Somebody else's half, such as another VPN's, is theirs: full mode does not
// fight it, and the read-only check reports it first.
#[test]
fn a_half_through_another_interface_is_not_taken() {
    let _turn = turn();
    let Some(wintun) = wintun() else { return };
    let tunnel = "ubc-vpn-half0";
    let other = "ubc-vpn-other0";
    let dir = state_dir("half");
    let _adapter = wintun.adapter(tunnel);
    let _other = wintun.adapter(other);
    let _cleanup = Cleanup(vec![dir.clone()]);
    let routes = WinRoutes::unchecked(&dir);
    routes
        .configure_tunnel(tunnel, Ipv4Addr::new(198, 18, 0, 4), 1400)
        .unwrap();
    for v4 in [true, false] {
        let half: Ipv4Net = "128.0.0.0/1".parse().unwrap();
        let theirs = foreign_v6(other, Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0), 1);
        if v4 {
            Outsider.add_route(other, half);
        } else {
            // SAFETY: the row is valid and initialised.
            checked(unsafe { CreateIpForwardEntry2(&theirs) }).expect("their half");
        }
        let foreign = routes.foreign_full_tunnel(tunnel);
        let added = routes.add_full_tunnel(tunnel);
        if v4 {
            Outsider.remove_route(other, half);
        } else {
            // SAFETY: as above.
            let _ = unsafe { DeleteIpForwardEntry2(&theirs) };
        }
        routes.remove_full_tunnel(tunnel).unwrap();
        assert_eq!(foreign, Ok(true), "v4 {v4}");
        assert_eq!(added, Err(Error::AlreadyExists), "v4 {v4}");
    }
    ran("full tunnel foreign");
}
