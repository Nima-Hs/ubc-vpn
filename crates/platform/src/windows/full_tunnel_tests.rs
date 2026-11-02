//! Full mode against a real Wintun adapter: the shared check, what Windows
//! journals, and what the OS then picks for a neighbour that does not
//! answer. Like the other routing tests they need an elevated process and
//! the Wintun library, and are skipped without them unless CI requires
//! them.
//!
//! While the halves are in place every connection of the machine goes to an
//! adapter nobody reads, so each test keeps them for as short a time as it
//! can.

use std::net::Ipv4Addr;

use windows_sys::Win32::NetworkManagement::IpHelper::{
    DeleteIpNetEntry2, GetIpNetEntry2, MIB_IPNET_ROW2,
};
use windows_sys::Win32::Networking::WinSock::{NlnsIncomplete, NlnsUnreachable};

use super::routes::{WinRoutes, best_route, checked, luid, v4, value};
use super::routes_tests::{Cleanup, Outsider, ran, state_dir, step, turn, wintun};
use crate::suite;
use crate::{Ipv6Block, Routes, Verified};

/// The gateway the tests reach by the physical network.
const GATEWAY: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

// The shared rules on the device that ships: the halves take every IPv4
// address and block every IPv6 one, while the gateway, the router and the
// local network stay on the physical network; somebody else's half is not
// taken; and with no IPv6 on the tunnel, full mode is refused only where
// IPv6 could leak. The runner has no IPv6 beyond link-local, which the
// check needs. Then the halves are journalled, each in a row of its own.
#[test]
fn passes_the_shared_full_tunnel_check() {
    let _turn = turn();
    let Some(wintun) = wintun() else { return };
    let (tunnel, other) = ("ubc-vpn-full0", "ubc-vpn-other0");
    let dir = state_dir("full");
    let _adapter = wintun.adapter(tunnel);
    let _other = wintun.adapter(other);
    let _cleanup = Cleanup(vec![dir.clone()]);
    let routes = WinRoutes::unchecked(&dir);
    routes
        .configure_tunnel(tunnel, Ipv4Addr::new(198, 18, 0, 2), 1400)
        .unwrap();
    step("check_full_tunnel");
    let restarted = || Box::new(WinRoutes::unchecked(&dir)) as Box<dyn Routes>;
    suite::check_full_tunnel(&routes, &restarted, &Outsider, tunnel, other);

    step("the journal");
    assert_eq!(routes.add_full_tunnel(tunnel), Ok(Ipv6Block::Blocked));
    let journal = std::fs::read_to_string(dir.join("routes.journal")).unwrap();
    routes.remove_full_tunnel(tunnel).unwrap();
    for half in ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"] {
        assert!(journal.contains(&format!("route {half} ")), "{journal}");
    }
    ran("full tunnel");
    ran("full tunnel foreign");
    ran("full tunnel no ipv6");
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
