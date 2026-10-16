//! Network events from the real IP Helper notifications, with Wintun
//! adapters playing both the physical network and the tunnel, so nothing on
//! the runner's own network changes. Elevated and on CI only, like the
//! routing tests.

use std::net::Ipv4Addr;

use std::time::Duration;

use super::events::WinEvents;
use super::routes::WinRoutes;
use super::routes_tests::{Cleanup, Outsider, ran, state_dir, turn, wintun};
use crate::suite::Foreign;
use crate::{NetworkEvent, NetworkEvents, PhysicalNetwork, Routes, Subscription};

/// The next event, if one comes within `wait`.
fn next(events: &Subscription, wait: Duration) -> Option<NetworkEvent> {
    events.events().recv_timeout(wait).ok()
}

// The contract: "physical changed" is sent for a change to the watched
// network, and never for the routes this product adds or removes, nor for
// anything that happens to the tunnel.
#[test]
fn only_a_change_to_the_watched_network_is_reported() {
    let _turn = turn();
    let Some(wintun) = wintun() else { return };
    let (wire, tunnel) = ("ubc-vpn-watch0", "ubc-vpn-events0");
    let dir = state_dir("events");
    let watched = wintun.adapter(wire);
    let _tunnel_adapter = wintun.adapter(tunnel);
    let _cleanup = Cleanup(vec![dir.clone()]);
    let routes = WinRoutes::unchecked(&dir);
    routes
        .configure_tunnel(wire, Ipv4Addr::new(198, 18, 0, 10), 1500)
        .unwrap();
    std::thread::sleep(Duration::from_secs(2));
    let physical = PhysicalNetwork {
        interface: wire.to_string(),
        next_hop: None,
        // As captured: the address it was given above.
        own_addresses: vec![Ipv4Addr::new(198, 18, 0, 10)],
        on_link: Vec::new(),
    };
    let events = WinEvents.subscribe(&physical).unwrap();
    let quiet = Duration::from_secs(3);

    // Everything a connection does: none of it is a change to the network.
    let gateway = Ipv4Addr::new(192, 0, 2, 1);
    routes
        .configure_tunnel(tunnel, Ipv4Addr::new(198, 18, 0, 2), 1300)
        .unwrap();
    routes.add_gateway_route(gateway, &physical).unwrap();
    routes
        .add_tunnel_routes(tunnel, &["198.51.100.0/24".parse().unwrap()])
        .unwrap();
    // Full mode's halves, the IPv6 ones too, are our own routes.
    let full = routes.add_full_tunnel(tunnel);
    routes.remove_all().unwrap();
    assert_eq!(full, Ok(crate::Ipv6Block::Blocked));
    assert_eq!(
        next(&events, quiet),
        None,
        "an event for our own routes or the tunnel"
    );

    // A new address on the watched network is a change.
    Outsider.add_address(wire, Ipv4Addr::new(198, 18, 0, 11));
    assert_eq!(
        next(&events, Duration::from_secs(10)),
        Some(NetworkEvent::PhysicalChanged)
    );
    while next(&events, Duration::from_millis(500)).is_some() {}

    // So is the network going away.
    drop(watched);
    assert_eq!(
        next(&events, Duration::from_secs(10)),
        Some(NetworkEvent::PhysicalChanged)
    );
    ran("events");
}

// Security rule: once a subscription is dropped, Windows calls back for it
// no more. A registration left behind would call into a subscription that
// is gone, which in the service, running as SYSTEM, is memory freed.
#[test]
fn a_dropped_subscription_gets_no_more_callbacks() {
    let _turn = turn();
    let Some(wintun) = wintun() else { return };
    let wire = "ubc-vpn-late0";
    let dir = state_dir("late");
    let _watched = wintun.adapter(wire);
    let _cleanup = Cleanup(vec![dir.clone()]);
    let routes = WinRoutes::unchecked(&dir);
    routes
        .configure_tunnel(wire, Ipv4Addr::new(198, 18, 1, 10), 1500)
        .unwrap();
    std::thread::sleep(Duration::from_secs(2));
    let physical = PhysicalNetwork {
        interface: wire.to_string(),
        next_hop: None,
        own_addresses: vec![Ipv4Addr::new(198, 18, 1, 10)],
        on_link: Vec::new(),
    };
    let late_before = super::events::late_callbacks();
    drop(WinEvents.subscribe(&physical).unwrap());
    // Changes Windows would have told it about, had it still been there.
    for n in 11..14 {
        Outsider.add_address(wire, Ipv4Addr::new(198, 18, 1, n));
    }
    std::thread::sleep(Duration::from_secs(3));
    let late = super::events::late_callbacks() - late_before;
    assert_eq!(late, 0, "callbacks for a subscription that had ended");
    ran("events late");
}

// A change between capturing the network and subscribing to it is reported
// at once, not taken as the starting point: here the capture is missing the
// address the watched adapter has.
#[test]
fn a_change_since_capture_is_reported_at_once() {
    let _turn = turn();
    let Some(wintun) = wintun() else { return };
    let wire = "ubc-vpn-since0";
    let dir = state_dir("since");
    let _watched = wintun.adapter(wire);
    let _cleanup = Cleanup(vec![dir.clone()]);
    let routes = WinRoutes::unchecked(&dir);
    routes
        .configure_tunnel(wire, Ipv4Addr::new(198, 18, 2, 10), 1500)
        .unwrap();
    std::thread::sleep(Duration::from_secs(2));
    // As if captured before the address was there.
    let physical = PhysicalNetwork {
        interface: wire.to_string(),
        next_hop: None,
        own_addresses: Vec::new(),
        on_link: Vec::new(),
    };
    let events = WinEvents.subscribe(&physical).unwrap();
    assert_eq!(
        next(&events, Duration::from_secs(5)),
        Some(NetworkEvent::PhysicalChanged)
    );
    ran("events since capture");
}

/// A global IPv6 address on `interface`, as another program would add it.
fn ipv6_address(
    interface: &str,
    address: std::net::Ipv6Addr,
) -> windows_sys::Win32::NetworkManagement::IpHelper::MIB_UNICASTIPADDRESS_ROW {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        InitializeUnicastIpAddressEntry, MIB_UNICASTIPADDRESS_ROW,
    };
    use windows_sys::Win32::Networking::WinSock::IpDadStatePreferred;
    // SAFETY: plain data for which all zeroes is valid; then initialised.
    let mut row: MIB_UNICASTIPADDRESS_ROW = unsafe { std::mem::zeroed() };
    // SAFETY: the pointer is to a valid row.
    unsafe { InitializeUnicastIpAddressEntry(&mut row) };
    row.InterfaceLuid.Value = super::routes::luid(interface).expect("the interface");
    row.Address = super::routes::v6(address);
    row.OnLinkPrefixLength = 64;
    row.DadState = IpDadStatePreferred;
    row
}

/// The first event within `wait` that is not "physical changed", which a
/// change on another adapter may bring as well, harmlessly.
fn next_ipv6(events: &Subscription, wait: Duration) -> Option<NetworkEvent> {
    let started = std::time::Instant::now();
    while let Some(left) = wait.checked_sub(started.elapsed()) {
        match next(events, left)? {
            NetworkEvent::PhysicalChanged => continue,
            event => return Some(event),
        }
    }
    None
}

// Security rule: a new way out for IPv6, on any interface but the tunnel, is
// reported, so that in full mode the service decides again whether IPv6 can
// leak. Here, on an adapter other than the watched one, a global route
// appears and goes, then a global address does.
#[test]
fn a_new_ipv6_route_anywhere_is_reported() {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        CreateIpForwardEntry2, CreateUnicastIpAddressEntry, DeleteIpForwardEntry2,
        DeleteUnicastIpAddressEntry,
    };
    let _turn = turn();
    let Some(wintun) = wintun() else { return };
    let (wire, other) = ("ubc-vpn-v6watch0", "ubc-vpn-v6out0");
    let dir = state_dir("events-v6");
    let _watched = wintun.adapter(wire);
    let _other = wintun.adapter(other);
    let _cleanup = Cleanup(vec![dir.clone()]);
    let routes = WinRoutes::unchecked(&dir);
    routes
        .configure_tunnel(wire, Ipv4Addr::new(198, 18, 3, 10), 1500)
        .unwrap();
    std::thread::sleep(Duration::from_secs(2));
    let physical = PhysicalNetwork {
        interface: wire.to_string(),
        next_hop: None,
        own_addresses: vec![Ipv4Addr::new(198, 18, 3, 10)],
        on_link: Vec::new(),
    };
    let events = WinEvents.subscribe(&physical).unwrap();
    while next(&events, Duration::from_secs(2)).is_some() {}
    let way_out = super::full_tunnel_tests::foreign_v6(
        other,
        std::net::Ipv6Addr::new(0x2001, 0xdb8, 0x2, 0, 0, 0, 0, 0),
        48,
    );
    let wait = Duration::from_secs(10);
    // SAFETY: the row is valid and initialised.
    super::routes::checked(unsafe { CreateIpForwardEntry2(&way_out) }).expect("an IPv6 route");
    let added = next_ipv6(&events, wait);
    while next(&events, Duration::from_secs(2)).is_some() {}
    // SAFETY: as above.
    let removing = super::routes::checked(unsafe { DeleteIpForwardEntry2(&way_out) });
    let removed = next_ipv6(&events, wait);
    assert_eq!(added, Some(NetworkEvent::Ipv6Changed), "a route appeared");
    assert_eq!(removing, Ok(()));
    assert_eq!(removed, Some(NetworkEvent::Ipv6Changed), "a route went");
    while next(&events, Duration::from_secs(2)).is_some() {}

    let address = ipv6_address(
        other,
        std::net::Ipv6Addr::new(0x2001, 0xdb8, 0x3, 0, 0, 0, 0, 0x10),
    );
    // SAFETY: the row is valid and initialised.
    super::routes::checked(unsafe { CreateUnicastIpAddressEntry(&address) })
        .expect("an IPv6 address");
    let added = next_ipv6(&events, wait);
    while next(&events, Duration::from_secs(2)).is_some() {}
    // SAFETY: as above.
    let removing = super::routes::checked(unsafe { DeleteUnicastIpAddressEntry(&address) });
    let removed = next_ipv6(&events, wait);
    assert_eq!(
        added,
        Some(NetworkEvent::Ipv6Changed),
        "an address appeared"
    );
    assert_eq!(removing, Ok(()));
    assert_eq!(removed, Some(NetworkEvent::Ipv6Changed), "an address went");
    ran("events ipv6");
}
