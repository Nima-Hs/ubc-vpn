//! Network events from the real IP Helper notifications, with Wintun
//! adapters playing the physical network, the tunnel and another network,
//! so nothing on the runner's own network changes. Elevated and on CI only,
//! like the routing tests.

use std::net::Ipv4Addr;

use std::time::Duration;

use super::events::WinEvents;
use super::routes::WinRoutes;
use super::routes_tests::{Cleanup, Outsider, ran, state_dir, step, turn, wintun};
use crate::suite::{self, Foreign};
use crate::{NetworkEvent, NetworkEvents, PhysicalNetwork, Routes, Subscription};

/// The next event, if one comes within `wait`.
fn next(events: &Subscription, wait: Duration) -> Option<NetworkEvent> {
    events.events().recv_timeout(wait).ok()
}

// The shared rules: "physical changed" is sent for a new address on the
// watched network and for its link going down and up, and never for the
// routes this product adds or removes, nor for anything that happens to the
// tunnel; "IPv6 changed" is sent for an IPv6 route or address that comes or
// goes on another adapter.
#[test]
fn passes_the_shared_events_check() {
    let _turn = turn();
    let Some(wintun) = wintun() else { return };
    let (wire, tunnel, other) = ("ubc-vpn-watch0", "ubc-vpn-events0", "ubc-vpn-v6out0");
    let dir = state_dir("events");
    let _watched = wintun.adapter(wire);
    let _tunnel_adapter = wintun.adapter(tunnel);
    let _other = wintun.adapter(other);
    let _cleanup = Cleanup(vec![dir.clone()]);
    let routes = WinRoutes::unchecked(&dir);
    routes
        .configure_tunnel(wire, Ipv4Addr::new(198, 18, 0, 10), 1500)
        .unwrap();
    // The new adapters settle before the check starts listening.
    std::thread::sleep(Duration::from_secs(3));
    let physical = PhysicalNetwork {
        interface: wire.to_string(),
        next_hop: None,
        // As captured: the address it was given above.
        own_addresses: vec![Ipv4Addr::new(198, 18, 0, 10)],
        on_link: Vec::new(),
    };
    step("check_events");
    suite::check_events(&WinEvents, &routes, &Outsider, &physical, tunnel, other);
    ran("events");
    ran("events ipv6");
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
