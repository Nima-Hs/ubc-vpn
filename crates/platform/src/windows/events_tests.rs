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
        own_addresses: Vec::new(),
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
    routes.remove_all().unwrap();
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
