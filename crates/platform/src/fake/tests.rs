//! Tests of the fake itself, and that it passes the shared suite.

use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::time::Duration;

use crate::{Dns, NetworkEvents, Routes, Subscription, Transport};

use super::*;
use crate::suite;

const GATEWAY: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const TUNNEL: &str = "fake-tun0";

fn net(text: &str) -> Ipv4Net {
    text.parse().unwrap()
}

// Full mode sends every IPv4 address through the tunnel but the
// machine's own networks, their router and the gateway, which keep
// their more specific routes; IPv6 goes to the tunnel too, where it
// fails, but link-local stays. Removing the halves puts it all back,
// and nothing is left after a teardown.
#[test]
fn full_mode_takes_all_but_the_local_network() {
    let fake = Fake::new();
    let physical = fake.capture_physical(GATEWAY).unwrap();
    assert!(physical.router_is_on_link());
    fake.add_gateway_route(GATEWAY, &physical).unwrap();
    fake.add_tunnel_routes(TUNNEL, &[net("10.255.0.0/16")])
        .unwrap();
    let elsewhere = Ipv4Addr::new(1, 0, 0, 1);
    let high = Ipv4Addr::new(203, 0, 113, 1);
    let v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    assert_eq!(fake.uses_interface(elsewhere, TUNNEL), Verified::No);
    assert_eq!(
        fake.uses_interface_v6(v6, PHYSICAL_INTERFACE),
        Verified::Yes
    );

    assert_eq!(fake.add_full_tunnel(TUNNEL), Ok(Ipv6Block::Blocked));
    for dest in [elsewhere, high, Ipv4Addr::new(10, 255, 0, 1)] {
        assert_eq!(fake.uses_interface(dest, TUNNEL), Verified::Yes, "{dest}");
    }
    for dest in [GATEWAY, ROUTER, Ipv4Addr::new(192, 168, 0, 20)] {
        let direct = fake.uses_interface(dest, PHYSICAL_INTERFACE);
        assert_eq!(direct, Verified::Yes, "{dest}");
    }
    assert_eq!(fake.uses_interface_v6(v6, TUNNEL), Verified::Yes);
    let local = fake.uses_interface_v6(LINK_LOCAL_V6, PHYSICAL_INTERFACE);
    assert_eq!(local, Verified::Yes);

    fake.remove_full_tunnel(TUNNEL).unwrap();
    assert_eq!(fake.uses_interface(elsewhere, TUNNEL), Verified::No);
    assert_eq!(fake.uses_interface_v6(v6, TUNNEL), Verified::No);
    assert_eq!(fake.add_full_tunnel(TUNNEL), Ok(Ipv6Block::Blocked));
    fake.remove_all().unwrap();
    fake.clear_split_dns().unwrap();
    assert_eq!(fake.applied(), Applied::default());
}

// Security rule: IPv6 is blocked in full mode, or there is none to
// block. What can be done is read first, so a refusal (a tunnel with no
// IPv6 on a machine with an IPv6 leak path) comes before anything is
// added; with no IPv6 anywhere it goes ahead, and says so.
#[test]
fn ipv6_is_blocked_or_absent_never_left_open() {
    let fake = Fake::new();
    assert_eq!(fake.full_tunnel_ipv6(TUNNEL), Ok(Ipv6Block::Blocked));
    fake.set_ipv6(false, true);
    assert_eq!(fake.full_tunnel_ipv6(TUNNEL), Err(Error::Unsupported));
    assert_eq!(fake.add_full_tunnel(TUNNEL), Err(Error::Unsupported));
    assert_eq!(fake.applied().full_tunnel, None, "added before refusing");
    let v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let elsewhere = Ipv4Addr::new(1, 0, 0, 1);
    assert_eq!(fake.uses_interface(elsewhere, TUNNEL), Verified::No);

    fake.set_ipv6(false, false);
    assert_eq!(fake.full_tunnel_ipv6(TUNNEL), Ok(Ipv6Block::NothingToBlock));
    assert_eq!(fake.add_full_tunnel(TUNNEL), Ok(Ipv6Block::NothingToBlock));
    assert_eq!(fake.uses_interface(elsewhere, TUNNEL), Verified::Yes);
    assert_eq!(fake.uses_interface_v6(v6, TUNNEL), Verified::No);
    assert_eq!(fake.uses_interface_v6(v6, PHYSICAL_INTERFACE), Verified::No);
    // A snapshot: when a leak path appears later, the check says so.
    fake.set_ipv6(false, true);
    assert_eq!(fake.full_tunnel_ipv6(TUNNEL), Err(Error::Unsupported));
}

// A machine with a home LAN and two host-only adapters, none of them a
// UBC range: full mode keeps every one of those networks direct, their
// routers included, and takes everything else.
#[test]
fn full_mode_keeps_every_network_the_machine_is_on() {
    let fake = Fake::new();
    // The home network is the physical one; the host-only networks are
    // on adapters of their own, as a virtual machine program makes them.
    let router = Ipv4Addr::new(10, 200, 0, 1);
    fake.set_router(router);
    fake.set_local(&[Ipv4Addr::new(10, 200, 0, 10)], &[net("10.200.0.0/24")]);
    fake.add_adapter_network("fake-host1", net("172.31.130.0/24"));
    fake.add_adapter_network("fake-host2", net("172.31.140.0/24"));
    let physical = fake.capture_physical(GATEWAY).unwrap();
    assert_eq!(physical.next_hop(), Some(router));
    assert!(physical.router_is_on_link());
    assert_eq!(physical.on_link().len(), 3);
    fake.add_gateway_route(GATEWAY, &physical).unwrap();
    assert_eq!(fake.add_full_tunnel(TUNNEL), Ok(Ipv6Block::Blocked));
    let direct = [
        (router, PHYSICAL_INTERFACE),
        (Ipv4Addr::new(10, 200, 0, 200), PHYSICAL_INTERFACE),
        (Ipv4Addr::new(172, 31, 130, 128), "fake-host1"),
        (Ipv4Addr::new(172, 31, 140, 254), "fake-host2"),
        (GATEWAY, PHYSICAL_INTERFACE),
    ];
    for (dest, adapter) in direct {
        assert_eq!(fake.uses_interface(dest, TUNNEL), Verified::No, "{dest}");
        assert_eq!(fake.uses_interface(dest, adapter), Verified::Yes, "{dest}");
        // Not the physical interface, for the host-only networks.
        let physical = fake.uses_interface(dest, PHYSICAL_INTERFACE);
        assert_eq!(physical == Verified::Yes, adapter == PHYSICAL_INTERFACE);
    }
    for dest in [Ipv4Addr::new(10, 201, 0, 1), Ipv4Addr::new(203, 0, 113, 1)] {
        assert_eq!(fake.uses_interface(dest, TUNNEL), Verified::Yes, "{dest}");
    }
    assert_eq!(fake.resolvers_for("www.example.org"), [router]);
}

// "On error some may have been added": a failing add of the halves or
// set of the catch-all leaves them behind, so a service that does not
// record them before it adds them fails its tests. A route check can be
// made to say it could not tell, for one address only.
#[test]
fn failing_full_mode_steps_leave_what_they_did() {
    let fake = Fake::new();
    fake.set_failure(Op::AddFullTunnel, failed());
    fake.set_failure(Op::SetCatchAllDns, failed());
    assert!(fake.add_full_tunnel(TUNNEL).is_err());
    let resolvers = [Ipv4Addr::new(10, 255, 0, 53)];
    assert!(fake.set_catch_all_dns(&resolvers).is_err());
    let applied = fake.applied();
    assert!(applied.full_tunnel.is_some());
    assert_eq!(applied.catch_all_dns, Some(resolvers.to_vec()));
    fake.set_failure(Op::SetCatchAllDns, None);
    assert_eq!(fake.set_catch_all_dns(&[]), Err(Error::InvalidInput));

    let away = Ipv4Addr::new(203, 0, 113, 1);
    fake.cannot_tell_route_to(away);
    assert_eq!(fake.uses_interface(away, TUNNEL), Verified::Unknown);
    let other = Ipv4Addr::new(203, 0, 113, 2);
    assert_eq!(fake.uses_interface(other, TUNNEL), Verified::Yes);
}

// Another program's halves are a conflict: it is seen before anything
// is changed, and an add over them fails, adding nothing.
#[test]
fn another_programs_halves_are_a_conflict() {
    let fake = Fake::new();
    assert_eq!(fake.foreign_full_tunnel(TUNNEL), Ok(false));
    fake.add_foreign_route("other-vpn0", net("128.0.0.0/1"));
    assert_eq!(fake.foreign_full_tunnel(TUNNEL), Ok(true));
    assert_eq!(fake.add_full_tunnel(TUNNEL), Err(Error::AlreadyExists));
    assert_eq!(fake.applied().full_tunnel, None);
    // One the tunnel itself has is no conflict.
    fake.remove_foreign_route("other-vpn0", net("128.0.0.0/1"));
    fake.add_foreign_route(TUNNEL, net("0.0.0.0/1"));
    assert_eq!(fake.foreign_full_tunnel(TUNNEL), Ok(false));
}

// The catch-all sends every name the split domains do not take to its
// resolvers. Another program's catch-all is a conflict, seen before and
// refused on set. Clearing split DNS clears the catch-all too.
#[test]
fn the_catch_all_takes_every_other_name() {
    let fake = Fake::new();
    let tunnel_dns = Ipv4Addr::new(10, 255, 0, 53);
    let lab_dns = Ipv4Addr::new(10, 255, 1, 53);
    let split = SplitDns {
        resolvers: vec![lab_dns],
        domains: vec!["lab.example".to_string()],
    };
    fake.set_split_dns(TUNNEL, &split).unwrap();
    assert_eq!(fake.resolvers_for("www.example.org"), [ROUTER]);
    assert_eq!(fake.catch_all_dns_matches(&[tunnel_dns]), Verified::No);

    fake.set_catch_all_dns(&[tunnel_dns]).unwrap();
    assert_eq!(fake.resolvers_for("www.example.org"), [tunnel_dns]);
    assert_eq!(fake.resolvers_for("a.lab.example"), [lab_dns]);
    assert_eq!(fake.catch_all_dns_matches(&[tunnel_dns]), Verified::Yes);
    assert_eq!(fake.catch_all_dns_matches(&[lab_dns]), Verified::No);
    fake.clear_catch_all_dns().unwrap();
    assert_eq!(fake.resolvers_for("www.example.org"), [ROUTER]);
    assert_eq!(fake.applied().split_dns.map(|(_, dns)| dns), Some(split));

    fake.set_catch_all_dns(&[tunnel_dns]).unwrap();
    fake.clear_split_dns().unwrap();
    assert_eq!(fake.applied().catch_all_dns, None);

    assert_eq!(fake.foreign_catch_all(), Ok(false));
    fake.set_foreign_catch_all(true);
    assert_eq!(fake.foreign_catch_all(), Ok(true));
    assert_eq!(
        fake.set_catch_all_dns(&[tunnel_dns]),
        Err(Error::AlreadyExists)
    );
    assert_eq!(fake.applied().catch_all_dns, None);
}

// A router outside every network the machine is on would be routed into
// the tunnel by the halves, so full mode needs it on-link.
#[test]
fn the_router_must_be_on_a_local_network() {
    let fake = Fake::new();
    fake.set_local(&[OWN_ADDRESS], &[]);
    let physical = fake.capture_physical(GATEWAY).unwrap();
    assert!(!physical.router_is_on_link());
    fake.set_local(&[OWN_ADDRESS], &[net("10.0.0.0/8"), net("192.168.0.0/24")]);
    let physical = fake.capture_physical(GATEWAY).unwrap();
    assert!(physical.router_is_on_link());
    let direct = PhysicalNetwork {
        next_hop: None,
        on_link: Vec::new(),
        ..physical
    };
    assert!(direct.router_is_on_link());
}

fn user(name: &str) -> UserId {
    name.parse().unwrap()
}

fn subnets() -> [Ipv4Net; 2] {
    ["192.0.2.0/24", "198.51.100.0/24"].map(|s| s.parse().unwrap())
}

fn failed() -> Option<Error> {
    Some(Error::Failed("injected".to_string()))
}

// Security rule: the shared DNS check accepts "in effect, but the OS
// cannot show it" in place of a "yes", and nothing weaker.
#[test]
fn the_dns_check_accepts_yes_or_unobservable_and_nothing_else() {
    let passes = |verdict| {
        std::panic::catch_unwind(|| suite::assert_in_effect(verdict, "split DNS")).is_ok()
    };
    assert!(passes(Verified::Yes));
    assert!(passes(Verified::Unobservable));
    assert!(!passes(Verified::No));
    assert!(!passes(Verified::Unknown));
    // An OS that cannot observe its resolver still passes the suite.
    let fake = Fake::new();
    fake.cannot_observe(Op::VerifyDns, true);
    suite::check_dns(&fake, TUNNEL, &|name| fake.resolvers_for(name));
}

#[test]
fn passes_the_shared_suite_and_ends_clean() {
    let fake = Fake::new();
    suite::check_routes(&fake, TUNNEL);
    suite::check_configure_tunnel(&fake, &fake, TUNNEL);
    let restarted = || Box::new(fake.clone()) as Box<dyn Routes>;
    suite::check_route_ownership(&fake, &restarted, &fake, TUNNEL);
    suite::check_dns(&fake, TUNNEL, &|name| fake.resolvers_for(name));
    let as_stranger = |name: &str| fake.connect_as(name, &user("stranger"));
    suite::check_transport(&fake, "suite", &as_stranger);
    assert_eq!(fake.applied(), Applied::default());
    assert!(fake.state().listeners.is_empty());
}

#[test]
fn records_calls_in_order_and_the_resulting_state() {
    let fake = Fake::new();
    let [subnet, _] = subnets();
    let physical = fake.capture_physical(GATEWAY).unwrap();
    fake.add_gateway_route(GATEWAY, &physical).unwrap();
    fake.add_tunnel_routes(TUNNEL, &[subnet, subnet]).unwrap();
    let _events = fake.subscribe(&physical).unwrap();
    let expected = [
        Op::CapturePhysical,
        Op::AddGatewayRoute,
        Op::AddTunnelRoutes,
    ];
    assert_eq!(fake.calls(), expected);
    let applied = fake.applied();
    assert_eq!(applied.gateway_routes, [(GATEWAY, physical)]);
    assert_eq!(applied.tunnel_routes, [(TUNNEL.to_string(), subnet)]);
}

#[test]
fn a_failing_operation_changes_nothing_until_healed() {
    let fake = Fake::new();
    let physical = fake.capture_physical(GATEWAY).unwrap();
    fake.set_failure(Op::AddGatewayRoute, Some(Error::PermissionDenied));
    let refused = fake.add_gateway_route(GATEWAY, &physical);
    assert_eq!(refused, Err(Error::PermissionDenied));
    assert_eq!(fake.applied(), Applied::default());
    assert_eq!(fake.calls(), [Op::CapturePhysical, Op::AddGatewayRoute]);
    fake.set_failure(Op::AddGatewayRoute, None);
    assert_eq!(fake.add_gateway_route(GATEWAY, &physical), Ok(()));
}

// "On error some may have been added": the fake leaves some, so a service
// that does not clean up after a failed add fails its tests.
#[test]
fn a_failing_add_of_tunnel_routes_leaves_some_behind() {
    let fake = Fake::new();
    let [first, _] = subnets();
    fake.set_failure(Op::AddTunnelRoutes, failed());
    assert!(fake.add_tunnel_routes(TUNNEL, &subnets()).is_err());
    assert_eq!(fake.applied().tunnel_routes, [(TUNNEL.to_string(), first)]);
    assert_eq!(fake.remove_all(), Ok(()));
    assert_eq!(fake.applied(), Applied::default());
}

#[test]
fn records_configuring_the_tunnel_in_order_and_can_fail_it() {
    let fake = Fake::new();
    let address = Ipv4Addr::new(10, 255, 0, 2);
    fake.capture_physical(GATEWAY).unwrap();
    fake.configure_tunnel(TUNNEL, address, 1300).unwrap();
    fake.add_tunnel_routes(TUNNEL, &subnets()).unwrap();
    let order = [
        Op::CapturePhysical,
        Op::ConfigureTunnel,
        Op::AddTunnelRoutes,
    ];
    assert_eq!(fake.calls(), order);
    assert_eq!(
        (fake.device_addresses(TUNNEL), fake.device_mtu(TUNNEL)),
        (vec![address], Some(1300))
    );

    fake.set_failure(Op::ConfigureTunnel, failed());
    let other = Ipv4Addr::new(10, 255, 0, 3);
    assert_eq!(fake.configure_tunnel(TUNNEL, other, 1400).err(), failed());
    // The failed call is recorded and changed nothing.
    assert_eq!(
        (fake.device_addresses(TUNNEL), fake.device_mtu(TUNNEL)),
        (vec![address], Some(1300))
    );
    let tunnel = TUNNEL.to_string();
    let expected = [(tunnel.clone(), address, 1300), (tunnel, other, 1400)];
    assert_eq!(fake.configured(), expected);
}

// The address goes with the device, and so do its routes; a device that
// is gone cannot be configured.
#[test]
fn a_device_that_is_gone_takes_its_address_and_routes_with_it() {
    let fake = Fake::new();
    let address = Ipv4Addr::new(10, 255, 0, 2);
    fake.configure_tunnel(TUNNEL, address, 1300).unwrap();
    fake.add_tunnel_routes(TUNNEL, &subnets()).unwrap();
    fake.set_device(TUNNEL, false);
    assert_eq!(
        (fake.device_addresses(TUNNEL), fake.device_mtu(TUNNEL)),
        (vec![], None)
    );
    assert_eq!(fake.applied(), Applied::default());
    let gone = fake.configure_tunnel(TUNNEL, address, 1300);
    assert_eq!(gone, Err(Error::NotFound));
    let unrouted = fake.add_tunnel_routes(TUNNEL, &subnets());
    assert_eq!(unrouted, Err(Error::NotFound));
    fake.set_device(TUNNEL, true);
    assert_eq!(fake.configure_tunnel(TUNNEL, address, 1300), Ok(()));
}

#[test]
fn captures_the_local_networks_a_test_sets() {
    let fake = Fake::new();
    let physical = fake.capture_physical(GATEWAY).unwrap();
    assert_eq!(physical.own_addresses(), [OWN_ADDRESS]);
    assert!(physical.on_link()[0].contains_addr(OWN_ADDRESS));
    let bridge: Ipv4Net = "172.17.0.0/16".parse().unwrap();
    let own = [OWN_ADDRESS, Ipv4Addr::new(172, 17, 0, 1)];
    fake.set_local(&own, &[bridge]);
    let physical = fake.capture_physical(GATEWAY).unwrap();
    assert_eq!(physical.own_addresses(), own);
    assert_eq!(physical.on_link(), [bridge]);
}

// An address the OS does not use is one of the machine's own, but puts
// it on no network, and no route comes with it.
#[test]
fn an_unused_address_is_the_machines_own_but_no_network() {
    let fake = Fake::new();
    let unused = Ipv4Addr::new(169, 254, 10, 20);
    fake.add_unused_address(unused, 16);
    let physical = fake.capture_physical(GATEWAY).unwrap();
    assert_eq!(physical.own_addresses(), [OWN_ADDRESS, unused]);
    assert_eq!(physical.on_link(), ["192.168.0.0/24".parse().unwrap()]);
    fake.add_full_tunnel(TUNNEL).unwrap();
    let neighbour = Ipv4Addr::new(169, 254, 10, 21);
    assert_eq!(fake.uses_interface(neighbour, TUNNEL), Verified::Yes);
}

// An OS that cannot honour split DNS refuses, and nothing is changed.
#[test]
fn split_dns_can_be_refused_as_unsupported() {
    let fake = Fake::new();
    let dns = SplitDns {
        resolvers: vec![Ipv4Addr::new(192, 0, 2, 53)],
        domains: vec!["dept.example".to_string()],
    };
    fake.set_failure(Op::SetSplitDns, Some(Error::Unsupported));
    assert_eq!(fake.set_split_dns(TUNNEL, &dns), Err(Error::Unsupported));
    assert_eq!(fake.applied(), Applied::default());
    assert_eq!(fake.resolvers_for("www.dept.example"), [ROUTER]);
}

// The suite's ownership check must notice an implementation that takes a
// route which was there first for its own.
#[test]
fn the_ownership_check_catches_a_route_taken_over() {
    struct Greedy(Fake);
    impl Routes for Greedy {
        fn capture_physical(&self, gateway: Ipv4Addr) -> Result<PhysicalNetwork> {
            self.0.capture_physical(gateway)
        }
        fn configure_tunnel(&self, tunnel: &str, address: Ipv4Addr, mtu: u16) -> Result<()> {
            self.0.configure_tunnel(tunnel, address, mtu)
        }
        fn add_gateway_route(&self, gateway: Ipv4Addr, via: &PhysicalNetwork) -> Result<()> {
            self.0.add_gateway_route(gateway, via)
        }
        fn remove_gateway_route(&self, gw: Ipv4Addr, via: &PhysicalNetwork) -> Result<()> {
            self.0.remove_gateway_route(gw, via)
        }
        fn add_tunnel_routes(&self, tunnel: &str, subnets: &[Ipv4Net]) -> Result<()> {
            self.0.add_tunnel_routes(tunnel, subnets)
        }
        // Removes whatever matches, its own or not.
        fn remove_tunnel_routes(&self, tunnel: &str, subnets: &[Ipv4Net]) -> Result<()> {
            for subnet in subnets {
                self.0.remove_foreign_route(tunnel, *subnet);
            }
            self.0.remove_tunnel_routes(tunnel, subnets)
        }
        fn remove_all(&self) -> Result<()> {
            self.0.remove_all()
        }
        fn uses_interface(&self, dest: Ipv4Addr, interface: &str) -> Verified {
            self.0.uses_interface(dest, interface)
        }
        fn full_tunnel_ipv6(&self, tunnel: &str) -> Result<Ipv6Block> {
            self.0.full_tunnel_ipv6(tunnel)
        }
        fn add_full_tunnel(&self, tunnel: &str) -> Result<Ipv6Block> {
            self.0.add_full_tunnel(tunnel)
        }
        fn remove_full_tunnel(&self, tunnel: &str) -> Result<()> {
            self.0.remove_full_tunnel(tunnel)
        }
        fn foreign_full_tunnel(&self, tunnel: &str) -> Result<bool> {
            self.0.foreign_full_tunnel(tunnel)
        }
        fn uses_interface_v6(&self, dest: Ipv6Addr, interface: &str) -> Verified {
            self.0.uses_interface_v6(dest, interface)
        }
    }
    let fake = Fake::new();
    let greedy = Greedy(fake.clone());
    let restarted = || Box::new(fake.clone()) as Box<dyn Routes>;
    let check = std::panic::AssertUnwindSafe(|| {
        suite::check_route_ownership(&greedy, &restarted, &fake, TUNNEL);
    });
    assert!(std::panic::catch_unwind(check).is_err());
}

// Security rule: the physical network is captured before the tunnel
// exists. Captured later it could be the tunnel, the previous client's bug.
#[test]
fn refuses_to_capture_the_physical_network_too_late() {
    let fake = Fake::new();
    fake.add_tunnel_routes(TUNNEL, &subnets()).unwrap();
    assert!(matches!(
        fake.capture_physical(GATEWAY),
        Err(Error::Failed(_))
    ));
    fake.remove_all().unwrap();
    assert!(fake.capture_physical(GATEWAY).is_ok());
}

// Crash recovery: a new run has no PhysicalNetwork and no memory of what
// the old one added, and must still be able to remove it all.
#[test]
fn a_later_run_can_remove_what_an_earlier_one_left() {
    let fake = Fake::new();
    let dns = SplitDns {
        resolvers: vec![Ipv4Addr::new(192, 0, 2, 53)],
        domains: vec!["dept.example".to_string()],
    };
    {
        let crashed = fake.platform(Path::new("fake"));
        let physical = crashed.routes.capture_physical(GATEWAY).unwrap();
        crashed
            .routes
            .add_gateway_route(GATEWAY, &physical)
            .unwrap();
        crashed
            .routes
            .add_tunnel_routes(TUNNEL, &subnets())
            .unwrap();
        crashed.dns.set_split_dns(TUNNEL, &dns).unwrap();
    }
    let restarted = fake.platform(Path::new("fake"));
    restarted.routes.remove_all().unwrap();
    restarted.dns.clear_split_dns().unwrap();
    assert_eq!(fake.applied(), Applied::default());
}

// Security rule: "could not tell" is its own answer, never a "no" and
// never a "yes", so the service can fail closed on it.
#[test]
fn could_not_determine_is_distinct_from_no() {
    let fake = Fake::new();
    let dns = SplitDns {
        resolvers: vec![Ipv4Addr::new(192, 0, 2, 53)],
        domains: vec!["dept.example".to_string()],
    };
    fake.set_split_dns(TUNNEL, &dns).unwrap();
    assert_eq!(fake.uses_interface(GATEWAY, TUNNEL), Verified::No);
    assert_eq!(fake.split_dns_matches(&dns), Verified::Yes);

    fake.set_failure(Op::VerifyRoute, failed());
    fake.set_failure(Op::VerifyDns, failed());
    let route = fake.uses_interface(GATEWAY, PHYSICAL_INTERFACE);
    assert_eq!(route, Verified::Unknown);
    assert_eq!(fake.split_dns_matches(&dns), Verified::Unknown);
    assert_ne!(Verified::Unknown, Verified::No);
}

// A check that cannot be observed answers so only where it would have
// answered "yes". A setting that differs is still "no", and a check
// that could not ask is still "could not tell".
#[test]
fn cannot_observe_replaces_only_a_yes() {
    let fake = Fake::new();
    let dns = SplitDns {
        resolvers: vec![Ipv4Addr::new(192, 0, 2, 53)],
        domains: vec!["dept.example".to_string()],
    };
    let other = SplitDns {
        domains: vec!["other.example".to_string()],
        ..dns.clone()
    };
    fake.set_split_dns(TUNNEL, &dns).unwrap();
    fake.cannot_observe(Op::VerifyDns, true);
    assert_eq!(fake.split_dns_matches(&dns), Verified::Unobservable);
    assert_eq!(fake.split_dns_matches(&other), Verified::No);
    // Only the check it was asked for.
    let route = fake.uses_interface(GATEWAY, PHYSICAL_INTERFACE);
    assert_eq!(route, Verified::Yes);
    fake.set_failure(Op::VerifyDns, failed());
    assert_eq!(fake.split_dns_matches(&dns), Verified::Unknown);
    fake.set_failure(Op::VerifyDns, None);
    fake.cannot_observe(Op::VerifyDns, false);
    assert_eq!(fake.split_dns_matches(&dns), Verified::Yes);
    // One destination alone, and a route "no" stays "no".
    let elsewhere = Ipv4Addr::new(198, 51, 100, 1);
    fake.cannot_observe_route_to(GATEWAY);
    let route = fake.uses_interface(GATEWAY, PHYSICAL_INTERFACE);
    assert_eq!(route, Verified::Unobservable);
    let route = fake.uses_interface(elsewhere, PHYSICAL_INTERFACE);
    assert_eq!(route, Verified::Yes);
    assert_eq!(fake.uses_interface(GATEWAY, TUNNEL), Verified::No);
    // Every route.
    fake.cannot_observe(Op::VerifyRoute, true);
    let route = fake.uses_interface(elsewhere, PHYSICAL_INTERFACE);
    assert_eq!(route, Verified::Unobservable);
    assert_eq!(fake.uses_interface(elsewhere, TUNNEL), Verified::No);
}

// A subscription whose drop never returns fails the suite's check, and
// the check does not hang on the ones it had not dropped yet.
#[test]
fn a_subscription_that_never_ends_fails_the_check_without_hanging_it() {
    /// Ends never: dropping it waits for ever.
    struct Stuck;
    impl Drop for Stuck {
        fn drop(&mut self) {
            loop {
                std::thread::park();
            }
        }
    }
    struct Hanging(std::sync::Arc<std::sync::atomic::AtomicUsize>);
    impl NetworkEvents for Hanging {
        fn subscribe(&self, _watching: &PhysicalNetwork) -> Result<Subscription> {
            self.0.fetch_add(1, Ordering::SeqCst);
            let (_sender, receiver) = mpsc::channel();
            Ok(Subscription::new(receiver, Stuck))
        }
        fn reports_ipv6_changes(&self) -> bool {
            false
        }
    }
    let fake = Fake::new();
    let physical = fake.capture_physical(GATEWAY).unwrap();
    let count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let hanging = Hanging(count.clone());
    let (done, finished) = mpsc::channel();
    std::thread::spawn(move || {
        let check = std::panic::AssertUnwindSafe(|| {
            suite::check_subscription_ends(&hanging, &physical, &|| count.load(Ordering::SeqCst));
        });
        let _ = done.send(std::panic::catch_unwind(check).is_err());
    });
    let failed = finished.recv_timeout(Duration::from_secs(20));
    assert_eq!(failed, Ok(true), "the check hung or passed");
}

// A dropped subscription is gone at once, and the suite notices one that
// lingers until the next event.
#[test]
fn a_dropped_subscription_ends_at_once() {
    let fake = Fake::new();
    let physical = fake.capture_physical(GATEWAY).unwrap();
    suite::check_subscription_ends(&fake, &physical, &|| fake.subscriptions());

    // One that ends only when it next has something to deliver.
    struct Lingering(Fake);
    impl NetworkEvents for Lingering {
        fn subscribe(&self, watching: &PhysicalNetwork) -> Result<Subscription> {
            let inner = self.0.subscribe(watching)?;
            let (sender, receiver) = mpsc::channel();
            drop(sender);
            // Keeps the fake's subscription after the drop.
            std::mem::forget(inner);
            Ok(Subscription::new(receiver, ()))
        }
        fn reports_ipv6_changes(&self) -> bool {
            false
        }
    }
    let lingering = Lingering(fake.clone());
    let check = std::panic::AssertUnwindSafe(|| {
        suite::check_subscription_ends(&lingering, &physical, &|| fake.subscriptions());
    });
    assert!(std::panic::catch_unwind(check).is_err());
}

#[test]
fn delivers_injected_events_to_every_subscriber() {
    let fake = Fake::new();
    let physical = fake.capture_physical(GATEWAY).unwrap();
    let subscribe = || fake.subscribe(&physical).unwrap();
    let (first, second) = (subscribe(), subscribe());
    drop(subscribe());
    fake.send_event(NetworkEvent::PhysicalChanged);
    fake.send_event(NetworkEvent::Sleeping);
    assert_eq!(first.events().try_recv(), Ok(NetworkEvent::PhysicalChanged));
    assert_eq!(first.events().try_recv(), Ok(NetworkEvent::Sleeping));
    assert_eq!(
        second.events().try_recv(),
        Ok(NetworkEvent::PhysicalChanged)
    );

    fake.set_failure(Op::Subscribe, failed());
    assert_eq!(fake.subscribe(&physical).err(), failed());
}

// Security rule: the service learns who is calling from the transport,
// and once narrowed to an owner nobody else gets a new connection.
#[test]
fn reports_the_caller_and_refuses_others_once_restricted() {
    let fake = Fake::new();
    let listener = fake.listen("svc").unwrap();
    let _mallory = fake.connect_as("svc", &user("mallory")).unwrap();
    let _queued = fake.connect_as("svc", &user("mallory")).unwrap();
    assert_eq!(listener.accept().unwrap().1, user("mallory"));

    listener.restrict_to(&user("alice")).unwrap();
    let refused = fake.connect_as("svc", &user("mallory")).err();
    assert_eq!(refused, Some(Error::PermissionDenied));
    assert_eq!(fake.connect("svc").err(), Some(Error::PermissionDenied));
    // A connection made before narrowing still arrives, as on a real OS:
    // the service has to check every caller itself.
    assert_eq!(listener.accept().unwrap().1, user("mallory"));
    let _alice = fake.connect_as("svc", &user("alice")).unwrap();
    assert_eq!(listener.accept().unwrap().1, user("alice"));
}

#[test]
fn transport_operations_can_be_made_to_fail() {
    let fake = Fake::new();
    fake.set_failure(Op::Listen, Some(Error::PermissionDenied));
    assert_eq!(fake.listen("svc").err(), Some(Error::PermissionDenied));
    fake.set_failure(Op::Listen, None);
    let listener = fake.listen("svc").unwrap();
    // A listener that is not the service: the caller gets no connection,
    // so it cannot send anything, and the listener sees nobody.
    fake.set_failure(Op::Connect, Some(Error::NotTheService));
    assert_eq!(fake.connect("svc").err(), Some(Error::NotTheService));
    fake.set_failure(Op::Connect, None);
    let _first = fake.connect("svc").unwrap();
    assert_eq!(listener.accept().unwrap().1, user("fake-user"));
    fake.set_failure(Op::RestrictTo, failed());
    assert_eq!(listener.restrict_to(&user("alice")).err(), failed());
    // The failed narrowing narrowed nothing.
    assert!(fake.connect_as("svc", &user("mallory")).is_ok());
    assert_eq!(fake.calls(), []);
}

// A listener that was closed must not release a name someone else has
// claimed since.
#[test]
fn a_closed_listener_no_longer_owns_the_name() {
    let fake = Fake::new();
    let old = fake.listen("svc").unwrap();
    old.close();
    let _new = fake.listen("svc").unwrap();
    assert_eq!(old.restrict_to(&user("alice")), Err(Error::Closed));
    drop(old);
    assert_eq!(fake.listen("svc").err(), Some(Error::AlreadyExists));
}

// Security rule: dev mode never shares a file or a channel with the
// installed product. The check must notice when it would.
#[test]
fn the_paths_check_catches_a_collision() {
    let installed = paths(Path::new("installed"));
    let collides = |other: &Paths| {
        let (installed, other) = (installed.clone(), other.clone());
        let checks = [
            std::panic::catch_unwind(|| suite::check_paths(&installed, &other)),
            std::panic::catch_unwind(|| suite::check_paths(&other, &installed)),
        ];
        assert_eq!(checks[0].is_err(), checks[1].is_err(), "not symmetric");
        checks[0].is_err()
    };
    let mut dev = paths(Path::new("dev"));
    assert!(!collides(&dev), "two roots share nothing");
    dev.state_dir = installed.policy_dir.join("dev");
    assert!(collides(&dev), "a dev folder inside an installed one");
    dev = paths(Path::new("dev"));
    dev.channel_name = installed.channel_name.clone();
    assert!(collides(&dev), "same channel name");
}
