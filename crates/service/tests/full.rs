//! Full mode, driven over the channel: connecting in it, switching a live
//! tunnel into it and out of it, and what it refuses. Tests marked
//! "Security rule" must fail if the rule they name is removed. Every
//! address is made up, or a private range such as a home network
//! as the harness plays it.

mod harness;

use std::net::Ipv4Addr;

use harness::*;
use ubc_vpn_core::routes::Ipv4Net;
use ubc_vpn_platform::fake::{FullTunnel, PHYSICAL_INTERFACE};
use ubc_vpn_platform::{Ipv6Block, Routes, SplitDns, Verified};

const ACCEPTED: Result<ResponseBody, ErrorCode> = Ok(ResponseBody::Accepted);
const DNS_SERVER: Ipv4Addr = Ipv4Addr::new(10, 255, 0, 53);

fn net(text: &str) -> Ipv4Net {
    text.parse().unwrap()
}

fn failed_with(state: &ConnState, expected: ErrorCode) -> bool {
    matches!(state, ConnState::Failed { code, .. } if *code == expected)
}

fn message_of(state: &ConnState) -> &str {
    match state {
        ConnState::Failed { message, .. } => message,
        other => panic!("not failed: {other:?}"),
    }
}

/// Full mode as the fake has it, through the pretend tunnel.
fn halves(ipv6: Ipv6Block) -> Option<FullTunnel> {
    let tunnel = "fake0".to_string();
    Some(FullTunnel { tunnel, ipv6 })
}

/// A rig on a home network, with the owner's first connection.
fn home_rig() -> (Rig, Peer) {
    let rig = rig();
    home_network(&rig.fake);
    let alice = rig.owner();
    (rig, alice)
}

/// The position of `op` in `calls`, which must hold it.
fn at(calls: &[Op], op: Op) -> usize {
    let found = calls.iter().position(|call| *call == op);
    found.unwrap_or_else(|| panic!("{op:?} never called: {calls:?}"))
}

/// Makes the read `op`, one of full mode's checks, fail with an error that
/// says nothing about the answer.
fn unreadable_op(rig: &Rig, op: Op) {
    rig.fake.set_failure(op, Some(Error::NotFound));
}

/// The calls that only read.
fn reads_only(calls: &[Op]) -> bool {
    calls.iter().all(|call| {
        matches!(
            call,
            Op::ForeignFullTunnel | Op::ForeignCatchAll | Op::FullTunnelIpv6
        )
    })
}

// Security rule: in full mode the service adds the tunnel's own routes (the
// DNS server's among them), then the halves, then split DNS and the
// catch-all, and reports "connected" only after checking each of them. The
// home network stays direct, home and host-only networks alike, though
// the host-only ones are on adapters of their own; everything else goes
// through the tunnel, and every name goes to the gateway's DNS server.
#[test]
fn connect_in_full_mode_applies_in_order_and_verifies() {
    let (rig, mut alice) = home_rig();
    let state = alice.connect_ends(good_full());
    assert_eq!(mode_of(&state), TunnelMode::Full, "{state:?}");

    let calls = rig.fake.calls();
    let order = [
        Op::ConfigureTunnel,
        Op::AddGatewayRoute,
        Op::AddTunnelRoutes,
        Op::AddFullTunnel,
        Op::SetSplitDns,
        Op::SetCatchAllDns,
    ];
    let places = order.map(|op| at(&calls, op));
    assert!(places.is_sorted(), "{calls:?}");
    // Each read before anything was changed, and every check after the
    // last change.
    for read in [
        Op::ForeignCatchAll,
        Op::ForeignFullTunnel,
        Op::FullTunnelIpv6,
    ] {
        assert!(at(&calls, read) < places[0], "{read:?}: {calls:?}");
    }
    assert!(at(&calls, Op::ForeignCatchAll) < at(&calls, Op::ConfigureTunnel));
    let checks = [Op::VerifyRoute, Op::VerifyRouteV6, Op::VerifyCatchAllDns];
    for check in checks {
        assert!(at(&calls, check) > places[5], "{check:?}: {calls:?}");
    }

    let applied = rig.fake.applied();
    assert_eq!(applied.full_tunnel, halves(Ipv6Block::Blocked));
    assert_eq!(applied.catch_all_dns, Some(vec![DNS_SERVER]));
    let routed: Vec<_> = applied.tunnel_routes.iter().map(|(_, n)| *n).collect();
    assert!(routed.contains(&net("10.255.0.53/32")), "{routed:?}");
    for name in [
        "www.example.com".to_string(),
        "intranet.example.org".to_string(),
        chosen_domain(),
    ] {
        assert_eq!(rig.fake.resolvers_for(&name), [DNS_SERVER], "{name}");
    }
    let stays = [
        ([10, 200, 0, 1], PHYSICAL_INTERFACE),
        ([10, 200, 0, 200], PHYSICAL_INTERFACE),
        ([172, 31, 130, 128], "fake-host1"),
        ([172, 31, 140, 254], "fake-host2"),
    ];
    for (addr, adapter) in stays {
        let addr = Ipv4Addr::from(addr);
        assert_eq!(rig.fake.uses_interface(addr, adapter), Verified::Yes);
    }
    let away = Ipv4Addr::new(203, 0, 113, 7);
    assert_eq!(rig.fake.uses_interface(away, "fake0"), Verified::Yes);
    assert_eq!(
        alice.ask(RequestBody::Status),
        Ok(ResponseBody::Status(state))
    );

    // A disconnect removes the halves, then the catch-all, then the rest.
    let before = rig.fake.calls().len();
    assert_eq!(alice.ask(RequestBody::Disconnect), ACCEPTED);
    assert_eq!(
        [alice.state(), alice.state()],
        [ConnState::Disconnecting, ConnState::Disconnected]
    );
    let teardown = [
        Op::RemoveFullTunnel,
        Op::ClearCatchAllDns,
        Op::RemoveTunnelRoutes,
        Op::ClearSplitDns,
        Op::RemoveGatewayRoute,
        Op::RemoveAllRoutes,
    ];
    assert_eq!(rig.fake.calls()[before..], teardown);
    assert!(rig.is_clean());
}

// With no DNS domains, full mode still routes the gateway's DNS server
// through the tunnel and sends every name there; no split DNS is set.
#[test]
fn full_mode_without_domains_still_sends_every_name_to_the_gateway() {
    let (rig, mut alice) = home_rig();
    let state = alice.connect_ends(full(&["192.0.2.0/24"], &[]));
    assert_eq!(mode_of(&state), TunnelMode::Full, "{state:?}");
    let applied = rig.fake.applied();
    assert_eq!(applied.split_dns, None);
    assert_eq!(applied.catch_all_dns, Some(vec![DNS_SERVER]));
    let routed = [
        ("fake0".to_string(), net("192.0.2.0/24")),
        ("fake0".to_string(), net("10.255.0.53/32")),
    ];
    assert_eq!(applied.tunnel_routes, routed);
    assert!(!rig.fake.calls().contains(&Op::SetSplitDns));
}

// With no IPv6 on the tunnel and no IPv6 leak path anywhere, there is no
// IPv6 to block: full mode connects without the IPv6 halves, and checks
// that this is still so instead of checking them.
#[test]
fn full_mode_with_no_ipv6_to_block_connects() {
    let (rig, mut alice) = home_rig();
    rig.fake.set_ipv6(false, false);
    let state = alice.connect_ends(good_full());
    assert_eq!(mode_of(&state), TunnelMode::Full, "{state:?}");
    assert_eq!(
        rig.fake.applied().full_tunnel,
        halves(Ipv6Block::NothingToBlock)
    );
    let calls = rig.fake.calls();
    assert!(!calls.contains(&Op::VerifyRouteV6), "{calls:?}");
    let asked = calls.iter().filter(|call| **call == Op::FullTunnelIpv6);
    assert_eq!(asked.count(), 2, "asked before the change and in the check");
}

// Security rule: what full mode needs is checked before the gateway is
// contacted where it can be, and otherwise before anything is applied.
// Each refusal is `route_refused` with a message naming its cause, and
// leaves nothing behind.
#[test]
fn each_reason_full_mode_cannot_be_had_refuses_the_connect() {
    // Refused at once, with nothing done.
    let forbidden = Rig::stopped(policy('A', r#","full_tunnel":"forbidden""#));
    let unwatched = rig();
    unwatched.fake.set_reports_ipv6_changes(false);
    for (case, mut rig) in [("policy", forbidden), ("ipv6 events", unwatched)] {
        if rig.service.is_none() {
            rig.start().unwrap();
        }
        let mut alice = rig.owner();
        assert_eq!(
            alice.ask(good_full()),
            Err(ErrorCode::RouteRefused),
            "{case}"
        );
        assert!(
            rig.fake
                .calls()
                .iter()
                .all(|call| matches!(call, Op::RemoveAllRoutes | Op::ClearSplitDns)),
            "{case}: {:?}",
            rig.fake.calls()
        );
        assert!(rig.spy.opens().is_empty(), "{case}");
    }

    // Refused by the worker. The first three before the gateway is
    // contacted, the rest once the tunnel is open and before anything is
    // applied to it. A check that could not be made refuses too: "could
    // not tell" is not "no".
    type Setup = fn(&Rig);
    let unreadable = "could not be checked";
    let cases: [(&str, Setup, bool, &str); 9] = [
        (
            "router",
            |rig| {
                rig.fake
                    .set_local(&[[10, 201, 0, 10].into()], &[net("10.201.0.0/24")])
            },
            false,
            "router",
        ),
        (
            "catch-all",
            |rig| rig.fake.set_foreign_catch_all(true),
            false,
            "already resolves all names",
        ),
        (
            "catch-all unreadable",
            |rig| unreadable_op(rig, Op::ForeignCatchAll),
            false,
            unreadable,
        ),
        (
            "halves",
            |rig| rig.fake.add_foreign_route("other0", net("0.0.0.0/1")),
            true,
            "already sends all traffic",
        ),
        (
            "halves unreadable",
            |rig| unreadable_op(rig, Op::ForeignFullTunnel),
            true,
            unreadable,
        ),
        (
            "ipv6 unreadable",
            |rig| unreadable_op(rig, Op::FullTunnelIpv6),
            true,
            unreadable,
        ),
        ("no dns server", |_| {}, true, "no DNS server"),
        (
            "ipv6 leak",
            |rig| rig.fake.set_ipv6(false, true),
            true,
            "IPv6",
        ),
        ("unusable dns server", |_| {}, true, "DNS server"),
    ];
    for (case, setup, opened, words) in cases {
        let mut rig = Rig::scripted(policy('A', ""), |script| match case {
            "no dns server" => script.assigned.dns.clear(),
            "unusable dns server" => script.assigned.dns = vec![[127, 0, 0, 1].into()],
            _ => {}
        });
        rig.start().unwrap();
        setup(&rig);
        let mut alice = rig.owner();
        let state = alice.connect_ends(full(&["192.0.2.0/24"], &[]));
        let code = match case {
            "unusable dns server" => ErrorCode::EngineFailed,
            _ => ErrorCode::RouteRefused,
        };
        assert!(failed_with(&state, code), "{case}: {state:?}");
        assert!(message_of(&state).contains(words), "{case}: {state:?}");
        assert_eq!(rig.spy.opens().len(), usize::from(opened), "{case}");
        let calls = rig.fake.calls();
        assert!(!calls.contains(&Op::ConfigureTunnel), "{case}: {calls:?}");
        assert!(!calls.contains(&Op::AddFullTunnel), "{case}: {calls:?}");
        rig.fake.remove_foreign_route("other0", net("0.0.0.0/1"));
        rig.fake.set_foreign_catch_all(false);
        assert!(rig.is_clean(), "{case} left something behind");
    }
}

/// Connected in split mode with `good()`, on a home network.
fn split_connected() -> (Rig, Peer, ConnState) {
    let (rig, mut alice) = home_rig();
    let state = alice.connect_ends(good());
    assert_eq!(mode_of(&state), TunnelMode::Split, "{state:?}");
    (rig, alice, state)
}

// Security rule: a live switch to full adds the halves, then the catch-all,
// and checks; a switch back clears the catch-all, then removes the halves,
// and checks that addresses outside the chosen subnets no longer use the
// tunnel. The tunnel is never reopened.
#[test]
fn a_live_switch_to_full_and_back_never_reconnects() {
    let (rig, mut alice, _) = split_connected();
    let before = rig.fake.calls().len();
    assert_eq!(alice.ask(set_tunnel(TunnelMode::Full)), ACCEPTED);
    let state = alice.state();
    assert_eq!(mode_of(&state), TunnelMode::Full, "{state:?}");
    let calls = rig.fake.calls()[before..].to_vec();
    let added = at(&calls, Op::AddFullTunnel);
    assert!(reads_only(&calls[..added]), "{calls:?}");
    assert!(added < at(&calls, Op::SetCatchAllDns), "{calls:?}");
    assert!(at(&calls, Op::SetCatchAllDns) < at(&calls, Op::VerifyCatchAllDns));
    assert!(at(&calls, Op::SetCatchAllDns) < at(&calls, Op::VerifyRouteV6));
    let applied = rig.fake.applied();
    assert_eq!(applied.full_tunnel, halves(Ipv6Block::Blocked));
    assert_eq!(applied.catch_all_dns, Some(vec![DNS_SERVER]));
    assert_eq!(
        alice.ask(RequestBody::Status),
        Ok(ResponseBody::Status(state))
    );

    let before = rig.fake.calls().len();
    assert_eq!(alice.ask(set_tunnel(TunnelMode::Split)), ACCEPTED);
    let state = alice.state();
    assert_eq!(mode_of(&state), TunnelMode::Split, "{state:?}");
    let calls = rig.fake.calls()[before..].to_vec();
    assert_eq!(calls[..2], [Op::ClearCatchAllDns, Op::RemoveFullTunnel]);
    let applied = rig.fake.applied();
    assert_eq!((applied.full_tunnel, applied.catch_all_dns), (None, None));
    let dns = SplitDns {
        resolvers: vec![DNS_SERVER],
        domains: vec![chosen_domain()],
    };
    assert_eq!(applied.split_dns, Some(("fake0".to_string(), dns)));
    let away = Ipv4Addr::new(203, 0, 113, 7);
    assert_eq!(
        rig.fake.uses_interface(away, PHYSICAL_INTERFACE),
        Verified::Yes
    );
    assert_eq!(rig.spy.opens().len(), 1, "the tunnel was opened again");
    assert!(alice.is_quiet(), "a state was reported");
}

// The bug seen on a real machine: adapters that are not connected have
// tentative 169.254.x.x addresses with no route. They are not networks the
// machine is on, so full mode does not ask that 169.254.0.0/16 stay off the
// tunnel, and the switch, and a connect in full mode, succeed.
#[test]
fn an_unused_link_local_address_does_not_stop_full_mode() {
    let unused = |rig: &Rig| {
        rig.fake
            .add_unused_address(Ipv4Addr::new(169, 254, 10, 20), 16);
        rig.fake
            .add_unused_address(Ipv4Addr::new(169, 254, 30, 40), 16);
    };
    let rig = rig();
    home_network(&rig.fake);
    unused(&rig);
    let mut alice = rig.owner();
    assert_eq!(mode_of(&alice.connect_ends(good())), TunnelMode::Split);
    assert_eq!(alice.ask(set_tunnel(TunnelMode::Full)), ACCEPTED);
    let state = alice.state();
    assert_eq!(mode_of(&state), TunnelMode::Full, "{state:?}");
    let link_local = Ipv4Addr::new(169, 254, 10, 21);
    assert_eq!(rig.fake.uses_interface(link_local, "fake0"), Verified::Yes);

    let (rig, mut alice) = home_rig();
    unused(&rig);
    let state = alice.connect_ends(good_full());
    assert_eq!(mode_of(&state), TunnelMode::Full, "{state:?}");
}

// Security rule: a 169.254.x.x address that is in use, such as on a cable
// with no DHCP, is a network the machine is on. Its route keeps it off the
// tunnel, and full mode fails if the tunnel takes it.
#[test]
fn a_used_link_local_network_stays_off_the_tunnel() {
    let link_local = net("169.254.0.0/16");
    let (rig, mut alice) = home_rig();
    rig.fake.add_adapter_network("fake-cable", link_local);
    let state = alice.connect_ends(good_full());
    assert_eq!(mode_of(&state), TunnelMode::Full, "{state:?}");
    let inside = Ipv4Addr::new(169, 254, 10, 21);
    assert_eq!(rig.fake.uses_interface(inside, "fake-cable"), Verified::Yes);

    let (rig, mut alice) = home_rig();
    rig.fake.add_adapter_network("fake-cable", link_local);
    rig.fake.add_foreign_route("fake0", net("169.254.0.0/17"));
    let state = alice.connect_ends(good_full());
    assert!(
        failed_with(&state, ErrorCode::VerificationFailed),
        "{state:?}"
    );
    assert!(message_of(&state).contains("169.254.0.0/16"), "{state:?}");
    rig.fake
        .remove_foreign_route("fake0", net("169.254.0.0/17"));
    assert!(rig.is_clean());
}

// A switch to full on a connection made with no domains routes the
// gateway's DNS server through the tunnel first: the catch-all names it.
#[test]
fn a_switch_to_full_routes_the_dns_server_first() {
    let (rig, mut alice) = home_rig();
    let state = alice.connect_ends(connect(COOKIE, GATEWAY, &["192.0.2.0/24"], &[]));
    assert_eq!(mode_of(&state), TunnelMode::Split, "{state:?}");
    let before = rig.fake.calls().len();
    assert_eq!(alice.ask(set_tunnel(TunnelMode::Full)), ACCEPTED);
    assert_eq!(mode_of(&alice.state()), TunnelMode::Full);
    let calls = rig.fake.calls()[before..].to_vec();
    assert!(at(&calls, Op::AddTunnelRoutes) < at(&calls, Op::AddFullTunnel));
    let applied = rig.fake.applied();
    let host = ("fake0".to_string(), net("10.255.0.53/32"));
    assert!(applied.tunnel_routes.contains(&host), "{applied:?}");
    assert_eq!(applied.catch_all_dns, Some(vec![DNS_SERVER]));
}

// A switch to the mode the tunnel has is no change: answered at once with
// the connection as it is, and nothing is done.
#[test]
fn a_switch_to_the_mode_in_effect_changes_nothing() {
    let (rig, mut alice, state) = split_connected();
    let calls = rig.fake.calls();
    let same = alice.ask(set_tunnel(TunnelMode::Split));
    assert_eq!(same, Ok(ResponseBody::Status(state)));
    assert_eq!(rig.fake.calls(), calls, "something was done");
    assert_eq!(alice.ask(set_tunnel(TunnelMode::Full)), ACCEPTED);
    let state = alice.state();
    let calls = rig.fake.calls();
    let same = alice.ask(set_tunnel(TunnelMode::Full));
    assert_eq!(same, Ok(ResponseBody::Status(state)));
    assert_eq!(rig.fake.calls(), calls, "something was done");
    assert!(alice.is_quiet(), "a state was reported");
}

// Without a tunnel there is nothing to switch, which is said with its own
// code, and the mode is used at the next connect.
#[test]
fn a_switch_needs_a_connection() {
    let rig = rig();
    let mut alice = rig.owner();
    for mode in [TunnelMode::Split, TunnelMode::Full] {
        let asked = alice.ask(set_tunnel(mode));
        assert_eq!(asked, Err(ErrorCode::NotConnected), "{mode:?}");
    }
    assert!(rig.is_clean());
}

// Security rule: a switch to full is checked against everything full mode
// needs before anything is changed. Each refusal is `route_refused`, and
// the connection is kept exactly as it was: no change, no state.
#[test]
fn a_refused_switch_leaves_the_connection_as_it_was() {
    type Setup = fn(&Rig);
    let cases: [(&str, Setup); 9] = [
        ("halves", |rig| {
            rig.fake.add_foreign_route("other0", net("128.0.0.0/1"))
        }),
        ("catch-all", |rig| rig.fake.set_foreign_catch_all(true)),
        ("ipv6 leak", |rig| rig.fake.set_ipv6(false, true)),
        ("ipv6 events", |rig| {
            rig.fake.set_reports_ipv6_changes(false)
        }),
        ("no dns server", |_| {}),
        // Not judged at connect: split mode with no domains has no use for
        // the DNS server. Full mode sends every name to it.
        ("dns server on the home network", |_| {}),
        ("catch-all unreadable", |rig| {
            unreadable_op(rig, Op::ForeignCatchAll)
        }),
        ("halves unreadable", |rig| {
            unreadable_op(rig, Op::ForeignFullTunnel)
        }),
        ("ipv6 unreadable", |rig| {
            unreadable_op(rig, Op::FullTunnelIpv6)
        }),
    ];
    for (case, setup) in cases {
        let rig = Rig::scripted(policy('A', ""), |script| match case {
            "no dns server" => script.assigned.dns.clear(),
            "dns server on the home network" => {
                script.assigned.dns = vec![Ipv4Addr::new(10, 200, 0, 53)];
            }
            _ => {}
        });
        let mut rig = rig;
        rig.start().unwrap();
        home_network(&rig.fake);
        let mut alice = rig.owner();
        let first = connect(COOKIE, GATEWAY, &["192.0.2.0/24"], &[]);
        let state = alice.connect_ends(first);
        assert_eq!(mode_of(&state), TunnelMode::Split, "{case}: {state:?}");
        setup(&rig);
        let (calls, applied) = (rig.fake.calls(), rig.fake.applied());
        let asked = alice.ask(set_tunnel(TunnelMode::Full));
        assert_eq!(asked, Err(ErrorCode::RouteRefused), "{case}");
        let done = rig.fake.calls()[calls.len()..].to_vec();
        assert!(reads_only(&done), "{case}: {done:?}");
        assert_eq!(rig.fake.applied(), applied, "{case}: something changed");
        assert!(alice.is_quiet(), "{case}: a state was reported");
        assert_eq!(
            alice.ask(RequestBody::Status),
            Ok(ResponseBody::Status(state)),
            "{case}"
        );
    }
}

// The same for a router that is not on the local network, and for a
// policy that forbids full mode: refused, and the connection kept.
#[test]
fn a_switch_is_refused_for_the_router_and_the_policy() {
    for case in ["router", "policy"] {
        let extra = match case {
            "policy" => r#","full_tunnel":"forbidden""#,
            _ => "",
        };
        let mut rig = Rig::stopped(policy('A', extra));
        rig.start().unwrap();
        if case == "router" {
            rig.fake
                .set_local(&[[10, 201, 0, 10].into()], &[net("10.201.0.0/24")]);
        }
        let mut alice = rig.owner();
        let state = alice.connect_ends(good());
        assert_eq!(mode_of(&state), TunnelMode::Split, "{case}: {state:?}");
        let (calls, applied) = (rig.fake.calls(), rig.fake.applied());
        let asked = alice.ask(set_tunnel(TunnelMode::Full));
        assert_eq!(asked, Err(ErrorCode::RouteRefused), "{case}");
        assert_eq!(rig.fake.calls(), calls, "{case}: something was done");
        assert_eq!(rig.fake.applied(), applied, "{case}: something changed");
        assert!(alice.is_quiet(), "{case}: a state was reported");
    }
}

// Security rule: fail closed. If any step or check of a switch fails, the
// connection is closed and everything removed, the halves and the
// catch-all included.
#[test]
fn a_switch_that_fails_part_way_tears_everything_down() {
    let unknown = Some(Error::Unsupported);
    let to_full = [
        (Op::AddFullTunnel, ErrorCode::Internal),
        (Op::SetCatchAllDns, ErrorCode::Internal),
        (Op::VerifyRoute, ErrorCode::VerificationFailed),
        (Op::VerifyRouteV6, ErrorCode::VerificationFailed),
        (Op::VerifyCatchAllDns, ErrorCode::VerificationFailed),
    ];
    for (op, code) in to_full {
        let (rig, mut alice, _) = split_connected();
        rig.fake.set_failure(op, unknown.clone());
        assert_eq!(alice.ask(set_tunnel(TunnelMode::Full)), ACCEPTED, "{op:?}");
        let state = alice.state();
        rig.fake.set_failure(op, None);
        assert!(failed_with(&state, code), "{op:?}: {state:?}");
        assert!(rig.is_clean(), "{op:?} left something behind");
    }
    let to_split = [
        (Op::ClearCatchAllDns, ErrorCode::Internal),
        (Op::RemoveFullTunnel, ErrorCode::Internal),
        (Op::VerifyRoute, ErrorCode::VerificationFailed),
        (Op::VerifyRouteV6, ErrorCode::VerificationFailed),
        (Op::VerifyCatchAllDns, ErrorCode::VerificationFailed),
    ];
    for (op, code) in to_split {
        let (rig, mut alice) = home_rig();
        assert_eq!(mode_of(&alice.connect_ends(good_full())), TunnelMode::Full);
        rig.fake.set_failure(op, unknown.clone());
        assert_eq!(alice.ask(set_tunnel(TunnelMode::Split)), ACCEPTED, "{op:?}");
        let state = alice.state();
        rig.fake.set_failure(op, None);
        assert!(failed_with(&state, code), "{op:?}: {state:?}");
        assert!(rig.is_clean(), "{op:?} left something behind");
    }
}

// Security rule: the halves and the catch-all are known to teardown before
// they are added, so what a failing add left is removed by name, even when
// the removals that need no memory fail too.
#[test]
fn what_a_failing_switch_added_is_removed_by_name() {
    for op in [Op::AddFullTunnel, Op::SetCatchAllDns] {
        let (rig, mut alice, _) = split_connected();
        let unknown = Some(Error::Unsupported);
        rig.fake.set_failure(op, unknown.clone());
        rig.fake.set_failure(Op::RemoveAllRoutes, unknown.clone());
        rig.fake.set_failure(Op::ClearSplitDns, unknown);
        assert_eq!(alice.ask(set_tunnel(TunnelMode::Full)), ACCEPTED);
        let state = alice.state();
        for healed in [op, Op::RemoveAllRoutes, Op::ClearSplitDns] {
            rig.fake.set_failure(healed, None);
        }
        assert!(
            matches!(state, ConnState::Failed { .. }),
            "{op:?}: {state:?}"
        );
        let applied = rig.fake.applied();
        assert_eq!(applied.full_tunnel, None, "{op:?}: halves left");
        assert_eq!(applied.catch_all_dns, None, "{op:?}: catch-all left");
    }
}

// Security rule: a check that full mode is gone after a switch to split.
// If an address outside the chosen subnets still uses the tunnel, the
// switch failed: it is undone, and full mode, put back, is checked again.
// The connection stays up in full mode, with every half and the catch-all
// in place, and the switch is said to be undone, with the reason.
#[test]
fn a_switch_to_split_that_leaves_traffic_in_the_tunnel_is_undone() {
    let (rig, mut alice) = home_rig();
    assert_eq!(mode_of(&alice.connect_ends(good_full())), TunnelMode::Full);
    // Somebody else's route keeps the upper half in the tunnel.
    rig.fake.add_foreign_route("fake0", net("128.0.0.0/2"));
    let before = rig.fake.calls().len();
    assert_eq!(alice.ask(set_tunnel(TunnelMode::Split)), ACCEPTED);
    let state = alice.state();
    assert_eq!(mode_of(&state), TunnelMode::Full, "{state:?}");
    let why = alice.undone().expect("the switch is said to be undone");
    assert_eq!(why.code, ErrorCode::VerificationFailed);
    assert!(why.message.contains("128.0.0.0/1"), "{why:?}");
    assert!(why.message.ends_with("in full tunnel."), "{why:?}");
    let calls = rig.fake.calls()[before..].to_vec();
    let removed = at(&calls, Op::RemoveFullTunnel);
    let put_back = at(&calls, Op::AddFullTunnel);
    assert!(removed < put_back, "{calls:?}");
    assert!(put_back < at(&calls, Op::SetCatchAllDns), "{calls:?}");
    let checked = calls[put_back..]
        .iter()
        .position(|op| *op == Op::VerifyCatchAllDns);
    assert!(
        checked.is_some(),
        "full mode was not checked again: {calls:?}"
    );
    let applied = rig.fake.applied();
    assert_eq!(applied.full_tunnel, halves(Ipv6Block::Blocked));
    assert_eq!(applied.catch_all_dns, Some(vec![DNS_SERVER]));
    assert_eq!(rig.spy.opens().len(), 1, "the tunnel was opened again");
    assert!(alice.is_quiet(), "a state was reported");
    rig.fake.remove_foreign_route("fake0", net("128.0.0.0/2"));
    assert_eq!(alice.ask(set_tunnel(TunnelMode::Split)), ACCEPTED);
    assert_eq!(mode_of(&alice.state()), TunnelMode::Split);
    assert_eq!(alice.undone(), None);
}

/// Split-connected on a home network, with a route somebody else added
/// that takes a host-only network into the tunnel: split mode does not
/// mind, but full mode's check that every network the machine is on stays
/// off the tunnel fails.
fn split_connected_with_a_stolen_network() -> (Rig, Peer) {
    let (rig, alice, _) = split_connected();
    rig.fake.add_foreign_route("fake0", net("172.31.130.0/25"));
    (rig, alice)
}

// Security rule: a switch to full that fails its checks is undone: the
// catch-all and the halves are removed, split mode is checked again, the
// IPv6 halves and the catch-all included, and the connection stays up in
// split mode. The switch is said to be undone, with the reason, before the
// state; the tunnel is never reopened.
#[test]
fn a_failed_switch_to_full_is_undone_and_stays_connected() {
    let (rig, mut alice) = split_connected_with_a_stolen_network();
    let split_dns = rig.fake.applied().split_dns;
    let before = rig.fake.calls().len();
    assert_eq!(alice.ask(set_tunnel(TunnelMode::Full)), ACCEPTED);
    let state = alice.state();
    assert_eq!(mode_of(&state), TunnelMode::Split, "{state:?}");
    let why = alice.undone().expect("the switch is said to be undone");
    assert_eq!(why.code, ErrorCode::VerificationFailed);
    let reason = "172.31.130.0/24, a network this computer is on, goes through the tunnel.";
    assert!(why.message.starts_with(reason), "{why:?}");
    assert!(why.message.ends_with("in split tunnel."), "{why:?}");
    let applied = rig.fake.applied();
    assert_eq!(applied.full_tunnel, None, "the halves were left");
    assert_eq!(applied.catch_all_dns, None, "the catch-all was left");
    assert_eq!(applied.split_dns, split_dns);
    let calls = rig.fake.calls()[before..].to_vec();
    let cleared = at(&calls, Op::ClearCatchAllDns);
    assert!(at(&calls, Op::SetCatchAllDns) < cleared, "{calls:?}");
    assert!(cleared < at(&calls, Op::RemoveFullTunnel), "{calls:?}");
    let checked = &calls[cleared..];
    for check in [Op::VerifyRoute, Op::VerifyRouteV6, Op::VerifyCatchAllDns] {
        assert!(
            checked.contains(&check),
            "{check:?} not asked again: {calls:?}"
        );
    }
    assert_eq!(
        alice.ask(RequestBody::Status),
        Ok(ResponseBody::Status(state))
    );
    assert_eq!(rig.spy.opens().len(), 1, "the tunnel was opened again");
    assert!(alice.is_quiet(), "a state was reported");
    let log: Vec<String> = alice
        .whole_log()
        .iter()
        .map(|l| l.text.as_str().to_string())
        .collect();
    assert!(log.iter().any(|l| l.contains("was undone")), "{log:?}");
    // The connection works on as before: another switch is admitted.
    rig.fake
        .remove_foreign_route("fake0", net("172.31.130.0/25"));
    assert_eq!(alice.ask(set_tunnel(TunnelMode::Full)), ACCEPTED);
    assert_eq!(mode_of(&alice.state()), TunnelMode::Full);
}

// Security rule: fail closed. A failed switch whose undoing fails at a
// step is not kept: the connection is closed and everything removed, and
// nothing is said to be undone.
#[test]
fn a_failed_switch_whose_undoing_fails_tears_everything_down() {
    let unknown = Some(Error::Unsupported);
    // The switch to full needs neither: only undoing it does.
    for op in [Op::ClearCatchAllDns, Op::RemoveFullTunnel] {
        let (rig, mut alice) = split_connected_with_a_stolen_network();
        rig.fake.set_failure(op, unknown.clone());
        assert_eq!(alice.ask(set_tunnel(TunnelMode::Full)), ACCEPTED);
        let state = alice.state();
        rig.fake.set_failure(op, None);
        assert!(
            failed_with(&state, ErrorCode::Internal),
            "{op:?}: {state:?}"
        );
        assert!(message_of(&state).contains("Undoing the switch failed too"));
        assert_eq!(alice.undone(), None, "{op:?}");
        rig.fake
            .remove_foreign_route("fake0", net("172.31.130.0/25"));
        assert!(rig.is_clean(), "{op:?} left something behind");
    }
    // The switch to split needs neither: only undoing it does.
    for op in [Op::AddFullTunnel, Op::SetCatchAllDns] {
        let (rig, mut alice) = home_rig();
        assert_eq!(mode_of(&alice.connect_ends(good_full())), TunnelMode::Full);
        rig.fake.add_foreign_route("fake0", net("128.0.0.0/2"));
        rig.fake.set_failure(op, unknown.clone());
        assert_eq!(alice.ask(set_tunnel(TunnelMode::Split)), ACCEPTED);
        let state = alice.state();
        rig.fake.set_failure(op, None);
        assert!(
            failed_with(&state, ErrorCode::Internal),
            "{op:?}: {state:?}"
        );
        assert_eq!(alice.undone(), None, "{op:?}");
        rig.fake.remove_foreign_route("fake0", net("128.0.0.0/2"));
        assert!(rig.is_clean(), "{op:?} left something behind");
    }
}

// Security rule: fail closed. A failed switch is kept undone only once the
// mode it had passes its checks again. One that does not, or whose checks
// cannot tell, closes the connection and removes everything.
#[test]
fn a_failed_switch_whose_undoing_fails_its_checks_tears_everything_down() {
    // The lower half cannot be told about: the switch to full is not
    // confirmed, and neither is split mode after it, which must see the
    // half no longer go through the tunnel.
    let (rig, mut alice, _) = split_connected();
    rig.fake.cannot_tell_route_to(Ipv4Addr::new(1, 0, 0, 0));
    assert_eq!(alice.ask(set_tunnel(TunnelMode::Full)), ACCEPTED);
    let state = alice.state();
    assert!(
        failed_with(&state, ErrorCode::VerificationFailed),
        "{state:?}"
    );
    let why = message_of(&state);
    assert!(why.starts_with("0.0.0.0/1 is not routed"), "{why}");
    assert!(
        why.contains("Undoing the switch failed too: 0.0.0.0/1 still"),
        "{why}"
    );
    assert_eq!(alice.undone(), None);
    assert!(rig.is_clean());

    // The switch to split leaves the upper half in the tunnel; full mode,
    // put back, cannot tell about the router.
    let (rig, mut alice) = home_rig();
    assert_eq!(mode_of(&alice.connect_ends(good_full())), TunnelMode::Full);
    rig.fake.add_foreign_route("fake0", net("128.0.0.0/2"));
    rig.fake.cannot_tell_route_to(HOME_ROUTER);
    assert_eq!(alice.ask(set_tunnel(TunnelMode::Split)), ACCEPTED);
    let state = alice.state();
    assert!(
        failed_with(&state, ErrorCode::VerificationFailed),
        "{state:?}"
    );
    let why = message_of(&state);
    assert!(
        why.contains("Undoing the switch failed too: The router"),
        "{why}"
    );
    assert_eq!(alice.undone(), None);
    rig.fake.remove_foreign_route("fake0", net("128.0.0.0/2"));
    assert!(rig.is_clean());
}

// Security rule (a home network): the networks the machine is on must
// not go through the tunnel, whichever adapter they are on. One that does
// fails full mode, and so does the router.
#[test]
fn a_local_network_or_router_in_the_tunnel_fails_full_mode() {
    let cases = [
        ("host-only", net("172.31.130.0/25")),
        ("router", net("10.200.0.1/32")),
    ];
    for (case, stolen) in cases {
        let (rig, mut alice) = home_rig();
        rig.fake.add_foreign_route("fake0", stolen);
        let state = alice.connect_ends(good_full());
        assert!(
            failed_with(&state, ErrorCode::VerificationFailed),
            "{case}: {state:?}"
        );
        rig.fake.remove_foreign_route("fake0", stolen);
        assert!(rig.is_clean(), "{case}");
    }
}

// Security rule: with nothing to block, an IPv6 change is checked again at
// once, and a leak path that has appeared closes the connection. While it
// is still so, nothing happens.
#[test]
fn an_ipv6_leak_path_that_appears_in_full_mode_fails_closed() {
    let (rig, mut alice) = home_rig();
    rig.fake.set_ipv6(false, false);
    let state = alice.connect_ends(good_full());
    assert_eq!(mode_of(&state), TunnelMode::Full, "{state:?}");
    let asked = || {
        let calls = rig.fake.calls();
        calls
            .iter()
            .filter(|call| **call == Op::FullTunnelIpv6)
            .count()
    };
    let before = asked();
    assert!(rig.os.send_to(0, NetworkEvent::Ipv6Changed));
    // An answered request shows the event was handled first.
    let mut checked = false;
    for _ in 0..500 {
        if asked() > before {
            checked = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    assert!(checked, "the change was not checked");
    assert!(alice.is_quiet(), "a state was reported");

    rig.fake.set_ipv6(false, true);
    assert!(rig.os.send_to(0, NetworkEvent::Ipv6Changed));
    let state = alice.state();
    assert!(
        failed_with(&state, ErrorCode::VerificationFailed),
        "{state:?}"
    );
    assert!(message_of(&state).contains("IPv6"), "{state:?}");
    assert!(rig.is_clean());
}

// Security rule: an IPv6 change whose check fails with a read error closes
// the connection too. "Could not tell" is not "nothing to block".
#[test]
fn an_ipv6_change_that_cannot_be_checked_fails_closed() {
    let (rig, mut alice) = home_rig();
    rig.fake.set_ipv6(false, false);
    let state = alice.connect_ends(good_full());
    assert_eq!(mode_of(&state), TunnelMode::Full, "{state:?}");
    unreadable_op(&rig, Op::FullTunnelIpv6);
    assert!(rig.os.send_to(0, NetworkEvent::Ipv6Changed));
    let state = alice.state();
    assert!(
        failed_with(&state, ErrorCode::VerificationFailed),
        "{state:?}"
    );
    assert!(rig.is_clean());
}

// An IPv6 change matters only in full mode with nothing to block: with the
// halves in place, or in split mode, it is not even looked at.
#[test]
fn an_ipv6_change_is_ignored_where_it_cannot_leak() {
    for request in [good_full(), good()] {
        let (rig, mut alice) = home_rig();
        assert!(matches!(
            alice.connect_ends(request),
            ConnState::Connected { .. }
        ));
        let calls = rig.fake.calls().len();
        assert!(rig.os.send_to(0, NetworkEvent::Ipv6Changed));
        assert!(alice.is_quiet(), "a state was reported");
        assert_eq!(rig.fake.calls().len(), calls, "something was asked");
    }
}

// Security rule: a change of routes in full mode keeps full mode: the
// halves and the catch-all stay, a dropped subnet still goes through the
// tunnel (by the halves) without failing the change, and the result is
// checked as full mode. Dropping every domain keeps every name going to
// the gateway's DNS server: split DNS is not cleared, since that would
// take the catch-all with it.
#[test]
fn a_change_of_routes_in_full_mode_keeps_full_mode() {
    let (rig, mut alice) = home_rig();
    assert_eq!(mode_of(&alice.connect_ends(good_full())), TunnelMode::Full);
    let before = rig.fake.calls().len();
    let change = RequestBody::UpdateRoutes(ubc_vpn_core::routes::RouteSet {
        subnets: vec![net("10.255.0.0/24")],
        dns_domains: Vec::new(),
    });
    assert_eq!(alice.ask(change), ACCEPTED);
    let state = alice.state();
    assert_eq!(mode_of(&state), TunnelMode::Full, "{state:?}");
    let calls = rig.fake.calls()[before..].to_vec();
    assert!(!calls.contains(&Op::ClearSplitDns), "{calls:?}");
    assert!(calls.contains(&Op::VerifyCatchAllDns), "{calls:?}");
    let applied = rig.fake.applied();
    assert_eq!(applied.full_tunnel, halves(Ipv6Block::Blocked));
    assert_eq!(applied.catch_all_dns, Some(vec![DNS_SERVER]));
    for name in [chosen_domain(), "www.example.com".to_string()] {
        assert_eq!(rig.fake.resolvers_for(&name), [DNS_SERVER], "{name}");
    }

    // Back in split mode, the domain dropped meanwhile is gone too.
    assert_eq!(alice.ask(set_tunnel(TunnelMode::Split)), ACCEPTED);
    let state = alice.state();
    assert_eq!(mode_of(&state), TunnelMode::Split, "{state:?}");
    let applied = rig.fake.applied();
    assert_eq!(applied.split_dns, None);
    assert_eq!(applied.catch_all_dns, None);
    assert_eq!(applied.full_tunnel, None);
}

// Issue #221: the DNS servers reach the checks. A DNS server's host route
// goes through the tunnel whatever its subnet's route does, so a subnet
// whose own route went missing must not be confirmed by it, at connect and
// after a change of routes.
#[test]
fn a_missing_subnet_route_is_not_confirmed_by_a_dns_servers_route() {
    let assigned = |script: &mut Script| script.assigned.dns = vec![[10, 255, 0, 1].into()];
    let mut rig = Rig::scripted(policy('A', ""), assigned);
    rig.start().unwrap();
    let mut alice = rig.owner();
    let small = net("10.255.0.0/24");
    rig.fake.lose_tunnel_route(small, true);
    let request = connect(COOKIE, GATEWAY, &["10.255.0.0/24"], &["dept.example.test"]);
    let state = alice.connect_ends(request);
    assert!(
        failed_with(&state, ErrorCode::VerificationFailed),
        "{state:?}"
    );
    assert!(rig.is_clean());

    rig.fake.lose_tunnel_route(small, false);
    let first = connect(COOKIE, GATEWAY, &["192.0.2.0/24"], &["dept.example.test"]);
    let mut rig = Rig::scripted(policy('A', ""), assigned);
    rig.start().unwrap();
    let mut alice = rig.owner();
    assert!(matches!(
        alice.connect_ends(first),
        ConnState::Connected { .. }
    ));
    rig.fake.lose_tunnel_route(small, true);
    let change = RequestBody::UpdateRoutes(ubc_vpn_core::routes::RouteSet {
        subnets: vec![net("192.0.2.0/24"), small],
        dns_domains: vec![chosen_domain()],
    });
    assert_eq!(alice.ask(change), ACCEPTED);
    let state = alice.state();
    assert!(
        failed_with(&state, ErrorCode::VerificationFailed),
        "{state:?}"
    );
}

// Security rule: full mode must see every IPv6 change. Where the network
// cannot be watched, a full connect is refused before the gateway is
// contacted, and a split connection cannot be switched to full.
#[test]
fn full_mode_needs_the_network_watched() {
    let (rig, mut alice) = home_rig();
    rig.fake
        .set_failure(Op::Subscribe, Some(Error::Unsupported));
    let state = alice.connect_ends(good_full());
    assert!(failed_with(&state, ErrorCode::RouteRefused), "{state:?}");
    assert!(rig.spy.opens().is_empty(), "the gateway was contacted");
    assert!(rig.is_clean());

    let state = alice.connect_ends(good());
    assert_eq!(mode_of(&state), TunnelMode::Split, "{state:?}");
    let applied = rig.fake.applied();
    let asked = alice.ask(set_tunnel(TunnelMode::Full));
    assert_eq!(asked, Err(ErrorCode::RouteRefused));
    assert_eq!(rig.fake.applied(), applied, "something changed");
    assert!(alice.is_quiet(), "a state was reported");
}
