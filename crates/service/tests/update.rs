//! Changing the routes of a live tunnel, driven over the channel. Tests
//! marked "Security rule" must fail if the rule they name is removed. The
//! ranges are made up: 10.255.0.0/16, 192.0.2.0/24 and 198.51.100.0/24.

mod harness;

use harness::*;
use ubc_vpn_core::routes::{Ipv4Net, RouteSet};
use ubc_vpn_platform::SplitDns;

const ACCEPTED: Result<ResponseBody, ErrorCode> = Ok(ResponseBody::Accepted);

fn update(subnets: &[&str], domains: &[&str]) -> RequestBody {
    RequestBody::UpdateRoutes(RouteSet {
        subnets: subnets.iter().map(|s| s.parse().unwrap()).collect(),
        dns_domains: domains.iter().map(|d| d.to_string()).collect(),
    })
}

fn net(text: &str) -> Ipv4Net {
    text.parse().unwrap()
}

fn routed(nets: &[&str]) -> Vec<(String, Ipv4Net)> {
    nets.iter().map(|n| ("fake0".to_string(), net(n))).collect()
}

fn subnets_of(state: &ConnState) -> Vec<Ipv4Net> {
    match state {
        ConnState::Connected { tunnel } => tunnel.subnets.clone(),
        other => panic!("not connected: {other:?}"),
    }
}

fn failed_with(state: &ConnState, expected: ErrorCode) -> bool {
    matches!(state, ConnState::Failed { code, .. } if *code == expected)
}

/// Connects with `good()`: 10.255.0.0/24 and 192.0.2.0/24, the domain
/// ece.example.test, and the gateway's DNS server 10.255.0.53.
fn connected(rig: &Rig) -> Peer {
    let mut alice = rig.owner();
    let state = alice.connect_ends(good());
    assert!(matches!(state, ConnState::Connected { .. }), "{state:?}");
    alice
}

// The issue's case: routes changed while connected are applied to the live
// tunnel, in order: the new added, then DNS, then the dropped removed, then
// all of it checked. The tunnel is not reopened.
#[test]
fn a_change_while_connected_is_applied_and_checked() {
    let rig = rig();
    let mut alice = connected(&rig);
    let before = rig.fake.calls().len();

    let change = update(
        &["10.255.0.0/24", "198.51.100.0/24"],
        &["ece.example.test", "cs.example.test"],
    );
    assert_eq!(alice.ask(change), ACCEPTED);
    let state = alice.state();
    assert_eq!(
        subnets_of(&state),
        [net("10.255.0.0/24"), net("198.51.100.0/24")]
    );

    let applied = rig.fake.applied();
    assert_eq!(
        applied.tunnel_routes,
        routed(&["10.255.0.0/24", "10.255.0.53/32", "198.51.100.0/24"])
    );
    let dns = SplitDns {
        resolvers: vec![[10, 255, 0, 53].into()],
        domains: vec![
            "ece.example.test".to_string(),
            "cs.example.test".to_string(),
        ],
    };
    assert_eq!(applied.split_dns, Some(("fake0".to_string(), dns)));
    // Add, DNS, remove; then each subnet, the gateway, the DNS server and
    // DNS; then the dropped subnet.
    let order = [
        Op::AddTunnelRoutes,
        Op::SetSplitDns,
        Op::RemoveTunnelRoutes,
        Op::VerifyRoute,
        Op::VerifyRoute,
        Op::VerifyRoute,
        Op::VerifyRoute,
        Op::VerifyDns,
        Op::VerifyRoute,
    ];
    assert_eq!(rig.fake.calls()[before..], order);
    assert_eq!(rig.spy.opens().len(), 1, "the tunnel was opened again");
    assert_eq!(
        alice.ask(RequestBody::Status),
        Ok(ResponseBody::Status(state))
    );
    let said = alice
        .whole_log()
        .into_iter()
        .map(|line| line.text.as_str().to_string());
    let line = ubc_vpn_service::ROUTES_CHANGED;
    assert!(said.into_iter().any(|text| text == line));

    // And a disconnect afterwards removes all of it.
    assert_eq!(alice.ask(RequestBody::Disconnect), ACCEPTED);
    assert_eq!(
        [alice.state(), alice.state()],
        [ConnState::Disconnecting, ConnState::Disconnected]
    );
    assert!(rig.is_clean());
}

// Dropping every domain clears split DNS. The route to the gateway's DNS
// server stays until the connection ends.
#[test]
fn dropping_the_domains_clears_split_dns() {
    let rig = rig();
    let mut alice = connected(&rig);
    assert_eq!(alice.ask(update(&["10.255.0.0/24"], &[])), ACCEPTED);
    assert!(matches!(alice.state(), ConnState::Connected { .. }));
    let applied = rig.fake.applied();
    assert_eq!(applied.split_dns, None);
    assert_eq!(
        applied.tunnel_routes,
        routed(&["10.255.0.0/24", "10.255.0.53/32"])
    );
}

// A connection made without domains has no route to a DNS server. Adding a
// domain adds that route first, then split DNS through it.
#[test]
fn adding_domains_routes_the_dns_server_first() {
    let rig = rig();
    let mut alice = rig.owner();
    let state = alice.connect_ends(connect(COOKIE, GATEWAY, &["192.0.2.0/24"], &[]));
    assert!(matches!(state, ConnState::Connected { .. }), "{state:?}");
    let change = update(&["192.0.2.0/24"], &["ece.example.test"]);
    assert_eq!(alice.ask(change), ACCEPTED);
    assert!(matches!(alice.state(), ConnState::Connected { .. }));
    let applied = rig.fake.applied();
    assert_eq!(
        applied.tunnel_routes,
        routed(&["192.0.2.0/24", "10.255.0.53/32"])
    );
    let resolvers = applied.split_dns.map(|(_, dns)| dns.resolvers);
    assert_eq!(resolvers, Some(vec![[10, 255, 0, 53].into()]));
}

// A dropped subnet that a broader one still holds goes on through the
// tunnel, as it should: that is not a failure.
#[test]
fn a_dropped_subnet_a_broader_one_still_holds_is_fine() {
    let rig = rig();
    let mut alice = rig.owner();
    let both = connect(COOKIE, GATEWAY, &["10.255.0.0/16", "10.255.7.0/24"], &[]);
    assert!(matches!(
        alice.connect_ends(both),
        ConnState::Connected { .. }
    ));
    assert_eq!(alice.ask(update(&["10.255.0.0/16"], &[])), ACCEPTED);
    let state = alice.state();
    assert_eq!(subnets_of(&state), [net("10.255.0.0/16")]);
    assert_eq!(rig.fake.applied().tunnel_routes, routed(&["10.255.0.0/16"]));
}

// Security rule: a change is held to the same rules as a connect: the
// policy's, and none into a network the machine is on, its router or the
// gateway itself. One refused is refused before anything is touched: the
// tunnel keeps the routes it had and stays connected.
#[test]
fn a_refused_change_leaves_the_tunnel_as_it_was() {
    let mut rig = Rig::stopped(policy(
        'A',
        r#","allowed_routes":["10.0.0.0/8","192.0.2.0/24"]"#,
    ));
    rig.start().unwrap();
    let own = [[192, 168, 0, 10].into()];
    rig.fake.set_local(&own, &[net("192.168.0.0/24")]);
    let mut alice = connected(&rig);
    let (calls, applied) = (rig.fake.calls(), rig.fake.applied());
    let refused = [
        // Too wide, and reserved.
        update(&["10.0.0.0/7"], &[]),
        update(&["127.0.0.0/8"], &[]),
        // Outside the policy's allow-list.
        update(&["198.51.100.0/24"], &[]),
        // The network the machine is on, and the gateway itself.
        update(&["192.168.0.0/24"], &[]),
        update(&["192.0.2.1/32"], &[]),
        // A domain that is not one.
        update(&["10.255.0.0/24"], &["not a domain"]),
    ];
    for change in refused {
        let what = format!("{change:?}");
        assert_eq!(alice.ask(change), Err(ErrorCode::RouteRefused), "{what}");
        assert_eq!(rig.fake.calls(), calls, "something was done: {what}");
        assert_eq!(rig.fake.applied(), applied, "something changed: {what}");
    }
    assert!(alice.is_quiet(), "a state was reported");
    let status = alice.ask(RequestBody::Status).unwrap();
    assert!(matches!(
        status,
        ResponseBody::Status(ConnState::Connected { .. })
    ));
    let said: Vec<String> = alice
        .whole_log()
        .into_iter()
        .map(|line| line.text.as_str().to_string())
        .collect();
    let line = "route change refused: route_refused; the connection is as it was";
    assert!(said.iter().any(|text| text == line), "{said:?}");
}

// Without a tunnel there is nothing to change, and that is said with its
// own code. (Only the owner may ask: see `channel.rs`.)
#[test]
fn a_change_needs_a_connection() {
    let rig = rig();
    let mut alice = rig.owner();
    let change = || update(&["10.255.0.0/24"], &[]);
    assert_eq!(alice.ask(change()), Err(ErrorCode::NotConnected));
    assert!(rig.fake.applied() == Default::default());
    // During a disconnect it is busy.
    let mut alice = connected(&rig);
    assert_eq!(alice.ask(RequestBody::Disconnect), ACCEPTED);
    let asked = alice.ask(change());
    assert!(
        matches!(asked, Err(ErrorCode::Busy | ErrorCode::NotConnected)),
        "{asked:?}"
    );
}

// Security rule: fail closed. If adding, setting DNS, removing or any check
// fails, the connection is closed and everything removed.
#[test]
fn a_change_that_fails_part_way_tears_everything_down() {
    let unknown = Some(Error::Unsupported);
    let cases = [
        ("adding", Op::AddTunnelRoutes, ErrorCode::Internal),
        ("DNS", Op::SetSplitDns, ErrorCode::Internal),
        ("removing", Op::RemoveTunnelRoutes, ErrorCode::Internal),
        ("checking", Op::VerifyRoute, ErrorCode::VerificationFailed),
        ("checking DNS", Op::VerifyDns, ErrorCode::VerificationFailed),
    ];
    for (case, op, code) in cases {
        let rig = rig();
        let mut alice = connected(&rig);
        rig.fake.set_failure(op, unknown.clone());
        let change = update(&["10.255.0.0/24", "198.51.100.0/24"], &["cs.example.test"]);
        assert_eq!(alice.ask(change), ACCEPTED, "{case}");
        // Failing until the outcome is known: the worker takes the change
        // after the answer, at a moment of its own.
        let state = alice.state();
        rig.fake.set_failure(op, None);
        assert!(failed_with(&state, code), "{case}: {state:?}");
        assert!(rig.is_clean(), "{case} left something behind");
    }
}

// Security rule: a route is known to teardown before it is added, so one
// added just before a failure is removed by name, even when the catch-all
// removal that needs no memory fails too.
#[test]
fn a_route_being_added_is_removed_by_name_if_the_change_fails() {
    let rig = rig();
    let mut alice = connected(&rig);
    let unknown = Some(Error::Unsupported);
    // The fake adds all but the last of a failing call's routes.
    rig.fake.set_failure(Op::AddTunnelRoutes, unknown.clone());
    rig.fake.set_failure(Op::RemoveAllRoutes, unknown);
    let change = update(
        &["10.255.0.0/24", "198.51.100.0/24", "198.51.100.128/25"],
        &["ece.example.test"],
    );
    assert_eq!(alice.ask(change), ACCEPTED);
    let state = alice.state();
    rig.fake.set_failure(Op::AddTunnelRoutes, None);
    rig.fake.set_failure(Op::RemoveAllRoutes, None);
    assert!(matches!(state, ConnState::Failed { .. }), "{state:?}");
    assert_eq!(rig.fake.applied().tunnel_routes, [], "left in the tunnel");
}

// Security rule: a dropped subnet must stop going through the tunnel. If
// it still does, the change failed, and nothing is left.
#[test]
fn a_dropped_subnet_still_in_the_tunnel_fails_the_change() {
    let rig = rig();
    let mut alice = connected(&rig);
    // Someone else's route keeps it there.
    rig.fake.add_foreign_route("fake0", net("192.0.2.0/25"));
    assert_eq!(alice.ask(update(&["10.255.0.0/24"], &[])), ACCEPTED);
    let state = alice.state();
    assert!(
        failed_with(&state, ErrorCode::VerificationFailed),
        "{state:?}"
    );
    if let ConnState::Failed { message, .. } = &state {
        assert!(
            message.contains("192.0.2.0/24 still goes through the tunnel"),
            "{message}"
        );
    }
    assert!(rig.is_clean());
}

// Security rule: only routes this service added are removed. Another
// program's route stays, even one for a subnet the user dropped, and so
// does the route to the gateway's DNS server, even when the user had chosen
// it as a subnet too.
#[test]
fn only_routes_the_service_added_are_removed() {
    let rig = rig();
    let mut alice = rig.owner();
    let subnets = ["192.0.2.0/24", "10.255.0.53/32", "10.255.9.0/24"];
    let first = connect(COOKIE, GATEWAY, &subnets, &["ece.example.test"]);
    assert!(matches!(
        alice.connect_ends(first),
        ConnState::Connected { .. }
    ));
    rig.fake.add_foreign_route("other0", net("10.255.9.0/24"));
    let change = update(&["192.0.2.0/24"], &["ece.example.test"]);
    assert_eq!(alice.ask(change), ACCEPTED);
    let state = alice.state();
    assert_eq!(subnets_of(&state), [net("192.0.2.0/24")]);
    assert_eq!(
        rig.fake.applied().tunnel_routes,
        routed(&["192.0.2.0/24", "10.255.0.53/32"])
    );
    assert_eq!(
        rig.fake.foreign_routes(),
        [("other0".to_string(), net("10.255.9.0/24"))]
    );
}

/// The service's own lines, as text.
fn own_lines(peer: &mut Peer) -> Vec<String> {
    let own = |line: &LogLine| line.source == ubc_vpn_core::protocol::LogSource::Service;
    let lines = peer.whole_log().into_iter().filter(own);
    lines.map(|line| line.text.as_str().to_string()).collect()
}

// A change to the routes the tunnel carries already is no change: it is
// answered at once with the connection as it is, and nothing is done,
// logged or reported.
#[test]
fn the_same_routes_again_change_nothing() {
    let rig = rig();
    let mut alice = connected(&rig);
    let ResponseBody::Status(state) = alice.ask(RequestBody::Status).unwrap() else {
        panic!("no status");
    };
    let (calls, before) = (rig.fake.calls(), own_lines(&mut alice).len());
    // Compared as sets: in another order, or with an entry twice, they are
    // still the same routes.
    let same = [
        update(&["10.255.0.0/24", "192.0.2.0/24"], &["ece.example.test"]),
        update(&["192.0.2.0/24", "10.255.0.0/24"], &["ece.example.test"]),
        update(
            &["10.255.0.0/24", "192.0.2.0/24", "10.255.0.0/24"],
            &["ece.example.test", "ece.example.test"],
        ),
    ];
    for request in same {
        let what = format!("{request:?}");
        assert_eq!(
            alice.ask(request),
            Ok(ResponseBody::Status(state.clone())),
            "{what}"
        );
    }
    assert!(alice.is_quiet(), "a state was reported");
    assert_eq!(rig.fake.calls(), calls, "something was done");
    assert_eq!(own_lines(&mut alice).len(), before, "something was logged");

    // While something else is in progress, even no change is busy. The
    // disconnect is held in its teardown so that it is still going on.
    rig.os.hold_at(Op::RemoveTunnelRoutes);
    assert_eq!(alice.ask(RequestBody::Disconnect), ACCEPTED);
    rig.os.wait_until_held();
    let same = update(&["10.255.0.0/24", "192.0.2.0/24"], &["ece.example.test"]);
    let asked = alice.ask(same);
    rig.os.release();
    assert_eq!(asked, Err(ErrorCode::Busy));
}

// Security rule: after a change, what the tunnel carries is what a later
// change is compared with. Changed to other routes and back, the second
// change is really applied: the tunnel carries the first routes again and
// the other one's extra is gone, and nothing is left outside the tunnel
// while the reply says applied.
#[test]
fn a_change_then_back_is_applied_both_times() {
    let rig = rig();
    let mut alice = connected(&rig);
    let first = || update(&["10.255.0.0/24", "192.0.2.0/24"], &["ece.example.test"]);
    let other = update(&["10.255.0.0/24", "198.51.100.0/24"], &["ece.example.test"]);
    assert_eq!(alice.ask(other), ACCEPTED);
    let state = alice.state();
    assert_eq!(
        subnets_of(&state),
        [net("10.255.0.0/24"), net("198.51.100.0/24")]
    );
    assert_eq!(alice.ask(first()), ACCEPTED, "taken for no change");
    let state = alice.state();
    assert_eq!(
        subnets_of(&state),
        [net("10.255.0.0/24"), net("192.0.2.0/24")]
    );
    assert_eq!(
        rig.fake.applied().tunnel_routes,
        routed(&["10.255.0.0/24", "10.255.0.53/32", "192.0.2.0/24"])
    );
    // And now the same again is no change.
    assert!(matches!(alice.ask(first()), Ok(ResponseBody::Status(_))));
}

// Security rule: a change costs the client nothing, so changes asked for
// again and again, more than the log holds, must not fill it. The
// service's first lines are still there, and the change is said once.
#[test]
fn changes_again_and_again_do_not_fill_the_log() {
    let rig = rig();
    let mut alice = connected(&rig);
    let one = || update(&["10.255.0.0/24", "198.51.100.0/24"], &["ece.example.test"]);
    let other = || update(&["10.255.0.0/24", "192.0.2.0/24"], &["cs.example.test"]);
    for round in 0..ubc_vpn_service::LOG_CAPACITY + 20 {
        let change = if round % 2 == 0 { one() } else { other() };
        assert_eq!(alice.ask(change), ACCEPTED, "{round}");
        let state = alice.state();
        assert!(
            matches!(state, ConnState::Connected { .. }),
            "{round}: {state:?}"
        );
    }
    let lines = own_lines(&mut alice);
    assert!(lines[0].starts_with("service started"), "{lines:?}");
    assert!(lines[1].starts_with("policy read"), "{lines:?}");
    let said = lines
        .iter()
        .filter(|line| *line == ubc_vpn_service::ROUTES_CHANGED);
    assert_eq!(said.count(), 1, "{lines:?}");

    // A new connection's first change is news again. (A lost connection
    // keeps the session, so the same one connects again.)
    rig.engine.drop_connection();
    assert!(matches!(alice.state(), ConnState::Failed { .. }));
    let again = alice.connect_ends(good());
    assert!(matches!(again, ConnState::Connected { .. }), "{again:?}");
    assert_eq!(alice.ask(one()), ACCEPTED);
    assert!(matches!(alice.state(), ConnState::Connected { .. }));
    let lines = own_lines(&mut alice);
    let said = lines
        .iter()
        .filter(|line| *line == ubc_vpn_service::ROUTES_CHANGED);
    assert_eq!(said.count(), 2, "{lines:?}");
}

// When a change adds DNS domains to a connection that has none, the DNS
// servers the gateway assigned are judged as at connect. Nothing has been
// changed yet, so servers that cannot be used refuse the change and the
// connection is kept.
#[test]
fn unusable_dns_servers_refuse_the_change_and_keep_the_connection() {
    let cases: [(&str, Vec<[u8; 4]>); 3] = [
        ("none", vec![]),
        ("the gateway", vec![[192, 0, 2, 1]]),
        ("loopback", vec![[127, 0, 0, 1]]),
    ];
    for (case, servers) in cases {
        let mut rig = Rig::scripted(policy('A', ""), |script| {
            script.assigned.dns = servers.iter().map(|addr| (*addr).into()).collect();
        });
        rig.start().unwrap();
        let mut alice = rig.owner();
        let first = connect(COOKIE, GATEWAY, &["10.255.0.0/24"], &[]);
        let state = alice.connect_ends(first);
        assert!(
            matches!(state, ConnState::Connected { .. }),
            "{case}: {state:?}"
        );
        let (calls, applied) = (rig.fake.calls(), rig.fake.applied());
        let change = update(&["10.255.0.0/24"], &["ece.example.test"]);
        assert_eq!(alice.ask(change), Err(ErrorCode::RouteRefused), "{case}");
        assert_eq!(rig.fake.calls(), calls, "{case}: something was done");
        assert_eq!(rig.fake.applied(), applied, "{case}: something changed");
        assert!(alice.is_quiet(), "{case}: a state was reported");
        assert_eq!(
            alice.ask(RequestBody::Status),
            Ok(ResponseBody::Status(state)),
            "{case}"
        );
    }
}
