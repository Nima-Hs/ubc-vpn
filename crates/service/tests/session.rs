//! Connecting, verifying and tearing down, driven over the channel. Tests
//! marked "Security rule" must fail if the rule they name is removed.

mod harness;

use harness::*;
use ubc_vpn_core::policy::Policy;
use ubc_vpn_core::protocol::LogLevel;
use ubc_vpn_engine::{CloseMode, Gateway};
use ubc_vpn_platform::SplitDns;
use ubc_vpn_platform::fake::PHYSICAL_INTERFACE;
use ubc_vpn_service::DNS_UNCONFIRMED;

const ACCEPTED: Result<ResponseBody, ErrorCode> = Ok(ResponseBody::Accepted);
/// What start-up does, and what each connect does before the tunnel exists.
const BEFORE_OPEN: [Op; 5] = [
    Op::RemoveAllRoutes,
    Op::ClearSplitDns,
    Op::ClearSplitDns,
    Op::RemoveAllRoutes,
    Op::CapturePhysical,
];
/// Configuring the device, applying, then one check per subnet, the gateway,
/// the DNS server and DNS.
const AFTER_OPEN: [Op; 9] = [
    Op::ConfigureTunnel,
    Op::AddGatewayRoute,
    Op::AddTunnelRoutes,
    Op::SetSplitDns,
    Op::VerifyRoute,
    Op::VerifyRoute,
    Op::VerifyRoute,
    Op::VerifyRoute,
    Op::VerifyDns,
];
const TEARDOWN: [Op; 4] = [
    Op::RemoveTunnelRoutes,
    Op::ClearSplitDns,
    Op::RemoveGatewayRoute,
    Op::RemoveAllRoutes,
];

fn failed_with(state: &ConnState, expected: ErrorCode) -> bool {
    matches!(state, ConnState::Failed { code, .. } if *code == expected)
}

fn connected(alice: &mut Peer) -> ConnState {
    let state = alice.connect_ends(good());
    assert!(matches!(state, ConnState::Connected { .. }), "{state:?}");
    state
}

// Security rule: the physical network is captured before the tunnel exists,
// the device is configured before any route goes in, the gateway's own
// route goes in before the tunnel's, and "connected" is reported only after
// every check has been made.
#[test]
fn connect_applies_in_order_and_verifies_before_connected() {
    let rig = rig();
    let (mut alice, mut second) = (rig.owner(), rig.peer("alice"));
    // An answered request shows the service has taken the second connection
    // in. Without it, on a busy machine, the connect below could begin
    // before that, and the second would hear one state fewer.
    let idle = Ok(ResponseBody::Status(ConnState::Disconnected));
    assert_eq!(second.ask(RequestBody::Status), idle);
    let state = connected(&mut alice);
    assert_eq!(rig.spy.opens()[0].1, BEFORE_OPEN, "before the tunnel");
    assert_eq!(
        rig.fake.calls()[5..],
        AFTER_OPEN,
        "by the time of the event"
    );

    let ConnState::Connected { tunnel } = &state else {
        unreachable!()
    };
    assert_eq!(tunnel.interface, "fake0");
    assert_eq!(tunnel.address, "10.255.0.2");
    // The device got the assigned address, as a host, and packet size,
    // before any route was added.
    let address = std::net::Ipv4Addr::new(10, 255, 0, 2);
    let configured = ("fake0".to_string(), address, 1300);
    assert_eq!(rig.fake.configured(), [configured]);
    assert_eq!(rig.fake.device_addresses("fake0"), [address]);
    let applied = rig.fake.applied();
    let (routed, via) = &applied.gateway_routes[0];
    assert_eq!(
        (*routed, via.interface()),
        (GATEWAY.into(), PHYSICAL_INTERFACE)
    );
    // The user's subnets, the gateway's DNS server, and nothing else.
    let routed = ["10.255.0.0/24", "192.0.2.0/24", "10.255.0.53/32"];
    let routed = routed.map(|net| ("fake0".to_string(), net.parse().unwrap()));
    assert_eq!(applied.tunnel_routes, routed);
    assert_eq!(
        tunnel.subnets.len(),
        2,
        "the state lists what the user chose"
    );
    let dns = SplitDns {
        resolvers: vec![[10, 255, 0, 53].into()],
        domains: vec!["ece.example.test".to_string()],
    };
    assert_eq!(applied.split_dns, Some(("fake0".to_string(), dns)));

    // Every connection of the owner hears every change, with no polling.
    let heard = [second.state(), second.state(), second.state()];
    assert_eq!(
        heard,
        [
            ConnState::Disconnected,
            ConnState::Connecting,
            state.clone()
        ]
    );
    assert_eq!(
        alice.ask(RequestBody::Status),
        Ok(ResponseBody::Status(state))
    );
}

// Security rule: the engine is handed the gateway from the service's own
// policy. A request can name an address and nothing more.
#[test]
fn the_gateway_comes_only_from_the_policy() {
    let rig = rig();
    let mut alice = rig.owner();
    connected(&mut alice);
    let policy = Policy {
        gateway: "vpn.example.test".to_string(),
        pins: vec![pin('A').try_into().unwrap()],
        allowed_routes: None,
    };
    assert_eq!(rig.spy.opens()[0].0, Gateway::from_policy(&policy).unwrap());

    // A request that tries to name a host or a pin is not a request at all.
    let smuggled = r#"{"cookie":"c","gateway_addr":"192.0.2.1","routes":{"subnets":["10.255.0.0/24"]},"gateway":"evil.example.test","pins":[]}"#;
    let line = format!(r#"{{"id":9,"body":{{"method":"connect","params":{smuggled}}}}}"#);
    alice.conn.write_line(&line).unwrap();
    assert!(alice.is_closed());
    assert_eq!(rig.spy.opens().len(), 1);

    // The pins are the policy's too: a key it does not list is refused.
    let mut other = Rig::stopped(harness::policy('B', ""));
    other.start().unwrap();
    let state = other.owner().connect_ends(good());
    assert!(failed_with(&state, ErrorCode::PinMismatch), "{state:?}");
    assert!(other.is_clean());
}

// Each way a connect can be refused has its own code, and none of them
// leaves anything applied.
#[test]
fn each_refusal_has_its_code_and_leaves_nothing_behind() {
    let allowed = r#","allowed_routes":["10.0.0.0/8"]"#;
    let mut rig = Rig::stopped(policy('A', allowed));
    rig.start().unwrap();
    let mut alice = rig.owner();
    let subnets = ["10.255.0.0/24", "10.1.0.0/16"];

    // Refused before anything is touched.
    let refused = [
        (
            connect(COOKIE, GATEWAY, &["0.0.0.0/1"], &[]),
            ErrorCode::RouteRefused,
        ),
        (
            connect(COOKIE, GATEWAY, &["172.16.0.0/12"], &[]),
            ErrorCode::RouteRefused,
        ),
        (
            connect(COOKIE, GATEWAY, &subnets, &["no domain"]),
            ErrorCode::RouteRefused,
        ),
        (
            connect(COOKIE, [127, 0, 0, 1], &subnets, &[]),
            ErrorCode::BadRequest,
        ),
    ];
    for (body, code) in refused {
        assert_eq!(alice.ask(body), Err(code));
    }
    assert_eq!(rig.fake.calls().len(), 2, "only the start-up cleanup ran");
    assert!(rig.spy.opens().is_empty());

    // Refused by the gateway.
    let elsewhere = alice.connect_ends(connect(COOKIE, [192, 0, 2, 9], &subnets, &[]));
    assert!(
        failed_with(&elsewhere, ErrorCode::GatewayUnreachable),
        "{elsewhere:?}"
    );
    let stale = alice.connect_ends(connect("stale-cookie-0000", GATEWAY, &subnets, &[]));
    assert_eq!(stale, ConnState::LoginNeeded);
    assert!(rig.is_clean());

    // Refused by the OS, part-way through. A failure logs the session off,
    // so each case gets a service of its own.
    for op in [
        Op::CapturePhysical,
        Op::ConfigureTunnel,
        Op::AddGatewayRoute,
        Op::AddTunnelRoutes,
        Op::SetSplitDns,
    ] {
        let rig = harness::rig();
        rig.fake.set_failure(op, Some(Error::PermissionDenied));
        let state = rig.owner().connect_ends(good());
        assert!(
            failed_with(&state, ErrorCode::Internal),
            "{op:?}: {state:?}"
        );
        assert!(rig.is_clean(), "{op:?} left something behind");
    }
}

// Security rule: unless every check answers "yes" the connection is torn
// down completely and reported as failed. "Could not tell" is not "yes",
// and a route that "cannot be observed" is not either.
#[test]
fn a_failed_or_unknown_check_tears_everything_down() {
    let unknown = |op| (op, Some(Error::Unsupported), false);
    let cases = [
        ("route unknown", unknown(Op::VerifyRoute)),
        ("DNS unknown", unknown(Op::VerifyDns)),
        ("route unobservable", (Op::VerifyRoute, None, true)),
    ];
    for (case, (op, error, unobservable)) in cases {
        let rig = rig();
        rig.fake.set_failure(op, error);
        rig.fake.cannot_observe(op, unobservable);
        let state = rig.owner().connect_ends(good());
        assert!(
            failed_with(&state, ErrorCode::VerificationFailed),
            "{case}: {state:?}"
        );
        assert!(rig.is_clean(), "{case} left something behind");
        assert!(rig.fake.calls().ends_with(&TEARDOWN));
    }
}

// Windows cannot show whether its resolver took the split DNS rules in.
// When the rules read back exactly, that is enough to connect, and the log
// says once that split DNS could not be confirmed.
#[test]
fn split_dns_that_cannot_be_observed_connects_and_says_so() {
    let rig = rig();
    rig.fake.cannot_observe(Op::VerifyDns, true);
    let mut alice = rig.owner();
    let state = connected(&mut alice);
    assert!(matches!(state, ConnState::Connected { .. }), "{state:?}");
    let said = alice.whole_log();
    let unconfirmed = |line: &&LogLine| line.text.as_str().contains(DNS_UNCONFIRMED);
    let lines: Vec<_> = said.iter().filter(unconfirmed).collect();
    assert_eq!(lines.len(), 1, "{said:?}");
    assert_eq!(lines[0].level, LogLevel::Warn);
}

// A split DNS check that answers "yes" writes no such line.
#[test]
fn split_dns_that_is_confirmed_says_nothing_more() {
    let rig = rig();
    let mut alice = rig.owner();
    let state = connected(&mut alice);
    assert!(matches!(state, ConnState::Connected { .. }), "{state:?}");
    let said = alice.whole_log();
    let unconfirmed = |line: &LogLine| line.text.as_str().contains(DNS_UNCONFIRMED);
    assert!(!said.iter().any(unconfirmed), "{said:?}");
}

// Security rule: teardown runs every step even when earlier steps fail, and
// never reports "disconnected" while something may still be applied.
#[test]
fn teardown_runs_every_step_even_when_steps_fail() {
    let rig = rig();
    let mut alice = rig.owner();
    connected(&mut alice);
    let broken = [
        Op::RemoveTunnelRoutes,
        Op::ClearSplitDns,
        Op::RemoveGatewayRoute,
    ];
    for op in broken {
        rig.fake.set_failure(op, Some(Error::PermissionDenied));
    }
    assert_eq!(alice.ask(RequestBody::Disconnect), ACCEPTED);
    assert_eq!(alice.state(), ConnState::Disconnecting);
    let state = alice.state();
    assert!(
        failed_with(&state, ErrorCode::Internal),
        "split DNS is still set: {state:?}"
    );
    assert!(rig.fake.calls().ends_with(&TEARDOWN));
    assert!(!rig.engine.tunnel_is_open());
    assert!(rig.fake.applied().tunnel_routes.is_empty());
    let logged = |what: &str| rig.logs().iter().any(|line| line.contains(what));
    assert!(logged("clearing split DNS failed") && logged("removing the gateway route failed"));

    // The last step failing on its own is not "clean" either.
    for op in broken {
        rig.fake.set_failure(op, None);
    }
    let denied = Some(Error::PermissionDenied);
    rig.fake.set_failure(Op::RemoveAllRoutes, denied);
    assert_eq!(alice.ask(RequestBody::Disconnect), ACCEPTED);
    assert_eq!(alice.state(), ConnState::Disconnecting);
    let state = alice.state();
    assert!(failed_with(&state, ErrorCode::Internal), "{state:?}");

    // Security rule: nothing is connected on a machine that could not be
    // cleaned first. No tunnel is opened, and the state says why.
    let opens = rig.spy.opens().len();
    let state = alice.connect_ends(good());
    assert!(failed_with(&state, ErrorCode::Internal), "{state:?}");
    assert_eq!(
        rig.spy.opens().len(),
        opens,
        "no tunnel on an unclean machine"
    );

    rig.fake.set_failure(Op::RemoveAllRoutes, None);
    assert_eq!(alice.ask(RequestBody::Disconnect), ACCEPTED);
    assert_eq!(
        [alice.state(), alice.state()],
        [ConnState::Disconnecting, ConnState::Disconnected]
    );
    assert!(rig.is_clean());
}

// Security rule: the cookie is used to open the tunnel and then forgotten.
// It reaches no log line, error, event, state or file.
#[test]
fn the_cookie_appears_nowhere() {
    let rig = rig();
    let mut alice = rig.owner();
    let state = connected(&mut alice);
    assert_eq!(
        alice.ask(RequestBody::Status),
        Ok(ResponseBody::Status(state))
    );
    assert_eq!(alice.ask(RequestBody::Disconnect), ACCEPTED);
    assert_eq!(alice.state(), ConnState::Disconnecting);
    assert_eq!(alice.state(), ConnState::Disconnected);
    assert_eq!(alice.connect_ends(good()), ConnState::LoginNeeded);

    let logs = rig.logs();
    assert!(logs.contains(&"> [redacted]".to_string()), "{logs:?}");
    let files = std::fs::read_dir(rig.state_dir()).unwrap();
    let files = files.map(|file| std::fs::read_to_string(file.unwrap().path()).unwrap());
    let shown = [
        logs,
        alice.lines.clone(),
        files.collect(),
        vec![format!("{:?}", good())],
    ];
    assert!(!shown.concat().join("\n").contains(COOKIE));
}

// Security rule: when the session ends or the connection drops, the service
// cleans up and stops. It never reconnects or opens a second tunnel itself.
#[test]
fn a_tunnel_that_ends_is_cleaned_up_and_never_reopened() {
    let expire: fn(&FakeEngine) = FakeEngine::expire_session;
    for (end, login_needed) in [(expire, true), (FakeEngine::drop_connection, false)] {
        let rig = rig();
        let mut alice = rig.owner();
        connected(&mut alice);
        end(&rig.engine);
        let state = alice.state();
        match login_needed {
            true => assert_eq!(state, ConnState::LoginNeeded),
            false => assert!(failed_with(&state, ErrorCode::EngineFailed), "{state:?}"),
        }
        assert!(rig.is_clean());
        assert!(rig.fake.calls().ends_with(&TEARDOWN));
        assert!(alice.is_quiet(), "nothing more happens");
        assert_eq!(rig.spy.opens().len(), 1, "no second open");
    }
}

#[test]
fn a_connect_during_a_connect_is_busy() {
    let rig = rig();
    let mut alice = rig.owner();
    rig.engine.hold();
    assert_eq!(alice.ask(good()), ACCEPTED);
    rig.engine.wait_until_blocked();
    assert_eq!(alice.ask(good()), Err(ErrorCode::Busy));
    rig.engine.release();
    let heard = [alice.state(), alice.state()];
    assert!(
        matches!(heard, [ConnState::Connecting, ConnState::Connected { .. }]),
        "{heard:?}"
    );
    assert_eq!(rig.spy.opens().len(), 1);
}

// A disconnect does not wait behind a connect that may never finish: it
// stops it, and nothing of it is left.
#[test]
fn a_disconnect_while_connecting_cancels_the_open() {
    let rig = rig();
    let mut alice = rig.owner();
    rig.engine.hold();
    assert_eq!(alice.ask(good()), ACCEPTED);
    rig.engine.wait_until_blocked();
    assert_eq!(alice.ask(RequestBody::Disconnect), ACCEPTED);
    let heard = [alice.state(), alice.state(), alice.state()];
    let expected = [
        ConnState::Connecting,
        ConnState::Disconnecting,
        ConnState::Disconnected,
    ];
    assert_eq!(heard, expected, "never connected");
    assert!(rig.is_clean());
    // The gate is open again afterwards.
    rig.engine.release();
    connected(&mut alice);
}

// Security rule: a user's disconnect removes everything and logs the session
// off at the gateway, so the cookie stops working.
#[test]
fn a_disconnect_removes_everything_and_logs_the_session_off() {
    let mut rig = rig();
    let mut alice = rig.owner();
    connected(&mut alice);
    assert_eq!(alice.ask(RequestBody::Disconnect), ACCEPTED);
    assert_eq!(
        [alice.state(), alice.state()],
        [ConnState::Disconnecting, ConnState::Disconnected]
    );
    assert!(rig.is_clean());
    assert!(rig.fake.calls().ends_with(&TEARDOWN));
    // The tunnel was closed after its routes and DNS were gone, and before
    // the gateway's own route, with a log-off.
    let (how, before) = rig.spy.closes().remove(0);
    assert_eq!(how, CloseMode::LogOff);
    assert!(before.ends_with(&TEARDOWN[..2]), "{before:?}");
    assert_eq!(alice.connect_ends(good()), ConnState::LoginNeeded);

    // Shutting down tears down as well. A fresh service, since that session
    // is gone.
    rig = harness::rig();
    connected(&mut rig.owner());
    rig.stop();
    assert!(rig.is_clean());
}

// The gateway's DNS servers often lie outside what the user chose. Each gets
// a route of its own through the tunnel, added with the subnets, checked
// like them, and removed with them.
#[test]
fn a_dns_server_outside_the_subnets_gets_its_own_route() {
    let rig = rig();
    let mut alice = rig.owner();
    let request = connect(COOKIE, GATEWAY, &["192.0.2.0/24"], &["ece.example.test"]);
    let state = alice.connect_ends(request);
    assert!(matches!(state, ConnState::Connected { .. }), "{state:?}");
    let routed = ["192.0.2.0/24", "10.255.0.53/32"];
    let routed = routed.map(|net| ("fake0".to_string(), net.parse().unwrap()));
    assert_eq!(rig.fake.applied().tunnel_routes, routed);
    let after_open = [
        Op::ConfigureTunnel,
        Op::AddGatewayRoute,
        Op::AddTunnelRoutes,
        Op::SetSplitDns,
        Op::VerifyRoute,
        Op::VerifyRoute,
        Op::VerifyRoute,
        Op::VerifyDns,
    ];
    assert_eq!(rig.fake.calls()[5..], after_open);

    assert_eq!(alice.ask(RequestBody::Disconnect), ACCEPTED);
    assert_eq!(
        [alice.state(), alice.state()],
        [ConnState::Disconnecting, ConnState::Disconnected]
    );
    assert!(rig.is_clean());
}

// With no DNS domains chosen the service touches no DNS at all: none is set,
// no DNS server is routed, and none is checked.
#[test]
fn without_dns_domains_no_dns_is_set_and_no_server_is_routed() {
    let rig = rig();
    let mut alice = rig.owner();
    let state = alice.connect_ends(connect(COOKIE, GATEWAY, &["192.0.2.0/24"], &[]));
    assert!(matches!(state, ConnState::Connected { .. }), "{state:?}");
    let applied = rig.fake.applied();
    assert_eq!(applied.split_dns, None);
    let routed = [("fake0".to_string(), "192.0.2.0/24".parse().unwrap())];
    assert_eq!(applied.tunnel_routes, routed);
    let after_open = [
        Op::ConfigureTunnel,
        Op::AddGatewayRoute,
        Op::AddTunnelRoutes,
        Op::VerifyRoute,
        Op::VerifyRoute,
    ];
    assert_eq!(rig.fake.calls()[5..], after_open);
}

/// Connects against a gateway that assigns `servers` and returns the rig and
/// the state the connect ended in.
fn with_dns_servers(servers: &[[u8; 4]]) -> (Rig, ConnState) {
    let mut rig = Rig::scripted(policy('A', ""), |script| {
        script.assigned.dns = servers.iter().map(|addr| (*addr).into()).collect();
    });
    rig.start().unwrap();
    let state = rig.owner().connect_ends(good());
    (rig, state)
}

// Security rule: the DNS servers come from the gateway, and each becomes a
// route added as an admin, so the list is not trusted. One that could not be
// a DNS server behind the tunnel, or too many of them, fails the connect
// before any route is added.
#[test]
fn a_dns_server_that_cannot_be_one_fails_the_connect() {
    let good_one = [10, 255, 0, 53];
    let refused: [&[[u8; 4]]; 9] = [
        &[good_one, [127, 0, 0, 53]],
        &[good_one, [0, 0, 0, 0]],
        &[good_one, [169, 254, 1, 1]],
        &[good_one, [224, 0, 0, 1]],
        // The gateway's own address, which must stay outside the tunnel.
        &[good_one, GATEWAY],
        // The router of the physical network.
        &[good_one, [192, 168, 0, 1]],
        // A neighbour on the network the machine is on, and the machine
        // itself: a route to either would take it into the tunnel.
        &[good_one, [192, 168, 0, 53]],
        &[good_one, [192, 168, 0, 10]],
        // One more than a gateway may assign.
        &[
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            [10, 0, 0, 3],
            [10, 0, 0, 4],
            [10, 0, 0, 5],
        ],
    ];
    for servers in refused {
        let (rig, state) = with_dns_servers(servers);
        let why = format!("{servers:?}: {state:?}");
        assert!(failed_with(&state, ErrorCode::EngineFailed), "{why}");
        assert!(rig.is_clean(), "{why}");
        let calls = rig.fake.calls();
        // Nothing is applied: not even the device is configured.
        let applied = [
            Op::ConfigureTunnel,
            Op::AddGatewayRoute,
            Op::AddTunnelRoutes,
        ];
        assert!(!calls.iter().any(|op| applied.contains(op)), "{why}");
    }

    // As many as allowed, each routed once however often it was named.
    let most = [
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        [10, 0, 0, 1],
        [10, 0, 0, 3],
        [10, 0, 0, 4],
    ];
    let (rig, state) = with_dns_servers(&most);
    assert!(matches!(state, ConnState::Connected { .. }), "{state:?}");
    let applied = rig.fake.applied();
    assert_eq!(
        applied.tunnel_routes.len(),
        2 + 4,
        "two subnets, four servers"
    );
    assert_eq!(applied.split_dns.unwrap().1.resolvers.len(), 4);
}

// Security rule: only what the user chose is routed. The routes the gateway
// suggests, here everything, never reach the OS.
#[test]
fn routes_the_gateway_suggests_are_never_applied() {
    let mut rig = Rig::scripted(policy('A', ""), |script| {
        let everything = ["0.0.0.0/1", "128.0.0.0/1", "172.16.0.0/12"];
        script.assigned.split_includes = everything.map(|net| net.parse().unwrap()).to_vec();
    });
    rig.start().unwrap();
    let state = rig.owner().connect_ends(good());
    assert!(matches!(state, ConnState::Connected { .. }), "{state:?}");
    let routed = ["10.255.0.0/24", "192.0.2.0/24", "10.255.0.53/32"];
    let routed = routed.map(|net| ("fake0".to_string(), net.parse().unwrap()));
    assert_eq!(rig.fake.applied().tunnel_routes, routed);
}

// Security rule: the tunnel must be connected to the address the cookie was
// issued at, which is the address the gateway route is for. One that is
// connected elsewhere is torn down.
#[test]
fn a_tunnel_at_another_address_is_torn_down() {
    let rig = rig();
    rig.spy.claim_address([192, 0, 2, 77]);
    let state = rig.owner().connect_ends(good());
    assert!(failed_with(&state, ErrorCode::EngineFailed), "{state:?}");
    assert!(rig.is_clean());
    assert!(!rig.fake.calls().contains(&Op::AddGatewayRoute));
}

// Security rule: a bug that panics the worker part-way through a connect
// leaves nothing applied and does not leave the service stuck. Everything is
// torn down, the session logged off, the state is `failed`, and the next
// request is taken.
#[test]
fn a_panic_part_way_through_a_connect_leaves_nothing_behind() {
    let stages = [
        Op::CapturePhysical,
        Op::ConfigureTunnel,
        Op::AddGatewayRoute,
        Op::AddTunnelRoutes,
        Op::SetSplitDns,
        Op::VerifyRoute,
        Op::VerifyDns,
    ];
    for stage in stages {
        let rig = rig();
        let mut alice = rig.owner();
        rig.os.panic_at(stage);
        let state = alice.connect_ends(good());
        assert!(
            failed_with(&state, ErrorCode::Internal),
            "{stage:?}: {state:?}"
        );
        assert!(rig.is_clean(), "{stage:?} left something behind");
        assert_eq!(
            alice.ask(RequestBody::Status),
            Ok(ResponseBody::Status(state))
        );

        // The service takes requests again. Before the tunnel existed the
        // session is untouched and connects; after, it was logged off.
        let next = alice.connect_ends(good());
        match stage {
            Op::CapturePhysical => assert!(matches!(next, ConnState::Connected { .. }), "{next:?}"),
            _ => assert_eq!(next, ConnState::LoginNeeded, "{stage:?}"),
        }
        assert_eq!(alice.ask(RequestBody::Disconnect), ACCEPTED);
        assert_eq!(alice.state(), ConnState::Disconnecting);
        assert_eq!(alice.state(), ConnState::Disconnected);
        assert!(rig.is_clean(), "{stage:?}");
    }
}

// A connect is taken only when nothing is connected or in progress. To
// replace a connection the client disconnects first.
#[test]
fn a_connect_while_connected_is_busy() {
    let rig = rig();
    let mut alice = rig.owner();
    let state = connected(&mut alice);
    assert_eq!(alice.ask(good()), Err(ErrorCode::Busy));
    assert_eq!(
        alice.ask(RequestBody::Status),
        Ok(ResponseBody::Status(state))
    );
    assert_eq!(rig.spy.opens().len(), 1);
    assert!(rig.engine.tunnel_is_open(), "the connection was left alone");

    // Once the tunnel has ended by itself a connect is taken again.
    rig.engine.drop_connection();
    assert!(matches!(alice.state(), ConnState::Failed { .. }));
    assert_eq!(alice.ask(good()), ACCEPTED);
}

// While a disconnect is in progress nothing else is taken.
#[test]
fn requests_during_a_disconnect_are_busy() {
    let rig = rig();
    let mut alice = rig.owner();
    connected(&mut alice);
    rig.spy.hold_closes();
    assert_eq!(alice.ask(RequestBody::Disconnect), ACCEPTED);
    rig.spy.wait_for_a_held_close();
    assert_eq!(alice.ask(RequestBody::Disconnect), Err(ErrorCode::Busy));
    assert_eq!(alice.ask(good()), Err(ErrorCode::Busy));
    rig.spy.release();
    assert_eq!(
        [alice.state(), alice.state()],
        [ConnState::Disconnecting, ConnState::Disconnected]
    );
    assert!(alice.is_quiet(), "one disconnect, and no connect");
    assert_eq!(rig.spy.opens().len(), 1);
}

// The ending of a tunnel that was already closed must not undo the
// connection that came after it.
#[test]
fn an_old_tunnels_ending_does_not_end_the_next_connection() {
    let rig = rig();
    // So that the same cookie opens a second tunnel after the first closes.
    rig.spy.keep_sessions();
    let mut alice = rig.owner();
    connected(&mut alice);
    rig.spy.hold_endings();
    assert_eq!(alice.ask(RequestBody::Disconnect), ACCEPTED);
    assert_eq!(
        [alice.state(), alice.state()],
        [ConnState::Disconnecting, ConnState::Disconnected]
    );
    let second = connected(&mut alice);
    // Only now does the first tunnel's "closed" arrive.
    rig.spy.release();
    assert!(alice.is_quiet(), "the second connection stays up");
    assert_eq!(
        alice.ask(RequestBody::Status),
        Ok(ResponseBody::Status(second))
    );
    assert!(rig.engine.tunnel_is_open());
}

// Security rule: a panic inside teardown itself still logs the session off
// and still ends with nothing applied. The tunnel is closed properly, not
// just dropped, which would leave the session alive at the gateway.
#[test]
fn a_panic_inside_teardown_still_logs_off_and_cleans_up() {
    let steps = [
        Op::RemoveTunnelRoutes,
        Op::ClearSplitDns,
        Op::RemoveGatewayRoute,
        Op::RemoveAllRoutes,
    ];
    for step in steps {
        let rig = rig();
        let mut alice = rig.owner();
        connected(&mut alice);
        rig.os.panic_at(step);
        assert_eq!(alice.ask(RequestBody::Disconnect), ACCEPTED);
        assert_eq!(alice.state(), ConnState::Disconnecting);
        let state = alice.state();
        assert!(
            failed_with(&state, ErrorCode::Internal),
            "{step:?}: {state:?}"
        );
        assert!(rig.is_clean(), "{step:?} left something behind");
        let closes = rig.spy.closes();
        let modes: Vec<_> = closes.iter().map(|(how, _)| *how).collect();
        assert_eq!(
            modes,
            [CloseMode::LogOff],
            "{step:?}: closed once, with a log-off"
        );
        // The gateway agrees: the cookie no longer opens a tunnel.
        assert_eq!(
            alice.connect_ends(good()),
            ConnState::LoginNeeded,
            "{step:?}"
        );
    }
}

// The same at shutdown, where nobody is left to tell: a panic part-way does
// not stop the rest of the cleanup.
#[test]
fn a_panic_in_the_teardown_at_shutdown_does_not_stop_the_cleanup() {
    for step in [Op::RemoveTunnelRoutes, Op::RemoveAllRoutes] {
        let mut rig = rig();
        connected(&mut rig.owner());
        rig.os.panic_at(step);
        rig.stop();
        assert!(rig.is_clean(), "{step:?} left something behind");
        let modes: Vec<_> = rig.spy.closes().iter().map(|(how, _)| *how).collect();
        assert_eq!(modes, [CloseMode::LogOff], "{step:?}");
    }
}

// A client that has heard how a disconnect ended may ask again at once, and
// is not told the service is busy: the service is ready for it before it
// says so. Many times over, since the wrong order shows only now and then.
#[test]
fn whoever_hears_the_end_may_ask_again_at_once() {
    let rig = rig();
    let mut alice = rig.owner();
    for round in 0..300 {
        assert_eq!(alice.ask(RequestBody::Disconnect), ACCEPTED, "{round}");
        assert_eq!(alice.state(), ConnState::Disconnecting);
        assert_eq!(alice.state(), ConnState::Disconnected);
    }
}

/// Connects with `subnets` on a fake whose machine has the addresses `own`
/// on the networks `on_link`, and returns the rig and how the connect ended.
fn on_local(own: &[[u8; 4]], on_link: &[&str], subnets: &[&str]) -> (Rig, ConnState) {
    let rig = rig();
    let own: Vec<_> = own.iter().map(|addr| (*addr).into()).collect();
    let on_link: Vec<_> = on_link.iter().map(|net| net.parse().unwrap()).collect();
    rig.fake.set_local(&own, &on_link);
    let request = connect(COOKIE, GATEWAY, subnets, &["ece.example.test"]);
    let state = rig.owner().connect_ends(request);
    (rig, state)
}

// Security rule: a route that would take a network the machine is on into
// the tunnel, or the gateway itself, or the router the gateway is reached
// through, is refused. It is refused before the gateway is contacted, so
// the cookie is never sent, and nothing is applied.
#[test]
fn a_route_into_a_local_network_is_refused_before_the_gateway_is_contacted() {
    let home = ["192.168.0.0/24"];
    let refused: [(&[&str], &[&str]); 4] = [
        // The home network itself, and a part of it.
        (&home, &["10.255.0.0/24", "192.168.0.0/24"]),
        (&home, &["192.168.0.128/25"]),
        // The router, when no network the machine is on holds it.
        (&[], &["192.168.0.0/16"]),
        // The gateway's own address.
        (&home, &["192.0.2.1/32"]),
    ];
    for (on_link, subnets) in refused {
        let (rig, state) = on_local(&[[192, 168, 0, 10]], on_link, subnets);
        let why = format!("{subnets:?} on {on_link:?}: {state:?}");
        assert!(failed_with(&state, ErrorCode::RouteRefused), "{why}");
        assert!(
            rig.spy.opens().is_empty(),
            "the gateway was contacted: {why}"
        );
        assert!(rig.is_clean(), "{why}");
    }
}

// The same rule lets through a route wider than the network the machine is
// on: that network stays the more specific route, router and all.
#[test]
fn a_route_wider_than_the_local_network_connects() {
    let subnets = ["10.255.0.0/24", "192.168.0.0/16"];
    let (_rig, state) = on_local(&[[192, 168, 0, 10]], &["192.168.0.0/24"], &subnets);
    assert!(matches!(state, ConnState::Connected { .. }), "{state:?}");
}

// Security rule: a gateway address that is one of this machine's own is
// refused before anything is contacted. Such an address could point the
// privileged service at a program on this machine.
#[test]
fn a_gateway_at_this_machines_own_address_is_refused() {
    let own = [[192, 168, 0, 10], GATEWAY];
    let (rig, state) = on_local(&own, &["192.168.0.0/24"], &["10.255.0.0/24"]);
    assert!(failed_with(&state, ErrorCode::BadRequest), "{state:?}");
    assert!(rig.spy.opens().is_empty(), "the gateway was contacted");
    assert!(rig.is_clean());
}

// Security rule: what the gateway assigned is applied with this machine's
// admin rights, so it is checked first. A packet size the device cannot
// take, or an address that is this machine's own, the gateway's, the
// router's or a reserved one, fails the connect before any route is added.
#[test]
fn an_assignment_that_cannot_be_used_fails_the_connect() {
    type Edit = fn(&mut Script);
    let refused: [(&str, Edit); 9] = [
        ("packet size too small", |s| s.assigned.mtu = 575),
        ("packet size too large", |s| s.assigned.mtu = 1501),
        ("no packet size", |s| s.assigned.mtu = 0),
        ("own address", |s| {
            s.assigned.address = [192, 168, 0, 10].into()
        }),
        ("gateway", |s| s.assigned.address = GATEWAY.into()),
        ("router", |s| s.assigned.address = [192, 168, 0, 1].into()),
        ("loopback", |s| s.assigned.address = [127, 0, 0, 1].into()),
        ("this network", |s| s.assigned.address = [0, 0, 0, 0].into()),
        ("link-local", |s| {
            s.assigned.address = [169, 254, 0, 9].into()
        }),
    ];
    for (case, edit) in refused {
        let mut rig = Rig::scripted(policy('A', ""), edit);
        rig.start().unwrap();
        let state = rig.owner().connect_ends(good());
        assert!(
            failed_with(&state, ErrorCode::EngineFailed),
            "{case}: {state:?}"
        );
        assert!(rig.is_clean(), "{case}");
        let calls = rig.fake.calls();
        let routed = [Op::AddGatewayRoute, Op::AddTunnelRoutes];
        assert!(!calls.iter().any(|op| routed.contains(op)), "{case}");
    }
    // The edges of the range are fine.
    for mtu in [576, 1500] {
        let mut rig = Rig::scripted(policy('A', ""), |s| s.assigned.mtu = mtu);
        rig.start().unwrap();
        let state = rig.owner().connect_ends(good());
        assert!(
            matches!(state, ConnState::Connected { .. }),
            "{mtu}: {state:?}"
        );
    }
}

/// Waits until `happened`, or fails the test after a while.
fn soon(what: &str, happened: impl Fn() -> bool) {
    let until = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !happened() {
        assert!(std::time::Instant::now() < until, "never: {what}");
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

// Security rule: when the physical network changes, the gateway's route
// leads nowhere and the connection is not what was checked. Everything is
// torn down, the session is logged off, and the user is told.
#[test]
fn a_change_of_network_tears_everything_down() {
    let rig = rig();
    let mut alice = rig.owner();
    connected(&mut alice);
    assert_eq!(rig.os.subscriptions(), 1, "watched from the start");
    assert!(rig.os.send_to(0, NetworkEvent::PhysicalChanged));
    let state = alice.state();
    assert!(failed_with(&state, ErrorCode::EngineFailed), "{state:?}");
    let ConnState::Failed { message, .. } = &state else {
        unreachable!()
    };
    assert!(message.contains("network changed"), "{message}");
    assert!(rig.is_clean());
    let modes: Vec<_> = rig.spy.closes().iter().map(|(how, _)| *how).collect();
    assert_eq!(modes, [CloseMode::LogOff]);
    // Nothing is left watching. The service takes a new connect at once,
    // and the gateway agrees the session was logged off.
    soon("the subscription ends", || {
        !rig.os.send_to(0, NetworkEvent::PhysicalChanged)
    });
    assert_eq!(alice.connect_ends(good()), ConnState::LoginNeeded);
}

// The watch on the network ends with the connection's teardown itself, not
// at the next network event, which might never come.
#[test]
fn a_disconnect_ends_the_network_watch_at_once() {
    let rig = rig();
    let mut alice = rig.owner();
    connected(&mut alice);
    assert_eq!(rig.os.subscriptions(), 1, "watched from the start");
    assert_eq!(alice.ask(RequestBody::Disconnect), ACCEPTED);
    assert_eq!(
        [alice.state(), alice.state()],
        [ConnState::Disconnecting, ConnState::Disconnected]
    );
    // Already ended: no event was needed to end it.
    assert!(!rig.os.send_to(0, NetworkEvent::Sleeping), "still watching");
}

// Going to sleep and waking say nothing about the network by themselves; a
// tunnel that does not survive them ends by itself.
#[test]
fn sleep_and_wake_leave_the_connection_alone() {
    let rig = rig();
    let mut alice = rig.owner();
    connected(&mut alice);
    assert!(rig.os.send_to(0, NetworkEvent::Sleeping));
    assert!(rig.os.send_to(0, NetworkEvent::Woke));
    assert!(alice.is_quiet(), "the connection stays up");
    assert!(rig.engine.tunnel_is_open());
}

// Security rule: a change reported for an earlier connection never ends a
// later one, which was set up on the network as it is now.
#[test]
fn a_change_from_an_earlier_connection_leaves_a_later_one_alone() {
    let rig = rig();
    rig.spy.keep_sessions();
    let mut alice = rig.owner();
    connected(&mut alice);
    assert_eq!(alice.ask(RequestBody::Disconnect), ACCEPTED);
    assert_eq!(alice.state(), ConnState::Disconnecting);
    assert_eq!(alice.state(), ConnState::Disconnected);
    connected(&mut alice);
    assert_eq!(rig.os.subscriptions(), 2);
    // The first subscription may already be gone, which is as good.
    let _ = rig.os.send_to(0, NetworkEvent::PhysicalChanged);
    assert!(alice.is_quiet(), "the second connection stays up");
    assert!(rig.engine.tunnel_is_open());
    // Its own subscription still ends it.
    assert!(rig.os.send_to(1, NetworkEvent::PhysicalChanged));
    let state = alice.state();
    assert!(failed_with(&state, ErrorCode::EngineFailed), "{state:?}");
}

// Security rule: the same, when the earlier attempt never opened a tunnel.
// It watched the network it was on and failed at the gateway; the user
// then connected on another network. A change to the first network must
// not end the connection on the second.
#[test]
fn a_change_from_a_failed_attempt_leaves_a_later_connection_alone() {
    let rig = rig();
    let mut alice = rig.owner();
    rig.engine.set_reachable(false);
    let state = alice.connect_ends(good());
    assert!(
        failed_with(&state, ErrorCode::GatewayUnreachable),
        "{state:?}"
    );
    rig.engine.set_reachable(true);
    connected(&mut alice);
    assert_eq!(rig.os.subscriptions(), 2);
    let _ = rig.os.send_to(0, NetworkEvent::PhysicalChanged);
    assert!(alice.is_quiet(), "the later connection stays up");
    assert!(rig.engine.tunnel_is_open());
    assert!(rig.os.send_to(1, NetworkEvent::PhysicalChanged));
    let state = alice.state();
    assert!(failed_with(&state, ErrorCode::EngineFailed), "{state:?}");
}

// Until Windows can report network changes, a system that cannot is not a
// reason to refuse: the connection goes ahead, and the log says once that
// changes are not watched. A dead tunnel still ends as a lost connection.
#[test]
fn a_system_that_cannot_watch_the_network_still_connects_and_says_so() {
    let rig = rig();
    rig.fake
        .set_failure(Op::Subscribe, Some(Error::Unsupported));
    rig.spy.keep_sessions();
    let mut alice = rig.owner();
    for _ in 0..2 {
        connected(&mut alice);
        assert_eq!(alice.ask(RequestBody::Disconnect), ACCEPTED);
        assert_eq!(alice.state(), ConnState::Disconnecting);
        assert_eq!(alice.state(), ConnState::Disconnected);
    }
    let said = |line: &String| line.contains("network changes cannot be watched");
    let lines = rig.logs();
    assert_eq!(
        lines.iter().filter(|line| said(line)).count(),
        1,
        "{lines:?}"
    );
}

// Security rule: any other failure to watch the network fails the connect
// before the gateway is contacted, so no cookie is sent, and nothing is
// left applied.
#[test]
fn a_failure_to_watch_the_network_fails_the_connect_before_the_gateway() {
    let rig = rig();
    rig.fake
        .set_failure(Op::Subscribe, Some(Error::PermissionDenied));
    let state = rig.owner().connect_ends(good());
    assert!(failed_with(&state, ErrorCode::Internal), "{state:?}");
    assert!(rig.spy.opens().is_empty(), "the gateway was contacted");
    assert!(rig.is_clean());
}
