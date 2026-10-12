//! Connecting, verifying and tearing down, driven over the channel. Tests
//! marked "Security rule" must fail if the rule they name is removed.

mod harness;

use harness::*;
use ubc_vpn_core::policy::Policy;
use ubc_vpn_engine::Gateway;
use ubc_vpn_platform::SplitDns;
use ubc_vpn_platform::fake::PHYSICAL_INTERFACE;

const ACCEPTED: Result<ResponseBody, ErrorCode> = Ok(ResponseBody::Accepted);
/// What start-up does, and what each connect does before the tunnel exists.
const BEFORE_OPEN: [Op; 5] = [
    Op::RemoveAllRoutes,
    Op::ClearSplitDns,
    Op::ClearSplitDns,
    Op::RemoveAllRoutes,
    Op::CapturePhysical,
];
/// Applying, then one check per subnet, the gateway, the DNS server and DNS.
const AFTER_OPEN: [Op; 8] = [
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
// the gateway's own route goes in before the tunnel's, and "connected" is
// reported only after every check has been made.
#[test]
fn connect_applies_in_order_and_verifies_before_connected() {
    let rig = rig();
    let (mut alice, mut second) = (rig.owner(), rig.peer("alice"));
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
// down completely and reported as failed. "Could not tell" is not "yes".
#[test]
fn a_failed_or_unknown_check_tears_everything_down() {
    for unknown in [Op::VerifyRoute, Op::VerifyDns] {
        let rig = rig();
        rig.fake.set_failure(unknown, Some(Error::Unsupported));
        let state = rig.owner().connect_ends(good());
        assert!(
            failed_with(&state, ErrorCode::VerificationFailed),
            "{unknown:?}: {state:?}"
        );
        assert!(rig.is_clean(), "{unknown:?} left something behind");
        assert!(rig.fake.calls().ends_with(&TEARDOWN));
    }
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

    for op in broken {
        rig.fake.set_failure(op, None);
    }
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
    assert_eq!(alice.ask(good()), ACCEPTED);
    assert_eq!(
        [alice.state(), alice.state()],
        [ConnState::Connecting, ConnState::LoginNeeded]
    );

    let logs = rig.logs();
    assert!(logs.contains(&"> [redacted]".to_string()), "{logs:?}");
    let files = std::fs::read_dir(rig.root.join("state")).unwrap();
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
        Op::AddGatewayRoute,
        Op::AddTunnelRoutes,
        Op::VerifyRoute,
        Op::VerifyRoute,
    ];
    assert_eq!(rig.fake.calls()[5..], after_open);
}

// Security rule: a DNS server address that could not be a server is never
// routed. The gateway chose it, but the route would be added as an admin.
#[test]
fn a_dns_server_that_cannot_be_one_fails_the_connect() {
    for bad in [
        [127, 0, 0, 53],
        [0, 0, 0, 0],
        [169, 254, 1, 1],
        [224, 0, 0, 1],
    ] {
        let mut rig = Rig::scripted(policy('A', ""), |script| {
            script.assigned.dns = vec![[10, 255, 0, 53].into(), bad.into()];
        });
        rig.start().unwrap();
        let state = rig.owner().connect_ends(good());
        assert!(
            failed_with(&state, ErrorCode::EngineFailed),
            "{bad:?}: {state:?}"
        );
        assert!(rig.is_clean(), "{bad:?} left something behind");
        assert!(!rig.fake.calls().contains(&Op::AddTunnelRoutes), "{bad:?}");
    }
}
