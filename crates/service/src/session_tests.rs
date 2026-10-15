//! What the worker does by itself, with nobody asking. Every value is made
//! up.

use std::time::Instant;

use ubc_vpn_core::policy::Pin;
use ubc_vpn_core::redact::Secret;
use ubc_vpn_core::routes::RouteSet;
use ubc_vpn_engine::fake::{FakeEngine, Script};
use ubc_vpn_platform::fake::Fake;

use super::*;

/// Waits, up to ten seconds, for something that should happen soon.
fn until(what: &str, happened: impl Fn() -> bool) {
    let started = Instant::now();
    while !happened() {
        assert!(started.elapsed() < Duration::from_secs(10), "{what}");
        thread::sleep(Duration::from_millis(2));
    }
}

// Security rule: the cookie is wiped when its time is up, on a service that
// is then asked for nothing at all. Here it lingers for a twentieth of a
// second; a session connects, disconnects and is left alone.
#[test]
fn a_cookie_is_wiped_on_an_idle_service_when_its_time_is_up() {
    let fake = Fake::new();
    // Nothing is read or written there: the policy is handed in below.
    let platform = fake.platform(&std::env::temp_dir().join("ubc-vpn-made-up"));
    let pin: Pin = format!("pin-sha256:{}=", "A".repeat(43))
        .try_into()
        .unwrap();
    let engine = Arc::new(FakeEngine::new(Script::new(pin.clone())));
    let policy = Policy {
        gateway: "vpn.example.test".to_string(),
        pins: vec![pin],
        allowed_routes: None,
    };
    let hub = Arc::new(Hub::new(None));
    let logs = Logs::lingering(Duration::from_millis(50));
    let session = Session::start(&platform, engine, Ok(policy), hub.clone(), logs.clone());
    let session = session.unwrap();

    let subnets = ["10.255.0.0/24", "192.0.2.0/24"];
    let params = ConnectParams {
        cookie: Secret::new("Zq7-made-up-0123456789"),
        gateway_addr: [192, 0, 2, 1].into(),
        routes: RouteSet {
            subnets: subnets.iter().map(|s| s.parse().unwrap()).collect(),
            dns_domains: Vec::new(),
        },
    };
    session.connect(params).unwrap();
    until("connected", || {
        matches!(hub.state(), ConnState::Connected { .. })
    });
    assert_eq!(logs.held(), 1, "the cookie is held while the tunnel is up");
    session.disconnect("the made-up kind").unwrap();
    until("disconnected", || hub.state() == ConnState::Disconnected);

    // Asked for nothing more, and counted without wiping.
    thread::sleep(Duration::from_millis(400));
    assert_eq!(
        logs.held(),
        0,
        "the cookie was still held on an idle service"
    );
    session.stop();
}

/// A session on fakes whose gateway keeps honouring the cookie, so that
/// it can connect again after a disconnect.
fn reconnecting_session() -> (Session, Arc<Hub>) {
    let fake = Fake::new();
    let platform = fake.platform(&std::env::temp_dir().join("ubc-vpn-made-up"));
    let pin: Pin = format!("pin-sha256:{}=", "A".repeat(43))
        .try_into()
        .unwrap();
    let engine = Arc::new(FakeEngine::for_dev_mode(Script::new(pin.clone())));
    let policy = Policy {
        gateway: "vpn.example.test".to_string(),
        pins: vec![pin],
        allowed_routes: None,
    };
    let hub = Arc::new(Hub::new(None));
    let session = Session::start(&platform, engine, Ok(policy), hub.clone(), Logs::default());
    (session.unwrap(), hub)
}

fn params() -> ConnectParams {
    ConnectParams {
        cookie: Secret::new("Zq7-made-up-0123456789"),
        gateway_addr: [192, 0, 2, 1].into(),
        routes: RouteSet {
            subnets: vec!["10.255.0.0/24".parse().unwrap()],
            dns_domains: Vec::new(),
        },
    }
}

// Security rule (#163): undoing the connect of a client that went undoes
// that connect only. A later one, admitted for someone who is watching it,
// is left alone; the one it was meant for is undone.
#[test]
fn abandoning_a_connect_undoes_that_connect_only() {
    let (session, hub) = reconnecting_session();
    let connected = || matches!(hub.state(), ConnState::Connected { .. });
    let first = session.connect(params()).unwrap();
    until("connected", connected);
    session.disconnect("the made-up kind").unwrap();
    until("disconnected", || hub.state() == ConnState::Disconnected);
    let second = session.connect(params()).unwrap();
    until("connected again", connected);

    session.abandon(first);
    thread::sleep(Duration::from_millis(200));
    assert!(connected(), "a later connect was undone: {:?}", hub.state());

    session.abandon(second);
    until("the abandoned connect undone", || {
        hub.state() == ConnState::Disconnected
    });
    session.stop();
}
