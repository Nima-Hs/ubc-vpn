//! The channel: the handshake, who is served, and start-up. Tests marked
//! "Security rule" must fail if the rule they name is removed.

mod harness;

use std::time::Duration;

use harness::*;
use ubc_vpn_core::protocol::{HelloReply, PROTOCOL_VERSION, decode};
use ubc_vpn_platform::fake::Applied;
use ubc_vpn_platform::{Dns, Routes, SplitDns};
use ubc_vpn_service::{MAX_CONNECTIONS, MAX_STRANGERS};

const DISCONNECTED: Result<ResponseBody, ErrorCode> =
    Ok(ResponseBody::Status(ConnState::Disconnected));

// Security rule: until someone claims the service it carries out nothing but
// `claim`, and tells nobody its state.
#[test]
fn nothing_but_claim_is_served_before_a_claim() {
    let rig = rig();
    let mut alice = rig.peer("alice");
    assert!(!alice.hello.owner_claimed);
    for body in [RequestBody::Status, RequestBody::Disconnect, good()] {
        assert_eq!(alice.ask(body), Err(ErrorCode::NotClaimed));
    }
    assert!(alice.is_quiet(), "no state is sent before the claim");

    assert_eq!(alice.ask(RequestBody::Claim), Ok(ResponseBody::Claimed));
    assert_eq!(alice.state(), ConnState::Disconnected);
    assert_eq!(alice.ask(RequestBody::Status), DISCONNECTED);
    assert_eq!(alice.ask(RequestBody::Claim), Ok(ResponseBody::Claimed));
}

// Security rule: once there is an owner, the service compares every caller
// with it. Anyone else is refused and disconnected, whatever they ask.
#[test]
fn a_non_owner_is_refused_and_disconnected() {
    // No time limit comes to the rescue: only the owner check closes these.
    let mut rig = Rig::stopped(policy('A', ""));
    rig.timeouts.stranger = Duration::from_secs(120);
    rig.start().unwrap();
    // The OS-level narrowing is switched off, so that the service's own
    // check is what stands between mallory and the service.
    rig.fake
        .set_failure(Op::RestrictTo, Some(Error::Unsupported));
    let mut early = rig.peer("mallory");
    let mut alice = rig.owner();
    assert!(
        early.is_closed(),
        "the claim closes a stranger's connection"
    );

    let requests = [
        RequestBody::Claim,
        RequestBody::Status,
        RequestBody::Disconnect,
        good(),
    ];
    for body in requests {
        let mut mallory = rig.peer("mallory");
        assert!(mallory.hello.owner_claimed);
        assert_eq!(mallory.ask(body), Err(ErrorCode::NotOwner));
        assert!(mallory.is_closed());
        assert_eq!(mallory.lines.len(), 1, "told nothing but the refusal");
    }
    assert_eq!(alice.ask(RequestBody::Status), DISCONNECTED);
}

// Security rule: a claim narrows the channel, so the OS itself refuses other
// users before any of this code runs.
#[test]
fn a_claim_narrows_the_channel_to_the_owner() {
    let rig = rig();
    assert!(rig.raw("mallory").is_ok());
    let _alice = rig.owner();
    assert_eq!(rig.raw("mallory").err(), Some(Error::PermissionDenied));
    assert!(rig.raw("alice").is_ok());
}

// Security rule: the owner is stored, so a restart neither forgets it nor
// lets a second user claim the service.
#[test]
fn the_owner_survives_a_restart_and_nobody_else_can_claim() {
    let mut rig = rig();
    drop(rig.owner());
    rig.stop();
    rig.start().unwrap();
    let refused = rig.raw("mallory").err();
    assert_eq!(refused, Some(Error::PermissionDenied), "narrowed at once");

    rig.stop();
    rig.fake
        .set_failure(Op::RestrictTo, Some(Error::Unsupported));
    rig.start().unwrap();
    let mut mallory = rig.peer("mallory");
    assert!(mallory.hello.owner_claimed);
    assert_eq!(mallory.ask(RequestBody::Claim), Err(ErrorCode::NotOwner));
    let mut alice = rig.peer("alice");
    let first = alice.state();
    assert_eq!(first, ConnState::Disconnected, "the owner hears the state");
    assert_eq!(alice.ask(RequestBody::Claim), Ok(ResponseBody::Claimed));
}

// Security rule: a state file that cannot be understood is never read as
// "nobody owns the service", which would let any local user claim it.
#[test]
fn a_damaged_state_file_stops_the_service() {
    let mut rig = Rig::stopped(policy('A', ""));
    std::fs::create_dir_all(rig.root.join("state")).unwrap();
    for damaged in ["", "{}", r#"{"owner":"two words"}"#] {
        std::fs::write(rig.root.join("state/state.json"), damaged).unwrap();
        assert!(rig.start().unwrap_err().contains("damaged"), "{damaged:?}");
        assert_eq!(rig.raw("mallory").err(), Some(Error::NotFound));
    }
}

// A client from another version, or one that sends nonsense, is always told
// the service's version before it is disconnected.
#[test]
fn a_mismatched_or_unreadable_hello_is_answered_before_the_close() {
    let rig = rig();
    let v = PROTOCOL_VERSION;
    let hellos = [
        format!(
            r#"{{"protocol_version":{},"client":"tray","new":1}}"#,
            v + 1
        ),
        format!(r#"{{"protocol_version":{v},"client":"cli","client_version":"0","owner":"me"}}"#),
        "not json".to_string(),
    ];
    for hello in hellos {
        let conn = rig.raw("alice").unwrap();
        conn.write_line(&hello).unwrap();
        let reply: HelloReply = decode(&conn.read_line().unwrap().unwrap()).unwrap();
        assert_eq!(reply.protocol_version, PROTOCOL_VERSION);
        // Whatever it asks next goes unanswered: the connection is closed.
        let _ = conn.write_line(r#"{"id":1,"body":{"method":"claim"}}"#);
        let after = conn.read_line();
        let closed = matches!(after, Ok(None) | Err(Error::Closed));
        assert!(closed, "{hello} was served: {after:?}");
    }
}

// Security rule: a client that says nothing is dropped after the limit and
// delays nobody else in the meantime. The owner is not such a client.
#[test]
fn a_silent_client_is_dropped_and_stalls_nobody() {
    // With a limit far longer than the test, alice is served while the
    // silent client is still being waited for.
    let mut patient = Rig::stopped(policy('A', ""));
    patient.timeouts.stranger = Duration::from_secs(120);
    patient.start().unwrap();
    let _silent = patient.raw("mallory").unwrap();
    assert_eq!(patient.owner().ask(RequestBody::Status), DISCONNECTED);

    let mut strict = Rig::stopped(policy('A', ""));
    strict.timeouts.stranger = Duration::from_secs(1);
    strict.start().unwrap();
    let (silent, mut slow) = (strict.raw("mallory").unwrap(), strict.peer("mallory"));
    // The owner's app is idle for hours while it waits for events.
    let mut alice = strict.owner();
    assert!(
        silent.read_line().unwrap().is_some(),
        "answered all the same"
    );
    assert_eq!(silent.read_line(), Ok(None), "then dropped");
    assert!(slow.is_closed(), "a stranger who never asks is dropped too");
    // The hello has to arrive in time from everyone, the owner included.
    let late = strict.raw("alice").unwrap();
    assert!(late.read_line().unwrap().is_some());
    assert_eq!(
        late.read_line(),
        Ok(None),
        "an owner with no hello is dropped"
    );
    std::thread::sleep(Duration::from_millis(1500));
    assert_eq!(alice.ask(RequestBody::Status), DISCONNECTED);
}

// Fail closed: without a usable policy there is no gateway to trust, so
// every connect is refused. Status still works.
#[test]
fn without_a_valid_policy_every_connect_is_refused() {
    let no_pins = r#"{"gateway":"vpn.example.test","pins":[]}"#.to_string();
    for policy in [None, Some("{".to_string()), Some(no_pins)] {
        let mut rig = Rig::stopped(policy);
        rig.start().unwrap();
        let mut alice = rig.owner();
        assert_eq!(alice.ask(good()), Err(ErrorCode::PolicyInvalid));
        assert_eq!(alice.ask(RequestBody::Status), DISCONNECTED);
        assert!(rig.logs()[0].contains("policy file"));
    }
}

// Whatever a crashed run left applied is removed before anyone can connect:
// here the channel never opens at all, and the cleanup has still happened.
#[test]
fn start_up_cleans_up_before_it_listens() {
    let mut rig = Rig::stopped(policy('A', ""));
    let gateway = GATEWAY.into();
    let physical = rig.fake.capture_physical(gateway).unwrap();
    let subnets = ["10.255.0.0/24".parse().unwrap()];
    let dns = SplitDns {
        resolvers: vec![[10, 255, 0, 53].into()],
        domains: vec!["ece.example.test".to_string()],
    };
    rig.fake.add_gateway_route(gateway, &physical).unwrap();
    rig.fake.add_tunnel_routes("old0", &subnets).unwrap();
    rig.fake.set_split_dns("old0", &dns).unwrap();

    rig.fake
        .set_failure(Op::Listen, Some(Error::PermissionDenied));
    assert!(rig.start().is_err());
    assert_eq!(rig.fake.applied(), Applied::default());
    let cleanup = [Op::RemoveAllRoutes, Op::ClearSplitDns];
    assert_eq!(rig.fake.calls()[4..], cleanup);
}

// Security rule: strangers can hold only so many connections, and fewer
// than the service serves in all, so they cannot use up its threads and
// keep the owner out.
#[test]
fn strangers_cannot_crowd_out_the_owner() {
    let mut rig = Rig::stopped(policy('A', ""));
    rig.timeouts.stranger = Duration::from_secs(120);
    // The OS-level narrowing is switched off: strangers still get through.
    rig.fake
        .set_failure(Op::RestrictTo, Some(Error::Unsupported));
    rig.start().unwrap();
    let mut alice = rig.owner();
    // The owner was a stranger when she connected, and holds one place.
    let held: Vec<_> = (1..MAX_STRANGERS).map(|_| rig.peer("mallory")).collect();
    let refused = rig.raw("mallory").unwrap();
    assert_eq!(refused.read_line(), Ok(None), "one too many is closed");

    let mut more: Vec<_> = (MAX_STRANGERS..MAX_CONNECTIONS)
        .map(|_| rig.peer("alice"))
        .collect();
    assert_eq!(more[0].ask(RequestBody::Status), DISCONNECTED);
    let full = rig.raw("alice").unwrap();
    assert_eq!(full.read_line(), Ok(None), "the total is limited too");

    // A place is given back when its connection ends.
    drop((held, more.pop()));
    assert_eq!(alice.ask(RequestBody::Status), DISCONNECTED);
    let again = (0..100).find_map(|_| {
        std::thread::sleep(Duration::from_millis(20));
        let conn = rig.raw("alice").unwrap();
        conn.write_line("{}").unwrap();
        conn.read_line().unwrap()
    });
    assert!(again.is_some(), "the freed place is never given out again");
}

// Connecting is not built yet. The service says so; it does not pretend.
#[test]
fn connect_and_disconnect_say_they_are_not_available_yet() {
    let rig = rig();
    let mut alice = rig.owner();
    assert_eq!(alice.ask(good()), Err(ErrorCode::Internal));
    assert_eq!(alice.ask(RequestBody::Disconnect), Err(ErrorCode::Internal));
    assert!(alice.lines.iter().all(|line| !line.contains(COOKIE)));
    assert!(alice.lines[2].contains("not available in this version yet"));
    assert_eq!(alice.ask(RequestBody::Status), DISCONNECTED);
}
