//! The engine contract, exercised from outside the crate through the fake.
//! Tests marked "Security rule" must fail if the rule they name is removed.

use std::net::Ipv4Addr;
use std::sync::mpsc::{Receiver, channel};
use std::sync::{Arc, Mutex};

use ubc_vpn_core::login::{LoginErrorCode, PromptKind};
use ubc_vpn_core::policy::{Pin, Policy, PolicyError};
use ubc_vpn_core::protocol::ErrorCode;
use ubc_vpn_core::redact::Secret;
use ubc_vpn_engine::fake::{FakeEngine, Script};
use ubc_vpn_engine::{
    Cancel, Gateway, LogLevel, LogSink, LoginEngine, LoginError, Prompt, Prompts, Session, Tunnel,
    TunnelEngine, TunnelError, TunnelEvent,
};

const PASSWORD: &str = "correct-password";

fn pin(c: char) -> Pin {
    Pin::try_from(format!("pin-sha256:{}=", c.to_string().repeat(43))).unwrap()
}

fn gateway(pins: &[Pin]) -> Gateway {
    Gateway::from_policy(&Policy {
        gateway: "vpn.example.test".to_string(),
        pins: pins.to_vec(),
        allowed_routes: None,
    })
    .unwrap()
}

/// Logs in with the given password, counting the questions the user sees.
fn login(
    engine: &FakeEngine,
    pins: &[Pin],
    password: &str,
) -> (Result<Session, LoginError>, usize) {
    let mut asked = 0;
    let mut ask = |p: &Prompt| {
        asked += 1;
        Some(Secret::new(match p.kind {
            PromptKind::Username => "alice",
            PromptKind::Password => password,
            _ => "123456",
        }))
    };
    let result = engine.login(
        &gateway(pins),
        &mut Prompts::new(&mut ask),
        &Cancel::new(),
        &LogSink::none(),
    );
    (result, asked)
}

fn open(
    engine: &FakeEngine,
    pins: &[Pin],
    session: &Session,
) -> (Result<Box<dyn Tunnel>, TunnelError>, Receiver<TunnelEvent>) {
    let (tx, rx) = channel();
    let result = engine.open(&gateway(pins), session, tx, LogSink::none());
    (result, rx)
}

fn drain(events: &Receiver<TunnelEvent>) -> Vec<TunnelEvent> {
    events.try_iter().collect()
}

/// A sink that keeps what it is given.
type Lines = Arc<Mutex<Vec<(LogLevel, String)>>>;
fn capture(max: LogLevel) -> (LogSink, Lines) {
    let lines = Lines::default();
    let kept = Arc::clone(&lines);
    let sink = LogSink::new(max, move |level, line| {
        kept.lock().unwrap().push((level, line.to_string()));
    });
    (sink, lines)
}

#[test]
fn login_returns_the_cookie_and_where_it_is_valid() {
    let engine = FakeEngine::new(Script::new(pin('A')));
    let (result, asked) = login(&engine, &[pin('B'), pin('A')], PASSWORD);
    let session = result.unwrap();
    assert_eq!(session.cookie.expose(), "fake-cookie-0123456789");
    assert_eq!(session.gateway_addr, Ipv4Addr::new(192, 0, 2, 1));
    assert_eq!(session.pin, pin('A'));
    assert_eq!(asked, 2);
    let kinds: Vec<_> = engine.answers().iter().map(|(k, _)| *k).collect();
    assert_eq!(kinds, [PromptKind::Username, PromptKind::Password]);
}

// Security rule: no blind retries. The gateway asks for the password again;
// the user must not be asked again and nothing may be sent a second time.
#[test]
fn a_wrong_password_is_sent_once_and_stops_the_login() {
    let engine = FakeEngine::new(Script::new(pin('A')));
    let (result, asked) = login(&engine, &[pin('A')], "wrong-password");
    assert_eq!(result, Err(LoginError::WrongPassword));
    assert_eq!(asked, 2, "one username and one password question");
    let answers = engine.answers();
    let passwords = answers.iter().filter(|(k, _)| *k == PromptKind::Password);
    assert_eq!(passwords.count(), 1, "the password is sent exactly once");
    assert_eq!(
        LoginErrorCode::from(LoginError::WrongPassword),
        LoginErrorCode::WrongPassword
    );
}

// Security rule: `Prompts` itself refuses a repeated username or password,
// whatever the engine does, without reaching the caller.
#[test]
fn prompts_never_ask_twice_for_a_username_or_password() {
    for kind in [PromptKind::Username, PromptKind::Password] {
        let mut calls = 0;
        let mut ask = |_: &Prompt| {
            calls += 1;
            Some(Secret::new("x"))
        };
        let mut prompts = Prompts::new(&mut ask);
        assert!(prompts.ask(kind, "first").is_ok());
        assert_eq!(
            prompts.ask(kind, "again").unwrap_err(),
            LoginError::WrongPassword
        );
        assert_eq!(calls, 1);
    }
}

#[test]
fn a_wrong_code_may_be_typed_again_but_only_once() {
    let mut script = Script::new(pin('A'));
    let code = Prompt {
        kind: PromptKind::Code,
        label: "Code".to_string(),
    };
    script.form.push((code, "654321".to_string()));
    let engine = FakeEngine::new(script);
    let (result, asked) = login(&engine, &[pin('A')], PASSWORD);
    assert_eq!(result, Err(LoginError::WrongPassword));
    assert_eq!(asked, 4, "username, password, and the code twice");
}

// Security rule: a gateway whose key matches no pin gets no session and is
// sent nothing, and the failure is reported as a pin mismatch.
#[test]
fn login_refuses_a_gateway_that_matches_no_pin() {
    let engine = FakeEngine::new(Script::new(pin('X')));
    let (result, asked) = login(&engine, &[pin('A'), pin('B')], PASSWORD);
    assert_eq!(result, Err(LoginError::PinMismatch));
    assert_eq!(asked, 0, "nothing may be asked for an unpinned gateway");
    assert!(engine.answers().is_empty());
    assert_eq!(
        LoginErrorCode::from(LoginError::PinMismatch),
        LoginErrorCode::PinMismatch
    );
}

// Security rule: an engine cannot be called without pins.
#[test]
fn a_gateway_cannot_exist_without_pins() {
    let policy = Policy {
        gateway: "vpn.example.test".to_string(),
        pins: vec![],
        allowed_routes: None,
    };
    assert_eq!(Gateway::from_policy(&policy), Err(PolicyError::NoPins));
}

#[test]
fn login_reports_an_unreachable_gateway() {
    let mut script = Script::new(pin('A'));
    script.reachable = false;
    let (result, asked) = login(&FakeEngine::new(script), &[pin('A')], PASSWORD);
    assert_eq!(result, Err(LoginError::GatewayUnreachable));
    assert_eq!(asked, 0);
}

#[test]
fn login_can_be_cancelled_from_a_prompt_or_from_outside() {
    let engine = FakeEngine::new(Script::new(pin('A')));
    let gateway = gateway(&[pin('A')]);
    let mut refuse = |_: &Prompt| None;
    let mut prompts = Prompts::new(&mut refuse);
    let result = engine.login(&gateway, &mut prompts, &Cancel::new(), &LogSink::none());
    assert_eq!(result, Err(LoginError::Cancelled));

    let cancel = Cancel::new();
    let remote = cancel.clone();
    // Cancelled from elsewhere while the first question is being answered.
    let mut ask = |_: &Prompt| {
        remote.cancel();
        Some(Secret::new("alice"))
    };
    let mut prompts = Prompts::new(&mut ask);
    let result = engine.login(&gateway, &mut prompts, &cancel, &LogSink::none());
    assert_eq!(result, Err(LoginError::Cancelled));
    let answers = engine.answers();
    assert!(answers.iter().all(|(k, _)| *k != PromptKind::Password));
}

#[test]
fn a_tunnel_reports_what_the_gateway_assigned() {
    let mut script = Script::new(pin('A'));
    script.assigned.split_includes = vec!["10.19.0.0/16".parse().unwrap()];
    let engine = FakeEngine::new(script.clone());
    let session = login(&engine, &[pin('A')], PASSWORD).0.unwrap();
    let (tunnel, events) = open(&engine, &[pin('A')], &session);
    assert_eq!(tunnel.unwrap().assigned(), &script.assigned);
    // Dropping the tunnel closed it.
    assert_eq!(drain(&events), [TunnelEvent::Closed]);
    assert!(!engine.tunnel_is_open());
}

// Security rule: the service's own pins decide. A session whose pin the
// service's policy does not list is refused, whatever the client says.
#[test]
fn a_tunnel_refuses_a_pin_the_service_does_not_list() {
    let engine = FakeEngine::new(Script::new(pin('A')));
    let session = login(&engine, &[pin('A')], PASSWORD).0.unwrap();
    let (result, _events) = open(&engine, &[pin('B')], &session);
    assert_eq!(result.err(), Some(TunnelError::PinMismatch));
    assert!(!engine.tunnel_is_open());

    // A client that names a listed pin the gateway does not actually hold.
    let lying = Session {
        pin: pin('B'),
        ..session
    };
    let (result, _events) = open(&engine, &[pin('A'), pin('B')], &lying);
    assert_eq!(result.err(), Some(TunnelError::PinMismatch));
    assert_eq!(
        ErrorCode::from(TunnelError::PinMismatch),
        ErrorCode::PinMismatch
    );
}

// Security rule: a refused or expired session is "login needed", and that is
// never confused with a network failure.
#[test]
fn login_needed_is_distinct_from_a_network_failure() {
    let engine = FakeEngine::new(Script::new(pin('A')));
    let pins = [pin('A')];
    let good = login(&engine, &pins, PASSWORD).0.unwrap();

    let stale = Session {
        cookie: Secret::new("stale-cookie"),
        ..good.clone()
    };
    let refused = open(&engine, &pins, &stale).0.err();
    assert_eq!(refused, Some(TunnelError::LoginNeeded));
    let elsewhere = Session {
        gateway_addr: Ipv4Addr::new(192, 0, 2, 99),
        ..good.clone()
    };
    let unreachable = open(&engine, &pins, &elsewhere).0.err();
    assert_eq!(unreachable, Some(TunnelError::GatewayUnreachable));
    assert_eq!(
        ErrorCode::from(TunnelError::LoginNeeded),
        ErrorCode::LoginNeeded
    );
    assert_eq!(
        ErrorCode::from(TunnelError::GatewayUnreachable),
        ErrorCode::EngineFailed
    );

    for ending in [TunnelEvent::LoginNeeded, TunnelEvent::ConnectionLost] {
        let (tunnel, events) = open(&engine, &pins, &good);
        let tunnel = tunnel.unwrap();
        engine.end_tunnel(ending);
        // Nothing follows the ending, not even a close.
        tunnel.close();
        drop(tunnel);
        assert_eq!(drain(&events), [ending]);
    }
}

// Security rule: close is idempotent and safe from another thread.
#[test]
fn close_is_idempotent_and_works_from_another_thread() {
    let engine = FakeEngine::new(Script::new(pin('A')));
    let session = login(&engine, &[pin('A')], PASSWORD).0.unwrap();
    let (tunnel, events) = open(&engine, &[pin('A')], &session);
    let tunnel: Arc<dyn Tunnel> = Arc::from(tunnel.unwrap());
    assert!(engine.tunnel_is_open());
    let closers: Vec<_> = (0..4)
        .map(|_| {
            let tunnel = Arc::clone(&tunnel);
            std::thread::spawn(move || tunnel.close())
        })
        .collect();
    closers.into_iter().for_each(|t| t.join().unwrap());
    tunnel.close();
    drop(tunnel);
    assert_eq!(drain(&events), [TunnelEvent::Closed]);
    assert!(!engine.tunnel_is_open());
}

// Security rule: log lines are redacted and limited to the caller's level.
// The fake logs the cookie at debug level, as libopenconnect does.
#[test]
fn log_lines_are_redacted_and_level_limited() {
    let engine = FakeEngine::new(Script::new(pin('A')));
    let gateway = gateway(&[pin('A')]);
    let run = |max| {
        let (sink, lines) = capture(max);
        let mut ask = |p: &Prompt| {
            let password = p.kind == PromptKind::Password;
            Some(Secret::new(if password { PASSWORD } else { "alice" }))
        };
        let mut prompts = Prompts::new(&mut ask);
        let session = engine.login(&gateway, &mut prompts, &Cancel::new(), &sink);
        let (tx, _rx) = channel();
        let tunnel = engine.open(&gateway, &session.unwrap(), tx, sink);
        assert!(tunnel.is_ok());
        lines.lock().unwrap().clone()
    };

    let info = run(LogLevel::Info);
    assert!(!info.is_empty());
    assert!(info.iter().all(|(level, _)| *level <= LogLevel::Info));

    let debug = run(LogLevel::Debug);
    for (_, line) in &debug {
        assert!(!line.contains("fake-cookie"), "{line:?} leaks the cookie");
    }
    // Debug output is delivered in debug builds only.
    let saw_debug = debug.iter().any(|(level, _)| *level == LogLevel::Debug);
    assert_eq!(saw_debug, cfg!(debug_assertions));

    // Every line of a multi-line message is redacted on its own.
    let (sink, lines) = capture(LogLevel::Error);
    sink.log(LogLevel::Error, "request failed\nCookie: webvpn=LEAK\n");
    sink.log(LogLevel::Info, "dropped");
    let lines = lines.lock().unwrap();
    assert_eq!(lines.len(), 2);
    assert!(lines.iter().all(|(_, line)| !line.contains("LEAK")));
}

// Security rule: no error, event or debug text carries a cookie or an answer.
#[test]
fn errors_events_and_debug_output_hold_no_secret() {
    let engine = FakeEngine::new(Script::new(pin('A')));
    let session = login(&engine, &[pin('A')], PASSWORD).0.unwrap();
    let mut text = format!("{session:?} {:?}", engine.answers());
    for e in [
        LoginError::WrongPassword,
        LoginError::PinMismatch,
        LoginError::Cancelled,
        LoginError::GatewayUnreachable,
        LoginError::Failed,
    ] {
        text += &format!("{e} {e:?}");
    }
    for e in [
        TunnelError::PinMismatch,
        TunnelError::LoginNeeded,
        TunnelError::GatewayUnreachable,
        TunnelError::Failed,
    ] {
        text += &format!("{e} {e:?}");
    }
    let (tunnel, events) = open(&engine, &[pin('A')], &session);
    drop(tunnel);
    text += &format!("{:?}", drain(&events));
    for secret in [PASSWORD, "alice", session.cookie.expose()] {
        assert!(!text.contains(secret), "found {secret:?} in {text}");
    }
}
