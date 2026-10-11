//! The engine contract, exercised through the fake.
//!
//! Tests marked "Security rule" must fail if the rule they name is removed.
//! This module is a sibling of `gateway`, `prompts` and `log`, so it can use
//! only what the binding will be able to use.

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, channel};
use std::sync::{Arc, Mutex};
use std::thread;

use ubc_vpn_core::login::{LoginErrorCode, PromptKind};
use ubc_vpn_core::policy::{Pin, Policy, PolicyError};
use ubc_vpn_core::protocol::ErrorCode;
use ubc_vpn_core::redact::{Secret, redact_line};

use crate::fake::{FakeEngine, Script};
use crate::{
    Cancel, CloseMode, DEBUG_LINES, Gateway, LogLevel, LogSink, LoginEngine, LoginError, Prompt,
    Prompts, Session, Tunnel, TunnelEngine, TunnelError, TunnelEvent, check_gateway_addr,
};

const USER: &str = "alice";
const PASSWORD: &str = "correct-horse-battery";
const COOKIE: &str = "Zq7-made-up-0123456789";

fn pin(c: char) -> Pin {
    Pin::try_from(format!("pin-sha256:{}=", c.to_string().repeat(43))).unwrap()
}

fn policy(host: &str, pins: &[Pin]) -> Policy {
    Policy {
        gateway: host.to_string(),
        pins: pins.to_vec(),
        allowed_routes: None,
    }
}

fn gateway(pins: &[Pin]) -> Gateway {
    Gateway::from_policy(&policy("vpn.example.test", pins)).unwrap()
}

fn engine() -> FakeEngine {
    FakeEngine::new(Script::new(pin('A')))
}

fn prompt(kind: PromptKind) -> Prompt {
    Prompt {
        kind,
        label: "Question".to_string(),
        message: None,
    }
}

/// What one login attempt looked like from the caller's side.
struct Attempt {
    result: Result<Session, LoginError>,
    /// Every question that reached the user.
    seen: Vec<Prompt>,
    /// `Prompts::asked(PromptKind::Code)` after the login.
    code_asked: bool,
}

/// Logs in, answering the code prompt with `123456`.
fn login(engine: &FakeEngine, pins: &[Pin], user: &str, password: &str) -> Attempt {
    let mut seen = Vec::new();
    let mut ask = |p: &Prompt| {
        seen.push(p.clone());
        Some(Secret::new(match p.kind {
            PromptKind::Username => user,
            PromptKind::Password => password,
            _ => "123456",
        }))
    };
    let mut prompts = Prompts::new(&mut ask);
    let result = engine.login(
        &gateway(pins),
        &mut prompts,
        &Cancel::new(),
        &LogSink::none(),
    );
    let code_asked = prompts.asked(PromptKind::Code);
    Attempt {
        result,
        seen,
        code_asked,
    }
}

fn session(engine: &FakeEngine) -> Session {
    login(engine, &[pin('A')], USER, PASSWORD).result.unwrap()
}

type Opened = Result<Box<dyn Tunnel>, TunnelError>;

fn open(engine: &FakeEngine, pins: &[Pin], session: &Session) -> (Opened, Receiver<TunnelEvent>) {
    let (tx, rx) = channel();
    let result = engine.open(&gateway(pins), session, &Cancel::new(), tx, LogSink::none());
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

// ---- Login ----

#[test]
fn login_returns_the_cookie_and_where_it_is_valid() {
    let engine = engine();
    let attempt = login(&engine, &[pin('B'), pin('A')], USER, PASSWORD);
    let session = attempt.result.unwrap();
    assert_eq!(session.cookie.expose(), COOKIE);
    assert_eq!(session.gateway_addr, Ipv4Addr::new(192, 0, 2, 1));
    assert_eq!(attempt.seen.len(), 2);
    assert!(attempt.seen.iter().all(|p| p.message.is_none()));
    let kinds: Vec<_> = engine.answers().iter().map(|(k, _)| *k).collect();
    assert_eq!(kinds, [PromptKind::Username, PromptKind::Password]);
}

// Security rule: no blind retries. The gateway shows the form again; the user
// must not be asked again and nothing may be sent a second time.
#[test]
fn a_wrong_password_is_sent_once_and_stops_the_login() {
    for (user, password) in [(USER, "wrong-horse"), ("mallory", PASSWORD)] {
        let engine = engine();
        let attempt = login(&engine, &[pin('A')], user, password);
        assert_eq!(attempt.result, Err(LoginError::WrongPassword));
        assert_eq!(attempt.seen.len(), 2, "one username, one password");
        assert_eq!(engine.answers().len(), 2, "each is sent exactly once");
        assert!(!attempt.code_asked);
    }
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
        assert!(!prompts.asked(kind));
        assert!(prompts.ask(&prompt(kind)).is_ok());
        assert!(prompts.asked(kind));
        let again = prompts.ask(&prompt(kind));
        assert_eq!(again.unwrap_err(), LoginError::WrongPassword);
        assert_eq!(calls, 1);
    }
}

#[test]
fn a_rejected_code_is_a_wrong_password_the_caller_can_tell_apart() {
    let mut script = Script::new(pin('A'));
    let code = (prompt(PromptKind::Code), Secret::new("654321"));
    script.form.push(code.clone());
    let attempt = login(&FakeEngine::new(script), &[pin('A')], USER, PASSWORD);
    assert_eq!(attempt.result, Err(LoginError::WrongPassword));
    assert_eq!(attempt.seen.len(), 3, "the form is not asked twice");
    assert!(attempt.code_asked, "the caller can see a code was involved");

    // A form with nothing but a code is shown again, with the gateway's
    // error, and the user types a new code.
    let mut script = Script::new(pin('A'));
    script.form = vec![code];
    let attempt = login(&FakeEngine::new(script), &[pin('A')], USER, PASSWORD);
    assert_eq!(attempt.result, Err(LoginError::WrongPassword));
    assert_eq!(attempt.seen.len(), 2);
    assert_eq!(attempt.seen[0].message, None);
    assert_eq!(attempt.seen[1].message.as_deref(), Some("Login failed."));
}

// Security rule: a gateway whose key matches no pin gets no session and is
// sent nothing, and the failure is reported as a pin mismatch.
#[test]
fn login_refuses_a_gateway_that_matches_no_pin() {
    let engine = FakeEngine::new(Script::new(pin('X')));
    let attempt = login(&engine, &[pin('A'), pin('B')], USER, PASSWORD);
    assert_eq!(attempt.result, Err(LoginError::PinMismatch));
    assert!(attempt.seen.is_empty(), "nothing may be asked");
    assert!(engine.answers().is_empty());
    assert_eq!(
        LoginErrorCode::from(LoginError::PinMismatch),
        LoginErrorCode::PinMismatch
    );
}

// Security rule: an engine cannot be called without pins or with a host name
// that is not a bare host.
#[test]
fn a_gateway_needs_pins_and_a_valid_host() {
    let no_pins = policy("vpn.example.test", &[]);
    assert_eq!(Gateway::from_policy(&no_pins), Err(PolicyError::NoPins));
    for host in ["", "https://vpn.example.test", "192.0.2.1", "a b"] {
        let bad_host = policy(host, &[pin('A')]);
        assert_eq!(
            Gateway::from_policy(&bad_host),
            Err(PolicyError::BadGateway),
            "{host:?}"
        );
    }
    let good = gateway(&[pin('A')]);
    assert_eq!(good.host(), "vpn.example.test");
    assert_eq!(good.pins(), [pin('A')]);
    assert!(good.accepts(&pin('A')) && !good.accepts(&pin('B')));
}

#[test]
fn login_reports_an_unreachable_gateway() {
    let mut script = Script::new(pin('A'));
    script.reachable = false;
    let engine = FakeEngine::new(script);
    let attempt = login(&engine, &[pin('A')], USER, PASSWORD);
    assert_eq!(attempt.result, Err(LoginError::GatewayUnreachable));
    assert!(attempt.seen.is_empty());
    engine.set_reachable(true);
    assert!(login(&engine, &[pin('A')], USER, PASSWORD).result.is_ok());
}

#[test]
fn login_can_be_cancelled_from_a_prompt_or_from_outside() {
    let engine = engine();
    let gateway = gateway(&[pin('A')]);
    let mut refuse = |_: &Prompt| None;
    let mut prompts = Prompts::new(&mut refuse);
    let result = engine.login(&gateway, &mut prompts, &Cancel::new(), &LogSink::none());
    assert_eq!(result, Err(LoginError::Cancelled));

    // Cancelled from elsewhere while the first question is being answered.
    let cancel = Cancel::new();
    let mut ask = |_: &Prompt| {
        cancel.cancel();
        Some(Secret::new(USER))
    };
    let mut prompts = Prompts::new(&mut ask);
    let result = engine.login(&gateway, &mut prompts, &cancel, &LogSink::none());
    assert_eq!(result, Err(LoginError::Cancelled));
    let answers = engine.answers();
    assert!(answers.iter().all(|(k, _)| *k != PromptKind::Password));
}

// Security rule: a cancelled login never yields a session, even when every
// answer was right and the cancel came during the last question.
#[test]
fn cancelling_inside_the_last_prompt_yields_no_session() {
    let engine = engine();
    let cancel = Cancel::new();
    let mut ask = |p: &Prompt| {
        let last = p.kind == PromptKind::Password;
        if last {
            cancel.cancel();
        }
        Some(Secret::new(if last { PASSWORD } else { USER }))
    };
    let mut prompts = Prompts::new(&mut ask);
    let gateway = gateway(&[pin('A')]);
    let result = engine.login(&gateway, &mut prompts, &cancel, &LogSink::none());
    assert_eq!(result, Err(LoginError::Cancelled));
    assert_eq!(engine.answers().len(), 2);
}

#[test]
fn a_login_waiting_for_mfa_can_be_cancelled_from_another_thread() {
    let engine = engine();
    engine.hold();
    let cancel = Cancel::new();
    let (worker, stop) = (engine.clone(), cancel.clone());
    let waiting = thread::spawn(move || {
        let mut ask = |p: &Prompt| {
            let password = p.kind == PromptKind::Password;
            Some(Secret::new(if password { PASSWORD } else { USER }))
        };
        let mut prompts = Prompts::new(&mut ask);
        worker.login(&gateway(&[pin('A')]), &mut prompts, &stop, &LogSink::none())
    });
    engine.wait_until_blocked();
    cancel.cancel();
    assert_eq!(waiting.join().unwrap(), Err(LoginError::Cancelled));
}

#[test]
fn cancel_hooks_run_once_and_at_once_if_already_cancelled() {
    let runs = Arc::new(AtomicUsize::new(0));
    let hook = |runs: &Arc<AtomicUsize>| {
        let runs = Arc::clone(runs);
        move || {
            runs.fetch_add(1, Ordering::SeqCst);
        }
    };
    let cancel = Cancel::new();
    cancel.on_cancel(hook(&runs));
    assert_eq!(runs.load(Ordering::SeqCst), 0);
    assert!(!cancel.is_cancelled());
    cancel.clone().cancel();
    cancel.cancel();
    assert!(cancel.is_cancelled());
    assert_eq!(runs.load(Ordering::SeqCst), 1);
    cancel.on_cancel(hook(&runs));
    assert_eq!(runs.load(Ordering::SeqCst), 2);
}

// ---- Tunnel ----

#[test]
fn a_tunnel_reports_what_the_gateway_assigned() {
    let mut script = Script::new(pin('A'));
    script.assigned.split_includes = vec!["10.19.0.0/16".parse().unwrap()];
    let engine = FakeEngine::new(script.clone());
    let session = session(&engine);
    let (tunnel, events) = open(&engine, &[pin('A')], &session);
    let tunnel = tunnel.unwrap();
    assert_eq!(tunnel.assigned(), &script.assigned);
    assert_eq!(tunnel.assigned().gateway_addr, session.gateway_addr);
    assert!(drain(&events).is_empty(), "no event while it is up");
    drop(tunnel);
    assert_eq!(drain(&events), [TunnelEvent::Closed]);
    assert!(!engine.tunnel_is_open());
}

// Security rule: the service's own pins decide. A gateway whose key the
// service's policy does not list is refused, whatever the client sent.
#[test]
fn a_tunnel_refuses_a_gateway_the_service_does_not_pin() {
    let engine = engine();
    let session = session(&engine);
    let (result, events) = open(&engine, &[pin('B'), pin('C')], &session);
    assert_eq!(result.err(), Some(TunnelError::PinMismatch));
    assert!(!engine.tunnel_is_open());
    assert!(drain(&events).is_empty(), "a failed open sends no event");
    assert_eq!(
        ErrorCode::from(TunnelError::PinMismatch),
        ErrorCode::PinMismatch
    );
}

// Security rule: the client-supplied gateway address is checked before
// anything connects to it.
#[test]
fn a_tunnel_refuses_an_address_no_gateway_can_have() {
    for bad in [
        [0, 0, 0, 0],
        [0, 1, 2, 3],
        [127, 0, 0, 1],
        [127, 255, 255, 254],
        [169, 254, 1, 1],
        [224, 0, 0, 1],
        [239, 255, 255, 255],
        [255, 255, 255, 255],
    ] {
        let addr = Ipv4Addr::from(bad);
        assert_eq!(
            check_gateway_addr(addr),
            Err(TunnelError::BadAddress),
            "{addr}"
        );
    }
    for good in [
        [192, 0, 2, 1],
        [10, 0, 0, 1],
        [142, 103, 1, 1],
        [1, 0, 0, 1],
    ] {
        assert_eq!(check_gateway_addr(Ipv4Addr::from(good)), Ok(()));
    }

    // The engine applies it, even where the fake gateway "lives" there.
    let mut script = Script::new(pin('A'));
    script.assigned.gateway_addr = Ipv4Addr::LOCALHOST;
    let engine = FakeEngine::new(script);
    let session = session(&engine);
    let (result, _events) = open(&engine, &[pin('A')], &session);
    assert_eq!(result.err(), Some(TunnelError::BadAddress));
    assert_eq!(
        ErrorCode::from(TunnelError::BadAddress),
        ErrorCode::BadRequest
    );
}

// Security rule: a refused or expired session is "login needed", and that is
// never confused with a network failure.
#[test]
fn login_needed_is_distinct_from_a_network_failure() {
    let engine = engine();
    let pins = [pin('A')];
    let good = session(&engine);

    let stale = Session {
        cookie: Secret::new("stale-value"),
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

    // The connection drops: the session is still good, so a reconnect works.
    let (tunnel, events) = open(&engine, &pins, &good);
    engine.drop_connection();
    assert_eq!(drain(&events), [TunnelEvent::ConnectionLost]);
    // Nothing follows the ending, not even a close.
    tunnel.unwrap().close(CloseMode::LogOff);
    assert!(drain(&events).is_empty());

    // The gateway forgets the session: only a new login helps.
    let (tunnel, events) = open(&engine, &pins, &good);
    engine.expire_session();
    assert_eq!(drain(&events), [TunnelEvent::LoginNeeded]);
    drop(tunnel);
    assert!(drain(&events).is_empty());
    let refused = open(&engine, &pins, &good).0.err();
    assert_eq!(refused, Some(TunnelError::LoginNeeded));
    let fresh = session(&engine);
    assert!(open(&engine, &pins, &fresh).0.is_ok());
}

#[test]
fn close_mode_decides_whether_the_session_survives() {
    let engine = engine();
    let pins = [pin('A')];
    let session = session(&engine);

    let (tunnel, events) = open(&engine, &pins, &session);
    tunnel.unwrap().close(CloseMode::KeepSession);
    assert_eq!(drain(&events), [TunnelEvent::Closed]);
    // Dropping also keeps the session.
    drop(open(&engine, &pins, &session).0.unwrap());

    let (tunnel, events) = open(&engine, &pins, &session);
    let tunnel = tunnel.unwrap();
    tunnel.close(CloseMode::LogOff);
    // The first close decided; a later one changes nothing.
    tunnel.close(CloseMode::KeepSession);
    assert_eq!(drain(&events), [TunnelEvent::Closed]);
    let refused = open(&engine, &pins, &session).0.err();
    assert_eq!(refused, Some(TunnelError::LoginNeeded));
}

// Security rule: close is idempotent and safe from another thread.
#[test]
fn close_is_idempotent_and_works_from_another_thread() {
    let engine = engine();
    let session = session(&engine);
    let (tunnel, events) = open(&engine, &[pin('A')], &session);
    let tunnel: Arc<dyn Tunnel> = Arc::from(tunnel.unwrap());
    assert!(engine.tunnel_is_open());
    let closers: Vec<_> = (0..4)
        .map(|_| {
            let tunnel = Arc::clone(&tunnel);
            thread::spawn(move || tunnel.close(CloseMode::KeepSession))
        })
        .collect();
    closers.into_iter().for_each(|t| t.join().unwrap());
    tunnel.close(CloseMode::KeepSession);
    assert_eq!(drain(&events), [TunnelEvent::Closed]);
    assert!(!engine.tunnel_is_open());

    // A tunnel that has ended cannot close the one opened after it.
    let (newer, newer_events) = open(&engine, &[pin('A')], &session);
    tunnel.close(CloseMode::LogOff);
    drop(tunnel);
    assert!(engine.tunnel_is_open());
    assert!(drain(&newer_events).is_empty());
    drop(newer);
}

/// Starts an `open` that the test holds at the gate.
fn held_open(
    engine: &FakeEngine,
    cancel: &Cancel,
) -> (thread::JoinHandle<Opened>, Receiver<TunnelEvent>) {
    let session = session(engine);
    engine.hold();
    let (tx, rx) = channel();
    let (worker, stop) = (engine.clone(), cancel.clone());
    let opening = thread::spawn(move || {
        worker.open(&gateway(&[pin('A')]), &session, &stop, tx, LogSink::none())
    });
    engine.wait_until_blocked();
    (opening, rx)
}

#[test]
fn opening_can_be_cancelled_from_another_thread() {
    let engine = engine();
    let cancel = Cancel::new();
    let (opening, events) = held_open(&engine, &cancel);
    cancel.cancel();
    let result = opening.join().unwrap();
    assert_eq!(result.err(), Some(TunnelError::Cancelled));
    assert!(!engine.tunnel_is_open());
    assert!(drain(&events).is_empty());
}

#[test]
fn a_held_open_sees_the_gateway_as_it_is_when_released() {
    let engine = engine();
    let (opening, _events) = held_open(&engine, &Cancel::new());
    engine.expire_session();
    engine.release();
    let result = opening.join().unwrap();
    assert_eq!(result.err(), Some(TunnelError::LoginNeeded));

    let (opening, _events) = held_open(&engine, &Cancel::new());
    engine.set_reachable(false);
    engine.release();
    let result = opening.join().unwrap();
    assert_eq!(result.err(), Some(TunnelError::GatewayUnreachable));

    engine.set_reachable(true);
    let (opening, _events) = held_open(&engine, &Cancel::new());
    engine.release();
    assert!(opening.join().unwrap().is_ok());
}

// ---- Secrets and logs ----

// The fake's secrets must not contain a word the redactor knows, or the
// tests below would pass by luck.
#[test]
fn the_fakes_secrets_carry_no_redaction_marker() {
    for value in [USER, PASSWORD, COOKIE, "wrong-horse", "stale-value"] {
        assert_eq!(redact_line(value), value);
    }
    let script = Script::new(pin('A'));
    assert_eq!(script.cookie.expose(), COOKIE);
    assert_eq!(script.form[0].1.expose(), USER);
    assert_eq!(script.form[1].1.expose(), PASSWORD);
}

// Security rule: log lines are limited to the caller's level, scrubbed of
// registered secrets and redacted. The fake logs the cookie at debug level,
// as libopenconnect does, with and without a marker word.
#[test]
fn log_lines_are_level_limited_scrubbed_and_redacted() {
    let engine = engine();
    let gateway = gateway(&[pin('A')]);
    let run = |max| {
        let (sink, lines) = capture(max);
        let mut ask = |p: &Prompt| {
            let password = p.kind == PromptKind::Password;
            Some(Secret::new(if password { PASSWORD } else { USER }))
        };
        let mut prompts = Prompts::new(&mut ask);
        let session = engine.login(&gateway, &mut prompts, &Cancel::new(), &sink);
        let (tx, _rx) = channel();
        let tunnel = engine.open(&gateway, &session.unwrap(), &Cancel::new(), tx, sink);
        assert!(tunnel.is_ok());
        lines.lock().unwrap().clone()
    };

    let info = run(LogLevel::Info);
    assert!(!info.is_empty());
    assert!(info.iter().all(|(level, _)| *level <= LogLevel::Info));

    let debug = run(LogLevel::Debug);
    for (_, line) in &debug {
        assert!(!line.contains(COOKIE), "{line:?} leaks the cookie");
    }
    // Debug output exists only where the build allows it, never in release.
    let debug_lines = debug.iter().filter(|(l, _)| *l == LogLevel::Debug);
    assert_eq!(debug_lines.count() > 0, DEBUG_LINES);
    const { assert!(cfg!(debug_assertions) || !DEBUG_LINES) };

    // Every line of a multi-line message is redacted on its own.
    let (sink, lines) = capture(LogLevel::Error);
    sink.log(LogLevel::Error, "request failed\nCookie: webvpn=LEAK\n");
    sink.log(LogLevel::Info, "dropped");
    let lines = lines.lock().unwrap();
    assert_eq!(lines.len(), 2);
    assert!(lines.iter().all(|(_, line)| !line.contains("LEAK")));
}

// Security rule: a registered secret is removed even from a line that has no
// marker word, in every clone of the sink.
#[test]
fn hidden_values_are_scrubbed_from_marker_free_lines() {
    let (sink, lines) = capture(LogLevel::Info);
    let line = format!("GET /+CSCOE+/{COOKIE}/x and {COOKIE}");
    assert_eq!(redact_line(&line), line, "the line has no marker");
    let clone = sink.clone();
    clone.hide(&Secret::new(COOKIE));
    clone.hide(&Secret::new(""));
    sink.log(LogLevel::Info, &line);
    sink.log(LogLevel::Info, "plain");
    let lines = lines.lock().unwrap();
    assert!(!lines[0].1.contains(COOKIE), "{:?}", lines[0].1);
    assert!(lines[0].1.starts_with("GET /+CSCOE+/"));
    assert_eq!(lines[1].1, "plain", "an empty secret hides nothing");
}

// Security rule: errors and events cannot carry a secret. A `Copy + 'static`
// type cannot own or borrow run-time text.
#[test]
fn errors_and_events_cannot_carry_text() {
    fn plain<T: Copy + 'static>() {}
    plain::<LoginError>();
    plain::<TunnelError>();
    plain::<TunnelEvent>();
    plain::<CloseMode>();
}

// Security rule: no error, event or debug text carries a cookie or an answer.
#[test]
fn errors_events_and_debug_output_hold_no_secret() {
    let engine = engine();
    let session = session(&engine);
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
        TunnelError::Cancelled,
        TunnelError::BadAddress,
        TunnelError::Failed,
    ] {
        text += &format!("{e} {e:?}");
    }
    let (tunnel, events) = open(&engine, &[pin('A')], &session);
    drop(tunnel);
    text += &format!("{:?}", drain(&events));
    for secret in [PASSWORD, USER, COOKIE] {
        assert!(!text.contains(secret), "found {secret:?} in {text}");
    }
}

// ---- The shape of the contract ----

#[test]
fn engines_and_tunnels_can_be_shared_across_threads() {
    fn shared<T: Send + Sync + ?Sized>() {}
    shared::<dyn LoginEngine>();
    shared::<dyn TunnelEngine>();
    shared::<dyn Tunnel>();
    shared::<Cancel>();
    shared::<LogSink>();
}

// Security rule: the guard types keep their fields private to their own
// files, and those files hold nothing but the guard. The compile-fail doc
// tests on each type show the fields cannot be reached; this shows nobody
// widened them to the crate or moved an engine in.
#[test]
fn guard_files_hold_only_the_guard_with_private_fields() {
    let files = [
        ("gateway.rs", include_str!("gateway.rs")),
        ("prompts.rs", include_str!("prompts.rs")),
        ("log.rs", include_str!("log.rs")),
    ];
    for (name, source) in files {
        for banned in ["pub(", "unsafe ", "extern \"", "\nmod ", "Engine for "] {
            assert!(!source.contains(banned), "{name} contains {banned:?}");
        }
    }
    let field = |source: &str, field: &str| source.contains(&format!("\n    {field}: "));
    let pub_field = |source: &str, field: &str| source.contains(&format!("pub {field}: "));
    for (source, fields) in [
        (files[0].1, ["host", "pins"].as_slice()),
        (files[1].1, ["ask", "asked"].as_slice()),
        (files[2].1, ["max", "write", "hidden"].as_slice()),
    ] {
        for name in fields {
            assert!(field(source, name), "field {name} not found");
            assert!(!pub_field(source, name), "field {name} is public");
        }
    }
}
