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
use std::time::Duration;

use ubc_vpn_core::login::{LoginErrorCode, PromptKind};
use ubc_vpn_core::policy::{Pin, Policy, PolicyError};
use ubc_vpn_core::protocol::ErrorCode;
use ubc_vpn_core::redact::{Secret, redact_line};

use crate::fake::{FakeEngine, Script};
use crate::{
    Cancel, CloseMode, DEBUG_LINES, Gateway, LogLevel, LogSink, LoginEngine, LoginError,
    MIN_HIDDEN_LEN, Prompt, Prompts, Session, Tunnel, TunnelEngine, TunnelError, TunnelEvent,
    check_cookie, check_gateway_addr,
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
        full_tunnel: Default::default(),
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

/// Runs `work` on another thread and fails if it has not finished in ten
/// seconds, so a lost wake-up fails the test run and does not hang it.
fn within_time<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = channel();
    thread::spawn(move || {
        let _ = tx.send(work());
    });
    rx.recv_timeout(Duration::from_secs(10))
        .expect("the call panicked or stayed blocked")
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
        // The username alone asked again, with no password asked, can only
        // be the username refused.
        let refused = match kind {
            PromptKind::Username => LoginError::CheckUsername,
            _ => LoginError::WrongPassword,
        };
        assert_eq!(again.unwrap_err(), refused);
        assert_eq!(calls, 1);
    }
}

// Once a password has been asked, a username asked again is a refusal that
// does not say which answer was wrong.
#[test]
fn a_username_asked_again_after_the_password_is_a_wrong_password() {
    let mut ask = |_: &Prompt| Some(Secret::new("x"));
    let mut prompts = Prompts::new(&mut ask);
    assert!(prompts.ask(&prompt(PromptKind::Username)).is_ok());
    assert!(prompts.ask(&prompt(PromptKind::Password)).is_ok());
    let again = prompts.ask(&prompt(PromptKind::Username));
    assert_eq!(again.unwrap_err(), LoginError::WrongPassword);
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

// Security rule: only a test build can say where the gateway is, and then
// only on this machine. Everything else still comes from the policy.
#[test]
fn a_test_gateway_is_local_and_still_checked_against_the_policy() {
    let good = policy("vpn.example.test", &[pin('a')]);
    assert_eq!(Gateway::from_policy(&good).unwrap().test_endpoint(), None);
    let local = "127.0.0.1:8443".parse().unwrap();
    let gateway = Gateway::for_test(&good, local).unwrap();
    assert_eq!(gateway.test_endpoint(), Some(local));
    assert_eq!(gateway.host(), "vpn.example.test");
    for remote in ["192.0.2.1:443", "0.0.0.0:443", "10.0.0.1:8443"] {
        let remote = remote.parse().unwrap();
        assert_eq!(
            Gateway::for_test(&good, remote),
            Err(PolicyError::BadGateway)
        );
    }
    let no_pins = policy("vpn.example.test", &[]);
    assert_eq!(Gateway::for_test(&no_pins, local), Err(PolicyError::NoPins));
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
    let result = within_time(move || {
        engine.wait_until_blocked();
        cancel.cancel();
        waiting.join().unwrap()
    });
    assert_eq!(result, Err(LoginError::Cancelled));
}

fn counting_hook(runs: &Arc<AtomicUsize>) -> impl Fn() + Send + Sync + 'static {
    let runs = Arc::clone(runs);
    move || {
        runs.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn cancel_hooks_run_once_and_at_once_if_already_cancelled() {
    let runs = Arc::new(AtomicUsize::new(0));
    let cancel = Cancel::new();
    let _armed = cancel.on_cancel(counting_hook(&runs));
    assert_eq!(runs.load(Ordering::SeqCst), 0);
    assert!(!cancel.is_cancelled());
    cancel.clone().cancel();
    cancel.cancel();
    assert!(cancel.is_cancelled());
    assert_eq!(runs.load(Ordering::SeqCst), 1);
    let _late = cancel.on_cancel(counting_hook(&runs));
    assert_eq!(runs.load(Ordering::SeqCst), 2);
}

// Security rule: a hook cannot fire after its guard is dropped, so a cancel
// that arrives after a call has returned touches nothing the call left.
#[test]
fn a_cancel_hook_is_disarmed_when_its_guard_is_dropped() {
    let (dropped, kept) = (Arc::default(), Arc::default());
    let cancel = Cancel::new();
    let guard = cancel.on_cancel(counting_hook(&dropped));
    let _kept = cancel.on_cancel(counting_hook(&kept));
    drop(guard);
    cancel.cancel();
    assert_eq!(dropped.load(Ordering::SeqCst), 0);
    assert_eq!(kept.load(Ordering::SeqCst), 1);

    // The fake keeps its hook only while a call is inside it: cancelling
    // after `open` has returned leaves the open tunnel alone.
    let engine = engine();
    let session = session(&engine);
    let cancel = Cancel::new();
    let (tx, events) = channel();
    let gateway = gateway(&[pin('A')]);
    let tunnel = engine.open(&gateway, &session, &cancel, tx, LogSink::none());
    cancel.cancel();
    assert!(tunnel.is_ok() && engine.tunnel_is_open());
    assert!(drain(&events).is_empty());
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
        [240, 0, 0, 1],
        [255, 255, 255, 255],
    ] {
        let addr = Ipv4Addr::from(bad);
        assert_eq!(
            check_gateway_addr(addr),
            Err(TunnelError::BadAddress),
            "{addr}"
        );
    }
    for good in [[192, 0, 2, 1], [10, 0, 0, 1], [198, 19, 1, 1], [1, 0, 0, 1]] {
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

    // It comes before everything else: with the gateway unreachable, a bad
    // address is still refused as such, so nothing was contacted.
    let engine = self::engine();
    let loopback = Session {
        gateway_addr: Ipv4Addr::LOCALHOST,
        ..self::session(&engine)
    };
    engine.set_reachable(false);
    let (result, _events) = open(&engine, &[pin('X')], &loopback);
    assert_eq!(result.err(), Some(TunnelError::BadAddress));
}

// Security rule: a session's cookie holds only what a cookie can hold. It
// goes into a header the privileged service sends, so a `;`, a line break or
// any other byte RFC 6265 does not allow is refused before anything is
// contacted, and the error says nothing of the cookie.
#[test]
fn a_cookie_no_gateway_could_issue_is_refused() {
    let engine = self::engine();
    for bad in [";", "\r", "\n", " ", "\"", ",", "\\", "é"] {
        let cookie = format!("{COOKIE}{bad}x=1");
        let odd = Session {
            cookie: Secret::new(cookie.clone()),
            ..self::session(&engine)
        };
        assert_eq!(check_cookie(&odd.cookie), Err(TunnelError::BadSession));
        let (result, _events) = open(&engine, &[pin('A')], &odd);
        let error = result.err();
        assert_eq!(error, Some(TunnelError::BadSession), "{bad:?}");
        let said = format!("{error:?} {}", TunnelError::BadSession);
        assert!(!said.contains(&cookie) && !said.contains(COOKIE), "{said}");
    }
    let padded = Secret::new(format!("{COOKIE}=="));
    assert_eq!(check_cookie(&padded), Ok(()));
    assert_eq!(
        ErrorCode::from(TunnelError::BadSession),
        ErrorCode::BadRequest
    );
}

#[test]
fn a_cancel_set_before_open_stops_it_at_once() {
    let engine = engine();
    let session = session(&engine);
    let cancel = Cancel::new();
    cancel.cancel();
    let (tx, events) = channel();
    let gateway = gateway(&[pin('A')]);
    let result = engine.open(&gateway, &session, &cancel, tx, LogSink::none());
    assert_eq!(result.err(), Some(TunnelError::Cancelled));
    assert!(!engine.tunnel_is_open());
    assert!(drain(&events).is_empty());
    assert_eq!(
        ErrorCode::from(TunnelError::Cancelled),
        ErrorCode::EngineFailed
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
        ErrorCode::GatewayUnreachable
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
    let waiter = engine.clone();
    within_time(move || waiter.wait_until_blocked());
    (opening, rx)
}

/// Waits for a held call to return, failing if it stays blocked.
fn finish<T: Send + 'static>(call: thread::JoinHandle<T>) -> T {
    within_time(move || call.join().unwrap())
}

#[test]
fn opening_can_be_cancelled_from_another_thread() {
    let engine = engine();
    let cancel = Cancel::new();
    let (opening, events) = held_open(&engine, &cancel);
    cancel.cancel();
    let result = finish(opening);
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
    let result = finish(opening);
    assert_eq!(result.err(), Some(TunnelError::LoginNeeded));

    let (opening, _events) = held_open(&engine, &Cancel::new());
    engine.set_reachable(false);
    engine.release();
    let result = finish(opening);
    assert_eq!(result.err(), Some(TunnelError::GatewayUnreachable));

    engine.set_reachable(true);
    let (opening, _events) = held_open(&engine, &Cancel::new());
    engine.release();
    assert!(finish(opening).is_ok());
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
        // The service's sink is a different one: it has never seen the cookie.
        let (service_sink, service_lines) = capture(max);
        let (tx, _rx) = channel();
        let session = session.unwrap();
        let tunnel = engine.open(&gateway, &session, &Cancel::new(), tx, service_sink);
        assert!(tunnel.is_ok());
        let mut all = lines.lock().unwrap().clone();
        all.extend(service_lines.lock().unwrap().clone());
        all
    };

    let info = run(LogLevel::Info);
    assert!(!info.is_empty());
    assert!(info.iter().all(|(level, _)| *level <= LogLevel::Info));

    let debug = run(LogLevel::Debug);
    // The fake echoes the cookie and every answer at debug level.
    for (_, line) in &debug {
        for secret in [COOKIE, PASSWORD, USER] {
            assert!(!line.contains(secret), "{line:?} leaks {secret:?}");
        }
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
    // Too short to register: hiding these would shred ordinary lines.
    clone.hide(&Secret::new(""));
    clone.hide(&Secret::new("1"));
    clone.hide(&Secret::new("a".repeat(MIN_HIDDEN_LEN - 1)));
    sink.log(LogLevel::Info, &line);
    sink.log(LogLevel::Info, "plain aaa 192.0.2.1");
    let seen = lines.lock().unwrap().clone();
    assert!(!seen[0].1.contains(COOKIE), "{:?}", seen[0].1);
    assert!(seen[0].1.starts_with("GET /+CSCOE+/"));
    assert_eq!(seen[1].1, "plain aaa 192.0.2.1");

    // A value of exactly the minimum length is hidden.
    let shortest = "b".repeat(MIN_HIDDEN_LEN);
    sink.hide(&Secret::new(shortest.clone()));
    sink.log(LogLevel::Info, &format!("x {shortest} y"));
    assert!(!lines.lock().unwrap()[2].1.contains(&shortest));
}

// Security rule: the text of one `log` call is scrubbed as a whole before it
// is split into lines, so a hidden value that contains a line break is still
// removed.
#[test]
fn a_hidden_value_that_spans_a_line_break_is_scrubbed() {
    let (sink, lines) = capture(LogLevel::Info);
    sink.hide(&Secret::new("first-half\nsecond-half"));
    sink.log(LogLevel::Info, "before first-half\nsecond-half after");
    let text = format!("{:?}", lines.lock().unwrap());
    assert!(!text.contains("first-half") && !text.contains("second-half"));
    assert!(text.contains("before") && text.contains("after"));
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
        TunnelError::BadSession,
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
        for banned in [
            "pub(",
            "unsafe ",
            "extern \"",
            "\nmod ",
            "Engine for ",
            // A `Default` would be a second way to make a guard.
            "Default",
            "fn default",
        ] {
            assert!(!source.contains(banned), "{name} contains {banned:?}");
        }
    }
    // Every public function, so that adding one (a `forget`, say) is a
    // visible, deliberate change to this list.
    let allowed = [
        vec![
            "for_test",
            "test_endpoint",
            "from_policy",
            "host",
            "pins",
            "accepts",
        ],
        vec!["new", "ask", "asked"],
        vec!["new", "none", "hide", "log"],
    ];
    for ((name, source), allowed) in files.iter().zip(allowed) {
        let found: Vec<&str> = source
            .split("pub ")
            .skip(1)
            .map(|rest| {
                rest.trim_start_matches("const ")
                    .trim_start_matches("async ")
            })
            .filter_map(|rest| rest.strip_prefix("fn "))
            .filter_map(|rest| rest.split(['(', '<']).next())
            .collect();
        assert_eq!(found, allowed, "public functions of {name}");
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

// Dev mode runs the login and the tunnel in two processes. The service's
// fake must accept the cookie that the client's fake issues, and go on
// accepting it after a log-off, or dev mode would connect exactly once.
#[test]
fn a_dev_mode_fake_accepts_a_new_login_after_a_log_off() {
    let pins = [pin('A')];
    // Two engines that share nothing, as in two processes.
    let service = FakeEngine::for_dev_mode(Script::new(pin('A')));
    let client = FakeEngine::new(Script::new(pin('A')));

    for _ in 0..3 {
        let fresh = session(&client);
        let (tunnel, events) = open(&service, &pins, &fresh);
        tunnel.unwrap().close(CloseMode::LogOff);
        assert_eq!(drain(&events), [TunnelEvent::Closed]);
    }

    // It is still a gateway: another cookie is refused, and so is the right
    // one once the session has expired.
    let wrong = Session {
        cookie: Secret::new("not-the-dev-cookie"),
        ..session(&client)
    };
    let refused = open(&service, &pins, &wrong).0.err();
    assert_eq!(refused, Some(TunnelError::LoginNeeded));
    service.expire_session();
    let refused = open(&service, &pins, &session(&client)).0.err();
    assert_eq!(refused, Some(TunnelError::LoginNeeded));

    // The ordinary fake is unchanged: a log-off ends the session.
    let ordinary = FakeEngine::new(Script::new(pin('A')));
    let (tunnel, _events) = open(&ordinary, &pins, &session(&client));
    tunnel.unwrap().close(CloseMode::LogOff);
    let refused = open(&ordinary, &pins, &session(&client)).0.err();
    assert_eq!(refused, Some(TunnelError::LoginNeeded));
}
