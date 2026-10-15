//! Logging in with the real engine against the stand-in gateway.
//!
//! Needs `--features libopenconnect,fake` and `UBC_VPN_NATIVE_DIR`. The
//! tests are skipped without the gateway's tools, and say so (see
//! `gateway/mod.rs`). All names, passwords, codes and cookies are made up.

#![cfg(all(feature = "libopenconnect", feature = "fake"))]

#[path = "gateway/mod.rs"]
mod gateway;

use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::Duration;

use gateway::Gateway as StandIn;
use ubc_vpn_core::login::{LoginErrorCode, PromptKind};
use ubc_vpn_core::policy::{Pin, Policy};
use ubc_vpn_core::redact::{REDACTED, Secret};
use ubc_vpn_engine::ffi::{Callbacks, FieldKind, FormAnswer, Handle, Library};
use ubc_vpn_engine::{
    Cancel, Gateway, LogLevel, LogSink, LoginEngine, LoginError, OpenConnect, Prompt, Prompts,
    Role, Session, prepare_environment,
};

const HOST: &str = "vpn.example.test";
const NAME: &str = "someone";
const PASSWORD: &str = "not-a-real-password";
const CODE: &str = "000000-not-a-real-code";
/// A pin no test certificate has.
const ANOTHER_PIN: &str = "pin-sha256:fTzrkd+T2QOdSW5oSF7vp4M6JCp1hHMbYY2Q+IX4x5o=";

/// The engine and the raw library, loaded once for the process. The guard
/// keeps the tests from running side by side.
fn engine() -> (&'static OpenConnect, Library, MutexGuard<'static, ()>) {
    static LOADED: OnceLock<OpenConnect> = OnceLock::new();
    static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());
    let guard = ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let engine = LOADED.get_or_init(|| {
        let prepared = prepare_environment(Role::Client, None).expect("the environment is clean");
        // Only in the control child of the key-log test.
        #[cfg(windows)]
        if let Some(file) = std::env::var_os(PUT_BACK) {
            put_key_log_back(&file);
        }
        let libs = Path::new(env!("UBC_VPN_NATIVE_LIBS"));
        OpenConnect::load(libs, &prepared).expect("the pinned library loads")
    });
    // The library too, for reading a stand-in gateway's pin.
    (engine, engine.library(), guard)
}

/// The pin of the stand-in gateway's key, as the library reports it. The
/// handle that reads it refuses the certificate, so nothing is sent.
fn pin_of(library: Library, stand_in: &StandIn) -> String {
    let seen = Arc::new(Mutex::new(String::new()));
    let (hashes, port) = (Arc::clone(&seen), stand_in.port);
    let mut callbacks = Callbacks::refusing(Box::new(|_, _, _| {}));
    callbacks.certificate = Box::new(move |hash| {
        *hashes.lock().unwrap() = hash.to_string();
        false
    });
    callbacks.resolve = Box::new(move |_, _| Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)));
    let handle = Handle::new(library, callbacks).expect("the library makes a handle");
    assert_eq!(handle.parse_url(c"https://vpn.example.test"), 0);
    assert_ne!(handle.obtain_cookie(), 0);
    drop(handle);
    assert_eq!(stand_in.requests(), Vec::<String>::new());
    let pin = seen.lock().unwrap();
    pin.clone()
}

/// The policy's gateway with `pin`, reached at the stand-in on this machine.
fn gateway(stand_in: &StandIn, pin: &str) -> Gateway {
    let policy = Policy {
        gateway: HOST.to_string(),
        pins: vec![Pin::try_from(pin.to_string()).expect("a full pin")],
        allowed_routes: None,
    };
    let endpoint = SocketAddrV4::new(Ipv4Addr::LOCALHOST, stand_in.port);
    Gateway::for_test(&policy, endpoint).expect("a valid policy and a local endpoint")
}

/// What one login was asked and what its log received.
struct Attempt {
    result: Result<Session, LoginError>,
    prompts: Vec<Prompt>,
    lines: Arc<Mutex<Vec<String>>>,
    /// The lines that came as errors, which the command-line client prints.
    errors: Arc<Mutex<Vec<String>>>,
    logs: LogSink,
}

/// Logs in, answering each kind of question with the made-up value for it.
fn attempt(engine: &OpenConnect, gateway: &Gateway) -> Attempt {
    let lines = Arc::new(Mutex::new(Vec::new()));
    let errors = Arc::new(Mutex::new(Vec::new()));
    let (seen, failed) = (Arc::clone(&lines), Arc::clone(&errors));
    let logs = LogSink::new(LogLevel::Debug, move |level, line: &str| {
        seen.lock().unwrap().push(line.to_string());
        if level == LogLevel::Error {
            failed.lock().unwrap().push(line.to_string());
        }
    });
    let mut prompts = Vec::new();
    let mut ask = |prompt: &Prompt| {
        prompts.push(prompt.clone());
        Some(Secret::new(match prompt.kind {
            PromptKind::Username => NAME,
            PromptKind::Password => PASSWORD,
            PromptKind::Code | PromptKind::Text => CODE,
        }))
    };
    let result = engine.login(gateway, &mut Prompts::new(&mut ask), &Cancel::new(), &logs);
    Attempt {
        result,
        prompts,
        lines,
        errors,
        logs,
    }
}

/// The lines of an attempt that came as errors.
fn errors(attempt: &Attempt) -> Vec<String> {
    attempt.errors.lock().unwrap().clone()
}

/// What the library logs when a reply has no body.
const EMPTY_REPLY: &str = "Unexpected empty response body from server";

fn kinds(attempt: &Attempt) -> Vec<PromptKind> {
    attempt.prompts.iter().map(|prompt| prompt.kind).collect()
}

/// How many of the gateway's requests carried `text`.
fn sent(stand_in: &StandIn, text: &str) -> usize {
    let requests = stand_in.requests();
    requests.iter().filter(|line| line.contains(text)).count()
}

// The main path: the pin matches, the user is asked for a name and a
// password, and the gateway's cookie comes back with the address used.
#[test]
fn a_good_login_returns_the_cookie_and_the_address() {
    let (engine, library, _guard) = engine();
    let Some(stand_in) = StandIn::start("accept") else {
        return;
    };
    let pin = pin_of(library, &stand_in);
    let attempt = attempt(engine, &gateway(&stand_in, &pin));
    let session = attempt.result.clone().expect("the login succeeds");
    assert!(session.cookie.expose().contains("FAKE-GATEWAY-COOKIE-"));
    assert_eq!(session.gateway_addr, Ipv4Addr::LOCALHOST);
    assert_eq!(
        kinds(&attempt),
        [PromptKind::Username, PromptKind::Password]
    );
    let said = Some("Please log in.".to_string());
    assert_eq!(attempt.prompts[0].label, "Username:");
    assert!(attempt.prompts.iter().all(|prompt| prompt.message == said));
    // Each answer went once, to the gateway itself, with the policy's host
    // name and not the address it was reached at.
    assert_eq!((sent(&stand_in, NAME), sent(&stand_in, PASSWORD)), (1, 1));
    let requests = stand_in.requests();
    assert!(
        requests
            .iter()
            .all(|line| line.contains(r#""listener": "main""#))
    );
    assert!(
        !attempt.lines.lock().unwrap().is_empty(),
        "nothing was logged"
    );
    println!("RAN: engine logs in");
}

// Security rule: the cookie, all of it, and every answer are registered with
// the log sink as soon as they are held. So whatever is logged through that
// sink afterwards comes out without them, and nothing logged during the
// login held them either.
#[test]
fn the_cookie_and_the_answers_never_reach_the_log() {
    let (engine, library, _guard) = engine();
    let Some(stand_in) = StandIn::start("code") else {
        return;
    };
    let pin = pin_of(library, &stand_in);
    let attempt = attempt(engine, &gateway(&stand_in, &pin));
    let session = attempt.result.clone().expect("the login succeeds");
    let cookie = session.cookie.expose();
    for secret in [cookie, PASSWORD, NAME, CODE] {
        attempt
            .logs
            .log(LogLevel::Error, &format!("seen {secret} here"));
    }
    let lines = attempt.lines.lock().unwrap();
    for secret in [cookie, PASSWORD, NAME, CODE] {
        let leaked: Vec<&String> = lines.iter().filter(|line| line.contains(secret)).collect();
        assert!(leaked.is_empty(), "a secret was logged: {leaked:?}");
    }
    // Each value was taken out by itself, and what stood after it is still
    // there. Line redaction alone would also hide the made-up cookie and
    // password, which happen to hold words it looks for, but it cuts the
    // line off from that word on. So this is the sink having been told.
    let ours: Vec<&String> = lines.iter().filter(|l| l.starts_with("seen ")).collect();
    let hidden = format!("seen {REDACTED} here");
    assert_eq!(ours, [&hidden, &hidden, &hidden, &hidden]);
}

// Security rule: a gateway whose key matches no pin is sent nothing and the
// user is asked nothing.
#[test]
fn a_wrong_pin_sends_nothing_and_asks_nothing() {
    let (engine, _, _guard) = engine();
    let Some(stand_in) = StandIn::start("accept") else {
        return;
    };
    let attempt = attempt(engine, &gateway(&stand_in, ANOTHER_PIN));
    assert_eq!(attempt.result, Err(LoginError::PinMismatch));
    assert!(attempt.prompts.is_empty());
    assert_eq!(stand_in.requests(), Vec::<String>::new());
    println!("RAN: engine refuses a wrong pin");
}

// Security rule: turning the system's trust off is what keeps the password
// from a gateway an authority vouches for but no pin matches. Through the
// engine this time: nothing is asked and nothing is sent. Only the CI
// workflow makes a certificate the machine trusts (see `tests/handle.rs`).
#[test]
fn a_certificate_the_system_trusts_still_needs_the_pin() {
    let (engine, _, _guard) = engine();
    let Some(stand_in) = StandIn::start_trusted("accept") else {
        return;
    };
    let attempt = attempt(engine, &gateway(&stand_in, ANOTHER_PIN));
    assert_eq!(attempt.result, Err(LoginError::PinMismatch));
    assert!(attempt.prompts.is_empty());
    assert_eq!(stand_in.requests(), Vec::<String>::new());
    println!("RAN: engine refuses a trusted certificate");
}

// Security rule: no blind retries. A form shown again is a rejection: the
// login ends there, and each answer was sent exactly once.
#[test]
fn a_form_shown_again_is_a_wrong_password_and_nothing_is_sent_twice() {
    let (engine, library, _guard) = engine();
    let Some(stand_in) = StandIn::start("reject") else {
        return;
    };
    let pin = pin_of(library, &stand_in);
    let attempt = attempt(engine, &gateway(&stand_in, &pin));
    assert_eq!(attempt.result, Err(LoginError::WrongPassword));
    assert_eq!(
        kinds(&attempt),
        [PromptKind::Username, PromptKind::Password]
    );
    assert_eq!((sent(&stand_in, NAME), sent(&stand_in, PASSWORD)), (1, 1));
    // The gateway's own words on the form it showed again are what tells
    // the user what was wrong: they come as an error, to be printed.
    assert_eq!(errors(&attempt), ["The gateway said: Login failed."]);
}

// A gateway that answers the username and password with an empty reply
// judged no password: seen at UBC's gateway with a username not in the form
// it expects. That is its own error, which points at the username, and the
// library's complaint about the reply is kept as progress, not as an error.
#[test]
fn an_empty_reply_to_the_answers_asks_to_check_the_username() {
    let (engine, library, _guard) = engine();
    let Some(stand_in) = StandIn::start("emptyreply") else {
        return;
    };
    let pin = pin_of(library, &stand_in);
    let attempt = attempt(engine, &gateway(&stand_in, &pin));
    assert_eq!(attempt.result, Err(LoginError::CheckUsername));
    assert_eq!(
        kinds(&attempt),
        [PromptKind::Username, PromptKind::Password]
    );
    assert_eq!((sent(&stand_in, NAME), sent(&stand_in, PASSWORD)), (1, 1));
    let lines = attempt.lines.lock().unwrap().clone();
    assert!(lines.iter().any(|line| line == EMPTY_REPLY), "{lines:?}");
    assert_eq!(errors(&attempt), Vec::<String>::new());
    assert_eq!(
        LoginErrorCode::from(LoginError::CheckUsername),
        LoginErrorCode::CheckUsername
    );
}

// A gateway that asks for the username again before any password has
// refused the username: that points at the username too, and the gateway's
// words come as an error. Nothing is sent twice.
#[test]
fn a_username_asked_again_before_a_password_asks_to_check_it() {
    let (engine, library, _guard) = engine();
    let Some(stand_in) = StandIn::start("usernameagain") else {
        return;
    };
    let pin = pin_of(library, &stand_in);
    let attempt = attempt(engine, &gateway(&stand_in, &pin));
    assert_eq!(attempt.result, Err(LoginError::CheckUsername));
    assert_eq!(kinds(&attempt), [PromptKind::Username]);
    assert_eq!(sent(&stand_in, NAME), 1);
    assert_eq!(errors(&attempt), ["The gateway said: Unknown user."]);
}

// An empty reply that does not end the login, here to the library's first
// probe of the gateway, which it then asks again another way, is no error
// at all: the login succeeds and nothing comes as an error to be printed.
// The library's complaint is kept as progress for the log.
#[test]
fn an_empty_reply_the_login_gets_past_is_not_an_error() {
    let (engine, library, _guard) = engine();
    let Some(stand_in) = StandIn::start("emptyprobe") else {
        return;
    };
    let pin = pin_of(library, &stand_in);
    let attempt = attempt(engine, &gateway(&stand_in, &pin));
    assert!(attempt.result.is_ok(), "{:?}", attempt.result);
    let lines = attempt.lines.lock().unwrap().clone();
    assert!(lines.iter().any(|line| line == EMPTY_REPLY), "{lines:?}");
    assert_eq!(errors(&attempt), Vec::<String>::new());
}

// A second form with one password field that is not the password asks for a
// one-time code, with the gateway's words for it.
#[test]
fn a_second_form_asks_for_a_one_time_code() {
    let (engine, library, _guard) = engine();
    let Some(stand_in) = StandIn::start("code") else {
        return;
    };
    let pin = pin_of(library, &stand_in);
    let attempt = attempt(engine, &gateway(&stand_in, &pin));
    assert!(attempt.result.is_ok(), "{:?}", attempt.result);
    let expected = [PromptKind::Username, PromptKind::Password, PromptKind::Code];
    assert_eq!(kinds(&attempt), expected);
    let code = &attempt.prompts[2];
    assert_eq!(code.label, "Code:");
    assert_eq!(code.message.as_deref(), Some("Enter the code."));
    assert_eq!((sent(&stand_in, PASSWORD), sent(&stand_in, CODE)), (1, 1));
}

// A form with a choice of group is not supported: the login fails before
// the user is asked anything, and no answer is sent.
#[test]
fn a_form_with_a_choice_of_group_fails_unasked() {
    let (engine, library, _guard) = engine();
    for scenario in ["group", "fields"] {
        let Some(stand_in) = StandIn::start(scenario) else {
            return;
        };
        let pin = pin_of(library, &stand_in);
        let attempt = attempt(engine, &gateway(&stand_in, &pin));
        assert_eq!(attempt.result, Err(LoginError::Failed), "{scenario}");
        assert!(attempt.prompts.is_empty(), "{scenario}");
        assert_eq!(
            stand_in.requests().len(),
            1,
            "only the request for the form"
        );
    }
}

// Security rule: a login never offers the gateway a single sign-on or an
// external-browser login. The library offers both in every request unless
// the patch has set `no_external_auth`; the stand-in gateway records what
// each request carried.
#[test]
fn a_login_offers_no_single_sign_on() {
    let (engine, library, _guard) = engine();
    let Some(stand_in) = StandIn::start("accept") else {
        return;
    };
    let pin = pin_of(library, &stand_in);
    assert!(attempt(engine, &gateway(&stand_in, &pin)).result.is_ok());
    let requests = stand_in.requests();
    // The first request is the one that says what this client can do.
    assert!(requests[0].contains("capabilities"), "{requests:?}");
    assert_eq!(sent(&stand_in, "single-sign-on"), 0, "{requests:?}");
    println!("RAN: engine offers no single sign-on");
}

// Security rule: no single sign-on and no external browser. A gateway that
// asks for a login in an external browser gets nothing: the login fails at
// once, and the library never listens on its port for the browser (29786)
// and so never waits for one. Our libraries are built without that login,
// and the engine never sets a single sign-on handler.
//
// Only ever run this against such a library: one with the external-browser
// login would start a browser on this machine. So the test first refuses,
// loudly, to run against a library file that has that login in it.
//
// It also shows the single sign-on form is what ended the login, not some
// other step: a handle of its own sees exactly the form the gateway sent.
#[test]
fn a_single_sign_on_form_fails_at_once_and_nothing_listens() {
    let library_file = Path::new(env!("UBC_VPN_NATIVE_LIBS")).join(ubc_vpn_engine::ffi::FILE);
    let bytes = std::fs::read(&library_file).expect("the library file can be read");
    let marker = b"single-sign-on-external-browser";
    assert!(
        !bytes.windows(marker.len()).any(|window| window == marker),
        "{} has the external-browser login; this test would start a browser. \
         Use a library built from main after #119.",
        library_file.display()
    );
    let (engine, library, _guard) = engine();
    let Some(stand_in) = StandIn::start("sso") else {
        return;
    };
    let pin = pin_of(library, &stand_in);
    // The marker: what a handle's form callback is shown, and what the
    // library then makes of the form.
    let seen = Arc::new(Mutex::new(Vec::new()));
    let shown = Arc::clone(&seen);
    let port = stand_in.port;
    let mut callbacks = Callbacks::refusing(Box::new(|_, _, _| {}));
    callbacks.certificate = Box::new(|_| true);
    callbacks.resolve = Box::new(move |_, _| Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)));
    callbacks.form = Box::new(move |form| {
        let fields: Vec<(FieldKind, String)> = form
            .fields()
            .into_iter()
            .map(|field| (field.kind, field.name))
            .collect();
        shown.lock().unwrap().push((form.message(), fields));
        FormAnswer::Fail
    });
    let handle = Handle::new(library, callbacks).expect("the library makes a handle");
    assert_eq!(handle.parse_url(c"https://vpn.example.test"), 0);
    assert_ne!(handle.obtain_cookie(), 0);
    drop(handle);
    let only_sso = vec![(
        Some("Log in with your browser.".to_string()),
        vec![(FieldKind::Other, "sso-token".to_string())],
    )];
    assert_eq!(*seen.lock().unwrap(), only_sso);
    let gateway = gateway(&stand_in, &pin);
    let done = std::sync::mpsc::channel();
    // On a thread of its own, so that a library waiting for a browser fails
    // this test and does not hold it.
    std::thread::spawn(move || {
        let attempt = attempt(engine, &gateway);
        let _ = done.0.send((attempt.result, attempt.prompts.len()));
    });
    let browser_ports = [
        std::net::SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, 29786)),
        std::net::SocketAddr::from((Ipv4Addr::LOCALHOST, 29786)),
    ];
    let mut listened = false;
    let started = std::time::Instant::now();
    let ended = loop {
        for port in &browser_ports {
            listened |=
                std::net::TcpStream::connect_timeout(port, Duration::from_millis(100)).is_ok();
        }
        if let Ok(ended) = done.1.try_recv() {
            break Some(ended);
        }
        if started.elapsed() > Duration::from_secs(20) {
            break None;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(!listened, "something listened on port 29786 for a browser");
    assert_eq!(ended, Some((Err(LoginError::Failed), 0)));
    // Nothing went to the login page the gateway named.
    assert_eq!(sent(&stand_in, r#""listener": "other""#), 0);
    println!("RAN: engine refuses single sign-on");
}

// Security rule: one handle for one attempt. A handle asked for a cookie a
// second time reports success without connecting to anything, so a login
// that reused one would succeed here, where the user gives up.
#[test]
fn every_login_starts_afresh() {
    let (engine, library, _guard) = engine();
    let Some(stand_in) = StandIn::start("accept") else {
        return;
    };
    let pin = pin_of(library, &stand_in);
    let gateway = gateway(&stand_in, &pin);
    assert!(attempt(engine, &gateway).result.is_ok());
    let before = stand_in.requests().len();
    let mut give_up = |_: &Prompt| None;
    let mut prompts = Prompts::new(&mut give_up);
    let second = engine.login(&gateway, &mut prompts, &Cancel::new(), &LogSink::none());
    assert_eq!(second, Err(LoginError::Cancelled));
    // The second login did go to the gateway, for a new form.
    assert_eq!(stand_in.requests().len(), before + 1);
    // And a third, with a pin that no longer matches, is judged again.
    let third = attempt(engine, &self::gateway(&stand_in, ANOTHER_PIN));
    assert_eq!(third.result, Err(LoginError::PinMismatch));
}

// Security rule: a login reaches the gateway's own host and port and nothing
// else. The certificate check sees a key, not who presented it, and here the
// other listener has the same key and would hand out a cookie. A redirect to
// it, or a form whose answers are to go to it, gets nothing at all.
#[test]
fn a_login_never_follows_the_gateway_to_another_address() {
    let (engine, library, _guard) = engine();
    for scenario in ["redirect", "action"] {
        let Some(stand_in) = StandIn::start(scenario) else {
            return;
        };
        let pin = pin_of(library, &stand_in);
        let attempt = attempt(engine, &gateway(&stand_in, &pin));
        assert_eq!(attempt.result, Err(LoginError::Failed), "{scenario}");
        assert_eq!(sent(&stand_in, r#""listener": "other""#), 0, "{scenario}");
        assert_eq!(sent(&stand_in, PASSWORD), 0, "{scenario}");
    }
}

// Security rule: the host and the port are each checked. Each redirect here
// is wrong in one way only: another host name on port 443, or the gateway's
// own name on another port. The resolver alone decides where a name leads,
// so with either check gone this one would lead back to the stand-in, which
// would show its form and take the answers. Nothing may be asked or sent.
#[test]
fn a_redirect_to_another_host_or_another_port_is_refused() {
    let (engine, library, _guard) = engine();
    for scenario in ["otherhost", "otherport"] {
        let Some(stand_in) = StandIn::start(scenario) else {
            return;
        };
        let pin = pin_of(library, &stand_in);
        let attempt = attempt(engine, &gateway(&stand_in, &pin));
        assert_eq!(attempt.result, Err(LoginError::Failed), "{scenario}");
        assert!(attempt.prompts.is_empty(), "{scenario}");
        assert_eq!(stand_in.requests().len(), 1, "{scenario}: only the first");
        assert_eq!(sent(&stand_in, NAME), 0, "{scenario}");
    }
}

// Security rule: a cancelled login never returns a session. Here the user
// cancels while answering the last question, and the gateway then accepts.
// The cancel arrives after the form is filled, so only the check made before
// the session is returned can catch it.
#[test]
fn a_login_cancelled_in_its_last_prompt_returns_no_session() {
    let (engine, library, _guard) = engine();
    let Some(stand_in) = StandIn::start("accept") else {
        return;
    };
    let pin = pin_of(library, &stand_in);
    let cancel = Cancel::new();
    let from_inside = cancel.clone();
    let mut ask = |prompt: &Prompt| {
        if prompt.kind == PromptKind::Password {
            from_inside.cancel();
            return Some(Secret::new(PASSWORD));
        }
        Some(Secret::new(NAME))
    };
    let mut prompts = Prompts::new(&mut ask);
    let gateway = gateway(&stand_in, &pin);
    let result = engine.login(&gateway, &mut prompts, &cancel, &LogSink::none());
    assert_eq!(result, Err(LoginError::Cancelled));
}

// Security rule: a field the library refuses to fill ends the login, and the
// form is not sent with that field left out. A form sent so would count as a
// try against the account with an answer the user never gave. A password
// with a NUL in it is one the binding refuses.
#[test]
fn a_field_that_cannot_be_filled_ends_the_login_unsent() {
    let (engine, library, _guard) = engine();
    let Some(stand_in) = StandIn::start("accept") else {
        return;
    };
    let pin = pin_of(library, &stand_in);
    let mut ask = |prompt: &Prompt| {
        Some(Secret::new(match prompt.kind {
            PromptKind::Password => "not-a-real\0password",
            _ => NAME,
        }))
    };
    let mut prompts = Prompts::new(&mut ask);
    let gateway = gateway(&stand_in, &pin);
    let result = engine.login(&gateway, &mut prompts, &Cancel::new(), &LogSink::none());
    assert_eq!(result, Err(LoginError::Failed));
    assert_eq!(
        stand_in.requests().len(),
        1,
        "only the request for the form"
    );
    assert_eq!(sent(&stand_in, NAME), 0);
}

// A gateway that asks for a code again and again gets three, and then the
// login ends as a wrong password. Each code may be an approval request on
// the user's phone. The user here would keep answering.
#[test]
fn a_login_asks_for_at_most_three_codes() {
    let (engine, library, _guard) = engine();
    let Some(stand_in) = StandIn::start("codeagain") else {
        return;
    };
    let pin = pin_of(library, &stand_in);
    let mut codes = 0;
    let mut ask = |prompt: &Prompt| {
        Some(Secret::new(match prompt.kind {
            PromptKind::Username => NAME,
            PromptKind::Password => PASSWORD,
            _ => {
                codes += 1;
                // Give up in the end, so a login without the bound ends.
                if codes > 10 {
                    return None;
                }
                CODE
            }
        }))
    };
    let mut prompts = Prompts::new(&mut ask);
    let gateway = gateway(&stand_in, &pin);
    let result = engine.login(&gateway, &mut prompts, &Cancel::new(), &LogSink::none());
    assert_eq!(result, Err(LoginError::WrongPassword));
    assert!(prompts.asked(PromptKind::Code));
    drop(prompts);
    assert_eq!(codes, 3);
    assert_eq!(sent(&stand_in, CODE), 3);
}

// Security rule: the engine sets no host-scan wrapper, so a gateway's offer
// of a program to download and run ends the login: nothing is run, and the
// user is asked nothing. The library does fetch the program's stub first,
// if the offer names one, and refuses to run it only afterwards. So a stub
// elsewhere is a fetch the resolver must refuse; this offer points at the
// other listener, which gets nothing. The test below covers a stub on the
// gateway's own host.
#[test]
fn an_offer_of_a_host_scan_program_ends_the_login() {
    let (engine, library, _guard) = engine();
    let Some(stand_in) = StandIn::start("csd") else {
        return;
    };
    let pin = pin_of(library, &stand_in);
    let attempt = attempt(engine, &gateway(&stand_in, &pin));
    assert_eq!(attempt.result, Err(LoginError::Failed));
    assert!(attempt.prompts.is_empty(), "{:?}", kinds(&attempt));
    assert_eq!(sent(&stand_in, r#""listener": "other""#), 0);
    assert_eq!(
        stand_in.requests().len(),
        1,
        "only the request for the form"
    );
}

// A host-scan stub on the gateway's own host is fetched from the pinned
// gateway, and then not run: the login fails, nothing is asked, and no
// answer is sent. The fetch is the library's; there is no switch for it.
// The offer comes on a login address with no path, which crashed unpatched
// libopenconnect 9.21 on macOS and Linux; the pinned builds carry the fix.
#[test]
fn a_host_scan_stub_on_the_gateway_is_fetched_and_not_run() {
    let (engine, library, _guard) = engine();
    let Some(stand_in) = StandIn::start("csdstub") else {
        return;
    };
    let pin = pin_of(library, &stand_in);
    let attempt = attempt(engine, &gateway(&stand_in, &pin));
    assert_eq!(attempt.result, Err(LoginError::Failed));
    assert!(attempt.prompts.is_empty(), "{:?}", kinds(&attempt));
    let requests = stand_in.requests();
    assert_eq!(requests.len(), 2, "{requests:?}");
    assert!(requests[1].contains("/CACHE/stub"), "{requests:?}");
    assert_eq!(sent(&stand_in, NAME), 0);
    assert_eq!(sent(&stand_in, r#""listener": "other""#), 0);
    println!("RAN: engine fetches a host-scan stub and runs nothing");
}

// A login that is waiting on the gateway stops when another thread cancels
// it, and reports that it was cancelled. Here the gateway takes the answers
// and then says nothing for an hour.
#[test]
fn a_login_waiting_on_the_gateway_stops_when_cancelled() {
    let (engine, library, _guard) = engine();
    let Some(stand_in) = StandIn::start("hang") else {
        return;
    };
    let pin = pin_of(library, &stand_in);
    let gateway = gateway(&stand_in, &pin);
    let cancel = Cancel::new();
    let (from_outside, done) = (cancel.clone(), std::sync::mpsc::channel());
    // On a thread of its own, so that a login that never stops fails this
    // test and does not hold it.
    std::thread::spawn(move || {
        let mut ask = |prompt: &Prompt| {
            if prompt.kind == PromptKind::Password {
                // The cancel comes once the answers are with the gateway.
                let cancel = cancel.clone();
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(1500));
                    cancel.cancel();
                });
            }
            Some(Secret::new(PASSWORD))
        };
        let mut prompts = Prompts::new(&mut ask);
        let result = engine.login(&gateway, &mut prompts, &cancel, &LogSink::none());
        let _ = done.0.send(result);
    });
    let result = done.1.recv_timeout(Duration::from_secs(60));
    assert_eq!(result, Ok(Err(LoginError::Cancelled)));
    assert_eq!(
        sent(&stand_in, PASSWORD),
        1,
        "the login was not yet waiting"
    );
    // The login is over and its handle freed. A cancel now reaches nothing.
    from_outside.cancel();
}

/// Set for the child process of the key-log test.
const CHILD: &str = "UBC_VPN_TEST_LOGIN_CHILD";

/// Not a test of its own: the body of that child. It prepares the
/// environment as every program does, logs in once and says how that went.
#[test]
fn child() {
    if std::env::var_os(CHILD).is_none() {
        return;
    }
    let (engine, library, _guard) = engine();
    let stand_in = StandIn::start("accept").expect("the parent had the tools");
    let pin = pin_of(library, &stand_in);
    let attempt = attempt(engine, &gateway(&stand_in, &pin));
    println!("CHILD LOGIN: {}", attempt.result.is_ok());
}

/// Set, with a file name, for the control child of the key-log test. That
/// child puts `SSLKEYLOGFILE` back where the libraries read it, after the
/// environment step and before loading, as a careless program could.
#[cfg(windows)]
const PUT_BACK: &str = "UBC_VPN_TEST_PUT_BACK_KEY_LOG";

/// Sets `SSLKEYLOGFILE` in this program's C runtime, the copy of the
/// environment the libraries read. For the control child only.
#[cfg(windows)]
fn put_key_log_back(file: &std::ffi::OsStr) {
    unsafe extern "C" {
        fn _putenv_s(name: *const std::ffi::c_char, value: *const std::ffi::c_char) -> i32;
    }
    let file = std::ffi::CString::new(file.to_str().expect("a plain path")).unwrap();
    // SAFETY: both are NUL-terminated strings that outlive the call, which
    // copies them. The child runs this one test, before any library code.
    let set = unsafe { _putenv_s(c"SSLKEYLOGFILE".as_ptr(), file.as_ptr()) };
    assert_eq!(set, 0);
}

// Security rule: on Windows the start-up step removes `SSLKEYLOGFILE` where
// the libraries read it, so a TLS key log is never written, whatever the
// program was started with. Watched here on a real login.
//
// The control puts the variable back after the step and before loading, and
// then the key log must appear. Without it, this test would also pass if a
// future GnuTLS stopped reading the variable, and would then show nothing.
#[cfg(windows)]
#[test]
fn a_key_log_named_in_the_environment_is_never_written() {
    // Only to skip, or fail, as every other test here does without the tools.
    if StandIn::start("accept").is_none() {
        return;
    }
    let run = |put_back: bool| {
        let name = format!("ubc-vpn-test-keys-{}-{put_back}", std::process::id());
        let file = std::env::temp_dir().join(name);
        let _ = std::fs::remove_file(&file);
        let mut child = std::process::Command::new(std::env::current_exe().unwrap());
        child
            .args(["child", "--exact", "--nocapture", "--test-threads=1"])
            .env(CHILD, "1")
            .env("SSLKEYLOGFILE", &file);
        if put_back {
            child.env(PUT_BACK, &file);
        }
        let output = child.output().expect("the child starts");
        let written = file.exists();
        let _ = std::fs::remove_file(&file);
        let said = String::from_utf8_lossy(&output.stdout).into_owned();
        assert!(said.contains("CHILD LOGIN: true"), "{said}");
        written
    };
    assert!(
        run(true),
        "the control wrote no key log: the test cannot see one"
    );
    assert!(!run(false), "a TLS key log was written");
    println!("RAN: engine writes no key log");
}

// A cancel that is already set stops the login before anything is contacted.
#[test]
fn a_login_cancelled_beforehand_contacts_nothing() {
    let (engine, library, _guard) = engine();
    let Some(stand_in) = StandIn::start("accept") else {
        return;
    };
    let pin = pin_of(library, &stand_in);
    let cancel = Cancel::new();
    cancel.cancel();
    let mut ask = |_: &Prompt| -> Option<Secret> { panic!("nothing may be asked") };
    let mut prompts = Prompts::new(&mut ask);
    let gateway = gateway(&stand_in, &pin);
    let result = engine.login(&gateway, &mut prompts, &cancel, &LogSink::none());
    assert_eq!(result, Err(LoginError::Cancelled));
    assert_eq!(stand_in.requests(), Vec::<String>::new());
}
