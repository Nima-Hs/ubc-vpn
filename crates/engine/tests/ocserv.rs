//! The real engine against a real gateway: ocserv, an open-source server for
//! the AnyConnect protocol, started on this machine by
//! `tests/ocserv/start.sh`.
//!
//! Only the engine workflow starts one, on a throwaway Linux runner, and
//! names its folder in `UBC_VPN_TEST_OCSERV_DIR`. Without it these tests are
//! skipped and say so; with `UBC_VPN_TEST_REQUIRE_OCSERV` set they fail
//! instead. The account and its password are made up.
//!
//! What this shows, and what it does not:
//!
//! - A login through [`LoginEngine`], with the pin check, the forms and the
//!   cookie, against a gateway that is not ours.
//! - That cookie, in the tunnel's own calls of the binding, opens a tunnel
//!   connection at the real gateway, and what the gateway assigns passes
//!   every check the tunnel engine makes of it.
//! - [`TunnelEngine::open`] with the session from that login connects, and
//!   the gateway takes the session and assigns an address (the library
//!   says so), then the engine stops at the device step. On macOS and Linux
//!   it makes no device yet, so it returns `Failed` there: no packet goes
//!   through a tunnel here, and nothing shows the main loop, a close or a
//!   log-off against a real gateway.

#![cfg(all(feature = "libopenconnect", feature = "fake"))]

use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use ubc_vpn_core::login::PromptKind;
use ubc_vpn_core::policy::{Pin, Policy};
use ubc_vpn_core::redact::Secret;
use ubc_vpn_engine::ffi::{Callbacks, Handle, Library};
use ubc_vpn_engine::{
    Cancel, Gateway, LogSink, LoginEngine, LoginError, OpenConnect, Prompt, Prompts, Role, Session,
    TunnelEngine, TunnelError, check_assignment, prepare_environment,
};

const HOST: &str = "vpn.example.test";
/// The account `start.sh` made. Made up.
const NAME: &str = "someone";
const PASSWORD: &str = "not-a-real-password";
/// A pin the test key does not have.
const ANOTHER_PIN: &str = "pin-sha256:fTzrkd+T2QOdSW5oSF7vp4M6JCp1hHMbYY2Q+IX4x5o=";

/// The engine and the raw library, loaded once for the process, and a guard
/// that keeps the tests from running side by side.
fn engine() -> (&'static OpenConnect, Library, MutexGuard<'static, ()>) {
    static LOADED: OnceLock<OpenConnect> = OnceLock::new();
    static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());
    let guard = ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let engine = LOADED.get_or_init(|| {
        let prepared = prepare_environment(Role::Client, None).expect("the environment is clean");
        let libs = Path::new(env!("UBC_VPN_NATIVE_LIBS"));
        OpenConnect::load(libs, &prepared).expect("the pinned library loads")
    });
    (engine, engine.library(), guard)
}

/// Where ocserv listens, or `None` to skip.
fn ocserv() -> Option<SocketAddrV4> {
    let Some(dir) = std::env::var_os("UBC_VPN_TEST_OCSERV_DIR") else {
        assert!(
            std::env::var_os("UBC_VPN_TEST_REQUIRE_OCSERV").is_none(),
            "the ocserv tests were required to run, but UBC_VPN_TEST_OCSERV_DIR is not set"
        );
        println!("SKIPPED: no ocserv on this machine");
        return None;
    };
    let port = std::fs::read_to_string(PathBuf::from(dir).join("port")).expect("ocserv's port");
    let port = port.trim().parse().expect("a port number");
    Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
}

/// The pin of ocserv's key, as the library reports it. The handle that reads
/// it refuses the certificate, so nothing is sent.
fn pin_of(library: Library, endpoint: SocketAddrV4) -> String {
    let seen = Arc::new(Mutex::new(String::new()));
    let hashes = Arc::clone(&seen);
    let mut callbacks = Callbacks::refusing(Box::new(|_, _, _| {}));
    callbacks.certificate = Box::new(move |hash| {
        *hashes.lock().unwrap() = hash.to_string();
        false
    });
    callbacks.resolve = Box::new(move |_, _| Some(endpoint));
    let handle = Handle::new(library, callbacks).expect("the library makes a handle");
    assert_eq!(handle.parse_url(c"https://vpn.example.test"), 0);
    assert_ne!(handle.obtain_cookie(), 0);
    let pin = seen.lock().unwrap().clone();
    assert!(pin.starts_with("pin-sha256:"), "{pin:?}");
    pin
}

fn gateway(endpoint: SocketAddrV4, pin: &str) -> Gateway {
    let policy = Policy {
        gateway: HOST.to_string(),
        pins: vec![Pin::try_from(pin.to_string()).expect("a full pin")],
        allowed_routes: None,
        full_tunnel: Default::default(),
    };
    Gateway::for_test(&policy, endpoint).expect("a valid policy and a local endpoint")
}

/// Logs in with `password`, and says what was asked.
fn login(
    engine: &OpenConnect,
    gateway: &Gateway,
    password: &str,
) -> (Result<Session, LoginError>, Vec<PromptKind>) {
    let mut asked = Vec::new();
    let mut ask = |prompt: &Prompt| {
        asked.push(prompt.kind);
        Some(Secret::new(match prompt.kind {
            PromptKind::Username => NAME,
            _ => password,
        }))
    };
    let result = engine.login(
        gateway,
        &mut Prompts::new(&mut ask),
        &Cancel::new(),
        &LogSink::none(),
    );
    (result, asked)
}

// The whole way a real gateway allows here: a login, a tunnel connection
// made with its cookie, an assignment that passes the tunnel engine's
// checks, and the engine itself up to the device step.
#[test]
fn a_real_gateway_takes_the_login_and_the_cookie_for_a_tunnel() {
    let (engine, library, _guard) = engine();
    let Some(endpoint) = ocserv() else {
        return;
    };
    let pin = pin_of(library, endpoint);
    let gateway = gateway(endpoint, &pin);
    let (session, asked) = login(engine, &gateway, PASSWORD);
    let session = session.expect("the login succeeds");
    assert!(asked.contains(&PromptKind::Username) && asked.contains(&PromptKind::Password));
    assert_eq!(session.gateway_addr, Ipv4Addr::LOCALHOST);

    // The tunnel's calls of the binding, as the tunnel engine makes them,
    // on a fresh handle with only the cookie.
    // The library's lines, kept for a failure message. They go through a
    // sink told about the cookie, so the cookie never reaches the output,
    // and only errors and progress are kept.
    let lines = Arc::new(Mutex::new(Vec::new()));
    let kept = Arc::clone(&lines);
    let sink = ubc_vpn_engine::LogSink::new(ubc_vpn_engine::LogLevel::Info, move |_, line| {
        kept.lock().unwrap().push(line.to_string());
    });
    sink.hide(&session.cookie);
    let mut callbacks = Callbacks::refusing(Box::new(move |level, line, state| {
        let level = match level {
            0 => ubc_vpn_engine::LogLevel::Error,
            1 => ubc_vpn_engine::LogLevel::Info,
            _ => return,
        };
        if state == ubc_vpn_engine::ffi::LineState::Whole {
            sink.log(level, &line.to_string_lossy());
        }
    }));
    let judged = pin.clone();
    callbacks.certificate = Box::new(move |hash| hash == judged);
    callbacks.resolve = Box::new(move |_, _| Some(endpoint));
    let handle = Handle::new(library, callbacks).expect("the library makes a handle");
    assert_eq!(handle.parse_url(c"https://vpn.example.test"), 0);
    // Named, as the tunnel engine names it: ocserv's cookie ends in base64
    // padding, which the library would otherwise split inside the value.
    let named = Secret::new(format!("webvpn={}", session.cookie.expose()));
    assert!(handle.set_cookie(&named));
    assert!(handle.disable_dtls());
    let connected = handle.make_cstp_connection();
    let said = || lines.lock().unwrap().join("\n");
    assert_eq!(connected, 0, "the library said:\n{}", said());
    assert!(handle.certificate_accepted());
    let info = handle.ip_info().expect("a connection has an assignment");
    drop(handle);
    let assigned = check_assignment(&info, session.gateway_addr);
    let assigned = assigned.unwrap_or_else(|error| panic!("{error:?}: {info:?}"));
    // What start.sh configured.
    let octets = assigned.address.octets();
    assert_eq!(octets[..3], [10, 12, 0], "{assigned:?}");
    assert_eq!(assigned.netmask, Ipv4Addr::new(255, 255, 255, 0));
    assert_eq!(assigned.dns, [Ipv4Addr::new(10, 12, 0, 1)]);
    let routes: Vec<String> = assigned
        .split_includes
        .iter()
        .map(|r| r.to_string())
        .collect();
    assert_eq!(routes, ["10.13.0.0/16"]);
    println!("ocserv assigned {assigned:?}");

    // The engine itself, with the same session, up to the device step,
    // which it does not take on this system yet. The library says "CSTP
    // connected" only once the gateway has answered the CONNECT with 200 and
    // its assignment has been read; the engine's sink keeps the cookie out
    // of what it says.
    let (events, _received) = mpsc::channel();
    let said = Arc::new(Mutex::new(Vec::new()));
    let kept = Arc::clone(&said);
    let logs = LogSink::new(ubc_vpn_engine::LogLevel::Info, move |_, line| {
        kept.lock().unwrap().push(line.to_string());
    });
    let opened = engine.open(&gateway, &session, &Cancel::new(), events, logs);
    let said = said.lock().unwrap().join("\n");
    match opened {
        Err(error) if cfg!(not(windows)) => assert_eq!(error, TunnelError::Failed, "{said}"),
        Ok(tunnel) => drop(tunnel),
        Err(error) => panic!("{error:?}\n{said}"),
    }
    let lines: Vec<&str> = said.lines().collect();
    let connected = lines.contains(&"Got CONNECT response: HTTP/1.1 200 CONNECTED")
        && lines.iter().any(|line| line.starts_with("CSTP connected."));
    assert!(connected, "the engine's connection was not taken:\n{said}");
    println!("RAN: ocserv takes a login and a tunnel connection");
}

// Security rule: no blind retries, against a real gateway too. A wrong
// password is asked once and is reported as such.
#[test]
fn a_real_gateway_refuses_a_wrong_password() {
    let (engine, library, _guard) = engine();
    let Some(endpoint) = ocserv() else {
        return;
    };
    let gateway = gateway(endpoint, &pin_of(library, endpoint));
    let (result, asked) = login(engine, &gateway, "not-the-password-either");
    assert_eq!(result, Err(LoginError::WrongPassword));
    let passwords = asked.iter().filter(|kind| **kind == PromptKind::Password);
    assert_eq!(passwords.count(), 1, "{asked:?}");
}

// Security rule: a real gateway whose key matches no pin is sent nothing
// and the user is asked nothing.
#[test]
fn a_real_gateway_with_another_key_is_refused() {
    let (engine, _, _guard) = engine();
    let Some(endpoint) = ocserv() else {
        return;
    };
    let (result, asked) = login(engine, &gateway(endpoint, ANOTHER_PIN), PASSWORD);
    assert_eq!(result, Err(LoginError::PinMismatch));
    assert!(asked.is_empty(), "{asked:?}");
}
