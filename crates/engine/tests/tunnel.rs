//! Opening tunnels with the real engine against the stand-in gateway.
//!
//! Needs `--features libopenconnect,fake` and `UBC_VPN_NATIVE_DIR`. The
//! tests that need the gateway are skipped without its tools, and say so
//! (see `gateway/mod.rs`). All cookies are made up.
//!
//! The tests that create a tunnel device run only where
//! `UBC_VPN_TEST_DEVICE` is set: in the engine workflow, on a Windows runner,
//! as administrator, with `wintun.dll` beside the test program. Each removes
//! its device on every path, and the workflow checks that none is left.

#![cfg(all(feature = "libopenconnect", feature = "fake"))]

#[path = "gateway/mod.rs"]
mod gateway;

use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};
use std::path::Path;
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::Duration;

use gateway::Gateway as StandIn;
use ubc_vpn_core::policy::{Pin, Policy};
use ubc_vpn_core::redact::{REDACTED, Secret};
use ubc_vpn_engine::ffi::{Callbacks, Handle, Library};
use ubc_vpn_engine::{
    Cancel, Gateway, LogLevel, LogSink, OpenConnect, Role, Session, Tunnel, TunnelEngine,
    TunnelError, TunnelEvent, prepare_environment,
};

const HOST: &str = "vpn.example.test";
/// The stand-in gateway's session cookie.
const COOKIE: &str = "webvpn=FAKE-GATEWAY-COOKIE-0123456789abcdef";
/// A pin no test certificate has.
const ANOTHER_PIN: &str = "pin-sha256:fTzrkd+T2QOdSW5oSF7vp4M6JCp1hHMbYY2Q+IX4x5o=";

/// The engine and the raw library, loaded once for the process. The guard
/// keeps the tests from running side by side: there is one tunnel handle in
/// a process at a time.
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

/// The policy's gateway with `pin`, reached at `port` on this machine.
fn gateway(port: u16, pin: &str) -> Gateway {
    let policy = Policy {
        gateway: HOST.to_string(),
        pins: vec![Pin::try_from(pin.to_string()).expect("a full pin")],
        allowed_routes: None,
    };
    let endpoint = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
    Gateway::for_test(&policy, endpoint).expect("a valid policy and a local endpoint")
}

fn session(addr: Ipv4Addr) -> Session {
    Session {
        cookie: Secret::new(COOKIE),
        gateway_addr: addr,
    }
}

/// What one opening returned, the events channel and the log lines.
struct Opened {
    result: Result<Box<dyn Tunnel>, TunnelError>,
    events: Receiver<TunnelEvent>,
    lines: Arc<Mutex<Vec<String>>>,
    logs: LogSink,
}

fn open(engine: &OpenConnect, gateway: &Gateway, session: &Session, cancel: &Cancel) -> Opened {
    let lines = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&lines);
    let logs = LogSink::new(LogLevel::Debug, move |_, line: &str| {
        seen.lock().unwrap().push(line.to_string());
    });
    let (sender, events) = mpsc::channel();
    let result = engine.open(gateway, session, cancel, sender, logs.clone());
    Opened {
        result,
        events,
        lines,
        logs,
    }
}

/// The error of an opening that must fail.
fn failed(opened: &Opened) -> TunnelError {
    match &opened.result {
        Ok(_) => panic!("the tunnel opened"),
        Err(error) => *error,
    }
}

/// How many tunnel requests reached the gateway, and how many of those
/// carried the cookie.
fn connects(stand_in: &StandIn) -> (usize, usize) {
    let requests = stand_in.requests();
    let connects: Vec<&String> = requests
        .iter()
        .filter(|request| request.contains(r#""method": "CONNECT""#))
        .collect();
    let with_cookie = connects
        .iter()
        .filter(|request| request.contains(r#""body": "cookie""#))
        .count();
    (connects.len(), with_cookie)
}

// Security rule: the session's address is checked before anything else. A
// gateway with a test endpoint accepts that one address only; nothing is
// contacted for any other.
#[test]
fn an_address_other_than_the_endpoints_contacts_nothing() {
    let (engine, library, _guard) = engine();
    let Some(stand_in) = StandIn::start("accept") else {
        return;
    };
    let gateway = gateway(stand_in.port, &pin_of(library, &stand_in));
    for addr in [Ipv4Addr::new(127, 0, 0, 2), Ipv4Addr::new(192, 0, 2, 1)] {
        let opened = open(engine, &gateway, &session(addr), &Cancel::new());
        assert_eq!(failed(&opened), TunnelError::BadAddress, "{addr}");
    }
    assert_eq!(stand_in.requests(), Vec::<String>::new());
}

// Security rule: the cookie goes only to a gateway whose key matches a pin.
// Here none does, so the gateway receives nothing at all.
#[test]
fn a_wrong_pin_sends_nothing() {
    let (engine, _, _guard) = engine();
    let Some(stand_in) = StandIn::start("accept") else {
        return;
    };
    let gateway = gateway(stand_in.port, ANOTHER_PIN);
    let opened = open(
        engine,
        &gateway,
        &session(Ipv4Addr::LOCALHOST),
        &Cancel::new(),
    );
    assert_eq!(failed(&opened), TunnelError::PinMismatch);
    assert_eq!(stand_in.requests(), Vec::<String>::new());
    assert!(opened.events.try_recv().is_err());
    println!("RAN: tunnel refuses a wrong pin");
}

// Security rule: system trust is off on the tunnel's handle too. A
// certificate the machine's own store trusts still needs the pin, and the
// cookie is not sent. Only the CI workflow makes such a certificate (see
// `tests/handle.rs`).
#[test]
fn a_certificate_the_system_trusts_still_needs_the_pin() {
    let (engine, _, _guard) = engine();
    let Some(stand_in) = StandIn::start_trusted("accept") else {
        return;
    };
    let gateway = gateway(stand_in.port, ANOTHER_PIN);
    let opened = open(
        engine,
        &gateway,
        &session(Ipv4Addr::LOCALHOST),
        &Cancel::new(),
    );
    assert_eq!(failed(&opened), TunnelError::PinMismatch);
    assert_eq!(stand_in.requests(), Vec::<String>::new());
    println!("RAN: tunnel refuses a trusted certificate");
}

// A gateway that refuses the cookie means the user must log in again. The
// engine does not try anything else.
#[test]
fn a_refused_cookie_is_login_needed() {
    let (engine, library, _guard) = engine();
    let Some(stand_in) = StandIn::start("ended") else {
        return;
    };
    let gateway = gateway(stand_in.port, &pin_of(library, &stand_in));
    let opened = open(
        engine,
        &gateway,
        &session(Ipv4Addr::LOCALHOST),
        &Cancel::new(),
    );
    assert_eq!(failed(&opened), TunnelError::LoginNeeded);
    assert_eq!(connects(&stand_in), (1, 1));
    assert!(opened.events.try_recv().is_err());
}

#[test]
fn nothing_listening_is_unreachable() {
    let (engine, _, _guard) = engine();
    let port = {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("a free port");
        listener.local_addr().expect("a bound port").port()
    };
    let gateway = gateway(port, ANOTHER_PIN);
    let opened = open(
        engine,
        &gateway,
        &session(Ipv4Addr::LOCALHOST),
        &Cancel::new(),
    );
    assert_eq!(failed(&opened), TunnelError::GatewayUnreachable);
}

// A cancel that is already set stops the opening before anything is
// contacted.
#[test]
fn a_tunnel_cancelled_beforehand_contacts_nothing() {
    let (engine, library, _guard) = engine();
    let Some(stand_in) = StandIn::start("accept") else {
        return;
    };
    let gateway = gateway(stand_in.port, &pin_of(library, &stand_in));
    let cancel = Cancel::new();
    cancel.cancel();
    let opened = open(engine, &gateway, &session(Ipv4Addr::LOCALHOST), &cancel);
    assert_eq!(failed(&opened), TunnelError::Cancelled);
    assert_eq!(stand_in.requests(), Vec::<String>::new());
}

// An opening that waits on the gateway stops when another thread cancels
// it. Here the gateway takes the cookie and never answers.
#[test]
fn an_opening_waiting_on_the_gateway_stops_when_cancelled() {
    let (engine, library, _guard) = engine();
    let Some(stand_in) = StandIn::start("hang") else {
        return;
    };
    let gateway = gateway(stand_in.port, &pin_of(library, &stand_in));
    let cancel = Cancel::new();
    let (from_outside, done) = (cancel.clone(), mpsc::channel());
    // On a thread of its own, so that an opening that never stops fails
    // this test and does not hold it.
    std::thread::spawn(move || {
        let opened = open(engine, &gateway, &session(Ipv4Addr::LOCALHOST), &cancel);
        let _ = done.0.send(failed(&opened));
    });
    for _ in 0..200 {
        if connects(&stand_in) == (1, 1) {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(
        connects(&stand_in),
        (1, 1),
        "the tunnel was not yet waiting"
    );
    from_outside.cancel();
    let result = done.1.recv_timeout(Duration::from_secs(60));
    assert_eq!(result, Ok(TunnelError::Cancelled));
}

// Security rule: the cookie is registered with the log sink as soon as the
// engine holds it, whether the tunnel opens or not. Whatever is logged
// through that sink afterwards comes out without it.
#[test]
fn the_cookie_never_reaches_the_log() {
    let (engine, library, _guard) = engine();
    let Some(stand_in) = StandIn::start("ended") else {
        return;
    };
    let gateway = gateway(stand_in.port, &pin_of(library, &stand_in));
    let opened = open(
        engine,
        &gateway,
        &session(Ipv4Addr::LOCALHOST),
        &Cancel::new(),
    );
    assert_eq!(failed(&opened), TunnelError::LoginNeeded);
    opened
        .logs
        .log(LogLevel::Error, &format!("seen {COOKIE} here"));
    let lines = opened.lines.lock().unwrap();
    assert!(lines.iter().all(|line| !line.contains(COOKIE)), "{lines:?}");
    // Taken out by itself, and what stood after it is still there.
    assert!(
        lines.contains(&format!("seen {REDACTED} here")),
        "{lines:?}"
    );
}

// Until the engine opens the device itself on macOS and Linux, a tunnel
// that got that far is refused there, and no device is made. Everything
// before it ran: the cookie went to the gateway.
#[cfg(not(windows))]
#[test]
fn elsewhere_than_windows_the_device_step_refuses() {
    let (engine, library, _guard) = engine();
    let Some(stand_in) = StandIn::start("accept") else {
        return;
    };
    let gateway = gateway(stand_in.port, &pin_of(library, &stand_in));
    let opened = open(
        engine,
        &gateway,
        &session(Ipv4Addr::LOCALHOST),
        &Cancel::new(),
    );
    assert_eq!(failed(&opened), TunnelError::Failed);
    assert_eq!(connects(&stand_in), (1, 1));
    assert!(opened.events.try_recv().is_err());
    println!("RAN: tunnel refuses at the device step");
}

/// Tests that make a device, which run only where the workflow allows it.
#[cfg(windows)]
mod device {
    use super::*;
    use ubc_vpn_engine::CloseMode;

    #[link(name = "iphlpapi")]
    unsafe extern "system" {
        fn ConvertInterfaceAliasToLuid(alias: *const u16, luid: *mut u64) -> u32;
    }

    /// Whether the system has an interface of this name.
    fn exists(name: &str) -> bool {
        let wide: Vec<u16> = name.encode_utf16().chain([0]).collect();
        let mut luid = 0;
        // SAFETY: `wide` is NUL-terminated UTF-16 that outlives the call,
        // and `luid` is valid to write to.
        unsafe { ConvertInterfaceAliasToLuid(wide.as_ptr(), &mut luid) == 0 }
    }

    /// Whether this run may make devices. Never on a developer's machine.
    fn allowed() -> bool {
        let allowed = std::env::var_os("UBC_VPN_TEST_DEVICE").is_some();
        if !allowed {
            println!("SKIPPED: making a tunnel device needs UBC_VPN_TEST_DEVICE");
        }
        allowed
    }

    /// Opens a tunnel against `stand_in`, which must work.
    fn opened(engine: &OpenConnect, library: Library, stand_in: &StandIn) -> Opened {
        let gateway = gateway(stand_in.port, &pin_of(library, stand_in));
        let opened = open(
            engine,
            &gateway,
            &session(Ipv4Addr::LOCALHOST),
            &Cancel::new(),
        );
        if let Err(error) = &opened.result {
            let lines = opened.lines.lock().unwrap();
            panic!("the tunnel did not open: {error:?}\n{}", lines.join("\n"));
        }
        opened
    }

    /// Ends a tunnel in one of the three ways, and checks it was ended once
    /// and its device is gone by the time that returns.
    fn end(opened: Opened, how: Option<CloseMode>) {
        let tunnel = opened.result.expect("an open tunnel");
        let name = tunnel.assigned().interface.clone();
        assert!(exists(&name), "no interface {name:?}");
        assert!(opened.events.try_recv().is_err(), "an event while open");
        match how {
            Some(how) => {
                tunnel.close(how);
                assert!(!exists(&name), "{name:?} is left after {how:?}");
                // Only the first close does anything.
                tunnel.close(CloseMode::LogOff);
                drop(tunnel);
            }
            None => {
                drop(tunnel);
                assert!(!exists(&name), "{name:?} is left after a drop");
            }
        }
        assert_eq!(opened.events.try_recv(), Ok(TunnelEvent::Closed));
        assert!(opened.events.try_recv().is_err(), "more than one event");
    }

    // The whole path: the pin, the cookie, the connection, the checked
    // assignment and a device. Closed with "log off", the device is gone
    // when `close` returns.
    #[test]
    fn a_tunnel_opens_with_a_device_and_closing_removes_it() {
        if !allowed() {
            return;
        }
        let (engine, library, _guard) = engine();
        let Some(stand_in) = StandIn::start("accept") else {
            return;
        };
        let opened = opened(engine, library, &stand_in);
        let assigned = opened.result.as_ref().expect("open").assigned().clone();
        assert_eq!(assigned.address, Ipv4Addr::new(10, 11, 12, 13));
        assert_eq!(assigned.netmask, Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(assigned.gateway_addr, Ipv4Addr::LOCALHOST);
        assert_eq!(assigned.dns.len(), 2);
        assert_eq!(assigned.mtu, 1300);
        assert_eq!(assigned.split_includes.len(), 2);
        assert!(!assigned.interface.is_empty());
        assert_eq!(connects(&stand_in), (1, 1));
        end(opened, Some(CloseMode::LogOff));
        println!("RAN: tunnel makes and removes a device");
    }

    // Keeping the session and dropping the tunnel remove the device too.
    #[test]
    fn keeping_the_session_or_dropping_the_tunnel_removes_the_device() {
        if !allowed() {
            return;
        }
        let (engine, library, _guard) = engine();
        let Some(stand_in) = StandIn::start("accept") else {
            return;
        };
        end(
            opened(engine, library, &stand_in),
            Some(CloseMode::KeepSession),
        );
        end(opened(engine, library, &stand_in), None);
        assert_eq!(connects(&stand_in), (2, 2));
    }

    // Security rule: one tunnel handle in the process at a time. While one
    // tunnel is open another is refused, and contacts nothing; once it is
    // closed the next one opens.
    #[test]
    fn a_second_tunnel_is_refused_while_one_is_open() {
        if !allowed() {
            return;
        }
        let (engine, library, _guard) = engine();
        let Some(stand_in) = StandIn::start("accept") else {
            return;
        };
        let first = opened(engine, library, &stand_in);
        let gateway = gateway(stand_in.port, &pin_of(library, &stand_in));
        let second = open(
            engine,
            &gateway,
            &session(Ipv4Addr::LOCALHOST),
            &Cancel::new(),
        );
        assert_eq!(failed(&second), TunnelError::Failed);
        assert_eq!(connects(&stand_in), (1, 1));
        end(first, Some(CloseMode::LogOff));
        end(opened(engine, library, &stand_in), Some(CloseMode::LogOff));
    }
}
