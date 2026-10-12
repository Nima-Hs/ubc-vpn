//! A handle and its callbacks, driven by the real library against the
//! stand-in gateway. This is the binding only: what an engine must do with
//! it, such as checking a pin or asking the user, is not here.
//!
//! Needs `--features libopenconnect,fake` and `UBC_VPN_NATIVE_DIR`. The
//! tests that need the gateway are skipped without it, and say so (see
//! `gateway/mod.rs`). All names, passwords and cookies are made up.

#![cfg(all(feature = "libopenconnect", feature = "fake"))]

#[path = "gateway/mod.rs"]
mod gateway;

use std::ffi::CString;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use gateway::Gateway;
use ubc_vpn_engine::ffi::{
    Callbacks, Field, FieldKind, Fill, Form, FormAnswer, Handle, Judge, Library,
};
use ubc_vpn_engine::{Role, prepare_environment};

const HOST: &str = "vpn.example.test";

/// The library, loaded once for the process. The guard keeps the tests from
/// running side by side: each makes handles on its own thread, one at a time.
fn library() -> (Library, MutexGuard<'static, ()>) {
    static LIBRARY: OnceLock<Library> = OnceLock::new();
    static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());
    let guard = ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let library = LIBRARY.get_or_init(|| {
        let prepared = prepare_environment(Role::Client, None).expect("the environment is clean");
        let libs = Path::new(env!("UBC_VPN_NATIVE_LIBS"));
        Library::load(libs, &prepared).expect("the pinned library loads")
    });
    (*library, guard)
}

/// What the callbacks were called with.
#[derive(Default)]
struct Seen {
    resolved: Vec<(String, u16)>,
    hashes: Vec<String>,
    fields: Vec<Vec<Field>>,
    lines: usize,
}

/// A handle aimed at `https://vpn.example.test:<port>`, whose resolver sends
/// that to this machine while `reachable` is true and refuses otherwise.
fn handle(
    library: Library,
    port: u16,
    reachable: &Arc<AtomicBool>,
    mut judge: Judge,
    mut fill: Fill,
) -> (Handle, Arc<Mutex<Seen>>) {
    let seen = Arc::new(Mutex::new(Seen::default()));
    let (lines, hashes, fields, resolved) =
        (seen.clone(), seen.clone(), seen.clone(), seen.clone());
    let reachable = Arc::clone(reachable);
    let callbacks = Callbacks {
        lines: Box::new(move |_, _, _| lines.lock().unwrap().lines += 1),
        certificate: Box::new(move |hash| {
            hashes.lock().unwrap().hashes.push(hash.to_string());
            judge(hash)
        }),
        form: Box::new(move |form| {
            fields.lock().unwrap().fields.push(form.fields());
            fill(form)
        }),
        resolve: Box::new(move |host, port| {
            resolved
                .lock()
                .unwrap()
                .resolved
                .push((host.to_string(), port));
            let local = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
            reachable.load(Ordering::SeqCst).then_some(local)
        }),
    };
    let handle = Handle::new(library, callbacks).expect("the library makes a handle");
    let url = CString::new(format!("https://{HOST}:{port}")).unwrap();
    assert_eq!(handle.parse_url(&url), 0);
    (handle, seen)
}

fn yes() -> Arc<AtomicBool> {
    Arc::new(AtomicBool::new(true))
}

/// Answers the stand-in gateway's login form.
fn answer(form: &mut Form<'_>) -> FormAnswer {
    let filled = form.answer(0, c"someone") && form.answer(1, c"not-a-real-password");
    if filled {
        FormAnswer::Submit
    } else {
        FormAnswer::Fail
    }
}

// Security rule: every address the library connects to comes from the
// resolve callback, which is given the host and port the library wants. A
// refusal there means nothing is contacted: a gateway is listening on that
// very port, and it is not even shown a certificate to.
#[test]
fn the_resolver_is_asked_and_its_refusal_stops_the_login() {
    let (library, _guard) = library();
    let Some(gateway) = Gateway::start("accept") else {
        return;
    };
    let nowhere = Arc::new(AtomicBool::new(false));
    let (handle, seen) = handle(
        library,
        gateway.port,
        &nowhere,
        Box::new(|_| true),
        Box::new(answer),
    );
    assert_ne!(handle.obtain_cookie(), 0);
    let seen = seen.lock().unwrap();
    assert_eq!(seen.resolved, [(HOST.to_string(), gateway.port)]);
    assert!(seen.hashes.is_empty() && seen.fields.is_empty());
    assert!(!handle.certificate_accepted() && handle.cookie().is_none());
    assert_eq!(gateway.requests(), Vec::<String>::new());
}

// Security rule: the certificate callback is given the key's `pin-sha256:`
// hash, and when it says no, nothing at all is sent to the gateway.
#[test]
fn a_rejected_certificate_means_nothing_is_sent() {
    let (library, _guard) = library();
    let Some(gateway) = Gateway::start("accept") else {
        return;
    };
    let (handle, seen) = handle(
        library,
        gateway.port,
        &yes(),
        Box::new(|_| false),
        Box::new(answer),
    );
    assert_ne!(handle.obtain_cookie(), 0);
    let seen = seen.lock().unwrap();
    assert_eq!(seen.hashes.len(), 1, "{:?}", seen.hashes);
    // The prefix and a 44-character base64 SHA-256.
    assert!(seen.hashes[0].starts_with("pin-sha256:") && seen.hashes[0].len() == 55);
    assert!(seen.fields.is_empty() && !handle.certificate_accepted());
    assert_eq!(gateway.requests(), Vec::<String>::new());
    println!("RAN: handle rejects");
}

// The whole path through the binding: resolve, judge, fill in, cookie. This
// is also the first time the stand-in gateway's replies meet the library.
#[test]
fn an_accepted_certificate_and_a_filled_form_give_a_cookie() {
    let (library, _guard) = library();
    let Some(gateway) = Gateway::start("accept") else {
        return;
    };
    let (handle, seen) = handle(
        library,
        gateway.port,
        &yes(),
        Box::new(|_| true),
        Box::new(answer),
    );
    assert_eq!(handle.obtain_cookie(), 0);
    assert!(handle.certificate_accepted());
    let cookie = handle
        .cookie()
        .expect("a login that succeeded has a cookie");
    assert!(
        cookie.expose().contains("FAKE-GATEWAY-COOKIE-"),
        "an unexpected cookie"
    );
    let seen = seen.lock().unwrap();
    let kinds: Vec<(FieldKind, &str)> = seen.fields[0]
        .iter()
        .map(|field| (field.kind, field.name.as_str()))
        .collect();
    assert_eq!(
        kinds,
        [
            (FieldKind::Text, "username"),
            (FieldKind::Password, "password")
        ]
    );
    assert!(seen.fields[0].iter().all(|field| !field.ignored) && seen.lines > 0);
    let requests = gateway.requests();
    let sent = requests.last().expect("the gateway was sent the answers");
    assert!(
        sent.contains("someone") && sent.contains("not-a-real-password"),
        "{sent}"
    );
    assert!(
        requests
            .iter()
            .all(|request| request.contains(r#""listener": "main""#))
    );
    println!("RAN: handle logs in");
}

// Security rule: the record that the certificate callback accepted is
// cleared when a connection begins, so it never speaks for an earlier one.
#[test]
fn the_record_of_acceptance_is_cleared_before_each_connection() {
    let (library, _guard) = library();
    let Some(gateway) = Gateway::start("accept") else {
        return;
    };
    let reachable = yes();
    let (handle, _seen) = handle(
        library,
        gateway.port,
        &reachable,
        Box::new(|_| true),
        Box::new(answer),
    );
    assert_eq!(handle.obtain_cookie(), 0);
    assert!(handle.certificate_accepted());
    // A second call on the same handle. The library still holds the cookie
    // and reports success without connecting to anything, so no certificate
    // was judged this time, and the record must say so.
    reachable.store(false, Ordering::SeqCst);
    assert_eq!(handle.obtain_cookie(), 0);
    assert!(!handle.certificate_accepted());
}

// Security rule: a panic in a callback is the library's failure value, never
// an unwind into C, and never an acceptance.
#[test]
fn a_panic_in_any_callback_fails_the_login_and_goes_no_further() {
    let (library, _guard) = library();
    let Some(gateway) = Gateway::start("accept") else {
        return;
    };
    let quiet = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let judge = || -> Judge { Box::new(|_| panic!("the judge panics")) };
    let fill = || -> Fill { Box::new(|_| panic!("the form callback panics")) };
    let (first, _) = handle(library, gateway.port, &yes(), judge(), Box::new(answer));
    let rejected = (
        first.obtain_cookie(),
        first.certificate_accepted(),
        gateway.requests().len(),
    );
    let (second, _) = handle(library, gateway.port, &yes(), Box::new(|_| true), fill());
    let unanswered = (second.obtain_cookie(), second.cookie().is_none());
    std::panic::set_hook(quiet);
    assert!(
        rejected.0 != 0 && !rejected.1 && rejected.2 == 0,
        "{rejected:?}"
    );
    assert!(unanswered.0 != 0 && unanswered.1, "{unanswered:?}");
    // Only the request for the form reached the gateway, not an answer.
    assert_eq!(gateway.requests().len(), 1, "{:?}", gateway.requests());
}

#[test]
fn a_form_that_is_cancelled_or_cannot_be_answered_gives_no_cookie() {
    let (library, _guard) = library();
    let Some(gateway) = Gateway::start("accept") else {
        return;
    };
    for answer in [FormAnswer::Cancel, FormAnswer::Fail] {
        let (handle, _) = handle(
            library,
            gateway.port,
            &yes(),
            Box::new(|_| true),
            Box::new(move |_| answer),
        );
        assert_ne!(handle.obtain_cookie(), 0, "{answer:?}");
        assert!(handle.cookie().is_none(), "{answer:?}");
    }
}

// A cancel written to the command pipe before the login starts stops it,
// though everything else would let it through.
#[test]
fn a_cancel_on_the_command_pipe_stops_the_login() {
    let (library, _guard) = library();
    let Some(gateway) = Gateway::start("accept") else {
        return;
    };
    let (handle, _) = handle(
        library,
        gateway.port,
        &yes(),
        Box::new(|_| true),
        Box::new(answer),
    );
    let pipe = handle
        .command_pipe()
        .expect("the library makes a command pipe");
    // SAFETY: `handle` is alive, so the pipe is open. `x` is `OC_CMD_CANCEL`.
    assert!(unsafe { pipe.send(b'x') });
    assert_ne!(handle.obtain_cookie(), 0);
    assert!(handle.cookie().is_none());
}

// The callbacks are freed when the handle is, and not before: the library
// may still call them while it frees the handle.
#[test]
fn dropping_the_handle_frees_the_callbacks() {
    let (library, _guard) = library();
    let (handle, seen) = handle(library, 8443, &yes(), Box::new(|_| true), Box::new(answer));
    assert!(Arc::strong_count(&seen) > 1);
    drop(handle);
    assert_eq!(Arc::strong_count(&seen), 1);
}
