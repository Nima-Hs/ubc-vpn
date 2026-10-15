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
use ubc_vpn_core::redact::Secret;
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
    /// Each form's message, its error, and whether it asks for a group.
    forms: Vec<(Option<String>, Option<String>, bool)>,
    lines: usize,
}

/// A handle aimed at `https://vpn.example.test:<port>`, whose resolver sends
/// that to this machine while `reachable` is true and refuses otherwise.
fn handle(
    library: Library,
    port: u16,
    reachable: &Arc<AtomicBool>,
    mut judge: Judge,
    mut fill: Fill<'static>,
) -> (Handle<'static>, Arc<Mutex<Seen>>) {
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
            let shown = (form.message(), form.error(), form.asks_for_group());
            let mut seen = fields.lock().unwrap();
            seen.fields.push(form.fields());
            seen.forms.push(shown);
            drop(seen);
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
    let (name, password) = (Secret::new("someone"), Secret::new("not-a-real-password"));
    let filled = form.answer(0, &name) && form.answer(1, &password);
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
    let fill = || -> Fill<'_> { Box::new(|_| panic!("the form callback panics")) };
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

// Security rule: an answer with a NUL in it is refused, not cut short at the
// NUL and sent.
#[test]
fn an_answer_with_a_nul_in_it_is_refused() {
    let (library, _guard) = library();
    let Some(gateway) = Gateway::start("accept") else {
        return;
    };
    let taken = Arc::new(Mutex::new(Vec::new()));
    let results = Arc::clone(&taken);
    let fill: Fill<'_> = Box::new(move |form| {
        let cut = form.answer(0, &Secret::new("some\0one"));
        let whole = form.answer(0, &Secret::new("someone"));
        results.lock().unwrap().extend([cut, whole]);
        FormAnswer::Fail
    });
    let (handle, _) = handle(library, gateway.port, &yes(), Box::new(|_| true), fill);
    assert_ne!(handle.obtain_cookie(), 0);
    assert_eq!(*taken.lock().unwrap(), [false, true]);
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
    let pipe = handle.command_pipe();
    // Security rule: one pipe per handle, however often it is asked for. A
    // second would replace the first inside the library, and a cancel sent
    // to the first would be lost.
    assert_eq!(handle.command_pipe(), pipe);
    // SAFETY: `handle` is alive, so the pipe is open. `x` is `OC_CMD_CANCEL`.
    assert!(unsafe { pipe.send(b'x') });
    assert_ne!(handle.obtain_cookie(), 0);
    assert!(handle.cookie().is_none());
}

// Security rule: nothing is written to a command pipe once its handle is
// dropped. The stopper another thread holds writes while the handle lives,
// and afterwards says the handle is gone and writes nothing: the pipe is
// closed by then, and its number may already belong to something else.
#[test]
fn a_stopper_stops_a_live_handle_and_writes_nothing_to_a_dropped_one() {
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
    let stopper = handle.stopper();
    let elsewhere = stopper.clone();
    let written = std::thread::spawn(move || elsewhere.cancel()).join();
    assert_eq!(written.unwrap(), Some(true));
    assert_ne!(handle.obtain_cookie(), 0);
    assert!(handle.cookie().is_none());
    drop(handle);
    assert_eq!(stopper.cancel(), None);
}

// Security rule: freeing a handle closes its own command pipe and nothing
// else. The library closes file descriptor 0 when it frees a handle that
// never made a pipe, which is why every handle makes one: after that, 0 is
// whatever this process opens next, and the next free would close that too.
#[cfg(unix)]
#[test]
fn freeing_a_handle_leaves_standard_input_open() {
    unsafe extern "C" {
        fn fcntl(fd: std::ffi::c_int, command: std::ffi::c_int, ...) -> std::ffi::c_int;
    }
    // SAFETY: `F_GETFD`, which is 1, only reads the flags of descriptor 0,
    // and fails if it is closed.
    let open = || unsafe { fcntl(0, 1) } != -1;
    let (library, _guard) = library();
    assert!(open(), "this test needs standard input to be open");
    let (handle, _) = handle(library, 8443, &yes(), Box::new(|_| true), Box::new(answer));
    drop(handle);
    assert!(open(), "freeing the handle closed standard input");
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

// Security rule: the system's certificate store is not trusted, so the judge
// is asked about every certificate. This is what keeps the password from a
// gateway that some authority vouches for but no pin matches: with the
// store trusted, the library accepts such a certificate itself, never asks,
// and sends the password.
//
// It needs a certificate the machine's own store trusts. Only the CI
// workflow makes one, on a Linux runner that is thrown away afterwards, by
// adding a throwaway authority to that store. Never do that anywhere else:
// without the workflow's variable this test is skipped.
#[test]
fn a_certificate_the_system_trusts_is_still_judged_and_nothing_is_sent() {
    let (library, _guard) = library();
    let Some(gateway) = Gateway::start_trusted("accept") else {
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
    assert_eq!(seen.hashes.len(), 1, "the judge was not asked");
    assert!(seen.fields.is_empty() && handle.cookie().is_none());
    assert_eq!(gateway.requests(), Vec::<String>::new());
    println!("RAN: handle judges a trusted certificate");
}

// What a form says reaches the callback as the gateway sent it: its message,
// and its error when the gateway shows the form again after a refusal.
#[test]
fn a_form_shown_again_carries_the_gateways_error() {
    let (library, _guard) = library();
    let Some(gateway) = Gateway::start("reject") else {
        return;
    };
    // Answer the first form; give up on the one that comes back.
    let mut shown = 0;
    let fill: Fill<'_> = Box::new(move |form| {
        shown += 1;
        if shown == 1 {
            answer(form)
        } else {
            FormAnswer::Cancel
        }
    });
    let (handle, seen) = handle(library, gateway.port, &yes(), Box::new(|_| true), fill);
    assert_ne!(handle.obtain_cookie(), 0);
    let seen = seen.lock().unwrap();
    let said = |text: &str| Some(text.to_string());
    assert_eq!(seen.forms[0], (said("Please log in."), None, false));
    assert_eq!(
        seen.forms[1],
        (said("Please log in."), said("Login failed."), false)
    );
}

// A form that asks for a choice of group says so, and one that does not,
// does not (the test above).
#[test]
fn a_form_with_a_choice_of_group_says_so() {
    let (library, _guard) = library();
    let Some(gateway) = Gateway::start("group") else {
        return;
    };
    let (handle, seen) = handle(
        library,
        gateway.port,
        &yes(),
        Box::new(|_| true),
        Box::new(|_| FormAnswer::Fail),
    );
    assert_ne!(handle.obtain_cookie(), 0);
    assert!(seen.lock().unwrap().forms[0].2);
}

// The fields reach the callback with their type, and with the library's
// mark on one that is not to be shown or filled. An engine skips hidden and
// ignored fields, so it must be able to tell.
#[test]
fn hidden_and_ignored_fields_are_told_apart() {
    let (library, _guard) = library();
    let Some(gateway) = Gateway::start("fields") else {
        return;
    };
    let (handle, seen) = handle(
        library,
        gateway.port,
        &yes(),
        Box::new(|_| true),
        Box::new(|_| FormAnswer::Fail),
    );
    assert_ne!(handle.obtain_cookie(), 0);
    let seen = seen.lock().unwrap();
    let fields: Vec<(FieldKind, &str, bool)> = seen.fields[0]
        .iter()
        .map(|field| (field.kind, field.name.as_str(), field.ignored))
        .collect();
    // The library puts the choice of group first, whatever the form's order.
    let expected = [
        (FieldKind::Select, "group_list", false),
        (FieldKind::Text, "username", false),
        (FieldKind::Password, "password", false),
        (FieldKind::Password, "secondary_password", true),
        (FieldKind::Hidden, "token", false),
    ];
    assert_eq!(fields, expected);
}

/// The stand-in gateway's session cookie.
const COOKIE: &str = "webvpn=FAKE-GATEWAY-COOKIE-0123456789abcdef==";

/// How many tunnel requests reached the gateway, and how many of those
/// carried the cookie.
fn connects(gateway: &Gateway) -> (usize, usize) {
    let requests = gateway.requests();
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

// The tunnel's first step through the binding: the cookie is handed over,
// the connection is made with it, and what the gateway assigned comes back,
// copied, with the address the connection really went to.
#[test]
fn a_cookie_opens_a_tunnel_connection_and_the_assignment_is_read() {
    let (library, _guard) = library();
    let Some(gateway) = Gateway::start("accept") else {
        return;
    };
    let (handle, seen) = handle(
        library,
        gateway.port,
        &yes(),
        Box::new(|_| true),
        Box::new(|_| FormAnswer::Fail),
    );
    // Before connecting the library answers with an empty assignment.
    let before = handle.ip_info();
    assert_eq!(before.and_then(|info| info.address), None);
    assert!(handle.set_cookie(&Secret::new(COOKIE)));
    assert!(handle.disable_dtls());
    assert_eq!(handle.make_cstp_connection(), 0);
    assert!(handle.certificate_accepted());
    let info = handle.ip_info().expect("a connection has an assignment");
    let text = |value: &str| Some(value.to_string());
    assert_eq!(info.address, text("10.11.12.13"));
    assert_eq!(info.netmask, text("255.255.255.0"));
    assert_eq!(info.dns, ["10.11.0.1", "10.11.0.2"]);
    assert_eq!(info.mtu, 1300);
    // The library keeps them newest first; the order means nothing.
    let mut routes = info.split_includes.clone();
    routes.sort();
    assert_eq!(routes, ["10.0.0.0/255.0.0.0", "192.0.2.0/255.255.255.0"]);
    assert_eq!(info.gateway_addr, text("127.0.0.1"));
    // The tunnel asks the resolver like a login, and nothing else asked.
    assert_eq!(
        seen.lock().unwrap().resolved,
        [(HOST.to_string(), gateway.port)]
    );
    assert!(seen.lock().unwrap().fields.is_empty());
    assert_eq!(connects(&gateway), (1, 1));
    println!("RAN: handle opens a tunnel connection");
}

// Security rule: the record that the certificate callback accepted is
// cleared before a tunnel connection too. Here the handle has logged in,
// which set it; then the tunnel connection is made with the resolver
// refusing everything. The library reuses the connection the login left
// open, asks no resolver and judges no certificate, and still reports
// success. The record must say nothing was judged, which is why the tunnel
// engine refuses a connection whose record is false.
#[test]
fn the_record_of_acceptance_is_cleared_before_a_tunnel_connection() {
    let (library, _guard) = library();
    let Some(gateway) = Gateway::start("accept") else {
        return;
    };
    let reachable = yes();
    let (handle, seen) = handle(
        library,
        gateway.port,
        &reachable,
        Box::new(|_| true),
        Box::new(answer),
    );
    assert_eq!(handle.obtain_cookie(), 0);
    assert!(handle.certificate_accepted(), "the login set the record");
    reachable.store(false, Ordering::SeqCst);
    let judged = seen.lock().unwrap().hashes.len();
    assert_eq!(handle.make_cstp_connection(), 0);
    assert_eq!(
        seen.lock().unwrap().hashes.len(),
        judged,
        "a certificate was judged"
    );
    assert!(!handle.certificate_accepted());
}

// Security rule: a gateway that refuses the cookie gives an answer of its
// own, `-EPERM`, which the tunnel engine reports as "log in again".
#[test]
fn a_refused_cookie_is_told_apart() {
    let (library, _guard) = library();
    let Some(gateway) = Gateway::start("ended") else {
        return;
    };
    let (handle, _) = handle(
        library,
        gateway.port,
        &yes(),
        Box::new(|_| true),
        Box::new(|_| FormAnswer::Fail),
    );
    assert!(handle.set_cookie(&Secret::new(COOKIE)));
    assert!(handle.disable_dtls());
    // EPERM is 1 on all three systems.
    assert_eq!(handle.make_cstp_connection(), -1);
    assert_eq!(connects(&gateway), (1, 1));
}

// Security rule: the cookie goes to no gateway the certificate check
// refused. It is sent only after the pin check, and here it never is.
#[test]
fn a_refused_certificate_means_the_cookie_is_not_sent() {
    let (library, _guard) = library();
    let Some(gateway) = Gateway::start("accept") else {
        return;
    };
    let (handle, seen) = handle(
        library,
        gateway.port,
        &yes(),
        Box::new(|_| false),
        Box::new(|_| FormAnswer::Fail),
    );
    assert!(handle.set_cookie(&Secret::new(COOKIE)));
    assert!(handle.disable_dtls());
    assert_ne!(handle.make_cstp_connection(), 0);
    assert!(!handle.certificate_accepted());
    assert_eq!(seen.lock().unwrap().hashes.len(), 1);
    assert_eq!(gateway.requests(), Vec::<String>::new());
}

// Security rule: a cookie with a NUL in it is refused, not cut short and
// sent; and the copy made to hand a cookie over is wiped (the same lending
// as for an answer, tested in the binding's own unit tests).
#[test]
fn a_cookie_with_a_nul_in_it_is_refused() {
    let (library, _guard) = library();
    let (handle, _) = handle(
        library,
        8443,
        &yes(),
        Box::new(|_| true),
        Box::new(|_| FormAnswer::Fail),
    );
    assert!(!handle.set_cookie(&Secret::new("webvpn=FAKE\0COOKIE")));
    assert!(handle.set_cookie(&Secret::new(COOKIE)));
}

// A detach reaches a live handle, and nothing reaches a dropped one, as for
// a cancel.
#[test]
fn a_detach_reaches_a_live_handle_only() {
    let (library, _guard) = library();
    let (handle, _) = handle(
        library,
        8443,
        &yes(),
        Box::new(|_| true),
        Box::new(|_| FormAnswer::Fail),
    );
    let stopper = handle.stopper();
    assert_eq!(stopper.detach(), Some(true));
    drop(handle);
    assert_eq!(stopper.detach(), None);
}
