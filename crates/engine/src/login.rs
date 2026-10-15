//! Logging in with the real library: [`OpenConnect`] as a [`LoginEngine`].
//!
//! Each login makes one handle, asks it for a cookie once and frees it. The
//! rules this follows are in the crate documentation. There is no `unsafe`
//! here: every call into the library goes through the `ffi` module.
//!
//! A cancel is looked at before the login starts and before a session is
//! returned, and in between it stops a login that is waiting on the gateway.

use std::cell::Cell;
use std::ffi::{CStr, CString, c_int};
use std::net::{SocketAddr, SocketAddrV4, ToSocketAddrs};
use std::path::Path;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use ubc_vpn_core::login::PromptKind;
use ubc_vpn_core::policy::Pin;
use ubc_vpn_core::redact::Secret;

use crate::ffi::{
    Callbacks, Field, FieldKind, Form, FormAnswer, Handle, Library, LineState, LoadError, Prepared,
};
use crate::{
    Cancel, Gateway, LogLevel, LogSink, LoginEngine, LoginError, Prompt, Prompts, Session,
};

/// The only port a login or a tunnel connects to, unless the gateway is a
/// test's.
pub(crate) const HTTPS: u16 = 443;

/// What the library reports as the hash of a certificate it could not hash:
/// thirty-two zero bytes, in the form of a pin. It is never a gateway's.
const HASH_OF_NOTHING: &str = "pin-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

/// The real engine: `libopenconnect`, loaded into this process.
///
/// Its `library` accessor is for this crate's tests and exists only with the
/// `fake` feature, which nothing that ships has:
///
/// ```compile_fail
/// # #[cfg(feature = "fake")]
/// # compile_error!("only meaningful without the fake feature");
/// let _ = ubc_vpn_engine::OpenConnect::library;
/// ```
pub struct OpenConnect {
    pub(crate) library: Library,
}

impl OpenConnect {
    /// Loads the library from `dir`, the folder the program was installed
    /// in. Call it once, right after [`prepare_environment`], before any
    /// other thread exists, and treat an error as fatal.
    ///
    /// [`prepare_environment`]: crate::prepare_environment
    pub fn load(dir: &Path, environment: &Prepared) -> Result<Self, LoadError> {
        Library::load(dir, environment).map(|library| Self { library })
    }

    /// For this crate's tests, which load once in a process and also drive
    /// the library directly.
    #[cfg(feature = "fake")]
    #[doc(hidden)]
    pub fn library(&self) -> Library {
        self.library
    }
}

/// What the callbacks of one login note for the code that started it.
#[derive(Default)]
struct Notes {
    /// Where the gateway is, once it has been looked up. Looked up once, so
    /// that every connection of the login goes to the same machine.
    address: Cell<Option<SocketAddrV4>>,
    /// A certificate was shown, so something answered at that address.
    judged: Cell<bool>,
    /// A certificate was shown that no pin matches.
    refused: Cell<bool>,
    /// Why the form callback stopped the login.
    stopped: Cell<Option<LoginError>>,
    /// How many one-time codes the user was asked for.
    codes: Cell<usize>,
    /// What the library's lines said, which the line callback notes from
    /// whatever thread it is called on.
    heard: Arc<Heard>,
}

/// What the line callback of one login notes.
#[derive(Default)]
struct Heard {
    /// A form has been filled in and sent.
    answered: AtomicBool,
    /// After that, the library said the gateway's reply was empty.
    empty_reply: AtomicBool,
}

/// What the library logs when a reply has no body at all.
const EMPTY_REPLY: &str = "Unexpected empty response body from server";

/// Whether `hash`, as the library reports a certificate, is a full pin that
/// the gateway accepts. The hash of nothing never is, whatever the policy.
pub(crate) fn pin_matches(gateway: &Gateway, hash: &str) -> bool {
    hash != HASH_OF_NOTHING
        && Pin::try_from(hash.to_string()).is_ok_and(|pin| gateway.accepts(&pin))
}

/// Passes one of the library's lines to the sink, with the level it has
/// there. A line that was cut, or that failed to format, is dropped whole:
/// part of a secret in it would match nothing the sink was told to hide.
pub(crate) fn deliver(logs: &LogSink, level: c_int, line: &CStr, state: LineState) {
    if state != LineState::Whole {
        return;
    }
    // The library's PRG_ERR, PRG_INFO, then PRG_DEBUG and PRG_TRACE.
    let level = match level {
        0 => LogLevel::Error,
        1 => LogLevel::Info,
        _ => LogLevel::Debug,
    };
    logs.log(level, &line.to_string_lossy());
}

/// Passes one of the library's lines from a login to the sink, at most at
/// [`LogLevel::Info`]. The library logs as errors things that do not end a
/// login, such as an empty reply to its first probe of the gateway, after
/// which it carries on; the login's own result says what failed. A line
/// that was cut, or that failed to format, is dropped whole. An empty reply
/// once the answers have been sent is noted.
fn deliver_login(logs: &LogSink, heard: &Heard, level: c_int, line: &CStr, state: LineState) {
    if state != LineState::Whole {
        return;
    }
    let line = line.to_string_lossy();
    if heard.answered.load(Ordering::SeqCst) && line.trim_end() == EMPTY_REPLY {
        heard.empty_reply.store(true, Ordering::SeqCst);
    }
    // The library's PRG_ERR and PRG_INFO, then PRG_DEBUG and PRG_TRACE.
    let level = match level {
        0 | 1 => LogLevel::Info,
        _ => LogLevel::Debug,
    };
    logs.log(level, &line);
}

/// The questions a form asks: for each, the field's place in the form, the
/// kind of answer and the gateway's wording. The kind comes from the field's
/// type and name alone, never from its place. Hidden fields and ones the
/// library marks to be ignored are left out. A form with a field of any other
/// sort, or with nothing to ask, cannot be answered.
fn questions(fields: &[Field]) -> Result<Vec<(usize, PromptKind, &str)>, LoginError> {
    let mut questions = Vec::new();
    for (index, field) in fields.iter().enumerate() {
        if field.ignored || field.kind == FieldKind::Hidden {
            continue;
        }
        let kind = match (field.kind, field.name.as_str()) {
            (FieldKind::Text, "username") => PromptKind::Username,
            (FieldKind::Password, "password") => PromptKind::Password,
            (FieldKind::Password, _) => PromptKind::Code,
            (FieldKind::Text, _) => PromptKind::Text,
            _ => return Err(LoginError::Failed),
        };
        questions.push((index, kind, field.label.as_str()));
    }
    if questions.is_empty() {
        return Err(LoginError::Failed);
    }
    Ok(questions)
}

/// The most one-time codes one login asks for. A gateway may show the code
/// form again and again, and each code may mean an approval request on the
/// user's phone. After this many the login ends as
/// [`LoginError::WrongPassword`], which is what a rejected code is, and
/// [`Prompts::asked`] tells the caller a code was involved.
const MAX_CODES: usize = 3;

/// Fills in one form by asking the user. Each field is answered once, from
/// one `ask`, and the answer is registered with the sink and then dropped.
/// `codes` counts the one-time codes asked for so far in this login.
fn fill(
    form: &mut Form<'_>,
    prompts: &mut Prompts<'_>,
    logs: &LogSink,
    codes: &Cell<usize>,
) -> Result<(), LoginError> {
    if form.asks_for_group() {
        return Err(LoginError::Failed);
    }
    // A form shown again after a refusal carries an error. Asking again is
    // what stops the login: `Prompts` refuses a second username or password.
    let message = form.error().or_else(|| form.message());
    let fields = form.fields();
    for (index, kind, label) in questions(&fields)? {
        if kind == PromptKind::Code {
            if codes.get() == MAX_CODES {
                return Err(LoginError::WrongPassword);
            }
            codes.set(codes.get() + 1);
        }
        let prompt = Prompt {
            kind,
            label: label.to_string(),
            message: message.clone(),
        };
        let answer = match prompts.ask(&prompt) {
            Ok(answer) => answer,
            Err(refused @ (LoginError::WrongPassword | LoginError::CheckUsername)) => {
                // The gateway's own words on the form it showed again are
                // what tells the user what was wrong, so they are an error.
                if let Some(said) = message.as_deref().filter(|said| !said.trim().is_empty()) {
                    logs.log(LogLevel::Error, &format!("The gateway said: {said}"));
                }
                return Err(refused);
            }
            Err(other) => return Err(other),
        };
        // The sink does not register an answer shorter than `MIN_HIDDEN_LEN`
        // (4 bytes), so such an answer is not taken out of log lines. That is
        // decided, not overlooked: an answer that short is a choice, such as
        // `1` for a way to confirm, not a secret, and hiding every `1` would
        // shred the log. A four-byte choice such as `push` is registered.
        logs.hide(&answer);
        if !form.answer(index, &answer) {
            return Err(LoginError::Failed);
        }
    }
    Ok(())
}

/// How one attempt ended, as far as the library and the callbacks can tell.
struct Ended {
    /// What `openconnect_obtain_cookie` returned. Zero is success.
    result: c_int,
    /// Whether the certificate callback ran and accepted on this connection.
    accepted: bool,
    judged: bool,
    refused: bool,
    stopped: Option<LoginError>,
    cancelled: bool,
    /// The gateway sent an empty reply once the answers were sent.
    empty_reply: bool,
    cookie: Option<Secret>,
    address: Option<SocketAddrV4>,
}

/// Turns the end of an attempt into the login's result.
///
/// A success is believed only with a certificate the pin check accepted on
/// this connection. Without one the library let the gateway through by
/// itself, and the answers may have gone to it, so this is `Failed` and not
/// `PinMismatch`, which promises that nothing was sent.
fn conclude(ended: Ended) -> Result<Session, LoginError> {
    if ended.refused {
        return Err(LoginError::PinMismatch);
    }
    if let Some(error) = ended.stopped {
        return Err(error);
    }
    if ended.cancelled {
        return Err(LoginError::Cancelled);
    }
    if ended.result != 0 && ended.empty_reply {
        // Seen with a username the gateway does not take in that form: it
        // answers the password with nothing at all.
        return Err(LoginError::CheckUsername);
    }
    if ended.result != 0 {
        // With no certificate shown, nothing answered at the gateway's address.
        return Err(match ended.judged {
            true => LoginError::Failed,
            false => LoginError::GatewayUnreachable,
        });
    }
    if !ended.accepted {
        return Err(LoginError::Failed);
    }
    match (ended.cookie, ended.address) {
        (Some(cookie), Some(address)) if !cookie.expose().is_empty() => Ok(Session {
            cookie,
            gateway_addr: *address.ip(),
        }),
        _ => Err(LoginError::Failed),
    }
}

/// Where to connect for the gateway: the test endpoint if it has one, or the
/// first IPv4 address its name resolves to, on port 443.
fn look_up(gateway: &Gateway) -> Option<SocketAddrV4> {
    if let Some(endpoint) = gateway.test_endpoint() {
        return Some(endpoint);
    }
    let found = (gateway.host(), HTTPS).to_socket_addrs().ok()?;
    found.into_iter().find_map(|address| match address {
        SocketAddr::V4(address) => Some(address),
        SocketAddr::V6(_) => None,
    })
}

impl LoginEngine for OpenConnect {
    fn login(
        &self,
        gateway: &Gateway,
        prompts: &mut Prompts<'_>,
        cancel: &Cancel,
        logs: &LogSink,
    ) -> Result<Session, LoginError> {
        if cancel.is_cancelled() {
            return Err(LoginError::Cancelled);
        }
        // The host name is all the library is told. Where that is, it must
        // ask the resolve callback.
        let url = CString::new(format!("https://{}", gateway.host()));
        let url = url.map_err(|_| LoginError::Failed)?;
        let notes = Rc::new(Notes::default());
        let (judging, filling, resolving) = (notes.clone(), notes.clone(), notes.clone());
        let (pinned, sought, sink) = (gateway.clone(), gateway.clone(), logs.clone());
        let heard = Arc::clone(&notes.heard);
        let callbacks = Callbacks {
            lines: Box::new(move |level, line, state| {
                deliver_login(&sink, &heard, level, line, state);
            }),
            certificate: Box::new(move |hash| {
                let matches = pin_matches(&pinned, hash);
                judging.judged.set(true);
                judging.refused.set(judging.refused.get() || !matches);
                matches
            }),
            form: Box::new(
                move |form| match fill(form, prompts, logs, &filling.codes) {
                    Ok(()) => {
                        filling.heard.answered.store(true, Ordering::SeqCst);
                        FormAnswer::Submit
                    }
                    Err(error) => {
                        filling.stopped.set(Some(error));
                        match error {
                            LoginError::Cancelled => FormAnswer::Cancel,
                            _ => FormAnswer::Fail,
                        }
                    }
                },
            ),
            // The only host and port a login may reach are the gateway's own.
            // A redirect or a form's address that names another gets nothing.
            resolve: Box::new(move |host, port| {
                if !host.eq_ignore_ascii_case(sought.host()) || port != HTTPS {
                    return None;
                }
                let known = resolving.address.get().or_else(|| look_up(&sought));
                resolving.address.set(known);
                known
            }),
        };
        // One handle for this attempt, asked for a cookie once.
        let handle = Handle::new(self.library, callbacks).ok_or(LoginError::Failed)?;
        if handle.parse_url(&url) != 0 {
            return Err(LoginError::Failed);
        }
        // A cancel from another thread wakes the library through its command
        // pipe. The hook is armed for this one call and disarmed before the
        // handle is freed; a cancel that comes later reaches nothing.
        let stopper = handle.stopper();
        let armed = cancel.on_cancel(move || {
            stopper.cancel();
        });
        let result = handle.obtain_cookie();
        drop(armed);
        finish(handle, result, &notes, cancel, logs)
    }
}

/// Reads what a handle holds once it has been asked for a cookie, frees it,
/// and decides how the login ended. `result` is what the library answered.
fn finish(
    handle: Handle<'_>,
    result: c_int,
    notes: &Notes,
    cancel: &Cancel,
    logs: &LogSink,
) -> Result<Session, LoginError> {
    let accepted = handle.certificate_accepted();
    // Copied out at once and registered whole before anything else.
    let cookie = (result == 0 && accepted).then(|| handle.cookie()).flatten();
    if let Some(cookie) = &cookie {
        logs.hide(cookie);
    }
    // The library holds copies of the answers until the handle is freed.
    drop(handle);
    conclude(Ended {
        result,
        accepted,
        judged: notes.judged.get(),
        refused: notes.refused.get(),
        stopped: notes.stopped.take(),
        cancelled: cancel.is_cancelled(),
        empty_reply: notes.heard.empty_reply.load(Ordering::SeqCst),
        cookie,
        address: notes.address.get(),
    })
}

// The stand-in gateway, for the unit tests that need a real handle. It is
// named here and not inside `tests`: a path given inside an inline module is
// looked up through a folder that does not exist.
#[cfg(test)]
#[path = "../tests/gateway/mod.rs"]
pub(crate) mod stand_in;

/// The library, for the unit tests that need a real handle. The environment
/// is prepared and the library loaded once in a process, whichever test asks
/// first.
#[cfg(test)]
pub(crate) fn test_library() -> Library {
    static LOADED: std::sync::OnceLock<Library> = std::sync::OnceLock::new();
    *LOADED.get_or_init(|| {
        let prepared = crate::prepare_environment(crate::Role::Client, None);
        let libs = Path::new(env!("UBC_VPN_NATIVE_LIBS"));
        let library = Library::load(libs, &prepared.expect("the environment is clean"));
        library.expect("the pinned library loads")
    })
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::{Arc, Mutex};

    use ubc_vpn_core::policy::Policy;

    use super::*;

    const A_PIN: &str = "pin-sha256:fTzrkd+T2QOdSW5oSF7vp4M6JCp1hHMbYY2Q+IX4x5o=";

    fn gateway(pins: &[&str]) -> Gateway {
        let pin = |pin: &&str| Pin::try_from(pin.to_string()).expect("a full pin");
        let policy = Policy {
            gateway: "vpn.example.test".to_string(),
            pins: pins.iter().map(pin).collect(),
            allowed_routes: None,
        };
        Gateway::from_policy(&policy).expect("a valid policy")
    }

    // Security rule: what a login returns depends on the handle's own record
    // that a certificate was accepted on this connection, not only on the
    // library saying it succeeded. A handle asked for a cookie a second time
    // says so without connecting, with nothing judged. No login asks twice,
    // so the test does, and hands the handle to the code that ends a login.
    #[test]
    fn a_handle_that_succeeded_unjudged_yields_no_session() {
        let Some(gateway) = stand_in::Gateway::start("accept") else {
            return;
        };
        let library = test_library();
        let local = SocketAddrV4::new(Ipv4Addr::LOCALHOST, gateway.port);
        let logged_in = || {
            let mut callbacks = Callbacks::refusing(Box::new(|_, _, _| {}));
            callbacks.certificate = Box::new(|_| true);
            callbacks.resolve = Box::new(move |_, _| Some(local));
            callbacks.form = Box::new(|form| {
                let value = Secret::new("not-a-real-answer");
                let filled = form.answer(0, &value) && form.answer(1, &value);
                [FormAnswer::Fail, FormAnswer::Submit][usize::from(filled)]
            });
            let handle = Handle::new(library, callbacks).expect("the library makes a handle");
            assert_eq!(handle.parse_url(c"https://vpn.example.test"), 0);
            assert_eq!(handle.obtain_cookie(), 0);
            handle
        };
        let notes = Notes::default();
        notes.address.set(Some(local));
        notes.judged.set(true);
        let (cancel, logs) = (Cancel::new(), LogSink::none());
        // Asked once, as a login does: a session.
        assert!(finish(logged_in(), 0, &notes, &cancel, &logs).is_ok());
        // Asked again: success, and nothing was judged.
        let handle = logged_in();
        let again = handle.obtain_cookie();
        assert_eq!(again, 0);
        let unjudged = finish(handle, again, &notes, &cancel, &logs);
        assert_eq!(unjudged, Err(LoginError::Failed));
    }

    /// An attempt that ended as a good login does.
    fn good() -> Ended {
        Ended {
            result: 0,
            accepted: true,
            judged: true,
            refused: false,
            stopped: None,
            cancelled: false,
            empty_reply: false,
            cookie: Some(Secret::new("NOT-A-REAL-COOKIE")),
            address: Some(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), HTTPS)),
        }
    }

    // Security rule: only a full pin the policy lists is accepted. A prefix
    // of one, or an empty hash, is not a pin at all.
    #[test]
    fn only_a_full_listed_pin_matches() {
        let gateway = gateway(&[A_PIN]);
        assert!(pin_matches(&gateway, A_PIN));
        let other = A_PIN.replace("fTz", "gTz");
        for hash in ["", "pin-sha256:", &A_PIN[..20], &other, &A_PIN[11..]] {
            assert!(!pin_matches(&gateway, hash), "{hash:?}");
        }
    }

    // Security rule: the hash of nothing is refused even if a policy lists
    // it. It is what the library reports when it could not hash the key.
    #[test]
    fn the_hash_of_nothing_never_matches() {
        assert!(!pin_matches(
            &gateway(&[HASH_OF_NOTHING, A_PIN]),
            HASH_OF_NOTHING
        ));
    }

    // Security rule: a line that was cut or that failed to format is dropped
    // whole. A secret cut at its end matches nothing the sink hides.
    #[test]
    fn a_cut_or_failed_line_is_dropped_whole() {
        let lines = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&lines);
        let logs = LogSink::new(LogLevel::Debug, move |level, line: &str| {
            seen.lock().unwrap().push((level, line.to_string()));
        });
        deliver(
            &logs,
            1,
            c"the first part of NOT-A-REAL-COO",
            LineState::Cut,
        );
        deliver(&logs, 0, c"half a line", LineState::Failed);
        assert_eq!(*lines.lock().unwrap(), []);
        deliver(&logs, 0, c"an error", LineState::Whole);
        deliver(&logs, 1, c"progress", LineState::Whole);
        deliver(&logs, 3, c"detail", LineState::Whole);
        let levels: Vec<LogLevel> = lines.lock().unwrap().iter().map(|line| line.0).collect();
        // The sink itself drops the library's detail where a build has none.
        let expected = [LogLevel::Error, LogLevel::Info, LogLevel::Debug];
        assert_eq!(levels, expected[..if crate::DEBUG_LINES { 3 } else { 2 }]);
    }

    // Security rule: a success the pin check did not accept on this
    // connection is refused, cookie and all. The library asks about a
    // certificate only when its own checks did not pass it.
    #[test]
    fn a_success_without_an_accepted_certificate_is_refused() {
        assert!(conclude(good()).is_ok());
        let unjudged = Ended {
            accepted: false,
            judged: false,
            ..good()
        };
        assert_eq!(conclude(unjudged), Err(LoginError::Failed));
    }

    // Security rule: a cancelled login never returns a session, and a pin
    // mismatch or a stop in the form outranks whatever the library reports.
    #[test]
    fn what_stopped_a_login_decides_its_error() {
        let ended = |change: fn(&mut Ended)| {
            let mut ended = good();
            change(&mut ended);
            conclude(ended)
        };
        let cancelled = ended(|ended| ended.cancelled = true);
        assert_eq!(cancelled, Err(LoginError::Cancelled));
        let refused = ended(|ended| ended.refused = true);
        assert_eq!(refused, Err(LoginError::PinMismatch));
        let stopped = ended(|ended| ended.stopped = Some(LoginError::WrongPassword));
        assert_eq!(stopped, Err(LoginError::WrongPassword));
        let unreachable = ended(|ended| (ended.result, ended.judged) = (-1, false));
        assert_eq!(unreachable, Err(LoginError::GatewayUnreachable));
        assert_eq!(ended(|ended| ended.result = -1), Err(LoginError::Failed));
        assert_eq!(ended(|ended| ended.cookie = None), Err(LoginError::Failed));
        let empty = ended(|ended| ended.cookie = Some(Secret::new("")));
        assert_eq!(empty, Err(LoginError::Failed));
        assert_eq!(ended(|ended| ended.address = None), Err(LoginError::Failed));
    }

    fn field(kind: FieldKind, name: &str, ignored: bool) -> Field {
        Field {
            kind,
            name: name.to_string(),
            label: format!("{name}:"),
            ignored,
        }
    }

    // Fields are told apart by type and name, and keep their own place in
    // the form whatever was left out before them. Hidden and ignored fields
    // are never asked about.
    #[test]
    fn questions_come_from_type_and_name_and_skip_what_is_not_asked() {
        let fields = [
            field(FieldKind::Hidden, "token", false),
            field(FieldKind::Password, "password", false),
            field(FieldKind::Password, "username", true),
            field(FieldKind::Password, "secondary_password", false),
            field(FieldKind::Text, "answer", false),
            field(FieldKind::Text, "username", false),
        ];
        let expected = [
            (1, PromptKind::Password, "password:"),
            (3, PromptKind::Code, "secondary_password:"),
            (4, PromptKind::Text, "answer:"),
            (5, PromptKind::Username, "username:"),
        ];
        assert_eq!(questions(&fields).unwrap(), expected);
    }

    // A form with a choice to make, a field of an unknown sort, or nothing
    // to ask cannot be answered. Without the last, a gateway could show
    // empty forms for ever and the login would send each one back.
    #[test]
    fn a_form_that_cannot_be_asked_about_fails() {
        let text = field(FieldKind::Text, "username", false);
        for odd in [FieldKind::Select, FieldKind::Other] {
            let fields = [text.clone(), field(odd, "group_list", false)];
            assert_eq!(questions(&fields), Err(LoginError::Failed));
        }
        let unasked = [field(FieldKind::Hidden, "token", false)];
        assert_eq!(questions(&unasked), Err(LoginError::Failed));
        assert_eq!(questions(&[]), Err(LoginError::Failed));
    }
}
