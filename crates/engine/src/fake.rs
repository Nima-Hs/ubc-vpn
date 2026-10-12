//! A scripted engine for tests and for the service's dev mode.
//!
//! This module exists only with the `fake` Cargo feature, so a release
//! service, which must not enable it, cannot link it.
//!
//! A [`Script`] describes a pretend gateway: the key it presents, the
//! questions it asks and the answers it accepts, the cookie it issues and
//! what it assigns to a tunnel. [`FakeEngine`] plays that gateway through the
//! real interfaces, so the outcome follows from what the caller does:
//!
//! - a wrong answer makes the gateway show the whole form again with an
//!   error message, as a real one does;
//! - a key that matches none of the caller's pins is a pin mismatch;
//! - a cookie other than the scripted one, or one that has been logged off
//!   or expired, means "login needed".
//!
//! A test can also change the gateway while it runs (`set_reachable`,
//! `expire_session`, `drop_connection`) and hold `login` and `open` blocked
//! part-way (`hold`, `wait_until_blocked`, `release`).
//!
//! Like `libopenconnect`, it writes the cookie to its debug log, so callers'
//! log handling can be tested against it. It talks to no network and starts
//! no thread: a tunnel's event is sent from whichever thread ends it.

use std::sync::mpsc::Sender;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};

use ubc_vpn_core::login::PromptKind;
use ubc_vpn_core::policy::Pin;
use ubc_vpn_core::redact::Secret;

use crate::{
    Assigned, Cancel, CloseMode, Gateway, LogLevel, LogSink, LoginEngine, LoginError, Prompt,
    Prompts, Session, Tunnel, TunnelEngine, TunnelError, TunnelEvent, check_gateway_addr,
};

/// What the pretend gateway does. Every field may be changed before the
/// script is given to [`FakeEngine::new`].
#[derive(Debug, Clone)]
pub struct Script {
    /// The hash of the key the gateway presents.
    pub key: Pin,
    /// Whether the gateway answers at first. See [`FakeEngine::set_reachable`].
    pub reachable: bool,
    /// The login form: the questions asked, in order, each with the one
    /// answer the gateway accepts.
    pub form: Vec<(Prompt, Secret)>,
    /// The cookie a successful login yields, and the only one a tunnel
    /// accepts.
    pub cookie: Secret,
    /// What a tunnel is given. Its `gateway_addr` is where the gateway lives.
    pub assigned: Assigned,
}

impl Script {
    /// A reachable gateway presenting `key`. It asks for a username (`alice`)
    /// and a password (`correct-horse-battery`), and assigns made-up values.
    pub fn new(key: Pin) -> Self {
        let ask = |kind, label: &str, accepted: &str| {
            let prompt = Prompt {
                kind,
                label: label.to_string(),
                message: None,
            };
            (prompt, Secret::new(accepted))
        };
        Self {
            key,
            reachable: true,
            form: vec![
                ask(PromptKind::Username, "Username", "alice"),
                ask(PromptKind::Password, "Password", "correct-horse-battery"),
            ],
            cookie: Secret::new("Zq7-made-up-0123456789"),
            assigned: Assigned {
                interface: "fake0".to_string(),
                address: [10, 255, 0, 2].into(),
                netmask: [255, 255, 255, 0].into(),
                gateway_addr: [192, 0, 2, 1].into(),
                dns: vec![[10, 255, 0, 53].into()],
                mtu: 1300,
                split_includes: Vec::new(),
            },
        }
    }
}

struct State {
    answers: Vec<(PromptKind, Secret)>,
    reachable: bool,
    /// Whether the gateway still honours the scripted cookie.
    session_alive: bool,
    /// Whether logging a session off ends it. False only for dev mode.
    log_off_ends_session: bool,
    /// Whether calls stop at the gate, and how many are stopped there.
    held: bool,
    waiting: usize,
    /// The open tunnel, if any: its number and its event channel.
    live: Option<(u64, Sender<TunnelEvent>)>,
    opened: u64,
}

struct Shared {
    state: Mutex<State>,
    changed: Condvar,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Ends the open tunnel, if there is one, and says why. Taking the sender
    /// out is what makes a tunnel report exactly one ending.
    fn end(state: &mut State, event: TunnelEvent) {
        if let Some((_, events)) = state.live.take() {
            // The receiver may be gone; there is then nobody to tell.
            let _ = events.send(event);
        }
    }
}

/// An engine that plays a [`Script`]. Clones share everything, so a test can
/// keep one clone and give the other away.
#[derive(Clone)]
pub struct FakeEngine {
    script: Script,
    shared: Arc<Shared>,
}

impl FakeEngine {
    /// An engine for the gateway `script` describes.
    pub fn new(script: Script) -> Self {
        let state = State {
            answers: Vec::new(),
            reachable: script.reachable,
            session_alive: true,
            log_off_ends_session: true,
            held: false,
            waiting: 0,
            live: None,
            opened: 0,
        };
        let shared = Shared {
            state: Mutex::new(state),
            changed: Condvar::new(),
        };
        Self {
            script,
            shared: Arc::new(shared),
        }
    }

    /// An engine for the service's dev mode, where logging in and opening the
    /// tunnel happen in two processes that share nothing.
    ///
    /// The command-line client logs in against a fake of its own, so the
    /// service's fake never sees a login that could bring a session back.
    /// This one therefore keeps honouring the scripted cookie after a
    /// log-off: every login in the other process yields that same cookie, and
    /// each must open a tunnel. A session still ends when the test hook
    /// [`FakeEngine::expire_session`] says so.
    ///
    /// Use [`FakeEngine::new`] everywhere else. Tests of the service rely on
    /// a log-off ending the session, as it does at a real gateway.
    pub fn for_dev_mode(script: Script) -> Self {
        let engine = Self::new(script);
        engine.shared.lock().log_off_ends_session = false;
        engine
    }

    /// Every answer the gateway was sent, in order.
    pub fn answers(&self) -> Vec<(PromptKind, Secret)> {
        self.shared.lock().answers.clone()
    }

    /// Whether a tunnel is open.
    pub fn tunnel_is_open(&self) -> bool {
        self.shared.lock().live.is_some()
    }

    /// Makes the gateway reachable or not for calls that check from now on.
    /// An open tunnel is not affected; see [`FakeEngine::drop_connection`].
    pub fn set_reachable(&self, reachable: bool) {
        self.shared.lock().reachable = reachable;
    }

    /// Makes the gateway forget the session. An open tunnel ends with
    /// [`TunnelEvent::LoginNeeded`], and the cookie is refused until someone
    /// logs in again.
    pub fn expire_session(&self) {
        let mut state = self.shared.lock();
        state.session_alive = false;
        Shared::end(&mut state, TunnelEvent::LoginNeeded);
    }

    /// Ends an open tunnel with [`TunnelEvent::ConnectionLost`], as a network
    /// change would. The session stays good.
    pub fn drop_connection(&self) {
        Shared::end(&mut self.shared.lock(), TunnelEvent::ConnectionLost);
    }

    /// Makes `login` and `open` block part-way until [`FakeEngine::release`]:
    /// `login` after the form is answered, like a wait for an MFA approval,
    /// and `open` before it contacts the gateway. Cancelling still works.
    pub fn hold(&self) {
        self.shared.lock().held = true;
    }

    /// Lets held calls continue. They see the gateway as it is now.
    pub fn release(&self) {
        self.shared.lock().held = false;
        self.shared.changed.notify_all();
    }

    /// Blocks until a held `login` or `open` is waiting at the gate. Call
    /// [`FakeEngine::hold`] first.
    pub fn wait_until_blocked(&self) {
        let mut state = self.shared.lock();
        while state.waiting == 0 {
            state = self.wait(state);
        }
    }

    fn wait<'a>(&self, state: MutexGuard<'a, State>) -> MutexGuard<'a, State> {
        let waited = self.shared.changed.wait(state);
        waited.unwrap_or_else(PoisonError::into_inner)
    }

    /// Waits while the test holds the gate. Returns whether to go on; false
    /// means the caller cancelled.
    fn pass_gate(&self, cancel: &Cancel) -> bool {
        let shared = Arc::clone(&self.shared);
        // Armed only while this call waits; dropped, after `state`, on return.
        let _armed = cancel.on_cancel(move || {
            // Taking the lock first means a waiter cannot miss the wake-up.
            let _state = shared.lock();
            shared.changed.notify_all();
        });
        let mut state = self.shared.lock();
        state.waiting += 1;
        self.shared.changed.notify_all();
        while state.held && !cancel.is_cancelled() {
            state = self.wait(state);
        }
        state.waiting -= 1;
        !cancel.is_cancelled()
    }
}

impl LoginEngine for FakeEngine {
    fn login(
        &self,
        gateway: &Gateway,
        prompts: &mut Prompts<'_>,
        cancel: &Cancel,
        logs: &LogSink,
    ) -> Result<Session, LoginError> {
        let script = &self.script;
        logs.log(LogLevel::Info, &format!("Connecting to {}", gateway.host()));
        if !self.shared.lock().reachable {
            logs.log(LogLevel::Error, "Failed to connect to the gateway");
            return Err(LoginError::GatewayUnreachable);
        }
        if !gateway.accepts(&script.key) {
            logs.log(LogLevel::Error, "Server certificate matches no pin");
            return Err(LoginError::PinMismatch);
        }
        // The gateway judges a whole form at once. On a wrong answer it shows
        // the form again with an error, which `Prompts` stops as soon as a
        // username or password would be asked twice.
        let mut message = None;
        let mut accepted = false;
        for _ in 0..2 {
            accepted = true;
            for (prompt, wanted) in &script.form {
                if cancel.is_cancelled() {
                    return Err(LoginError::Cancelled);
                }
                let mut shown = prompt.clone();
                shown.message = message.clone().or(shown.message);
                let answer = prompts.ask(&shown)?;
                logs.hide(&answer);
                // A real library can echo what it posts, with no marker word.
                logs.log(LogLevel::Debug, &format!("> {}", answer.expose()));
                accepted &= answer == *wanted;
                self.shared.lock().answers.push((prompt.kind, answer));
            }
            if accepted {
                break;
            }
            message = Some("Login failed.".to_string());
        }
        if !accepted {
            return Err(LoginError::WrongPassword);
        }
        // The wait for an MFA approval. A cancelled login yields no session.
        if !self.pass_gate(cancel) {
            return Err(LoginError::Cancelled);
        }
        // What the real library does at debug level, with and without a
        // word the redactor knows.
        logs.hide(&script.cookie);
        let cookie = script.cookie.expose();
        logs.log(LogLevel::Debug, &format!("Set-Cookie: webvpn={cookie}"));
        logs.log(LogLevel::Debug, &format!("< {cookie}"));
        logs.log(LogLevel::Info, "Login succeeded");
        self.shared.lock().session_alive = true;
        Ok(Session {
            cookie: script.cookie.clone(),
            gateway_addr: script.assigned.gateway_addr,
        })
    }
}

impl TunnelEngine for FakeEngine {
    fn open(
        &self,
        gateway: &Gateway,
        session: &Session,
        cancel: &Cancel,
        events: Sender<TunnelEvent>,
        logs: LogSink,
    ) -> Result<Box<dyn Tunnel>, TunnelError> {
        let script = &self.script;
        check_gateway_addr(session.gateway_addr)?;
        logs.hide(&session.cookie);
        if !self.pass_gate(cancel) {
            return Err(TunnelError::Cancelled);
        }
        let mut state = self.shared.lock();
        if !state.reachable || session.gateway_addr != script.assigned.gateway_addr {
            return Err(TunnelError::GatewayUnreachable);
        }
        // The key is judged before the cookie is sent.
        if !gateway.accepts(&script.key) {
            logs.log(LogLevel::Error, "Server certificate matches no pin");
            return Err(TunnelError::PinMismatch);
        }
        let cookie = session.cookie.expose();
        logs.log(LogLevel::Debug, &format!("Cookie: webvpn={cookie}"));
        logs.log(LogLevel::Debug, &format!("> {cookie}"));
        if !state.session_alive || session.cookie != script.cookie {
            logs.log(LogLevel::Error, "The gateway refused the session");
            return Err(TunnelError::LoginNeeded);
        }
        if state.live.is_some() {
            // One tunnel at a time, like the service.
            return Err(TunnelError::Failed);
        }
        state.opened += 1;
        state.live = Some((state.opened, events));
        logs.log(LogLevel::Info, "CSTP connected");
        Ok(Box::new(FakeTunnel {
            number: state.opened,
            assigned: script.assigned.clone(),
            shared: Arc::clone(&self.shared),
        }))
    }
}

struct FakeTunnel {
    number: u64,
    assigned: Assigned,
    shared: Arc<Shared>,
}

impl Tunnel for FakeTunnel {
    fn assigned(&self) -> &Assigned {
        &self.assigned
    }

    fn close(&self, how: CloseMode) {
        let mut state = self.shared.lock();
        // A later tunnel from the same engine is not this one's to close.
        if state.live.as_ref().is_some_and(|(n, _)| *n == self.number) {
            if how == CloseMode::LogOff && state.log_off_ends_session {
                state.session_alive = false;
            }
            Shared::end(&mut state, TunnelEvent::Closed);
        }
    }
}

impl Drop for FakeTunnel {
    fn drop(&mut self) {
        self.close(CloseMode::KeepSession);
    }
}
