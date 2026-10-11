//! A scripted engine for tests and for the service's dev mode.
//!
//! A [`Script`] describes a pretend gateway: the key it presents, the
//! questions it asks and the answers it accepts, the cookie it issues and
//! what it assigns to a tunnel. [`FakeEngine`] plays that gateway through the
//! real interfaces, so the outcome follows from what the caller does:
//!
//! - a wrong answer makes the gateway ask the same question again, as a real
//!   one does, and a second wrong answer ends the login;
//! - a key that matches none of the caller's pins is a pin mismatch;
//! - a cookie other than the scripted one means "login needed".
//!
//! Like `libopenconnect`, it writes the cookie to its debug log, so callers'
//! log handling can be tested against it. It talks to no network.

use std::net::Ipv4Addr;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use ubc_vpn_core::login::PromptKind;
use ubc_vpn_core::policy::Pin;
use ubc_vpn_core::redact::Secret;

use crate::{
    Assigned, Cancel, Gateway, LogLevel, LogSink, LoginEngine, LoginError, Prompt, Prompts,
    Session, Tunnel, TunnelEngine, TunnelError, TunnelEvent,
};

/// What the pretend gateway does. Every field may be changed before the
/// script is given to [`FakeEngine::new`].
#[derive(Debug, Clone)]
pub struct Script {
    /// The hash of the key the gateway presents.
    pub key: Pin,
    /// Whether the gateway answers at all.
    pub reachable: bool,
    /// The questions asked at login, in order, each with the one answer the
    /// gateway accepts.
    pub form: Vec<(Prompt, String)>,
    /// The cookie a successful login yields, and the only one a tunnel
    /// accepts.
    pub cookie: Secret,
    /// What a tunnel is given. Its `gateway_addr` is where the gateway lives.
    pub assigned: Assigned,
}

impl Script {
    /// A reachable gateway presenting `key`. It asks for a username (`alice`)
    /// and a password (`correct-password`), and assigns made-up values.
    pub fn new(key: Pin) -> Self {
        let ask = |kind, label: &str, accepted: &str| {
            let label = label.to_string();
            (Prompt { kind, label }, accepted.to_string())
        };
        Self {
            key,
            reachable: true,
            form: vec![
                ask(PromptKind::Username, "Username", "alice"),
                ask(PromptKind::Password, "Password", "correct-password"),
            ],
            cookie: Secret::new("fake-cookie-0123456789"),
            assigned: Assigned {
                interface: "fake0".to_string(),
                address: Ipv4Addr::new(10, 255, 0, 2),
                netmask: Ipv4Addr::new(255, 255, 255, 0),
                gateway_addr: Ipv4Addr::new(192, 0, 2, 1),
                dns: vec![Ipv4Addr::new(10, 255, 0, 53)],
                mtu: 1300,
                split_includes: Vec::new(),
            },
        }
    }
}

#[derive(Default)]
struct State {
    answers: Vec<(PromptKind, Secret)>,
    /// The event channel of the tunnel that is open, if any.
    live: Option<Sender<TunnelEvent>>,
}

/// Ends the open tunnel, if there is one, and says why. Taking the sender
/// out is what makes a tunnel report exactly one ending.
fn end(state: &Mutex<State>, event: TunnelEvent) {
    if let Some(events) = lock(state).live.take() {
        // The receiver may be gone; there is then nobody to tell.
        let _ = events.send(event);
    }
}

fn lock(state: &Mutex<State>) -> MutexGuard<'_, State> {
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

/// An engine that plays a [`Script`]. Clones share their record and their
/// open tunnel, so a test can keep one clone and give the other away.
#[derive(Clone)]
pub struct FakeEngine {
    script: Script,
    state: Arc<Mutex<State>>,
}

impl FakeEngine {
    /// An engine for the gateway `script` describes.
    pub fn new(script: Script) -> Self {
        Self {
            script,
            state: Arc::default(),
        }
    }

    /// Every answer the gateway was sent, in order.
    pub fn answers(&self) -> Vec<(PromptKind, Secret)> {
        lock(&self.state).answers.clone()
    }

    /// Whether a tunnel is open.
    pub fn tunnel_is_open(&self) -> bool {
        lock(&self.state).live.is_some()
    }

    /// Ends the open tunnel as the gateway or the network would, with
    /// [`TunnelEvent::LoginNeeded`] or [`TunnelEvent::ConnectionLost`]. Does
    /// nothing when no tunnel is open.
    pub fn end_tunnel(&self, event: TunnelEvent) {
        end(&self.state, event);
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
        if !script.reachable {
            logs.log(LogLevel::Error, "Failed to connect to the gateway");
            return Err(LoginError::GatewayUnreachable);
        }
        if !gateway.accepts(&script.key) {
            logs.log(LogLevel::Error, "Server certificate matches no pin");
            return Err(LoginError::PinMismatch);
        }
        for (prompt, accepted) in &script.form {
            let mut correct = false;
            // The second pass is the gateway asking again after a wrong
            // answer. `Prompts` stops it for a username or a password.
            for _ in 0..2 {
                if correct {
                    break;
                }
                if cancel.is_cancelled() {
                    return Err(LoginError::Cancelled);
                }
                let answer = prompts.ask(prompt.kind, &prompt.label)?;
                correct = answer.expose() == accepted;
                lock(&self.state).answers.push((prompt.kind, answer));
            }
            if !correct {
                return Err(LoginError::WrongPassword);
            }
        }
        if cancel.is_cancelled() {
            return Err(LoginError::Cancelled);
        }
        // What the real library does at debug level.
        let cookie = script.cookie.expose();
        logs.log(LogLevel::Debug, &format!("Set-Cookie: webvpn={cookie}"));
        logs.log(LogLevel::Info, "Login succeeded");
        Ok(Session {
            cookie: script.cookie.clone(),
            gateway_addr: script.assigned.gateway_addr,
            pin: script.key.clone(),
        })
    }
}

impl TunnelEngine for FakeEngine {
    fn open(
        &self,
        gateway: &Gateway,
        session: &Session,
        events: Sender<TunnelEvent>,
        logs: LogSink,
    ) -> Result<Box<dyn Tunnel>, TunnelError> {
        let script = &self.script;
        if !script.reachable || session.gateway_addr != script.assigned.gateway_addr {
            return Err(TunnelError::GatewayUnreachable);
        }
        if !gateway.accepts(&session.pin) || session.pin != script.key {
            logs.log(LogLevel::Error, "Server certificate matches no pin");
            return Err(TunnelError::PinMismatch);
        }
        let cookie = session.cookie.expose();
        logs.log(LogLevel::Debug, &format!("Cookie: webvpn={cookie}"));
        if session.cookie != script.cookie {
            logs.log(LogLevel::Error, "The gateway refused the session");
            return Err(TunnelError::LoginNeeded);
        }
        let mut state = lock(&self.state);
        if state.live.is_some() {
            // One tunnel at a time, like the service.
            return Err(TunnelError::Failed);
        }
        state.live = Some(events);
        drop(state);
        logs.log(LogLevel::Info, "CSTP connected");
        Ok(Box::new(FakeTunnel {
            assigned: script.assigned.clone(),
            state: Arc::clone(&self.state),
        }))
    }
}

struct FakeTunnel {
    assigned: Assigned,
    state: Arc<Mutex<State>>,
}

impl Tunnel for FakeTunnel {
    fn assigned(&self) -> &Assigned {
        &self.assigned
    }

    fn close(&self) {
        end(&self.state, TunnelEvent::Closed);
    }
}

impl Drop for FakeTunnel {
    fn drop(&mut self) {
        self.close();
    }
}
