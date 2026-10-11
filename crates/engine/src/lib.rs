//! The VPN engine interface.
//!
//! An engine speaks the AnyConnect protocol to the gateway. This crate defines
//! what the rest of the workspace may ask of one, and [`fake`] provides a
//! scripted engine for tests and for the service's dev mode. The real engine,
//! a binding to `libopenconnect`, will live behind the `libopenconnect` Cargo
//! feature. That feature is off by default and enables nothing yet, so
//! ordinary builds and tests need no native library.
//!
//! There are two capabilities, because they run in two processes:
//!
//! - [`LoginEngine`], for the unprivileged command-line client. It asks the
//!   user what the gateway wants to know and returns a [`Session`].
//! - [`TunnelEngine`], for the privileged service. It turns a [`Session`] into
//!   a tunnel device and reports what the gateway assigned. It never sees a
//!   password and never logs in.
//!
//! All calls block, and nothing here needs an async runtime.
//!
//! # What the types enforce
//!
//! - **Pins.** Both capabilities take a [`Gateway`], which cannot exist
//!   without at least one pin. There is no way to accept any certificate.
//! - **No blind retries.** An engine can reach the user only through
//!   [`Prompts`], which refuses to ask for the username or the password a
//!   second time and reports [`LoginError::WrongPassword`] instead.
//! - **Secrets.** Cookies and answers are [`Secret`]s. Errors and events are
//!   plain enums with no data, so they cannot carry one. Log lines reach the
//!   caller only through [`LogSink`], which redacts and filters them.
//! - **Session expiry.** A tunnel that the gateway ends or refuses reports
//!   "login needed", which is distinct from a network failure. Nothing on the
//!   tunnel side can prompt, so it cannot log in again.
//!
//! # Rules for the real engine
//!
//! The fake cannot enforce these. The `libopenconnect` binding must:
//!
//! - Turn system trust off (`openconnect_set_system_trust(v, 0)`) and make the
//!   pin check the only judge: the certificate callback accepts a peer only
//!   when its `pin-sha256:` hash equals one of the [`Gateway`]'s pins, compared
//!   in full, and anything else is a pin mismatch. Do not hand pins to the
//!   library for matching; it accepts prefixes.
//! - For a tunnel, connect to [`Session::gateway_addr`] and accept only
//!   [`Session::pin`], and only if the service's own [`Gateway`] lists it. Both
//!   fields come from an unprivileged program and are hints, not authority.
//! - Never set a vpnc-script, a CSD wrapper or a proxy. The tunnel device is
//!   created with a null script; routes and DNS belong to the service.
//! - Clear `SSLKEYLOGFILE`, `GNUTLS_SYSTEM_PRIORITY_FILE` and
//!   `GNUTLS_DEBUG_LEVEL` from the environment of the privileged process
//!   before the library is first used. GnuTLS honours all three.
//! - Fill each form field from one [`Prompts::ask`] call and keep no copy of
//!   the answer. When the library shows a form again, ask again; never answer
//!   from memory.
//! - Send every line the library logs through [`LogSink::log`] and nowhere
//!   else. The library logs the session cookie at debug level, so its debug
//!   output must be dropped in release builds ([`LogSink`] does this), and it
//!   must never be asked to dump request or response bodies.
//! - Never retry after a pin mismatch or a rejected login, and never try to
//!   log in again from the tunnel side.
//! - Stay inside v0.1.0: IPv4 only, no external-browser login, no client
//!   certificates.

#![cfg_attr(not(feature = "libopenconnect"), forbid(unsafe_code))]

use std::fmt;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;

use ubc_vpn_core::login::{LoginErrorCode, PromptKind};
use ubc_vpn_core::policy::{Pin, Policy, PolicyError};
use ubc_vpn_core::protocol::ErrorCode;
use ubc_vpn_core::redact::{Secret, redact_line};
use ubc_vpn_core::routes::Ipv4Net;

pub mod fake;

/// The gateway an engine may talk to: a host name and the pins that identify
/// it. It always holds at least one pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gateway {
    host: String,
    pins: Vec<Pin>,
}

impl Gateway {
    /// Takes the gateway from a policy, refusing a policy that is not valid.
    /// This is the only way to make one, so an engine is never called with a
    /// bad host name or without pins.
    pub fn from_policy(policy: &Policy) -> Result<Self, PolicyError> {
        policy.validate()?;
        Ok(Self {
            host: policy.gateway.clone(),
            pins: policy.pins.clone(),
        })
    }

    /// The gateway's host name.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The pins the gateway's key may match. Never empty.
    pub fn pins(&self) -> &[Pin] {
        &self.pins
    }

    /// Whether `key`, the hash of the key a server presented, matches a pin.
    /// An engine must refuse a server for which this is false.
    pub fn accepts(&self, key: &Pin) -> bool {
        self.pins.contains(key)
    }
}

/// How serious a log line is. Ordered from least to most detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    /// Something failed.
    Error,
    /// Normal progress.
    Info,
    /// Protocol detail. Never delivered in release builds.
    Debug,
}

/// Where an engine's log lines go.
///
/// The caller may rely on every line it receives having been through
/// [`redact_line`] and being no more detailed than the level it asked for. In
/// release builds debug lines are dropped whatever was asked for, because the
/// library's debug output holds the session cookie.
#[derive(Clone)]
pub struct LogSink {
    max: LogLevel,
    write: Arc<LogFn>,
}

type LogFn = dyn Fn(LogLevel, &str) + Send + Sync;

impl LogSink {
    /// Delivers lines up to and including `max` to `write`, one line per call.
    pub fn new(max: LogLevel, write: impl Fn(LogLevel, &str) + Send + Sync + 'static) -> Self {
        let max = if cfg!(debug_assertions) {
            max
        } else {
            max.min(LogLevel::Info)
        };
        Self {
            max,
            write: Arc::new(write),
        }
    }

    /// A sink that throws everything away.
    pub fn none() -> Self {
        Self::new(LogLevel::Error, |_, _| {})
    }

    /// For engines: reports raw output. It is split into lines, filtered by
    /// level and redacted before the caller sees it.
    pub fn log(&self, level: LogLevel, text: &str) {
        if level <= self.max {
            for line in text.lines() {
                (self.write)(level, &redact_line(line));
            }
        }
    }
}

/// A question the gateway asks during login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prompt {
    /// What kind of answer is wanted.
    pub kind: PromptKind,
    /// The gateway's wording.
    pub label: String,
}

/// The engine's only way to ask the user something during login.
///
/// It wraps the caller's callback and enforces the no-retry rule: the username
/// and the password are each asked for at most once. A gateway that asks for
/// either again has rejected the login, so the second request does not reach
/// the caller and fails with [`LoginError::WrongPassword`]. One-time codes and
/// free text may be asked for again; each is typed afresh by the user.
pub struct Prompts<'a> {
    ask: &'a mut dyn FnMut(&Prompt) -> Option<Secret>,
    asked: Vec<PromptKind>,
}

impl<'a> Prompts<'a> {
    /// Wraps the caller's callback. The callback returns the user's answer,
    /// or `None` to cancel the login.
    pub fn new(ask: &'a mut dyn FnMut(&Prompt) -> Option<Secret>) -> Self {
        Self {
            ask,
            asked: Vec::new(),
        }
    }

    /// For engines: asks the user one question. An error must be returned
    /// from the login as it is, without contacting the gateway again.
    pub fn ask(&mut self, kind: PromptKind, label: &str) -> Result<Secret, LoginError> {
        let once_only = matches!(kind, PromptKind::Username | PromptKind::Password);
        if once_only && self.asked.contains(&kind) {
            return Err(LoginError::WrongPassword);
        }
        self.asked.push(kind);
        let prompt = Prompt {
            kind,
            label: label.to_string(),
        };
        (self.ask)(&prompt).ok_or(LoginError::Cancelled)
    }
}

/// Lets another thread stop a login that is in progress, for example while
/// it waits for an MFA approval. Clones share one flag.
#[derive(Debug, Clone, Default)]
pub struct Cancel(Arc<AtomicBool>);

impl Cancel {
    /// A flag that is not yet set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Asks the login to stop. Safe to call from any thread, any number of
    /// times.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// For engines: whether the caller asked to stop.
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// What a successful login yields. The whole value is secret-bearing: its
/// `Debug` output hides the cookie, and it has no `Display`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    /// The session cookie the gateway issued.
    pub cookie: Secret,
    /// The address the login actually connected to. A host name may resolve
    /// to several gateways, and the cookie is only good at this one.
    pub gateway_addr: Ipv4Addr,
    /// The pin the gateway's key matched during login.
    pub pin: Pin,
}

/// Why a login failed. None of these is retried by the engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginError {
    /// The gateway rejected the credentials: it asked again for something
    /// already answered. Nothing was sent twice.
    WrongPassword,
    /// The gateway's key matched none of the pins. Nothing was sent to it.
    PinMismatch,
    /// The caller cancelled.
    Cancelled,
    /// The gateway could not be reached.
    GatewayUnreachable,
    /// Anything else, such as a login step this client does not support.
    Failed,
}

impl fmt::Display for LoginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::WrongPassword => "The gateway rejected the username, password or code.",
            Self::PinMismatch => {
                "The gateway's certificate is not the expected one. Nothing was sent to it."
            }
            Self::Cancelled => "Login was cancelled.",
            Self::GatewayUnreachable => "The gateway could not be reached.",
            Self::Failed => "Login failed unexpectedly.",
        })
    }
}

impl std::error::Error for LoginError {}

impl From<LoginError> for LoginErrorCode {
    fn from(e: LoginError) -> Self {
        match e {
            LoginError::WrongPassword => Self::WrongPassword,
            LoginError::PinMismatch => Self::PinMismatch,
            LoginError::Cancelled => Self::Cancelled,
            LoginError::GatewayUnreachable => Self::GatewayUnreachable,
            LoginError::Failed => Self::Internal,
        }
    }
}

/// Logging in. Used by the unprivileged command-line client.
pub trait LoginEngine {
    /// Logs in to `gateway` and returns the session.
    ///
    /// Blocks until the login succeeds, fails or is cancelled, either by the
    /// prompt callback returning `None` or through `cancel`. The gateway is
    /// checked against the pins before anything is asked or sent. Each answer
    /// is sent to the gateway at most once.
    fn login(
        &self,
        gateway: &Gateway,
        prompts: &mut Prompts<'_>,
        cancel: &Cancel,
        logs: &LogSink,
    ) -> Result<Session, LoginError>;
}

/// What the gateway assigned to a tunnel. Nothing here has been applied to
/// the system except the device itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assigned {
    /// The tunnel device's name, such as `utun4`.
    pub interface: String,
    /// This machine's address inside the tunnel.
    pub address: Ipv4Addr,
    /// The netmask that goes with `address`.
    pub netmask: Ipv4Addr,
    /// The gateway address the tunnel is connected to. The service routes
    /// this one address through the physical network.
    pub gateway_addr: Ipv4Addr,
    /// The DNS servers the gateway offers.
    pub dns: Vec<Ipv4Addr>,
    /// The largest packet the tunnel carries.
    pub mtu: u16,
    /// The routes the gateway asked to have tunnelled. Advice only: the
    /// service routes what the user chose. Empty means "everything".
    pub split_includes: Vec<Ipv4Net>,
}

/// Why a tunnel could not be opened. The engine retries none of these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelError {
    /// The gateway's key did not match the session's pin, or that pin is not
    /// in the service's policy.
    PinMismatch,
    /// The gateway refused the session cookie. The user must log in again.
    LoginNeeded,
    /// The gateway could not be reached.
    GatewayUnreachable,
    /// Anything else, such as the tunnel device not being created.
    Failed,
}

impl fmt::Display for TunnelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::PinMismatch => "The gateway's certificate is not the expected one.",
            Self::LoginNeeded => "The session is no longer valid. Log in again.",
            Self::GatewayUnreachable => "The gateway could not be reached.",
            Self::Failed => "The tunnel could not be opened.",
        })
    }
}

impl std::error::Error for TunnelError {}

impl From<TunnelError> for ErrorCode {
    fn from(e: TunnelError) -> Self {
        match e {
            TunnelError::PinMismatch => Self::PinMismatch,
            TunnelError::LoginNeeded => Self::LoginNeeded,
            TunnelError::GatewayUnreachable | TunnelError::Failed => Self::EngineFailed,
        }
    }
}

/// How an open tunnel ended. Exactly one is sent per tunnel, and nothing
/// follows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelEvent {
    /// The caller closed it.
    Closed,
    /// The gateway ended or refused the session. The user must log in again;
    /// the engine does not.
    LoginNeeded,
    /// The connection to the gateway was lost for a network reason. The
    /// session may still be good.
    ConnectionLost,
}

/// Opening tunnels. Used by the privileged service.
pub trait TunnelEngine {
    /// Connects to the gateway with the session's cookie and creates the
    /// tunnel device, running no script and changing no routes or DNS.
    ///
    /// `gateway` must come from the service's own policy, never from a
    /// client. Blocks until the device exists or opening fails. After that
    /// the tunnel runs by itself until it ends, and says how on `events`.
    fn open(
        &self,
        gateway: &Gateway,
        session: &Session,
        events: Sender<TunnelEvent>,
        logs: LogSink,
    ) -> Result<Box<dyn Tunnel>, TunnelError>;
}

/// An open tunnel. Dropping it closes it.
pub trait Tunnel: Send + Sync {
    /// What the gateway assigned. Fixed for the life of the tunnel.
    fn assigned(&self) -> &Assigned;

    /// Closes the tunnel and removes its device. Safe to call from any
    /// thread and more than once; only the first call on a live tunnel does
    /// anything, and it sends [`TunnelEvent::Closed`].
    fn close(&self);
}
