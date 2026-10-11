//! The VPN engine interface.
//!
//! An engine speaks the AnyConnect protocol to the gateway. This crate defines
//! what the rest of the workspace may ask of one. The `fake` module, behind
//! the `fake` Cargo feature, is a scripted engine for tests and for the
//! service's dev mode. The real engine, a binding to `libopenconnect`, will
//! live behind the `libopenconnect` feature. That feature is off by default
//! and enables nothing yet, so ordinary builds and tests need no native
//! library.
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
//! [`Gateway`], [`Prompts`] and [`LogSink`] each live in a file of their own
//! with private fields, so not even code inside this crate can get round
//! them. No engine may ever be added to those three files.
//!
//! - **Pins.** Both capabilities take a [`Gateway`], which cannot exist
//!   without a valid host name and at least one pin. There is no way to
//!   accept any certificate.
//! - **No blind retries.** An engine can reach the user only through
//!   [`Prompts`], which refuses to ask for the username or the password a
//!   second time and reports [`LoginError::WrongPassword`] instead.
//! - **Secrets.** Cookies and answers are [`Secret`]s. Errors and events are
//!   `Copy` enums, so they cannot own text and cannot carry a secret. Log
//!   lines reach the caller only through [`LogSink`], which filters them by
//!   level, removes registered secrets and redacts what is left.
//! - **Session expiry.** A tunnel that the gateway ends or refuses reports
//!   "login needed", which is distinct from a network failure. Nothing on the
//!   tunnel side can prompt, so it cannot log in again.
//!
//! # Rules for the real engine
//!
//! The fake cannot enforce these. The `libopenconnect` binding must:
//!
//! **Process and library setup**
//!
//! - Clear `SSLKEYLOGFILE`, `GNUTLS_SYSTEM_PRIORITY_FILE` and
//!   `GNUTLS_DEBUG_LEVEL` from the environment of the privileged process
//!   before the library is first used. GnuTLS honours all three.
//! - Never set a vpnc-script, a CSD wrapper or a proxy. The tunnel device is
//!   created with a null script; routes and DNS belong to the service.
//! - Disable IPv6 in the library (`openconnect_disable_ipv6`). v0.1.0 is IPv4
//!   only.
//! - Never enable a software-token mode, an external-browser or
//!   single-sign-on login, or a client certificate.
//! - Let one thread own the library handle and make every library call on
//!   it. Other threads touch only the command pipe.
//!
//! **Certificates**
//!
//! - Turn system trust off (`openconnect_set_system_trust(v, 0)`) and make the
//!   pin check the only judge: the certificate callback accepts a peer only
//!   when its `pin-sha256:` hash satisfies [`Gateway::accepts`], and anything
//!   else is a pin mismatch. Do not hand pins to the library for matching; it
//!   accepts prefixes.
//! - Reject inside the certificate callback, so that nothing, the cookie
//!   least of all, is sent before the pin check has passed.
//!
//! **Login**
//!
//! - Map form fields to prompt kinds by field type and name: the text
//!   field named `username` is the username; the password field named
//!   `password` is the password; any other password field, and any field the
//!   library flags as second authentication, is a one-time code; any other
//!   text field is free text. Skip hidden and ignored fields. Put the form's
//!   message or error text in [`Prompt::message`].
//! - Treat a form shown again with its error set as a rejection: ask again
//!   through [`Prompts::ask`], which stops the login, and never answer from
//!   memory. Fill each field from one `ask` call and keep no copy of the
//!   answer.
//! - Fail with [`LoginError::Failed`] on a form that needs a choice of group
//!   or realm. UBC selects the MFA method through the username, so group
//!   selection is out of scope for v0.1.0.
//! - Register an [`on_cancel`](Cancel::on_cancel) hook that writes the
//!   library's cancel command to the command pipe, so a login waiting for an
//!   MFA approval stops at once.
//!
//! **Tunnel**
//!
//! - Treat [`Session::gateway_addr`] as untrusted: it comes from an
//!   unprivileged program. Call [`check_gateway_addr`] before anything else.
//!   Reach the address through the library's address-resolution override
//!   while still using the policy's host name for TLS and HTTP, never
//!   through a URL built from client input. After connecting, check that the
//!   address the tunnel is connected to equals the session's and report it in
//!   [`Assigned::gateway_addr`].
//! - Make the tunnel side's own auth-form callback cancel. A gateway that
//!   answers a cookie with a login form has refused the session, which is
//!   [`TunnelError::LoginNeeded`].
//! - Stop with the command that matches the [`CloseMode`]: the cancel command
//!   (`OC_CMD_CANCEL`) for [`CloseMode::LogOff`], which logs the session off
//!   at the gateway, and the detach command (`OC_CMD_DETACH`) for
//!   [`CloseMode::KeepSession`], which leaves the cookie valid.
//! - Bound the library's own silent reconnects with a short reconnect
//!   timeout in the main loop, so a dead tunnel is reported as
//!   [`TunnelEvent::ConnectionLost`] and not hidden. A reconnect the gateway
//!   refuses is [`TunnelEvent::LoginNeeded`].
//! - Never retry after a pin mismatch or a refused session, and never try to
//!   log in.
//!
//! **Logs**
//!
//! - Send every line the library logs through [`LogSink::log`] and nowhere
//!   else, and register the cookie and each answer with [`LogSink::hide`] as
//!   soon as it is held. The library logs the session cookie at debug level,
//!   so its debug output is dropped in release builds (see
//!   [`DEBUG_LINES`]), and the library must never be asked to dump request
//!   or response bodies.

#![cfg_attr(not(feature = "libopenconnect"), forbid(unsafe_code))]

use std::fmt;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, PoisonError};

use ubc_vpn_core::login::LoginErrorCode;
use ubc_vpn_core::protocol::ErrorCode;
use ubc_vpn_core::redact::Secret;
use ubc_vpn_core::routes::Ipv4Net;

#[cfg(any(test, feature = "fake"))]
pub mod fake;
mod gateway;
mod log;
mod prompts;
#[cfg(test)]
mod tests;

pub use gateway::Gateway;
pub use log::{DEBUG_LINES, LogLevel, LogSink};
pub use prompts::{Prompt, Prompts};

type Hook = Box<dyn Fn() + Send + Sync>;

#[derive(Default)]
struct CancelState {
    cancelled: AtomicBool,
    hooks: Mutex<Vec<Hook>>,
}

/// Lets another thread stop one login or one tunnel opening that is in
/// progress. Clones share one flag. Make a new one for every call.
#[derive(Clone, Default)]
pub struct Cancel(Arc<CancelState>);

impl Cancel {
    /// A flag that is not yet set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Asks the call to stop. Safe from any thread, any number of times. The
    /// call then returns `Cancelled` promptly, without waiting on the
    /// gateway.
    pub fn cancel(&self) {
        let hooks = self.hooks();
        if !self.0.cancelled.swap(true, Ordering::SeqCst) {
            hooks.iter().for_each(|hook| hook());
        }
    }

    /// For engines: whether the caller asked to stop.
    pub fn is_cancelled(&self) -> bool {
        self.0.cancelled.load(Ordering::SeqCst)
    }

    /// For engines: runs `hook` once when the caller cancels, on the
    /// cancelling thread, or at once if that has already happened. An engine
    /// blocked inside its library uses this to wake itself, with no polling.
    /// The hook must be quick and must not call back into this `Cancel`.
    pub fn on_cancel(&self, hook: impl Fn() + Send + Sync + 'static) {
        let mut hooks = self.hooks();
        if self.is_cancelled() {
            drop(hooks);
            hook();
        } else {
            hooks.push(Box::new(hook));
        }
    }

    fn hooks(&self) -> std::sync::MutexGuard<'_, Vec<Hook>> {
        self.0.hooks.lock().unwrap_or_else(PoisonError::into_inner)
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
    ///
    /// On the tunnel side this value arrives from an unprivileged program
    /// and is a hint, not authority: see [`check_gateway_addr`].
    pub gateway_addr: Ipv4Addr,
}

/// Why a login failed. None of these is retried by the engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginError {
    /// The gateway rejected the login: it asked again for something already
    /// answered. Nothing was sent twice.
    ///
    /// This also covers a rejected one-time code, because the gateway simply
    /// shows the form again and does not say which answer was wrong. Use
    /// [`Prompts::asked`] to tell whether a code was involved.
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
pub trait LoginEngine: Send + Sync {
    /// Logs in to `gateway` and returns the session.
    ///
    /// Blocks until the login succeeds, fails or is cancelled, either by the
    /// prompt callback returning `None` or through `cancel`. The gateway is
    /// checked against the pins before anything is asked or sent. Each answer
    /// is sent to the gateway at most once. A cancelled login never returns
    /// a session.
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
    /// The gateway address the tunnel is connected to, always equal to the
    /// session's. The service routes this one address through the physical
    /// network.
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
    /// The gateway's key matched none of the service's pins. Nothing was
    /// sent to it.
    PinMismatch,
    /// The gateway refused the session cookie. The user must log in again.
    LoginNeeded,
    /// The gateway could not be reached.
    GatewayUnreachable,
    /// The caller cancelled. No device was left behind.
    Cancelled,
    /// The session's gateway address is not one a gateway can have. Nothing
    /// was contacted.
    BadAddress,
    /// Anything else, such as the tunnel device not being created.
    Failed,
}

impl fmt::Display for TunnelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::PinMismatch => "The gateway's certificate is not the expected one.",
            Self::LoginNeeded => "The session is no longer valid. Log in again.",
            Self::GatewayUnreachable => "The gateway could not be reached.",
            Self::Cancelled => "Connecting was cancelled.",
            Self::BadAddress => "The gateway address is not a usable address.",
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
            TunnelError::BadAddress => Self::BadRequest,
            // Moves to `ErrorCode::GatewayUnreachable` once core has it.
            TunnelError::GatewayUnreachable => Self::EngineFailed,
            // The service cancels its own connect and normally reports
            // "disconnected" instead of an error.
            TunnelError::Cancelled | TunnelError::Failed => Self::EngineFailed,
        }
    }
}

/// Checks a gateway address that came from an unprivileged client before
/// anything connects to it. Every tunnel engine calls this first.
///
/// It refuses addresses no gateway can have: the "this network" block
/// (`0.0.0.0/8`), loopback, link-local, multicast and broadcast. Such an
/// address could point the privileged service at a local program. Whatever
/// passes still has to present a pinned key before the cookie is sent.
pub fn check_gateway_addr(addr: Ipv4Addr) -> Result<(), TunnelError> {
    let bad = addr.octets()[0] == 0
        || addr.is_loopback()
        || addr.is_link_local()
        || addr.is_multicast()
        || addr.is_broadcast();
    if bad {
        Err(TunnelError::BadAddress)
    } else {
        Ok(())
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

/// What closing a tunnel does to the session at the gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseMode {
    /// Log the session off. The cookie stops working. For when the user
    /// disconnects.
    LogOff,
    /// Detach and leave the session alive, so the same cookie can open a new
    /// tunnel. For teardown before a reconnect, such as after sleep or a
    /// network change.
    KeepSession,
}

/// Opening tunnels. Used by the privileged service.
pub trait TunnelEngine: Send + Sync {
    /// Connects to the gateway with the session's cookie and creates the
    /// tunnel device, running no script and changing no routes or DNS.
    ///
    /// `gateway` must come from the service's own policy, never from a
    /// client. The session does come from a client: its address is checked
    /// with [`check_gateway_addr`] before anything is contacted, and the
    /// cookie is sent only after the gateway's key has matched a pin.
    ///
    /// Blocks until the device exists, opening fails, or `cancel` stops it.
    /// On success the engine has started a thread of its own that runs the
    /// tunnel until it ends. That thread sends the tunnel's one
    /// [`TunnelEvent`] on `events`; no event is sent when opening fails.
    fn open(
        &self,
        gateway: &Gateway,
        session: &Session,
        cancel: &Cancel,
        events: Sender<TunnelEvent>,
        logs: LogSink,
    ) -> Result<Box<dyn Tunnel>, TunnelError>;
}

/// An open tunnel. Dropping it closes it with [`CloseMode::KeepSession`].
pub trait Tunnel: Send + Sync {
    /// What the gateway assigned. Fixed for the life of the tunnel.
    fn assigned(&self) -> &Assigned;

    /// Closes the tunnel and removes its device.
    ///
    /// Safe from any thread and more than once. Only the first call on a
    /// live tunnel does anything: it decides the mode and causes
    /// [`TunnelEvent::Closed`]. On a tunnel that has already ended it sends
    /// nothing. Every call, and a drop, returns only after the engine's
    /// tunnel thread has ended and the device is gone, so the caller may
    /// clean up routes or open a new tunnel straight away.
    fn close(&self, how: CloseMode);
}
