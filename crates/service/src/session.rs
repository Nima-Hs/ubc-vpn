//! The connection state machine.
//!
//! One worker thread owns the tunnel and everything applied for it, and takes
//! one command at a time, so setup, teardown and the tunnel's own ending can
//! never overlap. Requests are admitted on the caller's thread: they are
//! validated, refused with `busy` while another is in progress, and answered
//! at once; progress follows as state events.
//!
//! The worker fails closed on its own bugs too: a panic while it handles a
//! command is caught, everything is torn down, and the state is `failed`.

use std::net::Ipv4Addr;
use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use ubc_vpn_core::policy::Policy;
use ubc_vpn_core::protocol::{
    ConnectParams, ErrorCode, ErrorInfo, LastError, LogLevel, is_plausible_cookie,
    is_plausible_gateway_addr,
};
use ubc_vpn_core::routes::Ipv4Net;
use ubc_vpn_core::state::ConnState;
use ubc_vpn_engine::{Cancel, Gateway, Tunnel, TunnelEngine, TunnelEvent};
use ubc_vpn_platform::{Dns, NetworkEvent, NetworkEvents, PhysicalNetwork, Platform, Routes};

use crate::diagnostics::failure;
use crate::hub::Hub;
use crate::logs::Held;
use crate::words::{counted, word};
use crate::{Logs, lock};

/// Builds the error a request is refused with.
pub(crate) fn error(code: ErrorCode, message: impl Into<String>) -> ErrorInfo {
    let message = message.into();
    ErrorInfo { code, message }
}

#[derive(PartialEq)]
enum Phase {
    Idle,
    Connecting,
    Connected,
    Stopping,
}

/// What decides whether a request is admitted.
struct Gate {
    phase: Phase,
    /// Stops the connect in progress, if there is one.
    cancel: Cancel,
}

enum Command {
    /// With the hold that keeps its cookie out of the log.
    Connect(ConnectParams, Cancel, Held),
    Disconnect,
    /// The OS reported this about the network watched by the subscription
    /// with this number.
    Network(u64, NetworkEvent),
    /// The tunnel with this number ended by itself.
    Ended(u64, TunnelEvent),
    Shutdown,
}

/// What the lines about the connection's state are about, for the repeat
/// rule.
const STATE: &str = "the connection's state";

/// What is applied to the system right now, as far as setup got. Teardown
/// works from this, so it is filled in before each step is attempted.
#[derive(Default)]
pub(crate) struct Applied {
    pub(crate) physical: Option<PhysicalNetwork>,
    pub(crate) tunnel: Option<Box<dyn Tunnel>>,
    pub(crate) gateway_route: Option<Ipv4Addr>,
    /// Everything routed through the tunnel: the chosen subnets and the
    /// DNS servers.
    pub(crate) routes: Vec<Ipv4Net>,
}

/// The worker's side: the only code that touches the tunnel, routes and DNS.
pub(crate) struct Machine {
    pub(crate) routes: Arc<dyn Routes>,
    pub(crate) dns: Arc<dyn Dns>,
    pub(crate) events: Arc<dyn NetworkEvents>,
    pub(crate) engine: Arc<dyn TunnelEngine>,
    /// From the service's own policy. No request can change it.
    pub(crate) gateway: Option<Gateway>,
    pub(crate) logs: Logs,
    pub(crate) applied: Applied,
    /// Keeps the cookie of the connection in hand out of the log, from the
    /// moment its request is admitted until everything is torn down.
    pub(crate) hidden: Option<Held>,
    /// Whether the last state written to the log was `disconnected`. It is
    /// where the service starts.
    disconnected: bool,
    /// The number of the subscription that watches the network of the
    /// connection now, or 0 when there is none. A subscription with any
    /// other number forwards nothing and ends.
    pub(crate) watching: Arc<AtomicU64>,
    /// Ends the subscription that watches the network of the connection now.
    /// Dropped at teardown, which ends it at once.
    pub(crate) network_watch: Option<ubc_vpn_platform::SubscriptionEnd>,
    /// Counts tunnels, so an ending is matched to the tunnel it came from.
    tunnels: u64,
    /// Counts subscriptions to network events. Every attempt gets a number
    /// of its own, whether or not its tunnel opened.
    subscriptions: u64,
    hub: Arc<Hub>,
    gate: Arc<Mutex<Gate>>,
    commands: Sender<Command>,
}

/// The requests' side of the state machine.
pub(crate) struct Session {
    /// The policy's allow-list, or why the policy is unusable.
    allowed: Result<Option<Vec<Ipv4Net>>, String>,
    gate: Arc<Mutex<Gate>>,
    commands: Sender<Command>,
    worker: Mutex<Option<JoinHandle<()>>>,
    logs: Logs,
}

impl Session {
    pub(crate) fn start(
        platform: &Platform,
        engine: Arc<dyn TunnelEngine>,
        policy: Result<Policy, String>,
        hub: Arc<Hub>,
        logs: Logs,
    ) -> Result<Self, String> {
        let trusted = policy.and_then(|policy| {
            let gateway = Gateway::from_policy(&policy).map_err(|e| e.to_string())?;
            Ok((gateway, policy.allowed_routes))
        });
        let (gateway, allowed) = match trusted {
            Ok((gateway, allowed)) => (Some(gateway), Ok(allowed)),
            Err(message) => (None, Err(message)),
        };
        let (phase, cancel) = (Phase::Idle, Cancel::new());
        let gate = Arc::new(Mutex::new(Gate { phase, cancel }));
        let (commands, inbox) = mpsc::channel();
        let machine = Machine {
            routes: platform.routes.clone(),
            dns: platform.dns.clone(),
            events: platform.events.clone(),
            watching: Arc::default(),
            network_watch: None,
            engine,
            gateway,
            logs: logs.clone(),
            applied: Applied::default(),
            hidden: None,
            disconnected: true,
            tunnels: 0,
            subscriptions: 0,
            hub,
            gate: gate.clone(),
            commands: commands.clone(),
        };
        let worker = thread::Builder::new().spawn(move || machine.run(&inbox));
        let worker = worker.map_err(|e| format!("The service could not start a thread: {e}."))?;
        Ok(Self {
            allowed,
            gate,
            commands,
            worker: Mutex::new(Some(worker)),
            logs,
        })
    }

    /// Checks a connect request and hands it to the worker. Nothing is
    /// applied for a request that is refused here. A connect is admitted
    /// only when nothing is connected or in progress: to replace a
    /// connection the client disconnects first.
    ///
    /// Whether it was admitted is logged: with what it carries, counted, or
    /// with the code it was refused with. Nothing else from the request: it
    /// holds the cookie. An admitted one is logged before the worker has it,
    /// so that the line comes before any the connect leads to.
    pub(crate) fn connect(&self, params: ConnectParams) -> Result<(), ErrorInfo> {
        let routes = &params.routes;
        let carries = format!(
            "{} and {}",
            counted(routes.subnets.len(), "subnet"),
            counted(routes.dns_domains.len(), "DNS domain")
        );
        let admitted = self.admit(params, &carries);
        if let Err(refusal) = &admitted {
            let line = format!("connect refused: {}", word!(refusal.code));
            self.logs.about_requests(LogLevel::Warn, &line);
        }
        admitted
    }

    fn admit(&self, params: ConnectParams, carries: &str) -> Result<(), ErrorInfo> {
        let refused = |code, message: String| Err(error(code, message));
        let allowed = match &self.allowed {
            Ok(allowed) => allowed.as_deref(),
            Err(message) => return refused(ErrorCode::PolicyInvalid, message.clone()),
        };
        if let Err(why) = params.routes.check(allowed) {
            return refused(ErrorCode::RouteRefused, format!("Route refused: {why}."));
        }
        // The machine's own addresses and the networks it is on are known
        // only once the worker captures them, so `set_up` refuses those,
        // still before the gateway is contacted.
        if !is_plausible_gateway_addr(params.gateway_addr) {
            let message = "The gateway address is not a usable address.";
            return refused(ErrorCode::BadRequest, message.to_string());
        }
        // The cookie goes into a header this service sends. The message is
        // fixed text: it never holds the cookie.
        if !is_plausible_cookie(&params.cookie) {
            let message = "The session is not one a gateway could have issued.";
            return refused(ErrorCode::BadRequest, message.to_string());
        }
        let mut gate = lock(&self.gate);
        if gate.phase != Phase::Idle {
            return Err(busy());
        }
        *gate = Gate {
            phase: Phase::Connecting,
            cancel: Cancel::new(),
        };
        // Held from here on, before the request is anywhere a line could
        // be written about it.
        let hidden = self.logs.hold(&params.cookie);
        let line = format!("connect admitted ({carries})");
        self.logs.about_requests(LogLevel::Info, &line);
        self.send(Command::Connect(params, gate.cancel.clone(), hidden))
    }

    /// Asks the worker to tear everything down. One that arrives during a
    /// connect cancels it first. `said` is what kind of client the client
    /// said it was; when there was something to disconnect it is logged as
    /// that, since nothing checks it.
    pub(crate) fn disconnect(&self, said: &str) -> Result<(), ErrorInfo> {
        let mut gate = lock(&self.gate);
        match gate.phase {
            Phase::Stopping => return Err(busy()),
            Phase::Connecting => gate.cancel.cancel(),
            Phase::Idle | Phase::Connected => {}
        }
        if gate.phase != Phase::Idle {
            let line = format!("disconnect requested by a client that said it was {said}");
            self.logs.about_requests(LogLevel::Info, &line);
        }
        gate.phase = Phase::Stopping;
        self.send(Command::Disconnect)
    }

    /// Tears everything down and ends the worker. Used at shutdown.
    pub(crate) fn stop(&self) {
        lock(&self.gate).cancel.cancel();
        let _ = self.commands.send(Command::Shutdown);
        if let Some(worker) = lock(&self.worker).take() {
            let _ = worker.join();
        }
    }

    fn send(&self, command: Command) -> Result<(), ErrorInfo> {
        let stopped = |_| error(ErrorCode::Internal, "The service is shutting down.");
        self.commands.send(command).map_err(stopped)
    }
}

fn busy() -> ErrorInfo {
    let message = "The VPN is connected, or a connect or disconnect is in progress.";
    error(ErrorCode::Busy, message)
}

fn failed(code: ErrorCode, message: &str) -> ConnState {
    let message = message.to_string();
    ConnState::Failed { code, message }
}

impl Machine {
    fn run(mut self, inbox: &Receiver<Command>) {
        loop {
            // While a cookie waits to be wiped, the wait for a command ends
            // when its time is up, so that it is wiped with nothing asked.
            let command = match self.logs.wipe() {
                None => inbox.recv().ok(),
                Some(wait) => match inbox.recv_timeout(wait + Duration::from_millis(1)) {
                    Err(RecvTimeoutError::Timeout) => continue,
                    command => command.ok(),
                },
            };
            let Some(command) = command else { break };
            if matches!(command, Command::Shutdown) {
                break;
            }
            let handled = panic::catch_unwind(AssertUnwindSafe(|| self.handle(command)));
            if handled.is_err() {
                self.recover();
            }
        }
        // At shutdown too, a panic part-way must not be the end of it: what
        // the first attempt took in hand is closed by then, and a second
        // one runs the steps that need no memory of what was applied.
        if panic::catch_unwind(AssertUnwindSafe(|| self.teardown())).is_err() {
            self.logs
                .error("teardown panicked at shutdown; trying again");
            let _ = panic::catch_unwind(AssertUnwindSafe(|| self.teardown()));
        }
    }

    /// After a panic while handling a command, which is a bug somewhere in
    /// the service, the platform or the engine: removes everything, reports
    /// the failure and takes requests again. Without this the routes would
    /// stay applied and the state would say `connecting` for ever.
    fn recover(&mut self) {
        // A bug that panics on every request is logged once, not every time.
        let line = "the worker panicked; tearing everything down";
        self.logs.error_about("panic", line);
        let torn_down = panic::catch_unwind(AssertUnwindSafe(|| self.teardown()));
        let message = match torn_down {
            Ok(true) => "Something went wrong inside the service. The connection was closed.",
            _ => LEFT_BEHIND,
        };
        // The gate first: a client that hears `failed` may ask again at once.
        lock(&self.gate).phase = Phase::Idle;
        self.publish(failed(ErrorCode::Internal, message));
    }

    /// Tells the owner's connections the new state. A failure is also kept
    /// for the diagnostics, cleaned here and now, while the service still
    /// holds what the failed connection's lines must not show.
    fn publish(&mut self, state: ConnState) {
        let failure = failure(&state, &self.logs);
        self.say(&state, failure.as_ref());
        self.hub.publish(state, failure);
    }

    /// Writes a line for a state that ends something. Connecting and
    /// disconnecting are not written: the request just before says so. Nor
    /// is a disconnected that follows one, as after asking to disconnect
    /// when nothing was connected.
    ///
    /// These lines are outside the budget for requests, so that asking can
    /// never hide one. A state that only repeats the last one, with nothing
    /// between, is passed over while that line is in the log: a disconnect
    /// asked for again and again while a fault persists says it once. An
    /// admitted connect ends the repeat (see [`Self::connect`]), so every
    /// attempt's outcome is written.
    fn say(&mut self, state: &ConnState, failure: Option<&LastError>) {
        let ending = match state {
            ConnState::Connecting | ConnState::Disconnecting => return,
            ConnState::Disconnected if self.disconnected => return,
            ConnState::Disconnected => (LogLevel::Info, "disconnected".to_string()),
            ConnState::Connected { .. } => (LogLevel::Info, "connected".to_string()),
            ConnState::LoginNeeded => (
                LogLevel::Info,
                "the session ended: the user must log in again".to_string(),
            ),
            ConnState::Failed { code, .. } => {
                let message = failure.map_or("", |failure| failure.message.as_str());
                (
                    LogLevel::Error,
                    format!("failed: {}: {message}", word!(code)),
                )
            }
        };
        self.disconnected = matches!(state, ConnState::Disconnected);
        let (level, line) = ending;
        self.logs.at_about(level, STATE, &line);
    }

    fn handle(&mut self, command: Command) {
        match command {
            Command::Connect(params, cancel, hidden) => self.connect(params, &cancel, hidden),
            Command::Disconnect => {
                self.publish(ConnState::Disconnecting);
                let idle = |phase: &mut Phase| *phase = Phase::Idle;
                self.finish_then_open(ConnState::Disconnected, idle);
            }
            // Only the ending of the tunnel that is open now counts. One
            // from a tunnel that teardown closed must not undo a later
            // connection.
            Command::Ended(tunnel, event)
                if tunnel == self.tunnels && self.applied.tunnel.is_some() =>
            {
                // SEAM: auto-reconnect starts here and at a network change
                // (keep the session, reopen). Until then nothing is retried
                // and the cookie is already forgotten.
                let state = match event {
                    TunnelEvent::Closed => ConnState::Disconnected,
                    TunnelEvent::LoginNeeded => ConnState::LoginNeeded,
                    TunnelEvent::ConnectionLost => failed(
                        ErrorCode::EngineFailed,
                        "The connection to the gateway was lost.",
                    ),
                };
                // A disconnect already on its way keeps its own phase.
                let idle = |phase: &mut Phase| {
                    if *phase == Phase::Connected {
                        *phase = Phase::Idle;
                    }
                };
                self.finish_then_open(state, idle);
            }
            // The network the connection was set up and checked on is gone,
            // so its gateway route may lead nowhere. Only a change seen by
            // the subscription of the connection that is up now counts:
            // not one from an earlier attempt, opened or not, whose
            // forwarder read the number just before a teardown.
            Command::Network(subscription, NetworkEvent::PhysicalChanged)
                if subscription == self.watching.load(Ordering::SeqCst)
                    && self.applied.tunnel.is_some() =>
            {
                let state = failed(ErrorCode::EngineFailed, NETWORK_CHANGED);
                let idle = |phase: &mut Phase| {
                    if *phase == Phase::Connected {
                        *phase = Phase::Idle;
                    }
                };
                self.finish_then_open(state, idle);
            }
            // Sleeping and waking change nothing by themselves: a tunnel
            // that does not survive them ends by itself.
            Command::Network(..) | Command::Ended(..) | Command::Shutdown => {}
        }
    }

    fn connect(&mut self, params: ConnectParams, cancel: &Cancel, hidden: Held) {
        // A new attempt: whatever it ends in is news, even the same as the
        // last one's.
        self.disconnected = false;
        self.logs.forget(STATE);
        self.publish(ConnState::Connecting);
        let clean = self.teardown();
        // After the teardown, which lets go of the hold before this one.
        self.hidden = Some(hidden);
        let result = match clean {
            true => self.set_up(params, cancel),
            false => Err((ErrorCode::Internal, LEFT_BEHIND.to_string())),
        };
        let cancelled = {
            let mut gate = lock(&self.gate);
            let cancelled = cancel.is_cancelled();
            if gate.phase == Phase::Connecting {
                gate.phase = match result.is_ok() && !cancelled {
                    true => Phase::Connected,
                    false => Phase::Idle,
                };
            }
            cancelled
        };
        match result {
            // The disconnect that cancelled this is queued behind it and
            // reports the end.
            _ if cancelled => {
                self.teardown();
            }
            // Reached only after `set_up` verified everything.
            Ok(tunnel) => self.publish(ConnState::Connected { tunnel }),
            Err((ErrorCode::LoginNeeded, _)) => self.finish(ConnState::LoginNeeded),
            Err((code, message)) => self.finish(ConnState::Failed { code, message }),
        }
    }

    /// Tears everything down, then reports `state`, or a failure if something
    /// may have been left applied.
    fn finish(&mut self, state: ConnState) {
        self.finish_then_open(state, |_| {});
    }

    /// The same, with `open` deciding the gate's phase between the teardown
    /// and the report: a client that hears the last state may ask again at
    /// once, and must not be told it is busy.
    fn finish_then_open(&mut self, state: ConnState, open: impl FnOnce(&mut Phase)) {
        let clean = self.teardown();
        let state = if clean {
            state
        } else {
            failed(ErrorCode::Internal, LEFT_BEHIND)
        };
        open(&mut lock(&self.gate).phase);
        self.publish(state);
    }

    /// Passes the tunnel's one ending on to the worker.
    pub(crate) fn watch(&mut self, ended: Receiver<TunnelEvent>) -> std::io::Result<()> {
        self.tunnels += 1;
        let (tunnel, commands) = (self.tunnels, self.commands.clone());
        let forward = move || {
            if let Ok(event) = ended.recv() {
                let _ = commands.send(Command::Ended(tunnel, event));
            }
        };
        thread::Builder::new().spawn(forward).map(drop)
    }
}

const LEFT_BEHIND: &str = "Some routes or DNS settings could not be removed.";

const NETWORK_CHANGED: &str = "The network changed, so the connection was closed. Connect again.";

/// Said once while it stays in the log, when the system cannot report
/// network changes. Windows can; macOS and Linux cannot yet.
const UNWATCHED: &str = "network changes cannot be watched on this system; \
    a connection that stops working ends when the tunnel notices";

impl Machine {
    /// Starts watching `physical` for the connection being set up, under a
    /// subscription number no other attempt has. Events reach the worker as
    /// commands; the subscription ends at the first event after teardown, or
    /// with the service. A system that cannot report changes is no reason to
    /// refuse; any other failure is.
    pub(crate) fn watch_network(
        &mut self,
        physical: &PhysicalNetwork,
    ) -> Result<(), (ErrorCode, String)> {
        self.subscriptions += 1;
        let number = self.subscriptions;
        self.watching.store(number, Ordering::SeqCst);
        let events = match self.events.subscribe(physical) {
            Ok(subscription) => {
                let (events, end) = subscription.into_parts();
                // Replacing an earlier one ends that one.
                self.network_watch = Some(end);
                events
            }
            Err(ubc_vpn_platform::Error::Unsupported) => {
                self.logs.warn_about("network events", UNWATCHED);
                return Ok(());
            }
            Err(e) => {
                let why = format!("Network changes cannot be watched: {e}.");
                return Err((ErrorCode::Internal, why));
            }
        };
        let (current, commands) = (self.watching.clone(), self.commands.clone());
        let forward = move || {
            while let Ok(event) = events.recv() {
                let stale = current.load(Ordering::SeqCst) != number;
                if stale || commands.send(Command::Network(number, event)).is_err() {
                    break;
                }
            }
        };
        let started = thread::Builder::new().spawn(forward);
        started.map(drop).map_err(|e| {
            let why = format!("No thread to watch the network: {e}.");
            (ErrorCode::Internal, why)
        })
    }
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;
