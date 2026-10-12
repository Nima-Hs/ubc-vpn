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
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use ubc_vpn_core::policy::Policy;
use ubc_vpn_core::protocol::{ConnectParams, ErrorCode, ErrorInfo, is_plausible_gateway_addr};
use ubc_vpn_core::routes::Ipv4Net;
use ubc_vpn_core::state::ConnState;
use ubc_vpn_engine::{Cancel, Gateway, Tunnel, TunnelEngine, TunnelEvent};
use ubc_vpn_platform::{Dns, PhysicalNetwork, Platform, Routes};

use crate::hub::Hub;
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
    Connect(ConnectParams, Cancel),
    Disconnect,
    /// The tunnel with this number ended by itself.
    Ended(u64, TunnelEvent),
    Shutdown,
}

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
    pub(crate) engine: Arc<dyn TunnelEngine>,
    /// From the service's own policy. No request can change it.
    pub(crate) gateway: Option<Gateway>,
    pub(crate) logs: Logs,
    pub(crate) applied: Applied,
    /// Counts tunnels, so an ending is matched to the tunnel it came from.
    tunnels: u64,
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
            engine,
            gateway,
            logs,
            applied: Applied::default(),
            tunnels: 0,
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
        })
    }

    /// Checks a connect request and hands it to the worker. Nothing is
    /// applied for a request that is refused here. A connect is admitted
    /// only when nothing is connected or in progress: to replace a
    /// connection the client disconnects first.
    pub(crate) fn connect(&self, params: ConnectParams) -> Result<(), ErrorInfo> {
        let refused = |code, message: String| Err(error(code, message));
        let allowed = match &self.allowed {
            Ok(allowed) => allowed.as_deref(),
            Err(message) => return refused(ErrorCode::PolicyInvalid, message.clone()),
        };
        if let Err(why) = params.routes.check(allowed) {
            return refused(ErrorCode::RouteRefused, format!("Route refused: {why}."));
        }
        // SEAM: the machine's own interface addresses must be refused here
        // too. That needs a platform operation that does not exist yet.
        if !is_plausible_gateway_addr(params.gateway_addr) {
            let message = "The gateway address is not a usable address.";
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
        self.send(Command::Connect(params, gate.cancel.clone()))
    }

    /// Asks the worker to tear everything down. One that arrives during a
    /// connect cancels it first.
    pub(crate) fn disconnect(&self) -> Result<(), ErrorInfo> {
        let mut gate = lock(&self.gate);
        match gate.phase {
            Phase::Stopping => return Err(busy()),
            Phase::Connecting => gate.cancel.cancel(),
            Phase::Idle | Phase::Connected => {}
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
        for command in inbox {
            if matches!(command, Command::Shutdown) {
                break;
            }
            let handled = panic::catch_unwind(AssertUnwindSafe(|| self.handle(command)));
            if handled.is_err() {
                self.recover();
            }
        }
        let _ = panic::catch_unwind(AssertUnwindSafe(|| self.teardown()));
    }

    /// After a panic while handling a command, which is a bug somewhere in
    /// the service, the platform or the engine: removes everything, reports
    /// the failure and takes requests again. Without this the routes would
    /// stay applied and the state would say `connecting` for ever.
    fn recover(&mut self) {
        self.logs
            .push("the worker panicked; tearing everything down");
        let torn_down = panic::catch_unwind(AssertUnwindSafe(|| self.teardown()));
        let message = match torn_down {
            Ok(true) => "Something went wrong inside the service. The connection was closed.",
            _ => LEFT_BEHIND,
        };
        self.hub.publish(failed(ErrorCode::Internal, message));
        lock(&self.gate).phase = Phase::Idle;
    }

    fn handle(&mut self, command: Command) {
        match command {
            Command::Connect(params, cancel) => self.connect(params, &cancel),
            Command::Disconnect => {
                self.hub.publish(ConnState::Disconnecting);
                self.finish(ConnState::Disconnected);
                lock(&self.gate).phase = Phase::Idle;
            }
            // Only the ending of the tunnel that is open now counts. One
            // from a tunnel that teardown closed must not undo a later
            // connection.
            Command::Ended(tunnel, event)
                if tunnel == self.tunnels && self.applied.tunnel.is_some() =>
            {
                // SEAM: auto-reconnect and network-change handling start
                // here and in `set_up` (subscribe to `NetworkEvents`, keep
                // the session, reopen). Until then nothing is retried and
                // the cookie is already forgotten.
                self.finish(match event {
                    TunnelEvent::Closed => ConnState::Disconnected,
                    TunnelEvent::LoginNeeded => ConnState::LoginNeeded,
                    TunnelEvent::ConnectionLost => failed(
                        ErrorCode::EngineFailed,
                        "The connection to the gateway was lost.",
                    ),
                });
                let mut gate = lock(&self.gate);
                if gate.phase == Phase::Connected {
                    gate.phase = Phase::Idle;
                }
            }
            Command::Ended(..) | Command::Shutdown => {}
        }
    }

    fn connect(&mut self, params: ConnectParams, cancel: &Cancel) {
        self.hub.publish(ConnState::Connecting);
        let result = match self.teardown() {
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
            Ok(tunnel) => self.hub.publish(ConnState::Connected { tunnel }),
            Err((ErrorCode::LoginNeeded, _)) => self.finish(ConnState::LoginNeeded),
            Err((code, message)) => self.finish(ConnState::Failed { code, message }),
        }
    }

    /// Tears everything down, then reports `state`, or a failure if something
    /// may have been left applied.
    fn finish(&mut self, state: ConnState) {
        let clean = self.teardown();
        let state = if clean {
            state
        } else {
            failed(ErrorCode::Internal, LEFT_BEHIND)
        };
        self.hub.publish(state);
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
