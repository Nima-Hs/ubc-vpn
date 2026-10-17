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
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use ubc_vpn_core::policy::{FullTunnel, Policy};
use ubc_vpn_core::protocol::{
    ConnectParams, ErrorCode, ErrorInfo, LastError, LogLevel, is_plausible_cookie,
    is_plausible_gateway_addr,
};
use ubc_vpn_core::routes::{Ipv4Net, LocalNetworks, RouteSet, check_against_local};
use ubc_vpn_core::state::{ConnState, TunnelInfo, TunnelMode};
use ubc_vpn_engine::{Cancel, Gateway, Tunnel, TunnelEngine, TunnelEvent};
use ubc_vpn_platform::{
    Dns, Ipv6Block, NetworkEvent, NetworkEvents, PhysicalNetwork, Platform, Routes,
};

use crate::connect::dns_servers;
use crate::diagnostics::failure;
use crate::full;
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
    /// Connected, and changing the tunnel's routes.
    Updating,
    Stopping,
}

/// What decides whether a request is admitted.
struct Gate {
    phase: Phase,
    /// Stops the connect in progress, if there is one.
    cancel: Cancel,
    /// While connected: what a change of routes is checked against before
    /// it is admitted.
    live: Option<Live>,
}

/// What came of a change of routes that was not refused.
pub(crate) enum Admitted {
    /// The worker is applying it; the outcome comes as a state event.
    Changing,
    /// The tunnel carries these routes already: nothing was done.
    Unchanged(TunnelInfo),
}

/// What a change of routes is checked against while connected.
struct Live {
    /// The gateway the connection reaches.
    gateway: Ipv4Addr,
    /// The network the connection was set up on.
    physical: PhysicalNetwork,
    /// What the tunnel carries now.
    tunnel: TunnelInfo,
    /// The DNS servers the gateway assigned.
    assigned_dns: Vec<Ipv4Addr>,
    /// Whether routes to them are in place, as they are once a connection
    /// has had DNS domains or full mode.
    dns_routed: bool,
    /// Whether the network is watched, so that an IPv6 change is seen.
    watched: bool,
}

/// What the log says when a connect is undone because its client went
/// before it could be told the connect was admitted. It holds none of the
/// words that make the log hide the rest of a line.
pub const ABANDONED: &str =
    "the client that asked to connect went before it was told; disconnecting";

/// One admitted connect, as its worker waits to hear whether the client that
/// asked was told it was admitted. Dropping it unsettled counts as not told:
/// fail closed, so a thread that dies before it answers undoes the connect.
#[derive(Debug)]
pub(crate) struct Attempt {
    settled: Sender<bool>,
}

impl Attempt {
    /// Says whether the client was told its connect was admitted. The worker
    /// does nothing for the connect until it hears this, and undoes one whose
    /// client was not told: nobody is watching it, and nobody would undo it.
    pub(crate) fn settle(&self, told: bool) {
        let _ = self.settled.send(told);
    }
}

enum Command {
    /// With the hold that keeps its cookie out of the log, and what tells
    /// it whether the client was told it was admitted.
    Connect(ConnectParams, Cancel, Held, Receiver<bool>),
    Disconnect,
    /// Apply these routes to the live tunnel. Checked before it was
    /// admitted.
    UpdateRoutes(RouteSet),
    /// Switch the live tunnel to this mode. Checked before it was admitted.
    SetTunnel(TunnelMode),
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
    /// DNS servers. A route is in here before it is added, and leaves only
    /// once it is removed, so teardown removes whatever may be there.
    pub(crate) routes: Vec<Ipv4Net>,
    /// Of those, the subnets the user chose.
    pub(crate) subnets: Vec<Ipv4Net>,
    /// Of those, one host route for each DNS server the gateway assigned.
    /// A change of routes never removes them.
    pub(crate) dns_servers: Vec<Ipv4Net>,
    /// The DNS domains resolved through the tunnel.
    pub(crate) dns_domains: Vec<String>,
    /// The domains split DNS is set for. The same as `dns_domains`, except
    /// in full mode after a change of routes dropped domains: clearing them
    /// would take the catch-all with it, so they stay until the mode or the
    /// connection ends. They name the same servers as the catch-all.
    pub(crate) split_rules: Vec<String>,
    /// Whether full mode's halves may be in place: set before they are
    /// added, cleared once they are removed. It is the connection's mode.
    pub(crate) full: bool,
    /// What full mode did about IPv6, once its halves were added.
    pub(crate) ipv6: Option<Ipv6Block>,
    /// Whether full mode's catch-all may be set, as for `full`.
    pub(crate) catch_all: bool,
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
    /// Whether the policy allows full mode.
    full_allowed: bool,
    /// For the checks a switch to full mode needs before it is admitted.
    /// They only read.
    routes: Arc<dyn Routes>,
    dns: Arc<dyn Dns>,
    events: Arc<dyn NetworkEvents>,
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
            let full = policy.full_tunnel == FullTunnel::Allowed;
            Ok((gateway, policy.allowed_routes, full))
        });
        let (gateway, allowed, full_allowed) = match trusted {
            Ok((gateway, allowed, full)) => (Some(gateway), Ok(allowed), full),
            Err(message) => (None, Err(message), false),
        };
        let (phase, cancel) = (Phase::Idle, Cancel::new());
        let gate = Arc::new(Mutex::new(Gate {
            phase,
            cancel,
            live: None,
        }));
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
            full_allowed,
            routes: platform.routes.clone(),
            dns: platform.dns.clone(),
            events: platform.events.clone(),
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
    pub(crate) fn connect(&self, params: ConnectParams) -> Result<Attempt, ErrorInfo> {
        let routes = &params.routes;
        let full = match params.tunnel {
            TunnelMode::Split => "",
            TunnelMode::Full => ", full tunnel",
        };
        let carries = format!(
            "{} and {}{full}",
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

    fn admit(&self, params: ConnectParams, carries: &str) -> Result<Attempt, ErrorInfo> {
        let refused = |code, message: String| Err(error(code, message));
        let allowed = match &self.allowed {
            Ok(allowed) => allowed.as_deref(),
            Err(message) => return refused(ErrorCode::PolicyInvalid, message.clone()),
        };
        if let Err(why) = params.routes.check(allowed) {
            return refused(ErrorCode::RouteRefused, format!("Route refused: {why}."));
        }
        // What full mode needs of the policy and of this system. What it
        // needs of the network and the tunnel is known only once the worker
        // captures the one and opens the other, so `set_up` refuses those.
        if params.tunnel == TunnelMode::Full
            && let Err(why) = full::refuse_anywhere(self.full_allowed, &*self.events)
        {
            return refused(ErrorCode::RouteRefused, why);
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
            live: None,
        };
        // Held from here on, before the request is anywhere a line could
        // be written about it.
        let hidden = self.logs.hold(&params.cookie);
        let line = format!("connect admitted ({carries})");
        self.logs.about_requests(LogLevel::Info, &line);
        let (settled, answered) = mpsc::channel();
        let command = Command::Connect(params, gate.cancel.clone(), hidden, answered);
        self.send(command).map(|()| Attempt { settled })
    }

    /// Checks a change of the live tunnel's routes and hands it to the
    /// worker, which adds the new routes, removes the dropped ones and
    /// verifies both; the outcome comes as a state event. A change refused
    /// here leaves the tunnel exactly as it was. The same rules hold as for
    /// a connect: the policy's, and none touching the gateway or the
    /// network the connection was set up on.
    ///
    /// A change to what the tunnel carries already is no change: it is
    /// answered at once with the connection as it is, and nothing is done
    /// or logged, so asking for it again and again costs nothing.
    pub(crate) fn update_routes(&self, routes: RouteSet) -> Result<Admitted, ErrorInfo> {
        let carries = format!(
            "{} and {}",
            counted(routes.subnets.len(), "subnet"),
            counted(routes.dns_domains.len(), "DNS domain")
        );
        let admitted = self.admit_update(routes, &carries);
        if let Err(refusal) = &admitted {
            let line = format!(
                "route change refused: {}; the connection is as it was",
                word!(refusal.code)
            );
            self.logs.about_requests(LogLevel::Warn, &line);
        }
        admitted
    }

    /// Switches the live tunnel between split and full, which the worker
    /// does and checks; the outcome comes as a state event.
    ///
    /// A switch to full is checked first against everything full mode
    /// needs: the policy and this system, then the connection's network and
    /// tunnel. Those checks only read. A switch refused here leaves the
    /// connection exactly as it was. A switch to the mode the tunnel has is
    /// no change: it is answered at once with the connection as it is.
    pub(crate) fn set_tunnel(&self, mode: TunnelMode) -> Result<Admitted, ErrorInfo> {
        let admitted = self.admit_set_tunnel(mode);
        if let Err(refusal) = &admitted {
            let line = format!(
                "tunnel mode change refused: {}; the connection is as it was",
                word!(refusal.code)
            );
            self.logs.about_requests(LogLevel::Warn, &line);
        }
        admitted
    }

    fn admit_set_tunnel(&self, mode: TunnelMode) -> Result<Admitted, ErrorInfo> {
        let full = mode == TunnelMode::Full;
        let refused = |why: String| Err(error(ErrorCode::RouteRefused, why));
        if full && let Err(why) = full::refuse_anywhere(self.full_allowed, &*self.events) {
            return refused(why);
        }
        let mut gate = lock(&self.gate);
        match gate.phase {
            Phase::Connected => {}
            Phase::Idle => {
                let message = "The VPN is not connected. The mode is used at the next connect.";
                return Err(error(ErrorCode::NotConnected, message.to_string()));
            }
            Phase::Connecting | Phase::Updating | Phase::Stopping => return Err(busy()),
        }
        let Some(live) = &gate.live else {
            let message = "The connection's network is not known.";
            return Err(error(ErrorCode::Internal, message.to_string()));
        };
        if live.tunnel.mode == mode {
            return Ok(Admitted::Unchanged(live.tunnel.clone()));
        }
        // Checked under the gate, so nothing else starts meanwhile.
        if full && let Err(why) = self.full_needs(live) {
            return refused(format!("{why} The connection keeps the mode it has."));
        }
        gate.phase = Phase::Updating;
        let line = format!("tunnel mode change admitted ({})", word!(mode));
        self.logs.about_requests(LogLevel::Info, &line);
        self.send(Command::SetTunnel(mode))
            .map(|()| Admitted::Changing)
    }

    /// What full mode needs of the live connection: of its network, of the
    /// gateway's DNS servers, judged as at connect, and of its tunnel.
    fn full_needs(&self, live: &Live) -> Result<(), String> {
        if !live.watched {
            return Err(full::UNSUPPORTED.to_string());
        }
        full::refuse_here(&live.physical, &*self.dns)?;
        let servers = dns_servers(&live.assigned_dns, live.gateway, &live.physical);
        let servers = servers.map_err(|(_, why)| why)?;
        let local = LocalNetworks {
            own_addresses: live.physical.own_addresses(),
            on_link: live.physical.on_link(),
            next_hop: live.physical.next_hop(),
        };
        check_against_local(&servers, live.gateway, &local)
            .map_err(|c| format!("A DNS server the gateway assigned cannot be used: {c}."))?;
        full::refuse_on(&live.tunnel.interface, &servers, &*self.routes)
    }

    fn admit_update(&self, routes: RouteSet, carries: &str) -> Result<Admitted, ErrorInfo> {
        let refused = |code, message: String| Err(error(code, message));
        let unchanged = "The connection keeps the routes it has.";
        let allowed = match &self.allowed {
            Ok(allowed) => allowed.as_deref(),
            Err(message) => return refused(ErrorCode::PolicyInvalid, message.clone()),
        };
        if let Err(why) = routes.check(allowed) {
            let message = format!("Route refused: {why}. {unchanged}");
            return refused(ErrorCode::RouteRefused, message);
        }
        let mut gate = lock(&self.gate);
        match gate.phase {
            Phase::Connected => {}
            Phase::Idle => {
                let message = "The VPN is not connected. The routes are used at the next connect.";
                return refused(ErrorCode::NotConnected, message.to_string());
            }
            Phase::Connecting | Phase::Updating | Phase::Stopping => return Err(busy()),
        }
        let Some(live) = &gate.live else {
            let message = "The connection's network is not known.";
            return refused(ErrorCode::Internal, message.to_string());
        };
        if routes.is_carried_by(&live.tunnel.subnets, &live.tunnel.dns_domains) {
            return Ok(Admitted::Unchanged(live.tunnel.clone()));
        }
        let local = LocalNetworks {
            own_addresses: live.physical.own_addresses(),
            on_link: live.physical.on_link(),
            next_hop: live.physical.next_hop(),
        };
        if let Err(conflict) = check_against_local(&routes.subnets, live.gateway, &local) {
            let message = format!("Route refused: {conflict}. {unchanged}");
            return refused(ErrorCode::RouteRefused, message);
        }
        // Split DNS for a connection that had none needs routes to the
        // gateway's DNS servers, which are judged as at connect. Nothing
        // has been changed yet, so servers that cannot be used refuse the
        // change rather than end the connection.
        if !routes.dns_domains.is_empty() && !live.dns_routed {
            let servers = dns_servers(&live.assigned_dns, live.gateway, &live.physical);
            let usable = servers.and_then(|servers| match servers.is_empty() {
                true => Err((
                    ErrorCode::RouteRefused,
                    "The gateway assigned no DNS server for the DNS domains.".to_string(),
                )),
                false => check_against_local(&servers, live.gateway, &local).map_err(|c| {
                    let why = format!("A DNS server the gateway assigned cannot be used: {c}.");
                    (ErrorCode::RouteRefused, why)
                }),
            });
            if let Err((_, why)) = usable {
                return refused(ErrorCode::RouteRefused, format!("{why} {unchanged}"));
            }
        }
        gate.phase = Phase::Updating;
        let line = format!("route change admitted ({carries})");
        self.logs.about_requests(LogLevel::Info, &line);
        self.send(Command::UpdateRoutes(routes))
            .map(|()| Admitted::Changing)
    }

    /// Asks the worker to tear everything down. One that arrives during a
    /// connect cancels it first. `said` is what kind of client the client
    /// said it was; when there was something to disconnect it is logged as
    /// that, since nothing checks it.
    pub(crate) fn disconnect(&self, said: &str) -> Result<(), ErrorInfo> {
        let gate = lock(&self.gate);
        let line = format!("disconnect requested by a client that said it was {said}");
        // Within the budget for lines that requests cause.
        self.stop_with(gate, || self.logs.about_requests(LogLevel::Info, &line))
    }

    /// Cancels a connect in progress, if there is one, and has the worker
    /// tear everything down. `say` writes the line about it, when there was
    /// something to stop.
    fn stop_with(
        &self,
        mut gate: MutexGuard<'_, Gate>,
        say: impl FnOnce(),
    ) -> Result<(), ErrorInfo> {
        match gate.phase {
            Phase::Stopping => return Err(busy()),
            Phase::Connecting => gate.cancel.cancel(),
            // A change of routes in progress finishes first; the
            // disconnect is queued behind it.
            Phase::Idle | Phase::Connected | Phase::Updating => {}
        }
        if gate.phase != Phase::Idle {
            say();
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
            Command::Connect(params, cancel, hidden, answered) => {
                self.connect(params, &cancel, hidden, &answered)
            }
            Command::UpdateRoutes(routes) => self.update(|machine| machine.change_routes(routes)),
            Command::SetTunnel(mode) => self.update(|machine| machine.change_tunnel(mode)),
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
                    if matches!(*phase, Phase::Connected | Phase::Updating) {
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
                    if matches!(*phase, Phase::Connected | Phase::Updating) {
                        *phase = Phase::Idle;
                    }
                };
                self.finish_then_open(state, idle);
            }
            // Full mode with no IPv6 to block holds only while there is no
            // IPv6 leak path. Any IPv6 change is checked again at once, and
            // a leak path that has appeared closes the connection.
            Command::Network(subscription, NetworkEvent::Ipv6Changed)
                if subscription == self.watching.load(Ordering::SeqCst)
                    && self.applied.ipv6 == Some(Ipv6Block::NothingToBlock) =>
            {
                let Some(tunnel) = &self.applied.tunnel else {
                    return;
                };
                let still = self.routes.full_tunnel_ipv6(&tunnel.assigned().interface);
                if still != Ok(Ipv6Block::NothingToBlock) {
                    let state = failed(ErrorCode::VerificationFailed, full::IPV6_APPEARED);
                    let idle = |phase: &mut Phase| {
                        if matches!(*phase, Phase::Connected | Phase::Updating) {
                            *phase = Phase::Idle;
                        }
                    };
                    self.finish_then_open(state, idle);
                }
            }
            // Sleeping and waking change nothing by themselves: a tunnel
            // that does not survive them ends by itself.
            Command::Network(..) | Command::Ended(..) | Command::Shutdown => {}
        }
    }

    /// The connect is about to contact the gateway. From here it is a real
    /// attempt, which costs a login, so whatever it ends in is news, even
    /// the same as the last one's. A connect that stops before this costs
    /// nothing, so it does not reset the repeat rule: asking again and
    /// again for one that fails the same way must not fill the log.
    pub(crate) fn reaching_the_gateway(&mut self) {
        self.disconnected = false;
        self.logs.forget(STATE);
        self.logs.forget(crate::update::CHANGED);
        self.logs.forget(full::SWITCHED);
    }

    fn connect(
        &mut self,
        params: ConnectParams,
        cancel: &Cancel,
        hidden: Held,
        answered: &Receiver<bool>,
    ) {
        self.publish(ConnState::Connecting);
        // Nothing is done for a connect until the client that asked has been
        // told it was admitted. One that could not be told has gone: nobody
        // is watching this connect, and nobody would undo it, so it is
        // undone here, before anything is applied or the gateway contacted.
        // An attempt dropped unsettled counts as not told: whatever stopped
        // the answer, nobody is known to watch this connect. One cancelled by now
        // is ended by the disconnect that cancelled it.
        let told = answered.recv().unwrap_or(false);
        if !told && !cancel.is_cancelled() {
            drop(hidden);
            // Under the repeat rule, not the budget for requests: connecting
            // and going costs the client nothing, so a repeat must not fill
            // the log, and nothing can hide the first one.
            let line = ABANDONED;
            self.logs
                .at_about(LogLevel::Info, "an undone connect", line);
            let idle = |phase: &mut Phase| {
                if *phase == Phase::Connecting {
                    *phase = Phase::Idle;
                }
            };
            return self.finish_then_open(ConnState::Disconnected, idle);
        }
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
            // What a change of routes is checked against while connected.
            gate.live = match &result {
                Ok(tunnel) => self.live(tunnel.clone()),
                Err(_) => None,
            };
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

    /// What a change to the connection carrying `tunnel` will be checked
    /// against, or nothing if the connection is not complete.
    fn live(&self, tunnel: TunnelInfo) -> Option<Live> {
        let applied = &self.applied;
        let (gateway, physical) = (applied.gateway_route?, applied.physical.clone()?);
        let assigned_dns = applied.tunnel.as_ref()?.assigned().dns.clone();
        Some(Live {
            gateway,
            physical,
            tunnel,
            assigned_dns,
            dns_routed: !applied.dns_servers.is_empty(),
            watched: self.network_watch.is_some(),
        })
    }

    /// Applies a change to the live tunnel, of its routes or of its mode,
    /// with `change`. Connected again with the change when every step and
    /// check passed; otherwise the connection is closed and everything
    /// removed, as for a connect that fails. A tunnel that ended while the
    /// change waited has been reported already, and there is nothing to
    /// change.
    fn update(
        &mut self,
        change: impl FnOnce(&mut Self) -> Result<TunnelInfo, (ErrorCode, String)>,
    ) {
        if self.applied.tunnel.is_none() {
            let mut gate = lock(&self.gate);
            if gate.phase == Phase::Updating {
                gate.phase = Phase::Idle;
            }
            return;
        }
        match change(self) {
            Ok(tunnel) => {
                {
                    // A disconnect that came meanwhile keeps its own phase.
                    let mut gate = lock(&self.gate);
                    if gate.phase == Phase::Updating {
                        gate.phase = Phase::Connected;
                    }
                    gate.live = self.live(tunnel.clone());
                }
                self.publish(ConnState::Connected { tunnel });
            }
            Err((code, message)) => {
                let idle = |phase: &mut Phase| {
                    if *phase == Phase::Updating {
                        *phase = Phase::Idle;
                    }
                };
                self.finish_then_open(ConnState::Failed { code, message }, idle);
            }
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
    /// refuse, except in full mode (`full`), which must see IPv6 changes;
    /// any other failure is.
    pub(crate) fn watch_network(
        &mut self,
        physical: &PhysicalNetwork,
        full: bool,
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
            Err(ubc_vpn_platform::Error::Unsupported) if full => {
                return Err((ErrorCode::RouteRefused, full::UNSUPPORTED.to_string()));
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
