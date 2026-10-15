//! What the fakes cannot do by themselves, done by wrapping them: an engine
//! that records and can be made to misbehave, and an OS that can panic.

use std::net::Ipv4Addr;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

/// Longer than anything a test waits for should take. A wait that reaches
/// it panics, so a regression fails its test and does not hang it.
const WAIT: Duration = Duration::from_secs(10);

/// As long as a held close or ending is kept back when nothing releases it.
/// The test that forgot, or failed first, then ends instead of hanging.
const HOLD: Duration = Duration::from_secs(30);

use ubc_vpn_core::routes::Ipv4Net;
use ubc_vpn_engine::fake::FakeEngine;
use ubc_vpn_engine::{
    Assigned, Cancel, CloseMode, Gateway, LogLevel, LogSink, Session, Tunnel, TunnelEngine,
    TunnelError, TunnelEvent,
};
use ubc_vpn_platform::fake::{Fake, Op};
use ubc_vpn_platform::{
    Dns, NetworkEvent, NetworkEvents, PhysicalNetwork, Result, Routes, SplitDns, Subscription,
    Verified,
};

/// What a test has asked the spy to do, and what it has seen.
#[derive(Default)]
struct Controls {
    /// The gateway each `open` was given and the OS calls made before it.
    opens: Vec<(Gateway, Vec<Op>)>,
    /// How each tunnel was closed and the OS calls made before that.
    closes: Vec<(CloseMode, Vec<Op>)>,
    /// Makes the next tunnels claim to be connected to this address.
    claims_address: Option<Ipv4Addr>,
    /// Leaves the session alive at the gateway whatever the service asks,
    /// so that one test can open several tunnels in a row.
    keeps_sessions: bool,
    holds_closes: bool,
    closes_waiting: usize,
    holds_endings: bool,
}

/// Wraps the engine fake. It records every `open` and `close`, logs the
/// cookie as a careless library would (at a level that is kept, with no
/// marker word, before the engine has hidden it), and can be told to hold a
/// close or a tunnel's ending back, or to hand out a tunnel that claims
/// another address.
pub struct Spy {
    engine: FakeEngine,
    fake: Fake,
    controls: Arc<(Mutex<Controls>, Condvar)>,
}

impl Spy {
    pub fn new(engine: FakeEngine, fake: Fake) -> Self {
        let controls = Arc::default();
        Self {
            engine,
            fake,
            controls,
        }
    }

    fn set(&self, change: impl FnOnce(&mut Controls)) {
        change(&mut self.controls.0.lock().unwrap());
        self.controls.1.notify_all();
    }

    pub fn opens(&self) -> Vec<(Gateway, Vec<Op>)> {
        self.controls.0.lock().unwrap().opens.clone()
    }

    pub fn closes(&self) -> Vec<(CloseMode, Vec<Op>)> {
        self.controls.0.lock().unwrap().closes.clone()
    }

    pub fn claim_address(&self, addr: [u8; 4]) {
        self.set(|controls| controls.claims_address = Some(addr.into()));
    }

    pub fn keep_sessions(&self) {
        self.set(|controls| controls.keeps_sessions = true);
    }

    /// Makes every close wait until [`Spy::release`].
    pub fn hold_closes(&self) {
        self.set(|controls| controls.holds_closes = true);
    }

    /// Blocks until a close is waiting. Call [`Spy::hold_closes`] first.
    pub fn wait_for_a_held_close(&self) {
        let controls = self.controls.0.lock().unwrap();
        let none = |controls: &mut Controls| controls.closes_waiting == 0;
        let waited = self.controls.1.wait_timeout_while(controls, WAIT, none);
        assert!(!waited.unwrap().1.timed_out(), "no close was ever held");
    }

    /// Keeps every tunnel's ending from the service until [`Spy::release`].
    pub fn hold_endings(&self) {
        self.set(|controls| controls.holds_endings = true);
    }

    /// Lets held closes and endings through.
    pub fn release(&self) {
        self.set(|controls| (controls.holds_closes, controls.holds_endings) = (false, false));
    }
}

impl TunnelEngine for Spy {
    fn open(
        &self,
        gateway: &Gateway,
        session: &Session,
        cancel: &Cancel,
        events: Sender<TunnelEvent>,
        logs: LogSink,
    ) -> std::result::Result<Box<dyn Tunnel>, TunnelError> {
        let seen = (gateway.clone(), self.fake.calls());
        self.set(|controls| controls.opens.push(seen));
        logs.log(LogLevel::Info, &format!("> {}", session.cookie.expose()));

        // The tunnel's ending passes through here, where it can be held.
        let (ended, ending) = mpsc::channel();
        let controls = self.controls.clone();
        std::thread::spawn(move || {
            let Ok(event) = ending.recv() else { return };
            let held = |controls: &mut Controls| controls.holds_endings;
            drop(
                controls
                    .1
                    .wait_timeout_while(controls.0.lock().unwrap(), HOLD, held),
            );
            let _ = events.send(event);
        });
        let inner = self.engine.open(gateway, session, cancel, ended, logs)?;
        let mut assigned = inner.assigned().clone();
        let claimed = self.controls.0.lock().unwrap().claims_address;
        assigned.gateway_addr = claimed.unwrap_or(assigned.gateway_addr);
        Ok(Box::new(Watched {
            inner,
            assigned,
            fake: self.fake.clone(),
            controls: self.controls.clone(),
        }))
    }
}

/// A tunnel from the engine fake, with its closing recorded and held.
struct Watched {
    inner: Box<dyn Tunnel>,
    assigned: Assigned,
    fake: Fake,
    controls: Arc<(Mutex<Controls>, Condvar)>,
}

impl Tunnel for Watched {
    fn assigned(&self) -> &Assigned {
        &self.assigned
    }

    fn close(&self, how: CloseMode) {
        let mut controls = self.controls.0.lock().unwrap();
        controls.closes.push((how, self.fake.calls()));
        controls.closes_waiting += 1;
        self.controls.1.notify_all();
        let held = |controls: &mut Controls| controls.holds_closes;
        let waited = self.controls.1.wait_timeout_while(controls, HOLD, held);
        let mut controls = waited.unwrap().0;
        controls.closes_waiting -= 1;
        let how = match controls.keeps_sessions {
            true => CloseMode::KeepSession,
            false => how,
        };
        drop(controls);
        self.inner.close(how);
    }
}

/// The platform fake's routes, DNS and network events, with one operation
/// that can be made to panic, once, as a bug in an OS implementation would.
/// Each events subscription is kept apart, so that a test can tell one
/// connection's from another's.
pub struct Faulty {
    fake: Fake,
    panics_at: Mutex<Option<Op>>,
    /// Each subscription's sender, or `None` once its stopping end is dropped.
    subscriptions: Arc<Mutex<Vec<Option<Sender<NetworkEvent>>>>>,
}

impl Faulty {
    pub fn new(fake: Fake) -> Self {
        Self {
            fake,
            panics_at: Mutex::default(),
            subscriptions: Arc::default(),
        }
    }

    pub fn panic_at(&self, op: Op) {
        *self.panics_at.lock().unwrap() = Some(op);
    }

    /// How many subscriptions were made, in order.
    pub fn subscriptions(&self) -> usize {
        self.subscriptions.lock().unwrap().len()
    }

    /// Sends `event` to subscription `n` only, and says whether its
    /// receiver is still there.
    pub fn send_to(&self, n: usize, event: NetworkEvent) -> bool {
        let subscriptions = self.subscriptions.lock().unwrap();
        subscriptions[n]
            .as_ref()
            .is_some_and(|sender| sender.send(event).is_ok())
    }

    fn reached(&self, op: Op) {
        let mut panics_at = self.panics_at.lock().unwrap();
        if *panics_at == Some(op) {
            *panics_at = None;
            // Without the lock, so that it is not poisoned.
            drop(panics_at);
            panic!("the test makes {op:?} panic");
        }
    }
}

impl Routes for Faulty {
    fn capture_physical(&self, gateway: Ipv4Addr) -> Result<PhysicalNetwork> {
        self.reached(Op::CapturePhysical);
        self.fake.capture_physical(gateway)
    }

    fn configure_tunnel(&self, tunnel: &str, address: Ipv4Addr, mtu: u16) -> Result<()> {
        self.reached(Op::ConfigureTunnel);
        self.fake.configure_tunnel(tunnel, address, mtu)
    }

    fn add_gateway_route(&self, gateway: Ipv4Addr, via: &PhysicalNetwork) -> Result<()> {
        self.reached(Op::AddGatewayRoute);
        self.fake.add_gateway_route(gateway, via)
    }

    fn remove_gateway_route(&self, gateway: Ipv4Addr, via: &PhysicalNetwork) -> Result<()> {
        self.reached(Op::RemoveGatewayRoute);
        self.fake.remove_gateway_route(gateway, via)
    }

    fn add_tunnel_routes(&self, tunnel: &str, subnets: &[Ipv4Net]) -> Result<()> {
        self.reached(Op::AddTunnelRoutes);
        self.fake.add_tunnel_routes(tunnel, subnets)
    }

    fn remove_tunnel_routes(&self, tunnel: &str, subnets: &[Ipv4Net]) -> Result<()> {
        self.reached(Op::RemoveTunnelRoutes);
        self.fake.remove_tunnel_routes(tunnel, subnets)
    }

    fn remove_all(&self) -> Result<()> {
        self.reached(Op::RemoveAllRoutes);
        self.fake.remove_all()
    }

    fn uses_interface(&self, dest: Ipv4Addr, interface: &str) -> Verified {
        self.reached(Op::VerifyRoute);
        self.fake.uses_interface(dest, interface)
    }
}

impl Dns for Faulty {
    fn set_split_dns(&self, tunnel: &str, dns: &SplitDns) -> Result<()> {
        self.reached(Op::SetSplitDns);
        self.fake.set_split_dns(tunnel, dns)
    }

    fn clear_split_dns(&self) -> Result<()> {
        self.reached(Op::ClearSplitDns);
        self.fake.clear_split_dns()
    }

    fn split_dns_matches(&self, dns: &SplitDns) -> Verified {
        self.reached(Op::VerifyDns);
        self.fake.split_dns_matches(dns)
    }
}

/// A subscription's stopping end: dropping it ends the subscription, as on a
/// real system, so `send_to` fails from then on.
struct Stop {
    subscriptions: Arc<Mutex<Vec<Option<Sender<NetworkEvent>>>>>,
    n: usize,
}

impl Drop for Stop {
    fn drop(&mut self) {
        if let Ok(mut subscriptions) = self.subscriptions.lock() {
            subscriptions[self.n] = None;
        }
    }
}

impl NetworkEvents for Faulty {
    /// Fails as the fake was told to; otherwise a subscription of its own.
    fn subscribe(&self, watching: &PhysicalNetwork) -> Result<Subscription> {
        self.reached(Op::Subscribe);
        drop(self.fake.subscribe(watching)?);
        let (sender, receiver) = mpsc::channel();
        let mut subscriptions = self.subscriptions.lock().unwrap();
        subscriptions.push(Some(sender));
        let stop = Stop {
            subscriptions: self.subscriptions.clone(),
            n: subscriptions.len() - 1,
        };
        Ok(Subscription::new(receiver, stop))
    }
}
