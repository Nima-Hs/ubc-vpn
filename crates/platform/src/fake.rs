//! An in-memory implementation of the seam, for tests and for the service's
//! dev mode. It touches nothing outside the process.
//!
//! A [`Fake`] records every routing and DNS call in order and keeps the state
//! those calls add up to, so a test can assert both. It can be told to fail
//! an operation, it delivers the network events a test injects, and its
//! channel lets a test choose who each caller is.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::Duration;

use ubc_vpn_core::routes::Ipv4Net;

use crate::{
    Connection, Dns, Error, Listener, NetworkEvent, NetworkEvents, Paths, PhysicalNetwork,
    Platform, RawConnection, Result, Routes, SplitDns, Transport, UserId, Verified, lock,
};

/// The interface the fake reports as physical.
pub const PHYSICAL_INTERFACE: &str = "fake-eth0";

/// An operation that [`Fake::set_failure`] can make fail. The routing and DNS
/// ones are also what [`Fake::calls`] records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Op {
    /// [`Routes::capture_physical`].
    CapturePhysical,
    /// [`Routes::configure_tunnel`]. Its arguments are in [`Fake::configured`].
    ConfigureTunnel,
    /// [`Routes::add_gateway_route`].
    AddGatewayRoute,
    /// [`Routes::remove_gateway_route`].
    RemoveGatewayRoute,
    /// [`Routes::add_tunnel_routes`].
    AddTunnelRoutes,
    /// [`Routes::remove_tunnel_routes`].
    RemoveTunnelRoutes,
    /// [`Routes::remove_all`].
    RemoveAllRoutes,
    /// [`Routes::uses_interface`].
    VerifyRoute,
    /// [`Dns::set_split_dns`]. Fail it with [`Error::Unsupported`] to play an OS
    /// that cannot honour split DNS.
    SetSplitDns,
    /// [`Dns::clear_split_dns`].
    ClearSplitDns,
    /// [`Dns::split_dns_matches`].
    VerifyDns,
    /// [`NetworkEvents::subscribe`]. Not recorded.
    Subscribe,
    /// [`Transport::listen`]. Not recorded.
    Listen,
    /// [`Listener::restrict_to`]. Not recorded.
    RestrictTo,
    /// [`Transport::connect`] and [`Fake::connect_as`]. Not recorded. Fail
    /// it with [`Error::NotTheService`] to play a listener that is not the
    /// service.
    Connect,
}

/// What is applied right now. After a full teardown it equals
/// `Applied::default()`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Applied {
    /// Host routes through the physical network, by destination.
    pub gateway_routes: Vec<(Ipv4Addr, PhysicalNetwork)>,
    /// Routes through a tunnel, by interface name.
    pub tunnel_routes: Vec<(String, Ipv4Net)>,
    /// The split DNS in effect and the interface it was set on.
    pub split_dns: Option<(String, SplitDns)>,
}

/// One call to [`Routes::configure_tunnel`]: the device, the address and the
/// largest packet size.
pub type Configured = (String, Ipv4Addr, u16);

/// The address the fake machine has on its physical network, the network
/// that address is on, and the resolver every name uses until split DNS says
/// otherwise.
pub const OWN_ADDRESS: Ipv4Addr = Ipv4Addr::new(192, 168, 0, 10);
const ROUTER: Ipv4Addr = Ipv4Addr::new(192, 168, 0, 1);

struct State {
    calls: Vec<Op>,
    failures: HashMap<Op, Error>,
    applied: Applied,
    /// Every `configure_tunnel` call, in order, failed ones included.
    configured: Vec<Configured>,
    /// The IPv4 addresses each device has now, in the order they were added.
    addresses: HashMap<String, Vec<Ipv4Addr>>,
    /// The packet size each configured device has now.
    mtus: HashMap<String, u16>,
    /// Devices a test took away.
    absent: HashSet<String>,
    /// Routes somebody else added: the interface and the destination.
    foreign: Vec<(String, Ipv4Net)>,
    own_addresses: Vec<Ipv4Addr>,
    on_link: Vec<Ipv4Net>,
    subscribers: Vec<Sender<NetworkEvent>>,
    listeners: HashMap<String, Endpoint>,
}

impl Default for State {
    fn default() -> Self {
        let home = Ipv4Net::new(Ipv4Addr::new(192, 168, 0, 0), 24);
        Self {
            calls: Vec::new(),
            failures: HashMap::new(),
            applied: Applied::default(),
            configured: Vec::new(),
            addresses: HashMap::new(),
            mtus: HashMap::new(),
            absent: HashSet::new(),
            foreign: Vec::new(),
            own_addresses: vec![OWN_ADDRESS],
            on_link: home.into_iter().collect(),
            subscribers: Vec::new(),
            listeners: HashMap::new(),
        }
    }
}

/// What is already there for one destination.
enum Present {
    None,
    /// A route through the interface asked for.
    Identical,
    /// A route through another interface.
    Elsewhere,
}

/// The host route for `addr`.
fn host(addr: Ipv4Addr) -> Result<Ipv4Net> {
    Ipv4Net::new(addr, 32).map_err(|e| Error::Failed(e.to_string()))
}

impl State {
    /// Every route on the fake machine as the OS would list it, the
    /// product's and anybody else's, as interface and destination.
    fn table(&self) -> Vec<(String, Ipv4Net)> {
        let gateway = self.applied.gateway_routes.iter();
        let gateway =
            gateway.filter_map(|(dest, via)| Some((via.interface.clone(), host(*dest).ok()?)));
        let tunnel = self.applied.tunnel_routes.iter().cloned();
        gateway
            .chain(tunnel)
            .chain(self.foreign.iter().cloned())
            .collect()
    }

    fn route_to(&self, net: Ipv4Net, interface: &str) -> Present {
        let table = self.table();
        let mut same = table.iter().filter(|(_, dest)| *dest == net);
        match same.next() {
            None => Present::None,
            Some(_) if table.iter().any(|(i, d)| *d == net && i != interface) => Present::Elsewhere,
            Some(_) => Present::Identical,
        }
    }

    /// The OS holds one route per destination and interface. When the
    /// product removes its own, an identical one recorded as somebody
    /// else's goes too, so an implementation that took one over shows it.
    fn forget(&mut self, interface: &str, net: Ipv4Net) {
        self.foreign.retain(|(i, d)| !(i == interface && *d == net));
    }
}

struct Endpoint {
    incoming: Sender<(Connection, UserId)>,
    owner: Option<UserId>,
}

/// The fake OS. Clones share one state, so a test keeps one and hands the
/// service another. The state outlives any one user of it, which is how a
/// test plays a service that crashed and started again.
#[derive(Clone, Default)]
pub struct Fake(Arc<Mutex<State>>);

impl Fake {
    /// A machine with one physical network, no tunnel routes and no split DNS.
    pub fn new() -> Self {
        Self::default()
    }

    /// This fake as a [`Platform`], with files under `root`.
    pub fn platform(&self, root: &Path) -> Platform {
        Platform {
            routes: Arc::new(self.clone()),
            dns: Arc::new(self.clone()),
            events: Arc::new(self.clone()),
            transport: Arc::new(self.clone()),
            paths: paths(root),
        }
    }

    /// Every routing and DNS call so far, in order, including failed ones.
    pub fn calls(&self) -> Vec<Op> {
        self.state().calls.clone()
    }

    /// What is applied right now.
    pub fn applied(&self) -> Applied {
        self.state().applied.clone()
    }

    /// Makes every later `op` fail with `error`, or with `None` work again.
    ///
    /// A failing operation changes nothing, with one exception: a failing
    /// [`Routes::add_tunnel_routes`] first adds every subnet but the last, as
    /// an OS that fails partway would. A failing check answers
    /// [`Verified::Unknown`].
    pub fn set_failure(&self, op: Op, error: Option<Error>) {
        let mut state = self.state();
        match error {
            Some(error) => state.failures.insert(op, error),
            None => state.failures.remove(&op),
        };
    }

    /// Every [`Routes::configure_tunnel`] call so far with its arguments, in
    /// order, including failed ones. [`Fake::calls`] shows where each fell
    /// among the other calls.
    pub fn configured(&self) -> Vec<Configured> {
        self.state().configured.clone()
    }

    /// The IPv4 addresses the device `name` has now. They are not part of
    /// [`Applied`]: no teardown step removes them, they go with the device,
    /// which a test plays with [`Fake::set_device`].
    pub fn device_addresses(&self, name: &str) -> Vec<Ipv4Addr> {
        let state = self.state();
        state.addresses.get(name).cloned().unwrap_or_default()
    }

    /// The largest packet size the device `name` was configured with.
    pub fn device_mtu(&self, name: &str) -> Option<u16> {
        self.state().mtus.get(name).copied()
    }

    /// Gives the device `name` an address as somebody else would, such as
    /// one an adapter kept from an earlier use.
    pub fn add_foreign_address(&self, name: &str, address: Ipv4Addr) {
        let mut state = self.state();
        let addresses = state.addresses.entry(name.to_string()).or_default();
        if !addresses.contains(&address) {
            addresses.push(address);
        }
    }

    /// Takes the device `name` away, or brings it back bare. Every name is a
    /// device until a test takes it away. Taking one away removes its address
    /// and every route through it, as an OS does when the engine closes the
    /// device, and from then on it cannot be configured or routed through.
    pub fn set_device(&self, name: &str, present: bool) {
        let mut state = self.state();
        if present {
            state.absent.remove(name);
            return;
        }
        state.absent.insert(name.to_string());
        state.addresses.remove(name);
        state.mtus.remove(name);
        state.foreign.retain(|(interface, _)| interface != name);
        let routes = &mut state.applied.tunnel_routes;
        routes.retain(|(interface, _)| interface != name);
    }

    /// Sets what the next [`Routes::capture_physical`] reports as the
    /// machine's own addresses and on-link networks.
    pub fn set_local(&self, own_addresses: &[Ipv4Addr], on_link: &[Ipv4Net]) {
        let mut state = self.state();
        state.own_addresses = own_addresses.to_vec();
        state.on_link = on_link.to_vec();
    }

    /// Adds a route as somebody other than the product would. No operation
    /// of the product removes it.
    pub fn add_foreign_route(&self, interface: &str, net: Ipv4Net) {
        let route = (interface.to_string(), net);
        let mut state = self.state();
        if !state.foreign.contains(&route) {
            state.foreign.push(route);
        }
    }

    /// Removes a route [`Fake::add_foreign_route`] added.
    pub fn remove_foreign_route(&self, interface: &str, net: Ipv4Net) {
        let route = (interface.to_string(), net);
        self.state().foreign.retain(|foreign| *foreign != route);
    }

    /// The routes somebody else added that are still there.
    pub fn foreign_routes(&self) -> Vec<(String, Ipv4Net)> {
        self.state().foreign.clone()
    }

    /// The resolvers a lookup of `name` would go to now: the split DNS
    /// resolvers for a chosen domain and the names under it, the machine's
    /// usual one for every other name.
    pub fn resolvers_for(&self, name: &str) -> Vec<Ipv4Addr> {
        let state = self.state();
        let under = |domain: &String| {
            let above = name.strip_suffix(domain.as_str());
            above.is_some_and(|rest| rest.is_empty() || rest.ends_with('.'))
        };
        match &state.applied.split_dns {
            Some((_, dns)) if dns.domains.iter().any(under) => dns.resolvers.clone(),
            _ => vec![ROUTER],
        }
    }

    /// Delivers `event` to every subscriber.
    pub fn send_event(&self, event: NetworkEvent) {
        let mut state = self.state();
        state.subscribers.retain(|s| s.send(event).is_ok());
    }

    /// Connects to `name` as `user`. [`Transport::connect`] on the fake
    /// connects as the user `fake-user`.
    pub fn connect_as(&self, name: &str, user: &UserId) -> Result<Connection> {
        let (state, outcome) = self.start(Op::Connect);
        outcome?;
        let endpoint = state.listeners.get(name).ok_or(Error::NotFound)?;
        if endpoint.owner.as_ref().is_some_and(|owner| owner != user) {
            return Err(Error::PermissionDenied);
        }
        let (client, server) = pipe_pair();
        let accepted = endpoint.incoming.send((server, user.clone()));
        accepted.map_err(|_| Error::NotFound)?;
        Ok(client)
    }

    fn state(&self) -> MutexGuard<'_, State> {
        lock(&self.0)
    }

    /// Records `op` if it is a routing or DNS one, and reports whether it was
    /// told to fail.
    fn start(&self, op: Op) -> (MutexGuard<'_, State>, Result<()>) {
        let mut state = self.state();
        if !matches!(
            op,
            Op::Subscribe | Op::Listen | Op::RestrictTo | Op::Connect
        ) {
            state.calls.push(op);
        }
        let outcome = state.failures.get(&op).cloned().map_or(Ok(()), Err);
        (state, outcome)
    }

    /// Records `op`, then applies it unless it was told to fail.
    fn run<T>(&self, op: Op, apply: impl FnOnce(&mut Applied) -> T) -> Result<T> {
        let (mut state, outcome) = self.start(op);
        outcome.map(|()| apply(&mut state.applied))
    }
}

/// The locations a fake rooted at `root` uses: folders under it, which
/// nothing creates, and a channel name no other root shares.
pub fn paths(root: &Path) -> Paths {
    Paths {
        policy_dir: root.join("policy"),
        state_dir: root.join("state"),
        settings_dir: root.join("settings"),
        channel_name: format!("ubc-vpn-fake-{}", root.display()),
    }
}

impl Routes for Fake {
    /// Refuses while tunnel routes are applied, so a service that captures
    /// too late fails its tests.
    fn capture_physical(&self, _gateway: Ipv4Addr) -> Result<PhysicalNetwork> {
        let (state, outcome) = self.start(Op::CapturePhysical);
        outcome?;
        if !state.applied.tunnel_routes.is_empty() {
            let late = "captured while tunnel routes are applied";
            return Err(Error::Failed(late.to_string()));
        }
        Ok(PhysicalNetwork {
            interface: PHYSICAL_INTERFACE.to_string(),
            next_hop: Some(ROUTER),
            own_addresses: state.own_addresses.clone(),
            on_link: state.on_link.clone(),
        })
    }

    /// Sets the address and nothing more: no network comes with it, so a
    /// service that counted on one fails its tests. Any other address the
    /// device had is removed.
    fn configure_tunnel(&self, tunnel: &str, address: Ipv4Addr, mtu: u16) -> Result<()> {
        let (mut state, outcome) = self.start(Op::ConfigureTunnel);
        state.configured.push((tunnel.to_string(), address, mtu));
        outcome?;
        if !crate::TUNNEL_MTU.contains(&mtu) {
            return Err(Error::InvalidInput);
        }
        if state.absent.contains(tunnel) {
            return Err(Error::NotFound);
        }
        state.addresses.insert(tunnel.to_string(), vec![address]);
        state.mtus.insert(tunnel.to_string(), mtu);
        Ok(())
    }

    /// An exclusive add, as the contract says. The fake has no next hops, so
    /// the interface alone tells routes to one destination apart.
    fn add_gateway_route(&self, gateway: Ipv4Addr, via: &PhysicalNetwork) -> Result<()> {
        let (mut state, outcome) = self.start(Op::AddGatewayRoute);
        outcome?;
        let host = host(gateway)?;
        match state.route_to(host, &via.interface) {
            Present::Identical => return Ok(()),
            Present::Elsewhere => return Err(Error::AlreadyExists),
            Present::None => {}
        }
        state.applied.gateway_routes.push((gateway, via.clone()));
        Ok(())
    }

    fn remove_gateway_route(&self, gateway: Ipv4Addr, via: &PhysicalNetwork) -> Result<()> {
        let (mut state, outcome) = self.start(Op::RemoveGatewayRoute);
        outcome?;
        let ours = |(dest, net): &(Ipv4Addr, PhysicalNetwork)| *dest == gateway && net == via;
        if state.applied.gateway_routes.iter().any(ours) {
            state.applied.gateway_routes.retain(|route| !ours(route));
            state.forget(&via.interface, host(gateway)?);
        }
        Ok(())
    }

    /// Exclusive adds, as the contract says. On a route to the same
    /// destination through another interface it stops there, keeping those
    /// added before it.
    fn add_tunnel_routes(&self, tunnel: &str, subnets: &[Ipv4Net]) -> Result<()> {
        let (mut state, outcome) = self.start(Op::AddTunnelRoutes);
        if outcome.is_ok() && state.absent.contains(tunnel) {
            return Err(Error::NotFound);
        }
        let skipped = usize::from(outcome.is_err() && !subnets.is_empty());
        for subnet in &subnets[..subnets.len() - skipped] {
            match state.route_to(*subnet, tunnel) {
                Present::Identical => {}
                Present::Elsewhere => return Err(Error::AlreadyExists),
                Present::None => {
                    let route = (tunnel.to_string(), *subnet);
                    state.applied.tunnel_routes.push(route);
                }
            }
        }
        outcome
    }

    fn remove_tunnel_routes(&self, tunnel: &str, subnets: &[Ipv4Net]) -> Result<()> {
        let (mut state, outcome) = self.start(Op::RemoveTunnelRoutes);
        outcome?;
        let ours = |(name, subnet): &(String, Ipv4Net)| name == tunnel && subnets.contains(subnet);
        let removed: Vec<_> = state
            .applied
            .tunnel_routes
            .iter()
            .filter(|r| ours(r))
            .cloned()
            .collect();
        state.applied.tunnel_routes.retain(|route| !ours(route));
        for (name, subnet) in removed {
            state.forget(&name, subnet);
        }
        Ok(())
    }

    fn remove_all(&self) -> Result<()> {
        let (mut state, outcome) = self.start(Op::RemoveAllRoutes);
        outcome?;
        let applied = std::mem::take(&mut state.applied.gateway_routes);
        for (gateway, via) in applied {
            state.forget(&via.interface, host(gateway)?);
        }
        for (name, subnet) in std::mem::take(&mut state.applied.tunnel_routes) {
            state.forget(&name, subnet);
        }
        Ok(())
    }

    /// Picks a route as an OS does: the most specific one wins, so a host
    /// route beats any subnet, and everything else leaves by the physical
    /// interface. Routes somebody else added count like the product's own.
    fn uses_interface(&self, dest: Ipv4Addr, interface: &str) -> Verified {
        let (state, outcome) = self.start(Op::VerifyRoute);
        if outcome.is_err() {
            return Verified::Unknown;
        }
        let applied = &state.applied;
        let host = applied.gateway_routes.iter().find(|(d, _)| *d == dest);
        let subnets = applied.tunnel_routes.iter().chain(&state.foreign);
        let narrowest = subnets
            .filter(|(_, subnet)| subnet.contains_addr(dest))
            .max_by_key(|(_, subnet)| subnet.prefix_len());
        let used = match (host, narrowest) {
            (Some((_, physical)), _) => physical.interface(),
            (None, Some((tunnel, _))) => tunnel,
            (None, None) => PHYSICAL_INTERFACE,
        };
        match used == interface {
            true => Verified::Yes,
            false => Verified::No,
        }
    }
}

#[cfg(any(test, feature = "fake"))]
impl crate::suite::Foreign for Fake {
    fn add_route(&self, interface: &str, net: Ipv4Net) {
        self.add_foreign_route(interface, net);
    }

    fn remove_route(&self, interface: &str, net: Ipv4Net) {
        self.remove_foreign_route(interface, net);
    }

    fn add_address(&self, interface: &str, address: Ipv4Addr) {
        self.add_foreign_address(interface, address);
    }

    fn addresses(&self, interface: &str) -> Vec<Ipv4Addr> {
        self.device_addresses(interface)
    }
}

impl Dns for Fake {
    fn set_split_dns(&self, tunnel: &str, dns: &SplitDns) -> Result<()> {
        self.run(Op::SetSplitDns, |applied| {
            applied.split_dns = Some((tunnel.to_string(), dns.clone()));
        })
    }

    fn clear_split_dns(&self) -> Result<()> {
        self.run(Op::ClearSplitDns, |applied| applied.split_dns = None)
    }

    fn split_dns_matches(&self, dns: &SplitDns) -> Verified {
        let verdict = self.run(Op::VerifyDns, |applied| match &applied.split_dns {
            Some((_, set)) if set == dns => Verified::Yes,
            _ => Verified::No,
        });
        verdict.unwrap_or(Verified::Unknown)
    }
}

impl NetworkEvents for Fake {
    /// Delivers only what [`Fake::send_event`] injects, whatever is watched.
    fn subscribe(&self, _watching: &PhysicalNetwork) -> Result<Receiver<NetworkEvent>> {
        let (mut state, outcome) = self.start(Op::Subscribe);
        outcome?;
        let (sender, receiver) = mpsc::channel();
        state.subscribers.push(sender);
        Ok(receiver)
    }
}

impl Transport for Fake {
    fn listen(&self, name: &str) -> Result<Box<dyn Listener>> {
        let (mut state, outcome) = self.start(Op::Listen);
        outcome?;
        if state.listeners.contains_key(name) {
            return Err(Error::AlreadyExists);
        }
        let (incoming, accepted) = mpsc::channel();
        let endpoint = Endpoint {
            incoming,
            owner: None,
        };
        state.listeners.insert(name.to_string(), endpoint);
        Ok(Box::new(FakeListener {
            fake: self.clone(),
            name: name.to_string(),
            accepted: Mutex::new(accepted),
            closed: AtomicBool::new(false),
        }))
    }

    fn connect(&self, name: &str) -> Result<Connection> {
        self.connect_as(name, &"fake-user".parse()?)
    }
}

struct FakeListener {
    fake: Fake,
    name: String,
    accepted: Mutex<Receiver<(Connection, UserId)>>,
    closed: AtomicBool,
}

impl Listener for FakeListener {
    fn accept(&self) -> Result<(Connection, UserId)> {
        // Closing drops the sending end, which ends the wait.
        let accepted = lock(&self.accepted).recv();
        match self.closed.load(Ordering::SeqCst) {
            true => Err(Error::Closed),
            false => accepted.map_err(|_| Error::Closed),
        }
    }

    fn restrict_to(&self, owner: &UserId) -> Result<()> {
        let (mut state, outcome) = self.fake.start(Op::RestrictTo);
        outcome?;
        if self.closed.load(Ordering::SeqCst) {
            return Err(Error::Closed);
        }
        let endpoint = state.listeners.get_mut(&self.name).ok_or(Error::Closed)?;
        endpoint.owner = Some(owner.clone());
        Ok(())
    }

    fn close(&self) {
        if !self.closed.swap(true, Ordering::SeqCst) {
            self.fake.state().listeners.remove(&self.name);
        }
    }
}

impl Drop for FakeListener {
    fn drop(&mut self) {
        self.close();
    }
}

/// One direction of an in-process connection.
#[derive(Default)]
struct Half {
    state: Mutex<HalfState>,
    changed: Condvar,
}

#[derive(Default)]
struct HalfState {
    bytes: VecDeque<u8>,
    closed: bool,
}

/// One end of an in-process connection.
struct PipeEnd {
    incoming: Arc<Half>,
    outgoing: Arc<Half>,
    timeout: Mutex<Option<Duration>>,
}

fn pipe_pair() -> (Connection, Connection) {
    let (up, down) = (Arc::new(Half::default()), Arc::new(Half::default()));
    let end = |incoming: &Arc<Half>, outgoing: &Arc<Half>| {
        Connection::new(Box::new(PipeEnd {
            incoming: incoming.clone(),
            outgoing: outgoing.clone(),
            timeout: Mutex::default(),
        }))
    };
    (end(&down, &up), end(&up, &down))
}

impl RawConnection for PipeEnd {
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let timeout = *lock(&self.timeout);
        let half = &self.incoming;
        let waiting = |state: &mut HalfState| state.bytes.is_empty() && !state.closed;
        let state = lock(&half.state);
        let waited = match timeout {
            None => half.changed.wait_while(state, waiting).ok(),
            Some(timeout) => half
                .changed
                .wait_timeout_while(state, timeout, waiting)
                .ok()
                .map(|(state, _)| state),
        };
        let panicked = || Error::Failed("a test panicked while using the fake".to_string());
        let mut state = waited.ok_or_else(panicked)?;
        if waiting(&mut state) {
            return Err(Error::TimedOut);
        }
        let n = buf.len().min(state.bytes.len());
        for (slot, byte) in buf.iter_mut().zip(state.bytes.drain(..n)) {
            *slot = byte;
        }
        Ok(n)
    }

    fn write_all(&self, bytes: &[u8]) -> Result<()> {
        let mut state = lock(&self.outgoing.state);
        if state.closed {
            return Err(Error::Closed);
        }
        state.bytes.extend(bytes);
        self.outgoing.changed.notify_all();
        Ok(())
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        *lock(&self.timeout) = timeout;
        Ok(())
    }

    /// Nothing to set: the fake takes every byte at once, so a write never
    /// waits.
    fn set_write_timeout(&self, _timeout: Option<Duration>) -> Result<()> {
        Ok(())
    }

    fn close(&self) {
        for half in [&self.incoming, &self.outgoing] {
            lock(&half.state).closed = true;
            half.changed.notify_all();
        }
    }
}

impl Drop for PipeEnd {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::suite;

    const GATEWAY: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
    const TUNNEL: &str = "fake-tun0";

    fn user(name: &str) -> UserId {
        name.parse().unwrap()
    }

    fn subnets() -> [Ipv4Net; 2] {
        ["192.0.2.0/24", "198.51.100.0/24"].map(|s| s.parse().unwrap())
    }

    fn failed() -> Option<Error> {
        Some(Error::Failed("injected".to_string()))
    }

    #[test]
    fn passes_the_shared_suite_and_ends_clean() {
        let fake = Fake::new();
        suite::check_routes(&fake, TUNNEL);
        suite::check_configure_tunnel(&fake, &fake, TUNNEL);
        let restarted = || Box::new(fake.clone()) as Box<dyn Routes>;
        suite::check_route_ownership(&fake, &restarted, &fake, TUNNEL);
        suite::check_dns(&fake, TUNNEL, &|name| fake.resolvers_for(name));
        let as_stranger = |name: &str| fake.connect_as(name, &user("stranger"));
        suite::check_transport(&fake, "suite", &as_stranger);
        assert_eq!(fake.applied(), Applied::default());
        assert!(fake.state().listeners.is_empty());
    }

    #[test]
    fn records_calls_in_order_and_the_resulting_state() {
        let fake = Fake::new();
        let [subnet, _] = subnets();
        let physical = fake.capture_physical(GATEWAY).unwrap();
        fake.add_gateway_route(GATEWAY, &physical).unwrap();
        fake.add_tunnel_routes(TUNNEL, &[subnet, subnet]).unwrap();
        let _events = fake.subscribe(&physical).unwrap();
        let expected = [
            Op::CapturePhysical,
            Op::AddGatewayRoute,
            Op::AddTunnelRoutes,
        ];
        assert_eq!(fake.calls(), expected);
        let applied = fake.applied();
        assert_eq!(applied.gateway_routes, [(GATEWAY, physical)]);
        assert_eq!(applied.tunnel_routes, [(TUNNEL.to_string(), subnet)]);
    }

    #[test]
    fn a_failing_operation_changes_nothing_until_healed() {
        let fake = Fake::new();
        let physical = fake.capture_physical(GATEWAY).unwrap();
        fake.set_failure(Op::AddGatewayRoute, Some(Error::PermissionDenied));
        let refused = fake.add_gateway_route(GATEWAY, &physical);
        assert_eq!(refused, Err(Error::PermissionDenied));
        assert_eq!(fake.applied(), Applied::default());
        assert_eq!(fake.calls(), [Op::CapturePhysical, Op::AddGatewayRoute]);
        fake.set_failure(Op::AddGatewayRoute, None);
        assert_eq!(fake.add_gateway_route(GATEWAY, &physical), Ok(()));
    }

    // "On error some may have been added": the fake leaves some, so a service
    // that does not clean up after a failed add fails its tests.
    #[test]
    fn a_failing_add_of_tunnel_routes_leaves_some_behind() {
        let fake = Fake::new();
        let [first, _] = subnets();
        fake.set_failure(Op::AddTunnelRoutes, failed());
        assert!(fake.add_tunnel_routes(TUNNEL, &subnets()).is_err());
        assert_eq!(fake.applied().tunnel_routes, [(TUNNEL.to_string(), first)]);
        assert_eq!(fake.remove_all(), Ok(()));
        assert_eq!(fake.applied(), Applied::default());
    }

    #[test]
    fn records_configuring_the_tunnel_in_order_and_can_fail_it() {
        let fake = Fake::new();
        let address = Ipv4Addr::new(10, 255, 0, 2);
        fake.capture_physical(GATEWAY).unwrap();
        fake.configure_tunnel(TUNNEL, address, 1300).unwrap();
        fake.add_tunnel_routes(TUNNEL, &subnets()).unwrap();
        let order = [
            Op::CapturePhysical,
            Op::ConfigureTunnel,
            Op::AddTunnelRoutes,
        ];
        assert_eq!(fake.calls(), order);
        assert_eq!(
            (fake.device_addresses(TUNNEL), fake.device_mtu(TUNNEL)),
            (vec![address], Some(1300))
        );

        fake.set_failure(Op::ConfigureTunnel, failed());
        let other = Ipv4Addr::new(10, 255, 0, 3);
        assert_eq!(fake.configure_tunnel(TUNNEL, other, 1400).err(), failed());
        // The failed call is recorded and changed nothing.
        assert_eq!(
            (fake.device_addresses(TUNNEL), fake.device_mtu(TUNNEL)),
            (vec![address], Some(1300))
        );
        let tunnel = TUNNEL.to_string();
        let expected = [(tunnel.clone(), address, 1300), (tunnel, other, 1400)];
        assert_eq!(fake.configured(), expected);
    }

    // The address goes with the device, and so do its routes; a device that
    // is gone cannot be configured.
    #[test]
    fn a_device_that_is_gone_takes_its_address_and_routes_with_it() {
        let fake = Fake::new();
        let address = Ipv4Addr::new(10, 255, 0, 2);
        fake.configure_tunnel(TUNNEL, address, 1300).unwrap();
        fake.add_tunnel_routes(TUNNEL, &subnets()).unwrap();
        fake.set_device(TUNNEL, false);
        assert_eq!(
            (fake.device_addresses(TUNNEL), fake.device_mtu(TUNNEL)),
            (vec![], None)
        );
        assert_eq!(fake.applied(), Applied::default());
        let gone = fake.configure_tunnel(TUNNEL, address, 1300);
        assert_eq!(gone, Err(Error::NotFound));
        let unrouted = fake.add_tunnel_routes(TUNNEL, &subnets());
        assert_eq!(unrouted, Err(Error::NotFound));
        fake.set_device(TUNNEL, true);
        assert_eq!(fake.configure_tunnel(TUNNEL, address, 1300), Ok(()));
    }

    #[test]
    fn captures_the_local_networks_a_test_sets() {
        let fake = Fake::new();
        let physical = fake.capture_physical(GATEWAY).unwrap();
        assert_eq!(physical.own_addresses(), [OWN_ADDRESS]);
        assert!(physical.on_link()[0].contains_addr(OWN_ADDRESS));
        let bridge: Ipv4Net = "172.17.0.0/16".parse().unwrap();
        let own = [OWN_ADDRESS, Ipv4Addr::new(172, 17, 0, 1)];
        fake.set_local(&own, &[bridge]);
        let physical = fake.capture_physical(GATEWAY).unwrap();
        assert_eq!(physical.own_addresses(), own);
        assert_eq!(physical.on_link(), [bridge]);
    }

    // An OS that cannot honour split DNS refuses, and nothing is changed.
    #[test]
    fn split_dns_can_be_refused_as_unsupported() {
        let fake = Fake::new();
        let dns = SplitDns {
            resolvers: vec![Ipv4Addr::new(192, 0, 2, 53)],
            domains: vec!["ece.example".to_string()],
        };
        fake.set_failure(Op::SetSplitDns, Some(Error::Unsupported));
        assert_eq!(fake.set_split_dns(TUNNEL, &dns), Err(Error::Unsupported));
        assert_eq!(fake.applied(), Applied::default());
        assert_eq!(fake.resolvers_for("www.ece.example"), [ROUTER]);
    }

    // The suite's ownership check must notice an implementation that takes a
    // route which was there first for its own.
    #[test]
    fn the_ownership_check_catches_a_route_taken_over() {
        struct Greedy(Fake);
        impl Routes for Greedy {
            fn capture_physical(&self, gateway: Ipv4Addr) -> Result<PhysicalNetwork> {
                self.0.capture_physical(gateway)
            }
            fn configure_tunnel(&self, tunnel: &str, address: Ipv4Addr, mtu: u16) -> Result<()> {
                self.0.configure_tunnel(tunnel, address, mtu)
            }
            fn add_gateway_route(&self, gateway: Ipv4Addr, via: &PhysicalNetwork) -> Result<()> {
                self.0.add_gateway_route(gateway, via)
            }
            fn remove_gateway_route(&self, gw: Ipv4Addr, via: &PhysicalNetwork) -> Result<()> {
                self.0.remove_gateway_route(gw, via)
            }
            fn add_tunnel_routes(&self, tunnel: &str, subnets: &[Ipv4Net]) -> Result<()> {
                self.0.add_tunnel_routes(tunnel, subnets)
            }
            // Removes whatever matches, its own or not.
            fn remove_tunnel_routes(&self, tunnel: &str, subnets: &[Ipv4Net]) -> Result<()> {
                for subnet in subnets {
                    self.0.remove_foreign_route(tunnel, *subnet);
                }
                self.0.remove_tunnel_routes(tunnel, subnets)
            }
            fn remove_all(&self) -> Result<()> {
                self.0.remove_all()
            }
            fn uses_interface(&self, dest: Ipv4Addr, interface: &str) -> Verified {
                self.0.uses_interface(dest, interface)
            }
        }
        let fake = Fake::new();
        let greedy = Greedy(fake.clone());
        let restarted = || Box::new(fake.clone()) as Box<dyn Routes>;
        let check = std::panic::AssertUnwindSafe(|| {
            suite::check_route_ownership(&greedy, &restarted, &fake, TUNNEL);
        });
        assert!(std::panic::catch_unwind(check).is_err());
    }

    // Security rule: the physical network is captured before the tunnel
    // exists. Captured later it could be the tunnel, the previous client's bug.
    #[test]
    fn refuses_to_capture_the_physical_network_too_late() {
        let fake = Fake::new();
        fake.add_tunnel_routes(TUNNEL, &subnets()).unwrap();
        assert!(matches!(
            fake.capture_physical(GATEWAY),
            Err(Error::Failed(_))
        ));
        fake.remove_all().unwrap();
        assert!(fake.capture_physical(GATEWAY).is_ok());
    }

    // Crash recovery: a new run has no PhysicalNetwork and no memory of what
    // the old one added, and must still be able to remove it all.
    #[test]
    fn a_later_run_can_remove_what_an_earlier_one_left() {
        let fake = Fake::new();
        let dns = SplitDns {
            resolvers: vec![Ipv4Addr::new(192, 0, 2, 53)],
            domains: vec!["ece.example".to_string()],
        };
        {
            let crashed = fake.platform(Path::new("fake"));
            let physical = crashed.routes.capture_physical(GATEWAY).unwrap();
            crashed
                .routes
                .add_gateway_route(GATEWAY, &physical)
                .unwrap();
            crashed
                .routes
                .add_tunnel_routes(TUNNEL, &subnets())
                .unwrap();
            crashed.dns.set_split_dns(TUNNEL, &dns).unwrap();
        }
        let restarted = fake.platform(Path::new("fake"));
        restarted.routes.remove_all().unwrap();
        restarted.dns.clear_split_dns().unwrap();
        assert_eq!(fake.applied(), Applied::default());
    }

    // Security rule: "could not tell" is its own answer, never a "no" and
    // never a "yes", so the service can fail closed on it.
    #[test]
    fn could_not_determine_is_distinct_from_no() {
        let fake = Fake::new();
        let dns = SplitDns {
            resolvers: vec![Ipv4Addr::new(192, 0, 2, 53)],
            domains: vec!["ece.example".to_string()],
        };
        fake.set_split_dns(TUNNEL, &dns).unwrap();
        assert_eq!(fake.uses_interface(GATEWAY, TUNNEL), Verified::No);
        assert_eq!(fake.split_dns_matches(&dns), Verified::Yes);

        fake.set_failure(Op::VerifyRoute, failed());
        fake.set_failure(Op::VerifyDns, failed());
        let route = fake.uses_interface(GATEWAY, PHYSICAL_INTERFACE);
        assert_eq!(route, Verified::Unknown);
        assert_eq!(fake.split_dns_matches(&dns), Verified::Unknown);
        assert_ne!(Verified::Unknown, Verified::No);
    }

    #[test]
    fn delivers_injected_events_to_every_subscriber() {
        let fake = Fake::new();
        let physical = fake.capture_physical(GATEWAY).unwrap();
        let subscribe = || fake.subscribe(&physical).unwrap();
        let (first, second) = (subscribe(), subscribe());
        drop(subscribe());
        fake.send_event(NetworkEvent::PhysicalChanged);
        fake.send_event(NetworkEvent::Sleeping);
        assert_eq!(first.try_recv(), Ok(NetworkEvent::PhysicalChanged));
        assert_eq!(first.try_recv(), Ok(NetworkEvent::Sleeping));
        assert_eq!(second.try_recv(), Ok(NetworkEvent::PhysicalChanged));

        fake.set_failure(Op::Subscribe, failed());
        assert_eq!(fake.subscribe(&physical).err(), failed());
    }

    // Security rule: the service learns who is calling from the transport,
    // and once narrowed to an owner nobody else gets a new connection.
    #[test]
    fn reports_the_caller_and_refuses_others_once_restricted() {
        let fake = Fake::new();
        let listener = fake.listen("svc").unwrap();
        let _mallory = fake.connect_as("svc", &user("mallory")).unwrap();
        let _queued = fake.connect_as("svc", &user("mallory")).unwrap();
        assert_eq!(listener.accept().unwrap().1, user("mallory"));

        listener.restrict_to(&user("alice")).unwrap();
        let refused = fake.connect_as("svc", &user("mallory")).err();
        assert_eq!(refused, Some(Error::PermissionDenied));
        assert_eq!(fake.connect("svc").err(), Some(Error::PermissionDenied));
        // A connection made before narrowing still arrives, as on a real OS:
        // the service has to check every caller itself.
        assert_eq!(listener.accept().unwrap().1, user("mallory"));
        let _alice = fake.connect_as("svc", &user("alice")).unwrap();
        assert_eq!(listener.accept().unwrap().1, user("alice"));
    }

    #[test]
    fn transport_operations_can_be_made_to_fail() {
        let fake = Fake::new();
        fake.set_failure(Op::Listen, Some(Error::PermissionDenied));
        assert_eq!(fake.listen("svc").err(), Some(Error::PermissionDenied));
        fake.set_failure(Op::Listen, None);
        let listener = fake.listen("svc").unwrap();
        // A listener that is not the service: the caller gets no connection,
        // so it cannot send anything, and the listener sees nobody.
        fake.set_failure(Op::Connect, Some(Error::NotTheService));
        assert_eq!(fake.connect("svc").err(), Some(Error::NotTheService));
        fake.set_failure(Op::Connect, None);
        let _first = fake.connect("svc").unwrap();
        assert_eq!(listener.accept().unwrap().1, user("fake-user"));
        fake.set_failure(Op::RestrictTo, failed());
        assert_eq!(listener.restrict_to(&user("alice")).err(), failed());
        // The failed narrowing narrowed nothing.
        assert!(fake.connect_as("svc", &user("mallory")).is_ok());
        assert_eq!(fake.calls(), []);
    }

    // A listener that was closed must not release a name someone else has
    // claimed since.
    #[test]
    fn a_closed_listener_no_longer_owns_the_name() {
        let fake = Fake::new();
        let old = fake.listen("svc").unwrap();
        old.close();
        let _new = fake.listen("svc").unwrap();
        assert_eq!(old.restrict_to(&user("alice")), Err(Error::Closed));
        drop(old);
        assert_eq!(fake.listen("svc").err(), Some(Error::AlreadyExists));
    }

    // Security rule: dev mode never shares a file or a channel with the
    // installed product. The check must notice when it would.
    #[test]
    fn the_paths_check_catches_a_collision() {
        let installed = paths(Path::new("installed"));
        let collides = |other: &Paths| {
            let (installed, other) = (installed.clone(), other.clone());
            let checks = [
                std::panic::catch_unwind(|| suite::check_paths(&installed, &other)),
                std::panic::catch_unwind(|| suite::check_paths(&other, &installed)),
            ];
            assert_eq!(checks[0].is_err(), checks[1].is_err(), "not symmetric");
            checks[0].is_err()
        };
        let mut dev = paths(Path::new("dev"));
        assert!(!collides(&dev), "two roots share nothing");
        dev.state_dir = installed.policy_dir.join("dev");
        assert!(collides(&dev), "a dev folder inside an installed one");
        dev = paths(Path::new("dev"));
        dev.channel_name = installed.channel_name.clone();
        assert!(collides(&dev), "same channel name");
    }
}
