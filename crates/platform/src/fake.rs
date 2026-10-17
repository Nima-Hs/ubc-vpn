//! An in-memory implementation of the seam, for tests and for the service's
//! dev mode. It touches nothing outside the process.
//!
//! A [`Fake`] records every routing and DNS call in order and keeps the state
//! those calls add up to, so a test can assert both. It can be told to fail
//! an operation, it delivers the network events a test injects, and its
//! channel lets a test choose who each caller is.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::Duration;

use ubc_vpn_core::routes::Ipv4Net;

use crate::{
    Connection, Dns, Error, FULL_TUNNEL_V4, Ipv6Block, Listener, NetworkEvent, NetworkEvents,
    Paths, PhysicalNetwork, Platform, RawConnection, Result, Routes, SplitDns, Subscription,
    Transport, UserId, Verified, lock,
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
    /// [`Routes::add_full_tunnel`].
    AddFullTunnel,
    /// [`Routes::remove_full_tunnel`].
    RemoveFullTunnel,
    /// [`Routes::foreign_full_tunnel`].
    ForeignFullTunnel,
    /// [`Routes::full_tunnel_ipv6`].
    FullTunnelIpv6,
    /// [`Routes::uses_interface_v6`].
    VerifyRouteV6,
    /// [`Dns::set_catch_all_dns`].
    SetCatchAllDns,
    /// [`Dns::clear_catch_all_dns`].
    ClearCatchAllDns,
    /// [`Dns::catch_all_dns_matches`].
    VerifyCatchAllDns,
    /// [`Dns::foreign_catch_all`].
    ForeignCatchAll,
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
    /// Full mode's halves, when this product added them.
    pub full_tunnel: Option<FullTunnel>,
    /// The resolvers every name goes to, when this product set a catch-all.
    pub catch_all_dns: Option<Vec<Ipv4Addr>>,
}

/// Full mode's halves as [`Routes::add_full_tunnel`] left them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FullTunnel {
    /// The tunnel they go through.
    pub tunnel: String,
    /// What was done about IPv6.
    pub ipv6: Ipv6Block,
}

/// An IPv6 address on the fake machine's local network, for tests that ask
/// where such an address goes.
pub const LINK_LOCAL_V6: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);

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
    subscribers: HashMap<u64, Sender<NetworkEvent>>,
    next_subscriber: u64,
    listeners: HashMap<String, Endpoint>,
    /// Checks that answer `Unobservable` where they would answer `Yes`.
    unobservable: HashSet<Op>,
    /// Destinations whose route check alone answers so.
    unobservable_routes: HashSet<Ipv4Addr>,
    /// Whether the tunnel device has IPv6, so that IPv6 halves can be added
    /// on it.
    tunnel_ipv6: bool,
    /// Whether the physical network has an IPv6 route other than
    /// link-local, which IPv6 would leave by.
    physical_ipv6: bool,
    /// Whether a rule that is not the product's takes every name.
    foreign_catch_all: bool,
    /// Networks the machine is on through an adapter other than the
    /// physical one, such as a virtual machine program's host-only network,
    /// with that adapter's name.
    adapters: Vec<(String, Ipv4Net)>,
    /// Tunnel routes the fake OS says it added but did not, to play a route
    /// that went missing.
    lost: HashSet<Ipv4Net>,
    /// Whether a subscription sends `Ipv6Changed`.
    reports_ipv6: bool,
    /// The router the physical network hands traffic to.
    router: Ipv4Addr,
    /// Destinations whose route check answers that it could not tell.
    untold_routes: HashSet<Ipv4Addr>,
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
            subscribers: HashMap::new(),
            next_subscriber: 0,
            listeners: HashMap::new(),
            unobservable: HashSet::new(),
            unobservable_routes: HashSet::new(),
            tunnel_ipv6: true,
            physical_ipv6: true,
            foreign_catch_all: false,
            adapters: Vec::new(),
            lost: HashSet::new(),
            reports_ipv6: true,
            router: ROUTER,
            untold_routes: HashSet::new(),
        }
    }
}

impl State {
    /// What check `op` answers when what it asks about is in effect.
    fn confirmed(&self, op: Op) -> Verified {
        match self.unobservable.contains(&op) {
            true => Verified::Unobservable,
            false => Verified::Yes,
        }
    }

    /// The same for the route check to `dest`.
    fn route_confirmed(&self, dest: Ipv4Addr) -> Verified {
        match self.unobservable_routes.contains(&dest) {
            true => Verified::Unobservable,
            false => self.confirmed(Op::VerifyRoute),
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

/// The two IPv4 halves of full mode.
fn v4_halves() -> [Ipv4Net; 2] {
    FULL_TUNNEL_V4.map(|half| half.parse().expect("a network"))
}

impl State {
    /// Every IPv4 route on the fake machine as the OS would list it, the
    /// product's and anybody else's, as interface and destination.
    fn table(&self) -> Vec<(String, Ipv4Net)> {
        let gateway = self.applied.gateway_routes.iter();
        let gateway =
            gateway.filter_map(|(dest, via)| Some((via.interface.clone(), host(*dest).ok()?)));
        let tunnel = self.applied.tunnel_routes.iter().cloned();
        let full = self.applied.full_tunnel.iter();
        let halves = full.flat_map(|full| v4_halves().map(|half| (full.tunnel.clone(), half)));
        gateway
            .chain(tunnel)
            .chain(halves)
            .chain(self.foreign.iter().cloned())
            .collect()
    }

    /// What full mode can do about IPv6 here, as the contract says: block it
    /// when the tunnel takes IPv6, nothing to block when there is no leak
    /// path either, and a refusal otherwise.
    fn ipv6_decision(&self) -> Result<Ipv6Block> {
        match (self.tunnel_ipv6, self.physical_ipv6) {
            (true, _) => Ok(Ipv6Block::Blocked),
            (false, false) => Ok(Ipv6Block::NothingToBlock),
            (false, true) => Err(Error::Unsupported),
        }
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
    /// A failing operation changes nothing, with three exceptions, each as
    /// an OS that fails part-way would: a failing
    /// [`Routes::add_tunnel_routes`] first adds every subnet but the last; a
    /// failing [`Routes::add_full_tunnel`] first adds the halves, when it
    /// would have added them; and a failing [`Dns::set_catch_all_dns`]
    /// first sets the catch-all, when it would have set it. A failing check
    /// answers [`Verified::Unknown`].
    pub fn set_failure(&self, op: Op, error: Option<Error>) {
        let mut state = self.state();
        match error {
            Some(error) => state.failures.insert(op, error),
            None => state.failures.remove(&op),
        };
    }

    /// Makes every later check `op` ([`Op::VerifyRoute`] or
    /// [`Op::VerifyDns`]) answer [`Verified::Unobservable`] where it would
    /// answer `Yes`, as Windows does for split DNS; `false` ends that. A
    /// `No` stays `No`. A real route check never answers it; the fake can,
    /// so that tests show the service refuses it.
    pub fn cannot_observe(&self, op: Op, unobservable: bool) {
        let mut state = self.state();
        match unobservable {
            true => state.unobservable.insert(op),
            false => state.unobservable.remove(&op),
        };
    }

    /// The same for the route check to `dest` alone: every later
    /// [`Routes::uses_interface`] for `dest` that would answer `Yes` answers
    /// [`Verified::Unobservable`]. Checks for other destinations are not
    /// changed, so a test can show each one is refused on its own.
    pub fn cannot_observe_route_to(&self, dest: Ipv4Addr) {
        self.state().unobservable_routes.insert(dest);
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

    /// Makes every later [`Routes::uses_interface`] for `dest` answer
    /// [`Verified::Unknown`], whatever it is asked, as a check that could
    /// not read the table would.
    pub fn cannot_tell_route_to(&self, dest: Ipv4Addr) {
        self.state().untold_routes.insert(dest);
    }

    /// Sets the router the next [`Routes::capture_physical`] reports, and
    /// the resolver every name uses until DNS rules say otherwise.
    pub fn set_router(&self, router: Ipv4Addr) {
        self.state().router = router;
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

    /// Whether the tunnel device has IPv6, so that [`Routes::add_full_tunnel`]
    /// can add the IPv6 halves on it, and whether the machine has an IPv6
    /// leak path (see [`Routes::full_tunnel_ipv6`]), played by the physical
    /// network's IPv6 default route. Both are true until a test says
    /// otherwise. Tell a subscriber with [`NetworkEvent::Ipv6Changed`].
    pub fn set_ipv6(&self, tunnel: bool, physical: bool) {
        let mut state = self.state();
        state.tunnel_ipv6 = tunnel;
        state.physical_ipv6 = physical;
    }

    /// Puts the machine on `net` through `adapter`, an adapter that is not
    /// the physical one, such as a virtual machine program's host-only
    /// network: the next [`Routes::capture_physical`] counts it among the
    /// networks the machine is on, and an address in it leaves by `adapter`.
    pub fn add_adapter_network(&self, adapter: &str, net: Ipv4Net) {
        let mut state = self.state();
        state.adapters.push((adapter.to_string(), net));
        if !state.on_link.contains(&net) {
            state.on_link.push(net);
        }
    }

    /// Makes [`Routes::add_tunnel_routes`] report `net` added without adding
    /// it, as an OS that lost a route would; `false` ends that.
    pub fn lose_tunnel_route(&self, net: Ipv4Net, lost: bool) {
        let mut state = self.state();
        match lost {
            true => state.lost.insert(net),
            false => state.lost.remove(&net),
        };
    }

    /// Whether a subscription sends [`NetworkEvent::Ipv6Changed`]; `true`
    /// until a test says otherwise.
    pub fn set_reports_ipv6_changes(&self, reports: bool) {
        self.state().reports_ipv6 = reports;
    }

    /// Plays a rule that is not the product's taking every name, such as
    /// another VPN's, or takes it away.
    pub fn set_foreign_catch_all(&self, present: bool) {
        self.state().foreign_catch_all = present;
    }

    /// The resolvers a lookup of `name` would go to now: the split DNS
    /// resolvers for a chosen domain and the names under it; for every other
    /// name, the catch-all's resolvers when one is set, otherwise the
    /// machine's usual one.
    pub fn resolvers_for(&self, name: &str) -> Vec<Ipv4Addr> {
        let state = self.state();
        let under = |domain: &String| {
            let above = name.strip_suffix(domain.as_str());
            above.is_some_and(|rest| rest.is_empty() || rest.ends_with('.'))
        };
        match (&state.applied.split_dns, &state.applied.catch_all_dns) {
            (Some((_, dns)), _) if dns.domains.iter().any(under) => dns.resolvers.clone(),
            (_, Some(all)) => all.clone(),
            _ => vec![state.router],
        }
    }

    /// Delivers `event` to every subscriber.
    pub fn send_event(&self, event: NetworkEvent) {
        let state = self.state();
        for subscriber in state.subscribers.values() {
            let _ = subscriber.send(event);
        }
    }

    /// How many subscriptions are live. A dropped [`Subscription`] is gone
    /// at once.
    pub fn subscriptions(&self) -> usize {
        self.state().subscribers.len()
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
            next_hop: Some(state.router),
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
                Present::None if state.lost.contains(subnet) => {}
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
        if let Some(full) = state.applied.full_tunnel.take() {
            for half in v4_halves() {
                state.forget(&full.tunnel, half);
            }
        }
        Ok(())
    }

    /// Picks a route as an OS does: the most specific one wins, so a host
    /// route beats any subnet, the networks the machine is on beat a wider
    /// route that contains them and the halves of full mode, and everything
    /// else leaves by the physical interface. Routes somebody else added
    /// count like the product's own.
    fn uses_interface(&self, dest: Ipv4Addr, interface: &str) -> Verified {
        let (state, outcome) = self.start(Op::VerifyRoute);
        if outcome.is_err() || state.untold_routes.contains(&dest) {
            return Verified::Unknown;
        }
        let applied = &state.applied;
        let host = applied.gateway_routes.iter().find(|(d, _)| *d == dest);
        // The machine's own networks are routes too: more specific than a
        // wider chosen subnet and than the halves of full mode.
        // Each through its own adapter: the physical one unless another was
        // named for it.
        let adapter = |net: &Ipv4Net| {
            let named = state.adapters.iter().find(|(_, n)| n == net);
            named.map_or(PHYSICAL_INTERFACE, |(name, _)| name.as_str())
        };
        let on_link = state.on_link.iter();
        let local = on_link.map(|net| (adapter(net).to_string(), *net));
        let table: Vec<_> = state.table().into_iter().chain(local).collect();
        let narrowest = table
            .iter()
            .filter(|(_, subnet)| subnet.contains_addr(dest))
            .max_by_key(|(_, subnet)| subnet.prefix_len());
        let used = match (host, narrowest) {
            (Some((_, physical)), _) => physical.interface(),
            (None, Some((tunnel, _))) => tunnel.as_str(),
            (None, None) => PHYSICAL_INTERFACE,
        };
        match used == interface {
            true => state.route_confirmed(dest),
            false => Verified::No,
        }
    }

    fn full_tunnel_ipv6(&self, _tunnel: &str) -> Result<Ipv6Block> {
        let (state, outcome) = self.start(Op::FullTunnelIpv6);
        outcome?;
        state.ipv6_decision()
    }

    /// Decides about IPv6 first, as the contract says, and refuses having
    /// added nothing. Then adds the halves. A half through another
    /// interface fails with [`Error::AlreadyExists`] before anything is
    /// added; where an OS would have added the first half, the fake adds
    /// none, which only makes less to remove. Told to fail, it adds the
    /// halves first, as an OS that failed after adding them would.
    fn add_full_tunnel(&self, tunnel: &str) -> Result<Ipv6Block> {
        let (mut state, outcome) = self.start(Op::AddFullTunnel);
        if state.absent.contains(tunnel) {
            return outcome.and(Err(Error::NotFound));
        }
        let ipv6 = match state.ipv6_decision() {
            Ok(ipv6) => ipv6,
            Err(refused) => return outcome.and(Err(refused)),
        };
        let elsewhere = |half| matches!(state.route_to(half, tunnel), Present::Elsewhere);
        if v4_halves().into_iter().any(elsewhere) {
            return outcome.and(Err(Error::AlreadyExists));
        }
        let full = FullTunnel {
            tunnel: tunnel.to_string(),
            ipv6,
        };
        state.applied.full_tunnel = Some(full);
        outcome.map(|()| ipv6)
    }

    fn remove_full_tunnel(&self, tunnel: &str) -> Result<()> {
        let (mut state, outcome) = self.start(Op::RemoveFullTunnel);
        outcome?;
        let ours = state.applied.full_tunnel.as_ref();
        if ours.is_some_and(|full| full.tunnel == tunnel) {
            state.applied.full_tunnel = None;
            for half in v4_halves() {
                state.forget(tunnel, half);
            }
        }
        Ok(())
    }

    fn foreign_full_tunnel(&self, tunnel: &str) -> Result<bool> {
        let (state, outcome) = self.start(Op::ForeignFullTunnel);
        outcome?;
        let halves = v4_halves();
        let foreign = state.foreign.iter();
        Ok(foreign
            .filter(|(name, _)| name != tunnel)
            .any(|(_, dest)| halves.contains(dest)))
    }

    /// The fake's IPv6 table: link-local through the physical network, the
    /// halves through the tunnel when they were added, and a default route
    /// through the physical network when it has IPv6. The longest prefix
    /// wins.
    fn uses_interface_v6(&self, dest: Ipv6Addr, interface: &str) -> Verified {
        let (state, outcome) = self.start(Op::VerifyRouteV6);
        if outcome.is_err() {
            return Verified::Unknown;
        }
        let link_local = dest.segments()[0] & 0xffc0 == 0xfe80;
        let blocked = state
            .applied
            .full_tunnel
            .as_ref()
            .filter(|full| full.ipv6 == Ipv6Block::Blocked);
        let used = match (link_local, blocked) {
            (true, _) => Some(PHYSICAL_INTERFACE),
            (false, Some(full)) => Some(full.tunnel.as_str()),
            (false, None) if state.physical_ipv6 => Some(PHYSICAL_INTERFACE),
            (false, None) => None,
        };
        match used == Some(interface) {
            true => state.confirmed(Op::VerifyRouteV6),
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

    /// Removes the catch-all too, as the contract says.
    fn clear_split_dns(&self) -> Result<()> {
        self.run(Op::ClearSplitDns, |applied| {
            applied.split_dns = None;
            applied.catch_all_dns = None;
        })
    }

    fn split_dns_matches(&self, dns: &SplitDns) -> Verified {
        let (state, outcome) = self.start(Op::VerifyDns);
        if outcome.is_err() {
            return Verified::Unknown;
        }
        match &state.applied.split_dns {
            Some((_, set)) if set == dns => state.confirmed(Op::VerifyDns),
            _ => Verified::No,
        }
    }

    /// Told to fail, it sets the catch-all first, as an OS that failed after
    /// writing the rule would.
    fn set_catch_all_dns(&self, resolvers: &[Ipv4Addr]) -> Result<()> {
        let (mut state, outcome) = self.start(Op::SetCatchAllDns);
        if state.foreign_catch_all {
            return outcome.and(Err(Error::AlreadyExists));
        }
        if resolvers.is_empty() {
            return outcome.and(Err(Error::InvalidInput));
        }
        state.applied.catch_all_dns = Some(resolvers.to_vec());
        outcome
    }

    fn clear_catch_all_dns(&self) -> Result<()> {
        self.run(Op::ClearCatchAllDns, |applied| applied.catch_all_dns = None)
    }

    fn catch_all_dns_matches(&self, resolvers: &[Ipv4Addr]) -> Verified {
        let (state, outcome) = self.start(Op::VerifyCatchAllDns);
        if outcome.is_err() {
            return Verified::Unknown;
        }
        match &state.applied.catch_all_dns {
            Some(set) if set == resolvers && !state.foreign_catch_all => {
                state.confirmed(Op::VerifyCatchAllDns)
            }
            _ => Verified::No,
        }
    }

    fn foreign_catch_all(&self) -> Result<bool> {
        let (state, outcome) = self.start(Op::ForeignCatchAll);
        outcome?;
        Ok(state.foreign_catch_all)
    }
}

impl NetworkEvents for Fake {
    fn reports_ipv6_changes(&self) -> bool {
        self.state().reports_ipv6
    }

    /// Delivers only what [`Fake::send_event`] injects, whatever is watched.
    fn subscribe(&self, _watching: &PhysicalNetwork) -> Result<Subscription> {
        let (mut state, outcome) = self.start(Op::Subscribe);
        outcome?;
        let (sender, receiver) = mpsc::channel();
        state.next_subscriber += 1;
        let id = state.next_subscriber;
        state.subscribers.insert(id, sender);
        let ends = Unsubscribe {
            fake: self.clone(),
            id,
        };
        Ok(Subscription::new(receiver, ends))
    }
}

/// Removes one subscriber from the fake when dropped.
struct Unsubscribe {
    fake: Fake,
    id: u64,
}

impl Drop for Unsubscribe {
    fn drop(&mut self) {
        self.fake.state().subscribers.remove(&self.id);
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

    fn net(text: &str) -> Ipv4Net {
        text.parse().unwrap()
    }

    // Full mode sends every IPv4 address through the tunnel but the
    // machine's own networks, their router and the gateway, which keep
    // their more specific routes; IPv6 goes to the tunnel too, where it
    // fails, but link-local stays. Removing the halves puts it all back,
    // and nothing is left after a teardown.
    #[test]
    fn full_mode_takes_all_but_the_local_network() {
        let fake = Fake::new();
        let physical = fake.capture_physical(GATEWAY).unwrap();
        assert!(physical.router_is_on_link());
        fake.add_gateway_route(GATEWAY, &physical).unwrap();
        fake.add_tunnel_routes(TUNNEL, &[net("10.255.0.0/16")])
            .unwrap();
        let elsewhere = Ipv4Addr::new(1, 0, 0, 1);
        let high = Ipv4Addr::new(203, 0, 113, 1);
        let v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        assert_eq!(fake.uses_interface(elsewhere, TUNNEL), Verified::No);
        assert_eq!(
            fake.uses_interface_v6(v6, PHYSICAL_INTERFACE),
            Verified::Yes
        );

        assert_eq!(fake.add_full_tunnel(TUNNEL), Ok(Ipv6Block::Blocked));
        for dest in [elsewhere, high, Ipv4Addr::new(10, 255, 0, 1)] {
            assert_eq!(fake.uses_interface(dest, TUNNEL), Verified::Yes, "{dest}");
        }
        for dest in [GATEWAY, ROUTER, Ipv4Addr::new(192, 168, 0, 20)] {
            let direct = fake.uses_interface(dest, PHYSICAL_INTERFACE);
            assert_eq!(direct, Verified::Yes, "{dest}");
        }
        assert_eq!(fake.uses_interface_v6(v6, TUNNEL), Verified::Yes);
        let local = fake.uses_interface_v6(LINK_LOCAL_V6, PHYSICAL_INTERFACE);
        assert_eq!(local, Verified::Yes);

        fake.remove_full_tunnel(TUNNEL).unwrap();
        assert_eq!(fake.uses_interface(elsewhere, TUNNEL), Verified::No);
        assert_eq!(fake.uses_interface_v6(v6, TUNNEL), Verified::No);
        assert_eq!(fake.add_full_tunnel(TUNNEL), Ok(Ipv6Block::Blocked));
        fake.remove_all().unwrap();
        fake.clear_split_dns().unwrap();
        assert_eq!(fake.applied(), Applied::default());
    }

    // Security rule: IPv6 is blocked in full mode, or there is none to
    // block. What can be done is read first, so a refusal (a tunnel with no
    // IPv6 on a machine with an IPv6 leak path) comes before anything is
    // added; with no IPv6 anywhere it goes ahead, and says so.
    #[test]
    fn ipv6_is_blocked_or_absent_never_left_open() {
        let fake = Fake::new();
        assert_eq!(fake.full_tunnel_ipv6(TUNNEL), Ok(Ipv6Block::Blocked));
        fake.set_ipv6(false, true);
        assert_eq!(fake.full_tunnel_ipv6(TUNNEL), Err(Error::Unsupported));
        assert_eq!(fake.add_full_tunnel(TUNNEL), Err(Error::Unsupported));
        assert_eq!(fake.applied().full_tunnel, None, "added before refusing");
        let v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let elsewhere = Ipv4Addr::new(1, 0, 0, 1);
        assert_eq!(fake.uses_interface(elsewhere, TUNNEL), Verified::No);

        fake.set_ipv6(false, false);
        assert_eq!(fake.full_tunnel_ipv6(TUNNEL), Ok(Ipv6Block::NothingToBlock));
        assert_eq!(fake.add_full_tunnel(TUNNEL), Ok(Ipv6Block::NothingToBlock));
        assert_eq!(fake.uses_interface(elsewhere, TUNNEL), Verified::Yes);
        assert_eq!(fake.uses_interface_v6(v6, TUNNEL), Verified::No);
        assert_eq!(fake.uses_interface_v6(v6, PHYSICAL_INTERFACE), Verified::No);
        // A snapshot: when a leak path appears later, the check says so.
        fake.set_ipv6(false, true);
        assert_eq!(fake.full_tunnel_ipv6(TUNNEL), Err(Error::Unsupported));
    }

    // A machine with a home LAN and two host-only adapters, none of them a
    // UBC range: full mode keeps every one of those networks direct, their
    // routers included, and takes everything else.
    #[test]
    fn full_mode_keeps_every_network_the_machine_is_on() {
        let fake = Fake::new();
        // The home network is the physical one; the host-only networks are
        // on adapters of their own, as a virtual machine program makes them.
        let router = Ipv4Addr::new(10, 200, 0, 1);
        fake.set_router(router);
        fake.set_local(&[Ipv4Addr::new(10, 200, 0, 10)], &[net("10.200.0.0/24")]);
        fake.add_adapter_network("fake-host1", net("172.31.130.0/24"));
        fake.add_adapter_network("fake-host2", net("172.31.140.0/24"));
        let physical = fake.capture_physical(GATEWAY).unwrap();
        assert_eq!(physical.next_hop(), Some(router));
        assert!(physical.router_is_on_link());
        assert_eq!(physical.on_link().len(), 3);
        fake.add_gateway_route(GATEWAY, &physical).unwrap();
        assert_eq!(fake.add_full_tunnel(TUNNEL), Ok(Ipv6Block::Blocked));
        let direct = [
            (router, PHYSICAL_INTERFACE),
            (Ipv4Addr::new(10, 200, 0, 200), PHYSICAL_INTERFACE),
            (Ipv4Addr::new(172, 31, 130, 128), "fake-host1"),
            (Ipv4Addr::new(172, 31, 140, 254), "fake-host2"),
            (GATEWAY, PHYSICAL_INTERFACE),
        ];
        for (dest, adapter) in direct {
            assert_eq!(fake.uses_interface(dest, TUNNEL), Verified::No, "{dest}");
            assert_eq!(fake.uses_interface(dest, adapter), Verified::Yes, "{dest}");
            // Not the physical interface, for the host-only networks.
            let physical = fake.uses_interface(dest, PHYSICAL_INTERFACE);
            assert_eq!(physical == Verified::Yes, adapter == PHYSICAL_INTERFACE);
        }
        for dest in [Ipv4Addr::new(10, 201, 0, 1), Ipv4Addr::new(203, 0, 113, 1)] {
            assert_eq!(fake.uses_interface(dest, TUNNEL), Verified::Yes, "{dest}");
        }
        assert_eq!(fake.resolvers_for("www.example.org"), [router]);
    }

    // "On error some may have been added": a failing add of the halves or
    // set of the catch-all leaves them behind, so a service that does not
    // record them before it adds them fails its tests. A route check can be
    // made to say it could not tell, for one address only.
    #[test]
    fn failing_full_mode_steps_leave_what_they_did() {
        let fake = Fake::new();
        fake.set_failure(Op::AddFullTunnel, failed());
        fake.set_failure(Op::SetCatchAllDns, failed());
        assert!(fake.add_full_tunnel(TUNNEL).is_err());
        let resolvers = [Ipv4Addr::new(10, 255, 0, 53)];
        assert!(fake.set_catch_all_dns(&resolvers).is_err());
        let applied = fake.applied();
        assert!(applied.full_tunnel.is_some());
        assert_eq!(applied.catch_all_dns, Some(resolvers.to_vec()));
        fake.set_failure(Op::SetCatchAllDns, None);
        assert_eq!(fake.set_catch_all_dns(&[]), Err(Error::InvalidInput));

        let away = Ipv4Addr::new(203, 0, 113, 1);
        fake.cannot_tell_route_to(away);
        assert_eq!(fake.uses_interface(away, TUNNEL), Verified::Unknown);
        let other = Ipv4Addr::new(203, 0, 113, 2);
        assert_eq!(fake.uses_interface(other, TUNNEL), Verified::Yes);
    }

    // Another program's halves are a conflict: it is seen before anything
    // is changed, and an add over them fails, adding nothing.
    #[test]
    fn another_programs_halves_are_a_conflict() {
        let fake = Fake::new();
        assert_eq!(fake.foreign_full_tunnel(TUNNEL), Ok(false));
        fake.add_foreign_route("other-vpn0", net("128.0.0.0/1"));
        assert_eq!(fake.foreign_full_tunnel(TUNNEL), Ok(true));
        assert_eq!(fake.add_full_tunnel(TUNNEL), Err(Error::AlreadyExists));
        assert_eq!(fake.applied().full_tunnel, None);
        // One the tunnel itself has is no conflict.
        fake.remove_foreign_route("other-vpn0", net("128.0.0.0/1"));
        fake.add_foreign_route(TUNNEL, net("0.0.0.0/1"));
        assert_eq!(fake.foreign_full_tunnel(TUNNEL), Ok(false));
    }

    // The catch-all sends every name the split domains do not take to its
    // resolvers. Another program's catch-all is a conflict, seen before and
    // refused on set. Clearing split DNS clears the catch-all too.
    #[test]
    fn the_catch_all_takes_every_other_name() {
        let fake = Fake::new();
        let tunnel_dns = Ipv4Addr::new(10, 255, 0, 53);
        let lab_dns = Ipv4Addr::new(10, 255, 1, 53);
        let split = SplitDns {
            resolvers: vec![lab_dns],
            domains: vec!["lab.example".to_string()],
        };
        fake.set_split_dns(TUNNEL, &split).unwrap();
        assert_eq!(fake.resolvers_for("www.example.org"), [ROUTER]);
        assert_eq!(fake.catch_all_dns_matches(&[tunnel_dns]), Verified::No);

        fake.set_catch_all_dns(&[tunnel_dns]).unwrap();
        assert_eq!(fake.resolvers_for("www.example.org"), [tunnel_dns]);
        assert_eq!(fake.resolvers_for("a.lab.example"), [lab_dns]);
        assert_eq!(fake.catch_all_dns_matches(&[tunnel_dns]), Verified::Yes);
        assert_eq!(fake.catch_all_dns_matches(&[lab_dns]), Verified::No);
        fake.clear_catch_all_dns().unwrap();
        assert_eq!(fake.resolvers_for("www.example.org"), [ROUTER]);
        assert_eq!(fake.applied().split_dns.map(|(_, dns)| dns), Some(split));

        fake.set_catch_all_dns(&[tunnel_dns]).unwrap();
        fake.clear_split_dns().unwrap();
        assert_eq!(fake.applied().catch_all_dns, None);

        assert_eq!(fake.foreign_catch_all(), Ok(false));
        fake.set_foreign_catch_all(true);
        assert_eq!(fake.foreign_catch_all(), Ok(true));
        assert_eq!(
            fake.set_catch_all_dns(&[tunnel_dns]),
            Err(Error::AlreadyExists)
        );
        assert_eq!(fake.applied().catch_all_dns, None);
    }

    // A router outside every network the machine is on would be routed into
    // the tunnel by the halves, so full mode needs it on-link.
    #[test]
    fn the_router_must_be_on_a_local_network() {
        let fake = Fake::new();
        fake.set_local(&[OWN_ADDRESS], &[]);
        let physical = fake.capture_physical(GATEWAY).unwrap();
        assert!(!physical.router_is_on_link());
        fake.set_local(&[OWN_ADDRESS], &[net("10.0.0.0/8"), net("192.168.0.0/24")]);
        let physical = fake.capture_physical(GATEWAY).unwrap();
        assert!(physical.router_is_on_link());
        let direct = PhysicalNetwork {
            next_hop: None,
            on_link: Vec::new(),
            ..physical
        };
        assert!(direct.router_is_on_link());
    }

    fn user(name: &str) -> UserId {
        name.parse().unwrap()
    }

    fn subnets() -> [Ipv4Net; 2] {
        ["192.0.2.0/24", "198.51.100.0/24"].map(|s| s.parse().unwrap())
    }

    fn failed() -> Option<Error> {
        Some(Error::Failed("injected".to_string()))
    }

    // Security rule: the shared DNS check accepts "in effect, but the OS
    // cannot show it" in place of a "yes", and nothing weaker.
    #[test]
    fn the_dns_check_accepts_yes_or_unobservable_and_nothing_else() {
        let passes = |verdict| {
            std::panic::catch_unwind(|| suite::assert_in_effect(verdict, "split DNS")).is_ok()
        };
        assert!(passes(Verified::Yes));
        assert!(passes(Verified::Unobservable));
        assert!(!passes(Verified::No));
        assert!(!passes(Verified::Unknown));
        // An OS that cannot observe its resolver still passes the suite.
        let fake = Fake::new();
        fake.cannot_observe(Op::VerifyDns, true);
        suite::check_dns(&fake, TUNNEL, &|name| fake.resolvers_for(name));
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
            domains: vec!["dept.example".to_string()],
        };
        fake.set_failure(Op::SetSplitDns, Some(Error::Unsupported));
        assert_eq!(fake.set_split_dns(TUNNEL, &dns), Err(Error::Unsupported));
        assert_eq!(fake.applied(), Applied::default());
        assert_eq!(fake.resolvers_for("www.dept.example"), [ROUTER]);
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
            fn full_tunnel_ipv6(&self, tunnel: &str) -> Result<Ipv6Block> {
                self.0.full_tunnel_ipv6(tunnel)
            }
            fn add_full_tunnel(&self, tunnel: &str) -> Result<Ipv6Block> {
                self.0.add_full_tunnel(tunnel)
            }
            fn remove_full_tunnel(&self, tunnel: &str) -> Result<()> {
                self.0.remove_full_tunnel(tunnel)
            }
            fn foreign_full_tunnel(&self, tunnel: &str) -> Result<bool> {
                self.0.foreign_full_tunnel(tunnel)
            }
            fn uses_interface_v6(&self, dest: Ipv6Addr, interface: &str) -> Verified {
                self.0.uses_interface_v6(dest, interface)
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
            domains: vec!["dept.example".to_string()],
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
            domains: vec!["dept.example".to_string()],
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

    // A check that cannot be observed answers so only where it would have
    // answered "yes". A setting that differs is still "no", and a check
    // that could not ask is still "could not tell".
    #[test]
    fn cannot_observe_replaces_only_a_yes() {
        let fake = Fake::new();
        let dns = SplitDns {
            resolvers: vec![Ipv4Addr::new(192, 0, 2, 53)],
            domains: vec!["dept.example".to_string()],
        };
        let other = SplitDns {
            domains: vec!["other.example".to_string()],
            ..dns.clone()
        };
        fake.set_split_dns(TUNNEL, &dns).unwrap();
        fake.cannot_observe(Op::VerifyDns, true);
        assert_eq!(fake.split_dns_matches(&dns), Verified::Unobservable);
        assert_eq!(fake.split_dns_matches(&other), Verified::No);
        // Only the check it was asked for.
        let route = fake.uses_interface(GATEWAY, PHYSICAL_INTERFACE);
        assert_eq!(route, Verified::Yes);
        fake.set_failure(Op::VerifyDns, failed());
        assert_eq!(fake.split_dns_matches(&dns), Verified::Unknown);
        fake.set_failure(Op::VerifyDns, None);
        fake.cannot_observe(Op::VerifyDns, false);
        assert_eq!(fake.split_dns_matches(&dns), Verified::Yes);
        // One destination alone, and a route "no" stays "no".
        let elsewhere = Ipv4Addr::new(198, 51, 100, 1);
        fake.cannot_observe_route_to(GATEWAY);
        let route = fake.uses_interface(GATEWAY, PHYSICAL_INTERFACE);
        assert_eq!(route, Verified::Unobservable);
        let route = fake.uses_interface(elsewhere, PHYSICAL_INTERFACE);
        assert_eq!(route, Verified::Yes);
        assert_eq!(fake.uses_interface(GATEWAY, TUNNEL), Verified::No);
        // Every route.
        fake.cannot_observe(Op::VerifyRoute, true);
        let route = fake.uses_interface(elsewhere, PHYSICAL_INTERFACE);
        assert_eq!(route, Verified::Unobservable);
        assert_eq!(fake.uses_interface(elsewhere, TUNNEL), Verified::No);
    }

    // A subscription whose drop never returns fails the suite's check, and
    // the check does not hang on the ones it had not dropped yet.
    #[test]
    fn a_subscription_that_never_ends_fails_the_check_without_hanging_it() {
        /// Ends never: dropping it waits for ever.
        struct Stuck;
        impl Drop for Stuck {
            fn drop(&mut self) {
                loop {
                    std::thread::park();
                }
            }
        }
        struct Hanging(std::sync::Arc<std::sync::atomic::AtomicUsize>);
        impl NetworkEvents for Hanging {
            fn subscribe(&self, _watching: &PhysicalNetwork) -> Result<Subscription> {
                self.0.fetch_add(1, Ordering::SeqCst);
                let (_sender, receiver) = mpsc::channel();
                Ok(Subscription::new(receiver, Stuck))
            }
            fn reports_ipv6_changes(&self) -> bool {
                false
            }
        }
        let fake = Fake::new();
        let physical = fake.capture_physical(GATEWAY).unwrap();
        let count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let hanging = Hanging(count.clone());
        let (done, finished) = mpsc::channel();
        std::thread::spawn(move || {
            let check = std::panic::AssertUnwindSafe(|| {
                suite::check_subscription_ends(&hanging, &physical, &|| {
                    count.load(Ordering::SeqCst)
                });
            });
            let _ = done.send(std::panic::catch_unwind(check).is_err());
        });
        let failed = finished.recv_timeout(Duration::from_secs(20));
        assert_eq!(failed, Ok(true), "the check hung or passed");
    }

    // A dropped subscription is gone at once, and the suite notices one that
    // lingers until the next event.
    #[test]
    fn a_dropped_subscription_ends_at_once() {
        let fake = Fake::new();
        let physical = fake.capture_physical(GATEWAY).unwrap();
        suite::check_subscription_ends(&fake, &physical, &|| fake.subscriptions());

        // One that ends only when it next has something to deliver.
        struct Lingering(Fake);
        impl NetworkEvents for Lingering {
            fn subscribe(&self, watching: &PhysicalNetwork) -> Result<Subscription> {
                let inner = self.0.subscribe(watching)?;
                let (sender, receiver) = mpsc::channel();
                drop(sender);
                // Keeps the fake's subscription after the drop.
                std::mem::forget(inner);
                Ok(Subscription::new(receiver, ()))
            }
            fn reports_ipv6_changes(&self) -> bool {
                false
            }
        }
        let lingering = Lingering(fake.clone());
        let check = std::panic::AssertUnwindSafe(|| {
            suite::check_subscription_ends(&lingering, &physical, &|| fake.subscriptions());
        });
        assert!(std::panic::catch_unwind(check).is_err());
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
        assert_eq!(first.events().try_recv(), Ok(NetworkEvent::PhysicalChanged));
        assert_eq!(first.events().try_recv(), Ok(NetworkEvent::Sleeping));
        assert_eq!(
            second.events().try_recv(),
            Ok(NetworkEvent::PhysicalChanged)
        );

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
