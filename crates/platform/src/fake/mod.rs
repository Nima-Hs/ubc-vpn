//! An in-memory implementation of the seam, for tests and for the service's
//! dev mode. It touches nothing outside the process.
//!
//! A [`Fake`] records every routing and DNS call in order and keeps the state
//! those calls add up to, so a test can assert both. It can be told to fail
//! an operation, it delivers the network events a test injects, and its
//! channel lets a test choose who each caller is.

mod dns;
mod events;
mod routes;
#[cfg(test)]
mod tests;
mod transport;

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, MutexGuard};

use ubc_vpn_core::routes::Ipv4Net;

use crate::on_link::{AddressRow, DadState};
use crate::{
    Connection, Error, Ipv6Block, NetworkEvent, Paths, PhysicalNetwork, Platform, Result, SplitDns,
    UserId, Verified, lock,
};
#[cfg(doc)]
use crate::{Dns, Listener, NetworkEvents, Routes, Subscription, Transport};
use transport::pipe_pair;

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
    /// Addresses the OS lists but does not use, such as a disconnected
    /// adapter's tentative link-local one: no route comes with them.
    unused: Vec<AddressRow>,
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
            unused: Vec::new(),
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

    /// Gives the machine an address the OS lists but does not use, as
    /// Windows lists a disconnected adapter's tentative `169.254.x.x`
    /// address: the next [`Routes::capture_physical`] counts it among the
    /// machine's own addresses but not its networks, and no route comes
    /// with it, so an address in it leaves as any other would.
    pub fn add_unused_address(&self, addr: Ipv4Addr, prefix_len: u8) {
        self.state().unused.push(AddressRow {
            addr,
            prefix_len,
            state: DadState::Tentative,
            interface_up: false,
        });
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
