//! The fake's routing: the table its calls add up to, and how it picks a
//! route.

use std::net::{Ipv4Addr, Ipv6Addr};

use ubc_vpn_core::routes::Ipv4Net;

use super::{Fake, FullTunnel, Op, PHYSICAL_INTERFACE, State};
use crate::on_link::{AddressRow, DadState, usable_networks};
use crate::{Error, FULL_TUNNEL_V4, Ipv6Block, PhysicalNetwork, Result, Routes, Verified};

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

/// The two IPv6 halves of full mode, as destination and prefix length.
const V6_HALVES: [(Ipv6Addr, u8); 2] = [
    (Ipv6Addr::UNSPECIFIED, 1),
    (Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0), 1),
];

/// An IPv6 route: the interface, the destination and its prefix length.
type RouteV6 = (String, Ipv6Addr, u8);

/// Whether `addr` is in the network `dest`/`len`.
fn contains_v6(dest: Ipv6Addr, len: u8, addr: Ipv6Addr) -> bool {
    let mask = u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0);
    u128::from(dest) & mask == u128::from(addr) & mask
}

/// Whether IPv6 could leave by a route to `dest`/`len`, as the contract
/// counts a leak path: any unicast route but link-local, loopback and
/// multicast.
fn leaks(dest: Ipv6Addr, len: u8) -> bool {
    let first = dest.segments()[0];
    let link_local = len >= 10 && first & 0xffc0 == 0xfe80;
    let multicast = len >= 8 && first & 0xff00 == 0xff00;
    let loopback = len == 128 && dest == Ipv6Addr::LOCALHOST;
    !(link_local || multicast || loopback)
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

    /// Whether `interface` takes IPv6 routes: nobody turned IPv6 off for it.
    fn has_ipv6(&self, interface: &str) -> bool {
        !self.ipv6_off.contains(interface)
    }

    /// Every IPv6 route on the fake machine: link-local through the
    /// physical network, its default route when it has IPv6, the halves
    /// when they block IPv6, and anybody else's. An interface with IPv6
    /// turned off has none.
    fn table_v6(&self) -> Vec<RouteV6> {
        let physical = PHYSICAL_INTERFACE.to_string();
        let link_local = (
            physical.clone(),
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0),
            10,
        );
        let default = (physical, Ipv6Addr::UNSPECIFIED, 0);
        let default = self.physical_ipv6.then_some(default);
        let full = self.applied.full_tunnel.iter();
        let blocking = full.filter(|full| full.ipv6 == Ipv6Block::Blocked);
        let halves =
            blocking.flat_map(|full| V6_HALVES.map(|(dest, len)| (full.tunnel.clone(), dest, len)));
        std::iter::once(link_local)
            .chain(default)
            .chain(halves)
            .chain(self.foreign_v6.iter().cloned())
            .filter(|(interface, _, _)| self.has_ipv6(interface))
            .collect()
    }

    /// What full mode can do about IPv6 here, as the contract says: block it
    /// when the tunnel takes IPv6, nothing to block when there is no leak
    /// path either, and a refusal otherwise. A leak path is any unicast IPv6
    /// route, other than link-local, on an interface other than the tunnel.
    fn ipv6_decision(&self, tunnel: &str) -> Result<Ipv6Block> {
        let table = self.table_v6();
        let mut paths = table.iter().filter(|(interface, _, _)| interface != tunnel);
        let leak = paths.any(|(_, dest, len)| leaks(*dest, *len));
        match (self.tunnel_ipv6 && self.has_ipv6(tunnel), leak) {
            (true, _) => Ok(Ipv6Block::Blocked),
            (false, false) => Ok(Ipv6Block::NothingToBlock),
            (false, true) => Err(Error::Unsupported),
        }
    }

    /// Whether a half of `family` goes through an interface other than
    /// `tunnel`.
    fn half_elsewhere(&self, tunnel: &str, v6: bool) -> bool {
        match v6 {
            false => self
                .table()
                .iter()
                .any(|(i, dest)| i != tunnel && v4_halves().contains(dest)),
            true => self
                .table_v6()
                .iter()
                .any(|(i, dest, len)| i != tunnel && V6_HALVES.contains(&(*dest, *len))),
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

    /// The same for full mode's halves through `tunnel`, of both families.
    fn forget_halves(&mut self, tunnel: &str) {
        for half in v4_halves() {
            self.forget(tunnel, half);
        }
        let half = |(i, d, l): &RouteV6| i == tunnel && V6_HALVES.contains(&(*d, *l));
        self.foreign_v6.retain(|route| !half(route));
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
        // The networks the machine is on as the OS lists them: each one's
        // address in use on an interface that is up, beside the unused ones,
        // which the rule leaves out.
        let used = state.on_link.iter().map(|net| AddressRow {
            addr: net.addr(),
            prefix_len: net.prefix_len(),
            state: DadState::Preferred,
            interface_up: true,
        });
        let unused = state.unused.iter().copied();
        let mut own_addresses = state.own_addresses.clone();
        own_addresses.extend(state.unused.iter().map(|row| row.addr));
        Ok(PhysicalNetwork {
            interface: PHYSICAL_INTERFACE.to_string(),
            next_hop: Some(state.router),
            own_addresses,
            on_link: usable_networks(used.chain(unused)),
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
            state.forget_halves(&full.tunnel);
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
        // A route on a link that is down carries nothing.
        let narrowest = table
            .iter()
            .filter(|(interface, _)| !state.links_down.contains(interface))
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

    fn full_tunnel_ipv6(&self, tunnel: &str) -> Result<Ipv6Block> {
        let (state, outcome) = self.start(Op::FullTunnelIpv6);
        outcome?;
        state.ipv6_decision(tunnel)
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
        let ipv6 = match state.ipv6_decision(tunnel) {
            Ok(ipv6) => ipv6,
            Err(refused) => return outcome.and(Err(refused)),
        };
        let v6_elsewhere = ipv6 == Ipv6Block::Blocked && state.half_elsewhere(tunnel, true);
        if state.half_elsewhere(tunnel, false) || v6_elsewhere {
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
            state.forget_halves(tunnel);
        }
        Ok(())
    }

    /// Any half through another interface counts, this product's own
    /// through another tunnel too.
    fn foreign_full_tunnel(&self, tunnel: &str) -> Result<bool> {
        let (state, outcome) = self.start(Op::ForeignFullTunnel);
        outcome?;
        Ok(state.half_elsewhere(tunnel, false) || state.half_elsewhere(tunnel, true))
    }

    /// Picks from the fake's IPv6 table (see `table_v6`) by the longest
    /// prefix, on links that are up. Equally long routes that disagree
    /// about `interface` answer `Unknown`.
    fn uses_interface_v6(&self, dest: Ipv6Addr, interface: &str) -> Verified {
        let (state, outcome) = self.start(Op::VerifyRouteV6);
        if outcome.is_err() {
            return Verified::Unknown;
        }
        let table = state.table_v6();
        let matching: Vec<_> = table
            .iter()
            .filter(|(i, _, _)| !state.links_down.contains(i))
            .filter(|(_, net, len)| contains_v6(*net, *len, dest))
            .collect();
        let longest = matching.iter().map(|(_, _, len)| *len).max();
        let winners = matching.iter().filter(|(_, _, len)| Some(*len) == longest);
        let through: Vec<bool> = winners.map(|(i, _, _)| i == interface).collect();
        match (through.iter().all(|t| *t), through.iter().any(|t| *t)) {
            (true, true) => state.confirmed(Op::VerifyRouteV6),
            (_, false) => Verified::No,
            (false, true) => Verified::Unknown,
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

    /// Every subscription is told IPv6 changed, unless `interface` is a
    /// tunnel this product configured; the same for the three below.
    fn add_route_v6(&self, interface: &str, dest: Ipv6Addr, prefix_len: u8) {
        let route = (interface.to_string(), dest, prefix_len);
        let mut state = self.state();
        if !state.foreign_v6.contains(&route) {
            state.foreign_v6.push(route);
            state.ipv6_changed(interface);
        }
    }

    fn remove_route_v6(&self, interface: &str, dest: Ipv6Addr, prefix_len: u8) {
        let route = (interface.to_string(), dest, prefix_len);
        let mut state = self.state();
        if state.foreign_v6.contains(&route) {
            state.foreign_v6.retain(|foreign| *foreign != route);
            state.ipv6_changed(interface);
        }
    }

    fn add_address_v6(&self, interface: &str, address: Ipv6Addr) {
        let added = (interface.to_string(), address);
        let mut state = self.state();
        if !state.addresses_v6.contains(&added) {
            state.addresses_v6.push(added);
            state.ipv6_changed(interface);
        }
    }

    fn remove_address_v6(&self, interface: &str, address: Ipv6Addr) {
        let removed = (interface.to_string(), address);
        let mut state = self.state();
        if state.addresses_v6.contains(&removed) {
            state.addresses_v6.retain(|address| *address != removed);
            state.ipv6_changed(interface);
        }
    }

    /// A subscription watching `interface` is told its network changed.
    fn set_link(&self, interface: &str, up: bool) {
        let mut state = self.state();
        let changed = match up {
            true => state.links_down.remove(interface),
            false => state.links_down.insert(interface.to_string()),
        };
        if changed {
            state.physical_changed(interface);
        }
    }

    fn bind_ipv6(&self, interface: &str, on: bool) {
        let mut state = self.state();
        let changed = match on {
            true => state.ipv6_off.remove(interface),
            false => state.ipv6_off.insert(interface.to_string()),
        };
        if changed {
            state.ipv6_changed(interface);
        }
    }
}
