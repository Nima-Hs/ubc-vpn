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
