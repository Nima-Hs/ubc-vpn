//! Changing the routes of a live tunnel, in the one order that never sends
//! a chosen network outside it: the new routes are added, then split DNS is
//! set for the new domains, then the dropped routes are removed, and then
//! everything is verified. Any step that fails stops the rest; the caller
//! then tears everything down, as for a connect that fails.
//!
//! Only routes this service added are ever removed: what is removed comes
//! from [`Applied`](crate::session::Applied), never from the system. The
//! routes to the gateway's DNS servers stay until the connection ends.

use std::net::Ipv4Addr;

use ubc_vpn_core::protocol::{ErrorCode, LogLevel};
use ubc_vpn_core::routes::{Ipv4Net, LocalNetworks, RouteSet, check_against_local};
use ubc_vpn_core::state::{TunnelInfo, TunnelMode};
use ubc_vpn_platform::{Error, SplitDns};

use crate::connect::{Failure, dns_servers};
use crate::session::Machine;
use crate::verify::{Confirmed, DNS_UNCONFIRMED, Expected, verify, verify_dropped};

/// What the lines about a change of routes are about, for the repeat rule.
/// A connection that reaches the gateway starts it afresh.
pub(crate) const CHANGED: &str = "a change of routes";

/// What the lines about split DNS that cannot be confirmed after a change
/// are about, for the repeat rule.
const UNCONFIRMED: &str = "split DNS after a change of routes";

/// What the log says when a change of routes was applied and checked.
pub const ROUTES_CHANGED: &str =
    "routes changed while connected and checked; the status shows what the tunnel carries";

impl Machine {
    /// Applies `chosen` to the live tunnel in place of the routes it has,
    /// and verifies the result. The request was checked before it was
    /// admitted, against the policy and the network the connection was set
    /// up on.
    pub(crate) fn change_routes(&mut self, chosen: RouteSet) -> Result<TunnelInfo, Failure> {
        let os =
            |what: &'static str| move |e: Error| (ErrorCode::Internal, format!("{what}: {e}."));
        let lost = || (ErrorCode::Internal, "The connection is not up.".to_string());
        let tunnel = self.applied.tunnel.as_ref().ok_or_else(lost)?;
        let assigned = tunnel.assigned().clone();
        let physical = self.applied.physical.clone().ok_or_else(lost)?;
        let gateway = self.applied.gateway_route.ok_or_else(lost)?;
        let interface = assigned.interface.as_str();

        // Split DNS needs the gateway's DNS servers routed through the
        // tunnel. A connection made with no domains has none yet.
        if !chosen.dns_domains.is_empty() && self.applied.dns_servers.is_empty() {
            let servers = dns_servers(&assigned.dns, gateway, &physical)?;
            let local = LocalNetworks {
                own_addresses: physical.own_addresses(),
                on_link: physical.on_link(),
                next_hop: physical.next_hop(),
            };
            let unusable = |conflict| {
                let why =
                    format!("The gateway assigned a DNS server that cannot be used: {conflict}.");
                (ErrorCode::EngineFailed, why)
            };
            check_against_local(&servers, gateway, &local).map_err(unusable)?;
            // Known before they are added, so teardown removes them.
            self.applied.routes.extend(&servers);
            self.applied.dns_servers.clone_from(&servers);
            let routed = self.routes.add_tunnel_routes(interface, &servers);
            routed.map_err(os("The DNS server routes could not be added"))?;
        }

        // 1. The new routes, each known before it is added.
        let mut added: Vec<Ipv4Net> = Vec::new();
        for subnet in &chosen.subnets {
            if !self.applied.routes.contains(subnet) && !added.contains(subnet) {
                added.push(*subnet);
            }
        }
        self.applied.routes.extend(&added);
        let routed = self.routes.add_tunnel_routes(interface, &added);
        routed.map_err(os("The new tunnel routes could not be added"))?;

        // 2. Split DNS for the new domains, or none.
        let dns = (!chosen.dns_domains.is_empty()).then(|| SplitDns {
            resolvers: self.applied.dns_servers.iter().map(Ipv4Net::addr).collect(),
            domains: chosen.dns_domains.clone(),
        });
        match &dns {
            Some(dns) => {
                let set = self.dns.set_split_dns(interface, dns);
                set.map_err(os("Split DNS could not be set"))?;
            }
            None if !self.applied.dns_domains.is_empty() => {
                let cleared = self.dns.clear_split_dns();
                cleared.map_err(os("Split DNS could not be cleared"))?;
            }
            None => {}
        }
        self.applied.dns_domains.clone_from(&chosen.dns_domains);

        // 3. The dropped routes: only subnets this service added for the
        // user, never a DNS server's route. Each stays known until it is
        // removed.
        let dropped: Vec<Ipv4Net> = self
            .applied
            .subnets
            .iter()
            .filter(|subnet| !chosen.subnets.contains(subnet))
            .filter(|subnet| !self.applied.dns_servers.contains(subnet))
            .copied()
            .collect();
        let removed = self.routes.remove_tunnel_routes(interface, &dropped);
        removed.map_err(os("The dropped tunnel routes could not be removed"))?;
        self.applied.routes.retain(|route| !dropped.contains(route));
        self.applied.subnets.clone_from(&chosen.subnets);

        // 4. Everything as it now should be, and the dropped ones gone.
        let servers: Vec<Ipv4Addr> = self.applied.dns_servers.iter().map(Ipv4Net::addr).collect();
        let expected = Expected {
            tunnel: interface,
            physical: &physical,
            gateway,
            subnets: &chosen.subnets,
            dns: dns.as_ref(),
            dns_servers: &servers,
        };
        let verified = verify(&*self.routes, &*self.dns, &expected);
        let confirmed = verified.map_err(|why| (ErrorCode::VerificationFailed, why))?;
        let remaining = &self.applied.routes;
        let gone = verify_dropped(&*self.routes, &expected, &dropped, remaining);
        gone.map_err(|why| (ErrorCode::VerificationFailed, why))?;

        // Under the repeat rule, in one form whatever the change: a change
        // costs the client nothing, so changes asked for again and again
        // must not fill the log. What the tunnel carries is in the status.
        self.logs.at_about(LogLevel::Info, CHANGED, ROUTES_CHANGED);
        if confirmed == Confirmed::DnsUnobservable {
            self.logs
                .at_about(LogLevel::Warn, UNCONFIRMED, DNS_UNCONFIRMED);
        }
        Ok(TunnelInfo {
            interface: assigned.interface.clone(),
            address: assigned.address.to_string(),
            subnets: chosen.subnets,
            dns_domains: chosen.dns_domains,
            mode: TunnelMode::Split,
        })
    }
}
