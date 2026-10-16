//! Changing the routes of a live tunnel, in the one order that never sends
//! a chosen network outside it: the new routes are added, then split DNS is
//! set for the new domains, then the dropped routes are removed, and then
//! everything is verified. Any step that fails stops the rest; the caller
//! then tears everything down, as for a connect that fails.
//!
//! Only routes this service added are ever removed: what is removed comes
//! from [`Applied`](crate::session::Applied), never from the system. The
//! routes to the gateway's DNS servers stay until the connection ends.
//!
//! In full mode the halves and the catch-all stay as they are, and the
//! result is checked as full mode.

use ubc_vpn_core::protocol::{ErrorCode, LogLevel};
use ubc_vpn_core::routes::{Ipv4Net, RouteSet};
use ubc_vpn_core::state::TunnelInfo;
use ubc_vpn_platform::{Error, FULL_TUNNEL_V4, SplitDns};

use crate::connect::Failure;
use crate::session::Machine;
use crate::verify::{Expected, verify_dropped};

/// What the lines about a change of routes are about, for the repeat rule.
/// A connection that reaches the gateway starts it afresh.
pub(crate) const CHANGED: &str = "a change of routes";

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
        let interface = assigned.interface.as_str();

        // Split DNS needs the gateway's DNS servers routed through the
        // tunnel. A connection made with no domains has none yet.
        if !chosen.dns_domains.is_empty() {
            self.route_dns_servers()?;
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
                self.applied.split_rules.clone_from(&dns.domains);
                let set = self.dns.set_split_dns(interface, dns);
                set.map_err(os("Split DNS could not be set"))?;
            }
            // In full mode split DNS stays: clearing it would take the
            // catch-all with it, and names would go to the local network's
            // resolver until it was set again. It names the same servers
            // as the catch-all, so it changes nothing, and it goes with
            // full mode or the connection.
            None if self.applied.catch_all => {}
            None if !self.applied.split_rules.is_empty() => {
                let cleared = self.dns.clear_split_dns();
                cleared.map_err(os("Split DNS could not be cleared"))?;
                self.applied.split_rules.clear();
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

        // 4. Everything as it now should be, and the dropped ones gone. In
        // full mode a dropped subnet goes on through the tunnel by the
        // halves, as it should.
        let mut remaining = self.applied.routes.clone();
        if self.applied.full {
            let halves = FULL_TUNNEL_V4
                .iter()
                .filter_map(|half| half.parse::<Ipv4Net>().ok());
            remaining.extend(halves);
        }
        let gone =
            |expected: &Expected<'_>| verify_dropped(&*self.routes, expected, &dropped, &remaining);
        let checked = self.check_applied(gone)?;

        // Under the repeat rule, in one form whatever the change: a change
        // costs the client nothing, so changes asked for again and again
        // must not fill the log. What the tunnel carries is in the status.
        self.logs.at_about(LogLevel::Info, CHANGED, ROUTES_CHANGED);
        self.say_unconfirmed(checked, true);
        self.tunnel_info().ok_or_else(lost)
    }
}
