//! Full mode: what it needs before anything is changed, and switching a live
//! tunnel into it and out of it.
//!
//! Each need is checked before anything is applied for it. At connect the
//! ones that need no tunnel are checked before the gateway is contacted, and
//! the rest once the tunnel is open and before anything is applied to it.
//! On a switch they are all checked before the switch is admitted, so a
//! refusal leaves the connection exactly as it was.
//!
//! A switch goes the way of a change of routes: to full, the DNS servers'
//! routes, then the halves, then the catch-all; to split, the catch-all
//! goes, then the halves; then everything is checked. Any step or check that
//! fails stops the rest, and the caller tears everything down. Each change
//! is in [`Applied`](crate::session::Applied) before it is made, so teardown
//! undoes whatever may have been made.

use std::net::Ipv4Addr;

use ubc_vpn_core::protocol::{ErrorCode, LogLevel};
use ubc_vpn_core::routes::Ipv4Net;
use ubc_vpn_core::state::{TunnelInfo, TunnelMode};
use ubc_vpn_platform::{Dns, Error, NetworkEvents, PhysicalNetwork, Routes};

use crate::connect::Failure;
use crate::session::Machine;
use crate::verify::{Expected, verify_full_gone};

/// What the lines about a switch of mode are about, for the repeat rule. A
/// connection that reaches the gateway starts it afresh.
pub(crate) const SWITCHED: &str = "a switch of tunnel mode";

/// What the log says when a switch of mode was applied and checked.
pub const MODE_CHANGED: &str =
    "tunnel mode changed while connected and checked; the status shows the mode";

/// Why full mode is refused: the policy forbids it.
pub(crate) const FORBIDDEN: &str = "Full tunnel is not allowed by this computer's VPN policy.";

/// Why full mode is refused: this system cannot do it, or cannot say when
/// IPv6 changes, which full mode must watch.
pub(crate) const UNSUPPORTED: &str = "Full tunnel is not available on this system.";

/// Why full mode is refused: the router would be routed into the tunnel.
const ROUTER: &str = "Full tunnel cannot be used on this network: its router is not on a \
    network this computer is on, so it could not stay reachable directly.";

/// Why full mode is refused: another program's halves.
const FOREIGN_HALVES: &str = "Full tunnel cannot be used: another program, such as another \
    VPN, already sends all traffic somewhere.";

/// Why full mode is refused: another program's catch-all.
const FOREIGN_CATCH_ALL: &str = "Full tunnel cannot be used: another program, such as another \
    VPN, already resolves all names.";

/// Why full mode is refused: no DNS server to send every name to.
const NO_DNS: &str = "Full tunnel cannot be used: the gateway assigned no DNS server, so names \
    could not go to UBC.";

/// Why full mode is refused: IPv6 could leak.
const IPV6_LEAK: &str = "Full tunnel cannot be used: IPv6 could leave by another network, and \
    the tunnel cannot block it.";

/// Why a full-mode connection was closed: IPv6 could leak now.
pub(crate) const IPV6_APPEARED: &str = "IPv6 could now leave by another network, which full \
    tunnel cannot block, so the connection was closed. Connect again.";

/// The refusal for a check that could not be made: "could not tell" is not
/// "no", so it refuses too.
fn unchecked(what: &str, error: &Error) -> String {
    match error {
        Error::Unsupported => UNSUPPORTED.to_string(),
        error => format!("Full tunnel cannot be used: {what} could not be checked: {error}."),
    }
}

/// What full mode needs of the policy and of this system, which no request
/// and no network changes: that the policy allows it, and that the system
/// reports IPv6 changes, without which "nothing to block" could go stale
/// unseen.
pub(crate) fn refuse_anywhere(allowed: bool, events: &dyn NetworkEvents) -> Result<(), String> {
    if !allowed {
        return Err(FORBIDDEN.to_string());
    }
    if !events.reports_ipv6_changes() {
        return Err(UNSUPPORTED.to_string());
    }
    Ok(())
}

/// What full mode needs of the network the connection is on, with no
/// tunnel: the router on a network the machine is on, whose route is more
/// specific than the halves, and no other program resolving all names.
pub(crate) fn refuse_here(physical: &PhysicalNetwork, dns: &dyn Dns) -> Result<(), String> {
    if !physical.router_is_on_link() {
        return Err(ROUTER.to_string());
    }
    match dns.foreign_catch_all() {
        Ok(false) => Ok(()),
        Ok(true) => Err(FOREIGN_CATCH_ALL.to_string()),
        Err(e) => Err(unchecked("another program's DNS for every name", &e)),
    }
}

/// What full mode needs once the tunnel `tunnel` is open: a DNS server for
/// every name (`servers`, as [`dns_servers`](crate::connect::dns_servers)
/// judged them), no other program's halves, and IPv6 blocked or nothing to
/// block.
pub(crate) fn refuse_on(
    tunnel: &str,
    servers: &[Ipv4Net],
    routes: &dyn Routes,
) -> Result<(), String> {
    if servers.is_empty() {
        return Err(NO_DNS.to_string());
    }
    match routes.foreign_full_tunnel(tunnel) {
        Ok(false) => {}
        Ok(true) => return Err(FOREIGN_HALVES.to_string()),
        Err(e) => return Err(unchecked("another program's routes for all traffic", &e)),
    }
    match routes.full_tunnel_ipv6(tunnel) {
        Ok(_) => Ok(()),
        Err(Error::Unsupported) => Err(IPV6_LEAK.to_string()),
        Err(e) => Err(unchecked("IPv6", &e)),
    }
}

impl Machine {
    /// Adds full mode's halves on the tunnel `tunnel`, recorded before they
    /// are added.
    pub(crate) fn add_halves(&mut self, tunnel: &str) -> Result<(), Failure> {
        self.applied.full = true;
        let ipv6 = self.routes.add_full_tunnel(tunnel).map_err(|e| {
            let why = format!("The routes for all traffic could not be added: {e}.");
            (ErrorCode::Internal, why)
        })?;
        self.applied.ipv6 = Some(ipv6);
        Ok(())
    }

    /// Sends every name to the gateway's DNS servers, which are routed
    /// through the tunnel already. Recorded before it is set.
    pub(crate) fn set_catch_all(&mut self) -> Result<(), Failure> {
        let servers: Vec<Ipv4Addr> = self.applied.dns_servers.iter().map(Ipv4Net::addr).collect();
        self.applied.catch_all = true;
        self.dns.set_catch_all_dns(&servers).map_err(|e| {
            let why = format!("DNS for every name could not be set: {e}.");
            (ErrorCode::Internal, why)
        })
    }

    /// Switches the live tunnel to `mode`, and checks the result. The switch
    /// was checked before it was admitted.
    pub(crate) fn change_tunnel(&mut self, mode: TunnelMode) -> Result<TunnelInfo, Failure> {
        let os =
            |what: &'static str| move |e: Error| (ErrorCode::Internal, format!("{what}: {e}."));
        let lost = || (ErrorCode::Internal, "The connection is not up.".to_string());
        let tunnel = self.applied.tunnel.as_ref().ok_or_else(lost)?;
        let interface = tunnel.assigned().interface.clone();
        let was = self.applied.ipv6;
        match (mode, was) {
            (TunnelMode::Full, None) => {
                // The catch-all names the DNS servers, which a connection
                // made with no DNS domains has not routed yet.
                self.route_dns_servers()?;
                self.add_halves(&interface)?;
                self.set_catch_all()?;
                let checked = self.check_applied(|_| Ok(()))?;
                self.say_unconfirmed(checked, true);
            }
            (TunnelMode::Split, Some(ipv6)) => {
                // Split DNS whose domains were dropped in full mode stays
                // until now; clearing it takes the catch-all with it.
                match self.applied.split_rules == self.applied.dns_domains {
                    true => {
                        let cleared = self.dns.clear_catch_all_dns();
                        cleared.map_err(os("DNS for every name could not be cleared"))?;
                    }
                    false => {
                        let cleared = self.dns.clear_split_dns();
                        cleared.map_err(os("DNS for every name could not be cleared"))?;
                        self.applied.split_rules.clear();
                    }
                }
                self.applied.catch_all = false;
                let removed = self.routes.remove_full_tunnel(&interface);
                removed.map_err(os("The routes for all traffic could not be removed"))?;
                (self.applied.full, self.applied.ipv6) = (false, None);
                let gone = |expected: &Expected<'_>| {
                    verify_full_gone(&*self.routes, &*self.dns, expected, ipv6)
                };
                let checked = self.check_applied(gone)?;
                self.say_unconfirmed(checked, true);
            }
            // Admitted as a change, but the tunnel has this mode: there is
            // nothing to do.
            _ => {}
        }
        self.logs.at_about(LogLevel::Info, SWITCHED, MODE_CHANGED);
        self.tunnel_info().ok_or_else(lost)
    }
}
