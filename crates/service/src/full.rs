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
//! goes, then the halves; then everything is checked. Any step that fails
//! stops the rest, and the caller tears everything down. A switch whose
//! steps all worked but whose checks failed is undone the same way, and the
//! mode it had is checked again: the connection is kept in that mode only
//! when both work, and torn down otherwise. Each change is in
//! [`Applied`](crate::session::Applied) before it is made, so teardown
//! undoes whatever may have been made.

use std::net::Ipv4Addr;

use ubc_vpn_core::protocol::{ErrorCode, ErrorInfo, LogLevel};
use ubc_vpn_core::routes::Ipv4Net;
use ubc_vpn_core::state::TunnelMode;
use ubc_vpn_platform::{Dns, Error, Ipv6Block, NetworkEvents, PhysicalNetwork, Routes};

use crate::connect::{Checked, Failure};
use crate::session::{Changed, Machine};
use crate::verify::{Confirmed, Expected, verify_full_gone};

/// What the lines about a switch of mode are about, for the repeat rule. A
/// connection that reaches the gateway starts it afresh.
pub(crate) const SWITCHED: &str = "a switch of tunnel mode";

/// What the log says when a switch of mode was applied and checked.
pub const MODE_CHANGED: &str =
    "tunnel mode changed while connected and checked; the status shows the mode";

/// What the log says when a switch of mode failed its checks and was undone.
pub const UNDONE: &str =
    "tunnel mode change failed its checks and was undone; the connection keeps its mode";

/// Said after why a switch to full was undone.
const KEPT_SPLIT: &str = "The switch was undone: the VPN stays connected in split tunnel.";

/// Said after why a switch to split was undone.
const KEPT_FULL: &str = "The switch was undone: the VPN stays connected in full tunnel.";

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
    ///
    /// A switch whose steps all worked but whose checks failed is undone:
    /// see [`Self::undo_switch`]. Any other failure is returned, and the
    /// caller tears everything down.
    pub(crate) fn change_tunnel(&mut self, mode: TunnelMode) -> Result<Changed, Failure> {
        let tunnel = self.applied.tunnel.as_ref().ok_or_else(lost)?;
        let interface = tunnel.assigned().interface.clone();
        let checked = match (mode, self.applied.ipv6) {
            (TunnelMode::Full, None) => {
                // The catch-all names the DNS servers, which a connection
                // made with no DNS domains has not routed yet.
                self.route_dns_servers()?;
                self.apply_full(&interface)?;
                self.check_applied(|_| Ok(()))
            }
            (TunnelMode::Split, Some(ipv6)) => {
                self.remove_full(&interface)?;
                self.check_split_after_full(ipv6)
            }
            // Admitted as a change, but the tunnel has this mode: there is
            // nothing to do.
            _ => Ok(Checked {
                split: Confirmed::Fully,
                catch_all: None,
            }),
        };
        match checked {
            Ok(checked) => self.say_unconfirmed(checked, true),
            Err((ErrorCode::VerificationFailed, why)) => {
                return self.undo_switch(&interface, mode, why);
            }
            Err(failure) => return Err(failure),
        }
        self.logs.at_about(LogLevel::Info, SWITCHED, MODE_CHANGED);
        self.tunnel_info().map(Changed::Applied).ok_or_else(lost)
    }

    /// Undoes a switch to `mode` that was applied but failed its checks
    /// (`why`): removes what it added and puts back what it removed, each
    /// change recorded in [`Applied`](crate::session::Applied) as for the
    /// switch, then checks the mode it had in full, as a switch to it is
    /// checked. Only when both work is the connection kept, in that mode,
    /// with the switch reported as undone. A step or a check of the undoing
    /// that fails, or cannot tell, fails the whole: the caller tears
    /// everything down.
    ///
    /// Undoing a switch to full leaves the DNS servers' routes, which a
    /// change never removes. Undoing a switch to split does not put back
    /// split DNS for domains a change of routes dropped in full mode: it
    /// was kept only because clearing it takes the catch-all with it, and
    /// names the same servers.
    fn undo_switch(
        &mut self,
        interface: &str,
        mode: TunnelMode,
        why: String,
    ) -> Result<Changed, Failure> {
        let undone = match mode {
            TunnelMode::Full => {
                let ipv6 = self.applied.ipv6.ok_or_else(lost);
                ipv6.and_then(|ipv6| {
                    self.remove_full(interface)?;
                    self.check_split_after_full(ipv6)
                })
            }
            TunnelMode::Split => self
                .apply_full(interface)
                .and_then(|()| self.check_applied(|_| Ok(()))),
        };
        let checked = undone.map_err(|(code, undo)| {
            let both = format!("{why} Undoing the switch failed too: {undo}");
            (code, both)
        })?;
        self.say_unconfirmed(checked, true);
        let kept = match mode {
            TunnelMode::Full => KEPT_SPLIT,
            TunnelMode::Split => KEPT_FULL,
        };
        let message = format!("{why} {kept}");
        let line = format!("{UNDONE}: {message}");
        self.logs.at_about(LogLevel::Warn, SWITCHED, &line);
        let tunnel = self.tunnel_info().ok_or_else(lost)?;
        let code = ErrorCode::VerificationFailed;
        Ok(Changed::Undone(tunnel, ErrorInfo { code, message }))
    }

    /// Adds full mode's halves, then its catch-all, on the tunnel
    /// `interface`, whose DNS servers are routed already.
    fn apply_full(&mut self, interface: &str) -> Result<(), Failure> {
        self.add_halves(interface)?;
        self.set_catch_all()
    }

    /// Removes full mode's catch-all, then its halves, from the tunnel
    /// `interface`, each recorded once it is gone.
    fn remove_full(&mut self, interface: &str) -> Result<(), Failure> {
        let os =
            |what: &'static str| move |e: Error| (ErrorCode::Internal, format!("{what}: {e}."));
        // Split DNS whose domains were dropped in full mode stays until
        // now; clearing it takes the catch-all with it.
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
        let removed = self.routes.remove_full_tunnel(interface);
        removed.map_err(os("The routes for all traffic could not be removed"))?;
        (self.applied.full, self.applied.ipv6) = (false, None);
        Ok(())
    }

    /// Checks split mode once full mode, which did `ipv6`, was removed:
    /// everything split mode needs, and that full mode is gone.
    fn check_split_after_full(&self, ipv6: Ipv6Block) -> Result<Checked, Failure> {
        let gone =
            |expected: &Expected<'_>| verify_full_gone(&*self.routes, &*self.dns, expected, ipv6);
        self.check_applied(gone)
    }
}

/// Why a step needs a tunnel that is not there.
fn lost() -> Failure {
    (ErrorCode::Internal, "The connection is not up.".to_string())
}
