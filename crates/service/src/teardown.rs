//! Removing everything a connection applied. Used by disconnect, by every
//! failure, by the tunnel's own ending, before each connect and at shutdown.

use ubc_vpn_engine::CloseMode;
use ubc_vpn_platform::Result;

use crate::session::Machine;

/// What closing does to the session at the gateway. Every teardown logs it
/// off: the service keeps no cookie, so it could not use a session it left
/// alive. Reconnecting will need `KeepSession` for some teardowns, and this
/// is the one place that decides.
const CLOSE: CloseMode = CloseMode::LogOff;

impl Machine {
    /// Runs every step, whatever earlier steps did and however far setup
    /// got, and logs each failure. Returns whether the system is known to be
    /// clean: the two catch-all steps, which need no memory of what was
    /// applied, both succeeded.
    pub(crate) fn teardown(&mut self) -> bool {
        let applied = std::mem::take(&mut self.applied);
        let logs = self.logs.clone();
        let step = |what: &str, result: Result<()>| {
            if let Err(error) = &result {
                logs.push(&format!("teardown: {what} failed: {error}"));
            }
            result.is_ok()
        };
        if let Some(tunnel) = &applied.tunnel {
            let interface = &tunnel.assigned().interface;
            let removed = self.routes.remove_tunnel_routes(interface, &applied.routes);
            step("removing the tunnel routes", removed);
        }
        let dns_clear = step("clearing split DNS", self.dns.clear_split_dns());
        if let Some(tunnel) = applied.tunnel {
            tunnel.close(CLOSE);
        }
        if let (Some(gateway), Some(physical)) = (applied.gateway_route, &applied.physical) {
            let removed = self.routes.remove_gateway_route(gateway, physical);
            step("removing the gateway route", removed);
        }
        let routes_clear = step("removing all routes", self.routes.remove_all());
        dns_clear && routes_clear
    }
}
