//! Removing everything a connection applied. Used by disconnect, by every
//! failure, by the tunnel's own ending, before each connect and at shutdown.

use ubc_vpn_engine::{CloseMode, Tunnel};
use ubc_vpn_platform::Result;

use crate::session::Machine;

/// What closing does to the session at the gateway. Every teardown logs it
/// off: the service keeps no cookie, so it could not use a session it left
/// alive. Reconnecting will need `KeepSession` for some teardowns, and this
/// is the one place that decides.
const CLOSE: CloseMode = CloseMode::LogOff;

/// The tunnel while it is being torn down. However teardown ends, a panic in
/// one of its steps included, the tunnel is closed with [`CLOSE`] and not
/// merely dropped, which would leave the session alive at the gateway.
struct Closing(Option<Box<dyn Tunnel>>);

impl Closing {
    fn close(&mut self) {
        if let Some(tunnel) = self.0.take() {
            tunnel.close(CLOSE);
        }
    }
}

impl Drop for Closing {
    fn drop(&mut self) {
        self.close();
    }
}

impl Machine {
    /// Runs every step, whatever earlier steps did and however far setup
    /// got, and logs each failure. Returns whether the system is known to be
    /// clean: the two catch-all steps, which need no memory of what was
    /// applied, both succeeded.
    pub(crate) fn teardown(&mut self) -> bool {
        let mut applied = std::mem::take(&mut self.applied);
        let mut tunnel = Closing(applied.tunnel.take());
        let logs = self.logs.clone();
        let step = |what: &str, result: Result<()>| {
            if let Err(error) = &result {
                logs.error(&format!("teardown: {what} failed: {error}"));
            }
            result.is_ok()
        };
        if let Some(tunnel) = &tunnel.0 {
            let interface = &tunnel.assigned().interface;
            let removed = self.routes.remove_tunnel_routes(interface, &applied.routes);
            step("removing the tunnel routes", removed);
        }
        let dns_clear = step("clearing split DNS", self.dns.clear_split_dns());
        tunnel.close();
        if let (Some(gateway), Some(physical)) = (applied.gateway_route, &applied.physical) {
            let removed = self.routes.remove_gateway_route(gateway, physical);
            step("removing the gateway route", removed);
        }
        let routes_clear = step("removing all routes", self.routes.remove_all());
        // The tunnel is closed, so the engine writes no more about it, and
        // the service forgets the cookie here too.
        self.hidden = None;
        dns_clear && routes_clear
    }
}
