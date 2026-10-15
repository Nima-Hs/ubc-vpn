//! Removing everything a connection applied. Used by disconnect, by every
//! failure, by the tunnel's own ending, before each connect and at shutdown.

use ubc_vpn_core::protocol::LogLevel;
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
        // Whatever watches the network for this connection stops.
        self.watching.store(0, std::sync::atomic::Ordering::SeqCst);
        let mut applied = std::mem::take(&mut self.applied);
        let had_some = applied.tunnel.is_some()
            || applied.gateway_route.is_some()
            || !applied.routes.is_empty();
        let mut tunnel = Closing(applied.tunnel.take());
        let logs = self.logs.clone();
        // A step that keeps failing the same way is logged once, so that no
        // number of requests can fill the log with it.
        let step = |what: &'static str, result: Result<()>| {
            if let Err(error) = &result {
                logs.error_about(what, &format!("teardown: {what} failed: {error}"));
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
        // The tunnel is closed and the cookie has no further use. It is
        // left to the cleaning of the log for a short time more, because
        // the client's lines about a connect that failed arrive just now.
        if let Some(hidden) = self.hidden.take() {
            hidden.linger();
        }
        let clean = dns_clear && routes_clear;
        // Said only when something had been applied: a teardown before each
        // connect usually finds nothing, and that is not news.
        if had_some && clean {
            let line = "everything applied for the connection was removed";
            self.logs.at(LogLevel::Info, line);
        }
        clean
    }
}
