//! Setting a connection up, in the one order that is safe. Any step that
//! fails stops the rest; the caller then tears everything down.

use std::sync::mpsc;

use ubc_vpn_core::protocol::{ConnectParams, ErrorCode};
use ubc_vpn_core::routes::Ipv4Net;
use ubc_vpn_core::state::TunnelInfo;
use ubc_vpn_engine::{Cancel, Session};
use ubc_vpn_platform::{Error, SplitDns};

use crate::session::Machine;
use crate::verify::{Expected, verify};

/// Why setup stopped: the code for the client and a sentence for the user,
/// built only from fixed text and OS errors, so it cannot hold the cookie.
pub(crate) type Failure = (ErrorCode, String);

impl Machine {
    /// Opens the tunnel and applies and verifies its routes and DNS. The
    /// request was validated before it was admitted.
    pub(crate) fn set_up(
        &mut self,
        params: ConnectParams,
        cancel: &Cancel,
    ) -> Result<TunnelInfo, Failure> {
        let ConnectParams {
            cookie,
            gateway_addr,
            routes: chosen,
        } = params;
        let os =
            |what: &'static str| move |e: Error| (ErrorCode::Internal, format!("{what}: {e}."));
        // The gateway is the policy's. The request names only an address.
        let no_policy = || (ErrorCode::PolicyInvalid, "There is no policy.".to_string());
        let gateway = self.gateway.clone().ok_or_else(no_policy)?;

        // Before the tunnel exists, so this can only be the real network.
        let physical = self.routes.capture_physical(gateway_addr);
        let physical = physical.map_err(os("The current network could not be determined"))?;
        self.applied.physical = Some(physical.clone());

        let (ended, events) = mpsc::channel();
        let session = Session {
            cookie,
            gateway_addr,
        };
        let logs = self.logs.sink(&session.cookie);
        let opened = self.engine.open(&gateway, &session, cancel, ended, logs);
        // The cookie has no further use. It was held in memory only, and
        // this is where the service forgets it.
        drop(session);
        let tunnel = opened.map_err(|e| (ErrorCode::from(e), e.to_string()))?;
        let assigned = tunnel.assigned().clone();
        self.watch(events);
        self.applied.tunnel = Some(tunnel);
        if cancel.is_cancelled() || assigned.gateway_addr != gateway_addr {
            let message = "The tunnel is not connected to the expected address.";
            return Err((ErrorCode::EngineFailed, message.to_string()));
        }
        // SEAM: the tunnel's address, netmask and MTU from `assigned` must be
        // set on the device here. The platform contract has no operation for
        // that yet, and the fake engine's device needs none.

        self.applied.gateway_route = Some(gateway_addr);
        let routed = self.routes.add_gateway_route(gateway_addr, &physical);
        routed.map_err(os("The route to the gateway could not be added"))?;

        // Split DNS only when the user chose domains. The gateway's DNS
        // servers often lie outside the chosen subnets, so each gets a route
        // of its own through the tunnel; verification then checks it.
        let tunnel = &assigned.interface;
        let dns = (!chosen.dns_domains.is_empty()).then(|| SplitDns {
            resolvers: assigned.dns.clone(),
            domains: chosen.dns_domains.clone(),
        });
        let resolvers = dns.iter().flat_map(|dns| &dns.resolvers);
        let hosts: Result<Vec<Ipv4Net>, Failure> = resolvers.map(|addr| resolver(*addr)).collect();

        // Only what the user chose, and those DNS servers. The routes the
        // gateway suggests are ignored.
        let routes = [chosen.subnets.clone(), hosts?].concat();
        self.applied.routes = routes.clone();
        let routed = self.routes.add_tunnel_routes(tunnel, &routes);
        routed.map_err(os("The tunnel routes could not be added"))?;

        if let Some(dns) = &dns {
            let set = self.dns.set_split_dns(tunnel, dns);
            set.map_err(os("Split DNS could not be set"))?;
        }

        let expected = Expected {
            tunnel,
            physical: &physical,
            gateway: gateway_addr,
            subnets: &chosen.subnets,
            dns: dns.as_ref(),
        };
        let verified = verify(&*self.routes, &*self.dns, &expected);
        verified.map_err(|why| (ErrorCode::VerificationFailed, why))?;
        Ok(TunnelInfo {
            interface: assigned.interface.clone(),
            address: assigned.address.to_string(),
            subnets: chosen.subnets,
            dns_domains: chosen.dns_domains,
        })
    }
}

/// The route for one DNS server the gateway assigned. An address that could
/// not be a server, such as a loopback one, is refused: the gateway chose it,
/// but the route would be added with this machine's admin rights.
fn resolver(addr: std::net::Ipv4Addr) -> Result<Ipv4Net, Failure> {
    let host = Ipv4Net::new(addr, 32)
        .ok()
        .filter(|host| !host.is_reserved());
    host.ok_or_else(|| {
        let message = format!("The gateway assigned a DNS server that cannot be used: {addr}.");
        (ErrorCode::EngineFailed, message)
    })
}
