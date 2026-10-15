//! Setting a connection up, in the one order that is safe. Any step that
//! fails stops the rest; the caller then tears everything down.

use std::sync::mpsc;

use std::net::Ipv4Addr;
use ubc_vpn_core::protocol::{ConnectParams, ErrorCode, LogLevel};
use ubc_vpn_core::routes::{Ipv4Net, LocalConflict, LocalNetworks, check_against_local};
use ubc_vpn_core::state::TunnelInfo;
use ubc_vpn_engine::{Assigned, Cancel, Session};

use ubc_vpn_platform::{Error, PhysicalNetwork, SplitDns, TUNNEL_MTU};

use crate::session::Machine;
use crate::verify::{Expected, verify};
use crate::words::counted;

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
        // Judged against the network the machine is on before the gateway
        // is contacted, so a refused connect sends no cookie anywhere.
        let local = LocalNetworks {
            own_addresses: physical.own_addresses(),
            on_link: physical.on_link(),
            next_hop: physical.next_hop(),
        };
        check_against_local(&chosen.subnets, gateway_addr, &local).map_err(refused_here)?;

        let (ended, events) = mpsc::channel();
        let session = Session {
            cookie,
            gateway_addr,
        };
        let logs = self.logs.sink(&session.cookie);
        let opened = self.engine.open(&gateway, &session, cancel, ended, logs);
        // The cookie has no further use here and was never written anywhere.
        // The one copy left is in the log sink the engine was given, which
        // needs it to keep it out of the log for as long as the tunnel runs.
        drop(session);
        let tunnel = opened.map_err(|e| (ErrorCode::from(e), e.to_string()))?;
        let assigned = tunnel.assigned().clone();
        // Recorded before anything else can fail, so teardown closes it.
        self.applied.tunnel = Some(tunnel);
        let watched = self.watch(events);
        watched.map_err(|e| {
            (
                ErrorCode::Internal,
                format!("No thread for the tunnel: {e}."),
            )
        })?;
        if cancel.is_cancelled() || assigned.gateway_addr != gateway_addr {
            let message = "The tunnel is not connected to the expected address.";
            return Err((ErrorCode::EngineFailed, message.to_string()));
        }
        // What the gateway assigned is judged before anything is applied.
        check_assigned(&assigned, gateway_addr, &physical)?;
        // Split DNS only when the user chose domains.
        let servers = match chosen.dns_domains.is_empty() {
            true => Vec::new(),
            false => dns_servers(&assigned.dns, gateway_addr, &physical)?,
        };
        let unusable = |conflict| {
            let why = format!("The gateway assigned a DNS server that cannot be used: {conflict}.");
            (ErrorCode::EngineFailed, why)
        };
        check_against_local(&servers, gateway_addr, &local).map_err(unusable)?;
        // SEAM: the tunnel's address, netmask and MTU from `assigned` must be
        // set on the device here. The platform contract has no operation for
        // that yet, and the fake engine's device needs none.

        self.applied.gateway_route = Some(gateway_addr);
        let routed = self.routes.add_gateway_route(gateway_addr, &physical);
        routed.map_err(os("The route to the gateway could not be added"))?;

        // The gateway's DNS servers often lie outside the chosen subnets, so
        // each gets a route of its own through the tunnel; verification
        // then checks it.
        let tunnel = &assigned.interface;
        let dns = (!chosen.dns_domains.is_empty()).then(|| SplitDns {
            resolvers: servers.iter().map(Ipv4Net::addr).collect(),
            domains: chosen.dns_domains.clone(),
        });

        // Only what the user chose, and those DNS servers. The routes the
        // gateway suggests are ignored.
        let routes = [chosen.subnets.clone(), servers].concat();
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
        // Counted, not listed: a long list would not fit in one line, and
        // how many is what someone helping the user asks first.
        let dns_servers = routes.len() - chosen.subnets.len();
        let split = match dns.as_ref().map_or(0, |dns| dns.domains.len()) {
            0 => "no split DNS".to_string(),
            domains => format!("split DNS for {}", counted(domains, "domain")),
        };
        let line = format!(
            "routes and DNS applied and checked: {}, {}, {split}",
            counted(chosen.subnets.len(), "subnet route"),
            counted(dns_servers, "DNS server route"),
        );
        self.logs.at(LogLevel::Info, &line);
        Ok(TunnelInfo {
            interface: assigned.interface.clone(),
            address: assigned.address.to_string(),
            subnets: chosen.subnets,
            dns_domains: chosen.dns_domains,
        })
    }
}

/// Why a connect cannot go ahead on the network the machine is on. A gateway
/// address that is the machine's own is a bad request, as any other address
/// that cannot be a gateway is; the rest are routes refused.
fn refused_here(conflict: LocalConflict) -> Failure {
    match conflict {
        LocalConflict::GatewayIsOwnAddress(_) => (
            ErrorCode::BadRequest,
            format!("The gateway address cannot be used: {conflict}."),
        ),
        _ => (
            ErrorCode::RouteRefused,
            format!("Route refused: {conflict}."),
        ),
    }
}

/// Checks the tunnel's packet size and this machine's address inside it,
/// which are set on the device with admin rights. The address must not be
/// reserved, nor this machine's own, the gateway's or the router's.
fn check_assigned(
    assigned: &Assigned,
    gateway: Ipv4Addr,
    physical: &PhysicalNetwork,
) -> Result<(), Failure> {
    let refuse = |why: String| Err((ErrorCode::EngineFailed, why));
    if !TUNNEL_MTU.contains(&assigned.mtu) {
        let mtu = assigned.mtu;
        return refuse(format!(
            "The gateway assigned a packet size that cannot be used: {mtu}."
        ));
    }
    let addr = assigned.address;
    let reserved = Ipv4Net::new(addr, 32).map_or(true, |host| host.is_reserved());
    let taken = addr == gateway
        || Some(addr) == physical.next_hop()
        || physical.own_addresses().contains(&addr);
    if reserved || taken {
        return refuse(format!(
            "The gateway assigned this computer an address that cannot be used: {addr}."
        ));
    }
    Ok(())
}

/// The most DNS servers a gateway may assign. A real one assigns two or
/// three; each becomes a route, so the number is not the gateway's to choose.
pub(crate) const MAX_DNS_SERVERS: usize = 4;

/// The routes for the DNS servers the gateway assigned, each one host. The
/// gateway chose them, but the routes are added with this machine's admin
/// rights, so the list is not trusted: duplicates are dropped, and the
/// connect fails if there are too many, or if one could not be a DNS server
/// behind the tunnel: a reserved address such as loopback, the gateway's own
/// address, or the router of the physical network.
fn dns_servers(
    assigned: &[Ipv4Addr],
    gateway: Ipv4Addr,
    physical: &PhysicalNetwork,
) -> Result<Vec<Ipv4Net>, Failure> {
    let refuse = |why: String| Err((ErrorCode::EngineFailed, why));
    let mut servers = Vec::new();
    for addr in assigned {
        let host = Ipv4Net::new(*addr, 32)
            .ok()
            .filter(|host| !host.is_reserved());
        let local = *addr == gateway || Some(*addr) == physical.next_hop();
        match host {
            Some(host) if !local && !servers.contains(&host) => servers.push(host),
            Some(_) if !local => {}
            _ => {
                return refuse(format!(
                    "The gateway assigned a DNS server that cannot be used: {addr}."
                ));
            }
        }
        // Checked as the list grows, so a long list costs nothing to refuse.
        if servers.len() > MAX_DNS_SERVERS {
            return refuse(format!(
                "The gateway assigned more than {MAX_DNS_SERVERS} DNS servers."
            ));
        }
    }
    Ok(servers)
}
