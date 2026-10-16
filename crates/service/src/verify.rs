//! Checking that what was applied is really in effect. Any answer but "yes"
//! is a failure: "could not tell" is never "probably fine". The one
//! exception is split DNS that reads back exactly but whose use the OS
//! cannot show ([`Verified::Unobservable`]), which is accepted and logged.

use std::net::Ipv4Addr;

use ubc_vpn_core::routes::{Ipv4Net, probe_address};
use ubc_vpn_platform::{Dns, PhysicalNetwork, Routes, SplitDns, Verified};

/// What must be true before a connection is reported as connected.
pub(crate) struct Expected<'a> {
    pub(crate) tunnel: &'a str,
    pub(crate) physical: &'a PhysicalNetwork,
    pub(crate) gateway: Ipv4Addr,
    pub(crate) subnets: &'a [Ipv4Net],
    /// `None` when the user chose no DNS domains, so none was set.
    pub(crate) dns: Option<&'a SplitDns>,
    /// The DNS servers with a host route through the tunnel, whether or
    /// not split DNS is set now.
    pub(crate) dns_servers: &'a [Ipv4Addr],
}

/// An address inside `subnet` to test its route with: one the route itself
/// decides. Not in a network the machine is on, whose route is more
/// specific; not the gateway's, which is routed outside the tunnel; and a
/// DNS server's, which has a host route of its own, only when nothing else
/// is left. See [`probe_address`].
fn probe(
    subnet: &Ipv4Net,
    physical: &PhysicalNetwork,
    gateway: Ipv4Addr,
    dns_servers: &[Ipv4Addr],
) -> Option<Ipv4Addr> {
    probe_address(subnet, physical.on_link(), &[gateway], dns_servers)
}

/// What the log says when split DNS was set but the OS cannot show whether
/// its resolver took it in.
pub const DNS_UNCONFIRMED: &str = "split DNS is set and reads back exactly, but this system \
    cannot show whether its resolver uses it";

/// How far the checks could confirm the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Confirmed {
    /// Every check answered `Yes`.
    Fully,
    /// Every check answered `Yes` but split DNS, which answered
    /// [`Verified::Unobservable`].
    DnsUnobservable,
}

/// Asks the OS about every chosen subnet, the gateway, each resolver and the
/// split DNS. The error says which check did not pass.
pub(crate) fn verify(
    routes: &dyn Routes,
    dns: &dyn Dns,
    expected: &Expected,
) -> Result<Confirmed, String> {
    let through = |addr, interface| routes.uses_interface(addr, interface) == Verified::Yes;
    for subnet in expected.subnets {
        let inside = probe(
            subnet,
            expected.physical,
            expected.gateway,
            expected.dns_servers,
        );
        if !inside.is_some_and(|addr| through(addr, expected.tunnel)) {
            return Err(format!("{subnet} is not routed through the tunnel."));
        }
    }
    if !through(expected.gateway, expected.physical.interface()) {
        return Err("The gateway is not reached through the physical network.".to_string());
    }
    let Some(split) = expected.dns else {
        return Ok(Confirmed::Fully);
    };
    if split.resolvers.is_empty() {
        return Err("The gateway offered no DNS server for the chosen domains.".to_string());
    }
    for resolver in &split.resolvers {
        if !through(*resolver, expected.tunnel) {
            return Err(format!(
                "DNS server {resolver} is not reached through the tunnel."
            ));
        }
    }
    // The one exception to "yes or nothing": the rules read back exactly,
    // and the OS cannot show more. Routes never get it.
    match dns.split_dns_matches(split) {
        Verified::Yes => Ok(Confirmed::Fully),
        Verified::Unobservable => Ok(Confirmed::DnsUnobservable),
        Verified::No | Verified::Unknown => Err("Split DNS is not in effect.".to_string()),
    }
}

/// Checks that the subnets a change of routes dropped no longer go through
/// the tunnel. One that a route still in `remaining` covers is meant to,
/// and is not asked about. Anything but "no" is a failure: a dropped
/// network the tunnel still carries is not what the user chose.
pub(crate) fn verify_dropped(
    routes: &dyn Routes,
    expected: &Expected,
    dropped: &[Ipv4Net],
    remaining: &[Ipv4Net],
) -> Result<(), String> {
    let (tunnel, gateway) = (expected.tunnel, expected.gateway);
    for subnet in dropped {
        let probed = probe(subnet, expected.physical, gateway, expected.dns_servers);
        let Some(inside) = probed else {
            continue;
        };
        if remaining.iter().any(|kept| kept.contains_addr(inside)) {
            continue;
        }
        if routes.uses_interface(inside, tunnel) != Verified::No {
            return Err(format!("{subnet} still goes through the tunnel."));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ubc_vpn_platform::fake::{Fake, Op};
    use ubc_vpn_platform::{Dns, Error, Routes};

    use super::*;

    const GATEWAY: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
    const TUNNEL: &str = "fake0";

    /// Applies a correct setup except for what `skip` names, lets `spoil`
    /// change it further, and verifies.
    fn check(skip: &str, spoil: impl FnOnce(&Fake)) -> Result<Confirmed, String> {
        let fake = Fake::new();
        let subnets = ["192.0.2.0/24", "10.255.0.0/24"].map(|s| s.parse::<Ipv4Net>().unwrap());
        let mut split = SplitDns {
            resolvers: vec![Ipv4Addr::new(10, 255, 0, 53)],
            domains: vec!["ece.example.test".to_string()],
        };
        let physical = fake.capture_physical(GATEWAY).unwrap();
        if skip != "gateway route" {
            fake.add_gateway_route(GATEWAY, &physical).unwrap();
        }
        let routed = if skip == "one subnet" { 1 } else { 2 };
        fake.add_tunnel_routes(TUNNEL, &subnets[..routed]).unwrap();
        fake.set_split_dns(TUNNEL, &split).unwrap();
        match skip {
            "resolver route" => split.resolvers = vec![Ipv4Addr::new(198, 51, 100, 53)],
            "resolvers" => split.resolvers.clear(),
            "dns" => fake.clear_split_dns().unwrap(),
            _ => {}
        }
        spoil(&fake);
        let expected = Expected {
            tunnel: TUNNEL,
            physical: &physical,
            gateway: GATEWAY,
            subnets: &subnets,
            dns: Some(&split),
            dns_servers: &split.resolvers,
        };
        verify(&fake, &fake, &expected)
    }

    // Security rule: each check stands alone, and every check must answer
    // "yes", except that split DNS may answer "cannot be observed". Removing
    // any one check, letting "could not tell" pass, or letting "cannot be
    // observed" pass for a route makes this test fail.
    #[test]
    fn every_check_must_answer_yes_but_dns_may_be_unobservable() {
        let unknown = |op| move |fake: &Fake| fake.set_failure(op, Some(Error::Unsupported));
        let unobservable = |op| move |fake: &Fake| fake.cannot_observe(op, true);
        let one_route = |dest| move |fake: &Fake| fake.cannot_observe_route_to(dest);
        assert_eq!(check("nothing", |_| {}), Ok(Confirmed::Fully));
        let failures = [
            check("one subnet", |_| {}),
            check("gateway route", |_| {}),
            check("resolver route", |_| {}),
            check("resolvers", |_| {}),
            check("dns", |_| {}),
            check("nothing", unknown(Op::VerifyRoute)),
            check("nothing", unknown(Op::VerifyDns)),
            check("nothing", unobservable(Op::VerifyRoute)),
            // What could not be observed must still read back as set.
            check("dns", unobservable(Op::VerifyDns)),
            // Each route check on its own: the first subnet, the second,
            // the gateway and the resolver.
            check("nothing", one_route(Ipv4Addr::new(192, 0, 2, 2))),
            check("nothing", one_route(Ipv4Addr::new(10, 255, 0, 1))),
            check("nothing", one_route(GATEWAY)),
            check("nothing", one_route(Ipv4Addr::new(10, 255, 0, 53))),
        ];
        let reasons = failures.map(|failure| failure.unwrap_err());
        assert!(
            reasons[0].contains("10.255.0.0/24 is not routed"),
            "{reasons:?}"
        );
        assert!(reasons[1].contains("gateway is not reached"), "{reasons:?}");
        assert!(
            reasons[2].contains("198.51.100.53 is not reached"),
            "{reasons:?}"
        );
        assert!(reasons[3].contains("no DNS server"), "{reasons:?}");
        assert!(reasons[4].contains("Split DNS"), "{reasons:?}");
        assert!(reasons[5].contains("is not routed"), "{reasons:?}");
        assert!(reasons[6].contains("Split DNS"), "{reasons:?}");
        assert!(reasons[7].contains("is not routed"), "{reasons:?}");
        assert!(reasons[8].contains("Split DNS"), "{reasons:?}");
        assert!(
            reasons[9].contains("192.0.2.0/24 is not routed"),
            "{reasons:?}"
        );
        assert!(
            reasons[10].contains("10.255.0.0/24 is not routed"),
            "{reasons:?}"
        );
        assert!(
            reasons[11].contains("gateway is not reached"),
            "{reasons:?}"
        );
        assert!(
            reasons[12].contains("10.255.0.53 is not reached"),
            "{reasons:?}"
        );
        // The one exception, said as such so that the caller can log it.
        let dns = check("nothing", unobservable(Op::VerifyDns));
        assert_eq!(dns, Ok(Confirmed::DnsUnobservable));
    }

    // The gateway may sit inside a chosen subnet, where its own route leads
    // outside the tunnel. The subnet is tested with another address.
    #[test]
    fn a_subnet_is_never_tested_with_the_gateway_address() {
        let net = |s: &str| s.parse::<Ipv4Net>().unwrap();
        let addr = |d| Some(Ipv4Addr::new(192, 0, 2, d));
        let physical = Fake::new().capture_physical(GATEWAY).unwrap();
        let probe = |subnet: &str, gateway| probe(&net(subnet), &physical, gateway, &[]);
        assert_eq!(probe("192.0.2.0/24", GATEWAY), addr(2));
        assert_eq!(probe("192.0.2.0/24", Ipv4Addr::LOCALHOST), addr(1));
        assert_eq!(probe("192.0.2.9/32", GATEWAY), addr(9));
        assert_eq!(probe("192.0.2.1/32", GATEWAY), None);
    }

    // The issue's case: a chosen subnet wider than the network the machine
    // is on was tested at an address inside that network, whose own route is
    // more specific and leads to the local network. The subnet is tested
    // outside it, so it is confirmed through the tunnel; and a DNS server,
    // whose host route goes through the tunnel whatever the subnet does, is
    // not the address it is tested with.
    #[test]
    fn a_subnet_is_tested_outside_the_local_network() {
        let fake = Fake::new();
        let physical = fake.capture_physical(GATEWAY).unwrap();
        fake.add_gateway_route(GATEWAY, &physical).unwrap();
        let wide = "192.168.0.0/16".parse::<Ipv4Net>().unwrap();
        fake.add_tunnel_routes(TUNNEL, &[wide]).unwrap();
        let inside = probe(&wide, &physical, GATEWAY, &[]).unwrap();
        assert_eq!(inside, Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(fake.uses_interface(inside, TUNNEL), Verified::Yes);
        let lan = Ipv4Addr::new(192, 168, 0, 1);
        assert_eq!(fake.uses_interface(lan, TUNNEL), Verified::No);
        let expected = Expected {
            tunnel: TUNNEL,
            physical: &physical,
            gateway: GATEWAY,
            subnets: &[wide],
            dns: None,
            dns_servers: &[],
        };
        assert_eq!(verify(&fake, &fake, &expected), Ok(Confirmed::Fully));

        let dns = Ipv4Addr::new(10, 255, 0, 1);
        let small = "10.255.0.0/24".parse::<Ipv4Net>().unwrap();
        let tested = probe(&small, &physical, GATEWAY, &[dns]);
        assert_eq!(tested, Some(Ipv4Addr::new(10, 255, 0, 2)));
    }
}
