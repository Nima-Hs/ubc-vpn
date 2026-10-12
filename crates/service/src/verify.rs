//! Checking that what was applied is really in effect. Any answer but "yes"
//! is a failure: "could not tell" is never "probably fine".

use std::net::Ipv4Addr;

use ubc_vpn_core::routes::Ipv4Net;
use ubc_vpn_platform::{Dns, PhysicalNetwork, Routes, SplitDns, Verified};

/// What must be true before a connection is reported as connected.
pub(crate) struct Expected<'a> {
    pub(crate) tunnel: &'a str,
    pub(crate) physical: &'a PhysicalNetwork,
    pub(crate) gateway: Ipv4Addr,
    pub(crate) subnets: &'a [Ipv4Net],
    /// `None` when the user chose no DNS domains, so none was set.
    pub(crate) dns: Option<&'a SplitDns>,
}

/// An address inside `subnet` to test with. Not the gateway's, which is
/// deliberately routed outside the tunnel.
fn probe(subnet: &Ipv4Net, gateway: Ipv4Addr) -> Option<Ipv4Addr> {
    let base = u32::from(subnet.addr());
    let candidates = [1, 2, 0].map(|n| Ipv4Addr::from(base.wrapping_add(n)));
    let usable = |addr: &Ipv4Addr| subnet.contains_addr(*addr) && *addr != gateway;
    candidates.into_iter().find(usable)
}

/// Asks the OS about every chosen subnet, the gateway, each resolver and the
/// split DNS. The error says which check did not pass.
pub(crate) fn verify(
    routes: &dyn Routes,
    dns: &dyn Dns,
    expected: &Expected,
) -> Result<(), String> {
    let through = |addr, interface| routes.uses_interface(addr, interface) == Verified::Yes;
    for subnet in expected.subnets {
        let inside = probe(subnet, expected.gateway);
        if !inside.is_some_and(|addr| through(addr, expected.tunnel)) {
            return Err(format!("{subnet} is not routed through the tunnel."));
        }
    }
    if !through(expected.gateway, expected.physical.interface()) {
        return Err("The gateway is not reached through the physical network.".to_string());
    }
    let Some(split) = expected.dns else {
        return Ok(());
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
    match dns.split_dns_matches(split) {
        Verified::Yes => Ok(()),
        Verified::No | Verified::Unknown => Err("Split DNS is not in effect.".to_string()),
    }
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
    fn check(skip: &str, spoil: impl FnOnce(&Fake)) -> Result<(), String> {
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
        };
        verify(&fake, &fake, &expected)
    }

    // Security rule: each check stands alone. Removing any one of them, or
    // letting "could not tell" pass, makes this test fail.
    #[test]
    fn every_check_must_answer_yes() {
        let unknown = |op| move |fake: &Fake| fake.set_failure(op, Some(Error::Unsupported));
        assert_eq!(check("nothing", |_| {}), Ok(()));
        let failures = [
            check("one subnet", |_| {}),
            check("gateway route", |_| {}),
            check("resolver route", |_| {}),
            check("resolvers", |_| {}),
            check("dns", |_| {}),
            check("nothing", unknown(Op::VerifyRoute)),
            check("nothing", unknown(Op::VerifyDns)),
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
    }

    // The gateway may sit inside a chosen subnet, where its own route leads
    // outside the tunnel. The subnet is tested with another address.
    #[test]
    fn a_subnet_is_never_tested_with_the_gateway_address() {
        let net = |s: &str| s.parse::<Ipv4Net>().unwrap();
        let addr = |d| Some(Ipv4Addr::new(192, 0, 2, d));
        assert_eq!(probe(&net("192.0.2.0/24"), GATEWAY), addr(2));
        assert_eq!(probe(&net("192.0.2.0/24"), Ipv4Addr::LOCALHOST), addr(1));
        assert_eq!(probe(&net("192.0.2.9/32"), GATEWAY), addr(9));
        assert_eq!(probe(&net("192.0.2.1/32"), GATEWAY), None);
    }
}
