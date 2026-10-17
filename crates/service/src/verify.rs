//! Checking that what was applied is really in effect. Any answer but "yes"
//! is a failure: "could not tell" is never "probably fine". The one
//! exception is DNS rules that read back exactly but whose use the OS
//! cannot show ([`Verified::Unobservable`]), which is accepted and logged:
//! split DNS, and full mode's catch-all.

use std::net::{Ipv4Addr, Ipv6Addr};

use ubc_vpn_core::routes::{Ipv4Net, probe_address};
use ubc_vpn_platform::{
    Dns, FULL_TUNNEL_V4, FULL_TUNNEL_V6, Ipv6Block, PhysicalNetwork, Routes, SplitDns, Verified,
};

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
/// decides. Not in a network the machine is on, nor in any of `others`,
/// whose routes are more specific wherever they lie inside `subnet`; not
/// the gateway's, which is routed outside the tunnel; and a DNS server's,
/// which has a host route of its own, only when nothing else is left. See
/// [`probe_address`].
fn probe(
    subnet: &Ipv4Net,
    physical: &PhysicalNetwork,
    others: &[Ipv4Net],
    gateway: Ipv4Addr,
    dns_servers: &[Ipv4Addr],
) -> Option<Ipv4Addr> {
    // Only routes more specific than `subnet` take part of it from it.
    let inside = others
        .iter()
        .filter(|other| *other != subnet && subnet.contains(other));
    let avoid: Vec<Ipv4Net> = physical.on_link().iter().chain(inside).copied().collect();
    probe_address(subnet, &avoid, &[gateway], dns_servers)
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
            expected.subnets,
            expected.gateway,
            expected.dns_servers,
        );
        let Some(inside) = inside else {
            return Err(format!(
                "{subnet} cannot be checked: the networks this computer is on and the other \
                 chosen subnets inside it cover all of it."
            ));
        };
        if !through(inside, expected.tunnel) {
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
/// the tunnel. One that a route still in `remaining` covers whole is meant
/// to, and is not asked about. Otherwise it is asked about at an address
/// outside every kept route, which would decide that address instead;
/// when there is none, it cannot be checked, which is a failure too.
/// Anything but "no" is a failure: a dropped network the tunnel still
/// carries is not what the user chose.
pub(crate) fn verify_dropped(
    routes: &dyn Routes,
    expected: &Expected,
    dropped: &[Ipv4Net],
    remaining: &[Ipv4Net],
) -> Result<(), String> {
    let (tunnel, gateway) = (expected.tunnel, expected.gateway);
    for subnet in dropped {
        if remaining.iter().any(|kept| kept.contains(subnet)) {
            continue;
        }
        let probed = probe(
            subnet,
            expected.physical,
            remaining,
            gateway,
            expected.dns_servers,
        );
        let Some(inside) = probed else {
            return Err(format!(
                "{subnet} cannot be checked once dropped: the routes kept and the networks \
                 this computer is on cover all of it."
            ));
        };
        if routes.uses_interface(inside, tunnel) != Verified::No {
            return Err(format!("{subnet} still goes through the tunnel."));
        }
    }
    Ok(())
}

/// What the log says when full mode's catch-all was set but the OS cannot
/// show whether its resolver took it in.
pub const CATCH_ALL_UNCONFIRMED: &str = "DNS for every name is set and reads back exactly, but \
    this system cannot show whether its resolver uses it";

/// The address full mode checks each IPv6 half at, in the order of
/// [`FULL_TUNNEL_V6`]. Neither is in a range with a meaning of its own
/// (link-local, unique local, multicast, Teredo, 6to4, documentation), so
/// no more specific route of the machine's is likely to hold it.
const PROBES_V6: [Ipv6Addr; 2] = [
    Ipv6Addr::new(0x4000, 0, 0, 0, 0, 0, 0, 1),
    Ipv6Addr::new(0xc000, 0, 0, 0, 0, 0, 0, 1),
];

/// For each IPv4 half of full mode, an address the half itself decides:
/// outside the networks the machine is on and the chosen subnets, whose
/// routes are more specific; not the gateway's or a DNS server's, which have
/// host routes of their own; and not in "this network", `0.0.0.0/8`, which
/// is not routed.
fn half_probes(expected: &Expected) -> Result<Vec<(Ipv4Net, Ipv4Addr)>, String> {
    let this_network = Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 8).map_err(|e| e.to_string())?;
    let physical = expected.physical.on_link().iter();
    let mut avoid: Vec<Ipv4Net> = physical.chain(expected.subnets).copied().collect();
    avoid.push(this_network);
    let never: Vec<Ipv4Addr> = [expected.gateway]
        .into_iter()
        .chain(expected.dns_servers.iter().copied())
        .collect();
    let mut probes = Vec::new();
    for half in FULL_TUNNEL_V4 {
        let half: Ipv4Net = half.parse().map_err(|e| format!("{e}"))?;
        let Some(addr) = probe_address(&half, &avoid, &never, &[]) else {
            return Err(format!(
                "{half} cannot be checked: the chosen subnets and the networks this \
                 computer is on cover all of it."
            ));
        };
        probes.push((half, addr));
    }
    Ok(probes)
}

/// Checks full mode, beside what [`verify`] checks, for the tunnel in
/// `expected`. Every answer must be "yes":
///
/// - an address in each IPv4 half, outside the chosen subnets and the
///   networks the machine is on, goes through the tunnel;
/// - an address in each IPv6 half goes through the tunnel; or, with
///   [`Ipv6Block::NothingToBlock`], there is still nothing to block;
/// - the gateway, the router and each network the machine is on do **not**
///   go through the tunnel. Not "go through the physical interface": a
///   network on an adapter of its own, such as a virtual machine program's
///   host-only network, rightly goes there;
/// - each DNS server goes through the tunnel, and the catch-all sends every
///   name to exactly them. It may answer [`Verified::Unobservable`], as
///   split DNS may; that is said in the result.
pub(crate) fn verify_full(
    routes: &dyn Routes,
    dns: &dyn Dns,
    expected: &Expected,
    ipv6: Ipv6Block,
) -> Result<Confirmed, String> {
    let tunnel = expected.tunnel;
    let through = |addr| routes.uses_interface(addr, tunnel) == Verified::Yes;
    let outside = |addr| routes.uses_interface(addr, tunnel) == Verified::No;
    for (half, addr) in half_probes(expected)? {
        if !through(addr) {
            return Err(format!("{half} is not routed through the tunnel."));
        }
    }
    match ipv6 {
        Ipv6Block::Blocked => {
            for (half, addr) in FULL_TUNNEL_V6.iter().zip(PROBES_V6) {
                if routes.uses_interface_v6(addr, tunnel) != Verified::Yes {
                    return Err(format!(
                        "IPv6 is not blocked: {half} does not go to the tunnel."
                    ));
                }
            }
        }
        Ipv6Block::NothingToBlock => {
            if routes.full_tunnel_ipv6(tunnel) != Ok(Ipv6Block::NothingToBlock) {
                let why = "IPv6 could leave by another network, and the tunnel cannot block it.";
                return Err(why.to_string());
            }
        }
    }
    let physical = expected.physical;
    if !outside(expected.gateway) {
        return Err("The gateway goes through the tunnel.".to_string());
    }
    let router = physical.next_hop();
    if let Some(router) = router
        && !outside(router)
    {
        return Err(format!("The router {router} goes through the tunnel."));
    }
    let direct: Vec<Ipv4Addr> = [expected.gateway].into_iter().chain(router).collect();
    for net in physical.on_link() {
        let inside = probe_address(net, &[], &direct, &[]).unwrap_or(net.addr());
        if !outside(inside) {
            return Err(format!(
                "{net}, a network this computer is on, goes through the tunnel."
            ));
        }
    }
    let servers = expected.dns_servers;
    if servers.is_empty() {
        return Err("The gateway offered no DNS server for every name.".to_string());
    }
    for server in servers {
        if !through(*server) {
            return Err(format!(
                "DNS server {server} is not reached through the tunnel."
            ));
        }
    }
    match dns.catch_all_dns_matches(servers) {
        Verified::Yes => Ok(Confirmed::Fully),
        Verified::Unobservable => Ok(Confirmed::DnsUnobservable),
        Verified::No | Verified::Unknown => Err("DNS for every name is not in effect.".to_string()),
    }
}

/// Checks that full mode is gone after a switch to split: an address in
/// each IPv4 half, outside the chosen subnets and the networks the machine
/// is on, no longer goes through the tunnel; nor does an address in each
/// IPv6 half, when they were blocked (`ipv6`); and the catch-all no longer
/// takes every name. Anything but "no" is a failure.
pub(crate) fn verify_full_gone(
    routes: &dyn Routes,
    dns: &dyn Dns,
    expected: &Expected,
    ipv6: Ipv6Block,
) -> Result<(), String> {
    let tunnel = expected.tunnel;
    for (half, addr) in half_probes(expected)? {
        if routes.uses_interface(addr, tunnel) != Verified::No {
            return Err(format!("{half} still goes through the tunnel."));
        }
    }
    if ipv6 == Ipv6Block::Blocked {
        for (half, addr) in FULL_TUNNEL_V6.iter().zip(PROBES_V6) {
            if routes.uses_interface_v6(addr, tunnel) != Verified::No {
                return Err(format!("IPv6 {half} still goes to the tunnel."));
            }
        }
    }
    if dns.catch_all_dns_matches(expected.dns_servers) != Verified::No {
        return Err("DNS for every name still goes to the gateway's servers.".to_string());
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
            domains: vec!["dept.example.test".to_string()],
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
        let probe = |subnet: &str, gateway| probe(&net(subnet), &physical, &[], gateway, &[]);
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
        let inside = probe(&wide, &physical, &[], GATEWAY, &[]).unwrap();
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
        let tested = probe(&small, &physical, &[], GATEWAY, &[dns]);
        assert_eq!(tested, Some(Ipv4Addr::new(10, 255, 0, 2)));
    }

    fn net(text: &str) -> Ipv4Net {
        text.parse().unwrap()
    }

    /// A connection on the fake: the gateway's route, `routed` through the
    /// tunnel, and what `verify` expects of `subnets` and `dns_servers`.
    fn connected(routed: &[Ipv4Net]) -> (Fake, PhysicalNetwork) {
        let fake = Fake::new();
        let physical = fake.capture_physical(GATEWAY).unwrap();
        fake.add_gateway_route(GATEWAY, &physical).unwrap();
        fake.add_tunnel_routes(TUNNEL, routed).unwrap();
        (fake, physical)
    }

    // A dropped subnet wider than the local network is asked about outside
    // it. One whose route is still there is reported, though its first
    // address is in the local network and so never went through the tunnel.
    #[test]
    fn a_dropped_route_still_there_is_seen_outside_the_local_network() {
        let wide = net("192.168.0.0/16");
        let (fake, physical) = connected(&[wide]);
        let expected = Expected {
            tunnel: TUNNEL,
            physical: &physical,
            gateway: GATEWAY,
            subnets: &[],
            dns: None,
            dns_servers: &[],
        };
        let still = verify_dropped(&fake, &expected, &[wide], &[]);
        assert_eq!(
            still,
            Err("192.168.0.0/16 still goes through the tunnel.".into())
        );
        fake.remove_tunnel_routes(TUNNEL, &[wide]).unwrap();
        assert_eq!(verify_dropped(&fake, &expected, &[wide], &[]), Ok(()));
    }

    // Security rule: a DNS server's own host route goes through the tunnel
    // whatever the subnet around it does, so it must not be what the subnet
    // is checked with: a subnet whose route is missing is not confirmed.
    #[test]
    fn a_dns_servers_route_does_not_stand_in_for_its_subnet() {
        let dns = Ipv4Addr::new(10, 255, 0, 1);
        let server = net("10.255.0.1/32");
        let (fake, physical) = connected(&[server]);
        let small = net("10.255.0.0/24");
        let expected = Expected {
            tunnel: TUNNEL,
            physical: &physical,
            gateway: GATEWAY,
            subnets: &[small],
            dns: None,
            dns_servers: &[dns],
        };
        let checked = verify(&fake, &fake, &expected);
        assert_eq!(
            checked,
            Err("10.255.0.0/24 is not routed through the tunnel.".into())
        );
        fake.add_tunnel_routes(TUNNEL, &[small]).unwrap();
        assert_eq!(verify(&fake, &fake, &expected), Ok(Confirmed::Fully));
    }

    // Two chosen subnets, one inside the other: an address in the inner one
    // proves only the inner route. The outer one is checked outside it, and
    // a missing outer route is seen.
    #[test]
    fn a_subnet_is_tested_outside_the_chosen_subnets_inside_it() {
        let (outer, inner) = (net("10.0.0.0/8"), net("10.0.0.0/24"));
        let (fake, physical) = connected(&[inner]);
        let expected = Expected {
            tunnel: TUNNEL,
            physical: &physical,
            gateway: GATEWAY,
            subnets: &[outer, inner],
            dns: None,
            dns_servers: &[],
        };
        let checked = verify(&fake, &fake, &expected);
        assert_eq!(
            checked,
            Err("10.0.0.0/8 is not routed through the tunnel.".into())
        );
        fake.add_tunnel_routes(TUNNEL, &[outer]).unwrap();
        assert_eq!(verify(&fake, &fake, &expected), Ok(Confirmed::Fully));
        // Chosen subnets inside it that cover all of it leave nothing to
        // check it with: that is said, not passed.
        let halves = [net("10.0.0.0/9"), net("10.128.0.0/9")];
        let covered = Expected {
            subnets: &[outer, halves[0], halves[1]],
            ..expected
        };
        fake.add_tunnel_routes(TUNNEL, &halves).unwrap();
        let checked = verify(&fake, &fake, &covered).unwrap_err();
        assert!(
            checked.starts_with("10.0.0.0/8 cannot be checked"),
            "{checked}"
        );
    }

    // A dropped subnet with a kept one inside it is asked about outside the
    // kept one, which would answer for itself. One a kept route covers
    // whole is meant to go through the tunnel, and is not asked about; one
    // that kept routes cover in pieces cannot be checked, and says so.
    #[test]
    fn a_dropped_route_is_tested_outside_the_routes_kept() {
        let (outer, kept) = (net("10.0.0.0/8"), net("10.0.0.0/24"));
        let (fake, physical) = connected(&[outer, kept]);
        let expected = Expected {
            tunnel: TUNNEL,
            physical: &physical,
            gateway: GATEWAY,
            subnets: &[kept],
            dns: None,
            dns_servers: &[],
        };
        let still = verify_dropped(&fake, &expected, &[outer], &[kept]);
        assert_eq!(
            still,
            Err("10.0.0.0/8 still goes through the tunnel.".into())
        );
        fake.remove_tunnel_routes(TUNNEL, &[outer]).unwrap();
        assert_eq!(verify_dropped(&fake, &expected, &[outer], &[kept]), Ok(()));

        let wider = net("10.0.0.0/7");
        assert_eq!(verify_dropped(&fake, &expected, &[kept], &[wider]), Ok(()));
        let halves = [net("10.0.0.0/9"), net("10.128.0.0/9")];
        let checked = verify_dropped(&fake, &expected, &[outer], &halves).unwrap_err();
        assert!(
            checked.starts_with("10.0.0.0/8 cannot be checked"),
            "{checked}"
        );
    }

    const SERVER: Ipv4Addr = Ipv4Addr::new(10, 255, 0, 53);
    const HOME_ROUTER: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 1);

    /// Full mode applied correctly on a home network with two host-only
    /// networks on adapters of their own, all made up; `spoil` then changes
    /// it, and full mode is checked.
    fn check_full(spoil: impl FnOnce(&Fake)) -> Result<Confirmed, String> {
        let fake = Fake::new();
        fake.set_router(HOME_ROUTER);
        let own = [Ipv4Addr::new(10, 200, 0, 10)];
        fake.set_local(&own, &[net("10.200.0.0/24")]);
        fake.add_adapter_network("fake-host1", net("172.31.130.0/24"));
        fake.add_adapter_network("fake-host2", net("172.31.140.0/24"));
        let physical = fake.capture_physical(GATEWAY).unwrap();
        fake.add_gateway_route(GATEWAY, &physical).unwrap();
        let subnets = [net("192.0.2.0/24")];
        let routed = [subnets[0], net("10.255.0.53/32")];
        fake.add_tunnel_routes(TUNNEL, &routed).unwrap();
        let ipv6 = fake.add_full_tunnel(TUNNEL).unwrap();
        fake.set_catch_all_dns(&[SERVER]).unwrap();
        spoil(&fake);
        let expected = Expected {
            tunnel: TUNNEL,
            physical: &physical,
            gateway: GATEWAY,
            subnets: &subnets,
            dns: None,
            dns_servers: &[SERVER],
        };
        verify_full(&fake, &fake, &expected, ipv6)
    }

    // Security rule: each check of full mode stands alone, and every one
    // must answer as required: "yes" for what goes through the tunnel, and
    // "no", not "could not tell", for what must not. Removing any one
    // check, or letting "could not tell" or "cannot be observed" pass for a
    // route, makes this test fail. The host-only networks are on adapters
    // of their own, so they are checked as "not the tunnel", not as "the
    // physical interface".
    #[test]
    fn every_full_mode_check_must_answer_as_required() {
        assert_eq!(check_full(|_| {}), Ok(Confirmed::Fully));
        let foreign =
            |dest: &'static str| move |fake: &Fake| fake.add_foreign_route(TUNNEL, net(dest));
        let elsewhere =
            |dest: &'static str| move |fake: &Fake| fake.add_foreign_route("other0", net(dest));
        let untold = |dest: Ipv4Addr| move |fake: &Fake| fake.cannot_tell_route_to(dest);
        let unobserved = |dest: Ipv4Addr| move |fake: &Fake| fake.cannot_observe_route_to(dest);
        let cases: [(&str, Result<Confirmed, String>); 13] = [
            (
                "0.0.0.0/1 is not routed",
                check_full(elsewhere("1.0.0.0/8")),
            ),
            (
                "128.0.0.0/1 is not routed",
                check_full(elsewhere("128.0.0.0/8")),
            ),
            (
                "0.0.0.0/1 is not routed",
                check_full(unobserved(Ipv4Addr::new(1, 0, 0, 0))),
            ),
            (
                "IPv6 is not blocked",
                check_full(|fake| fake.cannot_observe(Op::VerifyRouteV6, true)),
            ),
            (
                "The router 10.200.0.1 goes",
                check_full(foreign("10.200.0.1/32")),
            ),
            (
                "The router 10.200.0.1 goes",
                check_full(untold(HOME_ROUTER)),
            ),
            (
                "10.200.0.0/24, a network",
                check_full(foreign("10.200.0.2/32")),
            ),
            (
                "172.31.130.0/24, a network",
                check_full(foreign("172.31.130.0/25")),
            ),
            (
                "172.31.140.0/24, a network",
                check_full(foreign("172.31.140.0/25")),
            ),
            (
                "DNS server 10.255.0.53",
                check_full(elsewhere("10.255.0.53/32")),
            ),
            (
                "DNS for every name",
                check_full(|fake| fake.set_foreign_catch_all(true)),
            ),
            (
                "DNS for every name",
                check_full(|fake| {
                    fake.set_failure(Op::VerifyCatchAllDns, Some(Error::Unsupported))
                }),
            ),
            ("The gateway goes", check_full(untold(GATEWAY))),
        ];
        for (words, checked) in cases {
            let why = checked.unwrap_err();
            assert!(why.starts_with(words), "{words}: {why}");
        }
        // The one exception, said as such so that the caller can log it.
        let unobservable = check_full(|fake| fake.cannot_observe(Op::VerifyCatchAllDns, true));
        assert_eq!(unobservable, Ok(Confirmed::DnsUnobservable));
    }

    // Security rule: with nothing to block, the check asks again, and an
    // IPv6 leak path that appeared since fails it; the IPv6 halves, which
    // were not added, are not asked about.
    #[test]
    fn nothing_to_block_is_asked_again() {
        let set_up = |fake: &Fake| fake.set_ipv6(false, false);
        let fake = Fake::new();
        set_up(&fake);
        let physical = fake.capture_physical(GATEWAY).unwrap();
        fake.add_gateway_route(GATEWAY, &physical).unwrap();
        fake.add_tunnel_routes(TUNNEL, &[net("10.255.0.53/32")])
            .unwrap();
        let ipv6 = fake.add_full_tunnel(TUNNEL).unwrap();
        assert_eq!(ipv6, Ipv6Block::NothingToBlock);
        fake.set_catch_all_dns(&[SERVER]).unwrap();
        let expected = Expected {
            tunnel: TUNNEL,
            physical: &physical,
            gateway: GATEWAY,
            subnets: &[],
            dns: None,
            dns_servers: &[SERVER],
        };
        assert_eq!(
            verify_full(&fake, &fake, &expected, ipv6),
            Ok(Confirmed::Fully)
        );
        assert!(!fake.calls().contains(&Op::VerifyRouteV6));
        fake.set_ipv6(false, true);
        let why = verify_full(&fake, &fake, &expected, ipv6).unwrap_err();
        assert!(why.starts_with("IPv6 could leave"), "{why}");
    }

    // Security rule: once full mode is removed, an address in each half no
    // longer goes through the tunnel, nor does IPv6, and the catch-all is
    // gone. Anything left fails the check.
    #[test]
    fn full_mode_must_be_gone_after_a_switch_to_split() {
        let gone = |spoil: &dyn Fn(&Fake)| {
            let fake = Fake::new();
            let physical = fake.capture_physical(GATEWAY).unwrap();
            fake.add_gateway_route(GATEWAY, &physical).unwrap();
            spoil(&fake);
            let expected = Expected {
                tunnel: TUNNEL,
                physical: &physical,
                gateway: GATEWAY,
                subnets: &[],
                dns: None,
                dns_servers: &[SERVER],
            };
            verify_full_gone(&fake, &fake, &expected, Ipv6Block::Blocked)
        };
        assert_eq!(gone(&|_| {}), Ok(()));
        type Spoil<'a> = &'a dyn Fn(&Fake);
        let cases: [(&str, Spoil); 5] = [
            ("0.0.0.0/1 still", &|fake| {
                fake.add_foreign_route(TUNNEL, net("1.0.0.0/8"))
            }),
            ("128.0.0.0/1 still", &|fake| {
                fake.add_foreign_route(TUNNEL, net("128.0.0.0/8"))
            }),
            ("IPv6 ::/1 still", &|fake| {
                fake.add_full_tunnel(TUNNEL).unwrap();
                fake.add_foreign_route("other0", net("0.0.0.0/1"));
                fake.add_foreign_route("other0", net("128.0.0.0/1"));
            }),
            ("DNS for every name still", &|fake| {
                fake.set_catch_all_dns(&[SERVER]).unwrap();
            }),
            ("0.0.0.0/1 still", &|fake| {
                fake.cannot_tell_route_to(Ipv4Addr::new(1, 0, 0, 0));
            }),
        ];
        for (words, spoil) in cases {
            let why = gone(spoil).unwrap_err();
            assert!(why.starts_with(words), "{words}: {why}");
        }
    }
}
