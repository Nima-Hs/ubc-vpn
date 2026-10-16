//! Split-tunnel routes and the rule for which ones the service accepts.

use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// The widest route the service will apply. Anything wider (a smaller prefix
/// length) is refused, which rules out a default route and the usual ways of
/// splitting one in two.
///
/// This guards against mistakes. It does not bound how much traffic a long
/// list of routes can capture in total.
pub const MIN_PREFIX_LEN: u8 = 8;

/// The most subnets, and the most DNS domains, one route set may hold.
pub const MAX_ROUTES: usize = 256;

/// Ranges that are never a real destination behind a VPN: "this network",
/// loopback, link-local, multicast, and the reserved block that includes
/// broadcast. A route that touches any of them is refused.
const RESERVED: [(Ipv4Addr, u8); 5] = [
    (Ipv4Addr::new(0, 0, 0, 0), 8),
    (Ipv4Addr::new(127, 0, 0, 0), 8),
    (Ipv4Addr::new(169, 254, 0, 0), 16),
    (Ipv4Addr::new(224, 0, 0, 0), 4),
    (Ipv4Addr::new(240, 0, 0, 0), 4),
];

/// An IPv4 network in CIDR form, such as `10.19.0.0/16`.
///
/// The address is always the network address: host bits are zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Ipv4Net {
    addr: Ipv4Addr,
    prefix_len: u8,
}

/// Why a string is not a valid [`Ipv4Net`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetParseError {
    /// Not of the form `a.b.c.d/len`.
    Malformed,
    /// The prefix length is greater than 32.
    PrefixTooLong,
    /// Bits are set beyond the prefix, as in `10.0.0.1/8`.
    HostBitsSet,
}

impl fmt::Display for NetParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Malformed => "expected a network like 10.0.0.0/8",
            Self::PrefixTooLong => "prefix length must be 32 or less",
            Self::HostBitsSet => "address has bits set beyond the prefix",
        })
    }
}

impl std::error::Error for NetParseError {}

impl Ipv4Net {
    /// Creates a network, refusing an address with host bits set.
    pub fn new(addr: Ipv4Addr, prefix_len: u8) -> Result<Self, NetParseError> {
        if prefix_len > 32 {
            return Err(NetParseError::PrefixTooLong);
        }
        if u32::from(addr) & !Self::mask(prefix_len) != 0 {
            return Err(NetParseError::HostBitsSet);
        }
        Ok(Self { addr, prefix_len })
    }

    fn mask(prefix_len: u8) -> u32 {
        match prefix_len {
            0 => 0,
            n => u32::MAX << (32 - u32::from(n)),
        }
    }

    /// The network address.
    pub fn addr(&self) -> Ipv4Addr {
        self.addr
    }

    /// The prefix length, 0 to 32.
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// Whether `ip` lies inside this network.
    pub fn contains_addr(&self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & Self::mask(self.prefix_len) == u32::from(self.addr)
    }

    /// The last address inside this network.
    pub fn last(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.addr) | !Self::mask(self.prefix_len))
    }

    /// Whether `other` lies entirely inside this network.
    pub fn contains(&self, other: &Ipv4Net) -> bool {
        self.prefix_len <= other.prefix_len && self.contains_addr(other.addr)
    }

    /// Whether this network overlaps a range that is never a real
    /// destination: "this network", loopback, link-local, multicast, and the
    /// reserved block that includes broadcast.
    ///
    /// Routes and gateway addresses are both checked against this one list.
    pub fn is_reserved(&self) -> bool {
        RESERVED.iter().any(|&(addr, prefix_len)| {
            let reserved = Ipv4Net { addr, prefix_len };
            reserved.contains(self) || self.contains(&reserved)
        })
    }
}

impl FromStr for Ipv4Net {
    type Err = NetParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr, len) = s.split_once('/').ok_or(NetParseError::Malformed)?;
        let addr: Ipv4Addr = addr.parse().map_err(|_| NetParseError::Malformed)?;
        // Digits only, and no leading zero: `u8::from_str` alone would accept
        // `+8` and `08`, giving one network several spellings.
        let canonical = !len.is_empty()
            && len.bytes().all(|b| b.is_ascii_digit())
            && (len == "0" || !len.starts_with('0'));
        if !canonical {
            return Err(NetParseError::Malformed);
        }
        let len: u8 = len.parse().map_err(|_| NetParseError::PrefixTooLong)?;
        Self::new(addr, len)
    }
}

impl TryFrom<String> for Ipv4Net {
    type Error = NetParseError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl From<Ipv4Net> for String {
    fn from(net: Ipv4Net) -> Self {
        net.to_string()
    }
}

impl fmt::Display for Ipv4Net {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix_len)
    }
}

/// What the user chose to send through the tunnel.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct RouteSet {
    /// Subnets routed through the tunnel.
    #[cfg_attr(test, ts(type = "Array<string>"))]
    pub subnets: Vec<Ipv4Net>,
    /// DNS domains resolved through the tunnel, such as `ece.ubc.ca`.
    #[serde(default)]
    pub dns_domains: Vec<String>,
}

/// Why the service refuses a [`RouteSet`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteError {
    /// No subnets were chosen, so there is nothing to tunnel.
    NoSubnets,
    /// The route is wider than [`MIN_PREFIX_LEN`] allows.
    TooWide(Ipv4Net),
    /// The policy has an allow-list and the route is outside it.
    NotAllowed(Ipv4Net),
    /// The route touches a loopback, link-local, multicast or reserved range.
    Reserved(Ipv4Net),
    /// There are more than [`MAX_ROUTES`] subnets or DNS domains.
    TooMany,
    /// The DNS domain is not a plain host name.
    BadDomain(String),
}

impl fmt::Display for RouteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSubnets => f.write_str("no subnets were chosen"),
            Self::TooWide(net) => write!(f, "{net} is wider than /{MIN_PREFIX_LEN}"),
            Self::NotAllowed(net) => write!(f, "{net} is outside the allowed routes"),
            Self::Reserved(net) => write!(f, "{net} is a reserved range"),
            Self::TooMany => write!(f, "more than {MAX_ROUTES} routes or domains"),
            Self::BadDomain(d) => write!(f, "{d:?} is not a valid DNS domain"),
        }
    }
}

impl std::error::Error for RouteError {}

impl RouteSet {
    /// Whether these are the same routes as `subnets` and `dns_domains`,
    /// as sets: in any order, with duplicates counted once. A tunnel that
    /// carries those carries these.
    pub fn is_carried_by(&self, subnets: &[Ipv4Net], dns_domains: &[String]) -> bool {
        use std::collections::HashSet;
        let set = |nets: &[Ipv4Net]| nets.iter().copied().collect::<HashSet<_>>();
        let names = |names: &[String]| names.iter().cloned().collect::<HashSet<_>>();
        set(&self.subnets) == set(subnets) && names(&self.dns_domains) == names(dns_domains)
    }

    /// Applies the service's acceptance rule.
    ///
    /// Every subnet must be no wider than [`MIN_PREFIX_LEN`], touch no
    /// reserved range and, when the policy has an allow-list, lie inside one
    /// of its entries. The whole set is refused if any part is.
    ///
    /// Duplicate and overlapping subnets are accepted; applying them is the
    /// same as applying their union.
    pub fn check(&self, allow_list: Option<&[Ipv4Net]>) -> Result<(), RouteError> {
        if self.subnets.is_empty() {
            return Err(RouteError::NoSubnets);
        }
        if self.subnets.len() > MAX_ROUTES || self.dns_domains.len() > MAX_ROUTES {
            return Err(RouteError::TooMany);
        }
        for net in &self.subnets {
            if net.prefix_len() < MIN_PREFIX_LEN {
                return Err(RouteError::TooWide(*net));
            }
            if net.is_reserved() {
                return Err(RouteError::Reserved(*net));
            }
            if let Some(allowed) = allow_list
                && !allowed.iter().any(|a| a.contains(net))
            {
                return Err(RouteError::NotAllowed(*net));
            }
        }
        match self.dns_domains.iter().find(|d| !is_valid_domain(d)) {
            Some(bad) => Err(RouteError::BadDomain(bad.clone())),
            None => Ok(()),
        }
    }
}

/// The networks a machine was already on when a connection started, as the
/// platform captured them before the tunnel existed.
#[derive(Debug, Clone, Copy)]
pub struct LocalNetworks<'a> {
    /// The machine's own addresses on every interface but the tunnel.
    pub own_addresses: &'a [Ipv4Addr],
    /// The networks those interfaces reach directly, with no router between.
    pub on_link: &'a [Ipv4Net],
    /// The router of the physical network, when it has one.
    pub next_hop: Option<Ipv4Addr>,
}

/// Why a connection cannot be set up on the network the machine is on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalConflict {
    /// The gateway's address is one of this machine's own.
    GatewayIsOwnAddress(Ipv4Addr),
    /// The route (first) is the same as, or lies inside, a network the
    /// machine is directly on (second).
    InsideLocalNetwork(Ipv4Net, Ipv4Net),
    /// The route would capture the physical network's router.
    HoldsRouter(Ipv4Net, Ipv4Addr),
    /// The route is the gateway's own address, which is routed through the
    /// physical network, never the tunnel.
    IsGateway(Ipv4Net),
    /// Every address of the route is in a network the machine is directly
    /// on, or is the gateway: the more specific local routes would take all
    /// of it, so the tunnel would carry none of it, and that could not be
    /// checked.
    CoveredByLocalNetworks(Ipv4Net),
}

impl fmt::Display for LocalConflict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GatewayIsOwnAddress(addr) => {
                write!(f, "the gateway address {addr} is this computer's own")
            }
            Self::InsideLocalNetwork(net, local) => {
                write!(f, "{net} is part of {local}, a network this computer is on")
            }
            Self::HoldsRouter(net, router) => {
                write!(f, "{net} contains {router}, the router of this network")
            }
            Self::IsGateway(net) => {
                write!(f, "{net} is the gateway itself, which cannot be tunnelled")
            }
            Self::CoveredByLocalNetworks(net) => write!(
                f,
                "all of {net} is in networks this computer is on, so none of it would go through the tunnel"
            ),
        }
    }
}

impl std::error::Error for LocalConflict {}

/// Checks a connection against the network the machine is on. The rule is
/// the same on every OS; only how `local` is learned differs.
///
/// A route sent into the tunnel wins over a local network wherever it is the
/// more specific of the two, so:
///
/// - A subnet that equals an on-link network, or lies inside one, is refused:
///   it would take the machine's neighbours, and usually its router, away
///   from the network they are really on.
/// - A subnet wider than an on-link network is accepted. The local network
///   stays the more specific route, so `10.0.0.0/8` works from a home network
///   that is `10.0.0.0/24`. It is checked at an address outside the local
///   networks ([`probe_address`]). A subnet that local networks cover
///   entirely between them is refused: the tunnel would carry none of it.
/// - A subnet that contains the router is refused unless an on-link network
///   also contains it. That network is then the more specific of the two (a
///   wider one would have refused the subnet already), so the router stays
///   where it is. Without it the route to the gateway, which goes through
///   the router, would lead into the tunnel.
/// - The gateway's address must not be one of the machine's own.
/// - A subnet that is the gateway's address alone is refused. The gateway is
///   always reached through the physical network, by a host route of its
///   own; a wider subnet that contains it is fine.
pub fn check_against_local(
    subnets: &[Ipv4Net],
    gateway: Ipv4Addr,
    local: &LocalNetworks,
) -> Result<(), LocalConflict> {
    if local.own_addresses.contains(&gateway) {
        return Err(LocalConflict::GatewayIsOwnAddress(gateway));
    }
    for subnet in subnets {
        if subnet.prefix_len() == 32 && subnet.addr() == gateway {
            return Err(LocalConflict::IsGateway(*subnet));
        }
        if let Some(on_link) = local.on_link.iter().find(|net| net.contains(subnet)) {
            return Err(LocalConflict::InsideLocalNetwork(*subnet, *on_link));
        }
        // Several local networks, none wider than the subnet, may still
        // cover all of it between them.
        if probe_address(subnet, local.on_link, &[gateway], &[]).is_none() {
            return Err(LocalConflict::CoveredByLocalNetworks(*subnet));
        }
        if let Some(router) = local.next_hop
            && subnet.contains_addr(router)
            && !local.on_link.iter().any(|net| net.contains_addr(router))
        {
            return Err(LocalConflict::HoldsRouter(*subnet, router));
        }
    }
    Ok(())
}

/// An address inside `subnet` that shows whether the route for `subnet` is
/// the one the operating system uses, or `None` when there is none.
///
/// A route is tested by asking which way one address inside it goes. The
/// address must be one the route itself decides:
///
/// - **Never in `local`,** the networks the machine is directly on. Their
///   routes are more specific than a subnet wider than them, so an address
///   in one goes to the local network whatever the subnet's route says.
/// - **Never one of `never`,** such as the gateway, which has a host route
///   of its own through the physical network.
/// - **Rather not one of `rather_not`,** such as the DNS servers, whose host
///   routes go through the tunnel whatever the subnet's route says. One of
///   them is taken only when nothing else is left.
///
/// The first address after the network's own is preferred, then the next
/// ones, then the network's own address.
pub fn probe_address(
    subnet: &Ipv4Net,
    local: &[Ipv4Net],
    never: &[Ipv4Addr],
    rather_not: &[Ipv4Addr],
) -> Option<Ipv4Addr> {
    let usable = |addr: Ipv4Addr| {
        subnet.contains_addr(addr)
            && !never.contains(&addr)
            && !local.iter().any(|net| net.contains_addr(addr))
    };
    let first = |avoid: &[Ipv4Addr]| {
        let start = u32::from(subnet.addr());
        let end = u32::from(subnet.last());
        // Every address skipped is one of `avoid` or `never`, or a step
        // over a whole local network, so this ends after a few steps.
        let mut at = start.checked_add(1).filter(|next| *next <= end);
        while let Some(n) = at {
            let addr = Ipv4Addr::from(n);
            // Stepping over a whole network is for speed only: the same
            // address would be found one address at a time, but a `/9`
            // network inside a `/8` subnet is millions of steps.
            if let Some(net) = local.iter().find(|net| net.contains_addr(addr)) {
                at = u32::from(net.last())
                    .checked_add(1)
                    .filter(|next| *next <= end);
                continue;
            }
            if usable(addr) && !avoid.contains(&addr) {
                return Some(addr);
            }
            at = n.checked_add(1).filter(|next| *next <= end);
        }
        let own = subnet.addr();
        (usable(own) && !avoid.contains(&own)).then_some(own)
    };
    first(rather_not).or_else(|| first(&[]))
}

/// A plain lower-case host name: at least two dot-separated labels of
/// letters, digits and hyphens, the last one not all digits. No wildcard, no
/// trailing dot, no root, and so no IP address.
pub(crate) fn is_valid_domain(domain: &str) -> bool {
    let label_ok = |label: &str| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    let top_level_ok = domain
        .rsplit('.')
        .next()
        .is_some_and(|top| !top.bytes().all(|b| b.is_ascii_digit()));
    domain.len() <= 253 && domain.contains('.') && domain.split('.').all(label_ok) && top_level_ok
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(s: &str) -> Ipv4Net {
        s.parse().unwrap()
    }

    fn set(subnets: &[&str]) -> RouteSet {
        RouteSet {
            subnets: subnets.iter().map(|s| net(s)).collect(),
            dns_domains: vec![],
        }
    }

    // Routes are the same as sets: order and repeats do not matter, and a
    // missing or extra entry does.
    #[test]
    fn routes_are_compared_as_sets() {
        let carried = [net("10.255.0.0/24"), net("192.0.2.0/24")];
        let domains = ["ece.example.test".to_string()];
        let mut asked = set(&["192.0.2.0/24", "10.255.0.0/24", "192.0.2.0/24"]);
        asked.dns_domains = vec!["ece.example.test".to_string(); 2];
        assert!(asked.is_carried_by(&carried, &domains));
        assert!(!set(&["10.255.0.0/24"]).is_carried_by(&carried, &[]));
        let mut more = set(&["10.255.0.0/24", "192.0.2.0/24", "198.51.100.0/24"]);
        more.dns_domains = domains.to_vec();
        assert!(!more.is_carried_by(&carried, &domains));
        let mut other = set(&["10.255.0.0/24", "192.0.2.0/24"]);
        other.dns_domains = vec!["cs.example.test".to_string()];
        assert!(!other.is_carried_by(&carried, &domains));
        // The same subnets with a domain fewer, or one more, are a change
        // too: dropping a domain is as much the user's choice as adding one.
        let fewer = set(&["10.255.0.0/24", "192.0.2.0/24"]);
        assert!(!fewer.is_carried_by(&carried, &domains));
        let mut more_domains = set(&["10.255.0.0/24", "192.0.2.0/24"]);
        more_domains.dns_domains = vec![domains[0].clone(), "cs.example.test".to_string()];
        assert!(!more_domains.is_carried_by(&carried, &domains));
        // And the same for subnets: one fewer is a change.
        let mut fewer_subnets = set(&["10.255.0.0/24"]);
        fewer_subnets.dns_domains = domains.to_vec();
        assert!(!fewer_subnets.is_carried_by(&carried, &domains));
    }

    #[test]
    fn parses_and_prints_cidr() {
        assert_eq!(net("142.103.0.0/16").to_string(), "142.103.0.0/16");
        assert_eq!(net("10.0.0.0/8").prefix_len(), 8);
    }

    #[test]
    fn refuses_malformed_networks() {
        assert_eq!("10.0.0.0".parse::<Ipv4Net>(), Err(NetParseError::Malformed));
        assert_eq!(
            "10.0.0.0/33".parse::<Ipv4Net>(),
            Err(NetParseError::PrefixTooLong)
        );
        assert_eq!(
            "10.0.0.1/8".parse::<Ipv4Net>(),
            Err(NetParseError::HostBitsSet)
        );
        assert_eq!("::/0".parse::<Ipv4Net>(), Err(NetParseError::Malformed));
        // One network, one spelling.
        for odd in ["10.0.0.0/+8", "10.0.0.0/08", "10.0.0.0/ 8", "10.0.0.0/"] {
            assert_eq!(
                odd.parse::<Ipv4Net>(),
                Err(NetParseError::Malformed),
                "{odd}"
            );
        }
        assert_eq!(
            "10.0.0.0/256".parse::<Ipv4Net>(),
            Err(NetParseError::PrefixTooLong)
        );
        assert!("0.0.0.0/0".parse::<Ipv4Net>().is_ok());
    }

    // Security rule: loopback, link-local, multicast and reserved ranges are
    // never accepted, whether the route is inside one or spans one.
    #[test]
    fn refuses_reserved_ranges() {
        for reserved in [
            "0.0.0.0/8",
            "0.0.0.0/32",
            "127.0.0.0/8",
            "127.0.0.1/32",
            "169.254.0.0/16",
            "169.254.10.0/24",
            "169.0.0.0/8",
            "224.0.0.0/8",
            "239.1.2.0/24",
            "240.0.0.0/8",
            "255.255.255.255/32",
        ] {
            assert_eq!(
                set(&[reserved]).check(None),
                Err(RouteError::Reserved(net(reserved))),
                "{reserved} must be refused"
            );
        }
        // Their neighbours are ordinary addresses.
        assert_eq!(
            set(&["1.0.0.0/8", "126.0.0.0/8", "223.0.0.0/8"]).check(None),
            Ok(())
        );
    }

    #[test]
    fn refuses_too_many_routes_or_domains() {
        let many: Vec<Ipv4Net> = (0..=MAX_ROUTES as u32)
            .map(|i| Ipv4Net::new(Ipv4Addr::from(0x0A00_0000 + (i << 8)), 24).unwrap())
            .collect();
        let over = RouteSet {
            subnets: many.clone(),
            dns_domains: vec![],
        };
        assert_eq!(over.check(None), Err(RouteError::TooMany));
        let at_limit = RouteSet {
            subnets: many[..MAX_ROUTES].to_vec(),
            dns_domains: vec![],
        };
        assert_eq!(at_limit.check(None), Ok(()));

        let domains = RouteSet {
            subnets: vec![net("10.19.0.0/16")],
            dns_domains: (0..=MAX_ROUTES).map(|i| format!("h{i}.ubc.ca")).collect(),
        };
        assert_eq!(domains.check(None), Err(RouteError::TooMany));
    }

    #[test]
    fn duplicates_and_overlaps_are_accepted() {
        assert_eq!(
            set(&["10.19.0.0/16", "10.19.0.0/16", "10.0.0.0/8"]).check(None),
            Ok(())
        );
    }

    #[test]
    fn containment() {
        assert!(net("10.0.0.0/8").contains(&net("10.19.0.0/16")));
        assert!(!net("10.19.0.0/16").contains(&net("10.0.0.0/8")));
        assert!(net("142.103.0.0/16").contains_addr(Ipv4Addr::new(142, 103, 1, 2)));
        assert!(!net("142.103.0.0/16").contains_addr(Ipv4Addr::new(142, 104, 0, 1)));
    }

    #[test]
    fn accepts_ordinary_campus_routes() {
        assert_eq!(set(&["142.103.0.0/16", "10.0.0.0/8"]).check(None), Ok(()));
    }

    // Security rule: a default route, or either half of one, must never be
    // accepted. Removing the width check makes this test fail.
    #[test]
    fn refuses_default_route_and_its_halves() {
        for wide in ["0.0.0.0/0", "0.0.0.0/1", "128.0.0.0/1", "0.0.0.0/7"] {
            assert_eq!(
                set(&[wide]).check(None),
                Err(RouteError::TooWide(net(wide))),
                "{wide} must be refused"
            );
        }
    }

    #[test]
    fn one_bad_route_refuses_the_whole_set() {
        assert_eq!(
            set(&["10.19.0.0/16", "0.0.0.0/0"]).check(None),
            Err(RouteError::TooWide(net("0.0.0.0/0")))
        );
    }

    // Security rule: with an allow-list, nothing outside it is accepted.
    #[test]
    fn allow_list_is_enforced() {
        let allowed = [net("142.103.0.0/16")];
        assert_eq!(set(&["142.103.5.0/24"]).check(Some(&allowed)), Ok(()));
        assert_eq!(
            set(&["10.19.0.0/16"]).check(Some(&allowed)),
            Err(RouteError::NotAllowed(net("10.19.0.0/16")))
        );
        // A route wider than the allowed entry is outside it.
        assert_eq!(
            set(&["142.0.0.0/8"]).check(Some(&allowed)),
            Err(RouteError::NotAllowed(net("142.0.0.0/8")))
        );
    }

    #[test]
    fn refuses_an_empty_set() {
        assert_eq!(set(&[]).check(None), Err(RouteError::NoSubnets));
    }

    #[test]
    fn validates_dns_domains() {
        let with = |d: &str| RouteSet {
            subnets: vec![net("10.19.0.0/16")],
            dns_domains: vec![d.to_string()],
        };
        assert_eq!(with("ece.ubc.ca").check(None), Ok(()));
        assert_eq!(with("xn--bcher-kva.example").check(None), Ok(()));
        for bad in [
            "", "ubc", "*.ubc.ca", "ubc.ca.", "UBC.ca", "a..b", "-a.ca", "a_b.ca", "1.2", "1.2.3.4",
        ] {
            assert_eq!(
                with(bad).check(None),
                Err(RouteError::BadDomain(bad.to_string())),
                "{bad:?} must be refused"
            );
        }
    }

    #[test]
    fn serialises_as_strings() {
        let json = serde_json::to_string(&set(&["10.19.0.0/16"])).unwrap();
        assert_eq!(json, r#"{"subnets":["10.19.0.0/16"],"dns_domains":[]}"#);
        let back: RouteSet = serde_json::from_str(&json).unwrap();
        assert_eq!(back, set(&["10.19.0.0/16"]));
        assert!(serde_json::from_str::<RouteSet>(r#"{"subnets":["10.0.0.1/8"]}"#).is_err());
    }

    /// A home network, 10.0.0.0/24 behind 10.0.0.1, and a bridge.
    fn checked(subnet: &str, gateway: [u8; 4]) -> Result<(), LocalConflict> {
        let local = LocalNetworks {
            own_addresses: &[Ipv4Addr::new(10, 0, 0, 7), Ipv4Addr::new(172, 17, 0, 1)],
            on_link: &[net("10.0.0.0/24"), net("172.17.0.0/16")],
            next_hop: Some(Ipv4Addr::new(10, 0, 0, 1)),
        };
        check_against_local(&[net("192.0.2.0/24"), net(subnet)], gateway.into(), &local)
    }

    const GATEWAY: [u8; 4] = [198, 51, 100, 1];

    // Security rule: a route may not take the machine's own network, or its
    // router, into the tunnel.
    #[test]
    fn refuses_a_route_equal_to_or_inside_a_local_network() {
        let home = net("10.0.0.0/24");
        for inside in ["10.0.0.0/24", "10.0.0.0/25", "10.0.0.128/25", "10.0.0.9/32"] {
            let refused = LocalConflict::InsideLocalNetwork(net(inside), home);
            assert_eq!(checked(inside, GATEWAY), Err(refused), "{inside}");
        }
        // A bridge is a network the machine is on, as much as the physical one.
        let bridge = LocalConflict::InsideLocalNetwork(net("172.17.3.0/24"), net("172.17.0.0/16"));
        assert_eq!(checked("172.17.3.0/24", GATEWAY), Err(bridge));
    }

    // The local network stays the more specific route, so a campus range that
    // happens to contain a home network must keep working.
    #[test]
    fn accepts_a_route_wider_than_a_local_network_or_apart_from_it() {
        for fine in ["10.0.0.0/8", "10.0.0.0/23", "10.0.1.0/24", "172.16.0.0/12"] {
            assert_eq!(checked(fine, GATEWAY), Ok(()), "{fine}");
        }
        // The gateway may sit on a local network, as long as it is not us.
        assert_eq!(checked("10.19.0.0/16", [10, 0, 0, 9]), Ok(()));
    }

    // Security rule: the route to the gateway goes through the router, so a
    // route that captures the router sends the tunnel into itself.
    #[test]
    fn refuses_a_route_that_holds_a_router_no_local_network_keeps() {
        // A link whose router lies outside the machine's own network, as on
        // some mobile and cloud networks.
        let router = Ipv4Addr::new(100, 64, 0, 1);
        let local = |on_link: &[Ipv4Net]| {
            let own = [Ipv4Addr::new(100, 64, 5, 7)];
            let local = LocalNetworks {
                own_addresses: &own,
                on_link,
                next_hop: Some(router),
            };
            check_against_local(&[net("100.64.0.0/16")], GATEWAY.into(), &local)
        };
        let held = LocalConflict::HoldsRouter(net("100.64.0.0/16"), router);
        assert_eq!(local(&[net("100.64.5.7/32")]), Err(held.clone()));
        assert_eq!(local(&[]), Err(held));
        // A local network that holds the router is more specific than the
        // route, or the route would have been refused as lying inside it.
        assert_eq!(local(&[net("100.64.0.0/24")]), Ok(()));
        // No router at all: nothing to capture.
        let direct = LocalNetworks {
            own_addresses: &[],
            on_link: &[],
            next_hop: None,
        };
        let subnets = [net("100.64.0.0/16")];
        assert_eq!(
            check_against_local(&subnets, GATEWAY.into(), &direct),
            Ok(())
        );
    }

    // Every subnet is checked, not only the last: here the conflict comes
    // first and the rest are fine.
    #[test]
    fn checks_every_subnet_wherever_the_conflict_is() {
        let local = LocalNetworks {
            own_addresses: &[Ipv4Addr::new(10, 0, 0, 7)],
            on_link: &[net("10.0.0.0/24")],
            next_hop: Some(Ipv4Addr::new(10, 0, 0, 1)),
        };
        let subnets = [net("10.0.0.0/25"), net("192.0.2.0/24"), net("10.19.0.0/16")];
        let refused = LocalConflict::InsideLocalNetwork(net("10.0.0.0/25"), net("10.0.0.0/24"));
        let checked = check_against_local(&subnets, GATEWAY.into(), &local);
        assert_eq!(checked, Err(refused));
    }

    // Security rule: the gateway's own address is routed through the
    // physical network. A route for it alone would contend with that one.
    #[test]
    fn refuses_a_host_route_to_the_gateway_but_not_a_subnet_holding_it() {
        let host = net("198.51.100.1/32");
        assert_eq!(
            checked("198.51.100.1/32", GATEWAY),
            Err(LocalConflict::IsGateway(host))
        );
        assert_eq!(checked("198.51.100.0/24", GATEWAY), Ok(()));
        assert_eq!(checked("198.51.100.2/32", GATEWAY), Ok(()));
    }

    // A route is checked at an address the route itself decides: outside
    // every local network, whose routes are more specific, never the
    // gateway's, and the DNS servers' only when nothing else is left.
    #[test]
    fn a_route_is_probed_where_it_decides() {
        let ip = |text: &str| text.parse::<Ipv4Addr>().unwrap();
        let home = [net("192.168.0.0/24")];
        // The issue's case: a route wider than the home network was probed
        // at 192.168.0.1, inside it, which the local network takes.
        let wide = net("192.168.0.0/16");
        assert_eq!(
            probe_address(&wide, &home, &[], &[]),
            Some(ip("192.168.1.0"))
        );
        assert_eq!(probe_address(&wide, &[], &[], &[]), Some(ip("192.168.0.1")));
        // Several local networks are stepped over, as is the gateway.
        let lans = [net("10.0.0.0/24"), net("10.0.1.0/24")];
        let gateway = ip("10.0.2.0");
        let wide = net("10.0.0.0/16");
        assert_eq!(
            probe_address(&wide, &lans, &[gateway], &[]),
            Some(ip("10.0.2.1"))
        );
        // A DNS server is taken only when nothing else is left.
        let dns = ip("10.255.0.1");
        let tiny = net("10.255.0.0/31");
        assert_eq!(
            probe_address(&tiny, &[], &[], &[dns]),
            Some(ip("10.255.0.0"))
        );
        let host = net("10.255.0.1/32");
        assert_eq!(probe_address(&host, &[], &[], &[dns]), Some(dns));
        assert_eq!(probe_address(&host, &[], &[dns], &[]), None);
        // Nothing outside the local networks: no probe.
        let covered = net("10.0.0.0/23");
        assert_eq!(probe_address(&covered, &lans, &[], &[]), None);
        let edge = net("255.255.255.0/24");
        let last = [net("255.255.255.0/25")];
        assert_eq!(
            probe_address(&edge, &last, &[], &[]),
            Some(ip("255.255.255.128"))
        );
    }

    // A route that local networks cover between them, none of them wider,
    // would carry nothing through the tunnel: it is refused, with a reason.
    #[test]
    fn refuses_a_route_the_local_networks_cover_between_them() {
        let local = LocalNetworks {
            own_addresses: &[Ipv4Addr::new(10, 0, 0, 7)],
            on_link: &[net("10.0.0.0/24"), net("10.0.1.0/24")],
            next_hop: Some(Ipv4Addr::new(10, 0, 0, 1)),
        };
        let covered = net("10.0.0.0/23");
        let checked = check_against_local(&[covered], GATEWAY.into(), &local);
        assert_eq!(checked, Err(LocalConflict::CoveredByLocalNetworks(covered)));
        assert!(
            checked
                .unwrap_err()
                .to_string()
                .contains("none of it would go")
        );
        let wider = [net("10.0.0.0/22")];
        assert_eq!(check_against_local(&wider, GATEWAY.into(), &local), Ok(()));

        // The gateway counts too: a subnet whose one address outside the
        // local network is the gateway has nothing the tunnel would carry.
        let own = Ipv4Addr::new(10, 9, 0, 0);
        let local = LocalNetworks {
            own_addresses: &[own],
            on_link: &[net("10.9.0.0/32")],
            next_hop: None,
        };
        let pair = net("10.9.0.0/31");
        let gateway = Ipv4Addr::new(10, 9, 0, 1);
        let checked = check_against_local(&[pair], gateway, &local);
        assert_eq!(checked, Err(LocalConflict::CoveredByLocalNetworks(pair)));
        assert_eq!(check_against_local(&[pair], GATEWAY.into(), &local), Ok(()));
    }

    // Security rule: an unprivileged client names the gateway's address. It
    // must not be able to name this machine.
    #[test]
    fn refuses_a_gateway_that_is_one_of_the_machines_own_addresses() {
        for own in [[10, 0, 0, 7], [172, 17, 0, 1]] {
            let refused = LocalConflict::GatewayIsOwnAddress(own.into());
            assert_eq!(checked("192.0.2.0/24", own), Err(refused));
        }
    }
}
