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
}
