//! Whether a host's traffic goes through the tunnel: which saved network
//! covers each of its addresses, and which of the live tunnel's routes
//! carries it.
//!
//! The routes cover IPv4 networks only, so an IPv6 address is never
//! covered. Its traffic leaves over the usual network.
//!
//! The command-line client's `diagnostics --host` reports this, and the
//! app can use the same answer.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::routes::{Ipv4Net, RouteSet};
use crate::state::TunnelInfo;

/// What is known of the tunnel when a host is checked.
#[derive(Debug, Clone, Copy)]
pub enum Live<'a> {
    /// Connected, with these routes and DNS domains applied.
    Connected(&'a TunnelInfo),
    /// Not connected: nothing goes through the tunnel.
    NotConnected,
    /// The service could not say.
    Unknown,
}

/// The tunnel's state in a [`HostCoverage`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub enum TunnelKnown {
    /// Connected; each address says whether it goes through the tunnel.
    Connected,
    /// Not connected: nothing goes through the tunnel now.
    NotConnected,
    /// The service could not say whether it is connected.
    Unknown,
}

/// One address of a host, and what carries traffic to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct AddressCoverage {
    /// The address the name resolved to.
    #[cfg_attr(test, ts(type = "string"))]
    pub address: IpAddr,
    /// The most specific saved network that holds it, or `None` when no
    /// saved network does.
    #[cfg_attr(test, ts(type = "string | null"))]
    pub saved_network: Option<Ipv4Net>,
    /// The most specific route of the live tunnel that holds it. `None`
    /// when none does, or when not connected.
    #[cfg_attr(test, ts(type = "string | null"))]
    pub tunnel_route: Option<Ipv4Net>,
}

/// Whether a host's traffic goes through the tunnel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct HostCoverage {
    /// The host name, as it was checked.
    pub host: String,
    /// The most specific saved DNS domain the name is under, whose lookups
    /// go to the tunnel's DNS servers while connected.
    pub saved_dns_domain: Option<String>,
    /// Whether the tunnel is connected.
    pub tunnel: TunnelKnown,
    /// The most specific DNS domain of the live tunnel the name is under.
    /// `None` when it is under none, or when not connected.
    pub tunnel_dns_domain: Option<String>,
    /// Each address the name resolved to.
    pub addresses: Vec<AddressCoverage>,
    /// Whether the saved networks cover every address. False when there
    /// are none.
    pub covered: bool,
}

/// The most specific of `networks` that holds `address`. An IPv6 address
/// is held by none.
pub fn covering(networks: &[Ipv4Net], address: IpAddr) -> Option<Ipv4Net> {
    let IpAddr::V4(address) = address else {
        return None;
    };
    networks
        .iter()
        .filter(|net| net.contains_addr(address))
        .max_by_key(|net| net.prefix_len())
        .copied()
}

/// The most specific of `domains` that `host` is, or is under, compared
/// without regard to case or a final dot.
pub fn under_domain<'a>(host: &str, domains: &'a [String]) -> Option<&'a str> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    domains
        .iter()
        .filter(|domain| {
            let domain = domain.trim_matches('.').to_ascii_lowercase();
            !domain.is_empty() && (host == domain || host.ends_with(&format!(".{domain}")))
        })
        .max_by_key(|domain| domain.trim_matches('.').len())
        .map(String::as_str)
}

/// How `host`, which resolved to `addresses`, is covered by the `saved`
/// routes, and how the `live` tunnel carries it.
pub fn check_host(host: &str, addresses: &[IpAddr], saved: &RouteSet, live: Live) -> HostCoverage {
    let tunnel = match live {
        Live::Connected(info) => Some(info),
        Live::NotConnected | Live::Unknown => None,
    };
    let addresses: Vec<AddressCoverage> = addresses
        .iter()
        .map(|&address| AddressCoverage {
            address,
            saved_network: covering(&saved.subnets, address),
            tunnel_route: tunnel.and_then(|info| covering(&info.subnets, address)),
        })
        .collect();
    let covered = !addresses.is_empty() && addresses.iter().all(|a| a.saved_network.is_some());
    HostCoverage {
        host: host.to_string(),
        saved_dns_domain: under_domain(host, &saved.dns_domains).map(str::to_string),
        tunnel: match live {
            Live::Connected(_) => TunnelKnown::Connected,
            Live::NotConnected => TunnelKnown::NotConnected,
            Live::Unknown => TunnelKnown::Unknown,
        },
        tunnel_dns_domain: tunnel
            .and_then(|info| under_domain(host, &info.dns_domains))
            .map(str::to_string),
        addresses,
        covered,
    }
}

#[cfg(test)]
#[path = "coverage_tests.rs"]
mod tests;
