//! Coverage of made-up hosts by made-up routes. The addresses are from the
//! ranges set aside for documentation and private use.

use super::*;

fn net(text: &str) -> Ipv4Net {
    text.parse().unwrap()
}

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

/// The saved routes: one private network, a narrower one inside it, and
/// one DNS domain.
fn saved() -> RouteSet {
    RouteSet {
        subnets: vec![net("10.255.0.0/16"), net("10.255.7.0/24")],
        dns_domains: vec!["ece.example.test".to_string()],
    }
}

fn tunnel(subnets: &[&str], domains: &[&str]) -> TunnelInfo {
    TunnelInfo {
        interface: "tun0".to_string(),
        address: "10.255.250.2".to_string(),
        subnets: subnets.iter().map(|s| net(s)).collect(),
        dns_domains: domains.iter().map(ToString::to_string).collect(),
        mode: crate::state::TunnelMode::Split,
    }
}

// The issue's case: a server outside every saved network is reported as
// not covered, and as not going through the tunnel while it is connected.
#[test]
fn a_host_outside_the_routes_is_not_covered() {
    let live = tunnel(&["10.255.0.0/16", "10.255.7.0/24"], &["ece.example.test"]);
    let report = check_host(
        "ssh.elsewhere.example",
        &[ip("192.0.2.25")],
        &saved(),
        Live::Connected(&live),
    );
    assert!(!report.covered);
    assert_eq!(report.tunnel, TunnelKnown::Connected);
    assert_eq!(report.saved_dns_domain, None);
    assert_eq!(report.tunnel_dns_domain, None);
    let only = &report.addresses[..];
    assert_eq!(
        only,
        [AddressCoverage {
            address: ip("192.0.2.25"),
            saved_network: None,
            tunnel_route: None,
        }]
    );
}

// Inside the routes, the most specific network is the one named, both
// saved and live.
#[test]
fn a_host_inside_the_routes_is_covered_by_the_most_specific_network() {
    let live = tunnel(&["10.255.0.0/16", "10.255.7.0/24"], &["ece.example.test"]);
    let report = check_host(
        "build.ece.example.test",
        &[ip("10.255.7.9"), ip("10.255.1.1")],
        &saved(),
        Live::Connected(&live),
    );
    assert!(report.covered);
    assert_eq!(report.saved_dns_domain.as_deref(), Some("ece.example.test"));
    assert_eq!(
        report.tunnel_dns_domain.as_deref(),
        Some("ece.example.test")
    );
    let networks: Vec<_> = report
        .addresses
        .iter()
        .map(|a| (a.saved_network, a.tunnel_route))
        .collect();
    assert_eq!(
        networks,
        [
            (Some(net("10.255.7.0/24")), Some(net("10.255.7.0/24"))),
            (Some(net("10.255.0.0/16")), Some(net("10.255.0.0/16"))),
        ]
    );
}

// One address outside is enough for the host not to be covered: traffic to
// it leaves over the usual network.
#[test]
fn a_host_with_one_address_outside_is_not_covered() {
    let report = check_host(
        "mixed.example.test",
        &[ip("10.255.7.9"), ip("198.51.100.4")],
        &saved(),
        Live::NotConnected,
    );
    assert!(!report.covered);
    assert_eq!(
        report.addresses[0].saved_network,
        Some(net("10.255.7.0/24"))
    );
    assert_eq!(report.addresses[1].saved_network, None);
}

// The routes are IPv4 only, so an IPv6 address is never covered.
#[test]
fn an_ipv6_address_is_never_covered() {
    let report = check_host(
        "six.example.test",
        &[ip("2001:db8::1")],
        &saved(),
        Live::NotConnected,
    );
    assert!(!report.covered);
    assert_eq!(report.addresses[0].saved_network, None);
}

// A name that resolved to nothing is not covered.
#[test]
fn no_addresses_is_not_covered() {
    let report = check_host("none.example.test", &[], &saved(), Live::Unknown);
    assert!(!report.covered);
    assert_eq!(report.tunnel, TunnelKnown::Unknown);
}

// Not connected, nothing goes through the tunnel, whatever is saved.
#[test]
fn not_connected_nothing_goes_through_the_tunnel() {
    let report = check_host(
        "build.ece.example.test",
        &[ip("10.255.7.9")],
        &saved(),
        Live::NotConnected,
    );
    assert!(report.covered);
    assert_eq!(report.tunnel, TunnelKnown::NotConnected);
    assert_eq!(report.addresses[0].tunnel_route, None);
    assert_eq!(report.tunnel_dns_domain, None);
}

// The live routes are what was applied at connect, which may differ from
// what is saved now: each is reported for what it is.
#[test]
fn the_saved_and_the_live_routes_are_told_apart() {
    let live = tunnel(&["10.254.0.0/16"], &[]);
    let report = check_host(
        "build.ece.example.test",
        &[ip("10.255.7.9"), ip("10.254.3.3")],
        &saved(),
        Live::Connected(&live),
    );
    let networks: Vec<_> = report
        .addresses
        .iter()
        .map(|a| (a.saved_network, a.tunnel_route))
        .collect();
    assert_eq!(
        networks,
        [
            (Some(net("10.255.7.0/24")), None),
            (None, Some(net("10.254.0.0/16"))),
        ]
    );
    assert!(!report.covered);
    assert_eq!(report.tunnel_dns_domain, None);
}

#[test]
fn a_name_is_under_a_domain_only_at_a_label_boundary() {
    let domains = vec!["example.test".to_string(), "ece.example.test".to_string()];
    assert_eq!(under_domain("example.test", &domains), Some("example.test"));
    assert_eq!(
        under_domain("A.ECE.Example.Test.", &domains),
        Some("ece.example.test")
    );
    assert_eq!(under_domain("notexample.test", &domains), None);
    assert_eq!(under_domain("example.test.evil", &domains), None);
    assert_eq!(under_domain("test", &domains), None);
}

#[test]
fn the_report_is_plain_json() {
    let report = check_host(
        "ssh.elsewhere.example",
        &[ip("192.0.2.25")],
        &saved(),
        Live::NotConnected,
    );
    let json = serde_json::to_string(&report).unwrap();
    assert_eq!(
        json,
        r#"{"host":"ssh.elsewhere.example","saved_dns_domain":null,"tunnel":"not_connected","tunnel_dns_domain":null,"addresses":[{"address":"192.0.2.25","saved_network":null,"tunnel_route":null}],"covered":false}"#
    );
}
