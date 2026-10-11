//! Checks every implementation of the seam must pass.
//!
//! The fake passes them in this crate's tests. Each real implementation runs
//! the same functions on a CI machine with admin rights and a live tunnel
//! interface. They panic on the first property that does not hold.
//!
//! They use addresses reserved for documentation (192.0.2.0/24 and
//! 198.51.100.0/24), which no real network routes specially.

use std::net::Ipv4Addr;

use ubc_vpn_core::routes::Ipv4Net;

use crate::{Dns, Paths, Routes, SplitDns, Verified};

/// Checks [`Routes`] against the interface named `tunnel`, which must exist
/// and must not be the physical one. Leaves no route behind when it passes.
pub fn check_routes(routes: &dyn Routes, tunnel: &str) {
    let gateway = Ipv4Addr::new(192, 0, 2, 1);
    let inside = Ipv4Addr::new(192, 0, 2, 77);
    let outside = Ipv4Addr::new(198, 51, 100, 1);
    // The routed subnet contains the gateway, as UBC's does.
    let subnets = [Ipv4Net::new(Ipv4Addr::new(192, 0, 2, 0), 24).expect("valid network")];

    let physical = routes.capture_physical(gateway).expect("capture");
    assert_ne!(physical.interface(), tunnel, "captured the tunnel");
    let before = routes.uses_interface(inside, physical.interface());

    let remove_all = || {
        let removed = routes.remove_tunnel_routes(tunnel, &subnets);
        removed.expect("remove tunnel routes");
        let removed = routes.remove_gateway_route(gateway, &physical);
        removed.expect("remove gateway route");
    };
    remove_all(); // Nothing is applied yet, and removing must still succeed.

    let added = routes.add_gateway_route(gateway, &physical);
    added.expect("add gateway route");
    let added = routes.add_tunnel_routes(tunnel, &subnets);
    added.expect("add tunnel routes");
    let yes = Verified::Yes;
    assert_eq!(routes.uses_interface(inside, tunnel), yes, "inside");
    assert_eq!(routes.uses_interface(outside, tunnel), Verified::No);
    let to_gateway = routes.uses_interface(gateway, physical.interface());
    assert_eq!(to_gateway, yes, "the gateway route did not survive");
    assert_eq!(routes.uses_interface(gateway, tunnel), Verified::No);

    remove_all();
    remove_all(); // Removing twice is the same as removing once.
    assert_eq!(routes.uses_interface(inside, tunnel), Verified::No);
    let after = routes.uses_interface(inside, physical.interface());
    assert_eq!(after, before, "the previous state was not restored");
}

/// Checks [`Dns`] against the interface named `tunnel`, which must exist.
/// Leaves no split DNS behind when it passes.
pub fn check_dns(dns: &dyn Dns, tunnel: &str) {
    let wanted = SplitDns {
        resolvers: vec![Ipv4Addr::new(192, 0, 2, 53)],
        domains: vec!["suite.example".to_string()],
    };
    let other = SplitDns {
        domains: vec!["other.example".to_string()],
        ..wanted.clone()
    };

    dns.clear_split_dns().expect("clear when nothing is set");
    assert_eq!(dns.split_dns_matches(tunnel, &wanted), Verified::No);

    dns.set_split_dns(tunnel, &wanted).expect("set");
    assert_eq!(dns.split_dns_matches(tunnel, &wanted), Verified::Yes);
    assert_eq!(dns.split_dns_matches(tunnel, &other), Verified::No);

    dns.clear_split_dns().expect("clear");
    dns.clear_split_dns().expect("clear twice");
    assert_eq!(dns.split_dns_matches(tunnel, &wanted), Verified::No);
}

/// Checks that dev mode can never collide with the installed product: a
/// different channel name, and no dev folder at or under an installed one.
pub fn check_paths(installed: &Paths, dev: &Paths) {
    assert_ne!(installed.channel_name, dev.channel_name);
    let dirs = |p: &Paths| [&p.policy_dir, &p.state_dir, &p.settings_dir].map(Clone::clone);
    for dev_dir in dirs(dev) {
        for installed_dir in dirs(installed) {
            let inside = dev_dir.starts_with(&installed_dir);
            assert!(!inside, "{dev_dir:?} is inside {installed_dir:?}");
        }
    }
}
