//! Tests of the routing table on Linux. Until it is written it must say so,
//! not pretend to succeed, and its check must fail closed.

use std::net::Ipv4Addr;

use crate::{Error, Mode, PhysicalNetwork, Platform, Verified};

#[test]
fn routes_are_not_implemented_yet() {
    let unsupported = Some(Error::Unsupported);
    let gateway = Ipv4Addr::new(192, 0, 2, 1);
    let physical = PhysicalNetwork {
        interface: "eth0".to_string(),
        next_hop: None,
        own_addresses: Vec::new(),
        on_link: Vec::new(),
    };
    let subnets = ["192.0.2.0/24".parse().unwrap()];
    let modes = [
        Mode::Installed,
        #[cfg(feature = "dev-mode")]
        Mode::Dev,
    ];
    for mode in modes {
        let routes = Platform::native(mode).expect("a platform").routes;
        assert_eq!(routes.capture_physical(gateway).err(), unsupported);
        let results = [
            routes.configure_tunnel("tun0", gateway, 1300),
            routes.add_gateway_route(gateway, &physical),
            routes.remove_gateway_route(gateway, &physical),
            routes.add_tunnel_routes("tun0", &subnets),
            routes.remove_tunnel_routes("tun0", &subnets),
            routes.remove_all(),
        ];
        assert_eq!(results, [const { Err(Error::Unsupported) }; 6]);
        assert_eq!(routes.uses_interface(gateway, "tun0"), Verified::Unknown);
    }
}
