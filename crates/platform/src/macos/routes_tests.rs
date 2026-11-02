//! Tests of the routing table on macOS. Until it is written it must say so,
//! not pretend to succeed, and its check must fail closed. The boot the
//! route journal is kept for is real already.

use std::net::Ipv4Addr;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

// The route journal drops rows from another boot, so the boot must be read,
// stay the same while the machine runs, and agree with the clock.
#[test]
fn the_boot_is_read_from_the_kernel() {
    let first = super::routes::boot().expect("the boot");
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    assert!(first.started > 0 && first.uptime > 0, "{first:?}");
    // The time since start is counted from the start, not from some other
    // moment: the two add up to the clock, give or take the clock's drift.
    let gap = (first.started + first.uptime).abs_diff(now.as_secs());
    assert!(gap <= 60, "{first:?} at {now:?}");
    thread::sleep(Duration::from_millis(1100));
    let later = super::routes::boot().expect("the boot");
    assert!(later.uptime > first.uptime, "{first:?} then {later:?}");
    assert!(first.same_as(&later), "{first:?} then {later:?}");
}
