//! Tests of full mode on Linux: its routes and its catch-all DNS. Until they
//! are written they must say so, not pretend to succeed, and their checks
//! must fail closed.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::{Error, Mode, Platform, Verified};

#[test]
fn full_mode_is_not_implemented_yet() {
    let unsupported = Some(Error::Unsupported);
    let resolver = Ipv4Addr::new(192, 0, 2, 1);
    let v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let modes = [
        Mode::Installed,
        #[cfg(feature = "dev-mode")]
        Mode::Dev,
    ];
    for mode in modes {
        let native = Platform::native(mode).expect("a platform");
        let (routes, dns) = (native.routes, native.dns);
        assert_eq!(routes.add_full_tunnel("tun0").err(), unsupported);
        assert_eq!(routes.full_tunnel_ipv6("tun0").err(), unsupported);
        assert_eq!(routes.remove_full_tunnel("tun0").err(), unsupported);
        assert_eq!(routes.foreign_full_tunnel("tun0").err(), unsupported);
        assert_eq!(routes.uses_interface_v6(v6, "tun0"), Verified::Unknown);
        assert_eq!(dns.set_catch_all_dns(&[resolver]).err(), unsupported);
        assert_eq!(dns.clear_catch_all_dns().err(), unsupported);
        assert_eq!(dns.foreign_catch_all().err(), unsupported);
        let matches = dns.catch_all_dns_matches(&[resolver]);
        assert_eq!(matches, Verified::Unknown);
    }
}
