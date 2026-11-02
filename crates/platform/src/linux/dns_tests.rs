//! Tests of split DNS on Linux. Until it is written it must say so, not
//! pretend to succeed, and its check must fail closed.

use std::net::Ipv4Addr;

use crate::{Error, Mode, Platform, SplitDns, Verified};

#[test]
fn split_dns_is_not_implemented_yet() {
    let unsupported = Some(Error::Unsupported);
    let split = SplitDns {
        resolvers: vec![Ipv4Addr::new(192, 0, 2, 1)],
        domains: vec!["dept.example".to_string()],
    };
    let modes = [
        Mode::Installed,
        #[cfg(feature = "dev-mode")]
        Mode::Dev,
    ];
    for mode in modes {
        let dns = Platform::native(mode).expect("a platform").dns;
        assert_eq!(dns.set_split_dns("tun0", &split).err(), unsupported);
        assert_eq!(dns.clear_split_dns().err(), unsupported);
        assert_eq!(dns.split_dns_matches(&split), Verified::Unknown);
    }
}
