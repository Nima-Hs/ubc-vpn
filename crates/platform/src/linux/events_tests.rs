//! Tests of network change notifications on Linux. Until they are written
//! they must say so, and full mode must stay refused.

use crate::{Error, Mode, PhysicalNetwork, Platform};

#[test]
fn events_are_not_implemented_yet() {
    let physical = PhysicalNetwork {
        interface: "eth0".to_string(),
        next_hop: None,
        own_addresses: Vec::new(),
        on_link: Vec::new(),
    };
    let modes = [
        Mode::Installed,
        #[cfg(feature = "dev-mode")]
        Mode::Dev,
    ];
    for mode in modes {
        let events = Platform::native(mode).expect("a platform").events;
        let subscribed = events.subscribe(&physical);
        assert_eq!(subscribed.err(), Some(Error::Unsupported));
        // Full mode is refused where IPv6 changes cannot be watched.
        assert!(!events.reports_ipv6_changes());
    }
}
