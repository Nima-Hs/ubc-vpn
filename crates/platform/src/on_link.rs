//! Which of the machine's addresses put it on a network, for
//! [`PhysicalNetwork::on_link`](crate::PhysicalNetwork::on_link).
//!
//! An OS lists addresses it does not use. Windows gives an adapter that is
//! not connected, such as unplugged Ethernet, Bluetooth or an idle VPN
//! adapter, a tentative `169.254.x.x/16` address with no route. Counted as
//! a network the machine is on, that network would have to stay off the
//! tunnel in full mode, though nothing routes it anywhere but the halves.
//! So only a usable address counts: one the OS has finished checking for
//! duplicates and still uses, on an interface that is up. Its network has
//! an on-link route, more specific than the halves, wherever it lies, a
//! usable `169.254.x.x` address on a cable with no DHCP among them.
//!
//! The rule is here, apart from the OS's tables, so that it is tested on
//! every system.

// Only Windows reads every state from its tables; elsewhere only the fake
// and the tests use this.
#![cfg_attr(not(windows), allow(dead_code))]

use std::net::Ipv4Addr;

use ubc_vpn_core::routes::Ipv4Net;

/// Where an address is in the OS's check that no other machine on the link
/// has it (duplicate address detection), as Windows reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DadState {
    /// Not valid; or a state this code does not know.
    Invalid,
    /// Still being checked, or on an interface that is not connected, so
    /// not used yet.
    Tentative,
    /// Another machine on the link has it, so it is not used.
    Duplicate,
    /// Past its preferred lifetime but still valid: the OS keeps it, and
    /// its on-link route, for the connections that use it.
    Deprecated,
    /// Checked and in use.
    Preferred,
}

/// One IPv4 address the OS lists, with what decides whether it is used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AddressRow {
    pub(crate) addr: Ipv4Addr,
    /// The length of the prefix of the network the address is on.
    pub(crate) prefix_len: u8,
    pub(crate) state: DadState,
    /// Whether the address's interface is up.
    pub(crate) interface_up: bool,
}

impl AddressRow {
    /// Whether the address is in use, and so its network is one the machine
    /// is on. A deprecated address counts: it is still valid, and the OS
    /// keeps its on-link route, so leaving it out would let a route or the
    /// halves take a network that is still on the link into the tunnel.
    fn usable(&self) -> bool {
        let state = matches!(self.state, DadState::Preferred | DadState::Deprecated);
        state && self.interface_up
    }

    /// The network the address is on: the address with its prefix and the
    /// host bits cleared. A prefix longer than 32 is taken as 32.
    fn network(&self) -> Option<Ipv4Net> {
        let len = self.prefix_len.min(32);
        let mask = u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0);
        Ipv4Net::new(Ipv4Addr::from(u32::from(self.addr) & mask), len).ok()
    }
}

/// The networks of the usable addresses among `rows`, in their order.
pub(crate) fn usable_networks(rows: impl IntoIterator<Item = AddressRow>) -> Vec<Ipv4Net> {
    rows.into_iter()
        .filter(AddressRow::usable)
        .filter_map(|row| row.network())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(addr: [u8; 4], prefix_len: u8, state: DadState, interface_up: bool) -> AddressRow {
        AddressRow {
            addr: Ipv4Addr::from(addr),
            prefix_len,
            state,
            interface_up,
        }
    }

    fn net(text: &str) -> Ipv4Net {
        text.parse().unwrap()
    }

    // The bug: a disconnected adapter's tentative link-local address, with
    // no route, was counted as a network the machine is on. Only the home
    // network's, preferred and up, counts.
    #[test]
    fn a_disconnected_adapters_tentative_link_local_address_is_not_a_network() {
        let rows = [
            row([169, 254, 10, 20], 16, DadState::Tentative, false),
            row([10, 200, 0, 10], 24, DadState::Preferred, true),
        ];
        assert_eq!(usable_networks(rows), [net("10.200.0.0/24")]);
    }

    // Security rule: an address counts only when it is usable, preferred or
    // deprecated, and its interface is up. Each other state, and a down
    // interface whatever the state, leaves it out.
    #[test]
    fn only_a_usable_address_on_an_up_interface_counts() {
        use DadState::*;
        let one = |state, up| usable_networks([row([169, 254, 1, 2], 16, state, up)]);
        let link_local = vec![net("169.254.0.0/16")];
        assert_eq!(one(Preferred, true), link_local, "a cable with no DHCP");
        assert_eq!(one(Deprecated, true), link_local);
        for state in [Tentative, Duplicate, Invalid] {
            assert_eq!(one(state, true), [], "{state:?} on an up interface");
        }
        for state in [Preferred, Deprecated, Tentative, Duplicate, Invalid] {
            assert_eq!(one(state, false), [], "{state:?} on a down interface");
        }
    }

    // A machine with several adapters: the order is kept, the host bits are
    // cleared, and a prefix longer than 32 is a host.
    #[test]
    fn each_usable_address_gives_its_network() {
        let rows = [
            row([10, 200, 0, 10], 24, DadState::Preferred, true),
            row([172, 31, 130, 1], 24, DadState::Duplicate, true),
            row([172, 31, 140, 1], 24, DadState::Preferred, true),
            row([169, 254, 7, 7], 16, DadState::Tentative, true),
            row([198, 51, 100, 9], 40, DadState::Preferred, true),
        ];
        let expected = [
            net("10.200.0.0/24"),
            net("172.31.140.0/24"),
            net("198.51.100.9/32"),
        ];
        assert_eq!(usable_networks(rows), expected);
    }
}
