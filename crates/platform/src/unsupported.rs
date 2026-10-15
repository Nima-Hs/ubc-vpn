//! What an OS module offers for the parts whose real implementation is not
//! written yet: every operation fails with [`Error::Unsupported`], and every
//! check answers [`Verified::Unknown`].

use std::net::Ipv4Addr;

use ubc_vpn_core::routes::Ipv4Net;

use crate::{
    Connection, Dns, Error, Listener, NetworkEvents, PhysicalNetwork, Result, Routes, SplitDns,
    Subscription, Transport, Verified,
};

// Windows implements every part now; only this crate's own tests use the
// stub there.
#[cfg_attr(all(windows, not(test)), allow(dead_code))]
pub(crate) struct Native;

impl Routes for Native {
    fn capture_physical(&self, _gateway: Ipv4Addr) -> Result<PhysicalNetwork> {
        Err(Error::Unsupported)
    }
    fn configure_tunnel(&self, _tunnel: &str, _address: Ipv4Addr, _mtu: u16) -> Result<()> {
        Err(Error::Unsupported)
    }
    fn add_gateway_route(&self, _gateway: Ipv4Addr, _via: &PhysicalNetwork) -> Result<()> {
        Err(Error::Unsupported)
    }
    fn remove_gateway_route(&self, _gateway: Ipv4Addr, _via: &PhysicalNetwork) -> Result<()> {
        Err(Error::Unsupported)
    }
    fn add_tunnel_routes(&self, _tunnel: &str, _subnets: &[Ipv4Net]) -> Result<()> {
        Err(Error::Unsupported)
    }
    fn remove_tunnel_routes(&self, _tunnel: &str, _subnets: &[Ipv4Net]) -> Result<()> {
        Err(Error::Unsupported)
    }
    fn remove_all(&self) -> Result<()> {
        Err(Error::Unsupported)
    }
    fn uses_interface(&self, _dest: Ipv4Addr, _interface: &str) -> Verified {
        Verified::Unknown
    }
}

impl Dns for Native {
    fn set_split_dns(&self, _tunnel: &str, _dns: &SplitDns) -> Result<()> {
        Err(Error::Unsupported)
    }
    fn clear_split_dns(&self) -> Result<()> {
        Err(Error::Unsupported)
    }
    fn split_dns_matches(&self, _dns: &SplitDns) -> Verified {
        Verified::Unknown
    }
}

impl NetworkEvents for Native {
    fn subscribe(&self, _watching: &PhysicalNetwork) -> Result<Subscription> {
        Err(Error::Unsupported)
    }
}

impl Transport for Native {
    fn listen(&self, _name: &str) -> Result<Box<dyn Listener>> {
        Err(Error::Unsupported)
    }
    fn connect(&self, _name: &str) -> Result<Connection> {
        Err(Error::Unsupported)
    }
}
