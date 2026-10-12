//! What an OS module offers until its real implementation is written: every
//! operation fails with [`Error::Unsupported`], and every check answers
//! [`Verified::Unknown`].

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::mpsc::Receiver;

use ubc_vpn_core::routes::Ipv4Net;

use crate::{
    Connection, Dns, Error, Listener, Mode, NetworkEvent, NetworkEvents, Paths, PhysicalNetwork,
    Platform, Result, Routes, SplitDns, Transport, Verified,
};

pub(crate) struct Native;

#[cfg_attr(windows, allow(dead_code))]
/// The shape a real OS module fills in: it builds every part for `mode`, so
/// the transport and anything kept on disk know which mode they serve.
pub(crate) fn native(mode: Mode) -> Result<Platform> {
    Ok(Platform {
        routes: Arc::new(Native),
        dns: Arc::new(Native),
        events: Arc::new(Native),
        transport: Arc::new(Native),
        paths: paths(mode)?,
    })
}

#[cfg_attr(windows, allow(dead_code))]
fn paths(_mode: Mode) -> Result<Paths> {
    Err(Error::Unsupported)
}

impl Routes for Native {
    fn capture_physical(&self, _gateway: Ipv4Addr) -> Result<PhysicalNetwork> {
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
    fn subscribe(&self, _watching: &PhysicalNetwork) -> Result<Receiver<NetworkEvent>> {
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
