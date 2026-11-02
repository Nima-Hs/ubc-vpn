//! Split DNS on Linux, in systemd-resolved, on the tunnel's link: its DNS
//! servers, the domains for routing only (`~domain`), and its default route,
//! LLMNR and multicast DNS off. resolved is asked through busctl (see
//! [`resolved`]). Full mode's catch-all is not written yet: those operations
//! report [`Error::Unsupported`] and their check answers
//! [`Verified::Unknown`].
//!
//! What is the product's is told by the link's name: the tunnel device's
//! name starts with [`TUN_PREFIX`], and only such links are ever changed.
//! Their settings in resolved go with the link, so a crash leaves nothing
//! once the device has gone, and start-up takes back anything still there.

#[path = "resolved.rs"]
pub(super) mod resolved;

use std::net::Ipv4Addr;

use super::routes::netlink::{self, Link};
use crate::unsupported::Native;
use crate::{Dns, Error, Result, SplitDns, Verified};

/// How the name of every tunnel device of the product's starts.
pub(super) const TUN_PREFIX: &str = "ubcvpn";

/// What the kernel makes a tunnel device as.
const TUN: &str = "tun";

/// Linux DNS: [`Resolved`] for the product's tunnel devices.
pub(super) struct LinuxDns;

const PRODUCT: Resolved = Resolved::new(TUN_PREFIX);

/// Split DNS in resolved, on links whose names start with `prefix`. Tests
/// give their own devices' prefix, so they never touch the product's.
pub(super) struct Resolved {
    prefix: &'static str,
}

impl Resolved {
    pub(super) const fn new(prefix: &'static str) -> Self {
        Self { prefix }
    }

    /// The links whose names mark them as ours.
    fn ours(&self) -> Result<Vec<Link>> {
        let links = netlink::links().map_err(|error| Error::Failed(error.to_string()))?;
        let ours = links
            .into_iter()
            .filter(|link| link.name.starts_with(self.prefix));
        Ok(ours.collect())
    }
}

/// The setting checked before anything is asked: resolvers and domains
/// there are, not too many, and each one valid.
fn check(dns: &SplitDns) -> Result<()> {
    let domains_ok = !dns.domains.is_empty()
        && dns.domains.len() <= resolved::MOST_DOMAINS
        && dns
            .domains
            .iter()
            .all(|name| resolved::is_valid_domain(name));
    let resolvers_ok = !dns.resolvers.is_empty()
        && dns
            .resolvers
            .iter()
            .all(|r| resolved::is_valid_resolver(*r));
    match domains_ok && resolvers_ok {
        true => Ok(()),
        false => Err(Error::InvalidInput),
    }
}

impl Dns for Resolved {
    fn set_split_dns(&self, tunnel: &str, dns: &SplitDns) -> Result<()> {
        check(dns)?;
        // Security rule: a link not named as ours is never changed, so that
        // clearing, which goes by the name, always finds what was set.
        if !tunnel.starts_with(self.prefix) {
            return Err(Error::InvalidInput);
        }
        let ours = self.ours()?;
        let device = ours
            .iter()
            .find(|link| link.name == tunnel)
            .ok_or(Error::NotFound)?;
        if device.kind.as_deref() != Some(TUN) {
            let kind = device.kind.as_deref().unwrap_or("none given");
            let message = format!("{tunnel} is not a tunnel device (kind {kind})");
            return Err(Error::Failed(message));
        }
        if !resolved::usable()? {
            return Err(Error::Unsupported);
        }
        // There is one tunnel: what an earlier one was given goes.
        for other in ours.iter().filter(|link| link.index != device.index) {
            revert(other)?;
        }
        resolved::set_link(device.index, &dns.resolvers, &dns.domains).inspect_err(|_| {
            // Never left half set.
            let _ = resolved::revert_link(device.index);
        })
    }

    fn clear_split_dns(&self) -> Result<()> {
        let ours = self.ours()?;
        // Nothing of ours can be in effect where resolved is not running.
        if ours.is_empty() || !resolved::running()? {
            return Ok(());
        }
        let mut failed = None;
        for link in &ours {
            if let Err(error) = revert(link) {
                failed = Some(error);
            }
        }
        failed.map_or(Ok(()), Err)
    }

    fn split_dns_matches(&self, dns: &SplitDns) -> Verified {
        let Ok(ours) = self.ours() else {
            return Verified::Unknown;
        };
        if ours.is_empty() {
            return Verified::No;
        }
        match resolved::usable() {
            Ok(true) => {}
            Ok(false) => return Verified::No,
            Err(_) => return Verified::Unknown,
        }
        let mut set = Vec::new();
        for link in &ours {
            match resolved::link_state(link.index) {
                Ok(state) if state.has_dns() => set.push(state),
                Ok(_) => {}
                Err(_) => return Verified::Unknown,
            }
        }
        match set.as_slice() {
            [only] if only.is_exactly(&dns.resolvers, &dns.domains) => Verified::Yes,
            _ => Verified::No,
        }
    }

    fn set_catch_all_dns(&self, resolvers: &[Ipv4Addr]) -> Result<()> {
        Native.set_catch_all_dns(resolvers)
    }

    fn clear_catch_all_dns(&self) -> Result<()> {
        Native.clear_catch_all_dns()
    }

    fn catch_all_dns_matches(&self, resolvers: &[Ipv4Addr]) -> Verified {
        Native.catch_all_dns_matches(resolvers)
    }

    fn foreign_catch_all(&self) -> Result<bool> {
        Native.foreign_catch_all()
    }
}

/// Takes back what resolved holds for `link`. A link that went in the
/// meantime has nothing left to take back.
fn revert(link: &Link) -> Result<()> {
    match resolved::revert_link(link.index) {
        Ok(()) => Ok(()),
        Err(error) => {
            let still_there = netlink::links()
                .map(|links| links.iter().any(|l| l.index == link.index))
                .unwrap_or(true);
            match still_there {
                true => Err(error),
                false => Ok(()),
            }
        }
    }
}

impl Dns for LinuxDns {
    fn set_split_dns(&self, tunnel: &str, dns: &SplitDns) -> Result<()> {
        PRODUCT.set_split_dns(tunnel, dns)
    }

    fn clear_split_dns(&self) -> Result<()> {
        PRODUCT.clear_split_dns()
    }

    fn split_dns_matches(&self, dns: &SplitDns) -> Verified {
        PRODUCT.split_dns_matches(dns)
    }

    fn set_catch_all_dns(&self, resolvers: &[Ipv4Addr]) -> Result<()> {
        PRODUCT.set_catch_all_dns(resolvers)
    }

    fn clear_catch_all_dns(&self) -> Result<()> {
        PRODUCT.clear_catch_all_dns()
    }

    fn catch_all_dns_matches(&self, resolvers: &[Ipv4Addr]) -> Verified {
        PRODUCT.catch_all_dns_matches(resolvers)
    }

    fn foreign_catch_all(&self) -> Result<bool> {
        PRODUCT.foreign_catch_all()
    }
}
