//! The fake's DNS: the split DNS and the catch-all its calls leave in
//! effect.

use std::net::Ipv4Addr;

use super::{Fake, Op};
use crate::{Dns, Error, Result, SplitDns, Verified};

impl Dns for Fake {
    fn set_split_dns(&self, tunnel: &str, dns: &SplitDns) -> Result<()> {
        self.run(Op::SetSplitDns, |applied| {
            applied.split_dns = Some((tunnel.to_string(), dns.clone()));
        })
    }

    /// Removes the catch-all too, as the contract says.
    fn clear_split_dns(&self) -> Result<()> {
        self.run(Op::ClearSplitDns, |applied| {
            applied.split_dns = None;
            applied.catch_all_dns = None;
        })
    }

    fn split_dns_matches(&self, dns: &SplitDns) -> Verified {
        let (state, outcome) = self.start(Op::VerifyDns);
        if outcome.is_err() {
            return Verified::Unknown;
        }
        match &state.applied.split_dns {
            Some((_, set)) if set == dns => state.confirmed(Op::VerifyDns),
            _ => Verified::No,
        }
    }

    /// Told to fail, it sets the catch-all first, as an OS that failed after
    /// writing the rule would.
    fn set_catch_all_dns(&self, resolvers: &[Ipv4Addr]) -> Result<()> {
        let (mut state, outcome) = self.start(Op::SetCatchAllDns);
        if state.foreign_catch_all {
            return outcome.and(Err(Error::AlreadyExists));
        }
        if resolvers.is_empty() {
            return outcome.and(Err(Error::InvalidInput));
        }
        state.applied.catch_all_dns = Some(resolvers.to_vec());
        outcome
    }

    fn clear_catch_all_dns(&self) -> Result<()> {
        self.run(Op::ClearCatchAllDns, |applied| applied.catch_all_dns = None)
    }

    fn catch_all_dns_matches(&self, resolvers: &[Ipv4Addr]) -> Verified {
        let (state, outcome) = self.start(Op::VerifyCatchAllDns);
        if outcome.is_err() {
            return Verified::Unknown;
        }
        match &state.applied.catch_all_dns {
            Some(set) if set == resolvers && !state.foreign_catch_all => {
                state.confirmed(Op::VerifyCatchAllDns)
            }
            _ => Verified::No,
        }
    }

    fn foreign_catch_all(&self) -> Result<bool> {
        let (state, outcome) = self.start(Op::ForeignCatchAll);
        outcome?;
        Ok(state.foreign_catch_all)
    }
}
