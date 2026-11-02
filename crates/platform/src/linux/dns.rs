//! Split DNS and full mode's catch-all DNS on Linux. Not written yet: every
//! operation reports [`Error::Unsupported`] and every check answers
//! [`Verified::Unknown`].

#[cfg(doc)]
use crate::{Error, Verified};

/// Linux DNS, until it is written.
pub(super) use crate::unsupported::Native as LinuxDns;
