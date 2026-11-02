//! Split DNS and full mode's catch-all DNS on macOS. Not written yet: every
//! operation reports [`Error::Unsupported`] and every check answers
//! [`Verified::Unknown`].

#[cfg(doc)]
use crate::{Error, Verified};

/// macOS DNS, until it is written.
pub(super) use crate::unsupported::Native as MacDns;
