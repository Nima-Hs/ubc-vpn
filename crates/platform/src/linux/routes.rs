//! The routing table on Linux, full mode's routes included. Not written yet:
//! every operation reports [`Error::Unsupported`] and every check answers
//! [`Verified::Unknown`].

#[cfg(doc)]
use crate::{Error, Verified};

/// Linux routes, until they are written.
pub(super) use crate::unsupported::Native as LinuxRoutes;
