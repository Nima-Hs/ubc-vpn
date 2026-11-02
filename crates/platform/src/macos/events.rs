//! Network change notifications on macOS. Not written yet: subscribing
//! reports [`Error::Unsupported`], and IPv6 changes are not reported, so full
//! mode is refused.

#[cfg(doc)]
use crate::Error;

/// macOS network events, until they are written.
pub(super) use crate::unsupported::Native as MacEvents;
