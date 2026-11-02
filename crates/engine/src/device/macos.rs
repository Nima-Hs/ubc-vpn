//! The tunnel device on macOS: a `utun` device. Not written yet; PR M5
//! opens it. Until then a tunnel is refused at the device step.

use std::os::fd::OwnedFd;

use crate::TunnelError;

/// Not yet: PR M5 opens a `utun` device here.
pub(super) fn open() -> Result<(OwnedFd, String), TunnelError> {
    Err(TunnelError::Failed)
}

/// Nothing to wait for while no device is made. PR M5 decides whether a
/// closed `utun` device lingers.
pub(super) fn wait_until_gone(_name: &str) {}
