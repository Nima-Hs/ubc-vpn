//! The tunnel device on Linux: a `tun` device. Not written yet; PR X5
//! opens it. Until then a tunnel is refused at the device step.

use std::os::fd::OwnedFd;

use crate::TunnelError;

/// Not yet: PR X5 opens a `tun` device here.
pub(super) fn open() -> Result<(OwnedFd, String), TunnelError> {
    Err(TunnelError::Failed)
}

/// Nothing to wait for while no device is made. PR X5 decides whether a
/// closed `tun` device lingers.
pub(super) fn wait_until_gone(_name: &str) {}
