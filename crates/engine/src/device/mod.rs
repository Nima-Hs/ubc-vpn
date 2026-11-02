//! The tunnel device on macOS and Linux, which the engine opens itself.
//!
//! On Windows the library creates the Wintun device and removes it when the
//! main loop ends. On macOS and Linux it would create one too, but never
//! close it when no script is set (`os_shutdown_tun` in `tun.c` closes the
//! descriptor only when there is a script), so the device would outlive the
//! tunnel. So here the engine opens the device, hands the descriptor over
//! with `openconnect_setup_tun_fd`, and the handle closes it once the
//! library has freed the handle. Closing it removes the device.
//!
//! The device is opened with no script and changes nothing else: no
//! address, no route and no DNS. The service does all of that.

use std::os::fd::OwnedFd;

use crate::TunnelError;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux as os;
#[cfg(target_os = "linux")]
pub(crate) use linux::seal_vhost;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos as os;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("the engine opens a tunnel device on macOS and Linux only");

/// Opens a new tunnel device: its descriptor, and its name as the system
/// knows it, which is never empty. Needs the rights to create a device.
pub(crate) fn open() -> Result<(OwnedFd, String), TunnelError> {
    os::open()
}

/// Waits, for a bounded time, until the system no longer has the device
/// `name`, after its descriptor has been closed.
pub(crate) fn wait_until_gone(name: &str) {
    os::wait_until_gone(name);
}
