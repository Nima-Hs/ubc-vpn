//! The routing table on macOS, full mode's routes included. Not written yet:
//! every operation reports [`Error::Unsupported`] and every check answers
//! [`Verified::Unknown`]. The boot the route journal is kept for is here
//! already.

// Nothing uses the boot until routes are written; only its test does.
#![cfg_attr(not(test), allow(dead_code))]

use std::io;
use std::mem::size_of;
use std::ptr;

#[cfg(doc)]
use crate::Verified;
use crate::journal::Boot;
use crate::{Error, Result};

/// macOS routes, until they are written.
pub(super) use crate::unsupported::Native as MacRoutes;

/// The boot this process runs in.
///
/// The start time is the kernel's own (`kern.boottime`), which it moves with
/// the clock when the clock is set. The time since then is the monotonic
/// clock, which keeps counting while the machine sleeps, as Windows' does.
pub(super) fn boot() -> Result<Boot> {
    let mut started = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let mut size = size_of::<libc::timeval>();
    let mut name = [libc::CTL_KERN, libc::KERN_BOOTTIME];
    // SAFETY: `name` holds the two numbers named by the length passed, and
    // `started` and `size` are live and describe a buffer of `size` bytes
    // that the call fills. Nothing new is set.
    let status = unsafe {
        libc::sysctl(
            name.as_mut_ptr(),
            2,
            (&raw mut started).cast(),
            &mut size,
            ptr::null_mut(),
            0,
        )
    };
    if status != 0 {
        return Err(io::Error::last_os_error().into());
    }
    let started = u64::try_from(started.tv_sec)
        .ok()
        .filter(|_| size == size_of::<libc::timeval>());
    let started =
        started.ok_or_else(|| Error::Failed("the boot time cannot be read".to_string()))?;

    let mut since = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `since` is a live `timespec` for the call to fill.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut since) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    let uptime = u64::try_from(since.tv_sec)
        .map_err(|_| Error::Failed("the time since boot cannot be read".to_string()))?;
    Ok(Boot { started, uptime })
}
