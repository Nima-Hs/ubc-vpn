//! macOS: the channel is a Unix socket (see `unix`), and the folders are the
//! system's and the user's `Application Support`. Routes, DNS and network
//! events are not implemented yet and report that they are unsupported.

use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use rustix::net::SendFlags;

use crate::unix::{self, Env};
use crate::{Mode, Paths, Platform, Result};

const SUPPORT: &str = "Library/Application Support";
const SYSTEM: &str = "/Library/Application Support/UBC VPN";
/// Beside the policy, in a folder only root can change with no link on the
/// way to it. `/var/run` is not used: `/var` is a link, and the folder behind
/// it is writable by a group. The app must use this exact path.
const CHANNEL: &str = "/Library/Application Support/UBC VPN/service.sock";

/// Where a test running as root can make folders only root can change.
#[cfg(test)]
pub(crate) const ROOT_ONLY: &str = "/Library/Application Support";

pub(crate) fn native(mode: Mode) -> Result<Platform> {
    Ok(unix::native(mode, paths(mode, &unix::real_env)?))
}

/// Security rule: nothing the installed service uses comes from the
/// environment. Only the user's own settings folder does.
pub(crate) fn paths(mode: Mode, env: Env<'_>) -> Result<Paths> {
    let support = unix::home(env)?.join(SUPPORT);
    match mode {
        Mode::Installed => Ok(Paths {
            policy_dir: PathBuf::from(SYSTEM),
            state_dir: PathBuf::from(SYSTEM),
            settings_dir: support.join("UBC VPN"),
            channel_name: CHANNEL.to_string(),
        }),
        #[cfg(feature = "dev-mode")]
        // A sibling of the user's own settings folder, so never inside the
        // installed product's.
        Mode::Dev => Ok(unix::dev_paths(&support.join("UBC VPN Dev"), env, "TMPDIR")),
    }
}

/// The effective user ID of the process at the other end, as the kernel
/// recorded it when the connection was made.
pub(crate) fn peer_user(stream: &UnixStream) -> io::Result<u32> {
    // Never a real user, so a call that wrote nothing admits no one.
    let (mut user, mut group) = (u32::MAX, u32::MAX);
    // SAFETY: the descriptor is open for as long as `stream` is borrowed, and
    // both pointers are to live integers of the types the call writes.
    let status = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut user, &mut group) };
    match status {
        0 => Ok(user),
        _ => Err(io::Error::last_os_error()),
    }
}

/// Sends what the socket has room for, without waiting.
///
/// Security rule: a peer that went away is an error, not a signal that kills
/// the service. macOS has no flag for that on a send; it is a setting of the
/// socket (`SO_NOSIGPIPE`), which the standard library turns on for every
/// socket it creates and an accepted socket takes from its listener. Setting
/// it again here would be a line no test could miss, so the test of this rule
/// covers both a connected and an accepted socket instead.
pub(crate) fn send(stream: &UnixStream, bytes: &[u8]) -> rustix::io::Result<usize> {
    rustix::net::send(stream, bytes, SendFlags::DONTWAIT)
}
