//! macOS: the channel is a Unix socket (see `unix`), and the folders are the
//! system's and the user's `Application Support`. Routes, DNS and network
//! events are not implemented yet and report that they are unsupported.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use rustix::io::{FdFlags, fcntl_setfd};
use rustix::net::{AddressFamily, SendFlags, SocketType, sockopt};

use crate::unix::{self, Env};
use crate::{Mode, Paths, Platform, Result};

const SUPPORT: &str = "Library/Application Support";
const SYSTEM: &str = "/Library/Application Support/UBC VPN";
/// Beside the policy, in a folder only root can change with no link on the
/// way to it. `/var/run` is not used: `/var` is a link, and the folder behind
/// it is writable by a group. The app must use this exact path.
const CHANNEL: &str = "/Library/Application Support/UBC VPN/service.sock";

/// The longest path a socket address holds here.
pub(crate) const LONGEST_PATH: usize = 103;

/// Clears the file's flags, of the file itself and not of what a link points
/// to.
///
/// On macOS a file's owner can mark it unchangeable (`chflags uchg`, or
/// `uappnd`), and then even root can neither remove it nor change its owner
/// or mode until the mark is cleared. Clearing it does not by itself stop
/// the owner, who can set it again at once: `unix::take_back` repeats this
/// call and a change of owner until the file is no longer theirs.
pub(crate) fn clear_flags(path: &Path) -> io::Result<()> {
    let path = CString::new(path.as_os_str().as_bytes())?;
    // SAFETY: `path` is a NUL-terminated string that outlives the call.
    match unsafe { libc::lchflags(path.as_ptr(), 0) } {
        0 => Ok(()),
        _ => Err(io::Error::last_os_error()),
    }
}

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

/// A new socket for a client to connect with, closed in any program this one
/// starts.
///
/// Security rule: a peer that went away is an error, not a signal that kills
/// the program. macOS has no flag for that on a send; it is a setting of the
/// socket (`SO_NOSIGPIPE`). It is set here because nothing else sets it on a
/// socket made here. An accepted socket takes it from its listener, which
/// the standard library made with it set; the test of this rule covers both.
pub(crate) fn socket() -> io::Result<OwnedFd> {
    let socket = rustix::net::socket(AddressFamily::UNIX, SocketType::STREAM, None)?;
    fcntl_setfd(&socket, FdFlags::CLOEXEC)?;
    sockopt::set_socket_nosigpipe(&socket, true)?;
    Ok(socket)
}

/// Sends what the socket has room for, without waiting. See [`socket`] for
/// how a peer that went away is kept from raising a signal.
pub(crate) fn send(stream: &UnixStream, bytes: &[u8]) -> rustix::io::Result<usize> {
    rustix::net::send(stream, bytes, SendFlags::DONTWAIT)
}
