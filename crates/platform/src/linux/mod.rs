//! Linux: the channel is a Unix socket (see `unix`), and the folders follow
//! the usual system places and the XDG rules. Routes, DNS and network events
//! are not implemented yet and report that they are unsupported.

use std::io;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use rustix::net::{SendFlags, sockopt};

use crate::unix::{self, Env};
use crate::{Mode, Paths, Platform, Result};

const POLICY: &str = "/etc/ubc-vpn";
const STATE: &str = "/var/lib/ubc-vpn";
/// `/run` is root's, is emptied at boot, and holds no links on the way. The
/// app must use this exact path.
const CHANNEL: &str = "/run/ubc-vpn/service.sock";

/// Where a test running as root can make folders only root can change.
#[cfg(test)]
pub(crate) const ROOT_ONLY: &str = "/run";

pub(crate) fn native(mode: Mode) -> Result<Platform> {
    Ok(unix::native(mode, paths(mode, &unix::real_env)?))
}

/// Security rule: nothing the installed service uses comes from the
/// environment. Only the user's own settings folder does.
pub(crate) fn paths(mode: Mode, env: Env<'_>) -> Result<Paths> {
    // The XDG rules say to ignore a relative value.
    let config = match env("XDG_CONFIG_HOME").map(PathBuf::from) {
        Some(config) if config.is_absolute() => config,
        _ => unix::home(env)?.join(".config"),
    };
    match mode {
        Mode::Installed => Ok(Paths {
            policy_dir: PathBuf::from(POLICY),
            state_dir: PathBuf::from(STATE),
            settings_dir: config.join("ubc-vpn"),
            channel_name: CHANNEL.to_string(),
        }),
        #[cfg(feature = "dev-mode")]
        Mode::Dev => Ok(Paths {
            channel_name: unix::dev_channel(env, "XDG_RUNTIME_DIR"),
            ..unix::dev_folders(&config.join("ubc-vpn-dev"), &[POLICY, STATE])?
        }),
    }
}

/// The effective user ID of the process at the other end, as the kernel
/// recorded it when the connection was made (`SO_PEERCRED`).
pub(crate) fn peer_user(stream: &UnixStream) -> io::Result<u32> {
    Ok(sockopt::socket_peercred(stream)?.uid.as_raw())
}

/// Linux asks for no `SIGPIPE` on each send instead of once per socket.
pub(crate) fn no_sigpipe(_stream: &UnixStream) -> io::Result<()> {
    Ok(())
}

/// Security rule: a peer that went away is an error, not a signal that kills
/// the service.
pub(crate) fn send(stream: &UnixStream, bytes: &[u8]) -> rustix::io::Result<usize> {
    rustix::net::send(stream, bytes, SendFlags::NOSIGNAL)
}
