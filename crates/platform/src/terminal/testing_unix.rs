//! The Linux and macOS half of `terminal::testing`: a pseudo-terminal.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::fs::OFlags;
use rustix::io::Errno;
use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
use rustix::termios::{LocalModes, tcgetattr};

use crate::Result;

pub(super) struct Screen {
    /// The keyboard and the screen.
    ours: File,
    /// The child's end, kept so that the terminal's mode can be asked for
    /// and the terminal outlives a child that closes its own.
    theirs: File,
    shown: Vec<u8>,
}

pub(super) fn spawn(command: &mut Command) -> Result<(Child, Screen)> {
    // Neither end becomes this process's own terminal.
    let ours = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).map_err(io::Error::from)?;
    grantpt(&ours).map_err(io::Error::from)?;
    unlockpt(&ours).map_err(io::Error::from)?;
    let name = ptsname(&ours, Vec::new()).map_err(io::Error::from)?;
    let name = name
        .into_string()
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    let mut theirs = OpenOptions::new();
    theirs.read(true).write(true);
    theirs.custom_flags(OFlags::NOCTTY.bits() as i32);
    let theirs = theirs.open(name)?;

    command.stdin(theirs.try_clone()?);
    command.stdout(theirs.try_clone()?);
    command.stderr(theirs.try_clone()?);
    // SAFETY: the closure runs in the child between fork and exec, where
    // only calls that are safe in a signal handler may be made: it makes
    // two such calls, takes no lock and does not allocate. Standard input
    // is already the terminal by then.
    unsafe { command.pre_exec(own_terminal) };
    let child = command.spawn()?;
    let screen = Screen {
        ours: File::from(ours),
        theirs,
        shown: Vec::new(),
    };
    Ok((child, screen))
}

/// Makes the calling process the first of a new session, with the terminal
/// that is its standard input as that session's terminal: what a terminal
/// program does for the shell it starts.
fn own_terminal() -> io::Result<()> {
    // SAFETY: both calls have no memory-safety conditions. The last
    // argument of the second is a plain number, "do not take the terminal
    // from another session".
    let done = unsafe { libc::setsid() >= 0 && libc::ioctl(0, libc::TIOCSCTTY as _, 0) >= 0 };
    match done {
        true => Ok(()),
        false => Err(io::Error::last_os_error()),
    }
}

impl Screen {
    pub(super) fn wait_for(&mut self, text: &str, within: Duration) -> Result<String> {
        let deadline = Instant::now() + within;
        let found = |shown: &[u8]| String::from_utf8_lossy(shown).contains(text);
        while !found(&self.shown) {
            let left = deadline.saturating_duration_since(Instant::now());
            let left = Timespec::try_from(left)
                .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
            let mut ready = [PollFd::new(&self.ours, PollFlags::IN)];
            match poll(&mut ready, Some(&left)) {
                Ok(0) => break,
                Ok(_) => {}
                Err(Errno::INTR) => continue,
                Err(error) => return Err(io::Error::from(error).into()),
            }
            let mut some = [0; 1024];
            match self.ours.read(&mut some) {
                // The terminal is gone: nothing more will be shown.
                Ok(0) | Err(_) => break,
                Ok(read) => self.shown.extend_from_slice(&some[..read]),
            }
        }
        Ok(String::from_utf8_lossy(&self.shown).into_owned())
    }

    pub(super) fn type_text(&mut self, text: &str) -> Result<()> {
        Ok(self.ours.write_all(text.as_bytes())?)
    }

    pub(super) fn echoes(&self) -> Result<bool> {
        let mode = tcgetattr(&self.theirs).map_err(io::Error::from)?;
        Ok(mode.local_modes.contains(LocalModes::ECHO))
    }
}
