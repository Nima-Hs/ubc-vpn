//! The Linux and macOS half of `terminal::testing`: a pseudo-terminal.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

use rustix::fs::OFlags;
use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
use rustix::termios::{LocalModes, tcgetattr};

use crate::{Result, lock};

/// What the child has written, and whether more can come.
#[derive(Default)]
struct Shown {
    bytes: Vec<u8>,
    ended: bool,
}

pub(super) struct Screen {
    /// The keyboard, and where the terminal's mode is asked for.
    ours: File,
    shown: Arc<(Mutex<Shown>, Condvar)>,
}

pub(super) fn spawn(command: &mut Command) -> Result<(Child, Screen)> {
    // Neither end becomes this process's own terminal.
    let ours = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).map_err(io::Error::from)?;
    grantpt(&ours).map_err(io::Error::from)?;
    unlockpt(&ours).map_err(io::Error::from)?;
    let name = ptsname(&ours, Vec::new()).map_err(io::Error::from)?;
    let name = name.into_string();
    let name = name.map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    let mut theirs = OpenOptions::new();
    theirs.read(true).write(true);
    theirs.custom_flags(OFlags::NOCTTY.bits() as i32);
    let theirs = theirs.open(name)?;
    let ours = File::from(ours);

    command.stdin(theirs.try_clone()?);
    command.stdout(theirs.try_clone()?);
    command.stderr(theirs.try_clone()?);
    // SAFETY: the closure runs in the child between fork and exec, where
    // only calls that are safe in a signal handler may be made: it makes
    // two such calls, takes no lock and does not allocate. Standard input
    // is already the terminal by then.
    unsafe { command.pre_exec(own_terminal) };
    let child = command.spawn();
    // From here on only the child holds its end, so that the terminal goes
    // when the child does and the screen is seen to end.
    command.stdin(Stdio::null());
    command.stdout(Stdio::null());
    command.stderr(Stdio::null());
    drop(theirs);
    let child = child?;

    // The screen is read all the time, not only when the test looks. A
    // terminal holds little, and a program whose output nobody takes waits,
    // on macOS even to end.
    let shown = Arc::new((Mutex::new(Shown::default()), Condvar::new()));
    let (mut screen, written) = (ours.try_clone()?, shown.clone());
    thread::Builder::new().spawn(move || {
        let mut some = [0; 1024];
        loop {
            let read = screen.read(&mut some);
            let mut shown = lock(&written.0);
            match read {
                Ok(read) if read > 0 => shown.bytes.extend_from_slice(&some[..read]),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                // The terminal is gone: nothing more will be shown.
                _ => shown.ended = true,
            }
            written.1.notify_all();
            if shown.ended {
                return;
            }
        }
    })?;
    Ok((child, Screen { ours, shown }))
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
        let (shown, more) = &*self.shown;
        let waiting = |shown: &mut Shown| {
            !shown.ended && !String::from_utf8_lossy(&shown.bytes).contains(text)
        };
        let waited = more.wait_timeout_while(lock(shown), within, waiting);
        let (shown, _) = waited.unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(String::from_utf8_lossy(&shown.bytes).into_owned())
    }

    pub(super) fn type_text(&mut self, text: &str) -> Result<()> {
        Ok(self.ours.write_all(text.as_bytes())?)
    }

    pub(super) fn echoes(&self) -> Result<bool> {
        let mode = tcgetattr(&self.ours).map_err(io::Error::from)?;
        Ok(mode.local_modes.contains(LocalModes::ECHO))
    }
}
