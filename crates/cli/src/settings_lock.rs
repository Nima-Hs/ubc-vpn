//! One change to the settings at a time.
//!
//! Each change reads the whole settings file, alters one field and writes
//! the whole file back. Two at once could each read the file before the
//! other wrote it, and the one that wrote second would undo the other's
//! field: routes saved and the username lost, or the reverse. So whoever
//! changes the settings first takes a lock, and holds it from the read to
//! the write.
//!
//! The lock is the operating system's lock on a file beside the settings,
//! `settings.json.lock`. The system lets go of it when the program that
//! holds it ends, however it ends, so there is never a stale one to clear
//! away. The file itself is empty, is never written to or removed, and is
//! left alone by the sweep of old partial files.
//!
//! Reading the settings takes no lock: a save puts the new file in place in
//! one step, so a reader sees the old file or the new one, whole.
//!
//! # When the lock cannot be had
//!
//! The lock guards against a rare loss of one field. It is not worth
//! refusing every save for, so only one case refuses:
//!
//! - **Another change holds it for the whole wait.** The answer is
//!   [`SettingsFailureCode::Unwritable`]: something is stuck, and writing
//!   over it could lose its change.
//! - **Anything else** goes ahead without the lock, with the small risk
//!   there was before there was a lock, and says so once on standard error.
//!   That covers a file system that has no locks, as some network home
//!   folders do; a lock file that cannot be opened, such as one left
//!   belonging to another account; a link or a folder where the lock file
//!   should be, which is never opened; and a lock call that does not come
//!   back, which on such file systems can happen.
//!
//! The lock is asked for on a thread of its own so that the last case has an
//! end. A thread whose call never returns is left behind; if its call does
//! return later, it finds nobody waiting and lets the lock go at once. This
//! program runs one command and ends, so nothing waits behind it.

use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::channel;
use std::time::{Duration, Instant};

use ubc_vpn_core::settings_cli::SettingsFailureCode;

use crate::settings::{create_folder, folder_problem};

const LOCK: &str = "settings.json.lock";

/// How long a change waits for another to finish. A change takes a moment;
/// one that holds the lock this long is stuck, and waiting longer would
/// only hang whoever asked.
pub(crate) const WAIT: Duration = Duration::from_secs(5);

/// How much longer than the wait the asking thread is given to answer,
/// before its call is taken not to be coming back.
const GRACE: Duration = Duration::from_millis(500);

const UNLOCKED: &str = "The settings could not be locked here, so this change was made without \
                        the lock. Do not change the settings from two places at once.";

/// The right to change the settings: nobody else has it until this is
/// dropped. Or, where the lock could not be had, only leave to go ahead.
pub(crate) struct Changing {
    /// The lock, which dropping this lets go of. `None` without one.
    held: Option<Box<dyn Send>>,
}

impl Changing {
    /// Whether the change goes ahead without the lock.
    pub(crate) fn unlocked(&self) -> bool {
        self.held.is_none()
    }
}

/// What one try at the lock found.
pub(crate) enum Tried {
    /// The lock is ours for as long as this value lives.
    Held(Box<dyn Send>),
    /// Another change holds it.
    Busy,
}

/// Waits for this program's turn to change the settings in `dir`, making
/// the folder if it is not there. Fails with
/// [`SettingsFailureCode::Unreadable`] for a folder that is not safe to
/// use, and with [`SettingsFailureCode::Unwritable`] when the folder cannot
/// be made or another change held the lock for too long. Where the lock
/// cannot be had for any other reason the change goes ahead without it, and
/// standard error is told so.
pub(crate) fn change(dir: &Path) -> Result<Changing, SettingsFailureCode> {
    let changing = change_within(dir, WAIT)?;
    if changing.unlocked() {
        // A closed standard error must not end the program over a notice.
        let _ = writeln!(io::stderr(), "ubc-vpn: {UNLOCKED}");
    }
    Ok(changing)
}

/// [`change`] without the word on standard error, waiting no longer than
/// `wait`.
pub(crate) fn change_within(dir: &Path, wait: Duration) -> Result<Changing, SettingsFailureCode> {
    change_with(dir, wait, real(dir.join(LOCK)))
}

/// [`change`], waiting no longer than `wait`, and trying for the lock with
/// `attempt`, which is called again and again while it answers
/// [`Tried::Busy`].
pub(crate) fn change_with(
    dir: &Path,
    wait: Duration,
    mut attempt: impl FnMut() -> io::Result<Tried> + Send + 'static,
) -> Result<Changing, SettingsFailureCode> {
    if folder_problem(dir).is_some() {
        return Err(SettingsFailureCode::Unreadable);
    }
    create_folder(dir).map_err(|_| SettingsFailureCode::Unwritable)?;
    let (answer, answered) = channel();
    std::thread::spawn(move || {
        let give_up = Instant::now() + wait;
        let found = loop {
            match attempt() {
                Ok(Tried::Busy) if Instant::now() < give_up => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                found => break found,
            }
        };
        // If nobody is waiting any more the lock, if this is one, is
        // dropped here and so let go.
        let _ = answer.send(found);
    });
    match answered.recv_timeout(wait + GRACE) {
        Ok(Ok(Tried::Held(lock))) => Ok(Changing { held: Some(lock) }),
        // Held by another change for the whole wait.
        Ok(Ok(Tried::Busy)) => Err(SettingsFailureCode::Unwritable),
        // The lock cannot be had here, or the call has not come back.
        Ok(Err(_)) | Err(_) => Ok(Changing { held: None }),
    }
}

/// The real try: the operating system's lock on the file at `path`, opened
/// at the first try.
fn real(path: PathBuf) -> impl FnMut() -> io::Result<Tried> + Send + 'static {
    let mut file = None;
    move || {
        if file.is_none() {
            file = Some(open(&path)?);
        }
        let opened = file.take().ok_or(io::ErrorKind::NotFound)?;
        match opened.try_lock() {
            Ok(()) => Ok(Tried::Held(Box::new(opened))),
            Err(TryLockError::WouldBlock) => {
                file = Some(opened);
                Ok(Tried::Busy)
            }
            Err(TryLockError::Error(error)) => Err(error),
        }
    }
}

/// Opens the lock file, making it if it is not there. Only a plain file is
/// opened: a link is not followed to whatever it leads to, and a folder
/// cannot be locked.
fn open(path: &Path) -> io::Result<File> {
    if fs::symlink_metadata(path).is_ok_and(|found| !found.is_file()) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(false);
    // As for the settings file itself: the user's alone on Unix.
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)
}

#[cfg(test)]
#[path = "settings_lock_tests.rs"]
mod tests;
