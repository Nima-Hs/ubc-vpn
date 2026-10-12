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

use std::fs::{self, File, OpenOptions, TryLockError};
use std::path::Path;
use std::time::{Duration, Instant};

use ubc_vpn_core::settings_cli::SettingsFailureCode;

use crate::settings::{create_folder, folder_problem};

const LOCK: &str = "settings.json.lock";

/// How long a change waits for another to finish. A change takes a moment;
/// one that holds the lock this long is stuck, and waiting longer would
/// only hang whoever asked.
const WAIT: Duration = Duration::from_secs(5);

/// The right to change the settings. Nobody else has it until this is
/// dropped.
#[derive(Debug)]
pub(crate) struct Changing {
    /// Held for its lock, which closing it lets go of.
    _file: File,
}

/// Waits for this program's turn to change the settings in `dir`, making
/// the folder if it is not there. Fails with
/// [`SettingsFailureCode::Unreadable`] for a folder that is not safe to
/// use, and with [`SettingsFailureCode::Unwritable`] when the lock cannot
/// be had: the folder cannot be written to, or another change has held the
/// lock for too long.
pub(crate) fn change(dir: &Path) -> Result<Changing, SettingsFailureCode> {
    change_within(dir, WAIT)
}

/// [`change`], waiting no longer than `wait` for another change to finish.
pub(crate) fn change_within(dir: &Path, wait: Duration) -> Result<Changing, SettingsFailureCode> {
    let unwritable = SettingsFailureCode::Unwritable;
    if folder_problem(dir).is_some() {
        return Err(SettingsFailureCode::Unreadable);
    }
    create_folder(dir).map_err(|_| unwritable)?;
    let path = dir.join(LOCK);
    // Only a plain file is opened. A link is not followed to whatever it
    // leads to, and a folder cannot be locked.
    if fs::symlink_metadata(&path).is_ok_and(|found| !found.is_file()) {
        return Err(unwritable);
    }
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(false);
    // As for the settings file itself: the user's alone on Unix.
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let file = options.open(&path).map_err(|_| unwritable)?;
    let give_up = Instant::now() + wait;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(Changing { _file: file }),
            Err(TryLockError::WouldBlock) if Instant::now() < give_up => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(_) => return Err(unwritable),
        }
    }
}
