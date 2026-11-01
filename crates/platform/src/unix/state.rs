//! The service's state folder on macOS and Linux (see [`crate::StateDir`]).
//!
//! Security rule: nobody but the service's user can change anything there.
//! An ordinary user who could make the folder before the service did, or put
//! a file in it, could name themselves the owner in `state.json`. So,
//! installed, the folder and every folder above it are real folders (no
//! links), root's, and writable by root alone, and a file read from it is a
//! real file, root's, and writable by root alone. Dev mode's folder and files
//! are the developer's own and writable by them alone.
//!
//! Anything that breaks the rule is refused and left as it was found, never
//! fixed: whatever someone else made there cannot be trusted afterwards,
//! whatever its owner and mode become.

use std::fs::{DirBuilder, File, Metadata, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::Path;

use rustix::fs::OFlags;
use rustix::io::Errno;
#[cfg(feature = "dev-mode")]
use rustix::process::geteuid;

use super::set_mode;
use crate::{Error, Mode, Result};

pub(crate) const NOT_A_FOLDER: &str = "the state folder is a link or not a folder";
pub(crate) const WRONG_OWNER: &str = "the state folder belongs to the wrong user";
pub(crate) const TOO_OPEN: &str = "the state folder can be changed by other users";
pub(crate) const NOT_A_FILE: &str = "a state file is a link or not a file";
pub(crate) const FILE_OWNER: &str = "a state file belongs to the wrong user";
pub(crate) const FILE_OPEN: &str = "a state file can be changed by other users";

/// Permission bits that let someone other than the owner write.
const OTHERS_WRITE: u32 = 0o022;

/// The user who must own the folder and its files: root when installed, the
/// current user in dev mode.
fn owner(mode: Mode) -> u32 {
    match mode {
        Mode::Installed => 0,
        #[cfg(feature = "dev-mode")]
        Mode::Dev => geteuid().as_raw(),
    }
}

/// Makes the state folder `dir` when it is missing, then checks it.
/// Installed on macOS it also holds the policy and the channel, which every
/// user must reach, so others may look in: 0755. In dev mode it is 0700.
pub(crate) fn prepare(mode: Mode, dir: &Path) -> Result<()> {
    let made = match mode {
        Mode::Installed => 0o755,
        #[cfg(feature = "dev-mode")]
        Mode::Dev => 0o700,
    };
    make(mode, dir, made)
}

/// Makes the folder `dir` for temporary files inside the state folder
/// `state`, when it is missing, closed to others (0700). The state folder
/// is checked first, as in dev mode `dir` alone would be.
pub(crate) fn prepare_private(mode: Mode, state: &Path, dir: &Path) -> Result<()> {
    check_folder(mode, state)?;
    make(mode, dir, 0o700)
}

/// Makes `dir` with mode `made` when it is missing, then checks it. Only the
/// last folder is made when installed; the ones above must be there.
fn make(mode: Mode, dir: &Path, made: u32) -> Result<()> {
    match check_folder(mode, dir) {
        Err(Error::NotFound) => {}
        checked => return checked,
    }
    let mut builder = DirBuilder::new();
    builder.mode(made);
    #[cfg(feature = "dev-mode")]
    builder.recursive(mode == Mode::Dev);
    match builder.create(dir) {
        // Set again because the umask may have narrowed it, and only on a
        // folder this call made.
        Ok(()) => set_mode(dir, made)?,
        // Made by someone else meanwhile: the check below judges it.
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    check_folder(mode, dir)
}

/// Checks the state folder `dir`, and every folder above it when installed.
/// A missing folder is [`Error::NotFound`].
pub(crate) fn check_folder(mode: Mode, dir: &Path) -> Result<()> {
    if !dir.is_absolute() {
        return Err(Error::Failed(
            "the state folder is not an absolute path".to_string(),
        ));
    }
    let mut chain: Vec<&Path> = match mode {
        Mode::Installed => dir.ancestors().collect(),
        #[cfg(feature = "dev-mode")]
        Mode::Dev => vec![dir],
    };
    chain.reverse();
    for at in chain {
        // Not followed: a link here could be pointed anywhere later.
        let found = std::fs::symlink_metadata(at)?;
        let broken = if !found.is_dir() {
            NOT_A_FOLDER
        } else {
            match broken(mode, &found) {
                None => continue,
                Some(Broken::Owner) => WRONG_OWNER,
                Some(Broken::Open) => TOO_OPEN,
            }
        };
        return Err(Error::Failed(broken.to_string()));
    }
    Ok(())
}

enum Broken {
    Owner,
    Open,
}

/// How `found` breaks the rule that only the service's user may change it.
fn broken(mode: Mode, found: &Metadata) -> Option<Broken> {
    if found.uid() != owner(mode) {
        Some(Broken::Owner)
    } else if found.mode() & OTHERS_WRITE != 0 {
        Some(Broken::Open)
    } else {
        None
    }
}

/// The contents of `file` in the folder `dir`, or `None` when there is no
/// such file. The folder is checked first, then the file as it was opened:
/// a link is not followed, and what is judged is what is read.
pub(crate) fn read(mode: Mode, dir: &Path, file: &Path) -> Result<Option<Vec<u8>>> {
    check_folder(mode, dir)?;
    // Not blocking either: a pipe in the file's place would wait for ever.
    let flags = (OFlags::NOFOLLOW | OFlags::NONBLOCK).bits() as i32;
    let opened = OpenOptions::new().read(true).custom_flags(flags).open(file);
    let mut opened: File = match opened {
        Ok(opened) => opened,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) if error.raw_os_error() == Some(Errno::LOOP.raw_os_error()) => {
            return Err(Error::Failed(NOT_A_FILE.to_string()));
        }
        Err(error) => return Err(error.into()),
    };
    let found = opened.metadata()?;
    let broken = if !found.is_file() {
        NOT_A_FILE
    } else {
        match broken(mode, &found) {
            None => {
                let mut bytes = Vec::new();
                opened.read_to_end(&mut bytes)?;
                return Ok(Some(bytes));
            }
            Some(Broken::Owner) => FILE_OWNER,
            Some(Broken::Open) => FILE_OPEN,
        }
    };
    Err(Error::Failed(broken.to_string()))
}
