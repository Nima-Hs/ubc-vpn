//! The service's state folder, which holds `state.json` and, on macOS, the
//! route journal.
//!
//! Security rule: nobody but the service's user can change anything there.
//! An ordinary user who could make the folder before the service did, or put
//! a file in it, could take the service over through `state.json`, or have
//! it remove routes as root through a journal. So, installed, the folder and
//! every folder above it are real folders (no links), root's, and writable by
//! root alone, and a file in it is a real file, root's, and writable by root
//! alone. Dev mode's folder is the developer's own and closed to everyone
//! else, as the channel's folder is.
//!
//! Anything that breaks the rule is refused and left as it was found, never
//! fixed. Whatever someone else made there cannot be trusted afterwards,
//! whatever its owner and mode become.

use std::fs::DirBuilder;
use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;

#[cfg(feature = "dev-mode")]
use rustix::process::geteuid;

use super::{Broken, Kind, check_entry, set_mode};
use crate::{Error, Mode, Result};

pub(crate) const NOT_A_FOLDER: &str = "the state folder is a link or not a folder";
pub(crate) const WRONG_OWNER: &str = "the state folder belongs to the wrong user";
pub(crate) const TOO_OPEN: &str = "the state folder can be changed by other users";
pub(crate) const NOT_A_FILE: &str = "a state file is a link or not a file";
pub(crate) const FILE_OWNER: &str = "a state file belongs to the wrong user";
pub(crate) const FILE_OPEN: &str = "a state file can be changed by other users";

/// The mode of a state folder this makes. Installed, the macOS state folder
/// also holds the policy and the channel, which every user must reach, so
/// others may look in; a file that must stay private sets its own mode.
fn made_mode(mode: Mode) -> u32 {
    match mode {
        Mode::Installed => 0o755,
        #[cfg(feature = "dev-mode")]
        Mode::Dev => 0o700,
    }
}

/// Who must own the folder and its files, and which permission bits a folder
/// must not have.
fn rule(mode: Mode) -> (u32, u32) {
    match mode {
        Mode::Installed => (0, 0o022),
        #[cfg(feature = "dev-mode")]
        Mode::Dev => (geteuid().as_raw(), 0o077),
    }
}

/// Makes the state folder `dir` when it is missing, then checks it. Only the
/// last folder is made when installed; the ones above must be there.
pub(crate) fn prepare(mode: Mode, dir: &Path) -> Result<()> {
    match check(mode, dir) {
        Err(Error::NotFound) => {}
        checked => return checked,
    }
    let made_mode = made_mode(mode);
    let mut builder = DirBuilder::new();
    builder.mode(made_mode);
    #[cfg(feature = "dev-mode")]
    builder.recursive(mode == Mode::Dev);
    match builder.create(dir) {
        // Set again because the umask may have narrowed it, and only on a
        // folder this call made.
        Ok(()) => set_mode(dir, made_mode)?,
        // Made by someone else meanwhile: the check below judges it.
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    check(mode, dir)
}

/// Checks the state folder `dir`, and every folder above it when installed.
/// A missing folder is [`Error::NotFound`].
pub(crate) fn check(mode: Mode, dir: &Path) -> Result<()> {
    if !dir.is_absolute() {
        return Err(Error::Failed(
            "the state folder is not an absolute path".to_string(),
        ));
    }
    let (owner, forbidden) = rule(mode);
    let mut chain: Vec<&Path> = match mode {
        Mode::Installed => dir.ancestors().collect(),
        #[cfg(feature = "dev-mode")]
        Mode::Dev => vec![dir],
    };
    chain.reverse();
    for at in chain {
        let broken = match check_entry(at, Kind::Folder, owner, forbidden)? {
            None => continue,
            Some(Broken::Kind) => NOT_A_FOLDER,
            Some(Broken::Owner) => WRONG_OWNER,
            Some(Broken::Open) => TOO_OPEN,
        };
        return Err(Error::Failed(broken.to_string()));
    }
    Ok(())
}

/// Checks a file in the state folder, and the folder itself. A missing file
/// keeps the rule: there is nothing there to trust or distrust.
pub(crate) fn check_file(mode: Mode, file: &Path) -> Result<()> {
    let folder = file
        .parent()
        .filter(|folder| !folder.as_os_str().is_empty());
    let folder = folder.ok_or_else(|| Error::Failed("a state file has no folder".to_string()))?;
    check(mode, folder)?;
    let (owner, _) = rule(mode);
    // A file only has to be closed to writing by others.
    let broken = match check_entry(file, Kind::File, owner, 0o022) {
        Ok(None) => return Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
        Ok(Some(Broken::Kind)) => NOT_A_FILE,
        Ok(Some(Broken::Owner)) => FILE_OWNER,
        Ok(Some(Broken::Open)) => FILE_OPEN,
    };
    Err(Error::Failed(broken.to_string()))
}
