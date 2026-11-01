//! The state folder's plain file calls: all of it for the fake and tests,
//! and the writing on every OS once the folder's checks have passed (see
//! [`crate::StateDir`]).

use std::fs;
use std::io::{ErrorKind, Write};
use std::path::Path;

use crate::Result;

pub(crate) fn prepare(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir)?;
    Ok(())
}

pub(crate) fn read(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Writes a new file and moves it into place, so a crash leaves the old
/// contents or the new, never part of either.
pub(crate) fn write(path: &Path, fresh: &Path, bytes: &[u8]) -> Result<()> {
    match fs::remove_file(fresh) {
        Err(error) if error.kind() != ErrorKind::NotFound => return Err(error.into()),
        _ => {}
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    // Only the service may read what it keeps.
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(fresh)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(fresh, path)?;
    Ok(())
}
