//! The state folder without ownership checks: what the fake uses, and what
//! macOS and Linux use until their checks are written (see [`crate::StateDir`]).

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
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(fresh)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(fresh, path)?;
    Ok(())
}
