//! Files and folders the macOS and Linux installs make as root. Each OS's
//! `install` decides what goes where; how a file gets there is the same.
//!
//! Security rule: nothing here follows a link. Whatever a link points to
//! stays as it is, and a file another user left in the way is replaced, never
//! written through.

use std::fs::{self, DirBuilder, OpenOptions, Permissions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt, fchown};
use std::path::Path;

use rustix::fs::OFlags;

use super::acl;
use crate::{Error, Result};

/// Whether `path` is a real folder: `false` when there is nothing there,
/// and an error when something else is, a link included.
pub(crate) fn real_folder(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(found) if found.is_dir() => Ok(true),
        Ok(_) => Err(Error::Failed(format!(
            "{} is not a folder; run a fresh install",
            path.display()
        ))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

/// Removes whatever is at `path`. A link is removed itself, never what it
/// points to.
pub(crate) fn clear(path: &Path) -> Result<()> {
    let removed = match fs::symlink_metadata(path) {
        Ok(found) if found.is_dir() => fs::remove_dir_all(path),
        Ok(_) => fs::remove_file(path),
        Err(error) => Err(error),
    };
    match removed {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error.into()),
        _ => Ok(()),
    }
}

/// Removes the file or link `path`. Nothing there is fine.
pub(crate) fn remove_file(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error.into()),
        _ => Ok(()),
    }
}

/// Makes the folder `path`, root's with `mode` whatever the umask and
/// whatever group the folder above it hands on.
pub(crate) fn make_root_folder(path: &Path, mode: u32) -> Result<()> {
    DirBuilder::new().mode(mode).create(path)?;
    set_root_folder(path, mode)
}

/// Gives the folder `path` to root, with `mode` whatever the umask. Done
/// through the folder as opened, so a link put in its place is refused and
/// what it points to stays as it is.
pub(crate) fn set_root_folder(path: &Path, mode: u32) -> Result<()> {
    let folder = OpenOptions::new()
        .read(true)
        .custom_flags((OFlags::NOFOLLOW | OFlags::DIRECTORY).bits() as i32)
        .open(path)?;
    fchown(&folder, Some(0), Some(0))?;
    folder.set_permissions(Permissions::from_mode(mode))?;
    Ok(())
}

/// Writes `bytes` as `name` in `dir`, root's with `mode` whatever the umask,
/// replacing any. It is written beside it first and then moved into place,
/// so a reader never sees half of it. A file or link left in the way by an
/// earlier run is removed, never followed.
pub(crate) fn write_root_file(dir: &Path, name: &str, bytes: &[u8], mode: u32) -> Result<()> {
    let next = dir.join(format!(".{name}.new"));
    remove_file(&next)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(OFlags::NOFOLLOW.bits() as i32)
        .open(&next)?;
    file.write_all(bytes)?;
    fchown(&file, Some(0), Some(0))?;
    file.set_permissions(Permissions::from_mode(mode))?;
    file.sync_all()?;
    drop(file);
    fs::rename(&next, dir.join(name))?;
    Ok(())
}

/// What [`check_root`] expects to find.
#[derive(Clone, Copy)]
pub(crate) enum Expected {
    Folder,
    File,
}

/// Checks that `path` is a real folder or file, not a link, root's and root's
/// group's, with exactly `mode`, and no access list entry that allows anything.
pub(crate) fn check_root(path: &Path, expected: Expected, mode: u32) -> Result<()> {
    let found = fs::symlink_metadata(path)?;
    let kind = match expected {
        Expected::Folder => found.is_dir(),
        Expected::File => found.is_file(),
    };
    if !kind || found.uid() != 0 || found.gid() != 0 || found.mode() & 0o7777 != mode {
        return Err(Error::Failed(format!(
            "{} is not root's with mode {mode:o}",
            path.display()
        )));
    }
    if acl::path_allows(path)? {
        return Err(Error::Failed(format!(
            "{} has an access list that lets others change it",
            path.display()
        )));
    }
    Ok(())
}

/// The names of what is in the folder `dir`, sorted.
pub(crate) fn names_in(dir: &Path) -> Result<Vec<String>> {
    let mut found = Vec::new();
    for entry in fs::read_dir(dir)? {
        found.push(entry?.file_name().to_string_lossy().into_owned());
    }
    found.sort();
    Ok(found)
}
