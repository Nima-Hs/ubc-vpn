//! The installed service's own folder: the service refuses to run from one
//! that someone other than SYSTEM, the Administrators group or
//! TrustedInstaller could change, or that sits in a folder someone else
//! could swap.
//!
//! The service runs as LocalSystem and loads `libopenconnect` and its DLLs,
//! and Wintun, from the folder it runs from. Whoever could change that
//! folder could have their code run as LocalSystem. The installer puts it in
//! Program Files, but `/D=` once installed it elsewhere, and a file copied
//! by hand could be anywhere. So the service checks where it is.
//!
//! Two rules, each read from the owner and the access list through a handle
//! to the very folder or file, opened without following a link:
//!
//! - **The folder and every file directly in it:** owned by a trusted
//!   account, and no one else may change it in any way: write, add, delete,
//!   change its attributes, its access list or its owner.
//! - **Every folder above it, to the root of the drive:** owned by a trusted
//!   account, not a link, and no one else may delete, rename or replace
//!   what is in it, or change its access list or owner. Adding something
//!   new is allowed: ordinary users may create folders in `C:\`, and that
//!   cannot change the path to the service.
//!
//! In both, an entry that only applies to what is created inside a folder
//! (inherit-only) is not a right on the folder itself and is not counted.
//! Program Files gives CREATOR OWNER full control that way; the files it
//! applies to are made by an administrator.
//!
//! The folders stay open until the result is dropped, without letting
//! anyone delete or rename them, so none can be swapped between the check
//! and the loading of a library.

use std::path::Path;
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
use windows_sys::Win32::Security::{DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
    GetFileInformationByHandle, READ_CONTROL,
};

use super::security::{Handle, last_error, os_error, sid_text};
use super::state::{Entry, entries, open};
use crate::{Error, Result};

const SYSTEM: &str = "S-1-5-18";
const ADMINISTRATORS: &str = "S-1-5-32-544";
const TRUSTED_INSTALLER: &str = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
const TRUSTED: [&str; 3] = [SYSTEM, ADMINISTRATORS, TRUSTED_INSTALLER];

/// An entry that applies only to what is created inside, not to the folder.
const INHERIT_ONLY: u8 = 0x08;

/// Every right that changes a folder, a file or its security, as in the
/// state folder's check.
const CHANGE: u32 = 0x5000_0000 // GENERIC_ALL, GENERIC_WRITE
    | 0x000D_0000 // DELETE, WRITE_DAC, WRITE_OWNER
    | 0x0000_0156; // write or add, append or add folder, write EA, delete child, write attributes

/// The rights on a folder above that could swap what is in it: generic all,
/// delete, change the access list or owner, and delete what is inside.
const REPLACE: u32 = 0x1000_0000 | 0x000D_0000 | 0x0000_0040;

/// The service's folder and the folders above it, held open. Dropping it
/// lets them be renamed again.
pub struct ProgramFolder {
    _held: Vec<Handle>,
}

/// Checks the folder `program` is in, the files directly in it and every
/// folder above it. The error says which path failed and why.
pub fn check(program: &Path) -> Result<ProgramFolder> {
    let folder = program
        .parent()
        .filter(|folder| folder.is_absolute())
        .ok_or_else(|| Error::Failed("The service's folder is not a full path.".to_string()))?;
    let mut held = Vec::new();
    for above in folder.ancestors().skip(1) {
        held.push(check_path(above, REPLACE)?);
    }
    held.push(check_path(folder, CHANGE)?);
    for entry in std::fs::read_dir(folder)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            drop(check_path(&entry.path(), CHANGE)?);
        }
    }
    Ok(ProgramFolder { _held: held })
}

/// Checks one folder or file against `rights`, and returns it open.
fn check_path(path: &Path, rights: u32) -> Result<Handle> {
    let share = FILE_SHARE_READ | FILE_SHARE_WRITE;
    // Listing (reading, for a file) as well as reading the security: a
    // handle with only READ_CONTROL does not hold the share mode, so the
    // folder could still be renamed while it is open.
    const FILE_LIST_DIRECTORY: u32 = 0x1;
    let access = READ_CONTROL | FILE_LIST_DIRECTORY;
    let handle = open(path, access, share)?.ok_or(Error::NotFound)?;
    let refuse = |why: String| {
        let message = format!(
            "The service's folder is not safe to use: {} {why}.",
            path.display()
        );
        Err(Error::Failed(message))
    };
    // SAFETY: plain data for which all zeroes is valid.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: the handle is open and the out pointer valid.
    if unsafe { GetFileInformationByHandle(handle.0, &mut info) } == 0 {
        return Err(os_error(last_error()));
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return refuse("is a link to somewhere else".to_string());
    }
    let (owner, dacl) = security_of(&handle)?;
    match judge(&owner, dacl.as_deref(), rights) {
        Some(why) => refuse(format!("is not safe: {why}")),
        None => Ok(handle),
    }
}

/// The owner and access entries of the folder or file behind `handle`.
fn security_of(handle: &Handle) -> Result<(String, Option<Vec<Entry>>)> {
    let (mut owner, mut dacl, mut descriptor) = (null_mut(), null_mut(), null_mut());
    let what = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    // SAFETY: the handle is open with READ_CONTROL; the out pointers asked
    // for are valid and the others may be null.
    let status = unsafe {
        GetSecurityInfo(
            handle.0,
            SE_FILE_OBJECT,
            what,
            &mut owner,
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(os_error(status));
    }
    // `owner` and `dacl` point into the descriptor, freed after reading.
    let read = sid_text(owner).and_then(|owner| {
        let dacl = match dacl.is_null() {
            true => None,
            false => Some(entries(dacl)?),
        };
        Ok((owner, dacl))
    });
    // SAFETY: the API allocated the descriptor for the caller to free.
    unsafe { LocalFree(descriptor) };
    read
}

/// Why a folder or file with this owner and access list fails, when
/// someone untrusted holds any of `rights` on it, or nothing when it passes.
fn judge(owner: &str, dacl: Option<&[Entry]>, rights: u32) -> Option<String> {
    if !TRUSTED.contains(&owner) {
        return Some(format!("it is owned by {owner}"));
    }
    let Some(dacl) = dacl else {
        return Some("it has no access list, so everyone may change it".to_string());
    };
    for entry in dacl {
        match entry.kind {
            // A denial only takes rights away.
            1 => {}
            0 if entry.flags & INHERIT_ONLY != 0 => {}
            0 if TRUSTED.contains(&entry.sid.as_str()) || entry.mask & rights == 0 => {}
            0 => return Some(format!("{} may change it", entry.sid)),
            // Kinds this check does not read may grant anything.
            kind => return Some(format!("it has an access entry of kind {kind}")),
        }
    }
    None
}

#[cfg(test)]
#[path = "program_tests.rs"]
mod tests;
