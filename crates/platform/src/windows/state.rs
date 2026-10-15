//! The service's state folder on Windows: made with an access list of its
//! own, and checked before anything in it is read or written.
//!
//! The check reads the owner and the access list through a handle to the
//! very folder or file being used, opened without following a link, so what
//! is checked is what is read.

use std::fs::File;
use std::io::Read;
use std::os::windows::io::FromRawHandle;
use std::path::Path;
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, INVALID_HANDLE_VALUE, LocalFree};
use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, GetAce,
    OWNER_SECURITY_INFORMATION, PSID, SECURITY_ATTRIBUTES,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateDirectoryW, CreateFileW, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
    GetFileInformationByHandle, OPEN_EXISTING, READ_CONTROL,
};

use super::security::{Descriptor, Handle, last_error, os_error, sid_text, wide};
use crate::{Error, Mode, Result};

const SYSTEM: &str = "S-1-5-18";
const ADMINISTRATORS: &str = "S-1-5-32-544";
const TRUSTED_INSTALLER: &str = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

/// Every right that changes a folder, a file or its security: writing,
/// adding, deleting, and changing the access list or the owner.
const WRITE_RIGHTS: u32 = 0x5000_0000 // GENERIC_ALL, GENERIC_WRITE
    | 0x000D_0000 // DELETE, WRITE_DAC, WRITE_OWNER
    | 0x0000_0156; // write or add, append or add folder, write EA, delete child, write attributes

/// The users who may own the folder and write to it.
fn trusted(mode: Mode) -> Result<Vec<String>> {
    let mut trusted = vec![SYSTEM.to_string(), ADMINISTRATORS.to_string()];
    match mode {
        Mode::Installed => trusted.push(TRUSTED_INSTALLER.to_string()),
        #[cfg(feature = "dev-mode")]
        Mode::Dev => trusted.push(super::security::process_user()?),
    }
    Ok(trusted)
}

/// The access list a new folder gets: full control for the trusted users,
/// passed on to everything inside it, and nothing inherited from above.
fn new_folder_sddl(mode: Mode) -> Result<String> {
    let full = |sid: &str| format!("(A;OICI;FA;;;{sid})");
    Ok(match mode {
        Mode::Installed => format!("O:BAD:P{}{}", full("SY"), full("BA")),
        #[cfg(feature = "dev-mode")]
        Mode::Dev => {
            let me = super::security::process_user()?;
            format!("O:{me}D:P{}{}{}", full(&me), full("SY"), full("BA"))
        }
    })
}

/// One entry of an access list, as far as the check needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Entry {
    pub(super) kind: u8,
    pub(super) mask: u32,
    pub(super) sid: String,
}

/// Why a folder or file is not safe to use, or nothing when it is.
pub(super) fn judge(owner: &str, dacl: Option<&[Entry]>, trusted: &[String]) -> Option<String> {
    if !trusted.iter().any(|sid| sid == owner) {
        return Some(format!("it is owned by {owner}"));
    }
    let Some(dacl) = dacl else {
        return Some("it has no access list, so everyone may change it".to_string());
    };
    for entry in dacl {
        match entry.kind {
            // A denial only takes rights away.
            1 => {}
            0 if trusted.contains(&entry.sid) || entry.mask & WRITE_RIGHTS == 0 => {}
            0 => return Some(format!("{} may change it", entry.sid)),
            // Kinds this check does not read may grant anything.
            kind => return Some(format!("it has an access entry of kind {kind}")),
        }
    }
    None
}

/// The access entries of `acl`.
fn entries(acl: *const ACL) -> Result<Vec<Entry>> {
    // SAFETY: `acl` points to a valid access list owned by a descriptor the
    // caller keeps alive.
    let count = unsafe { (*acl).AceCount };
    let mut found = Vec::new();
    for index in 0..u32::from(count) {
        let mut ace = null_mut();
        // SAFETY: as above, and the index is below the count.
        if unsafe { GetAce(acl, index, &mut ace) } == 0 {
            return Err(os_error(last_error()));
        }
        // SAFETY: every entry starts with a header.
        let header = unsafe { *ace.cast::<ACE_HEADER>() };
        let (mask, sid) = match header.AceType {
            // SAFETY: entries of these two kinds have this layout, with the
            // SID starting at `SidStart`.
            0 | 1 => unsafe {
                let ace = ace.cast::<ACCESS_ALLOWED_ACE>();
                let sid: PSID = (&raw mut (*ace).SidStart).cast();
                ((*ace).Mask, sid_text(sid)?)
            },
            _ => (0, String::new()),
        };
        found.push(Entry {
            kind: header.AceType,
            mask,
            sid,
        });
    }
    Ok(found)
}

/// Checks the folder or file behind `handle`.
fn check_handle(handle: &Handle, what: &Path, trusted: &[String]) -> Result<()> {
    // SAFETY: plain data for which all zeroes is valid.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: the handle is open and the out pointer valid.
    if unsafe { GetFileInformationByHandle(handle.0, &mut info) } == 0 {
        return Err(os_error(last_error()));
    }
    let refuse = |why: &str| {
        let message = format!(
            "The state folder is not safe to use: {} {why}.",
            what.display()
        );
        Err(Error::Failed(message))
    };
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return refuse("is a link to somewhere else");
    }
    let (mut owner, mut dacl, mut descriptor) = (null_mut(), null_mut(), null_mut());
    let what_to_read = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    // SAFETY: the handle is open with READ_CONTROL; the out pointers asked
    // for are valid and the others may be null.
    let status = unsafe {
        GetSecurityInfo(
            handle.0,
            SE_FILE_OBJECT,
            what_to_read,
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
    // `owner` and `dacl` point into the descriptor, freed after the check.
    let checked = sid_text(owner).and_then(|owner| {
        let dacl = match dacl.is_null() {
            true => None,
            false => Some(entries(dacl)?),
        };
        Ok(judge(&owner, dacl.as_deref(), trusted))
    });
    // SAFETY: the API allocated the descriptor for the caller to free.
    unsafe { LocalFree(descriptor) };
    match checked? {
        Some(why) => refuse(&format!("is not safe: {why}")),
        None => Ok(()),
    }
}

/// Opens `path`, a folder or a file, without following a link.
fn open(path: &Path, access: u32, share: u32) -> Result<Option<Handle>> {
    let name = wide(&path.to_string_lossy());
    let flags = FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT;
    // SAFETY: `name` is NUL-terminated and outlives the call; the optional
    // pointers are null.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            access,
            share,
            null_mut(),
            OPEN_EXISTING,
            flags,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return match os_error(last_error()) {
            Error::NotFound => Ok(None),
            error => Err(error),
        };
    }
    Ok(Some(Handle(handle)))
}

/// The folder, held open while it is used. It is opened without letting
/// anyone delete or rename it, so a folder above it cannot be renamed and
/// swapped for another between the check and the use.
pub(crate) struct Held {
    _folder: Handle,
}

/// Refuses the folder unless the trusted users alone own it and may change
/// it, and holds it open for as long as the result is kept.
pub(crate) fn check_folder(mode: Mode, dir: &Path) -> Result<Held> {
    let share = FILE_SHARE_READ | FILE_SHARE_WRITE;
    let folder = open(dir, READ_CONTROL, share)?.ok_or(Error::NotFound)?;
    check_handle(&folder, dir, &trusted(mode)?)?;
    Ok(Held { _folder: folder })
}

/// Creates the folder with its own access list when it is missing, then
/// checks it either way.
pub(crate) fn prepare(mode: Mode, dir: &Path) -> Result<()> {
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let descriptor = Descriptor::parse(&new_folder_sddl(mode)?)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.as_ptr(),
        bInheritHandle: 0,
    };
    let name = wide(&dir.to_string_lossy());
    // SAFETY: the name is NUL-terminated, and it and the attributes, with
    // the descriptor they point to, outlive the call.
    if unsafe { CreateDirectoryW(name.as_ptr(), &attributes) } == 0 {
        let code = last_error();
        if code != ERROR_ALREADY_EXISTS {
            return Err(os_error(code));
        }
    }
    check_folder(mode, dir).map(drop)
}

/// The file's contents, after checking the folder and the file itself.
pub(crate) fn read(mode: Mode, dir: &Path, file: &Path) -> Result<Option<Vec<u8>>> {
    let _held = check_folder(mode, dir)?;
    const FILE_GENERIC_READ: u32 = 0x0012_0089;
    let Some(handle) = open(file, FILE_GENERIC_READ, FILE_SHARE_READ)? else {
        return Ok(None);
    };
    check_handle(&handle, file, &trusted(mode)?)?;
    let raw = handle.0;
    std::mem::forget(handle);
    // SAFETY: the handle is open, and ownership passes to the file, which
    // closes it.
    let mut file = unsafe { File::from_raw_handle(raw) };
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(Some(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Security::{GetSecurityDescriptorDacl, GetSecurityDescriptorOwner};

    /// The owner and access entries of a descriptor written in SDDL.
    fn parsed(sddl: &str) -> (String, Option<Vec<Entry>>) {
        let descriptor = Descriptor::parse(sddl).unwrap();
        let (mut owner, mut defaulted) = (null_mut(), 0);
        let (mut present, mut dacl) = (0, null_mut());
        // SAFETY: the descriptor is valid and the out pointers are valid.
        unsafe {
            assert_ne!(
                GetSecurityDescriptorOwner(descriptor.as_ptr(), &mut owner, &mut defaulted),
                0
            );
            assert_ne!(
                GetSecurityDescriptorDacl(
                    descriptor.as_ptr(),
                    &mut present,
                    &mut dacl,
                    &mut defaulted
                ),
                0
            );
        }
        let owner = sid_text(owner).unwrap();
        let dacl = (present != 0 && !dacl.is_null()).then(|| entries(dacl).unwrap());
        (owner, dacl)
    }

    fn verdict(sddl: &str) -> Option<String> {
        let (owner, dacl) = parsed(sddl);
        judge(&owner, dacl.as_deref(), &trusted(Mode::Installed).unwrap())
    }

    // Security rule: a folder an ordinary user made, or may change, decides
    // nothing.
    #[test]
    fn only_a_folder_the_administrators_alone_control_passes() {
        let fresh = new_folder_sddl(Mode::Installed).unwrap();
        assert_eq!(verdict(&fresh), None, "the folder the service makes");
        let installer =
            format!("O:{TRUSTED_INSTALLER}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{TRUSTED_INSTALLER})");
        assert_eq!(verdict(&installer), None, "one the installer made");
        // Reading is fine for anyone; so is a denial.
        assert_eq!(verdict("O:SYD:P(A;;FA;;;SY)(A;;FR;;;BU)(D;;FA;;;WD)"), None);
        let refused = [
            // Owned by an ordinary user, as a folder made under ProgramData
            // before the service would be.
            "O:S-1-5-21-1-2-3-1001D:P(A;OICI;FA;;;SY)",
            // Users may add files.
            "O:BAD:(A;;FA;;;SY)(A;;0x2;;;BU)",
            // The creator of anything inside gets full control.
            "O:BAD:(A;;FA;;;SY)(A;OICIIO;FA;;;CO)",
            // Users may change the access list, or take ownership.
            "O:BAD:(A;;WD;;;BU)",
            "O:BAD:(A;;WO;;;BU)",
            // Generic write, or delete.
            "O:BAD:(A;;GW;;;AU)",
            "O:BAD:(A;;SD;;;WD)",
            // No access list at all: anyone may do anything.
            "O:BAD:NO_ACCESS_CONTROL",
            // Entry kinds the check does not read: one for an object type,
            // and one with a condition.
            "O:BAD:(A;;FA;;;SY)(OA;;FA;;;BU)",
            "O:BAD:(A;;FA;;;SY)(XA;;FA;;;BU;(Member_of {SID(BA)}))",
        ];
        for sddl in refused {
            assert!(verdict(sddl).is_some(), "{sddl}");
        }
    }

    // In dev mode the folder is the current user's: one owned by another
    // user is refused, as is one an ordinary group may change.
    #[cfg(feature = "dev-mode")]
    #[test]
    fn dev_mode_trusts_only_the_current_user() {
        let trusted = trusted(Mode::Dev).unwrap();
        let me = super::super::security::process_user().unwrap();
        let fresh = new_folder_sddl(Mode::Dev).unwrap();
        let (owner, dacl) = parsed(&fresh);
        assert_eq!(judge(&owner, dacl.as_deref(), &trusted), None);
        let other = format!("O:S-1-5-21-1-2-3-1001D:P(A;;FA;;;{me})");
        let (owner, dacl) = parsed(&other);
        assert!(judge(&owner, dacl.as_deref(), &trusted).is_some());
        let shared = format!("O:{me}D:P(A;;FA;;;{me})(A;;0x2;;;BU)");
        let (owner, dacl) = parsed(&shared);
        assert!(judge(&owner, dacl.as_deref(), &trusted).is_some());
    }

    #[test]
    fn says_why_a_folder_is_refused() {
        let why = verdict("O:S-1-5-21-1-2-3-1001D:P(A;;FA;;;SY)").unwrap();
        assert!(why.contains("S-1-5-21-1-2-3-1001"), "{why}");
        let why = verdict("O:BAD:(A;;0x2;;;BU)").unwrap();
        assert!(why.contains("S-1-5-32-545 may change it"), "{why}");
    }
}
