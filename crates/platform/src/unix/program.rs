//! The installed service's own folder on Linux and macOS: the service refuses
//! to run from one that someone other than root could change, or that sits
//! in a folder someone else could swap.
//!
//! The service runs as root and loads `libopenconnect` and its libraries from
//! beside itself. Whoever could change that folder, or a folder above it,
//! could have their code run as root. So the service checks where it is:
//!
//! - **The folder, every folder above it up to `/`, and every file directly
//!   in the folder:** a real folder or file, not a link, owned by root, and
//!   writable by root alone: no group or other write. A sticky folder passes
//!   only on the same terms, so `/tmp` does not, but a root-owned 1755 one
//!   does. Folders inside the folder are not files and are not checked.
//! - **On macOS, access lists as well:** an entry there can let a user write
//!   whatever the mode says, so any entry that allows something is refused.
//!   Only entries that deny pass. On Linux an access list's write shows in
//!   the group bits, which the mode check already reads.
//!
//! The path is walked from `/` one folder at a time, each opened relative to
//! the one before without following a link, and judged from the open folder
//! itself, so what is judged is what is walked. A file is judged from the
//! file as opened. Anything else, or any error, refuses. A refusal says
//! which rule failed and names the folder or file it failed on, as on
//! Windows: the install path is not a secret. It says nothing else. Nothing
//! that breaks the rule is changed.
//!
//! Nothing needs to be held open: only root can rename or replace anything
//! in a folder that passes, so the path stays as it was checked.

use std::ffi::{CStr, OsStr};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use rustix::fs::{AtFlags, CWD, Dir, FileType, Mode, OFlags, Stat, fstat, openat, statat};
use rustix::io::Errno;

use crate::{Error, Result};

pub(crate) const NOT_FULL_PATH: &str = "the service's folder is not a plain full path";
pub(crate) const NOT_A_FOLDER: &str =
    "the service's folder or a folder above it is a link or not a folder";
pub(crate) const WRONG_OWNER: &str =
    "the service's folder or a folder above it does not belong to root";
pub(crate) const TOO_OPEN: &str =
    "the service's folder or a folder above it can be changed by other users";
pub(crate) const NOT_A_FILE: &str = "a file in the service's folder is a link or not a file";
pub(crate) const FILE_OWNER: &str = "a file in the service's folder does not belong to root";
pub(crate) const FILE_OPEN: &str = "a file in the service's folder can be changed by other users";
pub(crate) const CANNOT_CHECK: &str = "the service's folder could not be checked";

/// Permission bits that let someone other than the owner write.
const OTHERS_WRITE: Mode = Mode::WGRP.union(Mode::WOTH);

/// How a folder on the path is opened: never through a link.
const FOLDER: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

/// How a file in the folder is opened: never through a link, and without
/// waiting on a pipe put in its place.
const FILE: OFlags = OFlags::RDONLY
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK)
    .union(OFlags::CLOEXEC);

/// The service's folder, as checked. Dropping it closes the folder.
pub struct ProgramFolder {
    _folder: OwnedFd,
}

/// The refusal for the rule `why`, naming the folder or file `path` it
/// failed on.
pub(crate) fn refusal(why: &str, path: &Path) -> String {
    format!("{why}: {}", path.display())
}

/// What a folder or file is checked as.
#[derive(Clone, Copy)]
enum Kind {
    Folder,
    File,
}

impl Kind {
    fn not_this(self, path: &Path) -> Error {
        refuse(
            match self {
                Kind::Folder => NOT_A_FOLDER,
                Kind::File => NOT_A_FILE,
            },
            path,
        )
    }

    fn wrong_owner(self, path: &Path) -> Error {
        refuse(
            match self {
                Kind::Folder => WRONG_OWNER,
                Kind::File => FILE_OWNER,
            },
            path,
        )
    }

    fn too_open(self, path: &Path) -> Error {
        refuse(
            match self {
                Kind::Folder => TOO_OPEN,
                Kind::File => FILE_OPEN,
            },
            path,
        )
    }
}

/// Checks the folder `program` is in, the files directly in it and every
/// folder above it. The error says which rule failed and on which path.
pub fn check(program: &Path) -> Result<ProgramFolder> {
    let folder = program
        .parent()
        .filter(|folder| folder.is_absolute())
        .ok_or_else(|| refuse(NOT_FULL_PATH, program))?;
    let mut walked = PathBuf::from("/");
    let mut at = open_folder(CWD, OsStr::new("/"), &walked)?;
    for part in folder.components() {
        match part {
            Component::RootDir => {}
            Component::Normal(name) => {
                walked.push(name);
                at = open_folder(&at, name, &walked)?;
            }
            // `..` would walk back up past what was checked, and `.` is not
            // a plain path either.
            _ => return Err(refuse(NOT_FULL_PATH, program)),
        }
    }
    check_files(&at, &walked)?;
    Ok(ProgramFolder { _folder: at })
}

/// Opens and checks the folder `name` in the open folder `at`; `path` is
/// where it is, for the refusal.
fn open_folder(at: impl AsFd, name: &OsStr, path: &Path) -> Result<OwnedFd> {
    let opened = openat(at, name, FOLDER, Mode::empty()).map_err(|error| match error {
        Errno::LOOP | Errno::NOTDIR => Kind::Folder.not_this(path),
        error => cannot(error, path),
    })?;
    judge(&opened, Kind::Folder, path)?;
    Ok(opened)
}

/// Checks every entry of the open folder `folder`, at `path`, that is not a
/// folder.
fn check_files(folder: &OwnedFd, path: &Path) -> Result<()> {
    for entry in Dir::read_from(folder).map_err(|error| cannot(error, path))? {
        let entry = entry.map_err(|error| cannot(error, path))?;
        let name = entry.file_name();
        if name == c"." || name == c".." {
            continue;
        }
        let file = path.join(OsStr::from_bytes(name.to_bytes()));
        check_file(folder, name, &file)?;
    }
    Ok(())
}

/// Checks the entry `name` in the open folder `folder`: a folder is skipped,
/// a file is opened and judged, and anything else is refused. `path` is
/// where it is, for the refusal.
fn check_file(folder: &OwnedFd, name: &CStr, path: &Path) -> Result<()> {
    let found = statat(folder, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|e| cannot(e, path))?;
    match FileType::from_raw_mode(found.st_mode) {
        FileType::Directory => return Ok(()),
        FileType::RegularFile => {}
        _ => return Err(Kind::File.not_this(path)),
    }
    let opened = openat(folder, name, FILE, Mode::empty()).map_err(|error| match error {
        Errno::LOOP => Kind::File.not_this(path),
        error => cannot(error, path),
    })?;
    judge(&opened, Kind::File, path)
}

/// Whether the open folder or file `opened`, at `path`, is what `kind`
/// says, root's, and writable by root alone.
fn judge(opened: &OwnedFd, kind: Kind, path: &Path) -> Result<()> {
    let found: Stat = fstat(opened).map_err(|error| cannot(error, path))?;
    let wanted = match kind {
        Kind::Folder => FileType::Directory,
        Kind::File => FileType::RegularFile,
    };
    if FileType::from_raw_mode(found.st_mode) != wanted {
        return Err(kind.not_this(path));
    }
    if found.st_uid != 0 {
        return Err(kind.wrong_owner(path));
    }
    if Mode::from_raw_mode(found.st_mode).intersects(OTHERS_WRITE) {
        return Err(kind.too_open(path));
    }
    #[cfg(target_os = "macos")]
    if acl::allows(opened).map_err(|error| cannot(error, path))? {
        return Err(kind.too_open(path));
    }
    Ok(())
}

fn refuse(why: &str, path: &Path) -> Error {
    Error::Failed(refusal(why, path))
}

/// Any other failure: the check could not tell, so it refuses. Only the
/// error's own text is added, never anything read from the path.
fn cannot(error: impl Into<std::io::Error>, path: &Path) -> Error {
    let error: std::io::Error = error.into();
    Error::Failed(format!("{} ({error})", refusal(CANNOT_CHECK, path)))
}

/// macOS access lists, which can grant writing that the mode does not show.
#[cfg(target_os = "macos")]
mod acl {
    use std::ffi::{c_int, c_void};
    use std::io;
    use std::os::fd::{AsFd, AsRawFd};
    use std::ptr::null_mut;

    // From <sys/acl.h>.
    const ACL_TYPE_EXTENDED: c_int = 0x0000_0100;
    const ACL_FIRST_ENTRY: c_int = 0;
    const ACL_NEXT_ENTRY: c_int = -1;
    const ACL_EXTENDED_DENY: c_int = 2;

    // SAFETY: these are libSystem's declarations of the functions, with
    // `acl_t` and `acl_entry_t` as opaque pointers and the enums as `int`.
    unsafe extern "C" {
        fn acl_get_fd_np(fd: c_int, kind: c_int) -> *mut c_void;
        fn acl_get_entry(acl: *mut c_void, id: c_int, entry: *mut *mut c_void) -> c_int;
        fn acl_get_tag_type(entry: *mut c_void, tag: *mut c_int) -> c_int;
        fn acl_free(object: *mut c_void) -> c_int;
    }

    /// Frees the access list when dropped.
    struct List(*mut c_void);

    impl Drop for List {
        fn drop(&mut self) {
            // SAFETY: the list came from `acl_get_fd_np` and is freed once.
            unsafe { acl_free(self.0) };
        }
    }

    /// Whether the open folder or file `opened` has an access list entry
    /// that allows anything. Entries that only deny take rights away. Every
    /// entry is read: macOS keeps deny entries first, so an allow entry is
    /// often not the first.
    pub(super) fn allows(opened: impl AsFd) -> io::Result<bool> {
        let fd = opened.as_fd().as_raw_fd();
        // SAFETY: `fd` is open for the length of the call.
        let list = unsafe { acl_get_fd_np(fd, ACL_TYPE_EXTENDED) };
        if list.is_null() {
            let error = io::Error::last_os_error();
            // No access list at all.
            if error.raw_os_error() == Some(libc::ENOENT) {
                return Ok(false);
            }
            return Err(error);
        }
        let list = List(list);
        let mut id = ACL_FIRST_ENTRY;
        loop {
            let mut entry = null_mut();
            // SAFETY: the list is valid until dropped, and `entry` is a
            // valid out pointer.
            if unsafe { acl_get_entry(list.0, id, &mut entry) } != 0 {
                let error = io::Error::last_os_error();
                // The end of the list is EINVAL; anything else could hide
                // an entry, so the check cannot tell.
                if error.raw_os_error() == Some(libc::EINVAL) {
                    return Ok(false);
                }
                return Err(error);
            }
            id = ACL_NEXT_ENTRY;
            let mut tag: c_int = 0;
            // SAFETY: `entry` points into the list, and `tag` is a valid out
            // pointer.
            if unsafe { acl_get_tag_type(entry, &mut tag) } != 0 || tag != ACL_EXTENDED_DENY {
                return Ok(true);
            }
        }
    }
}
