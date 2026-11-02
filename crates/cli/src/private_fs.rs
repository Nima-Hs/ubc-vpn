//! The settings files' permissions: the folder `ubc-vpn settings` uses, the
//! settings file, and the lock file beside it, each the user's alone on
//! Unix.
//!
//! `docs/architecture.md` keeps OS-specific code in the platform crate,
//! `native/` and `packaging/`. This file is the command-line client's
//! exception, kept here on purpose and in this file only, so that it stays
//! in one place: it is the standard library's own Unix permission bits and
//! open options, with no unsafe code, and a platform operation for it would
//! be more code than these lines.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::Path;

/// Why the settings folder is not used, when it is not. On Unix that is a
/// folder its group, or anyone, may write to: whoever can write there can
/// replace the settings, and with them the routes the next connect asks
/// for. A link is judged by the folder it leads to, which is the one used. On Windows a folder takes its access list from the profile it is in,
/// and nothing is checked.
pub(crate) fn folder_problem(dir: &Path) -> Option<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let open = |found: fs::Metadata| found.permissions().mode() & 0o022 != 0;
        if fs::metadata(dir).is_ok_and(open) {
            // Quoted for a shell as it stands, whatever the path holds.
            let folder = crate::clean(&dir.to_string_lossy()).replace('\'', r"'\''");
            return Some(format!(
                "The settings folder can be changed by other users of this computer, so it \
                 is not used. To stop them, run: chmod go-w '{folder}'"
            ));
        }
    }
    let _ = dir;
    None
}

/// Makes the settings folder if it is not there. On Unix a folder made here
/// is the user's alone, mode 0700, whatever the umask; one that is already
/// there is left as it is, and must pass [`folder_problem`].
pub(crate) fn create_folder(dir: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(dir)?;
    match folder_problem(dir) {
        Some(_) => Err(io::ErrorKind::PermissionDenied.into()),
        None => Ok(()),
    }
}

/// Opens a new file for the settings. On Unix it is created with mode 0600,
/// whatever the umask, so only the user can read it. On Windows a new file
/// takes the access list of the folder it is in, whatever that is: under a
/// user's profile that is usually the user, administrators and the system,
/// and on a domain machine it can include other accounts. The file holds
/// the username and the routes, and no secret.
pub(crate) fn create_private(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)
}

/// Opens the lock file for writing, making it if it is not there and
/// keeping what it holds if it is. As for the settings file itself: one
/// made here is the user's alone on Unix, mode 0600, whatever the umask.
pub(crate) fn open_private(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(false);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)
}
