//! Where the product's files and channel live, and the service's checked
//! state folder.

use std::path::{Path, PathBuf};

#[cfg(doc)]
use crate::Transport;
#[cfg(windows)]
use crate::os;
#[cfg(unix)]
use crate::unix;
use crate::{Error, Result, state_plain};

/// Whether the program runs as the installed product or in dev mode.
///
/// Dev mode exists only when the crate is built with the `dev-mode` feature,
/// which a release build never enables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// The installed service and its clients.
    Installed,
    /// A developer's unprivileged run. Everything lives in per-user places
    /// that can never collide with the installed product's.
    #[cfg(feature = "dev-mode")]
    Dev,
}

/// Where the product's files and its channel live.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    /// The folder holding `policy.json`.
    pub policy_dir: PathBuf,
    /// The folder holding `state.json`.
    pub state_dir: PathBuf,
    /// The current user's folder holding `settings.json`.
    pub settings_dir: PathBuf,
    /// The pipe or socket name to pass to [`Transport`].
    pub channel_name: String,
}

/// The service's state folder ([`Paths::state_dir`]). Everything the service
/// keeps there, such as the owner in `state.json`, is read and written
/// through this, never with plain file calls.
///
/// The folder decides who controls the service, so nobody but the system's
/// administrators may have made or changed it. An ordinary user can create a
/// folder under `ProgramData` before the service does, and would own it.
///
/// - [`StateDir::open`] creates the folder when it is missing, with an access
///   list of its own that inherits nothing: on Windows SYSTEM and the
///   Administrators group have full control, and nobody else has any. In dev
///   mode the folder is the current user's.
/// - Before every read and write, the folder, and the file read, must be
///   owned by SYSTEM, Administrators or TrustedInstaller (in dev mode, the
///   current user), and no one else may be allowed to write to it. If not,
///   the call fails and says why. It never takes ownership of a folder or
///   changes its access list to make it pass: an administrator must remove
///   such a folder.
///
/// On macOS and Linux the rule is the same. Installed, the folder, every
/// folder above it and the file read are real (no links), root's, and
/// writable by root alone. In dev mode the folder and the file are the
/// current user's and writable by them alone. Files are written with mode
/// 0600.
#[derive(Debug, Clone)]
pub struct StateDir {
    mode: Mode,
    path: PathBuf,
    checked: bool,
}

impl StateDir {
    /// The state folder for `mode`, created if missing and then checked.
    pub fn open(mode: Mode, paths: &Paths) -> Result<Self> {
        let path = paths.state_dir.clone();
        #[cfg(windows)]
        os::state::prepare(mode, &path)?;
        #[cfg(unix)]
        unix::state::prepare(mode, &path)?;
        Ok(Self {
            mode,
            path,
            checked: true,
        })
    }

    /// A folder with no checks at all, for tests and the fake's dev mode.
    #[cfg(any(test, feature = "fake"))]
    pub fn unchecked(path: &Path) -> Result<Self> {
        state_plain::prepare(path)?;
        Ok(Self {
            mode: Mode::Installed,
            path: path.to_path_buf(),
            checked: false,
        })
    }

    /// Where the folder is, for messages.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// A folder for temporary files, inside this one, made and checked by
    /// the same rules. The service points the VPN library's temporary files
    /// here: a system-wide temporary folder such as `C:\Windows\Temp` lets
    /// ordinary users create files in it.
    pub fn temp_dir(&self) -> Result<PathBuf> {
        let path = self.path.join("temp");
        if self.checked {
            #[cfg(windows)]
            os::state::prepare(self.mode, &path)?;
            // Nothing uses it on macOS and Linux yet, so it is made closed.
            #[cfg(unix)]
            unix::state::prepare_private(self.mode, &self.path, &path)?;
            return Ok(path);
        }
        state_plain::prepare(&path)?;
        Ok(path)
    }

    /// The file's whole contents, or `None` when there is no such file.
    pub fn read(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let file = self.file(name)?;
        if self.checked {
            #[cfg(windows)]
            return os::state::read(self.mode, &self.path, &file);
            #[cfg(unix)]
            return unix::state::read(self.mode, &self.path, &file);
        }
        state_plain::read(&file)
    }

    /// Replaces the file's contents. A crash leaves the old contents or the
    /// new, never part of either.
    pub fn write(&self, name: &str, bytes: &[u8]) -> Result<()> {
        let file = self.file(name)?;
        let fresh = self.path.join(format!(".{name}.new"));
        if self.checked {
            // Held open until the file is in place.
            #[cfg(windows)]
            let _held = os::state::check_folder(self.mode, &self.path)?;
            // Once the folder passes, only root, or in dev mode the current
            // user, can put anything in it.
            #[cfg(unix)]
            unix::state::check_folder(self.mode, &self.path)?;
            return state_plain::write(&file, &fresh, bytes);
        }
        state_plain::write(&file, &fresh, bytes)
    }

    /// `name` inside the folder. It must be a plain file name.
    fn file(&self, name: &str) -> Result<PathBuf> {
        let plain = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_');
        if name.is_empty() || name.starts_with('.') || !name.chars().all(plain) {
            return Err(Error::Failed("not a state file name".to_string()));
        }
        Ok(self.path.join(name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The state folder takes plain file names only, and replaces a file
    // whole.
    #[test]
    fn the_state_folder_reads_and_replaces_plain_files_only() {
        let dir = std::env::temp_dir().join(format!("ubc-vpn-state-{}", std::process::id()));
        let state = StateDir::unchecked(&dir).unwrap();
        assert_eq!(state.read("state.json"), Ok(None));
        state.write("state.json", b"{\"owner\":\"a\"}").unwrap();
        state.write("state.json", b"{}").unwrap();
        assert_eq!(state.read("state.json"), Ok(Some(b"{}".to_vec())));
        for bad in [
            "",
            ".",
            "..",
            "../state.json",
            "a/b",
            "a\\b",
            ".state.json.new",
        ] {
            assert!(state.read(bad).is_err(), "{bad:?}");
            assert!(state.write(bad, b"").is_err(), "{bad:?}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
