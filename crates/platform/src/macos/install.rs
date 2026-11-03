//! Installing and removing the service on macOS: its registration with
//! launchd, and the folder that holds the policy and the state.
//!
//! The package's scripts run `ubc-vpn-service install` and `uninstall` as
//! root, as the Windows setup program does, and the service crate decides
//! the order there too. The calls are the ones Windows has, so that the
//! service crate's steps are the same on every OS.
//!
//! **The data folder.** `/Library/Application Support/UBC VPN` holds the
//! policy, the state and the channel's socket, so every user's client must
//! reach it and only root may change it: root's, 0755, with `policy.json`
//! root's, 0644. On a fresh install it is emptied, since anyone may have made
//! it; on an update its contents are kept. Because the state is in it, a
//! folder that is there already is never fixed: one that others could change
//! cannot be trusted afterwards, so the check after it fails and the install
//! stops (see `unix::state`).
//!
//! Not built yet: registering with launchd. Those calls change nothing and
//! fail with [`Error::Unsupported`], and `quoted` is the first of them that
//! `ubc-vpn-service install` makes, so it stops before anything is changed.

use std::path::Path;

use crate::unix::root_files::{
    Expected, check_root, clear, make_root_folder, names_in, real_folder, write_root_file,
};
use crate::{Error, Mode, Result};

/// The policy file's name in the data folder.
const POLICY: &str = "policy.json";

/// The data folder: every user reads the policy and reaches the channel.
const FOLDER_MODE: u32 = 0o755;
/// `policy.json`: root writes it, every user reads it.
const POLICY_MODE: u32 = 0o644;

/// What the service is registered as.
pub struct Registration<'a> {
    /// The name the service manager knows it by.
    pub name: &'a str,
    /// The name shown to people.
    pub display_name: &'a str,
    /// The text shown beside it.
    pub description: &'a str,
    /// The full command line, the program's path quoted.
    pub command_line: String,
}

/// The command line for `program` with no arguments. Not built yet.
pub fn quoted(_program: &Path) -> Result<String> {
    Err(Error::Unsupported)
}

/// Registers the service to start with the system. Not built yet.
pub fn register(_registration: &Registration) -> Result<()> {
    Err(Error::Unsupported)
}

/// Starts the registered service. Not built yet.
pub fn start(_name: &str) -> Result<()> {
    Err(Error::Unsupported)
}

/// Stops the service, which removes its routes and DNS first, and removes
/// its registration. Not built yet.
pub fn unregister(_name: &str) -> Result<()> {
    Err(Error::Unsupported)
}

/// Makes the data folder `dir`, or on a `fresh` install empties it first. A
/// folder that is kept is left as it is found: [`verify_data_folder`] judges
/// it.
pub fn prepare_data_folder(dir: &Path, fresh: bool) -> Result<()> {
    if fresh {
        clear(dir)?;
    }
    if !real_folder(dir)? {
        make_root_folder(dir, FOLDER_MODE)?;
    }
    Ok(())
}

/// Writes `policy` as `policy.json` in the data folder `dir`.
pub fn write_policy(dir: &Path, policy: &[u8]) -> Result<()> {
    write_root_file(dir, POLICY, policy, POLICY_MODE)
}

/// Checks the data folder `dir` once it is prepared and the policy written,
/// as the service and the client will check it, and after a fresh install
/// that it holds the policy alone.
pub fn verify_data_folder(dir: &Path, fresh: bool) -> Result<()> {
    // The folder and every folder above it are root's and changed by root
    // alone: the same check the service makes of its state folder.
    crate::unix::state::check_folder(Mode::Installed, dir)
        .map_err(|error| Error::Failed(format!("{}: {error}", dir.display())))?;
    check_root(dir, Expected::Folder, FOLDER_MODE)?;
    check_root(&dir.join(POLICY), Expected::File, POLICY_MODE)?;
    if fresh {
        let found = names_in(dir)?;
        if found != [POLICY] {
            let extra: Vec<String> = found.into_iter().filter(|name| name != POLICY).collect();
            return Err(Error::Failed(format!(
                "the data folder holds {} as well as the policy, so something else made or \
                 changed it during the install",
                extra.join(", ")
            )));
        }
    }
    Ok(())
}

/// Removes the data folder `dir` and everything in it. A missing folder is
/// fine.
pub fn remove_data_folder(dir: &Path) -> Result<()> {
    clear(dir)
}

#[cfg(test)]
#[path = "install_tests.rs"]
mod tests;
