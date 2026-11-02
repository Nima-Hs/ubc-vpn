//! Installing and removing the service on Linux and macOS: its registration
//! with launchd or systemd, and the folder that holds the policy and the
//! state.
//!
//! The packages' scripts run `ubc-vpn-service install` and `uninstall` as
//! root, as the Windows setup program does, and the service crate decides
//! the order there too. The calls are the ones Windows has, so that the
//! service crate's steps are the same on every OS.
//!
//! Not built yet: each call changes nothing and fails with
//! [`Error::Unsupported`]. The launchd daemon and the systemd unit come
//! with the macOS and Linux installers.

use std::path::Path;

use crate::{Error, Result};

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

/// Makes the data folder, or on a `fresh` install empties one that is
/// already there. Not built yet.
pub fn prepare_data_folder(_dir: &Path, _fresh: bool) -> Result<()> {
    Err(Error::Unsupported)
}

/// Writes `policy` into the data folder. Not built yet.
pub fn write_policy(_dir: &Path, _policy: &[u8]) -> Result<()> {
    Err(Error::Unsupported)
}

/// Checks the data folder is as it was set up. Not built yet.
pub fn verify_data_folder(_dir: &Path, _fresh: bool) -> Result<()> {
    Err(Error::Unsupported)
}

/// Removes the data folder and everything in it. Not built yet.
pub fn remove_data_folder(_dir: &Path) -> Result<()> {
    Err(Error::Unsupported)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Until it is built, nothing here claims to have done anything.
    #[test]
    fn every_call_is_unsupported_until_it_is_built() {
        let dir = Path::new("/nonexistent/ubc-vpn-test");
        let registration = Registration {
            name: "made-up",
            display_name: "Made Up",
            description: "made up",
            command_line: String::new(),
        };
        let results = [
            quoted(dir).map(drop),
            register(&registration),
            start("made-up"),
            unregister("made-up"),
            prepare_data_folder(dir, true),
            write_policy(dir, b"{}"),
            verify_data_folder(dir, true),
            remove_data_folder(dir),
        ];
        for (n, result) in results.into_iter().enumerate() {
            assert_eq!(result, Err(Error::Unsupported), "call {n}");
        }
    }
}
