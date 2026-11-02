//! The installed service's own folder on Linux and macOS.
//!
//! The rule is the one `docs/architecture.md` gives for every OS: the
//! installed service runs only from a folder that root alone can change,
//! with no links on the way, inside folders that no one else could swap.
//!
//! Not built yet. Until it is, [`check`] refuses every folder with
//! [`Error::Unsupported`], so the installed service does not run at all on
//! these systems: a check that cannot tell fails closed. Dev mode, which
//! runs unprivileged from a build folder, never asks.

use std::path::Path;

use crate::{Error, Result};

/// The service's folder and the folders above it, as checked. Dropping it
/// lets them go.
pub struct ProgramFolder {
    _private: (),
}

/// Checks the folder `program` is in, the files directly in it and every
/// folder above it. For now it refuses every one.
pub fn check(_program: &Path) -> Result<ProgramFolder> {
    Err(Error::Unsupported)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Security rule: until the check is built, no folder passes it, not even
    // the root folder, which only root can change.
    #[test]
    fn every_folder_is_refused_until_the_check_is_built() {
        for program in [
            "/ubc-vpn-service",
            "/opt/UBC VPN/ubc-vpn-service",
            "relative",
        ] {
            let checked = check(Path::new(program));
            assert_eq!(checked.err(), Some(Error::Unsupported), "{program}");
        }
    }
}
