//! Shared logic and channel message types.
//!
//! This crate holds everything the service, the command-line client and the
//! app agree on. It contains no OS-specific code and no unsafe code.

pub mod bridge;
pub mod login;
pub mod policy;
pub mod protocol;
pub mod redact;
pub mod routes;
pub mod settings;
pub mod settings_cli;
pub mod state;

/// The product version, taken from the workspace.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::VERSION;

    #[test]
    fn version_is_semver() {
        let parts: Vec<&str> = VERSION.split('.').collect();
        assert_eq!(parts.len(), 3, "expected MAJOR.MINOR.PATCH, got {VERSION}");
        assert!(parts.iter().all(|p| p.parse::<u32>().is_ok()));
    }
}
