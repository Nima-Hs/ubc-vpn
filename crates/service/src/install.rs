//! What the setup program's `install` and `uninstall` commands need besides
//! the OS calls in `ubc_vpn_platform::install`: the service's names, and the
//! policy file it brings, read and checked before anything is changed.

use std::path::Path;

/// The name the service manager knows the service by.
pub const SERVICE_NAME: &str = "ubc-vpn";

/// The name shown in the Services console.
pub const DISPLAY_NAME: &str = "UBC VPN Service";

/// The text shown beside it.
pub const DESCRIPTION: &str = "Opens the UBC VPN tunnel and applies its routes and DNS for the \
    UBC VPN app. Not made by or affiliated with the University of British Columbia.";

/// The policy file at `path`, after checking it is a valid policy, as the
/// bytes to install. An invalid one is refused before anything is changed.
pub fn read_policy(path: &Path) -> Result<Vec<u8>, String> {
    let bytes = std::fs::read(path)
        .map_err(|e| format!("The policy file to install cannot be read: {}.", e.kind()))?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| "The policy file to install is not valid: it is not UTF-8.".to_string())?;
    crate::policy::parse(text)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn written(name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("ubc-vpn-{name}-{}", std::process::id()));
        std::fs::write(&path, bytes).unwrap();
        path
    }

    #[test]
    fn a_valid_policy_is_installed_as_it_is() {
        let text = br#"{"gateway":"vpn.example.test","pins":["pin-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="]}"#;
        let path = written("good-policy", text);
        assert_eq!(read_policy(&path).unwrap(), text);
        std::fs::remove_file(path).unwrap();
    }

    // Security rule: the setup program never installs a policy the service
    // would refuse, such as one with no pins.
    #[test]
    fn an_invalid_policy_is_refused() {
        let bad: [&[u8]; 4] = [
            br#"{"gateway":"vpn.example.test","pins":[]}"#,
            br#"{"gateway":"https://vpn.example.test","pins":["pin-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="]}"#,
            b"not json",
            b"\xff\xfe",
        ];
        for (n, bytes) in bad.into_iter().enumerate() {
            let path = written(&format!("bad-policy-{n}"), bytes);
            let refused = read_policy(&path);
            std::fs::remove_file(path).unwrap();
            assert!(refused.unwrap_err().contains("not valid"), "case {n}");
        }
        let missing = std::env::temp_dir().join("ubc-vpn-no-such-policy");
        assert!(
            read_policy(&missing)
                .unwrap_err()
                .contains("cannot be read")
        );
    }
}
