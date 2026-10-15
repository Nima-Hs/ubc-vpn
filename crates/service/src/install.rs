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

/// What `install` does to the system, one call per step. The Windows
/// implementation is in the service binary; the order and the stopping
/// points are here, in [`install`], where they are tested.
pub trait Steps {
    /// Makes the data folder, emptied first when `fresh`, with its access list.
    fn prepare_data_folder(&mut self, fresh: bool) -> Result<(), String>;
    /// Writes the policy into it.
    fn write_policy(&mut self, policy: &[u8]) -> Result<(), String>;
    /// Checks the folder as the service will, and when `fresh` that it holds
    /// the policy alone.
    fn verify_data_folder(&mut self, fresh: bool) -> Result<(), String>;
    /// Registers the service, or brings its registration up to date.
    fn register(&mut self) -> Result<(), String>;
    /// Starts it and waits until it runs.
    fn start(&mut self) -> Result<(), String>;
}

/// Installs, with `policy` already read and checked: the data folder and the
/// policy in it, then the check of that folder, and only then the service,
/// which is started. The first step that fails stops it there, so a data
/// folder that is not as it was set up never gets a service registered.
pub fn install(steps: &mut impl Steps, policy: &[u8], fresh: bool) -> Result<(), String> {
    steps.prepare_data_folder(fresh)?;
    steps.write_policy(policy)?;
    steps.verify_data_folder(fresh)?;
    steps.register()?;
    steps.start()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Records the steps taken, and fails the one named in `fail`.
    #[derive(Default)]
    struct Recorded {
        taken: Vec<String>,
        fail: Option<&'static str>,
    }

    impl Recorded {
        fn step(&mut self, name: &str) -> Result<(), String> {
            self.taken.push(name.to_string());
            match self.fail == Some(name) {
                true => Err(format!("{name} failed")),
                false => Ok(()),
            }
        }
    }

    impl Steps for Recorded {
        fn prepare_data_folder(&mut self, fresh: bool) -> Result<(), String> {
            self.step(if fresh { "prepare fresh" } else { "prepare" })
        }
        fn write_policy(&mut self, _policy: &[u8]) -> Result<(), String> {
            self.step("write policy")
        }
        fn verify_data_folder(&mut self, fresh: bool) -> Result<(), String> {
            self.step(if fresh { "verify fresh" } else { "verify" })
        }
        fn register(&mut self) -> Result<(), String> {
            self.step("register")
        }
        fn start(&mut self) -> Result<(), String> {
            self.step("start")
        }
    }

    #[test]
    fn installs_in_order() {
        let mut steps = Recorded::default();
        install(&mut steps, b"{}", true).unwrap();
        let all = [
            "prepare fresh",
            "write policy",
            "verify fresh",
            "register",
            "start",
        ];
        assert_eq!(steps.taken, all);
        let mut steps = Recorded::default();
        install(&mut steps, b"{}", false).unwrap();
        assert_eq!(
            steps.taken,
            ["prepare", "write policy", "verify", "register", "start"]
        );
    }

    // Security rule: a data folder that is not as it was set up, such as one
    // something else made or wrote to during a fresh install, stops the
    // install before the service is registered.
    #[test]
    fn a_data_folder_that_fails_its_check_gets_no_service() {
        let mut steps = Recorded {
            fail: Some("verify fresh"),
            ..Recorded::default()
        };
        assert_eq!(
            install(&mut steps, b"{}", true),
            Err("verify fresh failed".to_string())
        );
        assert_eq!(
            steps.taken,
            ["prepare fresh", "write policy", "verify fresh"]
        );
    }

    // Any step that fails is the last one taken.
    #[test]
    fn a_failed_step_is_the_last() {
        for fail in ["prepare fresh", "write policy", "register", "start"] {
            let mut steps = Recorded {
                fail: Some(fail),
                ..Recorded::default()
            };
            assert!(install(&mut steps, b"{}", true).is_err());
            assert_eq!(steps.taken.last().map(String::as_str), Some(fail));
        }
    }

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

    // The policy the Windows setup program ships is one the service accepts,
    // for UBC's gateway, with exactly one pin.
    #[test]
    fn the_shipped_policy_is_valid() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../packaging/windows/policy.json");
        let bytes = read_policy(&path).unwrap();
        let policy = crate::policy::parse(std::str::from_utf8(&bytes).unwrap()).unwrap();
        assert_eq!(policy.gateway, "myvpn.ubc.ca");
        assert_eq!(policy.pins.len(), 1);
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
