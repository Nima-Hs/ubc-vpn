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
    /// Whether the data folder is already there with an owner the service
    /// would accept (see [`holds_an_owner`]). Asked only before a fresh
    /// install.
    fn holds_an_owner(&mut self) -> bool;
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
///
/// A fresh install keeps a data folder that holds an owner, and goes on as
/// an update would. An update that fails is undone, and the undo keeps the
/// data folder but removes the record of the install, so the setup program
/// run next counts as a first install. Emptying the folder then would reset
/// the owner, and anyone who could make an update fail could have the
/// service claimed afresh. Only the administrators can make a folder that
/// passes, so anything else is still emptied.
pub fn install(steps: &mut impl Steps, policy: &[u8], fresh: bool) -> Result<(), String> {
    let fresh = fresh && !steps.holds_an_owner();
    steps.prepare_data_folder(fresh)?;
    steps.write_policy(policy)?;
    steps.verify_data_folder(fresh)?;
    steps.register()?;
    steps.start()
}

/// Whether `state` holds an owner in a `state.json` the service would
/// accept. It is read through [`StateDir`], so on Windows the folder and
/// the file must be owned by the administrators and changeable by them
/// alone, as the service requires; a folder or file anyone else made or
/// could change, a damaged file, or no file at all is `false`.
///
/// [`StateDir`]: ubc_vpn_platform::StateDir
pub fn holds_an_owner(state: &ubc_vpn_platform::StateDir) -> bool {
    matches!(crate::owner::load(state), Ok(Some(_)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Records the steps taken, and fails the one named in `fail`.
    #[derive(Default)]
    struct Recorded {
        taken: Vec<String>,
        fail: Option<&'static str>,
        // What `holds_an_owner` answers.
        owner: bool,
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
        fn holds_an_owner(&mut self) -> bool {
            self.taken.push("check owner".to_string());
            self.owner
        }
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
            "check owner",
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
            [
                "check owner",
                "prepare fresh",
                "write policy",
                "verify fresh"
            ]
        );
    }

    // Security rule: a fresh install over a data folder that holds an owner,
    // as a failed and undone update leaves it, keeps the folder and goes on
    // as an update, so the owner is not reset (issue #184).
    #[test]
    fn a_fresh_install_keeps_a_folder_that_holds_an_owner() {
        let mut steps = Recorded {
            owner: true,
            ..Recorded::default()
        };
        install(&mut steps, b"{}", true).unwrap();
        let all = [
            "check owner",
            "prepare",
            "write policy",
            "verify",
            "register",
            "start",
        ];
        assert_eq!(steps.taken, all);
    }

    // Only a state.json with an owner the service would read counts.
    #[test]
    fn only_a_valid_owner_counts() {
        let dir = std::env::temp_dir().join(format!("ubc-vpn-owner-{}", std::process::id()));
        let state = ubc_vpn_platform::StateDir::unchecked(&dir).unwrap();
        assert!(!holds_an_owner(&state), "no state.json");
        let cases: [(&[u8], bool); 5] = [
            (br#"{"owner":"S-1-5-21-1-2-3-1001"}"#, true),
            (b"{}", false),
            (br#"{"owner":""}"#, false),
            (br#"{"owner":"has space"}"#, false),
            (b"not json", false),
        ];
        for (bytes, expected) in cases {
            state.write("state.json", bytes).unwrap();
            assert_eq!(
                holds_an_owner(&state),
                expected,
                "{}",
                String::from_utf8_lossy(bytes)
            );
        }
        std::fs::remove_dir_all(&dir).unwrap();
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
