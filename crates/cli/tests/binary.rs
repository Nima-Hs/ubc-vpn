//! The command-line client itself, run as a program.
//!
//! Security rule: no test may ever reach the service installed on the
//! machine it runs on. Every run here points the program at a channel that
//! this run alone names and nobody serves, with `UBC_VPN_TEST_CHANNEL`. Only
//! a debug build takes that, so in a release build a test that could reach a
//! service runs only on CI, whose machines have no service installed.

use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

const TEST_CHANNEL: &str = "UBC_VPN_TEST_CHANNEL";

/// A channel name for this run alone, which nobody serves.
fn unserved() -> String {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let n = NEXT.fetch_add(1, Ordering::SeqCst);
    let id = std::process::id();
    if cfg!(windows) {
        format!("ubc-vpn-test-{id}-{n}")
    } else {
        format!("/tmp/ubc-vpn-test-{id}-{n}/service.sock")
    }
}

/// Whether a test that could reach a service may run: always in a debug
/// build, which takes the channel it is given; in a release build only on
/// CI. Says why when it may not.
fn may_reach_a_service() -> bool {
    if cfg!(debug_assertions) || std::env::var_os("CI").is_some() {
        return true;
    }
    println!(
        "SKIPPED: a release build cannot be pointed away from the installed service, \
         so this runs on CI only"
    );
    false
}

/// The program, pointed at a channel nobody serves.
fn program() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ubc-vpn"));
    command.env(TEST_CHANNEL, unserved());
    command
}

/// Runs the program and returns its exit status and what it printed.
fn run(args: &[&str]) -> (Option<i32>, String, String) {
    let output = program().args(args).output().unwrap();
    let text = |bytes: &[u8]| String::from_utf8_lossy(bytes).into_owned();
    (
        output.status.code(),
        text(&output.stdout),
        text(&output.stderr),
    )
}

// Security rule (architecture): dev mode is compiled out of a build without
// the `dev-mode` feature, so such a build does not know the flag.
#[cfg(not(feature = "dev-mode"))]
#[test]
fn a_build_without_dev_mode_rejects_the_dev_flag() {
    for args in [&["--dev", "version"][..], &["--dev", "connect"], &["--dev"]] {
        let (status, out, err) = run(args);
        assert_eq!((status, out.as_str()), (Some(2), ""), "{args:?}");
        assert!(err.contains("Usage:"), "{err}");
    }
    assert_eq!(run(&["version"]).0, Some(0));
}

// With the feature the flag is known, and only as the first argument.
#[cfg(feature = "dev-mode")]
#[test]
fn a_build_with_dev_mode_knows_the_dev_flag() {
    let (status, out, _) = run(&["--dev", "version"]);
    assert_eq!(status, Some(0));
    assert!(out.starts_with("ubc-vpn "), "{out}");
    assert_eq!(run(&["version", "--dev"]).0, Some(2));
}

// Security rule: a password is never read from a pipe or a file. Here
// standard input is not a terminal, so `connect` says so and does nothing:
// it asks no question and talks to no service.
#[test]
fn connect_outside_a_terminal_asks_nothing() {
    let (status, out, err) = run(&["connect"]);
    assert_eq!((status, out.as_str()), (Some(1), ""));
    assert!(
        err.contains("Run it in a terminal, or use the app."),
        "{err}"
    );
}

// `connect --json` answers in JSON lines whatever happens. Here it cannot
// connect: this build has no engine, or this machine no policy. Standard
// input is empty, which it must survive.
#[test]
fn connect_for_the_app_ends_with_one_error_line() {
    let (status, out, _) = run(&["connect", "--json"]);
    assert!(!matches!(status, Some(0 | 2)), "{status:?}");
    assert_eq!(out.lines().count(), 1, "{out}");
    assert!(out.starts_with(r#"{"type":"error","code":""#), "{out}");
    // Only this spelling is the command.
    for args in [&["connect", "--json", "more"][..], &["connect", "json"]] {
        assert_eq!(run(args).0, Some(2), "{args:?}");
    }
}

// A Windows profile that has no roaming folder yet has no settings yet:
// `get` answers the defaults, and `set-routes` creates the folder and the
// file. The profile is an empty folder made for the test.
#[cfg(windows)]
#[test]
fn a_profile_with_no_roaming_folder_has_default_settings() {
    use std::io::Write;
    use std::process::Stdio;

    // Saving routes also offers them to a live connection.
    if !may_reach_a_service() {
        return;
    }
    let profile = std::env::temp_dir().join(format!("ubc-vpn-cli-profile-{}", std::process::id()));
    std::fs::create_dir_all(&profile).unwrap();
    let settings = |command: &str, typed: &str| {
        let mut child = program()
            .args(["settings", command, "--json"])
            .env("USERPROFILE", &profile)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(typed.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        (
            output.status.code(),
            String::from_utf8_lossy(&output.stdout).into_owned(),
        )
    };
    let (status, shown) = settings("get", "");
    let nothing_made = std::fs::read_dir(&profile).unwrap().next().is_none();
    let typed = "{\"subnets\":[\"10.19.0.0/16\"],\"dns_domains\":[]}\n";
    let (saved_status, saved) = settings("set-routes", typed);
    let (_, after) = settings("get", "");
    let file = profile.join(r"AppData\Roaming\UBC VPN\settings.json");
    let written = std::fs::read_to_string(&file);
    std::fs::remove_dir_all(&profile).unwrap();

    assert_eq!(status, Some(0), "{shown}");
    assert!(
        shown.contains(r#""subnets":[]"#) && !shown.contains("error"),
        "{shown}"
    );
    assert!(nothing_made, "get created something in the profile");
    assert_eq!(saved_status, Some(0), "{saved}");
    // Nobody serves its channel, so there is no connection to change.
    assert!(
        saved.contains(r#""live":{"result":"next_connect"}"#),
        "{saved}"
    );
    assert!(
        written.is_ok_and(|text| text.contains("10.19.0.0/16")),
        "{file:?}"
    );
    assert!(after.contains("10.19.0.0/16"), "{after}");
}

// Security rule: a test's run of the program talks to the channel the test
// names and to no other, so a service installed on the machine is never
// reached. Here the test serves that channel itself: the program comes to
// it, not to the installed service's channel.
#[cfg(all(windows, debug_assertions, feature = "dev-mode"))]
#[test]
fn a_test_run_talks_to_the_channel_it_is_given() {
    use std::io::Write;
    use std::process::Stdio;
    use std::sync::mpsc;
    use std::time::Duration;

    let channel = unserved();
    // Served as this user, as a dev-mode service serves its channel.
    let platform = ubc_vpn_platform::Platform::native(ubc_vpn_platform::Mode::Dev).unwrap();
    let listener = platform.transport.listen(&channel).unwrap();
    let (came, arrived) = mpsc::channel();
    std::thread::spawn(move || {
        if let Ok((conn, _)) = listener.accept() {
            let hello = conn.read_line().ok().flatten();
            let _ = came.send(hello);
        }
    });
    let settings = std::env::temp_dir().join(format!("ubc-vpn-cli-guard-{}", std::process::id()));
    std::fs::create_dir_all(&settings).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_ubc-vpn"))
        .args(["settings", "set-routes", "--json"])
        .env(TEST_CHANNEL, &channel)
        .env("USERPROFILE", &settings)
        .env("HOME", &settings)
        .env("XDG_CONFIG_HOME", &settings)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let typed = "{\"subnets\":[\"10.19.0.0/16\"],\"dns_domains\":[]}\n";
    child
        .stdin
        .take()
        .unwrap()
        .write_all(typed.as_bytes())
        .unwrap();
    let hello = arrived.recv_timeout(Duration::from_secs(30));
    let output = child.wait_with_output().unwrap();
    let _ = std::fs::remove_dir_all(&settings);
    let saved = String::from_utf8_lossy(&output.stdout);
    // It came here. (It then says nothing: this channel is not served by
    // the service, which the program checks before it sends anything.)
    assert!(
        hello.is_ok(),
        "the program never came to the channel it was given"
    );
    // So nothing was applied anywhere.
    assert!(!saved.contains(r#""result":"applied""#), "{saved}");
}

/// A 64-bit Windows program, read for what its headers say about loading.
#[cfg(all(windows, target_env = "msvc"))]
struct Image(Vec<u8>);

#[cfg(all(windows, target_env = "msvc"))]
impl Image {
    fn read(program: &std::path::Path) -> Self {
        let image = Self(std::fs::read(program).unwrap());
        let pe = image.u32_at(0x3c) as usize;
        assert_eq!(&image.0[pe..pe + 4], b"PE\0\0", "not a Windows program");
        assert_eq!(
            image.u16_at(image.optional()),
            0x20b,
            "not a 64-bit program"
        );
        image
    }

    fn u16_at(&self, at: usize) -> u16 {
        u16::from_le_bytes([self.0[at], self.0[at + 1]])
    }

    fn u32_at(&self, at: usize) -> u32 {
        u32::from_le_bytes(self.0[at..at + 4].try_into().unwrap())
    }

    /// Where the optional header starts, after the signature and COFF header.
    fn optional(&self) -> usize {
        self.u32_at(0x3c) as usize + 4 + 20
    }

    /// The file offset of data directory `index`: its start and size. A
    /// 64-bit program's directories start 112 bytes into its optional header.
    fn directory(&self, index: usize) -> (usize, u32) {
        let entry = self.optional() + 112 + index * 8;
        let (rva, size) = (self.u32_at(entry), self.u32_at(entry + 4));
        assert!(size > 0, "the program has no data directory {index}");
        (self.offset(rva), size)
    }

    /// The file offset of a relative virtual address.
    fn offset(&self, rva: u32) -> usize {
        let coff = self.u32_at(0x3c) as usize + 4;
        let sections = usize::from(self.u16_at(coff + 2));
        let table = self.optional() + usize::from(self.u16_at(coff + 16));
        for section in (0..sections).map(|n| table + n * 40) {
            let (length, address, raw) = (
                self.u32_at(section + 8),
                self.u32_at(section + 12),
                self.u32_at(section + 20),
            );
            if (address..address + length).contains(&rva) {
                return (rva - address + raw) as usize;
            }
        }
        panic!("address {rva:#x} is in no section");
    }

    /// The names of the DLLs the program imports (directory 1), in lower
    /// case. Each import descriptor is 20 bytes, the name's address at 12,
    /// and an all-zero one ends the list.
    fn imports(&self) -> Vec<String> {
        let (mut descriptor, _) = self.directory(1);
        let mut names = Vec::new();
        while self.u32_at(descriptor + 12) != 0 {
            let start = self.offset(self.u32_at(descriptor + 12));
            let end = start + self.0[start..].iter().position(|&b| b == 0).unwrap();
            names.push(String::from_utf8_lossy(&self.0[start..end]).to_lowercase());
            descriptor += 20;
        }
        names
    }

    /// `DependentLoadFlags` from the load configuration (directory 10): where
    /// Windows looks for the DLLs the program imports. It sits at offset 78
    /// of IMAGE_LOAD_CONFIG_DIRECTORY64, whose first field is its size.
    fn dependent_load_flags(&self) -> u16 {
        let (config, _) = self.directory(10);
        assert!(
            self.u32_at(config) >= 80,
            "the load configuration is too short"
        );
        self.u16_at(config + 78)
    }
}

// Security rule: the program's own imports come from its own folder and
// System32 only, never the working folder or PATH (build.rs). Exactly that:
// System32 alone would miss the bundled runtime, and any other place is one
// the install does not control.
#[cfg(all(windows, target_env = "msvc"))]
#[test]
fn imports_are_loaded_from_its_folder_and_system32_only() {
    let program = Image::read(std::path::Path::new(env!("CARGO_BIN_EXE_ubc-vpn")));
    assert_eq!(program.dependent_load_flags(), 0xA00);
}

// The Visual C++ runtime the program imports is exactly what the installer
// bundles (packaging/windows/vcruntime.lock): vcruntime140.dll and nothing
// else, such as vcruntime140_1.dll or msvcp140.dll. The Universal C Runtime
// is part of Windows and is not bundled.
#[cfg(all(windows, target_env = "msvc"))]
#[test]
fn the_runtime_it_imports_is_the_bundled_one() {
    let program = Image::read(std::path::Path::new(env!("CARGO_BIN_EXE_ubc-vpn")));
    let bundled = ["vcruntime140.dll"];
    let runtime: Vec<String> = program
        .imports()
        .into_iter()
        .filter(|name| {
            ["vcruntime", "msvcp", "concrt", "vccorlib"]
                .iter()
                .any(|p| name.starts_with(p))
        })
        .collect();
    assert_eq!(
        runtime, bundled,
        "update packaging/windows/vcruntime.lock to match"
    );
}
