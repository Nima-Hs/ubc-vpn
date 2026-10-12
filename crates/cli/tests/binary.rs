//! The command-line client itself, run as a program. Only commands that
//! talk to no service and read no input are run here.

use std::process::Command;

/// Runs the program and returns its exit status and what it printed.
fn run(args: &[&str]) -> (Option<i32>, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_ubc-vpn"))
        .args(args)
        .output()
        .unwrap();
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

// Until the terminal can be read with nothing shown, `connect` says so and
// does nothing: it asks no question and talks to no service.
#[test]
fn connect_in_a_terminal_is_not_available_yet() {
    let (status, out, err) = run(&["connect"]);
    assert_eq!((status, out.as_str()), (Some(1), ""));
    assert!(
        err.contains("cannot yet ask for a password in a terminal"),
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

    let profile = std::env::temp_dir().join(format!("ubc-vpn-cli-profile-{}", std::process::id()));
    std::fs::create_dir_all(&profile).unwrap();
    let settings = |command: &str, typed: &str| {
        let mut child = Command::new(env!("CARGO_BIN_EXE_ubc-vpn"))
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
    assert!(
        written.is_ok_and(|text| text.contains("10.19.0.0/16")),
        "{file:?}"
    );
    assert!(after.contains("10.19.0.0/16"), "{after}");
}
