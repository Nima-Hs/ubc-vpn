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
