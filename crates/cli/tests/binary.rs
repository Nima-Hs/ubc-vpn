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
