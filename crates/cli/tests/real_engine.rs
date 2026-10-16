//! The command-line client built with the real engine, run as a program
//! from folders of its own. It exists only in a build with the
//! `real-engine` feature, which needs `UBC_VPN_NATIVE_DIR` to name our own
//! build of the library; so it cannot be skipped where it is built.
//!
//! Windows only for now: there the library and the libraries it needs are
//! found beside the program, which is what these tests move around.
#![cfg(all(feature = "real-engine", windows))]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Our build of the library, as the build was given it.
const NATIVE: &str = env!("UBC_VPN_NATIVE_DIR");

/// A new folder holding a copy of the program, and with `libraries` a copy
/// of every library of our build beside it.
fn installed(name: &str, libraries: bool) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("real-engine-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::copy(env!("CARGO_BIN_EXE_ubc-vpn"), dir.join("ubc-vpn.exe")).unwrap();
    if libraries {
        for file in std::fs::read_dir(bin()).unwrap() {
            let file = file.unwrap().path();
            if file.extension().is_some_and(|ext| ext == "dll") {
                std::fs::copy(&file, dir.join(file.file_name().unwrap())).unwrap();
            }
        }
    }
    dir
}

fn bin() -> PathBuf {
    Path::new(NATIVE).join("bin")
}

/// Runs `connect --json` from `dir`, with our build of the library in the
/// working folder and first on the search path, where a careless loader
/// would find it. Returns the one line it printed.
fn connect_from(dir: &Path) -> String {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let mut paths = vec![bin()];
    paths.extend(std::env::split_paths(&path));
    // Security rule: never the service installed on this machine. A debug
    // build talks to this channel, which nobody serves; see `binary.rs`.
    let channel = format!("ubc-vpn-test-real-engine-{}", std::process::id());
    let output = Command::new(dir.join("ubc-vpn.exe"))
        .env("UBC_VPN_TEST_CHANNEL", channel)
        .args(["connect", "--json"])
        .current_dir(bin())
        .env("PATH", std::env::join_paths(paths).unwrap())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let out = String::from_utf8(output.stdout).unwrap();
    assert_ne!(output.status.code(), Some(0), "{out}");
    assert_eq!(out.lines().count(), 1, "{out}");
    assert!(out.starts_with(r#"{"type":"error","#), "{out}");
    out
}

// Security rule (engine): the library is loaded from the folder the program
// is in and from nowhere else. A program without it beside it does not load
// the copy in its working folder or on the search path, and says so.
#[test]
fn the_library_is_loaded_only_from_beside_the_program() {
    // A release build cannot be pointed away from the installed service, so
    // it runs this only on CI, whose machines have none.
    if !cfg!(debug_assertions) && std::env::var_os("CI").is_none() {
        println!("SKIPPED: a release build would reach the installed service; CI only");
        return;
    }
    let alone = installed("alone", false);
    let line = connect_from(&alone);
    assert!(
        line.contains("The VPN library could not be loaded."),
        "{line}"
    );

    // With the library beside it, loading succeeds, and the connect goes on
    // until something else stops it: here this machine's missing policy or
    // service.
    let beside = installed("beside", true);
    let line = connect_from(&beside);
    assert!(!line.contains("could not be loaded"), "{line}");
    assert!(!line.contains("no VPN engine"), "{line}");
}
