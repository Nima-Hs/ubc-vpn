//! The rules `build.rs` applies to a native build output before the
//! `libopenconnect` feature may link it. They need no native library, so
//! they run with the ordinary workspace tests.

#[allow(dead_code)]
#[path = "../build.rs"]
mod build;

use build::check_manifest;

const WINDOWS: &str = "x86_64-w64-mingw32 (MSYS2 UCRT64)";
const LINUX: &str = "x86_64-unknown-linux-gnu";
const COMMIT: &str = "8b702bf2dbaf11302ed98629214b1df5d50a12aa";

/// A manifest in the layout the native builds write. `flag` is the whole
/// `shippable` line, or nothing.
fn manifest(target: &str, flag: &str, version: &str, commit: &str) -> String {
    format!(
        r#"{{
  "target": "{target}",
  {flag}
  "components": [
    {{
      "name": "openconnect",
      "version": "{version}",
      "commit": "{commit}"
    }},
    {{ "name": "gnutls", "version": "3.8.13" }}
  ]
}}"#
    )
}

fn windows(flag: &str, release: bool, dev_override: bool) -> Result<Option<String>, String> {
    let json = manifest(WINDOWS, flag, "9.21", COMMIT);
    check_manifest(&json, WINDOWS, true, release, dev_override)
}

#[test]
fn the_pinned_build_is_accepted() {
    assert_eq!(windows(r#""shippable": true,"#, true, false), Ok(None));
    // macOS and Linux outputs carry no flag.
    let json = manifest(LINUX, "", "9.21", COMMIT);
    assert_eq!(check_manifest(&json, LINUX, false, true, false), Ok(None));
}

#[test]
fn another_target_version_or_commit_is_refused() {
    let refused = |json: String| check_manifest(&json, LINUX, false, false, true).is_err();
    assert!(refused(manifest(WINDOWS, "", "9.21", COMMIT)));
    // Ubuntu ships 9.12. The second component's version must not count.
    assert!(refused(manifest(LINUX, "", "9.12", COMMIT)));
    assert!(refused(manifest(LINUX, "", "3.8.13", COMMIT)));
    assert!(refused(manifest(LINUX, "", "9.21", "0000000")));
    assert!(refused(String::new()));
}

#[test]
fn an_unshippable_windows_build_is_refused() {
    for flag in [
        r#""shippable": false,"#,
        r#""shippable": "true","#,
        r#""shippable": null,"#,
        "",
    ] {
        assert!(windows(flag, false, false).is_err(), "{flag}");
        assert!(windows(flag, true, false).is_err(), "{flag}");
    }
}

#[test]
fn the_dev_override_works_only_outside_release_builds() {
    let flag = r#""shippable": false,"#;
    let warning = windows(flag, false, true).expect("a debug build may use the override");
    assert!(warning.is_some_and(|text| text.contains(build::DEV_VAR)));
    assert!(windows(flag, true, true).is_err());
    // It excuses the flag and nothing else.
    let old = manifest(WINDOWS, flag, "9.12", COMMIT);
    assert!(check_manifest(&old, WINDOWS, true, false, true).is_err());
}
