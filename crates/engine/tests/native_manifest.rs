//! The rules `build.rs` applies to a native build output before the
//! `libopenconnect` feature may use it. They need no native library.

#![cfg(feature = "libopenconnect")]

#[allow(dead_code)]
#[path = "../build.rs"]
mod build;

use build::{Build, DEV_VAR};
use serde_json::{Value, json};

type Triple = (&'static str, &'static str, &'static str);
const WINDOWS: Triple = ("windows", "x86_64", "msvc");
const MACOS: Triple = ("macos", "aarch64", "");
const LINUX: Triple = ("linux", "x86_64", "gnu");
const COMMIT: &str = "8b702bf2dbaf11302ed98629214b1df5d50a12aa";

/// A manifest in the layout that OS's native build writes.
fn manifest(target: Triple) -> Value {
    let gnutls = json!({ "name": "gnutls", "version": "3.8.13" });
    match target.0 {
        "windows" => json!({
            "target": "x86_64-w64-mingw32 (MSYS2 UCRT64)",
            "shippable": true,
            "components": [
                { "name": "openconnect", "version": "9.21", "source": { "commit": COMMIT } },
                gnutls,
            ],
        }),
        "macos" => json!({
            "target": "macos-arm64",
            "components": [{ "name": "openconnect", "version": "9.21" }, gnutls],
            "openconnect_tag_commit": COMMIT,
        }),
        _ => json!({
            "target": "x86_64-unknown-linux-gnu",
            "components": [{ "name": "openconnect", "version": "9.21", "commit": COMMIT }],
        }),
    }
}

/// A release build with no override.
fn release(json: &str, target: Triple) -> Result<Option<String>, String> {
    check(json, target, "release", None)
}

fn check(
    json: &str,
    target: Triple,
    profile: &str,
    dev: Option<&str>,
) -> Result<Option<String>, String> {
    let build = Build {
        target,
        profile,
        dev_override: dev,
    };
    build::check(json, &build).map(|(_, warning)| warning)
}

#[test]
fn the_pinned_build_is_accepted_on_each_target() {
    for target in [WINDOWS, MACOS, LINUX] {
        assert_eq!(release(&manifest(target).to_string(), target), Ok(None));
    }
}

#[test]
fn another_target_version_or_commit_is_refused() {
    let refused = |target, change: &dyn Fn(&mut Value)| {
        let mut manifest = manifest(target);
        change(&mut manifest);
        release(&manifest.to_string(), target).is_err()
    };
    assert!(release(&manifest(LINUX).to_string(), WINDOWS).is_err());
    assert!(release(&manifest(LINUX).to_string(), ("linux", "aarch64", "gnu")).is_err());
    for target in [WINDOWS, MACOS, LINUX] {
        assert!(refused(target, &|m| m["target"] = json!("another")));
        // Ubuntu ships 9.12.
        assert!(refused(target, &|m| m["components"][0]["version"] = json!("9.12")));
        // The version must be OpenConnect's own, not the next component's.
        assert!(refused(target, &|m| {
            m["components"][0]
                .as_object_mut()
                .unwrap()
                .remove("version");
            m["components"]
                .as_array_mut()
                .unwrap()
                .push(json!({ "name": "x", "version": "9.21" }));
        }));
        assert!(refused(target, &|m| m["components"] = json!([])));
        assert!(refused(target, &|m| {
            let again = m["components"][0].clone();
            m["components"].as_array_mut().unwrap().push(again);
        }));
    }
    // The commit must be where that build records it, not just somewhere.
    let elsewhere = |m: &mut Value| m["note"] = json!(COMMIT);
    assert!(refused(WINDOWS, &|m| {
        m["components"][0]["source"]["commit"] = json!("0000");
        elsewhere(m);
    }));
    assert!(refused(LINUX, &|m| {
        m["components"][0]["commit"] = json!("0000");
        elsewhere(m);
    }));
    assert!(refused(MACOS, &|m| {
        m["openconnect_tag_commit"] = json!("0000");
        m["components"][0]["commit"] = json!(COMMIT);
    }));
}

#[test]
fn a_file_that_is_not_json_is_refused() {
    let good = manifest(WINDOWS).to_string();
    assert!(release(&good[..good.len() - 1], WINDOWS).is_err());
    assert!(release(&format!("{good} x"), WINDOWS).is_err());
    assert!(release(&format!("{good}{good}"), WINDOWS).is_err());
    let fragments = format!(
        r#""target": "x86_64-w64-mingw32 (MSYS2 UCRT64)", "shippable": true, "name": "openconnect", "version": "9.21", "commit": "{COMMIT}""#
    );
    assert!(release(&fragments, WINDOWS).is_err());
    assert!(release("", WINDOWS).is_err());
}

#[test]
fn an_unshippable_windows_build_is_refused() {
    let with = |flag: Option<Value>, more: Value| {
        let mut manifest = manifest(WINDOWS);
        match flag {
            Some(flag) => manifest["shippable"] = flag,
            None => drop(manifest.as_object_mut().unwrap().remove("shippable")),
        }
        manifest["extra"] = more;
        manifest.to_string()
    };
    let nested = json!({ "shippable": true });
    let mut cases = vec![
        with(None, json!(0)),
        with(None, nested.clone()),
        with(Some(json!(false)), nested),
    ];
    for flag in [
        json!(false),
        json!("true"),
        json!(null),
        json!(1),
        json!([true]),
    ] {
        cases.push(with(Some(flag), json!(0)));
    }
    // A key given twice: every JSON reader takes the last.
    let twice = r#""shippable":true,"shippable":false"#;
    let good = manifest(WINDOWS).to_string();
    assert!(good.contains(r#""shippable":true"#));
    cases.push(good.replacen(r#""shippable":true"#, twice, 1));
    for json in cases {
        // In a debug build too, and whatever the override says short of `1`.
        for (profile, dev) in [
            ("release", None),
            ("debug", None),
            ("debug", Some("0")),
            ("debug", Some("true")),
        ] {
            assert!(
                check(&json, WINDOWS, profile, dev).is_err(),
                "{json} {profile} {dev:?}"
            );
        }
    }
}

#[test]
fn the_dev_override_works_only_in_a_debug_build() {
    let mut unshippable = manifest(WINDOWS);
    unshippable["shippable"] = json!(false);
    let json = unshippable.to_string();
    let warning = check(&json, WINDOWS, "debug", Some("1")).expect("a debug build may use it");
    assert!(warning.is_some_and(|text| text.contains(DEV_VAR)));
    for profile in ["release", "", "bench"] {
        assert!(
            check(&json, WINDOWS, profile, Some("1")).is_err(),
            "{profile}"
        );
    }
    // It excuses the flag and nothing else.
    unshippable["components"][0]["version"] = json!("9.12");
    assert!(check(&unshippable.to_string(), WINDOWS, "debug", Some("1")).is_err());
    // A shippable build needs no warning.
    assert_eq!(
        check(&manifest(WINDOWS).to_string(), WINDOWS, "debug", Some("1")),
        Ok(None)
    );
}
