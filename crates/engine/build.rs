//! Finds the native library for the `libopenconnect` feature.
//!
//! Without the feature this does nothing. With it, `UBC_VPN_NATIVE_DIR` must
//! name an unpacked output of this repository's own build of the library
//! (`native/`, the `libopenconnect-*` workflow artifacts). A library installed
//! on the system is never used: nothing here asks pkg-config or looks in a
//! system folder, and the build stops if the folder is not the pinned build.
//!
//! The rules are in [`check_manifest`], which `tests/native_manifest.rs` tests.

use std::path::{Path, PathBuf};
use std::{env, fs, process};

/// The one OpenConnect release the binding is written against.
const VERSION: &str = "9.21";
/// The commit that tag `v9.21` points to. Every manifest records it.
const COMMIT: &str = "8b702bf2dbaf11302ed98629214b1df5d50a12aa";
const DIR_VAR: &str = "UBC_VPN_NATIVE_DIR";
/// For development only: set to `1` to accept a Windows output that its
/// build did not mark shippable. Refused in a release build.
pub(crate) const DEV_VAR: &str = "UBC_VPN_NATIVE_DEV_UNSHIPPABLE";

/// What the manifest must say its target is, and where the library is.
fn target(os: &str, arch: &str, env: &str) -> Option<(&'static str, &'static str)> {
    match (os, arch, env) {
        ("windows", "x86_64", "msvc") => Some((
            "x86_64-w64-mingw32 (MSYS2 UCRT64)",
            "bin/libopenconnect-5.dll",
        )),
        ("macos", "aarch64", _) => Some(("macos-arm64", "lib/libopenconnect.5.dylib")),
        ("linux", "x86_64", "gnu") => Some(("x86_64-unknown-linux-gnu", "lib/libopenconnect.so.5")),
        _ => None,
    }
}

/// What follows the first `"key":` in `json`. The manifests are written by
/// our own build scripts in a fixed layout, so this is not a general JSON
/// reader. Anything it cannot read counts as absent, and an absent value
/// fails the check.
fn after<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let key = format!("\"{key}\"");
    let rest = json[json.find(&key)? + key.len()..].trim_start();
    Some(rest.strip_prefix(':')?.trim_start())
}

/// The contents of the string value of `key`.
fn text<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    after(json, key)?.strip_prefix('"')?.split('"').next()
}

/// The bare value of `key`, such as `true`. A string is not one.
fn word<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let end = |c: char| c == ',' || c == '}' || c.is_whitespace();
    after(json, key)?.split(end).next()
}

/// Decides whether a native build output may be linked. `dev_override` is
/// whether [`DEV_VAR`] is set. `Ok` carries a warning to print, if any.
pub(crate) fn check_manifest(
    json: &str,
    want_target: &str,
    windows: bool,
    release: bool,
    dev_override: bool,
) -> Result<Option<String>, String> {
    if text(json, "target") != Some(want_target) {
        return Err(format!("it is not a build for {want_target}"));
    }
    let openconnect = json.find("\"name\": \"openconnect\"").map(|at| &json[at..]);
    if openconnect.and_then(|part| text(part, "version")) != Some(VERSION) || !json.contains(COMMIT)
    {
        return Err(format!("it is not OpenConnect {VERSION} (commit {COMMIT})"));
    }
    // Only the Windows build has tests that decide this. Anything but a plain
    // `true` is a refusal, a missing flag included.
    if windows && word(json, "shippable") != Some("true") {
        if !dev_override {
            return Err("its build did not mark it shippable".into());
        }
        if release {
            return Err(format!("{DEV_VAR} is not allowed in a release build"));
        }
        return Ok(Some(format!(
            "linking a native library that is not shippable, because {DEV_VAR} is set"
        )));
    }
    Ok(None)
}

/// Checks the folder and returns the folder inside it that holds the library.
fn find(os: &str, arch: &str, env: &str) -> Result<(PathBuf, Option<String>), String> {
    let (want_target, library) =
        target(os, arch, env).ok_or("there is no native library for this target")?;
    let dir = env::var_os(DIR_VAR).ok_or(format!(
        "set {DIR_VAR} to an unpacked libopenconnect build output (see CONTRIBUTING.md)"
    ))?;
    let dir = std::path::absolute(&dir)
        .map_err(|e| format!("{DIR_VAR}: {}: {e}", Path::new(&dir).display()))?;
    let manifest = dir.join("manifest.json");
    println!("cargo:rerun-if-changed={}", manifest.display());
    let json = fs::read_to_string(&manifest)
        .map_err(|e| format!("{DIR_VAR}: {}: {e}", manifest.display()))?;
    let warning = check_manifest(
        &json,
        want_target,
        os == "windows",
        env::var("PROFILE").as_deref() == Ok("release"),
        env::var(DEV_VAR).as_deref() == Ok("1"),
    )
    .map_err(|why| format!("{DIR_VAR}: {} is refused: {why}", dir.display()))?;
    let library = dir.join(library);
    if !library.is_file() {
        return Err(format!("{DIR_VAR}: {} is missing", library.display()));
    }
    Ok((library.parent().unwrap_or(&dir).to_path_buf(), warning))
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed={DIR_VAR}");
    println!("cargo:rerun-if-env-changed={DEV_VAR}");
    if env::var_os("CARGO_FEATURE_LIBOPENCONNECT").is_none() {
        return;
    }
    let cfg = |name: &str| env::var(format!("CARGO_CFG_TARGET_{name}")).unwrap_or_default();
    let (os, arch, abi) = (cfg("OS"), cfg("ARCH"), cfg("ENV"));
    let (libs, warning) = find(&os, &arch, &abi).unwrap_or_else(|why| {
        eprintln!("error: the libopenconnect feature needs the native library.\n{why}");
        process::exit(1);
    });
    if let Some(warning) = warning {
        println!("cargo:warning={warning}");
    }
    let libs = libs.display();
    // The folder this crate's own tests load the library from.
    println!("cargo:rustc-env=UBC_VPN_NATIVE_LIBS={libs}");
    if os == "windows" {
        // The import is `raw-dylib`, so there is nothing to find at link
        // time. It is delay-loaded, so that nothing is loaded before
        // `Library::load` has chosen the folder. Link arguments reach only
        // this crate's own tests; a program that uses the engine passes the
        // same ones (see `src/ffi.rs`).
        println!("cargo:rustc-link-arg-tests=/DELAYLOAD:libopenconnect-5.dll");
        println!("cargo:rustc-link-arg-tests=delayimp.lib");
        // A test that does not use the library has nothing to delay.
        println!("cargo:rustc-link-arg-tests=/IGNORE:4199");
    } else {
        println!("cargo:rustc-link-search=native={libs}");
        println!("cargo:rustc-link-arg-tests=-Wl,-rpath,{libs}");
    }
}
