//! Checks the native library for the `libopenconnect` feature.
//!
//! Without the feature this does nothing. With it, `UBC_VPN_NATIVE_DIR` must
//! name an unpacked output of this repository's own build of the library
//! (`native/`, the `libopenconnect-*` workflow artifacts), and the build
//! stops unless that output is the pinned one. The library itself is not
//! linked: the engine loads it at run time (`src/ffi.rs`). Only `shim.c` is
//! compiled in. The folder is handed to this crate's own tests and to
//! nothing else.
//!
//! Every rule is in [`check`], which `tests/native_manifest.rs` tests.

#![cfg_attr(not(feature = "libopenconnect"), allow(dead_code, unused_imports))]

use std::path::{Path, PathBuf};
use std::{env, fs, process};

/// The one OpenConnect release the binding is written against.
const VERSION: &str = "9.21";
/// The commit that tag `v9.21` points to.
const COMMIT: &str = "8b702bf2dbaf11302ed98629214b1df5d50a12aa";
const DIR_VAR: &str = "UBC_VPN_NATIVE_DIR";
/// For development only: set to `1` to accept a Windows output that its
/// build did not mark shippable. Refused in a release build.
pub(crate) const DEV_VAR: &str = "UBC_VPN_NATIVE_DEV_UNSHIPPABLE";

/// What Cargo and the environment say about this build.
pub(crate) struct Build<'a> {
    /// `CARGO_CFG_TARGET_OS`, `_ARCH` and `_ENV`.
    pub target: (&'a str, &'a str, &'a str),
    /// `PROFILE`: `debug`, or `release` for every profile based on it.
    pub profile: &'a str,
    /// The value of [`DEV_VAR`], if it is set.
    pub dev_override: Option<&'a str>,
}

/// For a target: what the manifest calls it, and where the library is.
fn target(triple: (&str, &str, &str)) -> Option<(&'static str, &'static str)> {
    match triple {
        ("windows", "x86_64", "msvc") => Some((
            "x86_64-w64-mingw32 (MSYS2 UCRT64)",
            "bin/libopenconnect-5.dll",
        )),
        ("macos", "aarch64", _) => Some(("macos-arm64", "lib/libopenconnect.5.dylib")),
        ("linux", "x86_64", "gnu") => Some(("x86_64-unknown-linux-gnu", "lib/libopenconnect.so.5")),
        _ => None,
    }
}

/// Decides whether the native build output with this manifest may be used.
/// `Ok` carries the library's place in the folder and a warning to print.
///
/// The manifest is parsed as JSON and read at exact places. A file that is
/// not JSON, or lacks a field, or has it at another depth, is refused.
#[cfg(feature = "libopenconnect")]
pub(crate) fn check(json: &str, build: &Build) -> Result<(&'static str, Option<String>), String> {
    use serde_json::Value;

    let (name, library) =
        target(build.target).ok_or("there is no native library for this target")?;
    let manifest: Value = serde_json::from_str(json).map_err(|e| format!("not JSON: {e}"))?;
    if manifest.get("target").and_then(Value::as_str) != Some(name) {
        return Err(format!("it is not a build for {name}"));
    }
    let named = |c: &&Value| c.get("name").and_then(Value::as_str) == Some("openconnect");
    let components = manifest.get("components").and_then(Value::as_array);
    let mut found = components.into_iter().flatten().filter(named);
    let (Some(openconnect), None) = (found.next(), found.next()) else {
        return Err("it does not have exactly one openconnect component".into());
    };
    // Each OS's build records OpenConnect's commit in its own place.
    let commit = match build.target.0 {
        "windows" => openconnect
            .get("source")
            .and_then(|source| source.get("commit")),
        "linux" => openconnect.get("commit"),
        _ => manifest.get("openconnect_tag_commit"),
    };
    if openconnect.get("version").and_then(Value::as_str) != Some(VERSION)
        || commit.and_then(Value::as_str) != Some(COMMIT)
    {
        return Err(format!("it is not OpenConnect {VERSION} (commit {COMMIT})"));
    }
    // Only the Windows build has tests that decide this. Anything but a plain
    // `true` at the top level is a refusal, a missing flag included.
    if build.target.0 == "windows" && manifest.get("shippable") != Some(&Value::Bool(true)) {
        if build.dev_override != Some("1") {
            return Err("its build did not mark it shippable".into());
        }
        // Anything but a plain debug build counts as a release.
        if build.profile != "debug" {
            return Err(format!("{DEV_VAR} is not allowed in a release build"));
        }
        let warning = format!("using a native library that is not shippable: {DEV_VAR} is set");
        return Ok((library, Some(warning)));
    }
    Ok((library, None))
}

/// Checks the folder and returns the folder inside it that holds the library.
#[cfg(feature = "libopenconnect")]
fn find() -> Result<(PathBuf, Option<String>), String> {
    let var = |name: &str| env::var(name).unwrap_or_default();
    let target = ["OS", "ARCH", "ENV"].map(|part| var(&format!("CARGO_CFG_TARGET_{part}")));
    let (profile, dev_override) = (var("PROFILE"), env::var(DEV_VAR).ok());
    let build = Build {
        target: (&target[0], &target[1], &target[2]),
        profile: &profile,
        dev_override: dev_override.as_deref(),
    };
    let dir = env::var_os(DIR_VAR).ok_or(format!(
        "set {DIR_VAR} to an unpacked libopenconnect build output (see CONTRIBUTING.md)"
    ))?;
    let dir = std::path::absolute(&dir)
        .map_err(|e| format!("{DIR_VAR}: {}: {e}", Path::new(&dir).display()))?;
    let manifest = dir.join("manifest.json");
    println!("cargo:rerun-if-changed={}", manifest.display());
    let json = fs::read_to_string(&manifest)
        .map_err(|e| format!("{DIR_VAR}: {}: {e}", manifest.display()))?;
    let (library, warning) = check(&json, &build)
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
    #[cfg(feature = "libopenconnect")]
    {
        let (libs, warning) = find().unwrap_or_else(|why| {
            eprintln!("error: the libopenconnect feature needs the native library.\n{why}");
            process::exit(1);
        });
        if let Some(warning) = warning {
            println!("cargo:warning={warning}");
        }
        // The folder this crate's own tests load the library from.
        println!("cargo:rustc-env=UBC_VPN_NATIVE_LIBS={}", libs.display());
        // The engine's one C file. Left out when a test compiles this file
        // to reach `check`: a test has no build-dependencies.
        #[cfg(not(test))]
        {
            println!("cargo:rerun-if-changed=shim.c");
            cc::Build::new().file("shim.c").compile("ubc_vpn_shim");
        }
    }
}
