//! Loads the real `libopenconnect` and calls it.
//!
//! Needs `--features libopenconnect` and `UBC_VPN_NATIVE_DIR` (see
//! `build.rs`). The `Engine` workflow runs it on all three OSes.
//!
//! The binding is compiled into this test directly, so that it runs in a
//! process of its own: what a process has loaded cannot be undone, and the
//! steps below depend on their order. Keep them in one test.

#![cfg(feature = "libopenconnect")]

#[path = "../src/ffi.rs"]
mod ffi;

use std::path::Path;
use std::{env, fs};

use ffi::{Library, LoadError};

#[test]
fn only_the_pinned_version_is_accepted() {
    assert!(ffi::is_pinned("v9.21") && ffi::is_pinned("v9.21-unknown"));
    for other in ["v9.12", "v9.12-unknown", "v9.210", "v9.21-1-g8b702bf", ""] {
        assert!(!ffi::is_pinned(other), "{other}");
    }
}

#[test]
fn the_library_loads_from_the_given_folder_and_nowhere_else() {
    let libs = Path::new(env!("UBC_VPN_NATIVE_LIBS"));
    let scratch = Path::new(env!("CARGO_TARGET_TMPDIR")).join("library");
    let _ = fs::remove_dir_all(&scratch);
    let (empty, plants) = (scratch.join("empty"), scratch.join("plants"));
    fs::create_dir_all(&empty).unwrap();
    fs::create_dir_all(&plants).unwrap();

    // Windows: two copies of a harmless library under names nothing else
    // has. Before anything is set, Windows finds one by name alone in the
    // working directory, so planting works.
    #[cfg(windows)]
    {
        fs::copy(libs.join("zlib1.dll"), plants.join("ubc-vpn-planted-1.dll")).unwrap();
        fs::copy(libs.join("zlib1.dll"), plants.join("ubc-vpn-planted-2.dll")).unwrap();
        env::set_current_dir(&plants).unwrap();
        assert!(ffi::os::finds_by_name("ubc-vpn-planted-1.dll"));
    }

    // The working directory holds the real library and everything it needs.
    // The workflow puts the same folder on PATH as well. Neither may be
    // where a library is taken from.
    env::set_current_dir(libs).unwrap();
    let relative = Library::load(Path::new("."));
    assert_eq!(relative.err(), Some(LoadError::NotAbsolute));
    let elsewhere = if cfg!(windows) {
        LoadError::NotFound
    } else {
        LoadError::WrongFolder
    };
    assert_eq!(Library::load(&empty).err(), Some(elsewhere));

    // Windows: a folder with the library alone. What it needs must not be
    // taken from the working directory or PATH.
    #[cfg(windows)]
    {
        let dll = "libopenconnect-5.dll";
        fs::copy(libs.join(dll), empty.join(dll)).unwrap();
        assert_eq!(Library::load(&empty).err(), Some(LoadError::NotFound));
    }

    let library = Library::load(libs).expect("the pinned library loads from its folder");
    let version = library.version();
    println!("RAN: libopenconnect {version} from {}", libs.display());
    assert!(ffi::is_pinned(&version), "{version}");

    // Windows: from now on a library asked for by name alone comes from
    // System32 and not from the working directory.
    #[cfg(windows)]
    {
        env::set_current_dir(&plants).unwrap();
        assert!(!ffi::os::finds_by_name("ubc-vpn-planted-2.dll"));
        assert!(ffi::os::finds_by_name("version.dll"));
    }
}
