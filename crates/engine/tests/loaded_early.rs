//! Windows: a `libopenconnect` that is already in the process when the
//! folder is chosen is refused, because Windows found it by its usual
//! search. A process of its own, for the reason given in `library.rs`.

#![cfg(all(windows, feature = "libopenconnect"))]

#[path = "../src/ffi.rs"]
mod ffi;

use std::env;
use std::path::Path;

use ffi::{Library, LoadError};

#[test]
fn a_library_loaded_before_the_folder_was_chosen_is_refused() {
    let libs = Path::new(env!("UBC_VPN_NATIVE_LIBS"));
    // Stands in for a program linked without delay-loading: Windows fills
    // such an import in before `main`, searching the working directory and
    // PATH as it does here.
    env::set_current_dir(libs).unwrap();
    assert!(ffi::os::finds_by_name("libopenconnect-5.dll"));
    assert_eq!(Library::load(libs).err(), Some(LoadError::LoadedEarly));
}
