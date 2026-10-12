//! The raw binding to `libopenconnect` v9.21, and the only place in the
//! workspace that loads it. All `unsafe` code of the engine belongs here.
//!
//! Declarations are written by hand from `include/openconnect.h` of the
//! pinned build. So far there is one, enough to prove the library links and
//! loads on every OS. Nothing logs in or opens a tunnel yet.
//!
//! # Where the library comes from
//!
//! At build time, from the folder `build.rs` checks. At run time, only from
//! the one folder given to [`Library::load`], which must be called before
//! anything else here:
//!
//! - **Windows.** The import is `raw-dylib` and delay-loaded, so the process
//!   starts with no `libopenconnect` in it. `load` limits the process's DLL
//!   search to System32, then loads the DLL by its full path with its
//!   dependencies taken from its own folder or System32. The working
//!   directory and `PATH` are never searched.
//! - **macOS and Linux.** The system loader has already loaded the library
//!   through the program's rpath when `load` runs, so `load` checks which
//!   file that was and refuses any other folder. On Linux the library's own
//!   dependencies (GnuTLS, zlib) are the distribution's, by design.
//!
//! On every OS `load` then refuses a library that is not the pinned version.
//!
//! Cargo passes link arguments only to this crate's own tests. A program
//! that uses the engine must pass its own: `/DELAYLOAD:libopenconnect-5.dll`
//! and `delayimp.lib` on Windows, and an rpath that names the folder its
//! libraries are installed in on macOS and Linux.

// Nothing in the crate calls this yet. The login and tunnel code comes next.
#![allow(dead_code)]

use std::ffi::{CStr, c_char};
use std::path::Path;

/// The version string of the one release this binding is written for.
const PINNED: &str = "v9.21";

#[cfg_attr(windows, link(name = "libopenconnect-5", kind = "raw-dylib"))]
#[cfg_attr(not(windows), link(name = "openconnect"))]
unsafe extern "C" {
    fn openconnect_get_version() -> *const c_char;
}

/// Why the library was not loaded. Nothing of it may be called then.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LoadError {
    /// The folder was not given as an absolute path.
    NotAbsolute,
    /// The library, or something it needs, is not in the folder.
    NotFound,
    /// A `libopenconnect` was in the process before the folder was chosen,
    /// so Windows found it by its usual search. The program was not linked
    /// to delay-load it. Windows only.
    LoadedEarly,
    /// The library the system loader picked is not the one in the folder.
    /// macOS and Linux only.
    WrongFolder,
    /// The library is not the pinned version.
    WrongVersion,
}

/// Proof that the pinned library is loaded from the chosen folder. Safe
/// wrappers hang off this, so nothing can call the library before it exists.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Library(());

impl Library {
    /// Loads the library from `dir` and nowhere else, and checks it is the
    /// pinned version. Call it once, before anything else in this module and
    /// before the process starts threads that may load libraries.
    pub(crate) fn load(dir: &Path) -> Result<Self, LoadError> {
        if !dir.is_absolute() {
            return Err(LoadError::NotAbsolute);
        }
        os::load(dir)?;
        let library = Self(());
        if !is_pinned(&library.version()) {
            return Err(LoadError::WrongVersion);
        }
        Ok(library)
    }

    /// The library's version string, such as `v9.21`.
    pub(crate) fn version(self) -> String {
        // SAFETY: `self` proves the library is loaded. The function takes no
        // arguments and returns a NUL-terminated string that is never freed.
        unsafe { CStr::from_ptr(openconnect_get_version()) }
            .to_string_lossy()
            .into_owned()
    }
}

/// Whether `version` is the pinned release. Ubuntu, for one, ships an older
/// release with known bugs.
///
/// The library takes its version from `git describe`. The Windows build is
/// made from an archive with no git history and reports `v9.21-unknown`. A
/// build from any later commit has a count and a hash after the tag.
pub(crate) fn is_pinned(version: &str) -> bool {
    version == PINNED || version.strip_suffix("-unknown") == Some(PINNED)
}

#[cfg(windows)]
pub(crate) mod os {
    use std::ffi::{OsStr, c_void};
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr;

    use super::LoadError;

    const DLL: &str = "libopenconnect-5.dll";
    const LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR: u32 = 0x0100;
    const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x0800;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn SetDefaultDllDirectories(flags: u32) -> i32;
        fn LoadLibraryExW(name: *const u16, file: *mut c_void, flags: u32) -> *mut c_void;
        fn GetModuleHandleW(name: *const u16) -> *mut c_void;
    }

    fn wide(text: &OsStr) -> Vec<u16> {
        text.encode_wide().chain([0]).collect()
    }

    pub(super) fn load(dir: &Path) -> Result<(), LoadError> {
        let name = wide(OsStr::new(DLL));
        // SAFETY: `name` is NUL-terminated UTF-16 and outlives the call.
        if !unsafe { GetModuleHandleW(name.as_ptr()) }.is_null() {
            return Err(LoadError::LoadedEarly);
        }
        let path = wide(dir.join(DLL).as_os_str());
        // A NUL inside the path would make Windows read a shorter one.
        if path.iter().filter(|unit| **unit == 0).count() != 1 {
            return Err(LoadError::NotFound);
        }
        // From here on a library asked for by name alone, by anything in the
        // process, comes from System32 only. That covers the delay-load
        // helper and what GnuTLS loads later. It does not cover Wintun: the
        // library asks for `wintun.dll` in the program's own folder.
        // SAFETY: takes a flag and touches no memory of ours.
        if unsafe { SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) } == 0 {
            return Err(LoadError::NotFound);
        }
        // The library's own dependencies come from its folder or System32.
        let flags = LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32;
        // SAFETY: `path` is NUL-terminated UTF-16 and outlives the call; the
        // second argument is reserved and must be null. Loading runs the
        // start-up code of the library and of what it needs.
        if unsafe { LoadLibraryExW(path.as_ptr(), ptr::null_mut(), flags) }.is_null() {
            return Err(LoadError::NotFound);
        }
        Ok(())
    }

    /// For tests: whether Windows finds a library asked for by name alone,
    /// the way a program that is not careful asks.
    pub(crate) fn finds_by_name(name: &str) -> bool {
        let name = wide(OsStr::new(name));
        // SAFETY: `name` is NUL-terminated UTF-16 and outlives the call; the
        // second argument is reserved and must be null. Loading runs the
        // found library's start-up code; tests pass only our own libraries.
        !unsafe { LoadLibraryExW(name.as_ptr(), ptr::null_mut(), 0) }.is_null()
    }
}

#[cfg(unix)]
mod os {
    use std::ffi::{CStr, OsStr, c_char, c_int, c_void};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;
    use std::{fs, ptr};

    use super::LoadError;

    /// `Dl_info`, which has this layout on both macOS and Linux.
    #[repr(C)]
    struct DlInfo {
        file: *const c_char,
        base: *mut c_void,
        symbol: *const c_char,
        address: *mut c_void,
    }

    unsafe extern "C" {
        fn dladdr(address: *const c_void, info: *mut DlInfo) -> c_int;
    }

    /// The system loader chose the file before `main`. Find out which one,
    /// and accept only the one in `dir`.
    pub(super) fn load(dir: &Path) -> Result<(), LoadError> {
        let mut info = DlInfo {
            file: ptr::null(),
            base: ptr::null_mut(),
            symbol: ptr::null(),
            address: ptr::null_mut(),
        };
        let function = super::openconnect_get_version as *const c_void;
        // SAFETY: `dladdr` only looks the address up, and `info` is a valid
        // `Dl_info` for it to fill.
        if unsafe { dladdr(function, &mut info) } == 0 || info.file.is_null() {
            return Err(LoadError::WrongFolder);
        }
        // SAFETY: `dladdr` succeeded, so `file` is the loader's own
        // NUL-terminated path of a library that is never unloaded.
        let file = OsStr::from_bytes(unsafe { CStr::from_ptr(info.file) }.to_bytes());
        let dir = fs::canonicalize(dir).map_err(|_| LoadError::NotFound)?;
        match fs::canonicalize(file) {
            _ => Ok(()),
        }
    }
}
