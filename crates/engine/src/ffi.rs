//! The raw binding to `libopenconnect` v9.21, and the only place in the
//! workspace that loads it. All `unsafe` code of the engine belongs here.
//!
//! Nothing links the library. [`Library::load`] loads it at run time from a
//! full path and looks up each function by name, so no program that uses the
//! engine needs a link argument, and no `libopenconnect` is in the process
//! before `load` is called. Signatures are written by hand from
//! `include/openconnect.h` of the pinned build. So far there is one function.
//!
//! # What `load` controls, and what it does not
//!
//! It controls which `libopenconnect` file is loaded: the one in the folder
//! it is given, or none.
//!
//! - **Windows.** It also controls where that file's own dependencies come
//!   from: its folder or System32, never the program's folder, the working
//!   directory or `PATH`.
//! - **macOS and Linux.** It does not control the file's dependencies. The
//!   system loader resolves those: from the library's own folder on macOS
//!   (the bundle), from the distribution on Linux (GnuTLS, zlib), and in both
//!   cases the loader obeys its environment variables first. On macOS
//!   `DYLD_*` variables can even replace the file named by a full path, so
//!   `load` refuses to run with one set, the two fallback ones apart.
//!
//! So a service that runs as root still needs what no code here can give: an
//! install folder owned by root with no ancestor a user can write, and a
//! clean environment from systemd or launchd. It must never be setuid.

// Nothing in the crate calls this yet. The login and tunnel code comes next.
#![allow(dead_code)]

use std::ffi::{CStr, c_char, c_void};
use std::path::Path;

/// The version string of the one release this binding is written for.
const PINNED: &str = "v9.21";

/// Why the library was not loaded. Nothing of it may be called then.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LoadError {
    /// The folder is not a plain absolute path. On Windows that means a
    /// drive letter: network and device paths are refused.
    BadFolder,
    /// A loader variable is set that can replace the file. macOS only.
    UnsafeEnvironment,
    /// A `libopenconnect` was in the process before the folder was chosen.
    LoadedEarly,
    /// The library, or something it needs, could not be loaded.
    NotFound,
    /// The loader answered with a file from another folder. macOS and Linux
    /// only, where a library of the same name can stand in for the path.
    WrongFolder,
    /// The library lacks a function this binding declares.
    MissingFunction,
    /// The library is not the pinned version.
    WrongVersion,
}

/// The loaded library: one pointer per declared function, filled in by
/// [`Library::load`]. Every call into the library is a method on this, so
/// there is nothing to call before `load` has succeeded.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Library {
    /// `const char *openconnect_get_version(void)`
    get_version: unsafe extern "C" fn() -> *const c_char,
}

impl Library {
    /// Loads `libopenconnect` from `dir`, looks up every function, and
    /// checks the version. Call it once per process. The module
    /// documentation says what this does and does not control.
    pub(crate) fn load(dir: &Path) -> Result<Self, LoadError> {
        let file = dir.join(os::FILE);
        // A NUL would make the loader read a shorter path than the one given.
        if !os::is_plain(dir) || file.as_os_str().as_encoded_bytes().contains(&0) {
            return Err(LoadError::BadFolder);
        }
        let handle = os::open(&file)?;
        let get_version = os::symbol(handle, c"openconnect_get_version");
        if get_version.is_null() {
            return Err(LoadError::MissingFunction);
        }
        os::confirm(get_version, dir)?;
        // SAFETY: the pointer is the address of the function of that name in
        // the library just loaded, which is never unloaded. Its signature is
        // the one in `openconnect.h`, and has been in every release.
        let get_version = unsafe {
            std::mem::transmute::<*mut c_void, unsafe extern "C" fn() -> *const c_char>(get_version)
        };
        let library = Self { get_version };
        // The other signatures hold for the pinned release only.
        if !is_pinned(&library.version()) {
            return Err(LoadError::WrongVersion);
        }
        Ok(library)
    }

    /// The library's version string, such as `v9.21`.
    pub(crate) fn version(self) -> String {
        // SAFETY: `load` filled the pointer in. The function takes no
        // arguments and returns a NUL-terminated string that is never freed.
        unsafe { CStr::from_ptr((self.get_version)()) }
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
    use std::ffi::{CStr, OsStr, c_char, c_void};
    use std::os::windows::ffi::OsStrExt;
    use std::path::{Component, Path, Prefix};
    use std::ptr;

    use super::LoadError;

    pub(crate) const FILE: &str = "libopenconnect-5.dll";
    const LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR: u32 = 0x0100;
    const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x0800;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn SetDefaultDllDirectories(flags: u32) -> i32;
        fn LoadLibraryExW(name: *const u16, file: *mut c_void, flags: u32) -> *mut c_void;
        fn GetModuleHandleW(name: *const u16) -> *mut c_void;
        fn GetModuleFileNameW(module: *mut c_void, name: *mut u16, size: u32) -> u32;
        fn GetProcAddress(module: *mut c_void, name: *const c_char) -> *mut c_void;
    }

    fn wide(text: &OsStr) -> Vec<u16> {
        text.encode_wide().chain([0]).collect()
    }

    /// An absolute path on a drive letter: not a share, not a `\\?\` form.
    pub(super) fn is_plain(dir: &Path) -> bool {
        let disk =
            |first| matches!(first, Component::Prefix(p) if matches!(p.kind(), Prefix::Disk(_)));
        dir.is_absolute() && dir.components().next().is_some_and(disk)
    }

    fn loaded(name: &str) -> *mut c_void {
        let name = wide(OsStr::new(name));
        // SAFETY: `name` is NUL-terminated UTF-16 and outlives the call.
        unsafe { GetModuleHandleW(name.as_ptr()) }
    }

    pub(super) fn open(file: &Path) -> Result<*mut c_void, LoadError> {
        if !loaded(FILE).is_null() {
            return Err(LoadError::LoadedEarly);
        }
        let path = wide(file.as_os_str());
        // From here on a library asked for by name alone, by anything in the
        // process, comes from System32 only. That covers what GnuTLS loads
        // later. It does not cover Wintun: the library asks for `wintun.dll`
        // in the program's own folder.
        // SAFETY: takes a flag and touches no memory of ours.
        if unsafe { SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) } == 0 {
            return Err(LoadError::NotFound);
        }
        // The library's own dependencies come from its folder or System32.
        let flags = LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32;
        // SAFETY: `path` is NUL-terminated UTF-16 and outlives the call; the
        // second argument is reserved and must be null. Loading runs the
        // start-up code of the library and of what it needs.
        let handle = unsafe { LoadLibraryExW(path.as_ptr(), ptr::null_mut(), flags) };
        if handle.is_null() {
            return Err(LoadError::NotFound);
        }
        Ok(handle)
    }

    pub(super) fn symbol(handle: *mut c_void, name: &CStr) -> *mut c_void {
        // SAFETY: `handle` came from `open`, and `name` is a NUL-terminated
        // string that outlives the call.
        unsafe { GetProcAddress(handle, name.as_ptr()) }
    }

    /// Windows loaded the file by its full path; there is nothing to confirm.
    pub(super) fn confirm(_function: *mut c_void, _dir: &Path) -> Result<(), LoadError> {
        Ok(())
    }

    /// For tests: asks Windows for a library the way a careless program
    /// does, with the usual search.
    #[cfg(test)]
    pub(crate) fn careless_load(name: &OsStr) -> bool {
        let name = wide(name);
        // SAFETY: `name` is NUL-terminated UTF-16 and outlives the call; the
        // second argument is reserved and must be null. Loading runs the
        // found library's start-up code; tests pass only our own libraries.
        !unsafe { LoadLibraryExW(name.as_ptr(), ptr::null_mut(), 0) }.is_null()
    }

    /// For tests: the file a loaded library of this name came from.
    #[cfg(test)]
    pub(crate) fn module_path(name: &str) -> Option<std::path::PathBuf> {
        use std::os::windows::ffi::OsStringExt;
        let module = loaded(name);
        let mut buffer = [0u16; 1024];
        // SAFETY: `module` is checked below before the result is used, and
        // `buffer` is writable for the length given.
        let length = unsafe { GetModuleFileNameW(module, buffer.as_mut_ptr(), 1024) } as usize;
        let known = !module.is_null() && length > 0 && length < buffer.len();
        known.then(|| std::ffi::OsString::from_wide(&buffer[..length]).into())
    }
}

#[cfg(unix)]
pub(crate) mod os {
    use std::ffi::{CStr, CString, OsStr, c_char, c_int, c_void};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;
    use std::{fs, ptr};

    use super::LoadError;

    #[cfg(target_os = "macos")]
    pub(crate) const FILE: &str = "libopenconnect.5.dylib";
    #[cfg(not(target_os = "macos"))]
    pub(crate) const FILE: &str = "libopenconnect.so.5";

    const RTLD_LAZY: c_int = 1;
    const RTLD_NOW: c_int = 2;
    // `RTLD_LOCAL` then `RTLD_NOLOAD`, which differ between the two systems.
    #[cfg(target_os = "macos")]
    const LOCAL_NOLOAD: (c_int, c_int) = (4, 0x10);
    #[cfg(not(target_os = "macos"))]
    const LOCAL_NOLOAD: (c_int, c_int) = (0, 4);

    /// `Dl_info`, which has this layout on both macOS and Linux.
    #[repr(C)]
    struct DlInfo {
        file: *const c_char,
        base: *mut c_void,
        symbol: *const c_char,
        address: *mut c_void,
    }

    unsafe extern "C" {
        fn dlopen(path: *const c_char, mode: c_int) -> *mut c_void;
        fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
        fn dladdr(address: *const c_void, info: *mut DlInfo) -> c_int;
    }

    pub(super) fn is_plain(dir: &Path) -> bool {
        dir.is_absolute()
    }

    fn open_with(path: &OsStr, mode: c_int) -> *mut c_void {
        let Ok(path) = CString::new(path.as_bytes()) else {
            return ptr::null_mut();
        };
        // SAFETY: `path` is a NUL-terminated string that outlives the call.
        // Loading runs the start-up code of the library and of what it needs.
        unsafe { dlopen(path.as_ptr(), mode) }
    }

    pub(super) fn open(file: &Path) -> Result<*mut c_void, LoadError> {
        // dyld tries the file's name in `DYLD_LIBRARY_PATH` before the full
        // path it was given, and other `DYLD_*` variables redirect it too.
        // The two fallback variables are allowed: Cargo sets one when it
        // runs a program, and dyld does not use them for a full path. A
        // test checks that it still does not.
        let redirects = |name: &OsStr| {
            let name = name.as_bytes();
            name.starts_with(b"DYLD_") && !name.starts_with(b"DYLD_FALLBACK_")
        };
        if cfg!(target_os = "macos") && std::env::vars_os().any(|(name, _)| redirects(&name)) {
            return Err(LoadError::UnsafeEnvironment);
        }
        // Asks for the name alone, then the file, without loading anything.
        let present = |name: &OsStr| !open_with(name, RTLD_LAZY | LOCAL_NOLOAD.1).is_null();
        if present(OsStr::new(FILE)) || present(file.as_os_str()) {
            return Err(LoadError::LoadedEarly);
        }
        let handle = open_with(file.as_os_str(), RTLD_NOW | LOCAL_NOLOAD.0);
        if handle.is_null() {
            return Err(LoadError::NotFound);
        }
        Ok(handle)
    }

    pub(super) fn symbol(handle: *mut c_void, name: &CStr) -> *mut c_void {
        // SAFETY: `handle` came from `dlopen`, and `name` is a NUL-terminated
        // string that outlives the call.
        unsafe { dlsym(handle, name.as_ptr()) }
    }

    /// The loader may answer a full path with a library of the same name
    /// that is already loaded. So ask which file `function` is in, and
    /// accept only a full path to a file in `dir`.
    pub(super) fn confirm(function: *mut c_void, dir: &Path) -> Result<(), LoadError> {
        let mut info = DlInfo {
            file: ptr::null(),
            base: ptr::null_mut(),
            symbol: ptr::null(),
            address: ptr::null_mut(),
        };
        // SAFETY: `dladdr` only looks the address up, and `info` is a valid
        // `Dl_info` for it to fill.
        if unsafe { dladdr(function, &mut info) } == 0 || info.file.is_null() {
            return Err(LoadError::WrongFolder);
        }
        // SAFETY: `dladdr` succeeded, so `file` is the loader's own
        // NUL-terminated path of a library that is never unloaded.
        let file = Path::new(OsStr::from_bytes(
            unsafe { CStr::from_ptr(info.file) }.to_bytes(),
        ));
        // A relative answer would be resolved against the folder the process
        // is in now, which need not be the one the loader used.
        if !file.is_absolute() {
            return Err(LoadError::WrongFolder);
        }
        match (fs::canonicalize(file), fs::canonicalize(dir)) {
            (Ok(file), Ok(dir)) if file.parent() == Some(&dir) => Ok(()),
            _ => Err(LoadError::WrongFolder),
        }
    }

    /// For tests: loads a library the way a careless program does.
    #[cfg(test)]
    pub(crate) fn careless_load(name: &OsStr) -> bool {
        !open_with(name, RTLD_NOW).is_null()
    }
}
