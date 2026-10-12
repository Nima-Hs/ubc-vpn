//! The raw binding to `libopenconnect` v9.21, and the only place in the
//! workspace that loads it. All `unsafe` code of the engine belongs here.
//!
//! Nothing links the library. [`Library::load`] loads it at run time from a
//! full path and looks up each function by name, so no program that uses the
//! engine needs a link argument, and no `libopenconnect` is in the process
//! before `load` is called. Signatures are written by hand from
//! `include/openconnect.h` of the pinned build. No engine uses them yet.
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
//!   dyld reads those variables when the process starts, so `load` must run
//!   before anything removes one. If one was removed, `load` can only tell
//!   afterwards that the file came from another folder: by then the foreign
//!   code has already run, and the error is all that is left to do.
//!
//! So a service that runs as root still needs what no code here can give: an
//! install folder owned by root with no ancestor a user can write, and a
//! clean environment from systemd or launchd. It must never be setuid.
//!
//! A program works out the folder from its own location. On Windows it must
//! not canonicalize that path: the result is a `\\?\` form, which `load`
//! refuses along with every other path that does not start at a drive letter.
//!
//! What this crate's tests call is `pub`, so that they can drive the library.
//! The module itself is private in anything that ships (see the crate
//! documentation). What only a test needs lives in the tests.

// No engine calls this yet. The login and tunnel code comes next.
#![allow(dead_code)]

use std::ffi::{CStr, c_char, c_int, c_uint, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;

use crate::environment::{EnvironmentError, Role, check_environment};

/// The version string of the one release this binding is written for.
const PINNED: &str = "v9.21";

/// The library's file name on this OS.
pub const FILE: &str = os::FILE;

/// Written to the command pipe to stop a login or log a tunnel off.
pub(crate) const OC_CMD_CANCEL: u8 = b'x';
/// Written to the command pipe to stop a tunnel and keep its session.
pub(crate) const OC_CMD_DETACH: u8 = b'd';
/// The flag on a form field that must not be shown or filled.
pub(crate) const OC_FORM_OPT_IGNORE: c_uint = 0x0001;

/// `struct openconnect_info`. Only the library looks inside.
#[repr(C)]
pub(crate) struct VpnInfo {
    _opaque: [u8; 0],
}

/// `struct oc_auth_form`. Its fields are declared with the login code.
#[repr(C)]
pub(crate) struct AuthForm {
    _opaque: [u8; 0],
}

/// The C library's `struct addrinfo`, declared with the code that fills it.
#[repr(C)]
pub(crate) struct AddrInfo {
    _opaque: [u8; 0],
}

/// `openconnect_validate_peer_cert_vfn`: zero accepts the certificate. The
/// library calls it only when its own verification has failed.
pub(crate) type ValidatePeerCert =
    unsafe extern "C" fn(privdata: *mut c_void, reason: *const c_char) -> c_int;
/// `openconnect_write_new_config_vfn`.
pub(crate) type WriteNewConfig =
    unsafe extern "C" fn(privdata: *mut c_void, buf: *const c_char, buflen: c_int) -> c_int;
/// `openconnect_process_auth_form_vfn`: returns an `OC_FORM_RESULT_*`.
pub(crate) type ProcessAuthForm =
    unsafe extern "C" fn(privdata: *mut c_void, form: *mut AuthForm) -> c_int;
/// `openconnect_progress_vfn`. It is printf-style; only `shim.c` implements it.
pub(crate) type Progress =
    unsafe extern "C" fn(privdata: *mut c_void, level: c_int, fmt: *const c_char, ...);
/// `openconnect_getaddrinfo_vfn`: same contract as `getaddrinfo`.
pub(crate) type GetAddrInfo = unsafe extern "C" fn(
    privdata: *mut c_void,
    node: *const c_char,
    service: *const c_char,
    hints: *const AddrInfo,
    res: *mut *mut AddrInfo,
) -> c_int;

/// The write end of the command pipe: a `SOCKET` on Windows, where failure
/// is `INVALID_SOCKET`, and a file descriptor elsewhere, negative on failure.
#[cfg(windows)]
pub(crate) type CmdPipe = usize;
#[cfg(not(windows))]
pub(crate) type CmdPipe = c_int;

/// Why the library was not loaded. Nothing of it may be called then.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadError {
    /// The folder is not a plain absolute path. On Windows that means a
    /// drive letter: network and device paths are refused.
    BadFolder,
    /// This loader variable is set, and it can replace the file. macOS only.
    UnsafeEnvironment(String),
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

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadFolder => f.write_str("The VPN library's folder is not a usable path."),
            Self::UnsafeEnvironment(name) => write!(
                f,
                "The environment variable {name} is set. Unset it and start again."
            ),
            Self::LoadedEarly => f.write_str("A VPN library was already loaded."),
            Self::NotFound => f.write_str("The VPN library could not be loaded."),
            Self::WrongFolder => f.write_str("The VPN library came from the wrong folder."),
            Self::MissingFunction | Self::WrongVersion => {
                f.write_str("The VPN library is not the expected version.")
            }
        }
    }
}

/// Declares [`Library`] from the functions' C signatures, written by hand
/// from `openconnect.h` of the pinned release. A function `name` is
/// `openconnect_name` in the library.
macro_rules! library {
    ($(fn $name:ident($($arg:ty),*) $(-> $ret:ty)?;)*) => {
        /// The loaded library: one pointer per declared function, filled in
        /// by [`Library::load`]. Every call into the library goes through
        /// this, so there is nothing to call before `load` has succeeded.
        #[derive(Clone, Copy)]
        pub struct Library {
            $($name: unsafe extern "C" fn($($arg),*) $(-> $ret)?,)*
        }

        /// The name of every declared function, as the library spells it.
        pub const FUNCTIONS: &[&str] = &[$(concat!("openconnect_", stringify!($name))),*];

        impl Library {
            /// Looks every function up, and fails if one is missing.
            fn resolve(handle: *mut c_void) -> Result<Self, LoadError> {
                Ok(Self {$($name: {
                    let name = concat!("openconnect_", stringify!($name), "\0");
                    let name = CStr::from_bytes_with_nul(name.as_bytes());
                    let address = name.map_or(std::ptr::null_mut(), |name| os::symbol(handle, name));
                    if address.is_null() {
                        return Err(LoadError::MissingFunction);
                    }
                    // SAFETY: the pointer is the address of the function of
                    // that name in the library just loaded, which is never
                    // unloaded. The type is its signature in the pinned
                    // release, and `load` refuses any other release before
                    // anything but `get_version` can be called.
                    unsafe {
                        std::mem::transmute::<
                            *mut c_void,
                            unsafe extern "C" fn($($arg),*) $(-> $ret)?,
                        >(address)
                    }
                },)*})
            }
        }
    };
}

library! {
    fn get_version() -> *const c_char;
    fn init_ssl() -> c_int;
    fn vpninfo_new(
        *const c_char,
        Option<ValidatePeerCert>,
        Option<WriteNewConfig>,
        Option<ProcessAuthForm>,
        Option<Progress>,
        *mut c_void
    ) -> *mut VpnInfo;
    fn vpninfo_free(*mut VpnInfo);
    fn parse_url(*mut VpnInfo, *const c_char) -> c_int;
    fn set_system_trust(*mut VpnInfo, c_uint);
    fn get_peer_cert_hash(*mut VpnInfo) -> *const c_char;
    fn disable_ipv6(*mut VpnInfo) -> c_int;
    fn override_getaddrinfo(*mut VpnInfo, Option<GetAddrInfo>);
    fn setup_cmd_pipe(*mut VpnInfo) -> CmdPipe;
    fn obtain_cookie(*mut VpnInfo) -> c_int;
    fn get_cookie(*mut VpnInfo) -> *const c_char;
    fn set_cookie(*mut VpnInfo, *const c_char) -> c_int;
    fn mainloop(*mut VpnInfo, c_int, c_int) -> c_int;
}

impl Library {
    /// Loads `libopenconnect` from `dir`, looks up every function, and
    /// checks the version. Call it once per process. The module
    /// documentation says what this does and does not control.
    ///
    /// It takes a [`Prepared`], which only [`prepare_environment`] gives,
    /// so the environment has been dealt with first: GnuTLS reads some of
    /// its variables in the start-up code that loading runs.
    pub fn load(dir: &Path, _environment: &Prepared) -> Result<Self, LoadError> {
        let file = dir.join(os::FILE);
        // A NUL would make the loader read a shorter path than the one given.
        if !os::is_plain(dir) || file.as_os_str().as_encoded_bytes().contains(&0) {
            return Err(LoadError::BadFolder);
        }
        let library = Self::resolve(os::open(&file)?)?;
        os::confirm(library.get_version as *mut c_void, dir)?;
        // The signatures hold for the pinned release only.
        if !is_pinned(&library.version()) {
            return Err(LoadError::WrongVersion);
        }
        Ok(library)
    }

    /// The library's version string, such as `v9.21`.
    pub fn version(self) -> String {
        // SAFETY: `load` filled the pointer in. The function takes no
        // arguments, has had this signature in every release, and returns a
        // NUL-terminated string that is never freed.
        unsafe { CStr::from_ptr((self.get_version)()) }
            .to_string_lossy()
            .into_owned()
    }
}

#[link(name = "ubc_vpn_shim", kind = "static")]
unsafe extern "C" {
    /// In `shim.c`: formats a progress line and calls
    /// [`ubc_vpn_progress_line`] with it.
    fn ubc_vpn_progress(privdata: *mut c_void, level: c_int, fmt: *const c_char, ...);
}

/// Whether a log line is all of what the library logged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineState {
    /// The whole line.
    Whole,
    /// The line did not fit the shim's buffer and was cut. A secret in it
    /// may be cut too, and a cut secret matches no registered one: treat
    /// the line as holding part of one.
    Cut,
    /// The line could not be formatted. What arrives may be its beginning,
    /// or nothing.
    Failed,
}

/// Receives each line the library logs, with its `PRG_*` level. A line may
/// hold a secret: an engine passes it to `LogSink::log` and nowhere else.
pub type Lines = Box<dyn Fn(c_int, &CStr, LineState) + Send + Sync>;

/// Called by `shim.c` with one formatted log line. `state` is one of the
/// `UBC_VPN_LINE_*` values there.
///
/// # Safety
///
/// `privdata` must be null or the pointer [`Handle::new`] gave the library,
/// and `line` null or a NUL-terminated string valid for the call.
#[unsafe(no_mangle)]
unsafe extern "C" fn ubc_vpn_progress_line(
    privdata: *mut c_void,
    level: c_int,
    line: *const c_char,
    state: c_int,
) {
    if privdata.is_null() || line.is_null() {
        return;
    }
    // A value the shim does not send is read as the cautious one.
    let state = match state {
        0 => LineState::Whole,
        2 => LineState::Failed,
        _ => LineState::Cut,
    };
    // SAFETY: by the contract above `privdata` points to the `Lines` a live
    // `Handle` owns, and `line` is a NUL-terminated string for this call.
    let (lines, line) = unsafe { (&*privdata.cast::<Lines>(), CStr::from_ptr(line)) };
    // A panic must not unwind into C.
    let _ = catch_unwind(AssertUnwindSafe(|| lines(level, line, state)));
}

/// One `openconnect_info`, freed on drop. It is not `Send`: the thread that
/// makes it makes every library call on it.
pub struct Handle {
    library: Library,
    raw: *mut VpnInfo,
    /// What the library holds as `privdata`. Freed after the handle.
    lines: *mut Lines,
}

impl Handle {
    /// Makes a handle that logs to `lines`. The certificate and form
    /// callbacks are not set yet, so it cannot log in.
    pub fn new(library: Library, lines: Lines) -> Option<Self> {
        let lines = Box::into_raw(Box::new(lines));
        // SAFETY: the library is loaded. The user agent is a NUL-terminated
        // string the library copies; absent callbacks may be null; `lines`
        // stays valid until `drop` has freed the handle.
        let raw = unsafe {
            (library.vpninfo_new)(
                c"UBC VPN".as_ptr(),
                None,
                None,
                None,
                Some(ubc_vpn_progress),
                lines.cast(),
            )
        };
        let handle = Self {
            library,
            raw,
            lines,
        };
        (!raw.is_null()).then_some(handle)
    }

    /// `openconnect_parse_url`: zero, or a negative errno.
    pub fn parse_url(&self, url: &CStr) -> c_int {
        // SAFETY: `raw` is a live handle used on its own thread, and `url`
        // is a NUL-terminated string the library copies.
        unsafe { (self.library.parse_url)(self.raw, url.as_ptr()) }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            // SAFETY: `raw` came from `openconnect_vpninfo_new` and is freed
            // once. The library may log while freeing, so `lines` goes last.
            unsafe { (self.library.vpninfo_free)(self.raw) };
        }
        // SAFETY: `lines` came from `Box::into_raw` in `new`, and nothing
        // can reach it now that the handle is gone.
        drop(unsafe { Box::from_raw(self.lines) });
    }
}

/// Proof that [`prepare_environment`] ran and found the environment safe.
/// [`Library::load`] takes one, so the two cannot be called in the wrong
/// order. Nothing else can make one.
#[derive(Debug)]
pub struct Prepared(());

/// Makes the process's environment safe for the library. Call it once, first
/// thing in `main`, before any thread exists and before [`Library::load`]. A
/// second call in the same process is an error.
///
/// - **Windows:** removes every one of
///   [`DANGEROUS_VARIABLES`](crate::environment::DANGEROUS_VARIABLES). With
///   `temp`, also points `TMP` and `TEMP` at that folder, where the library
///   makes the socket file of its command pipe. The service passes a folder
///   only the system and administrators can write. The changes are made in
///   the C runtime the libraries use as well as in the process environment:
///   the libraries read the runtime's copy, which the Rust standard library
///   does not change.
/// - **macOS and Linux:** changes nothing, because a variable cannot be
///   removed safely there, and fails as [`check_environment`] does for the
///   role. `temp` is not used; the command pipe is a plain pipe.
pub fn prepare_environment(role: Role, temp: Option<&Path>) -> Result<Prepared, EnvironmentError> {
    // Once, whatever comes of it: the C runtime's setter is not safe against
    // another thread that is reading the environment, and a second call
    // would come when threads exist.
    static CALLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if CALLED.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return Err(EnvironmentError::AlreadyPrepared);
    }
    #[cfg(windows)]
    {
        for (name, _) in crate::environment::DANGEROUS_VARIABLES {
            os::set_variable(name, None)?;
        }
        if let Some(temp) = temp {
            // A folder on a drive letter, as for the library's own: not a share.
            if !os::is_plain(temp) || !temp.is_dir() {
                return Err(EnvironmentError::BadTemp);
            }
            os::set_variable("TMP", Some(temp))?;
            os::set_variable("TEMP", Some(temp))?;
        }
    }
    #[cfg(not(windows))]
    let _ = temp;
    // On Windows this confirms the removal, as far as Rust can see it.
    // Elsewhere it is the whole step.
    check_environment(role).map(|()| Prepared(()))
}

/// Whether `version` is the pinned release. Ubuntu, for one, ships an older
/// release with known bugs.
///
/// The library takes its version from `git describe`. The Windows build is
/// made from an archive with no git history and reports `v9.21-unknown`. A
/// build from any later commit has a count and a hash after the tag.
pub fn is_pinned(version: &str) -> bool {
    version == PINNED || version.strip_suffix("-unknown") == Some(PINNED)
}

#[cfg(windows)]
mod os {
    use std::ffi::{CStr, OsStr, c_char, c_int, c_void};
    use std::os::windows::ffi::OsStrExt;
    use std::path::{Component, Path, Prefix};
    use std::ptr;

    use super::LoadError;
    use crate::environment::EnvironmentError;

    pub(super) const FILE: &str = "libopenconnect-5.dll";
    const LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR: u32 = 0x0100;
    const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x0800;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn SetDefaultDllDirectories(flags: u32) -> i32;
        fn LoadLibraryExW(name: *const u16, file: *mut c_void, flags: u32) -> *mut c_void;
        fn GetModuleHandleW(name: *const u16) -> *mut c_void;
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

    /// Sets a variable, or removes it, where the bundled libraries read it.
    ///
    /// They are built against the Universal C Runtime and read its copy of
    /// the environment, with `getenv` and `_wgetenv`. That copy is made when
    /// the runtime starts, and `SetEnvironmentVariable`, which is all the
    /// Rust standard library calls, does not change it. So the change goes
    /// through `ucrtbase.dll` itself, asked for by name: this program's own
    /// C runtime may be a private one. The runtime passes the change on to
    /// the process environment; that is repeated here in case it did not.
    pub(super) fn set_variable(name: &str, value: Option<&Path>) -> Result<(), EnvironmentError> {
        let value = value.map_or(OsStr::new(""), Path::as_os_str);
        let (wide_name, wide_value) = (wide(OsStr::new(name)), wide(value));
        if wide_value.iter().filter(|unit| **unit == 0).count() != 1 {
            return Err(EnvironmentError::BadTemp);
        }
        let runtime = wide(OsStr::new("ucrtbase.dll"));
        // SAFETY: `runtime` is NUL-terminated UTF-16 and outlives the call;
        // the second argument is reserved. Only System32 is searched.
        let runtime = unsafe {
            LoadLibraryExW(
                runtime.as_ptr(),
                ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
        if runtime.is_null() {
            return Err(EnvironmentError::Runtime);
        }
        // SAFETY: `runtime` is a loaded module, and the name is a
        // NUL-terminated string.
        let put = unsafe { GetProcAddress(runtime, c"_wputenv_s".as_ptr()) };
        if put.is_null() {
            return Err(EnvironmentError::Runtime);
        }
        // SAFETY: `put` is the runtime's
        // `errno_t _wputenv_s(const wchar_t *, const wchar_t *)`.
        let put = unsafe {
            std::mem::transmute::<*mut c_void, unsafe extern "C" fn(*const u16, *const u16) -> c_int>(
                put,
            )
        };
        // SAFETY: both strings are NUL-terminated UTF-16 that outlive the
        // call, which copies them. An empty value removes the variable.
        if unsafe { put(wide_name.as_ptr(), wide_value.as_ptr()) } != 0 {
            return Err(EnvironmentError::Runtime);
        }
        // SAFETY: the standard library documents `set_var` and `remove_var`
        // as always safe to call on Windows, in single-threaded and
        // multi-threaded programs. They are `unsafe` because of other systems.
        unsafe {
            if value.is_empty() {
                std::env::remove_var(name);
            } else {
                std::env::set_var(name, value);
            }
        }
        Ok(())
    }
}

#[cfg(unix)]
mod os {
    use std::ffi::{CStr, CString, OsStr, c_char, c_int, c_void};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;
    use std::{fs, ptr};

    use super::LoadError;

    #[cfg(target_os = "macos")]
    pub(super) const FILE: &str = "libopenconnect.5.dylib";
    #[cfg(not(target_os = "macos"))]
    pub(super) const FILE: &str = "libopenconnect.so.5";

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
        let mut names = std::env::vars_os().map(|(name, _)| name);
        if let Some(name) = names.find(|name| cfg!(target_os = "macos") && redirects(name)) {
            return Err(LoadError::UnsafeEnvironment(
                name.to_string_lossy().into_owned(),
            ));
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
}
