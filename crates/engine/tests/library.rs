//! Loads the real `libopenconnect` and calls it.
//!
//! Needs `--features libopenconnect,fake` and `UBC_VPN_NATIVE_DIR` (see
//! `build.rs`). The `Engine` workflow runs it on all three OSes. On macOS
//! and Linux it compiles a small stand-in library with `cc`.
//!
//! What a process has loaded cannot be undone, and the loader reads its
//! environment at start. So every case runs this same test program again as
//! a child, set up the way a careless or hostile start would be. The child
//! runs `child` below and prints what happened.

#![cfg(all(feature = "libopenconnect", feature = "fake"))]

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::{env, fs};

use ubc_vpn_engine::ffi::{self, Callbacks, Handle, Library, LoadError};
use ubc_vpn_engine::{Role, prepare_environment};

const LIBS: &str = env!("UBC_VPN_NATIVE_LIBS");
/// The loader's search variable on this OS.
const SEARCH: &str = if cfg!(windows) {
    "PATH"
} else if cfg!(target_os = "macos") {
    "DYLD_LIBRARY_PATH"
} else {
    "LD_LIBRARY_PATH"
};

/// An empty folder of this test's own.
fn scratch(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("library")
        .join(name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Copies the files of the real library's folder into `to`.
fn copy_libs(to: &Path) {
    for entry in fs::read_dir(LIBS).unwrap().map(Result::unwrap) {
        if entry.path().is_file() {
            fs::copy(entry.path(), to.join(entry.file_name())).unwrap();
        }
    }
}

/// A folder holding what a hostile start would plant under the library's
/// name. Windows: copies of every real DLL, and one more under a name
/// nothing else has. macOS and Linux: a stand-in whose start-up code writes
/// a marker file, so that it shows if any of it ran.
fn hostile(name: &str) -> PathBuf {
    let dir = scratch(name);
    if cfg!(windows) {
        copy_libs(&dir);
        fs::copy(dir.join("zlib1.dll"), dir.join("ubc-vpn-planted.dll")).unwrap();
    } else {
        let source = dir.join("standin.c");
        let code = "#include <stdio.h>\n#include <stdlib.h>\n\
            __attribute__((constructor)) static void ran(void) {\n\
            const char *marker = getenv(\"UBC_VPN_TEST_MARKER\");\n\
            FILE *file = marker ? fopen(marker, \"w\") : NULL;\n\
            if (file) fclose(file);\n}\n";
        fs::write(&source, code).unwrap();
        let built = Command::new("cc")
            .args(["-shared", "-fPIC", "-o"])
            .arg(dir.join(ffi::FILE))
            .arg(&source)
            .status();
        assert!(built.unwrap().success(), "cc could not build the stand-in");
    }
    dir
}

/// Runs a child that loads the library from `dir` and returns its report.
/// `set` adds to its environment, and `cwd` is where it starts.
fn run(dir: &Path, cwd: &Path, set: &[(&str, &OsStr)]) -> String {
    printed("LOAD: ", dir, cwd, set)
}

/// The same, for the line the child printed after `label`.
fn printed(label: &str, dir: &Path, cwd: &Path, set: &[(&str, &OsStr)]) -> String {
    let output = child_output(dir, cwd, set);
    let text = String::from_utf8_lossy(&output.stdout);
    // The test harness prints the test's name first, on the same line.
    let line = text
        .split(label)
        .nth(1)
        .and_then(|rest| rest.lines().next());
    line.unwrap_or_else(|| panic!("the child printed no {label} in: {text}"))
        .to_string()
}

fn child_output(dir: &Path, cwd: &Path, set: &[(&str, &OsStr)]) -> std::process::Output {
    let mut child = Command::new(env::current_exe().unwrap());
    child.args(["child", "--exact", "--nocapture", "--test-threads=1"]);
    child.env("UBC_VPN_TEST_LOAD", dir).current_dir(cwd);
    child.envs(set.iter().copied());
    child.output().unwrap()
}

/// What the start-up step gives for a client, which `load` asks for. The
/// step runs once in a process, so its result is kept.
fn prepared() -> &'static ubc_vpn_engine::Prepared {
    static PREPARED: std::sync::OnceLock<ubc_vpn_engine::Prepared> = std::sync::OnceLock::new();
    PREPARED
        .get_or_init(|| prepare_environment(Role::Client, None).expect("the environment is clean"))
}

/// The result alone, without what Windows adds about the DLLs.
fn outcome(dir: &Path, cwd: &Path, set: &[(&str, &OsStr)]) -> String {
    let report = run(dir, cwd, set);
    report
        .split(" before=")
        .next()
        .unwrap_or_default()
        .to_string()
}

/// `dir` first in the loader's search variable.
fn searched(dir: &Path) -> std::ffi::OsString {
    let rest = env::var_os(SEARCH).unwrap_or_default();
    env::join_paths(
        [dir.to_path_buf()]
            .into_iter()
            .chain(env::split_paths(&rest)),
    )
    .unwrap()
}

fn refused(error: LoadError) -> String {
    format!("{:?}", Err::<String, _>(error))
}

/// Not a test of its own: the body of the child process.
#[test]
fn child() {
    let Some(dir) = env::var_os("UBC_VPN_TEST_LOAD").map(PathBuf::from) else {
        return;
    };
    // First, as in a real program: the environment step.
    let prepared = prepared();
    // Windows: puts two variables back the way a C library would, after the
    // step removed them, to show what the libraries do when they are there.
    #[cfg(windows)]
    if env::var_os("UBC_VPN_TEST_PUT_BACK").is_some() {
        raw::put_in_c_runtime(c"GNUTLS_DEBUG_LEVEL", c"9");
        raw::put_in_c_runtime(c"NETTLE_FAT_VERBOSE", c"1");
    }
    if let Some(first) = env::var_os("UBC_VPN_TEST_CARELESS") {
        assert!(
            raw::careless_load(&first),
            "the careless load itself failed"
        );
    }
    #[cfg(unix)]
    if let Some(name) = env::var_os("UBC_VPN_TEST_FORGET") {
        // SAFETY: this child runs this one test, and nothing else in it
        // touches the environment while the variable is removed.
        unsafe { raw::forget_variable(&name) };
    }
    // Windows: which of the folder's DLLs are in the process, and from where.
    #[cfg(windows)]
    let modules = || -> Vec<PathBuf> {
        let names = fs::read_dir(LIBS)
            .unwrap()
            .map(|entry| entry.unwrap().file_name());
        names
            .filter_map(|name| raw::module_path(name.to_str()?))
            .collect()
    };
    #[cfg(windows)]
    let before = modules().len();
    let loaded = Library::load(&dir, prepared);
    let result = loaded.clone().map(Library::version);
    #[cfg(windows)]
    let report = format!(
        " before={before} elsewhere={} planted={}",
        modules()
            .iter()
            .filter(|path| path.parent() != Some(&dir))
            .count(),
        raw::careless_load(OsStr::new("ubc-vpn-planted.dll")),
    );
    #[cfg(not(windows))]
    let report = "";
    println!("LOAD: {result:?}{report}");
    // What a handle logs when it is given server addresses it refuses. The
    // last one makes the library log about 9,000 bytes in one line.
    if let Ok(library) = loaded {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let lines = Arc::clone(&seen);
        let lines: ffi::Lines = Box::new(move |level, line, state| {
            let (length, line) = (line.to_bytes().len(), line.to_string_lossy());
            let start: String = line.chars().take(48).collect();
            lines.lock().unwrap().push((level, state, length, start));
        });
        let handle =
            Handle::new(library, Callbacks::refusing(lines)).expect("the library makes a handle");
        let long = std::ffi::CString::new(format!("ftp://{}", "h".repeat(9000))).unwrap();
        let results = [
            handle.parse_url(c"ftp://vpn.example.test"),
            handle.parse_url(c"http://vpn.example.test"),
            handle.parse_url(&long),
        ];
        drop(handle);
        println!("LOGGED: {results:?} {:?}", seen.lock().unwrap());
    }
}

// Security rule: the declared functions are spelled out here, so that a
// change to the table is a visible change to this list. Each signature was
// checked against `openconnect.h` of v9.21.
#[test]
fn the_declared_functions_are_the_reviewed_ones() {
    let reviewed = [
        "get_version",
        "init_ssl",
        "vpninfo_new",
        "vpninfo_free",
        "parse_url",
        "set_system_trust",
        "get_peer_cert_hash",
        "disable_ipv6",
        "override_getaddrinfo",
        "setup_cmd_pipe",
        "obtain_cookie",
        "get_cookie",
        "set_cookie",
        "mainloop",
        "set_option_value",
    ];
    let names: Vec<String> = reviewed
        .iter()
        .map(|name| format!("openconnect_{name}"))
        .collect();
    assert_eq!(ffi::FUNCTIONS, names);
}

// The library's log lines are printf-style. They reach Rust through the C
// shim, formatted, at the library's own level, and marked whole or cut.
//
// Security rule: a line longer than the shim's buffer is cut to fit it, and
// said to be cut. The real library's 9,000-byte line arrives as 4,095 bytes.
#[test]
fn a_handle_logs_through_the_shim() {
    let libs = Path::new(LIBS);
    let logged = printed("LOGGED: ", libs, libs, &[]);
    assert!(
        !logged.starts_with("[0, 0, 0]"),
        "none may be accepted: {logged}"
    );
    let lines = [
        // Each is the line's length and its first 48 characters.
        r#"(0, Whole, 52, "Failed to parse server URL 'ftp://vpn.example.te")"#,
        r#"(0, Whole, 39, "Only https:// permitted for server URL\n")"#,
        r#"(0, Cut, 4095, "Failed to parse server URL 'ftp://hhhhhhhhhhhhhh")"#,
    ];
    assert!(
        logged.ends_with(&format!("[{}]", lines.join(", "))),
        "{logged}"
    );
}

#[test]
fn only_the_pinned_version_is_accepted() {
    assert!(ffi::is_pinned("v9.21") && ffi::is_pinned("v9.21-unknown"));
    for other in ["v9.12", "v9.12-unknown", "v9.210", "v9.21-1-g8b702bf", ""] {
        assert!(!ffi::is_pinned(other), "{other}");
    }
}

// Security rule: the library comes from the given folder even when a copy
// sits in the working directory and first in the loader's search path, and
// none of that copy's code runs.
#[test]
fn a_planted_copy_is_not_loaded_and_does_not_run() {
    let libs = Path::new(LIBS);
    let planted = hostile("planted");
    let marker = planted.join("marker");
    let mut set = vec![("UBC_VPN_TEST_MARKER", marker.as_os_str())];
    let path = searched(&planted);
    // macOS refuses to load with the variable set; that is the next test.
    if !cfg!(target_os = "macos") {
        set.push((SEARCH, &path));
    }
    let report = run(libs, &planted, &set);
    println!("RAN: {report} from {LIBS}");
    let version = report.split('"').nth(1).unwrap_or_default();
    assert!(
        report.starts_with("Ok(") && ffi::is_pinned(version),
        "{report}"
    );
    // Windows: nothing was loaded before, everything loaded is from the
    // folder, and afterwards a name alone no longer finds the planted DLL.
    if cfg!(windows) {
        assert!(
            report.ends_with(" before=0 elsewhere=0 planted=false"),
            "{report}"
        );
    }
    assert!(!marker.exists(), "the stand-in's code ran");
}

// Security rule, macOS: dyld would try the stand-in before the full path,
// so nothing is loaded while a `DYLD_*` variable is set.
#[cfg(target_os = "macos")]
#[test]
fn nothing_is_loaded_with_a_dyld_variable_set() {
    let planted = hostile("dyld");
    let marker = planted.join("marker");
    let set = [
        ("UBC_VPN_TEST_MARKER", marker.as_os_str()),
        (SEARCH, planted.as_os_str()),
    ];
    assert_eq!(
        outcome(Path::new(LIBS), &planted, &set),
        refused(LoadError::UnsafeEnvironment(SEARCH.into()))
    );
    assert!(!marker.exists(), "the stand-in's code ran");
    // Not that one variable alone. This one makes dyld load the stand-in at
    // start, which is harmless here: it is given no marker to write.
    let inserted = planted.join(ffi::FILE);
    let insert = [("DYLD_INSERT_LIBRARIES", inserted.as_os_str())];
    let error = LoadError::UnsafeEnvironment("DYLD_INSERT_LIBRARIES".into());
    assert_eq!(
        outcome(Path::new(LIBS), &planted, &insert),
        refused(error.clone())
    );
    assert!(
        error
            .to_string()
            .contains("DYLD_INSERT_LIBRARIES is set. Unset it")
    );
    // The fallback variables are allowed, because dyld does not use them
    // for a full path. This fails if a later macOS does.
    let fallback = [set[0], ("DYLD_FALLBACK_LIBRARY_PATH", planted.as_os_str())];
    let empty = scratch("dyld-empty");
    assert_eq!(
        outcome(&empty, &empty, &fallback),
        refused(LoadError::NotFound)
    );
    assert!(!marker.exists(), "the stand-in's code ran");
}

// Security rule, macOS: dyld reads its variables when the process starts. If
// one is removed before `load`, the refusal above sees nothing and dyld
// still loads the copy it names. `load` must then say the file came from
// the wrong folder. The copy's code has run by then; this only stops it
// being used as the library.
#[cfg(target_os = "macos")]
#[test]
fn a_copy_loaded_through_a_removed_dyld_variable_is_refused() {
    let copy = scratch("removed");
    copy_libs(&copy);
    let set = [
        (SEARCH, copy.as_os_str()),
        ("UBC_VPN_TEST_FORGET", OsStr::new(SEARCH)),
    ];
    assert_eq!(
        outcome(Path::new(LIBS), &copy, &set),
        refused(LoadError::WrongFolder)
    );
}

// Security rule: the folder must be a plain absolute path with no NUL.
#[test]
fn a_folder_that_is_not_a_plain_absolute_path_is_refused() {
    let libs = Path::new(LIBS);
    // The loader would stop reading at the NUL and load the real file.
    let cut = PathBuf::from(format!("{}\0x", libs.join(ffi::FILE).display()));
    let mut bad = vec![PathBuf::from("."), PathBuf::from("lib"), cut];
    if cfg!(windows) {
        // A share, a device form, and a path with no drive.
        let (drive, rest) = LIBS.split_at(2);
        bad.push(format!(r"\\localhost\{}${rest}", &drive[..1]).into());
        bad.push(format!(r"\\?\{LIBS}").into());
        bad.push(rest.into());
    }
    for dir in bad {
        assert_eq!(
            Library::load(&dir, prepared()).err(),
            Some(LoadError::BadFolder),
            "{dir:?}"
        );
    }
    assert_eq!(
        outcome(&scratch("empty"), libs, &[]),
        refused(LoadError::NotFound)
    );
}

// Security rule: a library that lacks a declared function fails at load,
// not at the first call.
#[test]
fn a_library_without_a_declared_function_is_refused() {
    let dir = if cfg!(windows) {
        let dir = scratch("other");
        fs::copy(Path::new(LIBS).join("zlib1.dll"), dir.join(ffi::FILE)).unwrap();
        dir
    } else {
        hostile("other")
    };
    assert_eq!(
        outcome(&dir, &dir, &[]),
        refused(LoadError::MissingFunction)
    );
}

// Security rule: `load` itself refuses another version. The copy differs
// from the real library in its version string only.
#[test]
fn a_library_of_another_version_is_refused() {
    let dir = scratch("version");
    copy_libs(&dir);
    let file = dir.join(ffi::FILE);
    let mut bytes = fs::read(&file).unwrap();
    let mut patched = 0;
    for at in 0..bytes.len() - 5 {
        if &bytes[at..at + 5] == b"v9.21" {
            bytes[at..at + 5].copy_from_slice(b"v9.99");
            patched += 1;
        }
    }
    assert!(patched > 0, "the version string was not found");
    fs::write(&file, bytes).unwrap();
    // macOS will not load a changed library until it is signed again.
    if cfg!(target_os = "macos") {
        let signed = Command::new("codesign")
            .args(["--force", "--sign", "-"])
            .arg(&file)
            .status();
        assert!(signed.unwrap().success());
    }
    assert_eq!(outcome(&dir, &dir, &[]), refused(LoadError::WrongVersion));
}

// Security rule: a `libopenconnect` that is in the process before the folder
// is chosen is refused, however it got there.
#[test]
fn a_library_loaded_before_the_folder_was_chosen_is_refused() {
    let libs = Path::new(LIBS);
    // Windows searches the working directory for a name alone.
    let first = if cfg!(windows) {
        PathBuf::from(ffi::FILE)
    } else {
        libs.join(ffi::FILE)
    };
    let set = [("UBC_VPN_TEST_CARELESS", first.as_os_str())];
    assert_eq!(outcome(libs, libs, &set), refused(LoadError::LoadedEarly));
    // Linux: a copy from another folder counts too. glibc would answer the
    // full path with that copy, because it has the same name inside.
    if cfg!(target_os = "linux") {
        let copy = scratch("early");
        copy_libs(&copy);
        let first = copy.join(ffi::FILE);
        let set = [("UBC_VPN_TEST_CARELESS", first.as_os_str())];
        assert_eq!(outcome(libs, libs, &set), refused(LoadError::LoadedEarly));
    }
}

// Security rule, Windows: the environment step removes a variable where the
// library reads it, which is the C runtime's copy and not the one Rust
// reads. So this watches two libraries: as they load, GnuTLS logs to standard
// error when `GNUTLS_DEBUG_LEVEL` is set, and Nettle when `NETTLE_FAT_VERBOSE`
// is. Reading a variable back through Rust would pass even if nothing a
// library sees had changed.
#[cfg(windows)]
#[test]
fn the_environment_step_changes_what_the_library_sees() {
    let libs = Path::new(LIBS);
    // Whether GnuTLS, and whether Nettle, wrote to standard error.
    let logs = |set: &[(&str, &OsStr)]| {
        let output = child_output(libs, libs, set);
        let report = String::from_utf8_lossy(&output.stdout).into_owned();
        assert!(report.contains("LOAD: Ok("), "{report}");
        let printed = String::from_utf8_lossy(&output.stderr).into_owned();
        (printed.contains("gnutls["), printed.contains("libnettle:"))
    };
    let set = [
        ("GNUTLS_DEBUG_LEVEL", OsStr::new("9")),
        ("NETTLE_FAT_VERBOSE", OsStr::new("1")),
    ];
    assert_eq!(
        logs(&set),
        (false, false),
        "a library still saw its variable"
    );
    // The control: put back in the C runtime after the step, both are seen.
    let put_back = ("UBC_VPN_TEST_PUT_BACK", OsStr::new("1"));
    assert_eq!(logs(&[set[0], set[1], put_back]), (true, true));
}

/// What a careless or hostile program does, for the child to act out. None
/// of it belongs in the engine.
mod raw {
    #[cfg(unix)]
    use std::ffi::OsStr;

    #[cfg(windows)]
    pub use windows::*;

    #[cfg(windows)]
    mod windows {
        use std::ffi::{CStr, OsStr, OsString, c_char, c_int, c_void};
        use std::os::windows::ffi::{OsStrExt, OsStringExt};
        use std::path::PathBuf;
        use std::ptr;

        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn LoadLibraryExW(name: *const u16, file: *mut c_void, flags: u32) -> *mut c_void;
            fn GetModuleHandleW(name: *const u16) -> *mut c_void;
            fn GetModuleFileNameW(module: *mut c_void, name: *mut u16, size: u32) -> u32;
        }

        unsafe extern "C" {
            fn _putenv_s(name: *const c_char, value: *const c_char) -> c_int;
        }

        fn wide(text: &OsStr) -> Vec<u16> {
            text.encode_wide().chain([0]).collect()
        }

        /// Asks Windows for a library by name, with its usual search.
        pub fn careless_load(name: &OsStr) -> bool {
            let name = wide(name);
            // SAFETY: `name` is NUL-terminated UTF-16 and outlives the call;
            // the second argument is reserved. Loading runs the library's
            // start-up code; the tests pass only our own libraries.
            !unsafe { LoadLibraryExW(name.as_ptr(), ptr::null_mut(), 0) }.is_null()
        }

        /// The file a loaded library of this name came from.
        pub fn module_path(name: &str) -> Option<PathBuf> {
            let name = wide(OsStr::new(name));
            let mut buffer = [0u16; 1024];
            // SAFETY: `name` is NUL-terminated UTF-16. A null module makes
            // the second call answer for the program, which is filtered out
            // below; `buffer` is writable for the length given.
            let (module, length) = unsafe {
                let module = GetModuleHandleW(name.as_ptr());
                (
                    module,
                    GetModuleFileNameW(module, buffer.as_mut_ptr(), 1024) as usize,
                )
            };
            let known = !module.is_null() && length > 0 && length < buffer.len();
            known.then(|| OsString::from_wide(&buffer[..length]).into())
        }

        /// Sets a variable in this program's C runtime, the one the
        /// libraries share with it in a test build.
        pub fn put_in_c_runtime(name: &CStr, value: &CStr) {
            // SAFETY: both are NUL-terminated strings that outlive the call,
            // which copies them. The child runs this one test.
            assert_eq!(unsafe { _putenv_s(name.as_ptr(), value.as_ptr()) }, 0);
        }
    }

    /// Loads a library the way a careless program does.
    #[cfg(unix)]
    pub fn careless_load(name: &OsStr) -> bool {
        use std::os::unix::ffi::OsStrExt;
        unsafe extern "C" {
            fn dlopen(
                path: *const std::ffi::c_char,
                mode: std::ffi::c_int,
            ) -> *mut std::ffi::c_void;
        }
        let name = std::ffi::CString::new(name.as_bytes()).unwrap();
        // SAFETY: `name` is a NUL-terminated string that outlives the call.
        // 2 is `RTLD_NOW`. Loading runs the library's start-up code; the
        // tests pass only our own libraries.
        !unsafe { dlopen(name.as_ptr(), 2) }.is_null()
    }

    /// Removes a variable from the environment, as a program that tidies up
    /// after its start would.
    ///
    /// # Safety
    ///
    /// No other thread may read or write the environment during the call.
    #[cfg(unix)]
    pub unsafe fn forget_variable(name: &OsStr) {
        // SAFETY: the caller keeps other threads off the environment.
        unsafe { std::env::remove_var(name) };
    }
}
