//! Loads the real `libopenconnect` and calls it.
//!
//! Needs `--features libopenconnect` and `UBC_VPN_NATIVE_DIR` (see
//! `build.rs`). The `Engine` workflow runs it on all three OSes. On macOS
//! and Linux it compiles a small stand-in library with `cc`.
//!
//! What a process has loaded cannot be undone, and the loader reads its
//! environment at start. So every case runs this same test program again as
//! a child, set up the way a careless or hostile start would be. The child
//! runs `child` below and prints what happened.

#![cfg(feature = "libopenconnect")]

#[path = "../src/ffi.rs"]
mod ffi;

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::{env, fs};

use ffi::{Library, LoadError, os};

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
            .arg(dir.join(os::FILE))
            .arg(&source)
            .status();
        assert!(built.unwrap().success(), "cc could not build the stand-in");
    }
    dir
}

/// Runs a child that loads the library from `dir` and returns its report.
/// `set` adds to its environment, and `cwd` is where it starts.
fn run(dir: &Path, cwd: &Path, set: &[(&str, &OsStr)]) -> String {
    let mut child = Command::new(env::current_exe().unwrap());
    child.args(["child", "--exact", "--nocapture", "--test-threads=1"]);
    child.env("UBC_VPN_TEST_LOAD", dir).current_dir(cwd);
    child.envs(set.iter().copied());
    let output = child.output().unwrap();
    let text = String::from_utf8_lossy(&output.stdout);
    // The test harness prints the test's name first, on the same line.
    let line = text
        .split("LOAD: ")
        .nth(1)
        .and_then(|rest| rest.lines().next());
    line.unwrap_or_else(|| panic!("the child printed no result: {text}"))
        .to_string()
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
    if let Some(first) = env::var_os("UBC_VPN_TEST_CARELESS") {
        assert!(os::careless_load(&first), "the careless load itself failed");
    }
    // Windows: which of the folder's DLLs are in the process, and from where.
    #[cfg(windows)]
    let modules = || -> Vec<PathBuf> {
        let names = fs::read_dir(LIBS)
            .unwrap()
            .map(|entry| entry.unwrap().file_name());
        names
            .filter_map(|name| os::module_path(name.to_str()?))
            .collect()
    };
    #[cfg(windows)]
    let before = modules().len();
    let result = Library::load(&dir).map(Library::version);
    #[cfg(windows)]
    let report = format!(
        " before={before} elsewhere={} planted={}",
        modules()
            .iter()
            .filter(|path| path.parent() != Some(&dir))
            .count(),
        os::careless_load(OsStr::new("ubc-vpn-planted.dll")),
    );
    #[cfg(not(windows))]
    let report = "";
    println!("LOAD: {result:?}{report}");
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
        refused(LoadError::UnsafeEnvironment)
    );
    assert!(!marker.exists(), "the stand-in's code ran");
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

// Security rule: the folder must be a plain absolute path with no NUL.
#[test]
fn a_folder_that_is_not_a_plain_absolute_path_is_refused() {
    let libs = Path::new(LIBS);
    // The loader would stop reading at the NUL and load the real file.
    let cut = PathBuf::from(format!("{}\0x", libs.join(os::FILE).display()));
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
            Library::load(&dir).err(),
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
        fs::copy(Path::new(LIBS).join("zlib1.dll"), dir.join(os::FILE)).unwrap();
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
    let file = dir.join(os::FILE);
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
        PathBuf::from(os::FILE)
    } else {
        libs.join(os::FILE)
    };
    let set = [("UBC_VPN_TEST_CARELESS", first.as_os_str())];
    assert_eq!(outcome(libs, libs, &set), refused(LoadError::LoadedEarly));
    // Linux: a copy from another folder counts too. glibc would answer the
    // full path with that copy, because it has the same name inside.
    if cfg!(target_os = "linux") {
        let copy = scratch("early");
        copy_libs(&copy);
        let first = copy.join(os::FILE);
        let set = [("UBC_VPN_TEST_CARELESS", first.as_os_str())];
        assert_eq!(outcome(libs, libs, &set), refused(LoadError::LoadedEarly));
    }
}
