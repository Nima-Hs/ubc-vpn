//! The environment rules: the list, the check that runs in every build, and
//! the start-up step that exists with the `libopenconnect` feature. None of
//! it needs the native library to be loaded.
//!
//! A test cannot change its own environment safely, so each case runs this
//! same test program again as a child with the environment under test. The
//! child runs `child` below, which prints what the check and the step did.

use std::env;
use std::path::Path;
use std::process::Command;

use ubc_vpn_engine::{DANGEROUS_VARIABLES, EnvironmentError, Role, check_environment};

const CHILD: &str = "UBC_VPN_TEST_ENVIRONMENT_CHILD";
const TEMP: &str = "UBC_VPN_TEST_ENVIRONMENT_TEMP";
/// What the loader's own variables look like, on any OS.
const LOADER: [&str; 4] = [
    "LD_LIBRARY_PATH",
    "LD_PRELOAD",
    "DYLD_LIBRARY_PATH",
    "DYLD_X",
];

/// Runs a child that has `set` in its environment, and none of the listed
/// or loader variables besides. Returns what it printed after `label`.
fn run(label: &str, set: &[(&str, &str)], temp: Option<&Path>) -> String {
    let mut child = Command::new(env::current_exe().unwrap());
    child.args(["child", "--exact", "--nocapture", "--test-threads=1"]);
    let listed = DANGEROUS_VARIABLES.iter().map(|(name, _)| *name);
    for name in listed.chain(LOADER).chain(["GCONV_PATH"]) {
        child.env_remove(name);
    }
    child.env(CHILD, "1").envs(set.iter().copied());
    if let Some(temp) = temp {
        child.env(TEMP, temp);
    }
    let output = child.output().unwrap();
    let text = String::from_utf8_lossy(&output.stdout);
    // The test harness prints the test's name first, on the same line.
    let line = text
        .split(label)
        .nth(1)
        .and_then(|rest| rest.lines().next());
    line.unwrap_or_else(|| panic!("the child printed no {label} in: {text}"))
        .to_string()
}

fn refusal(error: EnvironmentError) -> String {
    format!("{:?}", Err::<(), _>(error))
}

/// Whether a variable is set where the libraries would read it. On Windows
/// that is the C runtime's copy as well as the process environment, and the
/// first is the one that matters; elsewhere the two are one.
#[cfg(feature = "libopenconnect")]
fn is_set(name: &str) -> bool {
    #[cfg(windows)]
    if c_runtime::get(name).is_some() {
        return true;
    }
    env::var_os(name).is_some()
}

/// Not a test of its own: the body of the child process.
#[test]
fn child() {
    if env::var_os(CHILD).is_none() {
        return;
    }
    println!("SERVICE: {:?}", check_environment(Role::Service));
    println!("CLIENT: {:?}", check_environment(Role::Client));
    #[cfg(feature = "libopenconnect")]
    {
        use ubc_vpn_engine::prepare_environment;
        let temp = env::var_os(TEMP).map(std::path::PathBuf::from);
        let result = prepare_environment(Role::Service, temp.as_deref()).map(|_prepared| ());
        let left = DANGEROUS_VARIABLES.iter().map(|(name, _)| *name);
        let left: Vec<&str> = left.filter(|name| is_set(name)).collect();
        // Both names, in both views on Windows, now hold the folder given.
        let folder = temp
            .as_ref()
            .map(|temp| temp.to_string_lossy().into_owned());
        let holds = |name: &str| {
            #[cfg(windows)]
            if c_runtime::get(name) != folder {
                return false;
            }
            env::var_os(name).map(|value| value.to_string_lossy().into_owned()) == folder
        };
        let moved = folder.is_some() && holds("TMP") && holds("TEMP");
        println!("STEP: {result:?} left={left:?} moved={moved}");
        let again = prepare_environment(Role::Service, None).map(|_prepared| ());
        println!("AGAIN: {again:?}");
    }
}

// Security rule: the list is spelled out here, so that deleting a name from
// the engine fails this test.
#[test]
fn every_dangerous_variable_is_on_the_list() {
    let names: Vec<&str> = DANGEROUS_VARIABLES.iter().map(|(name, _)| *name).collect();
    assert_eq!(
        names,
        [
            "SSLKEYLOGFILE",
            "GNUTLS_KEYLOGFILE",
            "GNUTLS_SYSTEM_PRIORITY_FILE",
            "GNUTLS_DEBUG_LEVEL",
            "GNUTLS_CPUID_OVERRIDE",
            "GNUTLS_BUFFER_RECLAIM",
            "GNUTLS_NO_EXPLICIT_INIT",
            "GNUTLS_NO_IMPLICIT_INIT",
            "NETTLE_FAT_VERBOSE",
            "XML_CATALOG_FILES",
            "XML_DEBUG_CATALOG",
        ]
    );
}

// Security rule: the check names any listed variable that is set, on every
// OS and in every build, and leaves `USER` and `NTLMUSER` alone. The service
// refuses all of them. A client may keep the two libxml2 ones on macOS and
// Linux, and nothing else: a key log would expose the login.
#[test]
fn the_check_names_each_dangerous_variable_that_is_set() {
    let clean = [("USER", "someone"), ("NTLMUSER", "someone")];
    for role in ["SERVICE: ", "CLIENT: "] {
        assert_eq!(run(role, &clean, None), "Ok(())");
        for (name, _) in DANGEROUS_VARIABLES {
            let kept = cfg!(unix) && role == "CLIENT: " && name.starts_with("XML_");
            let expected = if kept {
                "Ok(())".to_string()
            } else {
                refusal(EnvironmentError::Set(name))
            };
            assert_eq!(run(role, &[(name, "1")], None), expected, "{role}{name}");
        }
    }
}

// Security rule, macOS and Linux: the service refuses to start with a
// variable that steers the loader, and its name is not repeated. On Linux
// that includes `GCONV_PATH`. The client does not refuse; the two fallback
// variables are allowed for both.
#[test]
fn the_service_refuses_loader_variables_and_the_client_does_not() {
    let refused = refusal(EnvironmentError::LoaderVariable);
    let service = |name: &str| run("SERVICE: ", &[(name, "/somewhere")], None);
    for name in LOADER.into_iter().chain(["GCONV_PATH"]) {
        let steers = cfg!(unix) && (name != "GCONV_PATH" || cfg!(target_os = "linux"));
        let expected = if steers { refused.as_str() } else { "Ok(())" };
        assert_eq!(service(name), expected, "{name}");
        let client = run("CLIENT: ", &[(name, "/somewhere")], None);
        assert_eq!(client, "Ok(())", "{name}");
    }
    for name in [
        "DYLD_FALLBACK_LIBRARY_PATH",
        "LDFLAGS",
        "OLD_PATH",
        "GCONV_PATHS",
    ] {
        assert_eq!(service(name), "Ok(())", "{name}");
    }
}

// Security rule: the step runs once in a process. A second call would come
// when other threads may be reading the environment.
#[cfg(feature = "libopenconnect")]
#[test]
fn the_step_runs_only_once() {
    assert_eq!(
        run("AGAIN: ", &[], None),
        refusal(EnvironmentError::AlreadyPrepared)
    );
}

// Security rule, macOS and Linux: the step changes nothing and refuses to go
// on with any of the variables set.
#[cfg(all(feature = "libopenconnect", not(windows)))]
#[test]
fn the_step_refuses_each_dangerous_variable() {
    assert_eq!(run("STEP: ", &[], None), "Ok(()) left=[] moved=false");
    for (name, _) in DANGEROUS_VARIABLES {
        let expected = format!(
            "{} left=[{name:?}] moved=false",
            refusal(EnvironmentError::Set(name))
        );
        assert_eq!(run("STEP: ", &[(name, "1")], None), expected);
    }
    let loader = format!(
        "{} left=[] moved=false",
        refusal(EnvironmentError::LoaderVariable)
    );
    assert_eq!(run("STEP: ", &[("LD_PRELOAD", "/somewhere")], None), loader);
}

// Security rule, Windows: the step removes every variable where the libraries
// read it, which is the C runtime's copy, and the temporary folder becomes
// the one given there too. The child reads both through that runtime.
#[cfg(all(feature = "libopenconnect", windows))]
#[test]
fn the_step_removes_every_dangerous_variable_and_sets_the_temp_folder() {
    let all: Vec<(&str, &str)> = DANGEROUS_VARIABLES
        .iter()
        .map(|(name, _)| (*name, "1"))
        .collect();
    assert_eq!(run("STEP: ", &all, None), "Ok(()) left=[] moved=false");
    let temp = Path::new(env!("CARGO_TARGET_TMPDIR"));
    assert_eq!(run("STEP: ", &all, Some(temp)), "Ok(()) left=[] moved=true");
    // The folder must exist and be an absolute path on a drive letter: not
    // relative, even when it exists, and not a share. The variables are gone
    // all the same.
    let bad = format!("{} left=[] moved=false", refusal(EnvironmentError::BadTemp));
    let (drive, rest) = env!("CARGO_TARGET_TMPDIR").split_at(2);
    let share = format!(r"\\localhost\{}${rest}", &drive[..1]);
    for folder in [
        temp.join("missing"),
        "relative".into(),
        ".".into(),
        share.into(),
    ] {
        assert_eq!(run("STEP: ", &all, Some(&folder)), bad, "{folder:?}");
    }
}

/// The C runtime's own view of the environment, read the way the bundled
/// libraries read it.
#[cfg(all(windows, feature = "libopenconnect"))]
mod c_runtime {
    use std::ffi::{CStr, CString, c_char, c_void};

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetModuleHandleW(name: *const u16) -> *mut c_void;
        fn GetProcAddress(module: *mut c_void, name: *const c_char) -> *mut c_void;
    }

    /// `getenv` of the Universal C Runtime, which the libraries are built
    /// against, looked up by name in `ucrtbase.dll` as the engine's setter is.
    pub fn get(name: &str) -> Option<String> {
        let library: Vec<u16> = "ucrtbase.dll".encode_utf16().chain([0]).collect();
        let name = CString::new(name).unwrap();
        // SAFETY: the two names are NUL-terminated and outlive the calls;
        // each result is checked before it is used. `getenv` takes a
        // NUL-terminated name and returns null or a NUL-terminated string
        // that stays valid while nothing changes the environment, and it is
        // copied at once. The child runs this one test.
        unsafe {
            let module = GetModuleHandleW(library.as_ptr());
            assert!(!module.is_null(), "the C runtime is not loaded");
            let getenv = GetProcAddress(module, c"getenv".as_ptr());
            assert!(!getenv.is_null(), "the C runtime has no getenv");
            let getenv = std::mem::transmute::<
                *mut c_void,
                unsafe extern "C" fn(*const c_char) -> *const c_char,
            >(getenv);
            let value = getenv(name.as_ptr());
            (!value.is_null()).then(|| CStr::from_ptr(value).to_string_lossy().into_owned())
        }
    }
}
