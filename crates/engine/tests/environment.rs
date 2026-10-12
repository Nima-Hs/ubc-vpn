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
    for name in listed.chain(LOADER) {
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
        let temp = env::var_os(TEMP).map(std::path::PathBuf::from);
        let result = ubc_vpn_engine::prepare_environment(Role::Service, temp.as_deref());
        let result = result.map(|_prepared| ());
        let left = DANGEROUS_VARIABLES.iter().map(|(name, _)| *name);
        let left: Vec<&str> = left.filter(|name| env::var_os(name).is_some()).collect();
        let now = (env::var_os("TMP"), env::var_os("TEMP"));
        let moved = temp.is_some() && now.0 == temp.map(Into::into) && now.0 == now.1;
        println!("STEP: {result:?} left={left:?} moved={moved}");
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

// Security rule: the check names any listed variable that is set, for both
// roles, on every OS and in every build. It leaves `USER` and `NTLMUSER`
// alone.
#[test]
fn the_check_names_each_dangerous_variable_that_is_set() {
    let clean = [("USER", "someone"), ("NTLMUSER", "someone")];
    for role in ["SERVICE: ", "CLIENT: "] {
        assert_eq!(run(role, &clean, None), "Ok(())");
        for (name, _) in DANGEROUS_VARIABLES {
            let found = run(role, &[(name, "1")], None);
            assert_eq!(found, refusal(EnvironmentError::Set(name)));
        }
    }
}

// Security rule, macOS and Linux: the service refuses to start with a
// variable that steers the loader, and its name is not repeated. The client
// does not refuse; the two fallback variables are allowed for both.
#[test]
fn the_service_refuses_loader_variables_and_the_client_does_not() {
    let refused = if cfg!(unix) {
        refusal(EnvironmentError::LoaderVariable)
    } else {
        "Ok(())".to_string()
    };
    for name in LOADER {
        assert_eq!(
            run("SERVICE: ", &[(name, "/somewhere")], None),
            refused,
            "{name}"
        );
        assert_eq!(
            run("CLIENT: ", &[(name, "/somewhere")], None),
            "Ok(())",
            "{name}"
        );
    }
    for name in ["DYLD_FALLBACK_LIBRARY_PATH", "LDFLAGS", "OLD_PATH"] {
        assert_eq!(
            run("SERVICE: ", &[(name, "/somewhere")], None),
            "Ok(())",
            "{name}"
        );
    }
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

// Security rule, Windows: the step removes every variable, and the temporary
// folder becomes the one given.
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
    // A folder that is missing or not absolute is an error, and the
    // variables are gone all the same.
    let bad = format!("{} left=[] moved=false", refusal(EnvironmentError::BadTemp));
    assert_eq!(run("STEP: ", &all, Some(&temp.join("missing"))), bad);
    assert_eq!(run("STEP: ", &all, Some(Path::new("relative"))), bad);
}
