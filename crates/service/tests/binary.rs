//! The service binary itself, run as a program.
//!
//! Where the OS has a real channel the binary can really start, so nothing
//! here runs it in a way that should succeed. A run that does not end by
//! itself is a failure and is stopped, even if the test panics first.

use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use ubc_vpn_engine::DANGEROUS_VARIABLES;

/// A refusal is immediate, so a run still going after this is a failure, and
/// is not left running for long.
const LIMIT: Duration = Duration::from_secs(5);

/// The running program. Dropping it stops it.
struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Runs the binary with none of the forbidden variables but `set`, and none
/// that steers the loader: Cargo sets one of those for the tests it runs. Returns
/// whether it ended by itself with an error, and what it printed to standard
/// error. One that is still running at the limit is stopped.
fn run(args: &[&str], set: Option<&str>) -> (bool, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ubc-vpn-service"));
    for (name, _) in DANGEROUS_VARIABLES {
        command.env_remove(name);
    }
    let loader = |name: &std::ffi::OsString| {
        let name = name.to_string_lossy();
        name.starts_with("LD_") || name.starts_with("DYLD_")
    };
    for (name, _) in std::env::vars_os().filter(|(name, _)| loader(name)) {
        command.env_remove(name);
    }
    command.args(args).envs(set.map(|name| (name, "1")));
    command.stdin(Stdio::null()).stdout(Stdio::null());
    let mut running = Running(command.stderr(Stdio::piped()).spawn().unwrap());
    let started = Instant::now();
    let mut refused = false;
    while started.elapsed() < LIMIT {
        if let Some(status) = running.0.try_wait().unwrap() {
            refused = !status.success();
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let mut pipe = running.0.stderr.take().unwrap();
    // Stopped before its output is read, so the read cannot wait on it.
    drop(running);
    let mut stderr = String::new();
    pipe.read_to_string(&mut stderr).unwrap();
    (refused, stderr)
}

// Security rule (architecture): dev mode is compiled out of a build without
// the `dev-mode` feature, so such a build does not know the flag.
#[cfg(not(feature = "dev-mode"))]
#[test]
fn a_build_without_dev_mode_rejects_the_dev_flag() {
    let (refused, stderr) = run(&["--dev"], None);
    assert!(
        refused && stderr.contains("unknown argument: --dev"),
        "{stderr}"
    );
}

// With the feature the flag is known: the run gets past the arguments and is
// refused for the variable instead, at once and before anything starts.
#[cfg(feature = "dev-mode")]
#[test]
fn a_build_with_dev_mode_knows_the_dev_flag() {
    let (refused, stderr) = run(&["--dev"], Some("SSLKEYLOGFILE"));
    assert!(
        refused && stderr.contains("refusing to start while SSLKEYLOGFILE is set"),
        "{stderr}"
    );
    let (refused, stderr) = run(&["--dev", "--more"], Some("SSLKEYLOGFILE"));
    assert!(
        refused && stderr.contains("unknown argument: --more"),
        "{stderr}"
    );
}

// Security rule: a build with dev mode has the fake engine in it, so it
// never runs as the installed service, even with the real engine built in.
// It stops before it touches the system's folders or loads anything.
#[cfg(all(feature = "dev-mode", feature = "real-engine"))]
#[test]
fn a_build_with_dev_mode_never_runs_as_the_installed_service() {
    let (refused, stderr) = run(&[], None);
    let because = "a build with dev mode cannot run as the installed service";
    assert!(refused && stderr.contains(because), "{stderr}");
}

// A build without the real engine has nothing to connect with, and says so
// instead of starting. On Windows a run from a console stops earlier, because
// only the service manager starts the installed service; that is tested by
// on_windows_the_installed_service_needs_the_service_manager.
#[cfg(all(not(feature = "real-engine"), not(windows)))]
#[test]
fn a_build_without_the_real_engine_does_not_run_as_the_installed_service() {
    let (refused, stderr) = run(&[], None);
    assert!(refused && stderr.contains("no VPN engine"), "{stderr}");
}

// Security rule: the service does not start while a variable is set that
// makes a TLS library write out session keys or weaken its settings.
#[test]
fn refuses_to_start_while_a_tls_variable_is_set() {
    // The four the service has always refused, spelled out so that dropping
    // one from the engine's list is noticed here too.
    let always = [
        "SSLKEYLOGFILE",
        "GNUTLS_KEYLOGFILE",
        "GNUTLS_SYSTEM_PRIORITY_FILE",
        "GNUTLS_DEBUG_LEVEL",
    ];
    let names: Vec<&str> = DANGEROUS_VARIABLES.iter().map(|(name, _)| *name).collect();
    assert!(always.iter().all(|name| names.contains(name)), "{names:?}");
    for name in names {
        let (refused, stderr) = run(&[], Some(name));
        let because = format!("refusing to start while {name} is set");
        assert!(refused && stderr.contains(&because), "{stderr}");
    }
}

// Security rule, macOS and Linux: the installed service does not start while
// a variable that steers the system loader is set, and does not repeat the
// variable's name, which whoever set it chose.
#[cfg(unix)]
#[test]
fn refuses_to_start_while_a_loader_variable_is_set() {
    // Names the loader itself does nothing with when the value is no path.
    for name in ["LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH", "LD_ANYTHING"] {
        let (refused, stderr) = run(&[], Some(name));
        let because = "refusing to start while a variable that steers the system loader is set";
        assert!(refused && stderr.contains(because), "{name}: {stderr}");
        assert!(!stderr.contains(name), "{stderr}");
    }
}

// On Windows the installed service runs only under the service manager. Run
// from a console it stops at once and says so, before it opens anything.
#[cfg(windows)]
#[test]
fn on_windows_the_installed_service_needs_the_service_manager() {
    let (refused, stderr) = run(&[], None);
    assert!(
        refused && stderr.contains("started by the service manager"),
        "{stderr}"
    );
}
