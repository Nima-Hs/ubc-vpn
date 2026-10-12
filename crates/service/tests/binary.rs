//! The service binary itself, run as a program.
//!
//! Where the OS has a real channel the binary can really start. In a default
//! build nothing here runs it in a way that should succeed. With `dev-mode`
//! one test may start a dev-mode service for a moment. Either way a run that
//! does not end by itself is stopped, even if the test panics first.

use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use ubc_vpn_service::args::FORBIDDEN_ENV;

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

/// Runs the binary with none of the forbidden variables but `set`. Returns
/// whether it ended by itself with an error, and what it printed to standard
/// error. One that is still running at the limit is stopped.
fn run(args: &[&str], set: Option<&str>) -> (bool, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ubc-vpn-service"));
    for name in FORBIDDEN_ENV {
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

// With the feature the flag is known. Where the OS has no channel yet, dev
// mode says why it cannot run; where it has one, a dev-mode service runs on
// the developer's own dev channel until this test stops it.
#[cfg(feature = "dev-mode")]
#[test]
fn a_build_with_dev_mode_knows_the_dev_flag() {
    let (_, stderr) = run(&["--dev"], None);
    assert!(!stderr.contains("unknown argument"), "{stderr}");
}

// Security rule: the service does not start while a variable is set that
// makes a TLS library write out session keys or weaken its settings.
#[test]
fn refuses_to_start_while_a_tls_variable_is_set() {
    // Spelled out here, so that dropping one from the list is noticed.
    let names = [
        "SSLKEYLOGFILE",
        "GNUTLS_KEYLOGFILE",
        "GNUTLS_SYSTEM_PRIORITY_FILE",
        "GNUTLS_DEBUG_LEVEL",
    ];
    assert_eq!(names, FORBIDDEN_ENV);
    for name in names {
        let (refused, stderr) = run(&[], Some(name));
        let because = format!("refusing to start while {name} is set");
        assert!(refused && stderr.contains(&because), "{stderr}");
    }
}
