//! The service binary itself, run as a program.
//!
//! Where the OS has a real channel the binary can really start, so nothing
//! here runs it in a way that should succeed, and a run that does not end
//! by itself is stopped.

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use ubc_vpn_service::args::FORBIDDEN_ENV;

/// Runs the binary with none of the forbidden variables but `set`. Returns
/// whether it ended by itself with an error, and what it printed to standard
/// error. One that is still running after `limit` is stopped.
fn run(args: &[&str], set: Option<&str>, limit: Duration) -> (bool, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ubc-vpn-service"));
    for name in FORBIDDEN_ENV {
        command.env_remove(name);
    }
    command.args(args).envs(set.map(|name| (name, "1")));
    command.stdin(Stdio::null()).stdout(Stdio::null());
    let mut child = command.stderr(Stdio::piped()).spawn().unwrap();
    let started = Instant::now();
    let refused = loop {
        match child.try_wait().unwrap() {
            Some(status) => break !status.success(),
            None if started.elapsed() > limit => {
                child.kill().unwrap();
                child.wait().unwrap();
                break false;
            }
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    };
    let mut stderr = String::new();
    let mut pipe = child.stderr.take().unwrap();
    pipe.read_to_string(&mut stderr).unwrap();
    (refused, stderr)
}

const SOON: Duration = Duration::from_secs(30);

// Security rule (architecture): dev mode is compiled out of a build without
// the `dev-mode` feature, so such a build does not know the flag.
#[cfg(not(feature = "dev-mode"))]
#[test]
fn a_build_without_dev_mode_rejects_the_dev_flag() {
    let (refused, stderr) = run(&["--dev"], None, SOON);
    assert!(
        refused && stderr.contains("unknown argument: --dev"),
        "{stderr}"
    );
}

// With the feature the flag is known. Where the OS has no channel yet, dev
// mode says why it cannot run; where it has one, it runs until stopped.
#[cfg(feature = "dev-mode")]
#[test]
fn a_build_with_dev_mode_knows_the_dev_flag() {
    let (_, stderr) = run(&["--dev"], None, Duration::from_secs(3));
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
        let (refused, stderr) = run(&[], Some(name), SOON);
        let because = format!("refusing to start while {name} is set");
        assert!(refused && stderr.contains(&because), "{stderr}");
    }
}
