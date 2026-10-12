//! The service binary itself, run as a program.

use std::process::Command;

use ubc_vpn_service::args::FORBIDDEN_ENV;

/// Runs the binary and returns whether it succeeded and what it printed to
/// standard error.
fn run(args: &[&str], set: Option<&str>) -> (bool, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ubc-vpn-service"));
    for name in FORBIDDEN_ENV {
        command.env_remove(name);
    }
    command.args(args).envs(set.map(|name| (name, "1")));
    let output = command.output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    (output.status.success(), stderr)
}

// Security rule (architecture): dev mode is compiled out of a build without
// the `dev-mode` feature, so such a build does not know the flag.
#[cfg(not(feature = "dev-mode"))]
#[test]
fn a_build_without_dev_mode_rejects_the_dev_flag() {
    let (ok, stderr) = run(&["--dev"], None);
    assert!(
        !ok && stderr.contains("unknown argument: --dev"),
        "{stderr}"
    );
}

// The channel is not implemented for any OS yet, so dev mode cannot be
// reached from another program. It must say so and not pretend to run.
#[cfg(feature = "dev-mode")]
#[test]
fn dev_mode_says_why_it_cannot_run_yet() {
    let (ok, stderr) = run(&["--dev"], None);
    assert!(
        !ok && stderr.contains("dev mode cannot run yet"),
        "{stderr}"
    );
}

// Security rule: the service does not start while a variable is set that
// makes GnuTLS write out session keys or weaken its settings.
#[test]
fn refuses_to_start_while_a_tls_variable_is_set() {
    for name in FORBIDDEN_ENV {
        let (ok, stderr) = run(&[], Some(name));
        assert!(
            !ok && stderr.contains(&format!("while {name} is set")),
            "{stderr}"
        );
    }
    let (_, stderr) = run(&[], None);
    assert!(!stderr.contains("refusing"), "{stderr}");
}
