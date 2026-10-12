//! Starts the stand-in gateway (`fake_gateway.py`) for a test and stops it.
//!
//! A test file includes this with `#[path = "gateway/mod.rs"] mod gateway;`.
//!
//! The gateway needs a Python and a throwaway TLS key, which a test cannot
//! make. They come from the environment:
//!
//! - `UBC_VPN_TEST_PYTHON`: the Python to run.
//! - `UBC_VPN_TEST_GATEWAY_DIR`: a folder outside the repository holding
//!   `cert.pem` and `key.pem`, made for this run and thrown away after it.
//!   Request logs are written there too. They hold whatever the client sent,
//!   which in these tests is only made-up names, passwords and cookies.
//!
//! Without them a test is skipped and says so. With
//! `UBC_VPN_TEST_REQUIRE_GATEWAY` set, as in CI, it fails instead.

#![allow(dead_code)]

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{env, fs};

/// How long a gateway may take to start and print its ports.
const START_LIMIT: std::time::Duration = std::time::Duration::from_secs(30);

/// A running gateway. Dropping it stops it, also when a test panics.
pub struct Gateway {
    child: Child,
    /// The port the gateway itself listens on, on 127.0.0.1.
    pub port: u16,
    /// The port of the second listener, which a correct client never uses.
    pub other_port: u16,
    log: PathBuf,
}

/// The Python and the folder from the environment, or `None` to skip.
fn tools() -> Option<(PathBuf, PathBuf)> {
    let found = env::var_os("UBC_VPN_TEST_PYTHON").zip(env::var_os("UBC_VPN_TEST_GATEWAY_DIR"));
    if found.is_none() {
        assert!(
            env::var_os("UBC_VPN_TEST_REQUIRE_GATEWAY").is_none(),
            "the gateway tests were required to run, but UBC_VPN_TEST_PYTHON or \
             UBC_VPN_TEST_GATEWAY_DIR is not set"
        );
        println!("SKIPPED: no Python or key for the stand-in gateway");
    }
    found.map(|(python, dir)| (python.into(), dir.into()))
}

fn script(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/gateway")
        .join(name)
}

impl Gateway {
    /// Starts the gateway in `scenario` on ports the system chooses, or
    /// returns `None` when the test is to be skipped.
    pub fn start(scenario: &str) -> Option<Self> {
        static COUNT: AtomicUsize = AtomicUsize::new(0);
        let (python, dir) = tools()?;
        // One log per gateway: tests run side by side.
        let number = COUNT.fetch_add(1, Ordering::SeqCst);
        let log = dir.join(format!(
            "requests-{}-{number}-{scenario}.log",
            std::process::id()
        ));
        let mut child = Command::new(python)
            // -I: Python takes no code or settings from the folder it runs in.
            .arg("-I")
            .arg(script("fake_gateway.py"))
            .args([dir.join("cert.pem"), dir.join("key.pem")])
            .arg(scenario)
            .arg(&log)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .spawn()
            .expect("the Python for the gateway starts");
        // Owned from here on, so that a panic below still stops the child.
        let stdout = child.stdout.take().expect("the gateway's output is piped");
        let mut gateway = Self {
            child,
            port: 0,
            other_port: 0,
            log,
        };
        // Read on a thread of its own, so that a gateway that starts and
        // never says where it listens fails the test and does not hold it.
        // When the test gives up, dropping `gateway` kills the child, which
        // ends the read.
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut first = String::new();
            let _ = BufReader::new(stdout).read_line(&mut first);
            let _ = sender.send(first);
        });
        let first = receiver
            .recv_timeout(START_LIMIT)
            .expect("the gateway said where it listens in time");
        let ports = first.strip_prefix("PORTS ").unwrap_or_default();
        let mut ports = ports.split_whitespace().map(str::parse);
        let (Some(Ok(port)), Some(Ok(other))) = (ports.next(), ports.next()) else {
            panic!("the gateway did not say where it listens: {first:?}");
        };
        (gateway.port, gateway.other_port) = (port, other);
        Some(gateway)
    }

    /// Every request received so far, one JSON object per line, each saying
    /// which listener got it.
    pub fn requests(&self) -> Vec<String> {
        let log = fs::read_to_string(&self.log).unwrap_or_default();
        log.lines().map(str::to_string).collect()
    }
}

impl Drop for Gateway {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_file(&self.log);
    }
}

/// Posts to a port on this machine with the plain client beside the gateway
/// and returns the JSON line it prints. For tests of the gateway itself.
pub fn post(port: u16, path: &str, body: &str) -> String {
    let (python, _) = tools().expect("a gateway is running, so the tools exist");
    let output = Command::new(python)
        .arg("-I")
        .arg(script("client.py"))
        .args([&port.to_string(), path, body])
        .output()
        .expect("the Python for the client starts");
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}
