//! The real programs together: `ubc-vpn-service --dev` as a child process,
//! and `ubc-vpn --dev` run against it over the real channel. No fake
//! transport and nothing scripted; only routing, DNS and the gateway are
//! pretend, as dev mode makes them.
//!
//! It runs only when `UBC_VPN_SYSTEM_SERVICE` names a service built with the
//! `dev-mode` feature, and says `RAN: system` when it has. The workflow that
//! sets the variable also checks for that line, so a skip cannot pass there.
//!
//! What keeps this apart from a real UBC VPN on the same machine:
//!
//! - Both programs run with `--dev`, whose files and channel are never the
//!   installed product's.
//! - Every child gets a home of its own under one temporary folder, removed
//!   at the end. On Linux `XDG_CONFIG_HOME` holds dev mode's files and
//!   `XDG_RUNTIME_DIR` its socket; on macOS `HOME` and `TMPDIR` do; on
//!   Windows `USERPROFILE` holds the files.
//! - On Windows the dev channel is a pipe named after the user, not after
//!   the profile, so it is shared with any other dev-mode service this user
//!   runs. The test checks first that none is running, and fails if one is.
//!
//! Not covered here: a second user of the computer, who must be refused.
//! That needs an account this test cannot make without admin rights; the
//! elevated tests of the platform crate cover it.
#![cfg(feature = "dev-mode")]

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const SERVICE: &str = "UBC_VPN_SYSTEM_SERVICE";
/// What the pretend gateway of dev mode accepts and issues. All made up.
const USERNAME: &str = "alice";
const PASSWORD: &str = "correct-horse-battery";
const CODE: &str = "123456";
const COOKIE: &str = "Zq7-made-up-0123456789";
const ROUTES: &str = r#"{"subnets":["10.255.0.0/24"],"dns_domains":["ece.example.test"]}"#;
const PATIENCE: Duration = Duration::from_secs(30);

/// Everything any child wrote, on either stream.
type Said = Arc<Mutex<String>>;

/// Waits for `ready` to give something, but not for ever.
fn within<T>(what: &str, mut ready: impl FnMut() -> Option<T>) -> T {
    let started = Instant::now();
    loop {
        if let Some(found) = ready() {
            return found;
        }
        assert!(started.elapsed() < PATIENCE, "waited too long for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Copies a child's stream into `said` as it arrives, and each whole line
/// to the returned receiver.
fn follow(stream: impl Read + Send + 'static, said: &Said) -> Receiver<String> {
    let (to, lines) = channel();
    let said = said.clone();
    std::thread::spawn(move || {
        for line in BufReader::new(stream).lines() {
            let Ok(line) = line else { break };
            said.lock().unwrap().push_str(&format!("{line}\n"));
            let _ = to.send(line);
        }
    });
    lines
}

/// A child process that is killed when the test lets go of it, however the
/// test ends.
struct Running {
    child: Child,
    input: Option<ChildStdin>,
    out: Receiver<String>,
}

impl Running {
    fn start(mut command: Command, said: &Said) -> Self {
        let piped = || Stdio::piped();
        command.stdin(piped()).stdout(piped()).stderr(piped());
        let mut child = command.spawn().expect("the program starts");
        let out = follow(child.stdout.take().unwrap(), said);
        drop(follow(child.stderr.take().unwrap(), said));
        let input = child.stdin.take();
        Self { child, input, out }
    }

    fn say(&mut self, line: &str) {
        let input = self.input.as_mut().expect("standard input is open");
        writeln!(input, "{line}").expect("the program is reading");
    }

    /// The next line of standard output that contains `what`.
    fn until(&mut self, what: &str) -> String {
        let waiting = format!("a line with {what}");
        within(&waiting, || {
            let line = self.out.try_recv().ok()?;
            line.contains(what).then_some(line)
        })
    }

    /// Waits for the program to end and returns its exit status and the
    /// lines of standard output not read so far.
    fn end(mut self) -> (i32, Vec<String>) {
        drop(self.input.take());
        let status = within("the program to end", || self.child.try_wait().unwrap());
        // The reader ends when the stream closes, which it now has.
        let mut rest = Vec::new();
        while let Ok(line) = self.out.recv_timeout(Duration::from_secs(5)) {
            rest.push(line);
        }
        (status.code().expect("an exit status"), rest)
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A temporary home for dev mode, removed when dropped.
struct Home {
    root: PathBuf,
    variables: Vec<(&'static str, PathBuf)>,
    said: Said,
}

impl Home {
    fn new() -> Self {
        // Short, because a socket's path has to fit in a socket address.
        let base = match cfg!(unix) {
            true => PathBuf::from("/tmp"),
            false => std::env::temp_dir(),
        };
        let root = base.join(format!("ubcvpn-sys-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let at = |name: &str| root.join(name);
        let variables = match cfg!(windows) {
            true => vec![("USERPROFILE", at("profile"))],
            false => vec![
                ("HOME", at("home")),
                ("XDG_CONFIG_HOME", at("config")),
                ("XDG_RUNTIME_DIR", at("run")),
                ("TMPDIR", at("tmp")),
            ],
        };
        // Where dev mode keeps its files, by the platform crate's table.
        let dev = if cfg!(windows) {
            at("profile").join(r"AppData\Local\UBC VPN Dev")
        } else if cfg!(target_os = "macos") {
            at("home").join("Library/Application Support/UBC VPN Dev")
        } else {
            at("config").join("ubc-vpn-dev")
        };
        let mut folders: Vec<PathBuf> = variables.iter().map(|(_, at)| at.clone()).collect();
        folders.push(dev.join("policy"));
        for folder in folders {
            std::fs::create_dir_all(folder).unwrap();
        }
        // A developer writes the dev policy by hand; so does this test.
        let pin = format!("pin-sha256:{}=", "A".repeat(43));
        let policy = format!(r#"{{"gateway":"vpn.example.test","pins":["{pin}"]}}"#);
        std::fs::write(dev.join("policy/policy.json"), policy).unwrap();
        let said = Said::default();
        Self {
            root,
            variables,
            said,
        }
    }

    fn command(&self, program: &Path, args: &[&str]) -> Command {
        let mut command = Command::new(program);
        command
            .arg("--dev")
            .args(args)
            .envs(self.variables.iter().cloned());
        command
    }

    fn client(&self, args: &[&str]) -> Running {
        let program = Path::new(env!("CARGO_BIN_EXE_ubc-vpn"));
        Running::start(self.command(program, args), &self.said)
    }

    /// Runs the client to its end with `typed` on standard input.
    fn run(&self, args: &[&str], typed: &str) -> (i32, String) {
        let mut client = self.client(args);
        if !typed.is_empty() {
            client.say(typed);
        }
        let (status, lines) = client.end();
        (status, lines.join("\n"))
    }

    /// Runs `connect --json`, giving `replies` to its questions in turn; a
    /// reply of `None` is a cancel. Returns the exit status and last line.
    fn connect(&self, replies: &[Option<&str>]) -> (i32, String) {
        let mut client = self.client(&["connect", "--json"]);
        for (asked, reply) in replies.iter().enumerate() {
            let id = asked + 1;
            client.until(&format!(r#"{{"type":"prompt","id":{id},"#));
            match reply {
                Some(value) => {
                    client.say(&format!(
                        r#"{{"type":"answer","id":{id},"value":"{value}"}}"#
                    ));
                }
                None => client.say(r#"{"type":"cancel"}"#),
            }
        }
        let last = within("the last line", || {
            let line = client.out.try_recv().ok()?;
            let ending = line.contains(r#""type":"done""#) || line.contains(r#""type":"error""#);
            ending.then_some(line)
        });
        let (status, rest) = client.end();
        assert_eq!(rest, [""; 0], "nothing follows the last line");
        (status, last)
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn the_service_and_the_client_work_together() {
    let Some(service) = std::env::var_os(SERVICE) else {
        eprintln!("SKIPPED: system: {SERVICE} does not name a dev-mode service");
        return;
    };
    let home = Home::new();
    let state = |state: &str| format!(r#""state":"{state}""#);
    let connected = "Connected (fake0 as 10.255.0.2)\n  Subnets: 10.255.0.0/24\n  \
                     DNS domains: ece.example.test";

    // Nothing is running yet. On Windows this also shows that no other
    // dev-mode service of this user holds the channel.
    assert_eq!(
        home.run(&["status"], "").0,
        3,
        "a service is running already"
    );

    let service = home.command(Path::new(&service), &[]);
    let _service = Running::start(service, &home.said);
    // The first status that finds the service also makes this user its owner.
    let first = within("the service to listen", || {
        let (status, out) = home.run(&["status"], "");
        (status != 3).then_some((status, out))
    });
    assert_eq!(first, (0, "Disconnected".to_string()));

    // Settings: nothing saved yet, then a small set of routes.
    let (status, shown) = home.run(&["settings", "get", "--json"], "");
    assert!(status == 0 && shown.contains(r#""subnets":[]"#), "{shown}");
    let (status, checked) = home.run(&["settings", "check-routes", "--json"], ROUTES);
    assert!(
        status == 0 && checked.contains("10.255.0.0/24"),
        "{checked}"
    );
    let (status, saved) = home.run(&["settings", "set-routes", "--json"], ROUTES);
    assert_eq!((status, &saved), (0, &checked));
    let (status, shown) = home.run(&["settings", "get", "--json"], "");
    assert!(status == 0 && shown.contains("ece.example.test"), "{shown}");
    let (status, refused) = home.run(&["settings", "set-routes", "--json"], "not json");
    assert_eq!((status, refused.as_str()), (1, r#"{"error":"bad_input"}"#));

    // The bridge, held open as the app holds it.
    let mut bridge = home.client(&["bridge"]);
    let ready = bridge.until(r#""type":"ready""#);
    assert!(ready.contains(r#""owner_claimed":true"#), "{ready}");
    bridge.say(r#"{"id":1,"body":{"method":"status"}}"#);
    let answered = bridge.until(r#""id":1"#);
    assert!(answered.contains(&state("disconnected")), "{answered}");

    // Connect and disconnect, twice: the pretend gateway takes a new login
    // after a log-off.
    for round in 1..=2 {
        let replies = [Some(USERNAME), Some(PASSWORD), Some(CODE)];
        let (status, last) = home.connect(&replies);
        assert_eq!(
            (status, last.as_str()),
            (0, r#"{"type":"done"}"#),
            "{round}"
        );
        bridge.until(&state("connecting"));
        bridge.until(&state("connected"));
        assert_eq!(home.run(&["status"], ""), (0, connected.to_string()));
        // Connected already: busy, and nothing is asked.
        let (status, last) = home.connect(&[]);
        assert!(status == 7 && last.contains(r#""code":"busy""#), "{last}");

        let (status, out) = home.run(&["disconnect"], "");
        assert_eq!((status, out.as_str()), (0, "Disconnected"), "{round}");
        bridge.until(&state("disconnecting"));
        bridge.until(&state("disconnected"));
    }

    // A cancel at the password, and a wrong password: nothing is connected.
    let (status, last) = home.connect(&[Some(USERNAME), None]);
    assert!(
        status == 9 && last.contains(r#""code":"cancelled""#),
        "{last}"
    );
    let wrong = [Some(USERNAME), Some("wrong-password-0000"), Some(CODE)];
    let (status, last) = home.connect(&wrong);
    assert!(
        status == 8 && last.contains(r#""code":"wrong_password""#),
        "{last}"
    );
    assert_eq!(home.run(&["status"], ""), (0, "Disconnected".to_string()));
    // In a terminal's place there is a pipe here, so the plain connect asks
    // nothing and says why.
    assert_eq!(home.run(&["connect"], "").0, 1);

    // The app quits: the bridge ends quietly, having passed on nothing else.
    let (status, rest) = bridge.end();
    assert_eq!((status, rest), (0, Vec::new()));

    // Security rule: no password, code or cookie in anything any of the
    // programs wrote, on standard output or standard error.
    // What the last programs wrote may still be on its way here.
    let said = within("everything that was written", || {
        let said = home.said.lock().unwrap().clone();
        let all = said.contains("is running") && said.contains("Run it in a terminal");
        all.then_some(said)
    });
    for secret in [PASSWORD, CODE, COOKIE, "wrong-password-0000"] {
        assert!(!said.contains(secret), "{secret} was written:\n{said}");
    }
    println!("RAN: system");
}
