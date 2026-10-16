//! What the tests that run the real programs share: a temporary home for
//! dev mode, child processes that are ended however a test ends, and waits
//! that have an end.
//!
//! Each test file uses some of it and not all.
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const SERVICE: &str = "UBC_VPN_SYSTEM_SERVICE";
/// What the pretend gateway of dev mode accepts and issues. All made up.
pub const USERNAME: &str = "alice";
pub const PASSWORD: &str = "correct-horse-battery";
pub const CODE: &str = "123456";
pub const COOKIE: &str = "Zq7-made-up-0123456789";
pub const ROUTES: &str = r#"{"subnets":["10.255.0.0/24"],"dns_domains":["dept.example.test"]}"#;
pub const PATIENCE: Duration = Duration::from_secs(30);

/// Everything any child wrote, on either stream.
pub type Said = Arc<Mutex<String>>;

/// Waits for `ready` to give something, but not for ever.
pub fn within<T>(what: &str, mut ready: impl FnMut() -> Option<T>) -> T {
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
pub fn follow(stream: impl Read + Send + 'static, said: &Said) -> Receiver<String> {
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
pub struct Running {
    pub child: Child,
    pub input: Option<ChildStdin>,
    pub out: Receiver<String>,
}

impl Running {
    pub fn start(mut command: Command, said: &Said) -> Self {
        let piped = || Stdio::piped();
        command.stdin(piped()).stdout(piped()).stderr(piped());
        let mut child = command.spawn().expect("the program starts");
        let out = follow(child.stdout.take().unwrap(), said);
        drop(follow(child.stderr.take().unwrap(), said));
        let input = child.stdin.take();
        Self { child, input, out }
    }

    pub fn say(&mut self, line: &str) {
        let input = self.input.as_mut().expect("standard input is open");
        writeln!(input, "{line}").expect("the program is reading");
    }

    /// The next line of standard output that contains `what`.
    pub fn until(&mut self, what: &str) -> String {
        let waiting = format!("a line with {what}");
        within(&waiting, || {
            let line = self.out.try_recv().ok()?;
            line.contains(what).then_some(line)
        })
    }

    /// Waits for the program to end and returns its exit status and the
    /// lines of standard output not read so far.
    pub fn end(mut self) -> (i32, Vec<String>) {
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

/// Makes a folder that must not exist yet, for this user alone.
pub fn create_private_dir(folder: &Path) -> std::io::Result<()> {
    let builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    let builder = {
        let mut private = builder;
        std::os::unix::fs::DirBuilderExt::mode(&mut private, 0o700);
        private
    };
    builder.create(folder)
}

/// A temporary home for dev mode, removed when dropped.
pub struct Home {
    pub root: PathBuf,
    pub variables: Vec<(&'static str, PathBuf)>,
    pub said: Said,
    /// The dev policy file, which the test may write again.
    pub policy: PathBuf,
}

/// The user's name as every program this test starts is told it, made up
/// so that a test can look for it in what they write.
pub const MADE_UP_USER: &str = "made-up-user-7f3a";

impl Home {
    pub fn new() -> Self {
        // Short, because a socket's path has to fit in a socket address.
        let base = match cfg!(unix) {
            true => PathBuf::from("/tmp"),
            false => std::env::temp_dir(),
        };
        // A name nobody can guess, and a folder that was not there before.
        let root = (0..8).find_map(|_| {
            use std::hash::{BuildHasher, Hasher};
            let random = std::collections::hash_map::RandomState::new();
            let name = format!("ubcvpn-sys-{:016x}", random.build_hasher().finish());
            let root = base.join(name);
            create_private_dir(&root).ok().map(|()| root)
        });
        let root = root.expect("a new temporary folder");
        let at = |name: &str| root.join(name);
        let mut variables = match cfg!(windows) {
            true => vec![("USERPROFILE", at("profile"))],
            false => vec![
                ("HOME", at("home")),
                ("XDG_CONFIG_HOME", at("config")),
                ("XDG_RUNTIME_DIR", at("run")),
                ("TMPDIR", at("tmp")),
            ],
        };
        // Saved passwords in a folder of this run's, never the user's
        // keyring. Only a debug build of the client reads this. A release
        // build ignores it and uses the OS keyring, so a test that would
        // reach the keyring that way runs it on CI only.
        variables.push(("UBC_VPN_TEST_KEYRING", at("keyring")));
        // Not folders: names. Nothing should read them; if anything does,
        // a test that looks for this name finds it.
        for name in ["USER", "USERNAME", "LOGNAME"] {
            variables.push((name, PathBuf::from(MADE_UP_USER)));
        }
        // Where dev mode keeps its files, by the platform crate's table.
        let dev = if cfg!(windows) {
            at("profile").join(r"AppData\Local\UBC VPN Dev")
        } else if cfg!(target_os = "macos") {
            at("home").join("Library/Application Support/UBC VPN Dev")
        } else {
            at("config").join("ubc-vpn-dev")
        };
        let places = variables.iter().filter(|(_, at)| at.is_absolute());
        let mut folders: Vec<PathBuf> = places.map(|(_, at)| at.clone()).collect();
        folders.push(dev.join("policy"));
        for folder in folders {
            std::fs::create_dir_all(folder).unwrap();
        }
        // A developer writes the dev policy by hand; so does this test.
        let pin = format!("pin-sha256:{}=", "A".repeat(43));
        let policy = format!(r#"{{"gateway":"vpn.example.test","pins":["{pin}"]}}"#);
        let policy_file = dev.join("policy/policy.json");
        std::fs::write(&policy_file, policy).unwrap();
        let said = Said::default();
        Self {
            root,
            variables,
            said,
            policy: policy_file,
        }
    }

    pub fn command(&self, program: &Path, args: &[&str]) -> Command {
        let mut command = Command::new(program);
        command
            .arg("--dev")
            .args(args)
            .envs(self.variables.iter().cloned());
        command
    }

    pub fn client(&self, args: &[&str]) -> Running {
        let program = Path::new(env!("CARGO_BIN_EXE_ubc-vpn"));
        Running::start(self.command(program, args), &self.said)
    }

    /// Runs the client to its end with `typed` on standard input.
    pub fn run(&self, args: &[&str], typed: &str) -> (i32, String) {
        let mut client = self.client(args);
        if !typed.is_empty() {
            client.say(typed);
        }
        let (status, lines) = client.end();
        (status, lines.join("\n"))
    }

    /// Runs `connect --json`, giving `replies` to its questions in turn; a
    /// reply of `None` is a cancel. Returns the exit status and last line.
    pub fn connect(&self, replies: &[Option<&str>]) -> (i32, String) {
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
