//! For tests only: a terminal of its own for a child process.
//!
//! A program that asks questions in the terminal can only be tested whole by
//! running it in one. [`spawn_in_terminal`] starts a program with a new
//! terminal as its controlling terminal and as its standard input, output
//! and error, and hands the test the other end: a [`Screen`] to read what
//! the program shows and to type into. Nobody's real terminal is involved,
//! and no window opens.
//!
//! Linux and macOS only, with a pseudo-terminal. On Windows every call
//! fails with [`Error::Unsupported`]: the standard library cannot start a
//! program in a pseudo-console, and nothing else gives a console that can be
//! typed into and looked at from outside without a window. The console
//! tests in this crate stand in for it there.
//!
//! The module exists only with the `fake` feature, which no shipped build
//! has.

use std::process::{Child, Command};
use std::time::Duration;

use crate::{Error, Result};

#[cfg(unix)]
#[path = "testing_unix.rs"]
mod os;

#[cfg(not(unix))]
mod os {
    use std::process::{Child, Command};
    use std::time::Duration;

    use crate::{Error, Result};

    pub(super) struct Screen;

    pub(super) fn spawn(_command: &mut Command) -> Result<(Child, Screen)> {
        Err(Error::Unsupported)
    }

    impl Screen {
        pub(super) fn wait_for(&mut self, _text: &str, _within: Duration) -> Result<String> {
            Err(Error::Unsupported)
        }

        pub(super) fn type_text(&mut self, _text: &str) -> Result<()> {
            Err(Error::Unsupported)
        }

        pub(super) fn echoes(&self) -> Result<bool> {
            Err(Error::Unsupported)
        }
    }
}

/// The test's end of a child's terminal: its keyboard and its screen.
///
/// Dropping it does not end the child. A test must bring the child to its
/// end, by what it types or by killing it, and wait for it: a child left
/// running outlives the test.
pub struct Screen(os::Screen);

/// Starts `command` with a new terminal as its controlling terminal and as
/// its standard input, output and error.
///
/// The command is changed to that end, so start it once and do not reuse
/// it. The terminal starts as any does: it shows what is typed and hands it
/// on a line at a time.
pub fn spawn_in_terminal(command: &mut Command) -> Result<(Child, Screen)> {
    os::spawn(command).map(|(child, screen)| (child, Screen(screen)))
}

impl Screen {
    /// What the child has written so far, from the start, waiting until it
    /// contains `text`, `within` has passed, or the terminal has gone with
    /// the child. Check the result for `text`: running out of time is not
    /// an error.
    ///
    /// The screen is read all the while, whether or not a test is waiting,
    /// so a child is never held up by output nobody takes, and what it
    /// wrote before it ended can still be read afterwards.
    ///
    /// It is what a screen would be sent, so a line ends in `\r\n`, and what
    /// the terminal shows of the typing is in it too.
    pub fn wait_for(&mut self, text: &str, within: Duration) -> Result<String> {
        self.0.wait_for(text, within)
    }

    /// As [`Screen::wait_for`], but it is an error if `text` does not come:
    /// the error's message holds what the screen shows instead.
    ///
    /// Use this one to wait for the point a test is about, and only then
    /// say what must *not* be on the screen. "It is not there" proves
    /// nothing about a screen that has not got that far.
    pub fn expect(&mut self, text: &str, within: Duration) -> Result<String> {
        let shown = self.wait_for(text, within)?;
        match shown.contains(text) {
            true => Ok(shown),
            false => Err(Error::Failed(format!(
                "{text:?} did not come; the screen shows {shown:?}"
            ))),
        }
    }

    /// Types `text` as the user would. Enter is `\r`, Ctrl-C is `\x03`.
    pub fn type_text(&mut self, text: &str) -> Result<()> {
        self.0.type_text(text)
    }

    /// Whether the terminal shows what is typed. Ask while the child runs:
    /// its terminal goes with it, and the answer afterwards is not to be
    /// relied on.
    pub fn echoes(&self) -> Result<bool> {
        self.0.echoes()
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs::File;
    use std::io::{self, IsTerminal};
    use std::time::Instant;

    use super::*;
    use crate::terminal::read_hidden_line;

    const CHILD: &str = "UBC_VPN_TERMINAL_TEST_CHILD";
    const WAIT: Duration = Duration::from_secs(20);

    // The whole of it: the child has the terminal as its own and as its
    // three streams, a hidden question in it is hidden, and the test can
    // read the screen, type, and ask whether typing shows.
    #[test]
    fn a_child_gets_a_terminal_of_its_own() {
        let mut command = Command::new(std::env::current_exe().expect("this program"));
        let (_, tests) = module_path!().split_once("::").expect("a module path");
        let name = format!("{tests}::child");
        command.args(["--exact", name.as_str(), "--nocapture", "--test-threads=1"]);
        command.env(CHILD, "1");
        let (mut child, mut screen) = spawn_in_terminal(&mut command).expect("start");

        screen.expect("Password: ", WAIT).expect("the question");
        assert!(
            !screen.echoes().expect("the mode"),
            "the question shows typing"
        );
        // Waiting for what does not come gives up, and is not an error.
        let started = Instant::now();
        let brief = Duration::from_millis(300);
        let shown = screen.wait_for("never shown", brief).expect("read");
        assert!(!shown.contains("never shown"));
        assert!(started.elapsed() >= brief && started.elapsed() < WAIT);
        // The strict form says so, and says what is there instead.
        match screen.expect("never shown", brief) {
            Err(Error::Failed(why)) => assert!(why.contains("Password: "), "{why}"),
            other => panic!("it did not come, and yet: {other:?}"),
        }

        screen.type_text("s3cret fake\r").expect("type");
        let shown = screen.expect("own terminal", WAIT).expect("what it says");
        // Security rule: the child holds its terminal as its three streams
        // and nowhere else. With the test's end of that terminal in hand as
        // well, it would keep the terminal alive, and it could never hang
        // up. (Other things a test run was itself handed, which a child
        // gets too, are no part of this; a runner hands on several.)
        let said =
            "SAYS 11 bytes, other terminals [], streams [true, true, true], own terminal true";
        assert!(shown.contains(said), "{shown:?}");
        assert!(!shown.contains("s3cret"), "the secret was shown: {shown:?}");

        // Back to a terminal that shows what is typed, as it started.
        assert!(screen.echoes().expect("the mode"), "typing no longer shows");
        screen.type_text("visible\r").expect("type");
        let shown = screen.wait_for("SAYS line visible", WAIT).expect("read");
        assert_eq!(
            shown.matches("visible").count(),
            2,
            "typed and said: {shown:?}"
        );
        // The child ends though nobody is looking at its screen just then,
        // and what it wrote on the way out is there to read afterwards.
        assert!(child.wait().expect("wait").success(), "{shown:?}");
        let shown = screen.wait_for("test result: ok", WAIT).expect("read");
        assert!(shown.contains("test result: ok"), "{shown:?}");
        // Once the terminal has gone there is nothing to wait for.
        let started = Instant::now();
        let shown = screen.wait_for("never shown", WAIT).expect("read");
        assert!(!shown.contains("never shown"));
        assert!(
            started.elapsed() < WAIT,
            "waited for a terminal that is gone"
        );
    }

    // Not a test of its own: the test above runs it in a terminal.
    #[test]
    fn child() {
        if std::env::var_os(CHILD).is_none() {
            return;
        }
        let streams = [
            io::stdin().is_terminal(),
            io::stdout().is_terminal(),
            io::stderr().is_terminal(),
        ];
        // Every open descriptor past the three streams that is a terminal.
        // SAFETY: the call only asks about a number; it has no conditions.
        let terminal = |fd: &i32| unsafe { libc::isatty(*fd) } == 1;
        let others: Vec<i32> = (3..1024).filter(terminal).collect();
        let own = File::open("/dev/tty").is_ok();
        let typed = read_hidden_line("Password: ").expect("a hidden line");
        let bytes = typed.expose().len();
        println!(
            "SAYS {bytes} bytes, other terminals {others:?}, streams {streams:?}, own terminal {own}"
        );
        let mut line = String::new();
        io::stdin().read_line(&mut line).expect("a line");
        println!("SAYS line {}", line.trim());
    }
}

#[cfg(all(test, not(unix)))]
mod tests {
    use super::*;
    use crate::Error;

    // Said plainly, and nothing is started.
    #[test]
    fn there_is_no_terminal_for_a_child_on_this_system() {
        let mut command = Command::new("this-program-is-never-started");
        assert_eq!(
            spawn_in_terminal(&mut command).err(),
            Some(Error::Unsupported)
        );
    }
}
