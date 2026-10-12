//! The Linux and macOS half of `terminal`: the terminal is `/dev/tty`, and
//! its mode is the `termios` settings.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};

use rustix::termios::{
    LocalModes, OptionalActions, SpecialCodeIndex, Termios, tcgetattr, tcsetattr,
};
use ubc_vpn_core::redact::Secret;

use crate::terminal::read_keys;
use crate::{Error, Result};

pub(crate) fn read_hidden_line(prompt: &str) -> Result<Secret> {
    // The program's own terminal, whatever its standard input and output
    // are. A program without one cannot open it.
    let mut terminal = OpenOptions::new();
    let terminal = terminal.read(true).write(true).open("/dev/tty");
    read_hidden_from(&terminal.map_err(|_| Error::NotATerminal)?, prompt)
}

/// Puts the terminal's mode back when dropped, so on every way out.
struct Restore<'a>(&'a File, Termios);

impl Drop for Restore<'_> {
    fn drop(&mut self) {
        let _ = tcsetattr(self.0, OptionalActions::Now, &self.1);
    }
}

pub(crate) fn read_hidden_from(terminal: &File, prompt: &str) -> Result<Secret> {
    // Anything that has no terminal settings is not a terminal.
    let before = tcgetattr(terminal).map_err(|_| Error::NotATerminal)?;
    let mut quiet = before.clone();
    // Security rule: what is typed is not shown. Nor is it edited or turned
    // into signals by the terminal: every key comes here, one at a time, so
    // that Ctrl-C finds the program alive to put the mode back.
    let off = LocalModes::ECHO | LocalModes::ECHONL | LocalModes::ICANON;
    quiet
        .local_modes
        .remove(off | LocalModes::ISIG | LocalModes::IEXTEN);
    quiet.special_codes[SpecialCodeIndex::VMIN] = 1;
    quiet.special_codes[SpecialCodeIndex::VTIME] = 0;
    tcsetattr(terminal, OptionalActions::Drain, &quiet).map_err(io::Error::from)?;
    let _restore = Restore(terminal, before);

    let mut terminal = terminal;
    let prompted = terminal.write_all(prompt.as_bytes());
    let typed = prompted.map_err(Error::from).and_then(|()| {
        read_keys(|| {
            let mut key = [0];
            loop {
                match terminal.read(&mut key) {
                    Ok(0) => return Ok(None),
                    Ok(_) => return Ok(Some(key[0])),
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) => return Err(error.into()),
                }
            }
        })
    });
    // The newline that Enter did not show.
    let _ = terminal.write_all(b"\n");
    typed
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::OpenOptionsExt;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    use rustix::event::{PollFd, PollFlags, Timespec, poll};
    use rustix::fs::OFlags;
    use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};

    use super::*;
    use crate::terminal::MAX_HIDDEN_LINE_BYTES;

    /// A terminal that exists only for one test: `ours` is the keyboard and
    /// screen, `theirs` what a program sees as its terminal. It never
    /// becomes this process's own terminal.
    struct Pty {
        ours: File,
        theirs: File,
    }

    fn pty() -> Pty {
        let ours = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).expect("a pty");
        grantpt(&ours).expect("grant");
        unlockpt(&ours).expect("unlock");
        let name = ptsname(&ours, Vec::new()).expect("its name");
        let mut theirs = OpenOptions::new();
        theirs.read(true).write(true);
        theirs.custom_flags(OFlags::NOCTTY.bits() as i32);
        let theirs = theirs.open(name.to_str().expect("UTF-8")).expect("open");
        Pty {
            ours: File::from(ours),
            theirs,
        }
    }

    impl Pty {
        /// What reached the screen: until `awaited` is on it, or, with
        /// nothing awaited, until nothing more comes for a moment.
        fn screen(&mut self, awaited: Option<&str>) -> String {
            let mut shown = String::new();
            let pause = Duration::from_millis(if awaited.is_some() { 20_000 } else { 200 });
            let pause = Timespec::try_from(pause).expect("fits");
            while awaited != Some(shown.as_str()) {
                let mut ready = [PollFd::new(&self.ours, PollFlags::IN)];
                if poll(&mut ready, Some(&pause)).expect("poll") == 0 {
                    break;
                }
                let mut some = [0; 256];
                let read = self.ours.read(&mut some).expect("read the screen");
                shown.push_str(std::str::from_utf8(&some[..read]).expect("UTF-8"));
            }
            shown
        }

        /// Runs the call on its own thread while `keys` are typed, once the
        /// prompt is on the screen. Returns the result and the whole screen.
        fn ask(&mut self, keys: &[u8]) -> (Result<String>, String) {
            let terminal = self.theirs.try_clone().expect("clone");
            let (done, wait) = mpsc::channel();
            thread::spawn(move || {
                let read = read_hidden_from(&terminal, "Password: ");
                done.send(read.map(|secret| secret.expose().to_string()))
            });
            let mut screen = self.screen(Some("Password: "));
            assert_eq!(screen, "Password: ", "the prompt");
            // A few keys at a time, as a terminal holds only so many.
            for some in keys.chunks(64) {
                self.ours.write_all(some).expect("type");
                thread::sleep(Duration::from_millis(2));
            }
            let wait = wait.recv_timeout(Duration::from_secs(20));
            let read = wait.expect("the call did not return");
            screen.push_str(&self.screen(None));
            (read, screen)
        }

        /// The settings the call changes. `PENDIN` is left out: it is not a
        /// setting but a note macOS makes for itself when line editing comes
        /// back on, and drops at the next read.
        fn mode(&self) -> (LocalModes, u8) {
            let now = tcgetattr(&self.theirs).expect("its mode");
            let local = now.local_modes.difference(LocalModes::PENDIN);
            (local, now.special_codes[SpecialCodeIndex::VMIN])
        }
    }

    // Security rule: what is typed comes back and is never shown, and the
    // terminal is as it was afterwards.
    #[test]
    fn a_typed_line_is_returned_and_never_shown() {
        let mut pty = pty();
        let before = pty.mode();
        assert!(before.0.contains(LocalModes::ECHO), "a new terminal echoes");
        let (read, screen) = pty.ask(b"s3cret fakx\x7fe\r");
        assert_eq!(read, Ok("s3cret fake".to_string()));
        // The prompt and the newline, and nothing of what was typed.
        assert_eq!(screen, "Password: \r\n");
        assert_eq!(pty.mode(), before, "the mode was not put back");
    }

    // Security rule: the mode is put back on the ways out that are errors.
    #[test]
    fn the_mode_is_put_back_after_giving_up_and_after_a_long_line() {
        let mut pty = pty();
        let before = pty.mode();
        let (read, screen) = pty.ask(b"half\x03");
        assert_eq!(read, Err(Error::Closed));
        assert_eq!(screen, "Password: \r\n");
        assert_eq!(pty.mode(), before, "after Ctrl-C");

        let long = [vec![b'a'; MAX_HIDDEN_LINE_BYTES + 1], vec![b'\r']].concat();
        let (read, screen) = pty.ask(&long);
        assert_eq!(read, Err(Error::LineTooLong));
        assert_eq!(screen, "Password: \r\n");
        assert_eq!(pty.mode(), before, "after a long line");
    }

    // A file, a pipe or nothing at all is not a terminal, and nothing is
    // written to it.
    #[test]
    fn without_a_terminal_the_call_says_so() {
        let path = std::env::temp_dir().join(format!("uvt-not-a-tty-{}", std::process::id()));
        let mut file = OpenOptions::new();
        file.read(true).write(true).create(true).truncate(true);
        let file = file.open(&path).expect("a file");
        let read = read_hidden_from(&file, "Password: ");
        assert_eq!(read.map(|_| ()), Err(Error::NotATerminal));
        assert_eq!(std::fs::read(&path).expect("read"), b"");
        std::fs::remove_file(&path).expect("remove");

        // The real call, only where it cannot reach a real terminal: under
        // CI the tests have none. A developer's own terminal is left alone.
        match File::open("/dev/tty") {
            Err(_) => {
                let read = read_hidden_line("Password: ");
                assert_eq!(read.map(|_| ()), Err(Error::NotATerminal));
                say(b"\nRAN: no terminal\n");
            }
            Ok(_) => say(b"\nSKIPPED, this process has a terminal: no terminal\n"),
        }
    }

    /// One whole line in one write, because CI looks for it.
    fn say(line: &[u8]) {
        io::stderr().write_all(line).expect("say");
    }
}
