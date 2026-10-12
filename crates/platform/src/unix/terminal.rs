//! The Linux and macOS half of `terminal`: the terminal is `/dev/tty`, and
//! its mode is the `termios` settings.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsFd;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};

use rustix::fs::{Mode, OFlags, open};
use rustix::io::Errno;
use rustix::termios::{
    LocalModes, OptionalActions, QueueSelector, SpecialCodeIndex, Termios, tcflush, tcgetattr,
    tcsetattr,
};
use ubc_vpn_core::redact::Secret;

use crate::terminal::read_keys;
use crate::{Error, Result};

/// Whether a call is in progress, and the settings it changed as they were
/// before. Atomics, because a signal handler may read them at any moment.
static READING: AtomicBool = AtomicBool::new(false);
static LOCAL_MODES: AtomicU64 = AtomicU64::new(0);
static VMIN: AtomicU8 = AtomicU8::new(0);
static VTIME: AtomicU8 = AtomicU8::new(0);

pub(crate) fn read_hidden_line(prompt: &str) -> Result<Secret> {
    // The program's own terminal, whatever its standard input and output
    // are. A program without one cannot open it.
    let mut terminal = OpenOptions::new();
    let terminal = terminal.read(true).write(true).open("/dev/tty");
    read_hidden_from(&terminal.map_err(|_| Error::NotATerminal)?, prompt)
}

/// See `terminal::restore_after_signal` for what this may be called from,
/// and so for what it may do: no lock, no allocation, and no call but
/// `open`, `tcgetattr`, `tcsetattr` and `close`.
pub(crate) fn restore_after_signal() {
    if !READING.load(Ordering::SeqCst) {
        return;
    }
    let flags = OFlags::RDWR | OFlags::NOCTTY | OFlags::CLOEXEC;
    if let Ok(terminal) = open(c"/dev/tty", flags, Mode::empty()) {
        restore_saved(&terminal);
    }
}

/// Puts back the settings a call in progress changed, on `terminal`, and
/// throws away the keys still waiting there.
fn restore_saved(terminal: impl AsFd) {
    if !READING.load(Ordering::SeqCst) {
        return;
    }
    let Ok(mut now) = tcgetattr(&terminal) else {
        return;
    };
    now.local_modes = LocalModes::from_bits_retain(LOCAL_MODES.load(Ordering::SeqCst) as _);
    now.special_codes[SpecialCodeIndex::VMIN] = VMIN.load(Ordering::SeqCst);
    now.special_codes[SpecialCodeIndex::VTIME] = VTIME.load(Ordering::SeqCst);
    let _ = tcsetattr(&terminal, OptionalActions::Flush, &now);
}

/// Puts the terminal's mode back when dropped, so on every way out.
struct Restore<'a>(&'a File, Termios);

impl Drop for Restore<'_> {
    fn drop(&mut self) {
        let _ = tcsetattr(self.0, OptionalActions::Now, &self.1);
        READING.store(false, Ordering::SeqCst);
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

    // What `restore_after_signal` puts back, in place before the change.
    // The flags are 32 bits wide on Linux and 64 on macOS.
    #[allow(clippy::useless_conversion)]
    let local = u64::from(before.local_modes.bits());
    LOCAL_MODES.store(local, Ordering::SeqCst);
    VMIN.store(
        before.special_codes[SpecialCodeIndex::VMIN],
        Ordering::SeqCst,
    );
    VTIME.store(
        before.special_codes[SpecialCodeIndex::VTIME],
        Ordering::SeqCst,
    );
    READING.store(true, Ordering::SeqCst);
    let _restore = Restore(terminal, before);
    // Security rule: keys typed before the prompt are thrown away with the
    // change of mode. They were typed blind, and shown, and are no secret's
    // beginning.
    loop {
        match tcsetattr(terminal, OptionalActions::Flush, &quiet) {
            // A signal arrived first: nothing was changed, so again.
            Err(Errno::INTR) => {}
            changed => break changed.map_err(io::Error::from)?,
        }
    }

    let mut terminal = terminal;
    let prompted = terminal.write_all(prompt.as_bytes());
    let typed = prompted.map_err(Error::from).and_then(|()| {
        read_keys(|| {
            let mut key = [0];
            loop {
                match terminal.read(&mut key) {
                    Ok(0) => return Ok(None),
                    Ok(_) => return Ok(Some(std::mem::take(&mut key[0]))),
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) => return Err(error.into()),
                }
            }
        })
    });
    // Security rule: unless a line was entered, the keys still waiting are
    // thrown away. The shell would read them next: the rest of a password,
    // run as a command.
    if typed.is_err() {
        let _ = tcflush(terminal, QueueSelector::IFlush);
    }
    // The newline that Enter did not show.
    let _ = terminal.write_all(b"\n");
    typed
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::OpenOptionsExt;
    use std::sync::{Mutex, MutexGuard, mpsc};
    use std::thread;
    use std::time::Duration;

    use rustix::event::{PollFd, PollFlags, Timespec, poll};
    use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};

    use super::*;
    use crate::lock;
    use crate::terminal::MAX_HIDDEN_LINE_BYTES;

    /// One call at a time: what `restore_after_signal` puts back is the
    /// process's, not a terminal's.
    static TURN: Mutex<()> = Mutex::new(());

    /// A terminal that exists only for one test: `ours` is the keyboard and
    /// screen, `theirs` what a program sees as its terminal. It never
    /// becomes this process's own terminal.
    struct Pty {
        ours: File,
        theirs: File,
        _turn: MutexGuard<'static, ()>,
    }

    fn pty() -> Pty {
        let turn = lock(&TURN);
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
            _turn: turn,
        }
    }

    /// What can be read from `end` until nothing more comes for `pause`, or
    /// until it ends with `awaited`.
    fn read_from(mut end: &File, awaited: Option<&str>, pause: u64) -> String {
        let mut got = String::new();
        let pause = Timespec::try_from(Duration::from_millis(pause)).expect("fits");
        while awaited.is_none_or(|awaited| !got.ends_with(awaited)) {
            let mut ready = [PollFd::new(&end, PollFlags::IN)];
            if poll(&mut ready, Some(&pause)).expect("poll") == 0 {
                break;
            }
            let mut some = [0; 256];
            let read = end.read(&mut some).expect("read");
            got.push_str(std::str::from_utf8(&some[..read]).expect("UTF-8"));
        }
        got
    }

    impl Pty {
        /// Runs the call on its own thread. Once the prompt is on the
        /// screen, runs `meanwhile` and types `keys`. Returns the result and
        /// the whole screen.
        fn ask_while(&self, keys: &[u8], meanwhile: impl FnOnce()) -> (Result<String>, String) {
            let terminal = self.theirs.try_clone().expect("clone");
            let (done, wait) = mpsc::channel();
            thread::spawn(move || {
                let read = read_hidden_from(&terminal, "Password: ");
                done.send(read.map(|secret| secret.expose().to_string()))
            });
            let mut screen = read_from(&self.ours, Some("Password: "), 20_000);
            assert!(screen.ends_with("Password: "), "the prompt: {screen:?}");
            meanwhile();
            // A few keys at a time, as a terminal holds only so many.
            for some in keys.chunks(64) {
                (&self.ours).write_all(some).expect("type");
                thread::sleep(Duration::from_millis(2));
            }
            let wait = wait.recv_timeout(Duration::from_secs(20));
            let read = wait.expect("the call did not return");
            screen.push_str(&read_from(&self.ours, None, 200));
            (read, screen)
        }

        fn ask(&self, keys: &[u8]) -> (Result<String>, String) {
            self.ask_while(keys, || {})
        }

        /// What the next reader of the terminal, a shell, would get.
        fn left(&self) -> String {
            read_from(&self.theirs, None, 300)
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
        let pty = pty();
        let before = pty.mode();
        assert!(before.0.contains(LocalModes::ECHO), "a new terminal echoes");
        // With a left arrow in it, which is three bytes and no text.
        let (read, screen) = pty.ask(b"s3c\x1b[Dret fakx\x7fe\r");
        assert_eq!(read, Ok("s3cret fake".to_string()));
        // The prompt and the newline, and nothing of what was typed.
        assert_eq!(screen, "Password: \r\n");
        assert_eq!(pty.mode(), before, "the mode was not put back");
    }

    // Security rule: the mode is put back on the ways out that are errors.
    #[test]
    fn the_mode_is_put_back_after_giving_up_and_after_a_long_line() {
        let pty = pty();
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

    // Security rule: the rest of a password given up on is not left for the
    // shell to run as a command. After an entered line, what follows stays:
    // it is the answer to the next question.
    #[test]
    fn only_an_entered_line_leaves_keys_for_the_next_reader() {
        let long = [vec![b'a'; MAX_HIDDEN_LINE_BYTES + 40], b"\rNEXT\r".to_vec()].concat();
        let not_text = Error::Failed("the line is not text".to_string());
        let cases: [(&[u8], Result<&str>, &str); 5] = [
            (b"\xff\rNEXT\r", Err(not_text), ""),
            (b"half\x03REST-OF-FAKE-SECRET\r", Err(Error::Closed), ""),
            (b"\x04REST\r", Err(Error::Closed), ""),
            (&long, Err(Error::LineTooLong), ""),
            (b"fake\rNEXT\r", Ok("fake"), "NEXT\n"),
        ];
        for (keys, read, left) in cases {
            let pty = pty();
            let (got, _) = pty.ask(keys);
            assert_eq!(got, read.map(str::to_string));
            assert_eq!(pty.left(), left, "left for the next reader");
        }
    }

    // Security rule: keys typed before the prompt was there, blind and
    // shown, are not the beginning of a secret.
    #[test]
    fn keys_typed_before_the_prompt_are_thrown_away() {
        let pty = pty();
        (&pty.ours).write_all(b"blind").expect("type ahead");
        assert_eq!(read_from(&pty.ours, Some("blind"), 20_000), "blind");
        let (read, _) = pty.ask(b"real\r");
        assert_eq!(read, Ok("real".to_string()));
    }

    // What a program told to stop calls before it exits: the terminal is
    // back as it was though the call has not returned.
    #[test]
    fn the_mode_can_be_put_back_from_outside_the_call() {
        let pty = pty();
        let before = pty.mode();
        let (read, _) = pty.ask_while(b"x\r", || {
            assert_ne!(pty.mode(), before, "the call changed nothing");
            restore_saved(&pty.theirs);
            assert_eq!(pty.mode(), before, "not put back during the call");
        });
        assert_eq!(read, Ok("x".to_string()));

        // With no call in progress there is nothing to put back.
        let mut odd = tcgetattr(&pty.theirs).expect("its mode");
        odd.local_modes.remove(LocalModes::ECHO);
        tcsetattr(&pty.theirs, OptionalActions::Now, &odd).expect("set");
        restore_saved(&pty.theirs);
        restore_after_signal();
        assert!(
            !pty.mode().0.contains(LocalModes::ECHO),
            "changed when idle"
        );
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
