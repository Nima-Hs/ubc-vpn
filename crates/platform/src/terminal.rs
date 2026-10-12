//! Asking the user for a secret in the terminal, without showing it.
//!
//! [`read_hidden_line`] talks to the terminal itself (`/dev/tty` on Linux and
//! macOS, the console on Windows), never to standard input or output, which
//! may be piped. For the length of the call the terminal neither shows nor
//! edits what is typed: each key comes straight here, and the few keys a
//! person expects are handled by [`Line`].
//!
//! - **Enter** ends the line. The newline it did not show is written out.
//! - **Backspace** removes the last character, **Ctrl-U** the whole line.
//! - **Arrow keys, Delete** and the like do nothing. On Linux and macOS they
//!   arrive as an escape sequence, which is swallowed whole. (A lone Escape
//!   therefore also swallows the key after it.)
//! - **Ctrl-C** gives the line up: the call fails with [`Error::Closed`]. It
//!   arrives as a key and not as a signal, so the program is still running
//!   to put the terminal back. So does **Ctrl-D** on an empty line, and the
//!   terminal going away.
//! - A line over [`MAX_HIDDEN_LINE_BYTES`] fails with [`Error::LineTooLong`]
//!   once Enter is pressed. It is never cut short, and the rest of it is not
//!   left for the shell to read.
//!
//! Only an entered line leaves the keys after it for the next reader, which
//! may be the next question. Keys typed before the prompt appeared are
//! thrown away, so nothing typed blind starts a secret; and on every way out
//! that is not an entered line, so are the keys still waiting, or the shell
//! would read the rest of a password as a command.
//!
//! The terminal's mode is put back on every way out of the call, a panic
//! included. It is not put back if the program is killed during the call by
//! a signal from outside, or aborts, unless the program arranges for
//! [`restore_after_signal`] to be called first. Otherwise the user has to
//! type `stty sane` (a Windows shell resets the mode by itself).
//!
//! What is typed is kept in one fixed buffer that is wiped before the call
//! returns, with writes the compiler may not remove. Not wiped, because out
//! of reach: the copy inside the returned [`Secret`], which does not wipe
//! itself, and whatever the OS keeps.

use std::sync::atomic::{Ordering, compiler_fence};

use ubc_vpn_core::redact::Secret;

#[cfg(windows)]
use crate::os::terminal as os;
#[cfg(unix)]
use crate::unix::terminal as os;
use crate::{Error, Result};

/// The longest line [`read_hidden_line`] returns, in bytes of UTF-8, not
/// counting the Enter that ends it.
pub const MAX_HIDDEN_LINE_BYTES: usize = 1024;

/// Writes `prompt` to the terminal and reads one line from it that is not
/// shown. Fails with [`Error::NotATerminal`] when there is no terminal, with
/// [`Error::Closed`] when the user gives up, and with [`Error::LineTooLong`]
/// for a line over the limit. No error ever contains what was typed.
pub fn read_hidden_line(prompt: &str) -> Result<Secret> {
    os::read_hidden_line(prompt)
}

/// Puts the terminal back as it was when the [`read_hidden_line`] now in
/// progress began, and throws away the keys still waiting. Does nothing when
/// no call is in progress. It does not end the call: it is for a program
/// about to exit because it was told to stop.
///
/// On Linux and macOS it may be called from a signal handler, on any thread:
/// it reads only atomics and makes only calls POSIX lists as safe there
/// (`open` of `/dev/tty`, `tcgetattr`, `tcsetattr`, `close`). It takes no
/// lock and does not allocate. On Windows it may be called from a console
/// control handler, which runs on a thread of its own, or from any thread.
/// Nothing here installs a handler.
///
/// Two things for whoever does:
///
/// - A handler that returns to the program, rather than ending it, must
///   save `errno` before this call and put it back after: the calls made
///   here may change it.
/// - There is a small window at the start of a call. The call marks itself
///   in progress and then changes the mode. If this function runs between
///   the two, on another thread or in a handler that returns, it puts back
///   a mode that has not changed yet, and the call then goes on to quiet the
///   terminal. A program that ends after that leaves the terminal quiet. A
///   handler that ends the program itself, on the thread making the call,
///   cannot hit it.
pub fn restore_after_signal() {
    os::restore_after_signal();
}

/// Overwrites `bytes` with zeros in a way the compiler must keep, though
/// nothing reads them afterwards.
pub(crate) fn wipe(bytes: &mut [u8]) {
    for byte in bytes.iter_mut() {
        // SAFETY: `byte` is a valid, aligned reference to one byte that
        // nothing else can reach during the write.
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// Where in an escape sequence the keys are: `ESC [ ... final` for most
/// keys, `ESC O final` for some.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Escape {
    No,
    Started,
    Inside,
}

/// What a key did to the line.
#[derive(Debug, PartialEq, Eq)]
enum Key {
    More,
    Entered,
    GivenUp,
}

/// The line being typed. Wiped when dropped.
struct Line {
    bytes: [u8; MAX_HIDDEN_LINE_BYTES],
    len: usize,
    too_long: bool,
    escape: Escape,
}

impl Line {
    fn new() -> Self {
        Self {
            bytes: [0; MAX_HIDDEN_LINE_BYTES],
            len: 0,
            too_long: false,
            escape: Escape::No,
        }
    }

    /// Takes one byte as a terminal that edits nothing sends it.
    fn key(&mut self, byte: u8) -> Key {
        // The rest of an arrow key or the like is no part of a secret.
        if self.escape != Escape::No && byte >= 0x20 {
            self.escape = match (self.escape, byte) {
                (Escape::Started, b'[' | b'O') | (Escape::Inside, 0x20..=0x3f) => Escape::Inside,
                _ => Escape::No,
            };
            return Key::More;
        }
        self.escape = match byte {
            0x1b => Escape::Started,
            _ => Escape::No,
        };
        match byte {
            b'\r' | b'\n' => return Key::Entered,
            // Ctrl-C, and Ctrl-D on an empty line.
            0x03 => return Key::GivenUp,
            0x04 if self.len == 0 && !self.too_long => return Key::GivenUp,
            // Backspace, as either of the two bytes terminals send for it:
            // the bytes of one whole character go.
            0x08 | 0x7f => {
                while self.len > 0 && self.bytes[self.len - 1] & 0xc0 == 0x80 {
                    self.len -= 1;
                }
                self.len = self.len.saturating_sub(1);
            }
            // Ctrl-U.
            0x15 => (self.len, self.too_long) = (0, false),
            // No other control key is part of a secret.
            byte if byte < 0x20 => {}
            // Security rule: a line over the limit is refused, not cut.
            _ if self.len == self.bytes.len() => self.too_long = true,
            byte => {
                self.bytes[self.len] = byte;
                self.len += 1;
            }
        }
        Key::More
    }

    fn finish(&self) -> Result<Secret> {
        if self.too_long {
            return Err(Error::LineTooLong);
        }
        // The message says nothing of what was typed.
        let text = std::str::from_utf8(&self.bytes[..self.len]);
        let text = text.map_err(|_| Error::Failed("the line is not text".to_string()))?;
        Ok(Secret::new(text))
    }
}

impl Drop for Line {
    fn drop(&mut self) {
        // Security rule: what was typed does not stay in memory here.
        wipe(&mut self.bytes);
    }
}

/// Reads keys from `next` until the line ends. `None` is the terminal going
/// away.
pub(crate) fn read_keys(mut next: impl FnMut() -> Result<Option<u8>>) -> Result<Secret> {
    let mut line = Line::new();
    loop {
        let Some(byte) = next()? else {
            return Err(Error::Closed);
        };
        match line.key(byte) {
            Key::More => {}
            Key::Entered => return line.finish(),
            Key::GivenUp => return Err(Error::Closed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn typed(keys: &[u8]) -> Result<String> {
        let mut keys = keys.iter().copied();
        read_keys(|| Ok(keys.next())).map(|secret| secret.expose().to_string())
    }

    #[test]
    fn keys_edit_the_line_as_a_person_expects() {
        assert_eq!(typed(b"s3cret fake\r"), Ok("s3cret fake".to_string()));
        assert_eq!(typed(b"\n"), Ok(String::new()));
        // Backspace takes a whole character, however many bytes it is.
        assert_eq!(
            typed("ab\u{e9}\u{1f511}\x7f\x08c\r".as_bytes()),
            Ok("abc".to_string())
        );
        assert_eq!(typed(b"\x7f\x7fa\r"), Ok("a".to_string()));
        assert_eq!(typed(b"wrong\x15right\r"), Ok("right".to_string()));
        // No control byte enters the secret.
        assert_eq!(typed(b"a\tb\0c\r"), Ok("abc".to_string()));
        assert_eq!(typed(b"a\x04b\r"), Ok("ab".to_string()));
        assert!(matches!(typed(b"\xff\r"), Err(Error::Failed(_))));
    }

    // An arrow key is three bytes or more. None of them is typed text, and a
    // secret with `[D` in it that nobody typed would never match.
    #[test]
    fn arrow_keys_and_the_like_are_swallowed_whole() {
        // Left arrow, then Delete; then the other form, as for F1 and Home.
        assert_eq!(typed(b"a\x1b[Db\x1b[3~c\r"), Ok("abc".to_string()));
        assert_eq!(typed(b"a\x1bOPb\x1b[1;5Cc\r"), Ok("abc".to_string()));
        // Enter and Ctrl-C still count in the middle of one.
        assert_eq!(typed(b"ab\x1b[\r"), Ok("ab".to_string()));
        assert_eq!(typed(b"ab\x1b\x03"), Err(Error::Closed));
        // What follows a finished one is text again.
        assert_eq!(typed(b"\x1b[A[D\r"), Ok("[D".to_string()));
    }

    // Security rule: what was typed does not stay in the buffer. This shows
    // that the wipe happens. It cannot show that a compiler may not remove
    // it: reading the buffer back is itself a reason to keep the writes.
    // That guarantee is the volatile writes in `wipe`.
    #[test]
    fn the_line_is_wiped_when_it_is_done_with() {
        let mut line = std::mem::ManuallyDrop::new(Line::new());
        for byte in b"NOT-A-REAL-PASSWORD" {
            line.key(*byte);
        }
        assert_eq!(&line.bytes[..4], b"NOT-");
        // SAFETY: the line is dropped once, here. It owns no memory but its
        // own fields, which `ManuallyDrop` keeps in place, so they can still
        // be read; `read_volatile` keeps the compiler from assuming what a
        // dropped value holds.
        let left: Vec<u8> = unsafe {
            std::mem::ManuallyDrop::drop(&mut line);
            let at = line.bytes.as_ptr();
            (0..19)
                .map(|index| std::ptr::read_volatile(at.add(index)))
                .collect()
        };
        assert_eq!(left, [0; 19], "left in the buffer");
    }

    #[test]
    fn giving_up_and_a_vanished_terminal_end_the_call() {
        assert_eq!(typed(b"half\x03more\r"), Err(Error::Closed));
        assert_eq!(typed(b"\x04"), Err(Error::Closed));
        assert_eq!(typed(b"half"), Err(Error::Closed));
    }

    // Security rule: a line over the limit is an error, never a shorter
    // secret than the one typed.
    #[test]
    fn a_line_over_the_limit_is_refused_not_cut() {
        let longest = "a".repeat(MAX_HIDDEN_LINE_BYTES);
        assert_eq!(
            typed(format!("{longest}\r").as_bytes()),
            Ok(longest.clone())
        );
        let over = format!("{longest}b\r");
        assert_eq!(typed(over.as_bytes()), Err(Error::LineTooLong));
        // Rubbing out does not make it acceptable; starting again does.
        let rubbed = format!("{longest}bc\x7f\x7f\x7f\r");
        assert_eq!(typed(rubbed.as_bytes()), Err(Error::LineTooLong));
        let again = format!("{longest}b\x15short\r");
        assert_eq!(typed(again.as_bytes()), Ok("short".to_string()));
    }
}
