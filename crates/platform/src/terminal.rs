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
//! - **Ctrl-C** gives the line up: the call fails with [`Error::Closed`]. It
//!   arrives as a key and not as a signal, so the program is still running
//!   to put the terminal back. So does **Ctrl-D** on an empty line, and the
//!   terminal going away.
//! - A line over [`MAX_HIDDEN_LINE_BYTES`] fails with [`Error::LineTooLong`]
//!   once Enter is pressed. It is never cut short, and the rest of it is not
//!   left for the shell to read.
//!
//! The terminal's mode is put back on every way out of the call, a panic
//! included. It is not put back if the program is killed during the call by
//! a signal from outside, or aborts: the user then has to type `stty sane`
//! (a Windows shell resets the mode by itself).
//!
//! What is typed is kept in one fixed buffer that is wiped before the call
//! returns. Not wiped, because out of reach: the copy inside the returned
//! [`Secret`], which does not wipe itself, the last key read, and whatever
//! the OS keeps.

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
}

impl Line {
    fn new() -> Self {
        Self {
            bytes: [0; MAX_HIDDEN_LINE_BYTES],
            len: 0,
            too_long: false,
        }
    }

    /// Takes one byte as a terminal that edits nothing sends it.
    fn key(&mut self, byte: u8) -> Key {
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
        self.bytes.fill(0);
        // Keeps the wipe from being optimised away as a write nobody reads.
        std::hint::black_box(&self.bytes);
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
        // Arrow keys and the like leave no control bytes in the secret.
        assert_eq!(typed(b"a\x1bb\tc\r"), Ok("abc".to_string()));
        assert_eq!(typed(b"a\x04b\r"), Ok("ab".to_string()));
        assert!(matches!(typed(b"\xff\r"), Err(Error::Failed(_))));
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
