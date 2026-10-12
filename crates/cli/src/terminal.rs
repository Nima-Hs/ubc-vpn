//! The person at the terminal, as the one `connect` asks.
//!
//! A password or a one-time code is read by the platform's hidden read,
//! which talks to the terminal itself and shows nothing. It is never read
//! from standard input, so never from a pipe or a file. The username is not
//! a secret and is typed with the ordinary echo, on standard input, which
//! `connect` has by then made sure is a terminal.

use std::io::{BufRead, IsTerminal, Read, Write};

use ubc_vpn_core::login::PromptKind;
use ubc_vpn_core::redact::Secret;
use ubc_vpn_engine::Prompt;
use ubc_vpn_platform::terminal::{MAX_HIDDEN_LINE_BYTES, read_hidden_line};
use ubc_vpn_platform::{Error, Result};

use crate::clean;
use crate::connect::Ask;

const NOT_A_TERMINAL: &str = "connect asks for the password in a terminal, and this is not one. \
                              Run it in a terminal, or use the app.";
const TOO_LONG: &str = "That answer is too long, so the login was stopped.";
const UNREADABLE: &str = "The terminal could not be read, so the login was stopped.";

/// Writes the question and reads one line.
pub type ReadLine = Box<dyn FnMut(&str) -> Result<Secret>>;

/// Asks in the terminal.
pub struct Terminal {
    interactive: bool,
    shown: ReadLine,
    hidden: ReadLine,
    /// Why the login had to stop, when that was not the user giving up.
    stopped: Option<&'static str>,
}

impl Terminal {
    /// The terminal this program runs in.
    pub fn real() -> Self {
        let shown = |question: &str| {
            let (mut input, mut echo) = (std::io::stdin().lock(), std::io::stderr());
            read_shown(question, &mut input, &mut echo)
        };
        let interactive = std::io::stdin().is_terminal();
        Self::with(interactive, Box::new(shown), Box::new(read_hidden_line))
    }

    /// One that reads with `shown` and `hidden`. `interactive` is whether
    /// standard input is a terminal.
    pub fn with(interactive: bool, shown: ReadLine, hidden: ReadLine) -> Self {
        Self {
            interactive,
            shown,
            hidden,
            stopped: None,
        }
    }
}

impl Ask for Terminal {
    fn unusable(&self) -> Option<String> {
        (!self.interactive).then(|| NOT_A_TERMINAL.to_string())
    }

    fn ask(&mut self, prompt: &Prompt) -> Option<Secret> {
        // The wording is the gateway's, so it is cleaned like any text that
        // is not this program's own.
        let label = clean(&prompt.label);
        let question = match &prompt.message {
            Some(message) => format!("{}\n{label}: ", clean(message)),
            None => format!("{label}: "),
        };
        // Only a username is shown as it is typed.
        let read = match prompt.kind {
            PromptKind::Username => (self.shown)(&question),
            _ => (self.hidden)(&question),
        };
        match read {
            Ok(answer) => Some(answer),
            // Ctrl-C or Ctrl-D at the question, or the terminal went away.
            Err(Error::Closed) => None,
            Err(other) => {
                self.stopped = Some(match other {
                    Error::NotATerminal => NOT_A_TERMINAL,
                    Error::LineTooLong => TOO_LONG,
                    _ => UNREADABLE,
                });
                None
            }
        }
    }

    fn failure(&self) -> Option<String> {
        self.stopped.map(str::to_string)
    }
}

/// Writes `question` to `echo` and reads one line from `input`, which shows
/// it as it is typed. The end of the input is the user giving up.
pub fn read_shown(question: &str, input: &mut dyn BufRead, echo: &mut dyn Write) -> Result<Secret> {
    let _ = write!(echo, "{question}");
    let _ = echo.flush();
    let mut line = Vec::new();
    // Room for the line and its ending, and no more.
    let limit = MAX_HIDDEN_LINE_BYTES as u64 + 2;
    match input.take(limit).read_until(b'\n', &mut line) {
        Ok(0) | Err(_) => return Err(Error::Closed),
        Ok(_) => {}
    }
    if line.last() == Some(&b'\n') {
        line.pop();
        if line.last() == Some(&b'\r') {
            line.pop();
        }
    }
    if line.len() > MAX_HIDDEN_LINE_BYTES {
        return Err(Error::LineTooLong);
    }
    let text = String::from_utf8(line).map_err(|_| Error::Failed("not text".to_string()))?;
    Ok(Secret::new(text))
}
