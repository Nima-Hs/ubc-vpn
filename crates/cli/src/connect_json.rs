//! `ubc-vpn connect --json`: the connect the app runs.
//!
//! The same connect as in a terminal, with the app in place of the person:
//! each question is a [`CliMessage`] line on standard output, each answer an
//! [`AppMessage`] line on standard input. The last line is `done` once the
//! service has accepted the request, or one `error`. What the connection
//! does after that reaches the app as state events through its bridge.
//!
//! Whatever happens, a panic included, the command ends with exactly one of
//! those two last lines.
//!
//! Standard input is read on a thread of its own for as long as the command
//! runs, so that a `cancel` stops a login that is waiting on the gateway,
//! not only one that is waiting for an answer. Standard input closing means
//! the app has gone, and is a cancel too.
//!
//! A cancel is acted on up to the moment the connect request is sent. One
//! that arrives after that is too late: the command ends with `done`, and
//! the app undoes the connect by sending `disconnect` through its bridge.
//!
//! An answer is a [`Secret`] from the moment its line is decoded. A line that
//! cannot be understood is never repeated back. The bytes of each line are
//! overwritten once it has been decoded. That is as far as this program can
//! reach: the copy in the reader's own buffer, the one in the operating
//! system's pipe and the [`Secret`] itself are not wiped, and without unsafe
//! code the compiler is asked, not forced, to keep the overwrite.

use std::io::{BufRead, Read, Write};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};

use ubc_vpn_core::login::{AppMessage, CliMessage, LoginErrorCode};
use ubc_vpn_core::protocol::{MAX_LINE_BYTES, decode, encode};
use ubc_vpn_core::redact::Secret;
use ubc_vpn_engine::{Cancel, Prompt};
use ubc_vpn_platform::Platform;

use crate::clean;
use crate::client::Limits;
use crate::connect::{Ask, Engines, start};

/// The most of a question's label and of its message that is passed on, in
/// UTF-16 code units, which is how the app counts them. The gateway words
/// both, and a question must always fit in one line.
const MAX_LABEL: usize = 200;
const MAX_MESSAGE: usize = 1000;

/// How many answers may wait to be used. A prompt gets one answer, so more
/// than a few waiting means the app is not following the conversation.
const WAITING_ANSWERS: usize = 4;

/// What the reader of standard input passes on. A cancel is not passed on:
/// it is acted on where it is read.
enum Arrival {
    Answer {
        id: u32,
        value: Secret,
    },
    /// A line that is not an [`AppMessage`].
    NotUnderstood,
}

/// Runs `connect --json` and returns the exit status: 0 after `done`, and
/// after an `error` the status `connect` gives for the same failure.
pub fn connect(
    platform: &dyn Fn() -> ubc_vpn_platform::Result<Platform>,
    engines: Engines,
    input: impl BufRead + Send + 'static,
    limits: Limits,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    let cancel = Cancel::new();
    let (to_asker, answers) = sync_channel(WAITING_ANSWERS);
    let stopper = cancel.clone();
    // Not joined: it may be blocked reading, and ends with the program.
    std::thread::spawn(move || read_app(input, &to_asker, &stopper));

    let mut app = App {
        out: &mut *out,
        answers,
        cancel: &cancel,
        asked: 0,
        confused: false,
    };
    // A panic on the way, in an engine for one, still ends in a last line.
    let run = || start(platform, engines, &mut app, &cancel, limits, err);
    let Ok(ended) = catch_unwind(AssertUnwindSafe(run)) else {
        let (code, message) = (LoginErrorCode::Internal, PANICKED.to_string());
        let _ = write_line(out, &CliMessage::Error { code, message });
        return crate::FAILED;
    };
    // A line that made no sense may have arrived while nothing was being
    // asked; it cancelled the login all the same.
    let unread = |arrival| matches!(arrival, Arrival::NotUnderstood);
    let confused = app.confused || app.answers.try_iter().any(unread);
    let (last, exit) = match ended {
        Ok(_accepted) => (CliMessage::Done, 0),
        Err(stop) => {
            // Giving up on an app that makes no sense is not the user's cancel.
            let (code, message) = match confused {
                true => (LoginErrorCode::Internal, NOT_UNDERSTOOD.to_string()),
                false => (stop.code, stop.message),
            };
            let exit = if confused { crate::FAILED } else { stop.exit };
            (CliMessage::Error { code, message }, exit)
        }
    };
    let _ = write_line(out, &last);
    exit
}

const PANICKED: &str = "Something went wrong inside UBC VPN while logging in.";
const NOT_UNDERSTOOD: &str = "The app sent something that is not an answer to the question asked.";

fn write_line(out: &mut dyn Write, message: &CliMessage) -> std::io::Result<()> {
    let line = encode(message).map_err(std::io::Error::other)?;
    out.write_all(line.as_bytes())?;
    out.flush()
}

/// The app, as the one who is asked.
struct App<'a> {
    out: &'a mut dyn Write,
    answers: Receiver<Arrival>,
    cancel: &'a Cancel,
    asked: u32,
    /// Whether the app answered with something other than the answer to the
    /// question asked.
    confused: bool,
}

impl Ask for App<'_> {
    fn unusable(&self) -> Option<String> {
        None
    }

    fn ask(&mut self, prompt: &Prompt) -> Option<Secret> {
        if self.cancel.is_cancelled() {
            return None;
        }
        self.asked += 1;
        // The wording is the gateway's. JSON carries any character safely;
        // the app is spared the ones no label has a use for, and a length
        // that would not fit in a line.
        let worded = |text: &str, most| cut(&clean(text), most);
        let question = CliMessage::Prompt {
            id: self.asked,
            kind: prompt.kind,
            label: worded(&prompt.label, MAX_LABEL),
            message: prompt.message.as_deref().map(|m| worded(m, MAX_MESSAGE)),
        };
        // An app that cannot be written to has gone.
        write_line(self.out, &question).ok()?;
        match self.answers.recv() {
            Ok(Arrival::Answer { id, value }) if id == self.asked => Some(value),
            Ok(_) => {
                self.confused = true;
                None
            }
            // The reader stopped: a cancel, or the app has gone.
            Err(_) => None,
        }
    }
}

/// The start of `text`: as many whole characters as fit in `most` UTF-16
/// code units.
fn cut(text: &str, most: usize) -> String {
    let mut room = most;
    let fits = |c: &char| {
        let fit = c.len_utf16() <= room;
        room = room.saturating_sub(c.len_utf16());
        fit
    };
    text.chars().take_while(fits).collect()
}

/// Cancels when dropped: however the reader of standard input ends, a panic
/// included, a login is not left waiting for a cancel nobody can send.
struct CancelAtTheEnd<'a>(&'a Cancel);

impl Drop for CancelAtTheEnd<'_> {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

/// Reads the app's lines until it cancels, goes away, or stops making sense.
/// Each of those cancels the login, wherever it is.
fn read_app(mut input: impl BufRead, to: &SyncSender<Arrival>, cancel: &Cancel) {
    let _cancel = CancelAtTheEnd(cancel);
    // One buffer for every line, never grown, so that no copy of an answer
    // is left behind in memory this function has let go of.
    let mut line = Vec::with_capacity(MAX_LINE_BYTES + 1);
    loop {
        // No more of a line is held than could be a message. `decode`
        // refuses one that is too long, as it does one cut short here.
        let limit = MAX_LINE_BYTES as u64 + 1;
        let read = input.by_ref().take(limit).read_until(b'\n', &mut line);
        let message = match read {
            // The end of the input, or an error reading it: the app has gone.
            Ok(0) | Err(_) => {
                line.fill(0);
                break;
            }
            Ok(_) => std::str::from_utf8(&line)
                .ok()
                .and_then(|text| decode(text).ok()),
        };
        // The line may have held an answer. See the module's note on what
        // this does and does not reach.
        line.fill(0);
        std::hint::black_box(&mut line).clear();
        let arrival = match message {
            Some(AppMessage::Answer { id, value }) => Arrival::Answer { id, value },
            Some(AppMessage::Cancel) => break,
            None => Arrival::NotUnderstood,
        };
        let understood = matches!(arrival, Arrival::Answer { .. });
        // Full means answers nobody asked for; closed means the command is
        // past asking. Either way there is nothing more to read for.
        if to.try_send(arrival).is_err() || !understood {
            break;
        }
    }
}
