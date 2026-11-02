//! The service's log as the channel carries it: its lines, the places in
//! it, and the pages it is read in.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::settings_cli::misleads;

#[cfg(doc)]
use super::MAX_LINE_BYTES;

/// The longest text of one log line, in bytes.
pub const MAX_LOG_TEXT_BYTES: usize = 512;

/// About how much of a line a [`LogPage`] may fill, once encoded. It leaves
/// room for the rest of the response, so that a page can never pass
/// [`MAX_LINE_BYTES`].
pub const LOG_PAGE_BYTES: usize = 48 * 1024;

/// How many lines one connection may add with `add_log`.
pub const MAX_ADDED_LOG_LINES: usize = 20;

/// How many added lines the service keeps. They are kept apart from the
/// service's own lines, which they can therefore never push out.
pub const KEPT_ADDED_LOG_LINES: usize = 100;

/// How serious a log line is. There is no level for protocol detail: such
/// lines are never kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub enum LogLevel {
    /// Something failed.
    Error,
    /// Something is wrong but was dealt with.
    Warn,
    /// What happened, in the ordinary course.
    Info,
}

/// Who wrote a log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub enum LogSource {
    /// The service itself.
    Service,
    /// The VPN engine inside the service.
    Engine,
    /// The command-line client's login, handed over with `add_log`.
    Login,
}

/// The text of one log line: not empty, one line, at most
/// [`MAX_LOG_TEXT_BYTES`], and with no character that could mislead whoever
/// reads it (see [`misleads`]).
///
/// It cannot be made, and cannot be decoded, any other way. That it holds no
/// secret is not something a type can check: the service sees to that
/// before it makes one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, type = "string"))]
pub struct LogText(String);

/// Why a text is not a [`LogText`]. It does not repeat the text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotLogText;

impl fmt::Display for NotLogText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("not one plain line of a length that can be kept")
    }
}

impl std::error::Error for NotLogText {}

impl LogText {
    /// Stands where a line was that could not be kept.
    pub const LEFT_OUT: &'static str = "(a line that could not be kept was left out)";

    /// `text` as a log line's text, if it is one.
    pub fn new(text: &str) -> Result<Self, NotLogText> {
        let plain = !text.is_empty() && !text.chars().any(misleads);
        match plain && text.len() <= MAX_LOG_TEXT_BYTES {
            true => Ok(Self(text.to_string())),
            false => Err(NotLogText),
        }
    }

    /// `text` with every misleading character removed, if what is left is a
    /// log line's text. Nothing is cut to fit: a line that is still too
    /// long is not one, since half a line can read as something else.
    pub fn cleaned(text: &str) -> Result<Self, NotLogText> {
        let kept: String = text.chars().filter(|c| !misleads(*c)).collect();
        Self::new(&kept)
    }

    /// The marker that stands where a line could not be kept.
    pub fn left_out() -> Self {
        Self(Self::LEFT_OUT.to_string())
    }

    /// The text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for LogText {
    type Error = NotLogText;

    fn try_from(text: String) -> Result<Self, NotLogText> {
        Self::new(&text)
    }
}

impl From<LogText> for String {
    fn from(text: LogText) -> Self {
        text.0
    }
}

/// One line of the service's log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct LogLine {
    /// Its number within this run of the service, from 1. Numbers are given
    /// out without gaps; a page may skip those of lines no longer held.
    #[cfg_attr(test, ts(type = "number"))]
    pub seq: u64,
    /// When the service took the line, by its own clock: milliseconds since
    /// the start of 1970 (UTC). Clocks get set, so order is by `seq`.
    #[cfg_attr(test, ts(type = "number"))]
    pub at_unix_ms: u64,
    /// How serious it is.
    pub level: LogLevel,
    /// Who wrote it.
    pub source: LogSource,
    /// What it says.
    pub text: LogText,
}

/// A place in the service's log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct LogCursor {
    /// Which run of the service the number belongs to.
    #[cfg_attr(test, ts(type = "number"))]
    pub run: u64,
    /// The number of a line in that run.
    #[cfg_attr(test, ts(type = "number"))]
    pub seq: u64,
}

/// Some lines of the service's log, oldest first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct LogPage {
    /// This run of the service.
    #[cfg_attr(test, ts(type = "number"))]
    pub run: u64,
    /// The lines, oldest first. Empty when there are none after the cursor.
    pub lines: Vec<LogLine>,
    /// Where to read on from: with `run`, the cursor for the next request.
    /// The `seq` of the last line here, or the cursor that was used when
    /// there is none: 0 if none was given or it was from another run.
    #[cfg_attr(test, ts(type = "number"))]
    pub next: u64,
    /// Whether a line of this run with a `seq` greater than the cursor
    /// that was used existed and is no longer held. A cursor from another
    /// run does not make this true by itself; `run` shows that.
    pub dropped: bool,
}

impl LogPage {
    /// A page of the lines after `after` in this `run`: as many of `lines`,
    /// which must be in order, as fit in [`LOG_PAGE_BYTES`] once encoded.
    /// `after` is the cursor that was used: 0 when the client gave none or
    /// gave one from another run. `dropped` is for the service to say; see
    /// [`LogPage::dropped`].
    pub fn after(
        run: u64,
        after: u64,
        dropped: bool,
        lines: impl IntoIterator<Item = LogLine>,
    ) -> Self {
        let mut room = LOG_PAGE_BYTES;
        let fits = |line: &LogLine| {
            // What the line really takes on the wire, and the comma after it.
            let size = serde_json::to_string(line).map_or(usize::MAX, |text| text.len() + 1);
            let fit = size <= room;
            room = room.saturating_sub(size);
            fit
        };
        let lines: Vec<LogLine> = lines.into_iter().take_while(fits).collect();
        let next = lines.last().map_or(after, |last| last.seq);
        Self {
            run,
            lines,
            next,
            dropped,
        }
    }
}
