//! One message per line: writing and reading a line, and why one could
//! not be.

use std::fmt;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

#[cfg(doc)]
use super::Hello;
use super::MAX_LINE_BYTES;

/// Why a line could not be written or read.
///
/// It deliberately does not keep `serde_json`'s own error. That error's text
/// can quote the input, and the input may hold a cookie or a password, so only
/// the kind of problem and its position survive. Both `Display` and `Debug` are
/// therefore safe to log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// The line is longer than [`MAX_LINE_BYTES`].
    TooLong,
    /// The line is not the expected JSON.
    Invalid {
        /// What kind of problem it was.
        kind: InvalidKind,
        /// The column where parsing stopped, counted from 1.
        column: usize,
    },
}

/// What was wrong with a line that is not the expected JSON.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidKind {
    /// Not JSON at all, or cut short.
    Syntax,
    /// Valid JSON of the wrong shape: a wrong type, an unknown field or method,
    /// or a value that failed validation.
    Shape,
}

impl From<serde_json::Error> for FrameError {
    fn from(e: serde_json::Error) -> Self {
        let kind = match e.classify() {
            serde_json::error::Category::Data => InvalidKind::Shape,
            _ => InvalidKind::Syntax,
        };
        Self::Invalid {
            kind,
            column: e.column(),
        }
    }
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong => write!(f, "line is longer than {MAX_LINE_BYTES} bytes"),
            Self::Invalid {
                kind: InvalidKind::Syntax,
                column,
            } => write!(f, "message is not valid JSON at column {column}"),
            Self::Invalid {
                kind: InvalidKind::Shape,
                column,
            } => write!(f, "message has an unexpected shape at column {column}"),
        }
    }
}

impl std::error::Error for FrameError {}

/// Turns a message into one line, newline included.
pub fn encode<T: Serialize>(message: &T) -> Result<String, FrameError> {
    let mut line = serde_json::to_string(message)?;
    line.push('\n');
    if line.len() > MAX_LINE_BYTES {
        return Err(FrameError::TooLong);
    }
    Ok(line)
}

/// Reads a message from one line, with or without its newline.
///
/// The length is checked before any parsing, so an oversized line costs
/// nothing to refuse.
pub fn decode<T: DeserializeOwned>(line: &str) -> Result<T, FrameError> {
    if line.len() > MAX_LINE_BYTES {
        return Err(FrameError::TooLong);
    }
    Ok(serde_json::from_str(line.trim_end_matches(['\r', '\n']))?)
}

/// Reads only the protocol version from a client's first line.
///
/// Unlike [`decode`] of a [`Hello`], this ignores every other field, so the
/// service can tell a newer or older client "please update" even when it
/// cannot read the rest of that client's `Hello`.
pub fn peek_protocol_version(line: &str) -> Result<u32, FrameError> {
    #[derive(Deserialize)]
    struct VersionOnly {
        protocol_version: u32,
    }
    Ok(decode::<VersionOnly>(line)?.protocol_version)
}
