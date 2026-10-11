//! Where an engine's log lines go, with redaction built in.
//!
//! [`LogSink`] lives in a file of its own so that its fields are private to
//! this file. Rust privacy is per module: code anywhere else in the crate,
//! the `libopenconnect` binding included, can reach the caller's log
//! callback only through [`LogSink::log`].
//!
//! **Never put an engine, the binding or any other code in this file, and
//! never widen a field's visibility.** A test fails if a field becomes
//! reachable.

use std::sync::{Arc, Mutex, PoisonError};

use ubc_vpn_core::redact::{REDACTED, Secret, redact_line};

/// Whether debug-level lines can be delivered at all in this build.
///
/// True only when the `debug-logs` Cargo feature is on **and** the build has
/// debug assertions (or it is this crate's own test build). Shipped binaries
/// are release builds and must not enable the feature, so either mistake
/// alone still leaves debug output off. It is off because the library's debug
/// output holds the session cookie.
pub const DEBUG_LINES: bool = cfg!(all(any(test, feature = "debug-logs"), debug_assertions));

/// How serious a log line is. Ordered from least to most detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    /// Something failed.
    Error,
    /// Normal progress.
    Info,
    /// Protocol detail. Delivered only where [`DEBUG_LINES`] is true.
    Debug,
}

type LogFn = dyn Fn(LogLevel, &str) + Send + Sync;

/// Where an engine's log lines go. Clones share one destination.
///
/// The caller may rely on every line it receives: being no more detailed than
/// the level it asked for; having had every value registered with
/// [`LogSink::hide`] removed; and having been through [`redact_line`].
///
/// The callback cannot be reached except through [`LogSink::log`]:
///
/// ```compile_fail
/// fn callback(s: ubc_vpn_engine::LogSink) { let _ = &s.write; }
/// ```
///
/// ```compile_fail
/// fn level(mut s: ubc_vpn_engine::LogSink) { s.max = ubc_vpn_engine::LogLevel::Debug; }
/// ```
#[derive(Clone)]
pub struct LogSink {
    max: LogLevel,
    write: Arc<LogFn>,
    hidden: Arc<Mutex<Vec<Secret>>>,
}

impl LogSink {
    /// Delivers lines up to and including `max` to `write`, one line per call.
    /// `write` must not call back into this sink.
    pub fn new(max: LogLevel, write: impl Fn(LogLevel, &str) + Send + Sync + 'static) -> Self {
        let max = if DEBUG_LINES {
            max
        } else {
            max.min(LogLevel::Info)
        };
        Self {
            max,
            write: Arc::new(write),
            hidden: Arc::default(),
        }
    }

    /// A sink that throws everything away.
    pub fn none() -> Self {
        Self::new(LogLevel::Error, |_, _| {})
    }

    /// For engines: registers a value that must never appear in a line, from
    /// now on and in every clone. Engines register the cookie and each answer
    /// as soon as they hold it. This catches a secret on a line that carries
    /// no marker [`redact_line`] knows.
    pub fn hide(&self, secret: &Secret) {
        if !secret.expose().is_empty() {
            self.hidden().push(secret.clone());
        }
    }

    /// For engines: reports raw output. It is filtered by level, scrubbed of
    /// hidden values, split into lines and redacted before the caller sees
    /// it.
    pub fn log(&self, level: LogLevel, text: &str) {
        if level > self.max {
            return;
        }
        let mut text = text.to_string();
        for secret in self.hidden().iter() {
            text = text.replace(secret.expose(), REDACTED);
        }
        for line in text.lines() {
            (self.write)(level, &redact_line(line));
        }
    }

    fn hidden(&self) -> std::sync::MutexGuard<'_, Vec<Secret>> {
        self.hidden.lock().unwrap_or_else(PoisonError::into_inner)
    }
}
