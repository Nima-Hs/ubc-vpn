//! The service's log: bounded, in memory, and safe to show its owner.
//! Nothing is written to disk.
//!
//! Every line, whoever wrote it, goes through [`safe`] before it is kept:
//! the service's own, the engine's, and those a client hands over. A line is
//! kept whole or not at all. There is no way to keep a line of protocol
//! detail: the level does not exist here.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use ubc_vpn_core::protocol::{
    KEPT_ADDED_LOG_LINES, LogCursor, LogLevel, LogLine, LogPage, LogSource, LogText,
};
use ubc_vpn_core::redact::{REDACTED, Secret, redact_line};
use ubc_vpn_core::settings_cli::misleads;
use ubc_vpn_engine::{LogSink, MIN_HIDDEN_LEN};

use crate::lock;

/// The most lines of the service's own, and of its engine, that are kept.
/// Older lines are dropped first.
pub const CAPACITY: usize = 500;

/// Who hears of each line as it is kept.
type Tell = Box<dyn Fn(&LogLine) + Send>;

/// The log. Clones share it.
#[derive(Clone)]
pub struct Logs(Arc<Shared>);

struct Shared {
    /// Which run of the service this is.
    run: u64,
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    /// The number of the newest line.
    newest: u64,
    /// The service's own lines and its engine's.
    own: VecDeque<LogLine>,
    /// Lines that clients added. Kept apart, so that no client can push a
    /// line of the service's out.
    added: VecDeque<LogLine>,
    /// The highest number of a line that is no longer held, or 0.
    lost: u64,
    /// The secrets the service holds now, each with the number of its hold.
    hidden: Vec<(u64, Secret)>,
    holds: u64,
    tell: Option<Tell>,
}

/// Keeps a secret out of every line for as long as this lives.
pub(crate) struct Held(Logs, u64);

impl Drop for Held {
    fn drop(&mut self) {
        lock(&self.0.0.inner)
            .hidden
            .retain(|(hold, _)| *hold != self.1);
    }
}

/// The service's wall clock, in milliseconds since the start of 1970.
fn now_ms() -> u64 {
    let since = SystemTime::now().duration_since(UNIX_EPOCH);
    since.map_or(0, |since| u64::try_from(since.as_millis()).unwrap_or(0))
}

/// A number for this run that no earlier run had: the time it started, or
/// one more than the last when two start in the same millisecond.
fn new_run() -> u64 {
    static LAST: AtomicU64 = AtomicU64::new(0);
    let now = now_ms();
    let next = |last: u64| Some(now.max(last + 1));
    let last = LAST.try_update(Ordering::SeqCst, Ordering::SeqCst, next);
    now.max(last.unwrap_or(0) + 1)
}

/// `text` as it may be kept and shown.
///
/// 1. Characters that mislead are removed, and a line that is then empty or
///    too long is not kept: half a line can hold half a secret.
/// 2. Every secret in `hidden` is removed. This comes after step 1, so that
///    a secret cannot be put together by the removal of what split it.
/// 3. Everything from a word that marks a secret onward is removed.
///
/// A line that fails any step is replaced whole by the marker.
fn safe(text: &str, hidden: &[(u64, Secret)]) -> LogText {
    let Ok(plain) = LogText::cleaned(text) else {
        return LogText::left_out();
    };
    let mut line = String::from(plain);
    for (_, secret) in hidden {
        // The line no longer holds what misleads, so neither does the form
        // of the secret that could be in it.
        let shown: String = secret.expose().chars().filter(|c| !misleads(*c)).collect();
        if shown.len() >= MIN_HIDDEN_LEN {
            line = line.replace(&shown, REDACTED);
        }
    }
    LogText::new(&redact_line(&line)).unwrap_or_else(|_| LogText::left_out())
}

/// The level a line from the engine is kept at, if it is kept. A line of
/// protocol detail never is, in any build: it can hold the cookie.
fn kept(level: ubc_vpn_engine::LogLevel) -> Option<LogLevel> {
    match level {
        ubc_vpn_engine::LogLevel::Error => Some(LogLevel::Error),
        ubc_vpn_engine::LogLevel::Info => Some(LogLevel::Info),
        ubc_vpn_engine::LogLevel::Debug => None,
    }
}

impl Default for Logs {
    fn default() -> Self {
        let (run, inner) = (new_run(), Mutex::default());
        Self(Arc::new(Shared { run, inner }))
    }
}

impl Logs {
    /// Keeps a line about something that failed.
    pub fn error(&self, text: &str) {
        self.keep(LogLevel::Error, LogSource::Service, text);
    }

    /// Keeps a line about something wrong that was dealt with.
    pub fn warn(&self, text: &str) {
        self.keep(LogLevel::Warn, LogSource::Service, text);
    }

    /// Keeps a line a client handed over.
    pub(crate) fn add(&self, level: LogLevel, text: &LogText) {
        self.keep(level, LogSource::Login, text.as_str());
    }

    /// Cleans `text`, numbers it and keeps it, dropping the oldest line of
    /// its kind when that is full. A blank text is not a line.
    fn keep(&self, level: LogLevel, source: LogSource, text: &str) {
        if text.trim().is_empty() {
            return;
        }
        let mut inner = lock(&self.0.inner);
        let inner = &mut *inner;
        inner.newest += 1;
        let line = LogLine {
            seq: inner.newest,
            at_unix_ms: now_ms(),
            level,
            source,
            text: safe(text, &inner.hidden),
        };
        let (ring, most) = match source {
            LogSource::Login => (&mut inner.added, KEPT_ADDED_LOG_LINES),
            LogSource::Service | LogSource::Engine => (&mut inner.own, CAPACITY),
        };
        if ring.len() >= most
            && let Some(oldest) = ring.pop_front()
        {
            inner.lost = inner.lost.max(oldest.seq);
        }
        ring.push_back(line.clone());
        // Told under the lock, so that lines are heard of in order.
        if let Some(tell) = &inner.tell {
            tell(&line);
        }
    }

    /// Has `tell` called with each line kept from now on. It must not log.
    pub(crate) fn tell(&self, tell: impl Fn(&LogLine) + Send + 'static) {
        lock(&self.0.inner).tell = Some(Box::new(tell));
    }

    /// Keeps `secret` out of every line until what is returned is dropped.
    pub(crate) fn hold(&self, secret: &Secret) -> Held {
        let mut inner = lock(&self.0.inner);
        inner.holds += 1;
        let hold = inner.holds;
        inner.hidden.push((hold, secret.clone()));
        Held(self.clone(), hold)
    }

    /// `text` as a log line would show it, for text that is shown elsewhere.
    pub(crate) fn shown(&self, text: &str) -> LogText {
        safe(text, &lock(&self.0.inner).hidden)
    }

    /// The lines after `after`, oldest first, as many as fit in one answer.
    /// A place in another run is no place in this one: the page then starts
    /// from the oldest line held.
    pub(crate) fn page(&self, after: Option<LogCursor>) -> LogPage {
        let inner = lock(&self.0.inner);
        let in_this_run = |place: &LogCursor| place.run == self.0.run;
        let after = after.filter(in_this_run).map_or(0, |place| place.seq);
        let mut lines: Vec<&LogLine> = inner.own.iter().chain(&inner.added).collect();
        lines.retain(|line| line.seq > after);
        lines.sort_by_key(|line| line.seq);
        let dropped = inner.lost > after;
        LogPage::after(self.0.run, after, dropped, lines.into_iter().cloned())
    }

    /// The text of every line kept, oldest first.
    pub fn lines(&self) -> Vec<String> {
        let inner = lock(&self.0.inner);
        let mut lines: Vec<&LogLine> = inner.own.iter().chain(&inner.added).collect();
        lines.sort_by_key(|line| line.seq);
        let text = |line: &LogLine| line.text.as_str().to_string();
        lines.into_iter().map(text).collect()
    }

    /// Where an engine logs while it holds `cookie`: into this log, never a
    /// line of protocol detail, and with the cookie removed from every line
    /// even if the engine forgets to hide it.
    pub(crate) fn sink(&self, cookie: &Secret) -> LogSink {
        let logs = self.clone();
        let keep = move |level, line: &str| {
            if let Some(level) = kept(level) {
                logs.keep(level, LogSource::Engine, line);
            }
        };
        let sink = LogSink::new(ubc_vpn_engine::LogLevel::Info, keep);
        sink.hide(cookie);
        sink
    }
}

#[cfg(test)]
#[path = "logs_tests.rs"]
mod tests;
