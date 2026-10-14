//! The service's log: bounded, in memory, and safe to show its owner.
//! Nothing is written to disk.
//!
//! Every line, whoever wrote it, goes through [`safe`] before it is kept:
//! the service's own, the engine's, and those a client hands over. A line is
//! kept whole or not at all. There is no way to keep a line of protocol
//! detail: the level does not exist here.
//!
//! # What the removal of secrets does not do
//!
//! A secret the service holds is removed where it stands whole, as it was
//! given. That is all. It is not found when it is split over two lines,
//! when it is written with something between its characters, or in another
//! form such as percent-encoding or base64. Nor is anything shorter than
//! four bytes removed: so short an answer is a choice, such as which way to
//! be asked for a second factor, and not a secret, and removing every `1`
//! would cost real lines their numbers. Nobody should assume more: the
//! first defence is that nothing writes a secret, and this is the second.
//!
//! # How long the cookie is held
//!
//! From the moment a connect is admitted until [`LINGER`] after everything
//! for it has been torn down, or until the next connect is admitted if
//! that is sooner. It is held that little longer because a client hands
//! over what its login wrote just after a connect has failed, and those
//! lines are the likeliest to name it. In that time it is used for
//! nothing but this, and then it is wiped.
//!
//! # What cannot fill the log
//!
//! A line that the same cause can produce again and again, such as a
//! request that cannot be read, goes through [`Logs::error_about`] or
//! [`Logs::warn_about`]: a repeat of the last line about the same thing is
//! passed over for as long as that line is still in the log. So the log
//! holds one copy of it at most, and never none once it has happened; and
//! nothing a client sends, and no fault that persists, can push the
//! earlier lines out.
//!
//! The lines a client causes just by asking, about the connects and
//! disconnects it asks for and what came of them, go through
//! [`Logs::about_requests`]. At most [`REQUEST_LINES`] of them are kept in
//! any [`REQUEST_WINDOW`]; past that one line says the rest were not, and
//! nothing more is kept until the window has passed. Ordinary use writes
//! a handful in an hour.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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

/// How long the cookie is still held, for cleaning only, after everything
/// for its connection has been torn down.
pub const LINGER: Duration = Duration::from_secs(30);

/// How many lines caused by clients' requests are kept in one
/// [`REQUEST_WINDOW`].
pub const REQUEST_LINES: usize = 30;

/// See [`REQUEST_LINES`].
pub const REQUEST_WINDOW: Duration = Duration::from_secs(10 * 60);

/// What stands for the lines about requests that were not kept.
pub const NOT_LOGGED: &str = "more requests were not logged";

/// Who hears of each line as it is kept.
type Tell = Box<dyn Fn(&LogLine) + Send>;

/// What the time is. Tests put their own in.
type Clock = Box<dyn Fn() -> Instant + Send + Sync>;

/// The log. Clones share it.
#[derive(Clone)]
pub struct Logs(Arc<Shared>);

struct Shared {
    /// Which run of the service this is.
    run: u64,
    clock: Clock,
    /// How long a secret lingers: [`LINGER`], unless a test put in less.
    linger: Duration,
    inner: Mutex<Inner>,
}

/// A secret the service holds.
struct Hidden {
    /// The number of its hold.
    hold: u64,
    secret: Secret,
    /// When it is to be wiped, once nothing needs it but the cleaning.
    until: Option<Instant>,
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
    /// The secrets the service holds now.
    hidden: Vec<Hidden>,
    holds: u64,
    /// The number of the last line kept about each thing that can happen
    /// again and again.
    about: Vec<(&'static str, u64)>,
    tell: Option<Tell>,
    /// When the present window for lines about requests began, how many it
    /// has kept, and whether it has said that it keeps no more.
    window: Option<Instant>,
    in_window: usize,
    said_full: bool,
}

impl Inner {
    /// Wipes every secret whose time is up.
    fn wipe(&mut self, now: Instant) {
        let due = |hidden: &Hidden| hidden.until.is_some_and(|until| until <= now);
        self.hidden.retain(|hidden| !due(hidden));
    }
}

/// Keeps a secret out of every line for as long as this lives, and for
/// [`LINGER`] longer if it is ended with [`Held::linger`].
pub(crate) struct Held {
    logs: Logs,
    hold: u64,
    lingers: bool,
}

impl Held {
    /// Ends the hold, but leaves the secret to the cleaning for [`LINGER`]
    /// more, or until the next secret is held if that is sooner.
    pub(crate) fn linger(mut self) {
        let until = (self.logs.0.clock)() + self.logs.0.linger;
        let mut inner = lock(&self.logs.0.inner);
        let this = |hidden: &&mut Hidden| hidden.hold == self.hold;
        if let Some(hidden) = inner.hidden.iter_mut().find(this) {
            hidden.until = Some(until);
        }
        drop(inner);
        self.lingers = true;
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        if !self.lingers {
            let mut inner = lock(&self.logs.0.inner);
            inner.hidden.retain(|hidden| hidden.hold != self.hold);
        }
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
fn safe(text: &str, hidden: &[Hidden]) -> LogText {
    let Ok(plain) = LogText::cleaned(text) else {
        return LogText::left_out();
    };
    let mut line = String::from(plain);
    for Hidden { secret, .. } in hidden {
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
        Self::with(Instant::now, LINGER)
    }
}

impl Logs {
    /// A log that takes the time from `clock` and lets a secret linger for
    /// `linger`.
    fn with(clock: impl Fn() -> Instant + Send + Sync + 'static, linger: Duration) -> Self {
        let (run, clock, inner) = (new_run(), Box::new(clock), Mutex::default());
        Self(Arc::new(Shared {
            run,
            clock,
            linger,
            inner,
        }))
    }

    /// A log on the real clock that lets a secret linger only for `linger`.
    #[cfg(test)]
    pub(crate) fn lingering(linger: Duration) -> Self {
        Self::with(Instant::now, linger)
    }

    /// How many secrets are held at this moment. It wipes nothing itself,
    /// so that a test sees what was wiped without being asked.
    #[cfg(test)]
    pub(crate) fn held(&self) -> usize {
        lock(&self.0.inner).hidden.len()
    }

    /// Keeps a line about something that failed and happens once.
    pub fn error(&self, text: &str) {
        self.keep(LogLevel::Error, LogSource::Service, None, text);
    }

    /// Keeps a line about something wrong that was dealt with, once.
    pub fn warn(&self, text: &str) {
        self.keep(LogLevel::Warn, LogSource::Service, None, text);
    }

    /// Keeps a line about what happened, that happens once.
    pub fn info(&self, text: &str) {
        self.keep(LogLevel::Info, LogSource::Service, None, text);
    }

    /// Keeps a line that a client caused by asking, within the budget for
    /// such lines: see the module documentation.
    pub(crate) fn about_requests(&self, level: LogLevel, text: &str) {
        let now = (self.0.clock)();
        let kept = {
            let mut inner = lock(&self.0.inner);
            let over = |began: Instant| now.saturating_duration_since(began) >= REQUEST_WINDOW;
            if inner.window.is_none_or(over) {
                (inner.window, inner.in_window, inner.said_full) = (Some(now), 0, false);
            }
            if inner.in_window < REQUEST_LINES {
                inner.in_window += 1;
                Some((level, text))
            } else if !inner.said_full {
                inner.said_full = true;
                Some((LogLevel::Warn, NOT_LOGGED))
            } else {
                None
            }
        };
        if let Some((level, text)) = kept {
            self.keep(level, LogSource::Service, None, text);
        }
    }

    /// Keeps a line about a failure that can happen again and again, named
    /// by `what`, unless it repeats the last line about it and that line is
    /// still in the log.
    pub fn error_about(&self, what: &'static str, text: &str) {
        self.keep(LogLevel::Error, LogSource::Service, Some(what), text);
    }

    /// The same, for something wrong that was dealt with.
    pub fn warn_about(&self, what: &'static str, text: &str) {
        self.keep(LogLevel::Warn, LogSource::Service, Some(what), text);
    }

    /// Keeps a line a client handed over.
    pub(crate) fn add(&self, level: LogLevel, text: &LogText) {
        self.keep(level, LogSource::Login, None, text.as_str());
    }

    /// Cleans `text`, numbers it and keeps it, dropping the oldest line of
    /// its kind when that is full. A blank text is not a line, and neither
    /// is one that only repeats the last line about `what`.
    fn keep(&self, level: LogLevel, source: LogSource, what: Option<&'static str>, text: &str) {
        if text.trim().is_empty() {
            return;
        }
        let mut inner = lock(&self.0.inner);
        let inner = &mut *inner;
        inner.wipe((self.0.clock)());
        let text = safe(text, &inner.hidden);
        if let Some(what) = what {
            // A repeat is passed over only while the line it repeats is
            // still held: the log has one copy of it at most, and never
            // none once other lines have pushed that copy out.
            let last = inner.about.iter_mut().find(|(about, _)| *about == what);
            let held = |seq: u64| inner.own.iter().find(|line| line.seq == seq);
            match last {
                Some((_, seq)) if held(*seq).is_some_and(|line| line.text == text) => return,
                Some((_, seq)) => *seq = inner.newest + 1,
                None => inner.about.push((what, inner.newest + 1)),
            }
        }
        inner.newest += 1;
        let line = LogLine {
            seq: inner.newest,
            at_unix_ms: now_ms(),
            level,
            source,
            text,
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
    /// A secret that only lingered is wiped now: the next one has come.
    pub(crate) fn hold(&self, secret: &Secret) -> Held {
        let mut inner = lock(&self.0.inner);
        inner.hidden.retain(|hidden| hidden.until.is_none());
        inner.holds += 1;
        let hold = inner.holds;
        inner.hidden.push(Hidden {
            hold,
            secret: secret.clone(),
            until: None,
        });
        Held {
            logs: self.clone(),
            hold,
            lingers: false,
        }
    }

    /// Wipes every secret whose time is up, and says how long it is until
    /// the next one's is, if any is waiting for that.
    pub(crate) fn wipe(&self) -> Option<Duration> {
        let now = (self.0.clock)();
        let mut inner = lock(&self.0.inner);
        inner.wipe(now);
        let waits = inner.hidden.iter().filter_map(|hidden| hidden.until);
        waits
            .min()
            .map(|until| until.saturating_duration_since(now))
    }

    /// `text` as a log line would show it, for text that is shown elsewhere.
    pub(crate) fn shown(&self, text: &str) -> LogText {
        let mut inner = lock(&self.0.inner);
        inner.wipe((self.0.clock)());
        safe(text, &inner.hidden)
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
        let text = |line: LogLine| line.text.as_str().to_string();
        self.all().into_iter().map(text).collect()
    }

    /// Every line kept, oldest first.
    pub fn all(&self) -> Vec<LogLine> {
        let inner = lock(&self.0.inner);
        let mut lines: Vec<LogLine> = inner.own.iter().chain(&inner.added).cloned().collect();
        lines.sort_by_key(|line| line.seq);
        lines
    }

    /// Where an engine logs while it holds `cookie`: into this log, never a
    /// line of protocol detail, and with the cookie removed from every line
    /// even if the engine forgets to hide it.
    pub(crate) fn sink(&self, cookie: &Secret) -> LogSink {
        let logs = self.clone();
        let keep = move |level, line: &str| {
            if let Some(level) = kept(level) {
                logs.keep(level, LogSource::Engine, None, line);
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
