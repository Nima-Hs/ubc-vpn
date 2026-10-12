//! The service's log: a bounded buffer in memory. Nothing is written to disk.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use ubc_vpn_core::redact::Secret;
use ubc_vpn_engine::{LogLevel, LogSink};

use crate::lock;

/// The most lines kept. Older lines are dropped first.
pub const CAPACITY: usize = 500;

/// The log buffer. Clones share it.
#[derive(Clone, Default)]
pub struct Logs(Arc<Mutex<VecDeque<String>>>);

impl Logs {
    /// Adds a line the service wrote itself. It must never hold a secret.
    pub fn push(&self, line: &str) {
        let mut lines = lock(&self.0);
        if lines.len() == CAPACITY {
            lines.pop_front();
        }
        lines.push_back(line.to_string());
    }

    /// The lines kept, oldest first.
    pub fn lines(&self) -> Vec<String> {
        lock(&self.0).iter().cloned().collect()
    }

    /// Where an engine logs while it holds `cookie`: into this buffer, never
    /// in more detail than `Info`, and with the cookie removed from every
    /// line even if the engine forgets to hide it.
    pub(crate) fn sink(&self, cookie: &Secret) -> LogSink {
        let logs = self.clone();
        let sink = LogSink::new(LogLevel::Info, move |_, line| logs.push(line));
        sink.hide(cookie);
        sink
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Security rule: the cookie is registered with the sink, so a line that
    // carries it with no marker word still never reaches the buffer.
    #[test]
    fn the_cookie_never_reaches_the_buffer() {
        let logs = Logs::default();
        let sink = logs.sink(&Secret::new("Zq7-made-up-0123456789"));
        sink.log(LogLevel::Error, "> Zq7-made-up-0123456789 <");
        sink.log(LogLevel::Debug, "detail");
        assert_eq!(logs.lines(), ["> [redacted] <"]);
    }

    #[test]
    fn the_buffer_is_bounded() {
        let logs = Logs::default();
        (0..CAPACITY + 10).for_each(|n| logs.push(&n.to_string()));
        let lines = logs.lines();
        assert_eq!(lines.len(), CAPACITY);
        assert_eq!(lines[0], "10");
    }
}
