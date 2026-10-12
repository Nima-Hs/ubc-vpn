//! The service's log: a bounded buffer in memory. Nothing is written to disk.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_buffer_is_bounded() {
        let logs = Logs::default();
        (0..CAPACITY + 10).for_each(|n| logs.push(&n.to_string()));
        let lines = logs.lines();
        assert_eq!(lines.len(), CAPACITY);
        assert_eq!(lines[0], "10");
    }
}
