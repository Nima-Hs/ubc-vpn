//! What waits to be written to one connection of the owner's: states and
//! log lines, each with a limit of its own.
//!
//! A state must not be lost, so a connection with no room for one is closed
//! by whoever queued it. A log line may be lost: with no room for it, it is
//! dropped and nothing else happens, and the client sees the gap in the
//! numbers and asks for the lines. So no amount of logging can close a
//! connection or cost it a state.

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex};

use ubc_vpn_core::protocol::{Event, LogLine};
use ubc_vpn_core::state::ConnState;

use crate::lock;

/// How many states may wait for one connection. States are few, a handful
/// for a connect and a disconnect, so a client this far behind is not
/// reading.
pub(crate) const EVENT_QUEUE: usize = 16;

/// How many log lines may wait for one connection.
pub(crate) const LOG_QUEUE: usize = 64;

#[derive(Default)]
struct Waiting {
    states: VecDeque<ConnState>,
    logs: VecDeque<LogLine>,
    /// Whether nothing more will be queued.
    ended: bool,
}

type Shared = Arc<(Mutex<Waiting>, Condvar)>;

/// The end that queues. Dropping it ends the queue.
pub(crate) struct Queue(Shared);

/// The end that takes what was queued, to write it.
pub(crate) struct Taking(Shared);

/// A new, empty queue.
pub(crate) fn queue() -> (Queue, Taking) {
    let shared = Shared::default();
    (Queue(shared.clone()), Taking(shared))
}

impl Queue {
    /// Queues a state, or says that there was no room for it.
    pub(crate) fn state(&self, state: ConnState) -> bool {
        let mut waiting = lock(&self.0.0);
        let room = waiting.states.len() < EVENT_QUEUE;
        if room {
            waiting.states.push_back(state);
            self.0.1.notify_one();
        }
        room
    }

    /// Queues a log line if there is room for it.
    pub(crate) fn log(&self, line: &LogLine) {
        let mut waiting = lock(&self.0.0);
        if waiting.logs.len() < LOG_QUEUE {
            waiting.logs.push_back(line.clone());
            self.0.1.notify_one();
        }
    }
}

impl Drop for Queue {
    fn drop(&mut self) {
        lock(&self.0.0).ended = true;
        self.0.1.notify_one();
    }
}

impl Taking {
    /// Waits for the next thing to write: a state before a log line. `None`
    /// once the queue has ended and is empty.
    pub(crate) fn next(&self) -> Option<Event> {
        let mut waiting = lock(&self.0.0);
        loop {
            if let Some(state) = waiting.states.pop_front() {
                return Some(Event::StateChanged(state));
            }
            if let Some(line) = waiting.logs.pop_front() {
                return Some(Event::Log(line));
            }
            if waiting.ended {
                return None;
            }
            let woken = self.0.1.wait(waiting);
            waiting = woken.unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }
}

#[cfg(test)]
mod tests {
    use ubc_vpn_core::protocol::{LogLevel, LogSource, LogText};

    use super::*;

    fn line(seq: u64) -> LogLine {
        LogLine {
            seq,
            at_unix_ms: 0,
            level: LogLevel::Info,
            source: LogSource::Service,
            text: LogText::left_out(),
        }
    }

    // Security rule: the service does not buffer without limit for a client
    // that reads too slowly. Log lines there is no room for are dropped,
    // the newest first, and they never take a state's room.
    #[test]
    fn log_lines_beyond_the_room_are_dropped_and_states_are_not() {
        let (queue, taking) = queue();
        (1..=10 * LOG_QUEUE as u64).for_each(|seq| queue.log(&line(seq)));
        for _ in 0..EVENT_QUEUE {
            assert!(queue.state(ConnState::Connecting), "a state had no room");
        }
        assert!(!queue.state(ConnState::Connecting), "one state too many");
        drop(queue);

        // What was queued is still written after the queue has ended:
        // states first, then the lines that had room, in order.
        let taken: Vec<Event> = std::iter::from_fn(|| taking.next()).collect();
        let is_state = |event: &&Event| matches!(event, Event::StateChanged(_));
        assert_eq!(taken.iter().take_while(is_state).count(), EVENT_QUEUE);
        let seqs = taken.iter().filter_map(|event| match event {
            Event::Log(line) => Some(line.seq),
            Event::StateChanged(_) => None,
        });
        let kept: Vec<u64> = (1..=LOG_QUEUE as u64).collect();
        assert_eq!(seqs.collect::<Vec<_>>(), kept);
    }
}
