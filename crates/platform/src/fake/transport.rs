//! The fake's channel: in-process connections, with the caller a test
//! chooses.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use super::{Endpoint, Fake, Op};
use crate::{Connection, Error, Listener, RawConnection, Result, Transport, UserId, lock};

impl Transport for Fake {
    fn listen(&self, name: &str) -> Result<Box<dyn Listener>> {
        let (mut state, outcome) = self.start(Op::Listen);
        outcome?;
        if state.listeners.contains_key(name) {
            return Err(Error::AlreadyExists);
        }
        let (incoming, accepted) = mpsc::channel();
        let endpoint = Endpoint {
            incoming,
            owner: None,
        };
        state.listeners.insert(name.to_string(), endpoint);
        Ok(Box::new(FakeListener {
            fake: self.clone(),
            name: name.to_string(),
            accepted: Mutex::new(accepted),
            closed: AtomicBool::new(false),
        }))
    }

    fn connect(&self, name: &str) -> Result<Connection> {
        self.connect_as(name, &"fake-user".parse()?)
    }
}

struct FakeListener {
    fake: Fake,
    name: String,
    accepted: Mutex<Receiver<(Connection, UserId)>>,
    closed: AtomicBool,
}

impl Listener for FakeListener {
    fn accept(&self) -> Result<(Connection, UserId)> {
        // Closing drops the sending end, which ends the wait.
        let accepted = lock(&self.accepted).recv();
        match self.closed.load(Ordering::SeqCst) {
            true => Err(Error::Closed),
            false => accepted.map_err(|_| Error::Closed),
        }
    }

    fn restrict_to(&self, owner: &UserId) -> Result<()> {
        let (mut state, outcome) = self.fake.start(Op::RestrictTo);
        outcome?;
        if self.closed.load(Ordering::SeqCst) {
            return Err(Error::Closed);
        }
        let endpoint = state.listeners.get_mut(&self.name).ok_or(Error::Closed)?;
        endpoint.owner = Some(owner.clone());
        Ok(())
    }

    fn close(&self) {
        if !self.closed.swap(true, Ordering::SeqCst) {
            self.fake.state().listeners.remove(&self.name);
        }
    }
}

impl Drop for FakeListener {
    fn drop(&mut self) {
        self.close();
    }
}

/// One direction of an in-process connection.
#[derive(Default)]
struct Half {
    state: Mutex<HalfState>,
    changed: Condvar,
}

#[derive(Default)]
struct HalfState {
    bytes: VecDeque<u8>,
    closed: bool,
}

/// One end of an in-process connection.
struct PipeEnd {
    incoming: Arc<Half>,
    outgoing: Arc<Half>,
    timeout: Mutex<Option<Duration>>,
}

pub(super) fn pipe_pair() -> (Connection, Connection) {
    let (up, down) = (Arc::new(Half::default()), Arc::new(Half::default()));
    let end = |incoming: &Arc<Half>, outgoing: &Arc<Half>| {
        Connection::new(Box::new(PipeEnd {
            incoming: incoming.clone(),
            outgoing: outgoing.clone(),
            timeout: Mutex::default(),
        }))
    };
    (end(&down, &up), end(&up, &down))
}

impl RawConnection for PipeEnd {
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let timeout = *lock(&self.timeout);
        let half = &self.incoming;
        let waiting = |state: &mut HalfState| state.bytes.is_empty() && !state.closed;
        let state = lock(&half.state);
        let waited = match timeout {
            None => half.changed.wait_while(state, waiting).ok(),
            Some(timeout) => half
                .changed
                .wait_timeout_while(state, timeout, waiting)
                .ok()
                .map(|(state, _)| state),
        };
        let panicked = || Error::Failed("a test panicked while using the fake".to_string());
        let mut state = waited.ok_or_else(panicked)?;
        if waiting(&mut state) {
            return Err(Error::TimedOut);
        }
        let n = buf.len().min(state.bytes.len());
        for (slot, byte) in buf.iter_mut().zip(state.bytes.drain(..n)) {
            *slot = byte;
        }
        Ok(n)
    }

    fn write_all(&self, bytes: &[u8]) -> Result<()> {
        let mut state = lock(&self.outgoing.state);
        if state.closed {
            return Err(Error::Closed);
        }
        state.bytes.extend(bytes);
        self.outgoing.changed.notify_all();
        Ok(())
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        *lock(&self.timeout) = timeout;
        Ok(())
    }

    /// Nothing to set: the fake takes every byte at once, so a write never
    /// waits.
    fn set_write_timeout(&self, _timeout: Option<Duration>) -> Result<()> {
        Ok(())
    }

    fn close(&self) {
        for half in [&self.incoming, &self.outgoing] {
            lock(&half.state).closed = true;
            half.changed.notify_all();
        }
    }
}

impl Drop for PipeEnd {
    fn drop(&mut self) {
        self.close();
    }
}
