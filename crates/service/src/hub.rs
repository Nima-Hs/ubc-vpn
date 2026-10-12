//! Who is connected, who the owner is, and what the owner's connections are
//! told. One lock covers all three, so a connection can neither miss a state
//! change nor be told about one it has no right to see.
//!
//! Nothing is ever written to a connection while that lock is held. Under
//! the lock a state is only put in a connection's queue; a thread of the
//! connection's own writes it. So a client that stops reading holds up its
//! own events until the write limit closes it, and nobody else's. The queue
//! is short: a client that falls that far behind is closed, not buffered for.

use std::sync::mpsc::{self, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread;

use ubc_vpn_core::protocol::{Event, ServerMessage, encode};
use ubc_vpn_core::state::ConnState;
use ubc_vpn_platform::{Connection, UserId};

use crate::lock;

/// The shared view of clients and connection state.
pub(crate) struct Hub(Mutex<Inner>);

struct Inner {
    owner: Option<UserId>,
    state: ConnState,
    clients: Vec<Client>,
}

struct Client {
    user: UserId,
    conn: Arc<Connection>,
    /// Where its events are queued, once it receives any. Only ever set
    /// for the owner.
    events: Option<SyncSender<ConnState>>,
}

/// How many states may wait for one connection. States are few, a handful
/// for a connect and a disconnect, so a client this far behind is not
/// reading.
pub(crate) const EVENT_QUEUE: usize = 16;

/// Sends one message. A failed write has already closed the connection.
pub(crate) fn send(conn: &Connection, message: &ServerMessage) -> bool {
    encode(message).is_ok_and(|line| conn.write_line(line.trim_end()).is_ok())
}

/// Starts sending events to an owner's connection, beginning with the current
/// state, and lifts its read limit: see [`crate::Timeouts`]. Writes nothing
/// itself: it starts the connection's writer and queues the state for it.
fn subscribe(client: &mut Client, state: &ConnState) {
    let _ = client.conn.set_read_timeout(None);
    let (events, queued) = mpsc::sync_channel(EVENT_QUEUE);
    let conn = client.conn.clone();
    // Ends when the hub forgets the connection or a state cannot be sent.
    // The connection is then closed, whatever the reason: one that hears
    // nothing more must not stay open as if nothing had happened.
    let write = move || {
        let event = |state| ServerMessage::Event(Event::StateChanged(state));
        let _ = queued
            .into_iter()
            .try_for_each(|state| send(&conn, &event(state)).then_some(()));
        conn.close();
    };
    if thread::Builder::new().spawn(write).is_err() {
        return client.conn.close();
    }
    let _ = events.try_send(state.clone());
    client.events = Some(events);
}

impl Hub {
    pub(crate) fn new(owner: Option<UserId>) -> Self {
        Self(Mutex::new(Inner {
            owner,
            state: ConnState::Disconnected,
            clients: Vec::new(),
        }))
    }

    pub(crate) fn owner(&self) -> Option<UserId> {
        lock(&self.0).owner.clone()
    }

    pub(crate) fn state(&self) -> ConnState {
        lock(&self.0).state.clone()
    }

    /// Registers a connection whose handshake is done. The owner's is told
    /// the current state at once; anyone else's is told nothing.
    pub(crate) fn add(&self, user: &UserId, conn: &Arc<Connection>) {
        let mut inner = lock(&self.0);
        let (user, conn) = (user.clone(), conn.clone());
        let mut client = Client {
            user,
            conn,
            events: None,
        };
        if inner.owner.as_ref() == Some(&client.user) {
            subscribe(&mut client, &inner.state);
        }
        inner.clients.push(client);
    }

    pub(crate) fn remove(&self, conn: &Arc<Connection>) {
        let other = |client: &Client| !Arc::ptr_eq(&client.conn, conn);
        lock(&self.0).clients.retain(other);
    }

    /// Makes `user` the owner when there is none, once `persist` has stored
    /// that; then closes every other user's connection and starts sending
    /// events to the owner's. Returns whether `user` is the owner.
    pub(crate) fn claim(
        &self,
        user: &UserId,
        persist: impl FnOnce() -> Result<(), String>,
    ) -> Result<bool, String> {
        let mut inner = lock(&self.0);
        if let Some(owner) = &inner.owner {
            return Ok(owner == user);
        }
        persist()?;
        inner.owner = Some(user.clone());
        let Inner { state, clients, .. } = &mut *inner;
        clients.retain_mut(|client| {
            let owned = client.user == *user;
            match owned {
                true => subscribe(client, state),
                false => client.conn.close(),
            }
            owned
        });
        Ok(true)
    }

    /// Records the new state and queues it for every connection of the
    /// owner, in the order states are published. A connection whose queue
    /// is full is closed.
    pub(crate) fn publish(&self, state: ConnState) {
        let mut inner = lock(&self.0);
        for client in &mut inner.clients {
            let queued = client
                .events
                .as_ref()
                .map(|events| events.try_send(state.clone()));
            if matches!(queued, Some(Err(_))) {
                client.events = None;
                client.conn.close();
            }
        }
        inner.state = state;
    }

    pub(crate) fn close_all(&self) {
        let clients = std::mem::take(&mut lock(&self.0).clients);
        clients.iter().for_each(|client| client.conn.close());
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Condvar;
    use std::time::{Duration, Instant};

    use ubc_vpn_core::protocol::ErrorCode;
    use ubc_vpn_platform::{RawConnection, Result};

    use super::*;

    /// The far end of a connection, which either takes every write or takes
    /// none, and shows whether the service closed it.
    #[derive(Clone, Default)]
    struct Far(Arc<(Mutex<FarState>, Condvar)>);

    #[derive(Default)]
    struct FarState {
        reads_nothing: bool,
        holding_a_write: bool,
        closed: bool,
    }

    impl Far {
        fn state(&self) -> std::sync::MutexGuard<'_, FarState> {
            self.0.0.lock().unwrap()
        }

        /// Waits, up to ten seconds, for something that should happen soon.
        fn until(&self, what: &str, happened: impl Fn(&FarState) -> bool) {
            let started = Instant::now();
            while !happened(&self.state()) {
                assert!(started.elapsed() < Duration::from_secs(10), "{what}");
                thread::sleep(Duration::from_millis(2));
            }
        }
    }

    impl RawConnection for Far {
        fn read(&self, _buf: &mut [u8]) -> Result<usize> {
            Ok(0)
        }

        fn write_all(&self, _bytes: &[u8]) -> Result<()> {
            let mut state = self.state();
            if state.reads_nothing {
                state.holding_a_write = true;
                // Not for ever: a regression that waits here under the
                // hub's lock must fail the tests, not hang them.
                let open = |state: &mut FarState| !state.closed;
                let limit = Duration::from_secs(5);
                drop(self.0.1.wait_timeout_while(state, limit, open));
                return Err(ubc_vpn_platform::Error::TimedOut);
            }
            Ok(())
        }

        fn set_read_timeout(&self, _timeout: Option<Duration>) -> Result<()> {
            Ok(())
        }

        fn set_write_timeout(&self, _timeout: Option<Duration>) -> Result<()> {
            Ok(())
        }

        fn close(&self) {
            self.state().closed = true;
            self.0.1.notify_all();
        }
    }

    /// A hub owned by `alice` with one connection of hers to `far`.
    fn owned(far: &Far) -> Hub {
        let alice: UserId = "alice".parse().unwrap();
        let hub = Hub::new(Some(alice.clone()));
        hub.add(&alice, &Arc::new(Connection::new(Box::new(far.clone()))));
        hub
    }

    // Security rule: the service does not buffer without limit for a client
    // that reads too slowly. Its queue is short, and when it is full the
    // connection is closed. Publishing never waits for it.
    #[test]
    fn a_client_too_far_behind_is_closed() {
        let far = Far::default();
        far.state().reads_nothing = true;
        let hub = owned(&far);
        // Its first state is being written, and is never taken.
        far.until("a write", |far| far.holding_a_write);
        let started = Instant::now();
        for _ in 0..EVENT_QUEUE {
            hub.publish(ConnState::Connecting);
        }
        assert!(
            !far.state().closed,
            "a full queue is still within the limit"
        );
        hub.publish(ConnState::Disconnected);
        assert!(far.state().closed, "one state too many closes it");
        assert_eq!(hub.state(), ConnState::Disconnected);
        let took = started.elapsed();
        assert!(took < Duration::from_secs(2), "publishing waited: {took:?}");
    }

    // A state too long to send must not leave the client connected and
    // hearing nothing: the connection is closed.
    #[test]
    fn a_state_that_cannot_be_sent_closes_the_connection() {
        let far = Far::default();
        let hub = owned(&far);
        let (code, message) = (ErrorCode::Internal, "x".repeat(70_000));
        hub.publish(ConnState::Failed { code, message });
        far.until("the connection is closed", |far| far.closed);
    }

    // Security rule: only the first claim makes an owner. A second user is
    // told no, nothing is stored for them, and the owner does not change.
    #[test]
    fn a_second_claim_by_another_user_changes_nothing() {
        let hub = Hub::new(None);
        let user = |name: &str| name.parse::<UserId>().unwrap();
        let mut stored = Vec::new();
        let mut claim = |name: &str| {
            let persist = || {
                stored.push(name.to_string());
                Ok(())
            };
            hub.claim(&user(name), persist)
        };
        assert_eq!(claim("alice"), Ok(true));
        assert_eq!(claim("mallory"), Ok(false));
        assert_eq!(claim("alice"), Ok(true));
        assert_eq!(stored, ["alice"]);
        assert_eq!(hub.owner(), Some(user("alice")));
    }

    // Security rule: an owner the service could not store does not exist.
    // Otherwise a restart would forget it and let someone else claim.
    #[test]
    fn a_claim_that_cannot_be_stored_makes_no_owner() {
        let hub = Hub::new(None);
        let alice = "alice".parse().unwrap();
        let failed = hub.claim(&alice, || Err("disk full".to_string()));
        assert_eq!(failed, Err("disk full".to_string()));
        assert_eq!(hub.owner(), None);
    }
}
