//! Who is connected, who the owner is, and what the owner's connections are
//! told. One lock covers all three, so a connection can neither miss a state
//! change nor be told about one it has no right to see.
//!
//! Nothing is ever written to a connection while that lock is held. Under
//! the lock a state is only put in a connection's queue; a thread of the
//! connection's own writes it. So a client that stops reading holds up its
//! own events until the write limit closes it, and nobody else's.

use std::sync::mpsc::{self, Sender};
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
    events: Option<Sender<ConnState>>,
}

/// Sends one message. A failed write has already closed the connection.
pub(crate) fn send(conn: &Connection, message: &ServerMessage) -> bool {
    encode(message).is_ok_and(|line| conn.write_line(line.trim_end()).is_ok())
}

/// Starts sending events to an owner's connection, beginning with the current
/// state, and lifts its read limit: see [`crate::Timeouts`]. Writes nothing
/// itself: it starts the connection's writer and queues the state for it.
fn subscribe(client: &mut Client, state: &ConnState) {
    let _ = client.conn.set_read_timeout(None);
    let (events, queued) = mpsc::channel();
    let conn = client.conn.clone();
    // Ends when the hub forgets the connection or a write fails, which
    // closes the connection.
    let write = move || {
        let event = |state| ServerMessage::Event(Event::StateChanged(state));
        let _ = queued
            .into_iter()
            .try_for_each(|state| send(&conn, &event(state)).then_some(()));
    };
    if thread::Builder::new().spawn(write).is_err() {
        return client.conn.close();
    }
    let _ = events.send(state.clone());
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
    /// owner, in the order states are published.
    pub(crate) fn publish(&self, state: ConnState) {
        let mut inner = lock(&self.0);
        for events in inner
            .clients
            .iter()
            .filter_map(|client| client.events.as_ref())
        {
            let _ = events.send(state.clone());
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
    use super::*;

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
