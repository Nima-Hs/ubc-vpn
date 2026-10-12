//! Who is connected, who the owner is, and what the owner's connections are
//! told. One lock covers all three, so a connection can neither miss a state
//! change nor be told about one it has no right to see.

use std::sync::{Arc, Mutex};

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
    /// Whether it receives events. Only ever true for the owner.
    subscribed: bool,
}

/// Sends one message. A failed write has already closed the connection.
pub(crate) fn send(conn: &Connection, message: &ServerMessage) -> bool {
    encode(message).is_ok_and(|line| conn.write_line(line.trim_end()).is_ok())
}

/// Starts sending events to an owner's connection, beginning with the current
/// state, and lifts its read limit: see [`crate::Timeouts`].
fn subscribe(client: &mut Client, state: &ConnState) {
    let _ = client.conn.set_read_timeout(None);
    client.subscribed = true;
    let event = Event::StateChanged(state.clone());
    send(&client.conn, &ServerMessage::Event(event));
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
            subscribed: false,
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

    pub(crate) fn close_all(&self) {
        let clients = std::mem::take(&mut lock(&self.0).clients);
        clients.iter().for_each(|client| client.conn.close());
    }
}
