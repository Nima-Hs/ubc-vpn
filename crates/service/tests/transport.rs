//! What the platform fake cannot show: the limit the service puts on its
//! writes, clients that stop reading, a connection whose thread panics, and
//! what happens when accepting ends by itself. A transport made for these tests stands in for the fake's.

mod harness;

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use harness::*;
use ubc_vpn_platform::{Listener, Platform, RawConnection, Result, Transport};
use ubc_vpn_service::{Service, Timeouts};

/// A channel that hands the service the connections a test gives it, all as
/// the user `alice`. With none left it waits for more or to be closed, or
/// panics if the test asked for that.
#[derive(Clone, Default)]
struct Scripted(Arc<Script>);

#[derive(Default)]
struct Script {
    queue: Mutex<(VecDeque<Connection>, bool)>,
    changed: Condvar,
    panic_when_empty: bool,
}

impl Scripted {
    fn connect(&self, peer: &Peer) {
        let conn = Connection::new(Box::new(peer.clone()));
        self.0.queue.lock().unwrap().0.push_back(conn);
        self.0.changed.notify_all();
    }
}

impl Transport for Scripted {
    fn listen(&self, _name: &str) -> Result<Box<dyn Listener>> {
        Ok(Box::new(self.clone()))
    }

    fn connect(&self, _name: &str) -> Result<Connection> {
        Err(Error::Unsupported)
    }
}

impl Listener for Scripted {
    fn accept(&self) -> Result<(Connection, UserId)> {
        let mut queue = self.0.queue.lock().unwrap();
        loop {
            if let Some(conn) = queue.0.pop_front() {
                return Ok((conn, user("alice")));
            }
            if queue.1 {
                return Err(Error::Closed);
            }
            if self.0.panic_when_empty {
                // Without the lock, so that closing still works afterwards.
                drop(queue);
                panic!("the test ends accepting here");
            }
            queue = self.0.changed.wait(queue).unwrap();
        }
    }

    fn restrict_to(&self, _owner: &UserId) -> Result<()> {
        Ok(())
    }

    fn close(&self) {
        self.0.queue.lock().unwrap().1 = true;
        self.0.changed.notify_all();
    }
}

/// The far end of one connection: it sends what the test scripted, keeps
/// what the service writes, and can stop taking writes.
#[derive(Clone, Default)]
struct Peer(Arc<(Mutex<PeerState>, Condvar)>);

#[derive(Default)]
struct PeerState {
    /// What the peer has still to send.
    sends: VecDeque<u8>,
    /// Hangs up once everything is sent, where it would otherwise wait.
    hangs_up: bool,
    /// Makes every read panic, as a bug in the service's own thread would.
    panics: bool,
    received: String,
    /// How many writes it takes before it stops reading; `None` for all.
    takes: Option<usize>,
    /// Whether a write is waiting on it right now.
    holding_a_write: bool,
    write_limits: Vec<Option<Duration>>,
    closed: bool,
}

impl Peer {
    fn sending(lines: &[&str]) -> Self {
        let peer = Self::default();
        let bytes = lines
            .iter()
            .flat_map(|line| format!("{line}\n").into_bytes());
        peer.state().sends = bytes.collect();
        peer
    }

    fn state(&self) -> std::sync::MutexGuard<'_, PeerState> {
        self.0.0.lock().unwrap()
    }

    fn lines(&self) -> usize {
        self.state().received.lines().count()
    }
}

impl RawConnection for Peer {
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let mut state = self.state();
        if state.panics {
            // Without the lock, so that closing still works afterwards.
            drop(state);
            panic!("the test makes this connection's thread panic");
        }
        while state.sends.is_empty() && !state.closed && !state.hangs_up {
            state = self.0.1.wait(state).unwrap();
        }
        let n = buf.len().min(state.sends.len());
        let sent = state.sends.drain(..n);
        buf.iter_mut()
            .zip(sent)
            .for_each(|(slot, byte)| *slot = byte);
        Ok(n)
    }

    fn write_all(&self, bytes: &[u8]) -> Result<()> {
        let mut state = self.state();
        if state.takes == Some(0) {
            // Nobody reads: wait as long as the limit allows, or for ever.
            state.holding_a_write = true;
            let limit = state.write_limits.last().copied().flatten();
            let open = |state: &mut PeerState| !state.closed;
            let limit = limit.unwrap_or(Duration::MAX);
            let (waited, _) = self.0.1.wait_timeout_while(state, limit, open).unwrap();
            return Err(match waited.closed {
                true => Error::Closed,
                false => Error::TimedOut,
            });
        }
        state.takes = state.takes.map(|left| left - 1);
        state.received.push_str(&String::from_utf8_lossy(bytes));
        Ok(())
    }

    fn set_read_timeout(&self, _timeout: Option<Duration>) -> Result<()> {
        Ok(())
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        self.state().write_limits.push(timeout);
        Ok(())
    }

    fn close(&self) {
        self.state().closed = true;
        self.0.1.notify_all();
    }
}

fn start(rig: &Rig, channel: &Scripted, timeouts: Timeouts) -> Service {
    let platform = Platform {
        transport: Arc::new(channel.clone()),
        ..rig.fake.platform(&rig.root)
    };
    Service::start(platform, rig.spy.clone(), timeouts).unwrap()
}

/// Waits for something that should happen soon. A regression fails here.
fn until(what: &str, happened: impl Fn() -> bool) {
    let started = Instant::now();
    while !happened() {
        assert!(started.elapsed() < WAIT, "never happened: {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

const HELLO: &str = r#"{"protocol_version":2,"client":"app","client_version":"0.1.0"}"#;
const CLAIM: &str = r#"{"id":1,"body":{"method":"claim"}}"#;
const STATUS: &str = r#"{"id":2,"body":{"method":"status"}}"#;

// Security rule: every write to a client has a time limit, so one that
// stops reading is closed and cannot hold a thread for ever.
#[test]
fn every_connection_is_given_the_write_limit() {
    let rig = Rig::stopped(policy('A', ""));
    let (channel, peer) = (Scripted::default(), Peer::default());
    peer.state().hangs_up = true;
    channel.connect(&peer);
    let write = Duration::from_secs(7);
    let timeouts = Timeouts {
        write,
        ..Timeouts::default()
    };
    let _service = start(&rig, &channel, timeouts);
    // The service answers the hello that never came; that is a write.
    until("a write", || peer.lines() == 1);
    assert_eq!(peer.state().write_limits, [Some(write)]);
}

// Security rule: owner connections that stop reading delay nobody else.
// Nothing is written to a client while the hub's lock is held, so a healthy
// client is served while several stuck ones still wait out their limit.
#[test]
fn clients_that_stop_reading_delay_nobody_else() {
    let rig = Rig::stopped(policy('A', ""));
    let channel = Scripted::default();
    // Far longer than the test: nothing here may wait for it.
    let timeouts = Timeouts {
        write: Duration::from_secs(120),
        ..Timeouts::default()
    };
    let _service = start(&rig, &channel, timeouts);
    let owner = Peer::sending(&[HELLO, CLAIM]);
    channel.connect(&owner);
    until("the claim", || owner.lines() == 3);

    // Each takes the hello's answer and then never reads again, so the
    // state it is owed as the owner's connection is never taken.
    let stuck = [(); 3].map(|()| Peer::sending(&[HELLO]));
    for peer in &stuck {
        peer.state().takes = Some(1);
        channel.connect(peer);
        until("a write nobody takes", || peer.state().holding_a_write);
    }

    let healthy = Peer::sending(&[HELLO, STATUS]);
    channel.connect(&healthy);
    until("the healthy client is served", || healthy.lines() == 3);
    let received = healthy.state().received.clone();
    assert!(received.contains(r#""kind":"state_changed""#), "{received}");
    assert!(received.contains(r#""kind":"status""#), "{received}");
    assert!(stuck.iter().all(|peer| peer.lines() == 1), "still stuck");
}

// A connection's place, and the connection itself, are given back by a
// guard, so a thread that panics leaks neither: a user at their limit can
// connect again.
#[test]
fn a_thread_that_panics_gives_its_place_back() {
    let rig = Rig::stopped(policy('A', ""));
    let channel = Scripted::default();
    let _service = start(&rig, &channel, Timeouts::default());
    // Nobody owns the service, so this user is a stranger, with two places.
    for _ in 0..ubc_vpn_service::MAX_PER_STRANGER {
        let broken = Peer::default();
        broken.state().panics = true;
        channel.connect(&broken);
        until("the broken connection is closed", || broken.state().closed);
    }
    let next = Peer::sending(&[HELLO]);
    channel.connect(&next);
    until("the next connection is answered", || next.lines() == 1);
}

// A service that has stopped accepting must not look healthy. Nothing closes
// the channel on purpose while the program waits on the service, so any end
// of accepting is reported, and the program exits with an error.
#[test]
fn accepting_that_ends_by_itself_is_an_error() {
    let rig = Rig::stopped(policy('A', ""));
    let script = Script {
        panic_when_empty: true,
        ..Script::default()
    };
    // Waited for on another thread, so that a service which never returns
    // fails this test and does not hang it.
    let waited = |channel: Scripted| {
        let service = start(&rig, &channel, Timeouts::default());
        let (done, ended) = std::sync::mpsc::channel();
        std::thread::spawn(move || done.send(service.wait()));
        ended.recv_timeout(WAIT).expect("waiting never returned")
    };
    let ended = waited(Scripted(Arc::new(script)));
    assert!(ended.contains("stopped accepting"), "{ended}");

    // The same when the OS closes the channel under the service.
    let closing = Scripted::default();
    closing.close();
    let ended = waited(closing);
    assert!(ended.contains("stopped accepting"), "{ended}");

    // Shutting down on purpose is not waiting, and still works.
    drop(start(&rig, &Scripted::default(), Timeouts::default()));
}
