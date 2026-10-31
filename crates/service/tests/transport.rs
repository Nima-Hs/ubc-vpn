//! What the platform fake cannot show: the limit the service puts on its
//! writes, clients that stop reading, a connection whose thread panics, and
//! what happens when accepting ends by itself. A transport made for these tests stands in for the fake's.

mod harness;

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use harness::*;
use ubc_vpn_core::protocol::{Request, encode};
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
    /// Has gone: what it sent can still be read, as from a socket whose
    /// writer has closed, but every write to it fails at once.
    gone: bool,
    /// The same for answers to requests only: state events still arrive.
    /// So the service closes the connection only once its requests are
    /// done, and a test can tell when that is.
    gone_for_answers: bool,
    /// Run before an answer to a peer that has gone fails, as a slow
    /// machine would take its time: the service's other threads go on.
    before_failing: Option<Arc<dyn Fn() + Send + Sync>>,
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

    /// Sends one more line.
    fn send(&self, line: &str) {
        self.state().sends.extend(format!("{line}\n").into_bytes());
        self.0.1.notify_all();
    }

    /// How many times the service told it of the state named `state`.
    fn heard(&self, state: &str) -> usize {
        let event = format!(r#""kind":"state_changed","value":{{"state":"{state}""#);
        self.state().received.matches(&event).count()
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
        let answer = String::from_utf8_lossy(bytes).starts_with(r#"{"type":"response""#);
        if let Some(wait) = state
            .before_failing
            .clone()
            .filter(|_| (state.gone || state.gone_for_answers) && answer)
        {
            drop(state);
            wait();
            return Err(Error::Closed);
        }
        if state.gone || (state.gone_for_answers && answer) {
            return Err(Error::Closed);
        }
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
        ..rig.platform()
    };
    Service::start(platform, rig.state(), rig.spy.clone(), timeouts).unwrap()
}

/// Waits for something that should happen soon. A regression fails here.
fn until(what: &str, happened: impl Fn() -> bool) {
    let started = Instant::now();
    while !happened() {
        assert!(started.elapsed() < WAIT, "never happened: {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

const HELLO: &str = r#"{"protocol_version":6,"client":"app","client_version":"0.1.0"}"#;
const CLAIM: &str = r#"{"id":1,"body":{"method":"claim"}}"#;
const STATUS: &str = r#"{"id":2,"body":{"method":"status"}}"#;

// Security rule (#163): a client that asks to connect and goes before it
// hears the answer is watching nothing, and nobody is left to undo the
// connect. So when the service cannot give an admitted connect its answer,
// it undoes that connect itself, and nothing is left connected or applied.
#[test]
fn a_connect_whose_client_has_gone_is_undone() {
    let rig = Rig::stopped(policy('A', ""));
    let channel = Scripted::default();
    let service = start(&rig, &channel, Timeouts::default());
    let owner = Peer::sending(&[HELLO, CLAIM]);
    channel.connect(&owner);
    until("the claim", || owner.lines() == 3);
    // First the budget for lines that requests cause is spent, with
    // connects that are refused: the line that says why the connect below
    // was undone is not one of those, and must be written all the same.
    let request = |id, body| encode(&Request { id, body }).unwrap();
    let refused = || connect(COOKIE, [0, 0, 0, 0], &["10.255.0.0/24"], &[]);
    let spend = ubc_vpn_service::REQUEST_LINES + 1;
    for n in 0..spend {
        owner.send(request((10 + n).try_into().unwrap(), refused()).trim_end());
    }
    until("the refusals", || owner.lines() == 3 + spend);
    // Gone before the connect is read: its answer cannot reach anyone.
    owner.state().gone = true;
    owner.send(request(2, good()).trim_end());

    let said = |what: &str| service.logs().iter().any(|line| line.starts_with(what));
    until("the connect is undone, and said so", || {
        said(ubc_vpn_service::ABANDONED)
    });
    // Anyone who asks hears that it is disconnected. Asked, not read from
    // the log: the service was disconnected before this connect, which
    // never reached the gateway, so ending there again is not news there.
    let disconnected = || {
        let next = Peer::sending(&[HELLO, STATUS]);
        channel.connect(&next);
        until("the status", || next.lines() == 3);
        let received = next.state().received.clone();
        received.contains(r#""kind":"status","value":{"state":"disconnected""#)
    };
    until("disconnected", disconnected);
    assert!(!rig.engine.tunnel_is_open());
    assert!(rig.is_clean());
}

// Security rule: nothing is done at the gateway for a client that went
// before it could be told its connect was admitted: no session is logged in
// for nobody. Here the failed answer takes its time, as on a slow machine,
// which gives the service every chance to contact the gateway first. It
// must not: the connect waits for its answer to be settled, and one that
// cannot be given is undone before the gateway is reached.
#[test]
fn a_client_that_went_is_never_logged_in_at_the_gateway() {
    let rig = Rig::stopped(policy('A', ""));
    let channel = Scripted::default();
    let service = start(&rig, &channel, Timeouts::default());
    let owner = Peer::sending(&[HELLO, CLAIM]);
    channel.connect(&owner);
    until("the claim", || owner.lines() == 3);
    let peer = Peer::sending(&[HELLO]);
    channel.connect(&peer);
    until("the hello and the state", || peer.lines() == 2);
    // Its answer fails only once the gateway has been contacted, or after
    // a while. State events still reach it, so nothing else closes it first.
    let spy = rig.spy.clone();
    let slow = move || {
        let until = Instant::now() + Duration::from_millis(500);
        while spy.opens().is_empty() && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(5));
        }
    };
    {
        let mut state = peer.state();
        state.gone_for_answers = true;
        state.before_failing = Some(Arc::new(slow));
    }
    // The owner was told `disconnected` once already, when it claimed.
    let before = owner.heard("disconnected");
    let connect = encode(&Request {
        id: 2,
        body: good(),
    })
    .unwrap();
    peer.send(connect.trim_end());

    until("the connect is undone", || {
        owner.heard("disconnected") > before
    });
    assert!(rig.spy.opens().is_empty(), "{:#?}", service.logs());
    assert!(!rig.engine.tunnel_is_open());
    assert!(rig.is_clean());
}

// Security rule: asking to connect and going, again and again, costs the
// client nothing (the gateway is never contacted), so the line about it
// must not fill the log. It is written the first time, and a repeat is
// passed over while that copy is still in the log.
#[test]
fn connecting_and_going_again_and_again_is_said_once() {
    let rig = Rig::stopped(policy('A', ""));
    let channel = Scripted::default();
    let service = start(&rig, &channel, Timeouts::default());
    let owner = Peer::sending(&[HELLO, CLAIM]);
    channel.connect(&owner);
    until("the claim", || owner.lines() == 3);
    let undone = || {
        let lines = service.logs();
        lines
            .iter()
            .filter(|line| *line == ubc_vpn_service::ABANDONED)
            .count()
    };
    // Counted from what the owner's first connection is told, not from the
    // log: the log line comes before the clients are told, and a round may
    // begin only once the last one's end has been sent to everyone, or a
    // late state event would be the new connection's second line.
    let disconnected = || owner.heard("disconnected");
    for round in 0..40 {
        let before = disconnected();
        let peer = Peer::sending(&[HELLO]);
        channel.connect(&peer);
        // The hello's answer and the state an owner's connection is told: once
        // both are in, nothing more is written to it until it asks.
        until("the hello and the state", || peer.lines() == 2);
        peer.state().gone = true;
        let connect = encode(&Request {
            id: 2,
            body: good(),
        })
        .unwrap();
        peer.send(connect.trim_end());
        until(&format!("round {round} undone"), || disconnected() > before);
    }
    assert_eq!(undone(), 1, "{:#?}", service.logs());
}

// Security rule: connecting and going, more times than the log holds, does
// not push the service's own first lines out. None of the connects is
// worked on, since none of their clients was told: none reaches the gateway,
// and the undo line and the state lines it leads to are each said once at
// most, not once a round.
#[test]
fn connecting_and_going_does_not_fill_the_log() {
    let rig = Rig::stopped(policy('A', ""));
    let channel = Scripted::default();
    let service = start(&rig, &channel, Timeouts::default());
    let owner = Peer::sending(&[HELLO, CLAIM]);
    channel.connect(&owner);
    until("the claim", || owner.lines() == 3);
    let disconnected = || owner.heard("disconnected");
    for round in 0..ubc_vpn_service::LOG_CAPACITY + 20 {
        let before = disconnected();
        let peer = Peer::sending(&[HELLO]);
        channel.connect(&peer);
        until("the hello and the state", || peer.lines() == 2);
        peer.state().gone_for_answers = true;
        let connect = encode(&Request {
            id: 2,
            body: good(),
        })
        .unwrap();
        peer.send(connect.trim_end());
        until(&format!("round {round} undone"), || disconnected() > before);
    }
    assert!(rig.spy.opens().is_empty(), "the gateway was contacted");
    let lines = service.logs();
    assert!(lines[0].starts_with("service started"), "{lines:#?}");
    assert!(lines[1].starts_with("policy read"), "{lines:#?}");
    let said = |what: &str| lines.iter().filter(|line| *line == what).count();
    assert_eq!(said(ubc_vpn_service::ABANDONED), 1, "{lines:#?}");
    assert!(said("disconnected") <= 1, "{lines:#?}");
}

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

// The same for a state change: clients stuck on one state delay neither the
// next state for a healthy client nor anybody's requests.
#[test]
fn a_state_change_is_not_held_up_by_clients_that_stop_reading() {
    let rig = Rig::stopped(policy('A', ""));
    let channel = Scripted::default();
    let timeouts = Timeouts {
        write: Duration::from_secs(120),
        ..Timeouts::default()
    };
    let _service = start(&rig, &channel, timeouts);
    let owner = Peer::sending(&[HELLO, CLAIM]);
    channel.connect(&owner);
    until("the claim", || owner.lines() == 3);

    // Each takes the hello's answer and its first state, and no more.
    let stuck = [(); 3].map(|()| Peer::sending(&[HELLO]));
    for peer in &stuck {
        peer.state().takes = Some(2);
        channel.connect(peer);
        until("its first state", || peer.lines() == 2);
    }
    let healthy = Peer::sending(&[HELLO]);
    channel.connect(&healthy);
    until("its first state", || healthy.lines() == 2);

    let subnets = r#"{"subnets":["10.255.0.0/24","192.0.2.0/24"]}"#;
    let params =
        format!(r#"{{"cookie":"{COOKIE}","gateway_addr":"192.0.2.1","routes":{subnets}}}"#);
    owner.send(&format!(
        r#"{{"id":3,"body":{{"method":"connect","params":{params}}}}}"#
    ));
    for peer in &stuck {
        until("a state nobody takes", || peer.state().holding_a_write);
    }
    until("connected, for the healthy client", || {
        healthy.heard("connected") == 1
    });

    // Requests are served meanwhile, and the next change arrives too.
    healthy.send(STATUS);
    until("the status", || {
        healthy.state().received.contains(r#""kind":"status""#)
    });
    owner.send(r#"{"id":4,"body":{"method":"disconnect"}}"#);
    until("disconnected again", || healthy.heard("disconnected") == 2);
    assert!(stuck.iter().all(|peer| peer.lines() == 2), "still stuck");
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

// A service manager's stop request ends serving without an error, and shuts
// the service down as dropping it does, the tunnel included.
#[test]
fn a_stop_request_ends_serving_and_cleans_up() {
    let mut rig = harness::rig();
    let mut alice = rig.owner();
    let state = alice.connect_ends(good());
    assert!(matches!(state, ConnState::Connected { .. }), "{state:?}");
    assert!(!rig.is_clean());
    let service = rig.service.take().unwrap();
    let (stop, requests) = std::sync::mpsc::channel();
    let (done, ended) = std::sync::mpsc::channel();
    std::thread::spawn(move || done.send(service.serve_until(requests)));
    stop.send(()).unwrap();
    let ended = ended.recv_timeout(WAIT).expect("serving never ended");
    assert_eq!(ended, Ok(()));
    assert!(rig.is_clean());
}

// Accepting that ends by itself is still an error while serving until a stop
// request, and a stop channel whose sender is gone asks for nothing.
#[test]
fn accepting_that_ends_before_a_stop_request_is_an_error() {
    let rig = Rig::stopped(policy('A', ""));
    let closing = Scripted::default();
    closing.close();
    let service = start(&rig, &closing, Timeouts::default());
    let (stop, requests) = std::sync::mpsc::channel::<()>();
    drop(stop);
    let (done, ended) = std::sync::mpsc::channel();
    std::thread::spawn(move || done.send(service.serve_until(requests)));
    let ended = ended.recv_timeout(WAIT).expect("serving never ended");
    assert!(
        ended
            .as_ref()
            .is_err_and(|why| why.contains("stopped accepting")),
        "{ended:?}"
    );
}
