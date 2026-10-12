//! What the platform fake cannot show: the limit the service puts on its
//! writes, and what happens when accepting ends by itself. A transport made
//! for these tests stands in for the fake's.

mod harness;

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use harness::*;
use ubc_vpn_platform::{Listener, Platform, RawConnection, Result, Transport};
use ubc_vpn_service::{Service, Timeouts};

/// A channel that hands the service the connections a test queued. When they
/// run out it waits to be closed, or panics if the test asked for that.
#[derive(Clone, Default)]
struct Scripted(Arc<Script>);

#[derive(Default)]
struct Script {
    waiting: Mutex<VecDeque<Connection>>,
    then_panic: bool,
    closed: Mutex<bool>,
    closing: Condvar,
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
        if let Some(conn) = self.0.waiting.lock().unwrap().pop_front() {
            return Ok((conn, user("mallory")));
        }
        assert!(!self.0.then_panic, "the test ends accepting here");
        let closed = self.0.closed.lock().unwrap();
        drop(self.0.closing.wait_while(closed, |closed| !*closed));
        Err(Error::Closed)
    }

    fn restrict_to(&self, _owner: &UserId) -> Result<()> {
        Ok(())
    }

    fn close(&self) {
        *self.0.closed.lock().unwrap() = true;
        self.0.closing.notify_all();
    }
}

/// A connection whose peer has hung up, which keeps the write limits it was
/// given.
#[derive(Clone, Default)]
struct Recording(Arc<Mutex<Vec<Option<Duration>>>>);

impl RawConnection for Recording {
    fn read(&self, _buf: &mut [u8]) -> Result<usize> {
        Ok(0)
    }

    fn write_all(&self, _bytes: &[u8]) -> Result<()> {
        Ok(())
    }

    fn set_read_timeout(&self, _timeout: Option<Duration>) -> Result<()> {
        Ok(())
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        self.0.lock().unwrap().push(timeout);
        Ok(())
    }

    fn close(&self) {}
}

fn start(rig: &Rig, script: Script, timeouts: Timeouts) -> Service {
    let platform = Platform {
        transport: Arc::new(Scripted(Arc::new(script))),
        ..rig.fake.platform(&rig.root)
    };
    Service::start(platform, timeouts).unwrap()
}

// Security rule: every write to a client has a time limit, so one that
// stops reading is closed and cannot hold a thread, or whoever writes next.
#[test]
fn every_connection_is_given_the_write_limit() {
    let rig = Rig::stopped(policy('A', ""));
    let recording = Recording::default();
    let conn = Connection::new(Box::new(recording.clone()));
    let channel = Script {
        waiting: Mutex::new(VecDeque::from([conn])),
        ..Script::default()
    };
    let write = Duration::from_secs(7);
    let timeouts = Timeouts {
        write,
        ..Timeouts::default()
    };
    let _service = start(&rig, channel, timeouts);
    // The service answers the hello that never came; that is a write.
    let started = Instant::now();
    while recording.0.lock().unwrap().is_empty() {
        assert!(started.elapsed() < WAIT, "nothing was written");
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(*recording.0.lock().unwrap(), [Some(write)]);
}

// A service that has stopped accepting must not look healthy: waiting on it
// reports the failure, and the program exits with an error.
#[test]
fn accepting_that_ends_by_itself_is_an_error() {
    let rig = Rig::stopped(policy('A', ""));
    let channel = Script {
        then_panic: true,
        ..Script::default()
    };
    let service = start(&rig, channel, Timeouts::default());
    let ended = service.wait().unwrap_err();
    assert!(ended.contains("stopped accepting"), "{ended}");

    // Closed on purpose, it is no error.
    let service = start(&rig, Script::default(), Timeouts::default());
    drop(service);
}
