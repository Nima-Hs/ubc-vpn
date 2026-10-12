//! What a request to stop does at each point of a connect. The requests
//! here are values put on the channel the platform would put them on; the
//! real ones are sent to real programs in the system test.

use std::sync::Mutex;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

use ubc_vpn_engine::fake::{FakeEngine, Script};
use ubc_vpn_platform::Error;
use ubc_vpn_platform::interrupt::Stop;

use crate::connect::{Ended, undo};
use crate::connect_tests::{CODE, PASSWORD, Scene, Typist, brief, pin};
use crate::interrupt::{Progress, serve};
use crate::terminal::Terminal;

/// What the handler of requests did, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Did {
    Undo,
    Exit(Stop),
}

/// A handler of requests on a thread of its own, whose `undo` waits to be
/// let go and whose `exit` only notes that it was called.
struct Handler {
    requests: Sender<Stop>,
    did: Receiver<Did>,
    let_undo_end: Sender<()>,
}

fn handler(progress: &Progress) -> Handler {
    let (requests, incoming) = channel();
    let (done, did) = channel();
    let (let_undo_end, may_end) = channel::<()>();
    let (undone, exited) = (done.clone(), Mutex::new(done));
    let progress = progress.clone();
    std::thread::spawn(move || {
        let undo = move || {
            undone.send(Did::Undo).unwrap();
            // Until the test lets go, or has gone.
            let _ = may_end.recv();
        };
        let exit = move |stop| exited.lock().unwrap().send(Did::Exit(stop)).unwrap();
        serve(incoming, &progress, undo, exit);
    });
    Handler {
        requests,
        did,
        let_undo_end,
    }
}

impl Handler {
    fn next(&self) -> Did {
        let patience = Duration::from_secs(5);
        self.did.recv_timeout(patience).expect("the handler acted")
    }

    fn nothing_more(&self) {
        let quiet = self.did.recv_timeout(Duration::from_millis(200));
        assert!(quiet.is_err(), "{quiet:?}");
    }
}

// Before the connect request has gone there is nothing to undo: the program
// ends at once, and the service is told nothing.
#[test]
fn a_stop_before_the_request_ends_the_program_at_once() {
    for stop in [Stop::Interrupt, Stop::Terminate] {
        let progress = Progress::default();
        let handler = handler(&progress);
        assert!(!progress.stopping());
        handler.requests.send(stop).unwrap();
        assert_eq!(handler.next(), Did::Exit(stop));
        assert!(progress.stopping());
        // A second request is answered the same way, still with no undo.
        handler.requests.send(Stop::Interrupt).unwrap();
        assert_eq!(handler.next(), Did::Exit(Stop::Interrupt));
        handler.nothing_more();
    }
}

// After the request has gone the service is told to disconnect first, and
// the program ends only then, with the status for what was asked.
#[test]
fn a_stop_after_the_request_undoes_it_first() {
    let progress = Progress::default();
    let handler = handler(&progress);
    progress.sending();
    handler.requests.send(Stop::Terminate).unwrap();
    assert_eq!(handler.next(), Did::Undo);
    assert!(progress.stopping());
    handler.nothing_more();
    handler.let_undo_end.send(()).unwrap();
    assert_eq!(handler.next(), Did::Exit(Stop::Terminate));
}

// A second request means "now": the program ends without waiting for the
// disconnect to be taken.
#[test]
fn a_second_stop_does_not_wait_for_the_undo() {
    let progress = Progress::default();
    let handler = handler(&progress);
    progress.sending();
    handler.requests.send(Stop::Interrupt).unwrap();
    assert_eq!(handler.next(), Did::Undo);
    handler.requests.send(Stop::Interrupt).unwrap();
    assert_eq!(handler.next(), Did::Exit(Stop::Interrupt));
    handler.nothing_more();
}

// Security rule: Ctrl-C at a hidden question ends the connect there. It is
// not a cancelled login to report, nothing is printed, and nothing has gone
// to the service.
#[test]
fn ctrl_c_at_a_hidden_question_ends_the_connect_in_silence() {
    let scene = Scene::usual();
    let interrupted = Box::new(|_: &str| Err(Error::Interrupted));
    let shown = Box::new(|_: &str| panic!("the username is saved"));
    let mut terminal = Terminal::with(true, shown, interrupted);
    let progress = Progress::default();
    let (ended, out, err) = scene.connect_watched(&mut terminal, &progress);
    assert_eq!(
        (ended, out.as_str(), err.as_str()),
        (Ended::Interrupted, "", "")
    );
    // Nothing went to the service, so a stop would have nothing to undo.
    assert!(!progress.stop());
    assert!(scene.state().contains(r#""state":"disconnected""#));
}

// The connect says when its request goes to the service, and not before:
// a login that fails never gets there.
#[test]
fn the_connect_reports_when_its_request_goes() {
    let scene = Scene::usual();
    let progress = Progress::default();
    let mut typist = Typist::typing(&[Some("wrong-password-0000"), Some(CODE)]);
    let (ended, _, _) = scene.connect_watched(&mut typist, &progress);
    assert!(matches!(ended, Ended::Status(8)), "{ended:?}");
    assert!(!progress.stop(), "nothing was sent, so nothing is undone");

    let scene = Scene::usual();
    let progress = Progress::default();
    let mut typist = Typist::typing(&[Some(PASSWORD), Some(CODE)]);
    let (ended, _, _) = scene.connect_watched(&mut typist, &progress);
    assert_eq!(ended, Ended::Status(0));
    assert!(progress.stop(), "the request went, so there is one to undo");
}

// A stop while the service is connecting: the service is told to disconnect
// and does, and the connect that was waiting says nothing about it.
#[test]
fn a_stop_while_connecting_disconnects_and_says_nothing() {
    let mut scene = Scene::usual();
    // The service's own gateway is slow to open the tunnel.
    let slow = FakeEngine::new(Script::new(pin()));
    slow.hold();
    scene.service = None;
    scene.service = Some(scene.rig.service_on(slow.clone()));
    let progress = Progress::default();
    let (fake, root) = (scene.rig.fake.clone(), scene.rig.root.clone());
    let (stopping, let_go) = (progress.clone(), slow.clone());
    let stopper = std::thread::spawn(move || {
        // Once the service has the request and is waiting on its gateway.
        let_go.wait_until_blocked();
        assert!(stopping.stop(), "the request has gone");
        undo(&|| Ok(fake.platform(&root)), brief());
    });
    // Whatever happens, the service is not left waiting for ever.
    let last_resort = slow.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(8));
        last_resort.release();
    });
    let mut typist = Typist::typing(&[Some(PASSWORD), Some(CODE)]);
    let (ended, out, err) = scene.connect_watched(&mut typist, &progress);
    stopper.join().unwrap();
    assert_eq!(
        (ended, out.as_str(), err.as_str()),
        (Ended::Stopping, "", "")
    );
    let patience = Instant::now() + Duration::from_secs(5);
    while !scene.state().contains(r#""state":"disconnected""#) {
        assert!(Instant::now() < patience, "{}", scene.state());
        std::thread::sleep(Duration::from_millis(10));
    }
}
