//! What a request to stop does at each point of a connect. The requests
//! here are values put on the channel the platform would put them on; the
//! real ones are sent to real programs in the system test.

use std::sync::Mutex;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

use ubc_vpn_core::login::PromptKind;
use ubc_vpn_core::policy::Policy;
use ubc_vpn_core::redact::Secret;
use ubc_vpn_engine::fake::{FakeEngine, Script};
use ubc_vpn_engine::{Cancel, LoginEngine, Prompt};
use ubc_vpn_platform::Error;
use ubc_vpn_platform::interrupt::Stop;

use crate::connect::{Ask, Ended, start, undo};
use crate::connect_tests::{CODE, PASSWORD, ROUTES, Scene, Typist, brief, pin};
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
        handler.requests.send(stop).unwrap();
        assert_eq!(handler.next(), Did::Exit(stop));
        assert!(!progress.sending(), "after a stop no request may go");
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
    assert!(!progress.finish(), "a stopped connect reports nothing");
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
    // And nothing more went to the gateway: the saved username was all it
    // had been given when the question was asked.
    let given = scene.gateway.answers();
    let kinds: Vec<PromptKind> = given.iter().map(|(kind, _)| *kind).collect();
    assert_eq!(kinds, [PromptKind::Username]);
}

/// Answers like a [`Typist`], and notes a request to stop as it gives its
/// last answer: the moment a real one could come between the login and the
/// connect request.
struct StoppedAtTheLastAnswer {
    typist: Typist,
    left: usize,
    progress: Progress,
}

impl Ask for StoppedAtTheLastAnswer {
    fn unusable(&self) -> Option<String> {
        None
    }

    fn ask(&mut self, prompt: &Prompt) -> Option<Secret> {
        self.left -= 1;
        if self.left == 0 {
            assert!(!self.progress.stop(), "nothing has gone yet");
        }
        self.typist.ask(prompt)
    }
}

// Security rule: a request to stop that came before the connect request
// went found nothing to undo, so the request must never go. Otherwise the
// program ends and the service connects with nobody watching.
#[test]
fn a_stop_noted_before_the_request_keeps_it_from_going() {
    let scene = Scene::usual();
    let progress = Progress::default();
    let mut asked = StoppedAtTheLastAnswer {
        typist: Typist::typing(&[Some(PASSWORD), Some(CODE)]),
        left: 2,
        progress: progress.clone(),
    };
    let (ended, out, err) = scene.connect_watched(&mut asked, &progress);
    assert_eq!(
        (ended, out.as_str(), err.as_str()),
        (Ended::Stopping, "", "")
    );
    // The stop is still noted: a late request did not wipe it.
    assert!(!progress.sending() && !progress.finish());
    // The login was made, and the service heard nothing of it.
    assert_eq!(scene.gateway.answers().len(), 3);
    std::thread::sleep(Duration::from_millis(300));
    assert!(scene.state().contains(r#""state":"disconnected""#));
}

// The request counts as sent from just before it leaves, not from when the
// service answers: a stop in between has a request to undo. Here the
// service refuses the request, and the mark is there all the same. A login
// that fails never gets that far.
#[test]
fn the_request_is_marked_as_sent_before_it_leaves() {
    let begins = |scene: &Scene, typed: &[Option<&'static str>]| {
        let platform = || Ok(scene.rig.fake.platform(&scene.rig.root));
        let engines = |_: &Policy| Ok(Box::new(scene.gateway.clone()) as Box<dyn LoginEngine>);
        let (progress, mut typist) = (Progress::default(), Typist::typing(typed));
        let sending = || progress.sending();
        let (cancel, limits, mut err) = (Cancel::new(), brief(), Vec::new());
        let accepted = start(
            &platform,
            &engines,
            &mut typist,
            &cancel,
            limits,
            &sending,
            &mut err,
        );
        (accepted.is_ok(), progress.stop())
    };
    // The policy the service read when it started does not allow routes
    // that the policy file now does.
    let narrow = r#","allowed_routes":["142.103.0.0/16"]"#;
    let settings = format!(r#"{{"username":"alice",{ROUTES}}}"#);
    let scene = Scene::new(Some(&settings), narrow);
    let open = format!(
        r#"{{"gateway":"vpn.example.test","pins":["{}"]}}"#,
        pin().as_str()
    );
    std::fs::write(scene.rig.root.join("policy/policy.json"), open).unwrap();
    let refused = begins(&scene, &[Some(PASSWORD), Some(CODE)]);
    assert_eq!(refused, (false, true), "refused, and marked as sent");

    let scene = Scene::usual();
    let failed = begins(&scene, &[Some("wrong-password-0000"), Some(CODE)]);
    assert_eq!(failed, (false, false), "nothing was sent");
}

// Once the connect has told the user how it ended, a stop undoes nothing:
// Ctrl-C in the last instant must not take down the VPN the user has just
// been told is connected.
#[test]
fn a_stop_after_the_outcome_is_reported_leaves_the_vpn_alone() {
    let scene = Scene::usual();
    let progress = Progress::default();
    let mut typist = Typist::typing(&[Some(PASSWORD), Some(CODE)]);
    let (ended, out, _) = scene.connect_watched(&mut typist, &progress);
    assert_eq!(ended, Ended::Status(0));
    assert!(out.starts_with("Connected"), "{out}");
    let handler = handler(&progress);
    handler.requests.send(Stop::Interrupt).unwrap();
    assert_eq!(handler.next(), Did::Exit(Stop::Interrupt));
    handler.nothing_more();
    assert!(scene.state().contains(r#""state":"connected""#));
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
