//! The bridge, against the real service running on the fakes. Tests marked
//! "Security rule" must fail if the rule they name is removed.

use std::collections::VecDeque;
use std::io::BufReader;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use ubc_vpn_core::protocol::{Event, Hello, HelloReply, PROTOCOL_VERSION, ResponseBody};
use ubc_vpn_core::state::ConnState;
use ubc_vpn_platform::fake::{Op, paths};
use ubc_vpn_platform::{Listener, RawConnection, Transport};

use super::*;
use crate::client::Limits;
use crate::tests::Rig;
use ubc_vpn_engine::fake::{FakeEngine, Script};

const COOKIE: &str = "Zq7-made-up-0123456789";

/// Standard input the test writes to. Dropping the sender closes it.
struct Feed(Receiver<Vec<u8>>, VecDeque<u8>);

impl Read for Feed {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.1.is_empty() {
            self.1.extend(self.0.recv().unwrap_or_default());
        }
        let n = buf.len().min(self.1.len());
        let taken = self.1.drain(..n);
        buf.iter_mut()
            .zip(taken)
            .for_each(|(slot, byte)| *slot = byte);
        Ok(n)
    }
}

/// Standard output or standard error, readable while it is written.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Captured {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

/// A bridge running on a thread, as the fake's own user.
struct Bridge {
    app: Option<Sender<Vec<u8>>>,
    out: Captured,
    err: Captured,
    exit: JoinHandle<u8>,
}

fn start(rig: &Rig) -> Bridge {
    start_with(rig, Limits::default())
}

fn start_with(rig: &Rig, limits: Limits) -> Bridge {
    let (app, lines) = mpsc::channel();
    let (out, err) = (Captured::default(), Captured::default());
    let (fake, root) = (rig.fake.clone(), rig.root.clone());
    let (mut stdout, mut stderr) = (out.clone(), err.clone());
    let exit = thread::spawn(move || {
        let platform = || Ok(fake.platform(&root));
        let input = BufReader::new(Feed(lines, VecDeque::new()));
        run(&platform, input, limits, &mut stdout, &mut stderr)
    });
    let app = Some(app);
    Bridge {
        app,
        out,
        err,
        exit,
    }
}

impl Bridge {
    fn say(&self, line: &str) {
        let bytes = format!("{line}\n").into_bytes();
        // The bridge may have stopped reading already.
        let _ = self.app.as_ref().unwrap().send(bytes);
    }

    /// Waits until `count` lines were written and returns them all.
    fn lines(&self, count: usize) -> Vec<BridgeLine> {
        let started = Instant::now();
        loop {
            let text = self.out.text();
            if text.lines().count() >= count && (text.is_empty() || text.ends_with('\n')) {
                return text.lines().map(|line| decode(line).unwrap()).collect();
            }
            let waited = started.elapsed();
            assert!(waited < Duration::from_secs(10), "got only: {text}");
            thread::sleep(Duration::from_millis(5));
        }
    }

    /// Waits for the bridge to end. Returns its exit status, every line it
    /// wrote, and everything it wrote anywhere.
    fn end(self) -> (u8, Vec<BridgeLine>, String) {
        let status = finish(self.exit, &self.out);
        let out = self.out.text();
        let lines = out.lines().map(|line| decode(line).unwrap()).collect();
        (status, lines, out + &self.err.text())
    }
}

/// Waits for a bridge to end, but not for ever: one that does not end fails
/// the test and does not hang it.
fn finish(exit: JoinHandle<u8>, out: &Captured) -> u8 {
    let started = Instant::now();
    while !exit.is_finished() {
        let waited = started.elapsed();
        let wrote = out.text();
        assert!(
            waited < Duration::from_secs(10),
            "no end; it wrote: {wrote}"
        );
        thread::sleep(Duration::from_millis(5));
    }
    exit.join().unwrap()
}

/// Whether a line is the response to request `id` with this outcome.
fn is_response(line: &BridgeLine, id: u32, outcome: Result<ResponseBody, ErrorCode>) -> bool {
    let BridgeLine::Server {
        message: ServerMessage::Response(response),
    } = line
    else {
        return false;
    };
    let got = match &response.outcome {
        Outcome::Ok(body) => Ok(body.clone()),
        Outcome::Error(error) => Err(error.code),
    };
    response.id == id && got == outcome
}

/// Something listening where the service should be. It answers the hello
/// with `reply` and returns whatever the bridge sends after that, if anything.
fn answering(rig: &Rig, reply: String) -> JoinHandle<Option<String>> {
    let listener = rig.fake.listen(&paths(&rig.root).channel_name).unwrap();
    thread::spawn(move || {
        let (conn, _) = listener.accept().unwrap();
        let wait = Some(Duration::from_secs(10));
        conn.set_read_timeout(wait).unwrap();
        conn.read_line().unwrap();
        conn.write_line(&reply).unwrap();
        conn.read_line().ok().flatten()
    })
}

#[test]
fn carries_requests_and_messages_and_sends_none_of_its_own() {
    let rig = Rig::new();
    let _service = rig.service();
    let mut bridge = start(&rig);
    let ready = BridgeLine::Ready {
        service_version: ubc_vpn_core::VERSION.to_string(),
        owner_claimed: false,
    };
    assert_eq!(bridge.lines(1), [ready]);

    // The bridge claimed nothing: the app's first request is refused.
    bridge.say(r#"{"id":7,"body":{"method":"status"}}"#);
    let refused = Err(ErrorCode::NotClaimed);
    assert!(is_response(&bridge.lines(2)[1], 7, refused));
    // The app claims. The id comes back as sent, and the event follows.
    bridge.say(r#"{"id":4000000000,"body":{"method":"claim"}}"#);
    let lines = bridge.lines(4);
    let claimed = |line| is_response(line, 4_000_000_000, Ok(ResponseBody::Claimed));
    assert!(lines[2..].iter().any(claimed), "{lines:?}");
    let message = ServerMessage::Event(Event::StateChanged(ConnState::Disconnected));
    let event = BridgeLine::Server { message };
    assert!(lines[2..].contains(&event), "{lines:?}");

    // The app quits: the bridge ends quietly and reports success.
    bridge.app = None;
    let (status, lines, _) = bridge.end();
    assert_eq!((status, lines.len()), (0, 4));
}

// Security rule: the app never gets a session cookie to the service. A
// connect is answered by the bridge and nothing is sent on.
#[test]
fn a_connect_is_refused_here_and_never_reaches_the_service() {
    let rig = Rig::new();
    let _service = rig.service();
    let mut bridge = start(&rig);
    bridge.say(r#"{"id":1,"body":{"method":"claim"}}"#);
    bridge.lines(3);
    // A request the service would accept.
    let routes = r#"{"subnets":["10.255.0.0/24"]}"#;
    let params = format!(r#"{{"cookie":"{COOKIE}","gateway_addr":"192.0.2.1","routes":{routes}}}"#);
    let connect = format!(r#"{{"id":2,"body":{{"method":"connect","params":{params}}}}}"#);
    bridge.say(&connect);
    let refused = Err(ErrorCode::BadRequest);
    assert!(is_response(&bridge.lines(4)[3], 2, refused));
    bridge.say(r#"{"id":3,"body":{"method":"status"}}"#);
    let untouched = Ok(ResponseBody::Status(ConnState::Disconnected));
    let lines = bridge.lines(5);
    assert!(is_response(&lines[4], 3, untouched), "{lines:?}");
    bridge.app = None;
    let (status, lines, everything) = bridge.end();
    assert_eq!((status, lines.len()), (0, 5), "the service heard nothing");
    assert!(!everything.contains(COOKIE));
}

// A line that is not a request is a bug in the app. The bridge says so and
// stops, and never repeats the line: it could hold anything.
#[test]
fn a_bad_line_ends_the_bridge_and_is_never_echoed() {
    let pad = "x".repeat(MAX_LINE_BYTES);
    let long = format!(r#"{{"id":1,"body":{{"method":"status"}},"pad":"{pad}"}}"#);
    let unknown = r#"{"id":1,"body":{"method":"status"},"hunter2-made-up":1}"#;
    for bad in ["hunter2-made-up", unknown, &long, "\u{0}"] {
        let rig = Rig::new();
        let _service = rig.service();
        let bridge = start(&rig);
        bridge.say(bad);
        // A later, valid line is not acted on.
        bridge.say(r#"{"id":2,"body":{"method":"claim"}}"#);
        let (status, lines, everything) = bridge.end();
        let shown = &bad[..bad.len().min(40)];
        assert_eq!(status, 1, "{shown}");
        assert_eq!(lines[1..], [BridgeLine::BadLine], "{shown}");
        assert!(!everything.contains("hunter2") && !everything.contains("xxxx"));
    }
}

#[test]
fn each_way_of_having_no_channel_has_its_one_line() {
    let ends = |rig: &Rig| {
        let (status, lines, _) = start(rig).end();
        assert_eq!(status, 1);
        lines
    };
    let rig = Rig::new();
    assert_eq!(ends(&rig), [BridgeLine::ServiceUnavailable]);

    let service = rig.service();
    rig.claim_as_someone_else();
    assert_eq!(ends(&rig), [BridgeLine::NotOwner]);
    drop(service);

    // Something that is not the service holds the channel. The app is told,
    // and the impostor is sent nothing: not even a hello.
    let name = paths(&rig.root).channel_name;
    let listener = rig.fake.listen(&name).unwrap();
    let impostor = thread::spawn(move || {
        let (first, _) = listener.accept().unwrap();
        first.read_line().ok().flatten()
    });
    let untrusted = Some(Error::NotTheService);
    rig.fake.set_failure(Op::Connect, untrusted);
    assert_eq!(ends(&rig), [BridgeLine::UntrustedService]);
    rig.fake.set_failure(Op::Connect, None);
    // The first the impostor ever hears is this test connecting and
    // hanging up: the bridge never reached it.
    drop(rig.fake.connect(&name).unwrap());
    assert_eq!(impostor.join().unwrap(), None);

    let reply = HelloReply {
        protocol_version: PROTOCOL_VERSION + 1,
        service_version: "9.9.9".to_string(),
        owner_claimed: true,
    };
    let newer = answering(&rig, encode(&reply).unwrap().trim_end().to_string());
    let service_version = "9.9.9".to_string();
    assert_eq!(ends(&rig), [BridgeLine::UpdateNeeded { service_version }]);
    assert_eq!(newer.join().unwrap(), None, "nothing follows the hello");

    // A reply that cannot be read counts as no service.
    let odd = answering(&rig, "not a reply".to_string());
    assert_eq!(ends(&rig), [BridgeLine::ServiceUnavailable]);
    assert_eq!(odd.join().unwrap(), None, "nothing follows the hello");
}

#[test]
fn a_service_that_goes_away_is_reported_and_ends_the_bridge() {
    let rig = Rig::new();
    let service = rig.service();
    let bridge = start(&rig);
    bridge.lines(1);
    drop(service);
    let (status, lines, _) = bridge.end();
    assert_eq!(status, 1);
    assert_eq!(lines[1..], [BridgeLine::ServiceUnavailable]);
}

// Security rule: an endless line cannot fill memory. Reading stops just
// past the limit, and what was read is dropped.
#[test]
fn no_more_than_the_limit_is_read_for_one_line() {
    struct Endless(usize);
    impl Read for Endless {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = buf.len().min(10 * MAX_LINE_BYTES - self.0);
            buf[..n].fill(b'x');
            self.0 += n;
            Ok(n)
        }
    }
    let mut input = BufReader::new(Endless(0));
    let (to, arrivals) = mpsc::sync_channel(WAITING);
    read_app(&mut input, &to);
    assert!(matches!(arrivals.try_recv(), Ok(Arrival::App(Err(())))));
    assert!(
        arrivals.try_recv().is_err(),
        "reading stopped at the bad line"
    );
    let taken = input.get_ref().0;
    assert!(taken <= 2 * MAX_LINE_BYTES, "{taken} bytes were read");
}

// The bridge lives as long as the app. With nothing asked it waits without
// limit, but a request it has sent on must be answered in time: a service
// that takes requests and does not answer is reported, and the bridge ends.
#[test]
fn a_forwarded_request_must_be_answered_in_time() {
    let brief = Limits {
        answer: Duration::from_millis(600),
        ..Limits::default()
    };
    // Idle for longer than the limit, the bridge is still there and works.
    let rig = Rig::new();
    let _service = rig.service();
    let mut bridge = start_with(&rig, brief);
    bridge.lines(1);
    thread::sleep(2 * brief.answer);
    bridge.say(r#"{"id":1,"body":{"method":"status"}}"#);
    let refused = Err(ErrorCode::NotClaimed);
    assert!(is_response(&bridge.lines(2)[1], 1, refused));
    // An answered request leaves nothing to wait for.
    thread::sleep(2 * brief.answer);
    bridge.app = None;
    let (status, lines, _) = bridge.end();
    assert_eq!((status, lines.len()), (0, 2));

    // A service that answers the hello and nothing after it.
    let rig = Rig::new();
    let reply = HelloReply {
        protocol_version: PROTOCOL_VERSION,
        service_version: "0.1.0".to_string(),
        owner_claimed: true,
    };
    let listener = rig.fake.listen(&paths(&rig.root).channel_name).unwrap();
    let stuck = thread::spawn(move || {
        let (conn, _) = listener.accept().unwrap();
        // Not for ever, so that a bridge with no deadline fails this test.
        let patience = Some(Duration::from_secs(8));
        conn.set_read_timeout(patience).unwrap();
        conn.read_line().unwrap();
        conn.write_line(encode(&reply).unwrap().trim_end()).unwrap();
        // It takes the request, and then only waits for the bridge to go.
        let asked = conn.read_line().ok().flatten();
        drop(conn.read_line());
        asked
    });
    let bridge = start_with(&rig, brief);
    bridge.lines(1);
    let started = Instant::now();
    bridge.say(r#"{"id":1,"body":{"method":"status"}}"#);
    let (status, lines, everything) = bridge.end();
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "it waited too long"
    );
    assert_eq!(status, 1);
    assert_eq!(lines[1..], [BridgeLine::ServiceUnavailable]);
    assert!(everything.contains("did not answer a request in time"));
    assert!(stuck.join().unwrap().is_some(), "the request was sent on");
}

// The bridge runs for as long as the app. Every event is passed on as it
// arrives and none is kept, so no number of events between or during
// requests can make a later request fail.
#[test]
fn any_number_of_events_is_passed_on_and_none_is_kept() {
    const REQUESTS: usize = 5;
    const EVENTS_EACH: usize = 40;
    assert!(REQUESTS * EVENTS_EACH > 2 * Limits::default().kept_events);

    let rig = Rig::new();
    let listener = rig.fake.listen(&paths(&rig.root).channel_name).unwrap();
    let service = thread::spawn(move || {
        let (conn, _) = listener.accept().unwrap();
        let send = |line: String| conn.write_line(line.trim_end()).unwrap();
        // The bridge speaks for the app, and says so.
        let hello: Hello = decode(&conn.read_line().unwrap().unwrap()).unwrap();
        assert_eq!(hello.client, ClientKind::App);
        assert_eq!(hello.protocol_version, PROTOCOL_VERSION);
        send(
            encode(&HelloReply {
                protocol_version: PROTOCOL_VERSION,
                service_version: "0.1.0".to_string(),
                owner_claimed: true,
            })
            .unwrap(),
        );
        // Before each answer, more events than a client may keep.
        while let Ok(Some(line)) = conn.read_line() {
            let asked: Request = decode(&line).unwrap();
            let event = ServerMessage::Event(Event::StateChanged(ConnState::Connecting));
            (0..EVENTS_EACH).for_each(|_| send(encode(&event).unwrap()));
            let outcome = Outcome::Ok(ResponseBody::Status(ConnState::Connecting));
            let id = asked.id;
            send(encode(&ServerMessage::Response(Response { id, outcome })).unwrap());
        }
    });
    let mut bridge = start(&rig);
    for n in 1..=REQUESTS {
        bridge.say(&format!(r#"{{"id":{n},"body":{{"method":"status"}}}}"#));
        let lines = bridge.lines(1 + n * (EVENTS_EACH + 1));
        let answer = Ok(ResponseBody::Status(ConnState::Connecting));
        assert!(
            is_response(lines.last().unwrap(), n as u32, answer),
            "request {n}"
        );
    }
    bridge.app = None;
    let (status, lines, _) = bridge.end();
    service.join().unwrap();
    assert_eq!(status, 0);
    assert_eq!(
        lines.len(),
        1 + REQUESTS * (EVENTS_EACH + 1),
        "every line, once"
    );
}

const STATE_EVENT: ServerMessage = ServerMessage::Event(Event::StateChanged(ConnState::Connecting));

fn greeting() -> String {
    let reply = HelloReply {
        protocol_version: PROTOCOL_VERSION,
        service_version: "0.1.0".to_string(),
        owner_claimed: true,
    };
    encode(&reply).unwrap().trim_end().to_string()
}

// Events are not answers. A service that takes a request and then only
// sends events is as stuck as a silent one, and the events do not put the
// deadline off.
#[test]
fn events_do_not_put_off_the_deadline_for_an_answer() {
    let brief = Limits {
        answer: Duration::from_millis(600),
        ..Limits::default()
    };
    let rig = Rig::new();
    let listener = rig.fake.listen(&paths(&rig.root).channel_name).unwrap();
    let chatty = thread::spawn(move || {
        let (conn, _) = listener.accept().unwrap();
        conn.read_line().unwrap();
        conn.write_line(&greeting()).unwrap();
        let asked = conn.read_line().ok().flatten();
        // An event every so often and never an answer, until the bridge
        // goes. Not for ever, so that a bridge that never goes fails.
        let event = encode(&STATE_EVENT).unwrap();
        let patience = Instant::now() + Duration::from_secs(8);
        while Instant::now() < patience && conn.write_line(event.trim_end()).is_ok() {
            thread::sleep(Duration::from_millis(50));
        }
        asked
    });
    let bridge = start_with(&rig, brief);
    bridge.lines(1);
    let started = Instant::now();
    bridge.say(r#"{"id":1,"body":{"method":"status"}}"#);
    let (status, lines, everything) = bridge.end();
    let waited = started.elapsed();
    assert!(waited < Duration::from_secs(4), "it waited {waited:?}");
    assert_eq!(status, 1);
    let (last, events) = lines[1..].split_last().unwrap();
    assert_eq!(*last, BridgeLine::ServiceUnavailable);
    let event = BridgeLine::Server {
        message: STATE_EVENT,
    };
    assert!(events.len() >= 2 && events.iter().all(|line| *line == event));
    assert!(everything.contains("did not answer a request in time"));
    assert!(chatty.join().unwrap().is_some(), "the request was sent on");
}

// A connect is answered by the bridge itself, so no answer to it is owed by
// the service. The bridge is still there long after.
#[test]
fn a_refused_connect_leaves_nothing_to_wait_for() {
    let brief = Limits {
        answer: Duration::from_millis(400),
        ..Limits::default()
    };
    let rig = Rig::new();
    let _service = rig.service();
    let mut bridge = start_with(&rig, brief);
    let routes = r#"{"subnets":["10.255.0.0/24"]}"#;
    let params = format!(r#"{{"cookie":"{COOKIE}","gateway_addr":"192.0.2.1","routes":{routes}}}"#);
    bridge.say(&format!(
        r#"{{"id":1,"body":{{"method":"connect","params":{params}}}}}"#
    ));
    assert!(is_response(
        &bridge.lines(2)[1],
        1,
        Err(ErrorCode::BadRequest)
    ));
    thread::sleep(3 * brief.answer);
    bridge.say(r#"{"id":2,"body":{"method":"status"}}"#);
    assert!(is_response(
        &bridge.lines(3)[2],
        2,
        Err(ErrorCode::NotClaimed)
    ));
    bridge.app = None;
    let (status, lines, _) = bridge.end();
    assert_eq!((status, lines.len()), (0, 3));
}

/// Standard output that breaks after a number of lines.
struct Breaking(usize);

impl Write for Breaking {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.0 == 0 {
            return Err(std::io::ErrorKind::BrokenPipe.into());
        }
        self.0 -= 1;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// The app can go without closing standard input first. The bridge then
// cannot write, and ends with status 1 at whichever line that happens,
// without a panic.
#[test]
fn an_output_that_breaks_ends_the_bridge() {
    for lines_taken in 0..4 {
        let rig = Rig::new();
        // The service gives a user who is not the owner only so long to
        // say something, and then closes, which also ends the bridge with
        // status 1. Here that is a minute: far longer than this test takes
        // on a busy machine, and longer than `finish` waits, so a bridge
        // that ends only then fails the test.
        let engine = FakeEngine::new(Script::new(
            format!("pin-sha256:{}=", "A".repeat(43))
                .try_into()
                .unwrap(),
        ));
        let patient = ubc_vpn_service::Timeouts {
            stranger: Duration::from_secs(60),
            ..ubc_vpn_service::Timeouts::default()
        };
        let platform = rig.fake.platform(&rig.root);
        let _service =
            ubc_vpn_service::Service::start(platform, Arc::new(engine), patient).unwrap();
        let (app, lines): (Sender<Vec<u8>>, _) = mpsc::channel();
        let (fake, root) = (rig.fake.clone(), rig.root.clone());
        let exit = thread::spawn(move || {
            let platform = || Ok(fake.platform(&root));
            let input = BufReader::new(Feed(lines, VecDeque::new()));
            let (mut out, mut err) = (Breaking(lines_taken), Captured::default());
            run(&platform, input, Limits::default(), &mut out, &mut err)
        });
        // A connect, which the bridge answers itself, and then two requests
        // the service answers: three lines the app may not take.
        let routes = r#"{"subnets":["10.255.0.0/24"]}"#;
        let params =
            format!(r#"{{"cookie":"{COOKIE}","gateway_addr":"192.0.2.1","routes":{routes}}}"#);
        let connect = format!(r#"{{"id":1,"body":{{"method":"connect","params":{params}}}}}"#);
        let status = |id: u32| format!(r#"{{"id":{id},"body":{{"method":"status"}}}}"#);
        for request in [connect, status(2), status(3)] {
            let _ = app.send(format!("{request}\n").into_bytes());
        }
        // At that line, and not later when the service tires of the app:
        // that would be after `finish` has failed the test. No other
        // limit on time, which a busy machine could pass.
        let status = finish(exit, &Captured::default());
        assert_eq!(status, 1, "after {lines_taken} lines");
        drop(app);
    }
}

/// Notes, in order, each time something is read or written.
#[derive(Clone, Default)]
struct Noted(Arc<Mutex<Vec<&'static str>>>);

impl Read for Noted {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().push("input read");
        Ok(0)
    }
}

impl Write for Noted {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().push("line written");
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// Standard input is not read before the app has been told the channel is
// ready, and not at all when there is no channel.
#[test]
fn nothing_is_read_from_the_app_before_it_is_told_ready() {
    let rig = Rig::new();
    let runs = |noted: &Noted| {
        let platform = || Ok(rig.fake.platform(&rig.root));
        let input = BufReader::new(noted.clone());
        let (mut out, mut err) = (noted.clone(), Captured::default());
        run(&platform, input, Limits::default(), &mut out, &mut err)
    };
    let noted = Noted::default();
    assert_eq!(runs(&noted), 1);
    assert_eq!(*noted.0.lock().unwrap(), ["line written"]);

    let _service = rig.service();
    let noted = Noted::default();
    assert_eq!(runs(&noted), 0);
    assert_eq!(*noted.0.lock().unwrap(), ["line written", "input read"]);
}

/// A service that greets and then sends events as fast as they are read,
/// counting them, until told to stop.
#[derive(Clone, Default)]
struct Flood {
    sent: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    pending: Arc<Mutex<VecDeque<u8>>>,
}

impl RawConnection for Flood {
    fn read(&self, buf: &mut [u8]) -> ubc_vpn_platform::Result<usize> {
        let mut pending = self.pending.lock().unwrap();
        if pending.is_empty() {
            if self.stop.load(Ordering::SeqCst) {
                return Ok(0);
            }
            let line = match self.sent.fetch_add(1, Ordering::SeqCst) {
                0 => greeting() + "\n",
                _ => encode(&STATE_EVENT).unwrap(),
            };
            pending.extend(line.bytes());
        }
        let n = buf.len().min(pending.len());
        let taken = pending.drain(..n);
        buf.iter_mut()
            .zip(taken)
            .for_each(|(slot, byte)| *slot = byte);
        Ok(n)
    }
    fn write_all(&self, _: &[u8]) -> ubc_vpn_platform::Result<()> {
        Ok(())
    }
    fn set_read_timeout(&self, _: Option<Duration>) -> ubc_vpn_platform::Result<()> {
        Ok(())
    }
    fn set_write_timeout(&self, _: Option<Duration>) -> ubc_vpn_platform::Result<()> {
        Ok(())
    }
    fn close(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

impl Transport for Flood {
    fn listen(&self, _: &str) -> ubc_vpn_platform::Result<Box<dyn Listener>> {
        Err(Error::Unsupported)
    }
    fn connect(&self, _: &str) -> ubc_vpn_platform::Result<Connection> {
        Ok(Connection::new(Box::new(self.clone())))
    }
}

/// Standard output that takes one line and then waits to be let go.
struct Stuck(Arc<(Mutex<bool>, Condvar)>, usize);

impl Write for Stuck {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.1 += 1;
        let (free, freed) = &*self.0;
        let mut free = free.lock().unwrap();
        while self.1 > 1 && !*free {
            // Not for ever, so that a test that forgot it cannot hang.
            let patience = Duration::from_secs(10);
            free = freed.wait_timeout(free, patience).unwrap().0;
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// Security rule: a service that talks faster than the app listens cannot
// fill memory. While the app takes no lines the bridge stops reading the
// service after a handful of messages.
#[test]
fn messages_are_not_read_faster_than_the_app_takes_them() {
    let rig = Rig::new();
    let flood = Flood::default();
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let (app, lines): (Sender<Vec<u8>>, _) = mpsc::channel();
    let (fake, root) = (rig.fake.clone(), rig.root.clone());
    let (service, held) = (flood.clone(), gate.clone());
    let exit = thread::spawn(move || {
        let platform = || {
            let mut platform = fake.platform(&root);
            platform.transport = Arc::new(service.clone());
            Ok(platform)
        };
        let input = BufReader::new(Feed(lines, VecDeque::new()));
        let (mut out, mut err) = (Stuck(held, 0), Captured::default());
        run(&platform, input, Limits::default(), &mut out, &mut err)
    });
    // Once it has started reading, time enough to read a great many
    // messages, were nothing in the way.
    let started = Instant::now();
    while flood.sent.load(Ordering::SeqCst) < 2 {
        assert!(started.elapsed() < Duration::from_secs(10), "it never read");
        thread::sleep(Duration::from_millis(5));
    }
    thread::sleep(Duration::from_millis(300));
    let read = flood.sent.load(Ordering::SeqCst);
    flood.stop.store(true, Ordering::SeqCst);
    *gate.0.lock().unwrap() = true;
    gate.1.notify_all();
    let status = finish(exit, &Captured::default());
    drop(app);
    assert!((2..100).contains(&read), "{read} messages were read");
    assert_eq!(status, 1, "the service went away");
}

// Security rule: no secret reaches the log the app shows. A made-up
// password, one-time code and cookie go through a login whose library
// writes each of them in a line that is printed, with no word to mark it
// and without registering it. The lines are handed to the service, and the
// app, watching and then reading the log through the bridge, finds the
// lines and none of the three.
#[test]
fn no_secret_reaches_the_app_through_the_log() {
    use crate::connect_tests::{CODE, PASSWORD, ROUTES, Scene, Typist, pin};
    use ubc_vpn_core::login::PromptKind;
    use ubc_vpn_core::redact::Secret;
    use ubc_vpn_engine::fake::{FakeEngine, Script};

    let mut scene = Scene::new(Some(&format!("{{{ROUTES}}}")), "");
    let mut script = Script::new(pin());
    let mut code = script.form[1].clone();
    (code.0.kind, code.1) = (PromptKind::Code, Secret::new(CODE));
    script.form.push(code);
    script.leaks = true;
    scene.gateway = FakeEngine::new(script);

    let bridge = start(&scene.rig);
    bridge.say(r#"{"id":1,"body":{"method":"claim"}}"#);
    bridge.say(r#"{"id":2,"body":{"method":"watch_logs","params":{"on":true}}}"#);
    let accepted = |line| is_response(line, 2, Ok(ResponseBody::Accepted));
    assert!(bridge.lines(4).iter().any(accepted));

    let mut typist = Typist::typing(&[Some("alice"), Some(PASSWORD), Some(CODE)]);
    let (status, _, err) = scene.connect(&mut typist);
    assert_eq!(status, 0, "{err}");
    bridge.say(r#"{"id":3,"body":{"method":"logs","params":{"after":null}}}"#);

    // Three answers and the cookie, each in a line of its own: four lines
    // as events, and the same four in the page.
    let login_lines = |text: &str| text.matches(r#""source":"login""#).count();
    let started = Instant::now();
    let seen = loop {
        let text = bridge.out.text();
        if login_lines(&text) >= 8 && text.contains(r#""id":3"#) {
            break text;
        }
        let waited = started.elapsed();
        assert!(waited < Duration::from_secs(10), "got only: {text}");
        thread::sleep(Duration::from_millis(5));
    };
    let lines = |text: &str| seen.matches(&format!(r#""text":"{text}""#)).count();
    assert_eq!(
        (lines("> [redacted]"), lines("< [redacted]")),
        (6, 2),
        "{seen}"
    );
    let shown = seen.clone() + &bridge.err.text();
    for secret in [PASSWORD, CODE, COOKIE] {
        assert!(!shown.contains(secret), "{secret} reached the app");
    }
}
