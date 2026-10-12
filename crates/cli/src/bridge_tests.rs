//! The bridge, against the real service running on the fakes. Tests marked
//! "Security rule" must fail if the rule they name is removed.

use std::collections::VecDeque;
use std::io::BufReader;
use std::sync::Mutex;
use std::sync::mpsc::Receiver;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use ubc_vpn_core::protocol::{Event, Hello, HelloReply, PROTOCOL_VERSION, ResponseBody};
use ubc_vpn_core::state::ConnState;
use ubc_vpn_platform::Transport;
use ubc_vpn_platform::fake::{Op, paths};

use super::*;
use crate::client::Limits;
use crate::tests::Rig;

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
        let status = self.exit.join().unwrap();
        let out = self.out.text();
        let lines = out.lines().map(|line| decode(line).unwrap()).collect();
        (status, lines, out + &self.err.text())
    }
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
    let (to, arrivals) = mpsc::channel();
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
