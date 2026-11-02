//! The channel client, against the real service running on the platform
//! fake and the engine fake, and against a pretend service.

use std::sync::Arc;

use ubc_vpn_core::protocol::Response;
use ubc_vpn_core::state::ConnState;
use ubc_vpn_platform::fake::paths;

use super::*;
use crate::test_support::{PATIENCE, Rig, greet, scripted, tell};

// Against the real service: a claim, a request the service answers, and a
// request it refuses.
#[test]
fn requests_are_answered_or_refused_with_the_services_reason() {
    let rig = Rig::new();
    let _service = rig.service();
    let name = paths(&rig.root).channel_name;
    let mut client = Client::connect(&rig.fake, &name, ClientKind::Cli).unwrap();
    client.claim_if_unowned().unwrap();
    let status = ResponseBody::Status(ConnState::Disconnected);
    assert_eq!(client.request(RequestBody::Status), Ok(status));
    let nothing = ubc_vpn_core::routes::RouteSet::default();
    let refused = client.request(RequestBody::Connect(
        ubc_vpn_core::protocol::ConnectParams {
            cookie: ubc_vpn_core::redact::Secret::new("made-up-cookie"),
            gateway_addr: [192, 0, 2, 1].into(),
            routes: nothing,
            tunnel: Default::default(),
        },
    ));
    let Err(ClientError::Refused(why)) = refused else {
        panic!("{refused:?}");
    };
    // This rig's service has no policy file.
    assert_eq!(why.code, ubc_vpn_core::protocol::ErrorCode::PolicyInvalid);
}

// A response is matched to its request by id, and events that arrive while
// a response is awaited are kept for whoever asks for them next. The service
// here is scripted: an event, an answer to some other request, then the
// answer, and then it hangs up.
#[test]
fn responses_are_matched_by_id_and_events_are_kept() {
    let rig = Rig::new();
    let listener = rig.fake.listen(&paths(&rig.root).channel_name).unwrap();
    let service = std::thread::spawn(move || {
        let (conn, _) = listener.accept().unwrap();
        let send = |line: String| conn.write_line(line.trim_end()).unwrap();
        conn.read_line().unwrap();
        send(
            encode(&HelloReply {
                protocol_version: PROTOCOL_VERSION,
                service_version: "0.1.0".to_string(),
                owner_claimed: true,
            })
            .unwrap(),
        );
        let asked: Request = decode(&conn.read_line().unwrap().unwrap()).unwrap();
        let answer = |id, body| {
            let outcome = Outcome::Ok(body);
            encode(&ServerMessage::Response(Response { id, outcome })).unwrap()
        };
        let event = Event::StateChanged(ConnState::Connecting);
        send(encode(&ServerMessage::Event(event)).unwrap());
        send(answer(asked.id + 100, ResponseBody::Claimed));
        send(answer(
            asked.id,
            ResponseBody::Status(ConnState::Connecting),
        ));
    });
    let name = paths(&rig.root).channel_name;
    let mut client = Client::connect(&rig.fake, &name, ClientKind::Cli).unwrap();
    // Already owned, so nothing is claimed and the one request is the status.
    client.claim_if_unowned().unwrap();
    let status = ResponseBody::Status(ConnState::Connecting);
    assert_eq!(client.request(RequestBody::Status), Ok(status));
    service.join().unwrap();
    let kept = Event::StateChanged(ConnState::Connecting);
    assert_eq!(client.next_event(None), Ok(kept));
    // Nothing more was queued, and the service has gone.
    assert!(matches!(client.next_event(None), Err(ClientError::Lost(_))));
}

/// Short enough for a test to wait out, long enough for a slow machine.
fn brief() -> Limits {
    Limits {
        answer: Duration::from_millis(600),
        ..Limits::default()
    }
}

/// Connects to the pretend service on `rig` with `limits`.
fn client(rig: &Rig, limits: Limits) -> Result<Client, ClientError> {
    let conn = rig.fake.connect(&paths(&rig.root).channel_name).unwrap();
    Client::over(conn, ClientKind::Cli, limits)
}

/// Whether `result` is the client giving up, and soon enough after `started`.
fn gave_up<T: std::fmt::Debug>(result: &Result<T, ClientError>, started: Instant) -> bool {
    let soon = started.elapsed() < Duration::from_secs(3);
    matches!(result, Err(ClientError::Lost(_))) && soon
}

// A service that stops answering does not hang the client: the hello reply
// and each answer have one deadline, whatever else arrives meanwhile.
#[test]
fn an_answer_has_one_deadline_whatever_else_arrives() {
    // Nothing after the connection is made.
    let rig = Rig::new();
    let silent = scripted(&rig, |conn| {
        // It takes the hello, says nothing, and waits for whatever is next.
        drop(conn.read_line());
        drop(conn.read_line());
    });
    let started = Instant::now();
    let refused = client(&rig, brief()).map(drop);
    assert!(gave_up(&refused, started), "{refused:?}");
    silent.join().unwrap();

    // The hello is answered, the request never.
    let rig = Rig::new();
    let silent = scripted(&rig, |conn| {
        greet(conn);
        while conn.read_line().is_ok_and(|line| line.is_some()) {}
    });
    let mut asking = client(&rig, brief()).unwrap();
    let started = Instant::now();
    let answer = asking.request(RequestBody::Status);
    assert!(gave_up(&answer, started), "{answer:?}");
    drop(asking);
    silent.join().unwrap();

    // The hello is answered, then events keep coming and the answer never
    // does. Each event arrives well inside the limit; the answer does not.
    let rig = Rig::new();
    let chatty = scripted(&rig, |conn| {
        greet(conn);
        let event = ServerMessage::Event(Event::StateChanged(ConnState::Connecting));
        let started = Instant::now();
        while started.elapsed() < PATIENCE && tell(conn, &event) {
            std::thread::sleep(Duration::from_millis(50));
        }
    });
    let mut asking = client(&rig, brief()).unwrap();
    let started = Instant::now();
    let answer = asking.request(RequestBody::Status);
    assert!(gave_up(&answer, started), "{answer:?}");
    drop(asking);
    chatty.join().unwrap();
}

// Events that arrive while an answer is awaited are kept, but not without
// end: a service that sends a flood of them and no answer is given up on.
#[test]
fn events_are_not_kept_without_end() {
    let rig = Rig::new();
    let flood = scripted(&rig, |conn| {
        greet(conn);
        let event = ServerMessage::Event(Event::StateChanged(ConnState::Connecting));
        let started = Instant::now();
        while started.elapsed() < PATIENCE && tell(conn, &event) {
            std::thread::yield_now();
        }
    });
    // The deadline is far away, so only the cap can end this.
    let limits = Limits {
        answer: Duration::from_secs(120),
        kept_events: 5,
        ..Limits::default()
    };
    let mut asking = client(&rig, limits).unwrap();
    let started = Instant::now();
    let answer = asking.request(RequestBody::Status);
    assert!(gave_up(&answer, started), "{answer:?}");
    // What was kept is still there for whoever wants it.
    let kept = (0..5).filter(|_| asking.next_event(None).is_ok()).count();
    assert_eq!(kept, 5);
    drop(asking);
    flood.join().unwrap();
}

// Every write to the service has a time limit too. The fake never makes a
// write wait, so this checks the limit that the connection is given.
#[test]
fn writes_to_the_service_have_a_limit() {
    use std::sync::Mutex;
    use ubc_vpn_platform::RawConnection;

    /// A connection whose peer has gone, which keeps its write limits.
    #[derive(Clone, Default)]
    struct Recording(Arc<Mutex<Vec<Option<Duration>>>>);

    impl RawConnection for Recording {
        fn read(&self, _buf: &mut [u8]) -> ubc_vpn_platform::Result<usize> {
            Ok(0)
        }
        fn write_all(&self, _bytes: &[u8]) -> ubc_vpn_platform::Result<()> {
            Ok(())
        }
        fn set_read_timeout(&self, _timeout: Option<Duration>) -> ubc_vpn_platform::Result<()> {
            Ok(())
        }
        fn set_write_timeout(&self, timeout: Option<Duration>) -> ubc_vpn_platform::Result<()> {
            self.0.lock().unwrap().push(timeout);
            Ok(())
        }
        fn close(&self) {}
    }

    let recording = Recording::default();
    let limits = Limits {
        write: Duration::from_secs(7),
        ..Limits::default()
    };
    let conn = Connection::new(Box::new(recording.clone()));
    assert!(Client::over(conn, ClientKind::Cli, limits).is_err());
    assert_eq!(*recording.0.lock().unwrap(), [Some(limits.write)]);
}
