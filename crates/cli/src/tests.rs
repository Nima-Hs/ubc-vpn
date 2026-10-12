//! The `status` command and the channel client, against the real service
//! running on the platform fake and the engine fake.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use ubc_vpn_core::protocol::{Event, HelloReply, Outcome, PROTOCOL_VERSION, decode};
use ubc_vpn_engine::fake::{FakeEngine, Script};
use ubc_vpn_platform::fake::{Fake, Op, paths};
use ubc_vpn_platform::{Error, Transport};
use ubc_vpn_service::{Service, Timeouts};

use super::*;

/// A fake machine with the files of one service in a folder of its own.
struct Rig {
    fake: Fake,
    root: PathBuf,
}

impl Rig {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let unique = (std::process::id(), NEXT.fetch_add(1, Ordering::SeqCst));
        let root = std::env::temp_dir().join(format!("ubc-vpn-cli-test-{unique:?}"));
        let fake = Fake::new();
        Self { fake, root }
    }

    fn service(&self) -> Service {
        let key = format!("pin-sha256:{}=", "A".repeat(43));
        let engine = FakeEngine::new(Script::new(key.try_into().unwrap()));
        let platform = self.fake.platform(&self.root);
        Service::start(platform, Arc::new(engine), Timeouts::default()).unwrap()
    }

    /// Runs the command line as the fake's own user, `fake-user`.
    fn run(&self, args: &[&str]) -> (u8, String, String) {
        let platform = || Ok(self.fake.platform(&self.root));
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = run(args, &platform, &mut out, &mut err);
        let text = |bytes| String::from_utf8(bytes).unwrap();
        (code, text(out), text(err))
    }

    /// Makes another user the owner.
    fn claim_as_someone_else(&self) {
        let other = "someone-else".parse().unwrap();
        let name = paths(&self.root).channel_name;
        let conn = self.fake.connect_as(&name, &other).unwrap();
        let mut client = Client::over(conn, ClientKind::App).unwrap();
        client.claim_if_unowned().unwrap();
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn status_claims_on_first_use_and_prints_the_state() {
    let rig = Rig::new();
    let _service = rig.service();
    assert_eq!(
        rig.run(&["status"]),
        (0, "Disconnected\n".into(), "".into())
    );
    let json = "{\"state\":\"disconnected\"}\n";
    assert_eq!(rig.run(&["status", "--json"]), (0, json.into(), "".into()));
    // The first run made this user the owner.
    let name = paths(&rig.root).channel_name;
    let stranger = "someone-else".parse().unwrap();
    let refused = rig.fake.connect_as(&name, &stranger).err();
    assert_eq!(refused, Some(Error::PermissionDenied));
}

#[test]
fn each_failure_has_its_own_exit_code_and_message() {
    let rig = Rig::new();
    let (code, out, err) = rig.run(&["status"]);
    assert_eq!((code, out.as_str()), (NOT_RUNNING, ""));
    assert!(err.contains("service is not running"), "{err}");

    // Not the owner: refused by the OS, and, where the OS could not narrow
    // the channel, refused by the service.
    for narrowed in [true, false] {
        let rig = Rig::new();
        if !narrowed {
            let broken = Some(Error::Unsupported);
            rig.fake.set_failure(Op::RestrictTo, broken);
        }
        let _service = rig.service();
        rig.claim_as_someone_else();
        let (code, out, err) = rig.run(&["status", "--json"]);
        assert_eq!((code, out.as_str()), (NOT_OWNER, ""), "{narrowed}");
        assert!(err.contains("not the owner"), "{err}");
    }

    // Something else holds the channel. This is not "not running": the
    // user has to be told, and nothing may be sent.
    let rig = Rig::new();
    let _service = rig.service();
    let impostor = Some(Error::NotTheService);
    rig.fake.set_failure(Op::Connect, impostor);
    let (code, out, err) = rig.run(&["status"]);
    assert_eq!((code, out.as_str()), (NOT_THE_SERVICE, ""));
    assert!(err.contains("Another program is answering"), "{err}");
    rig.fake.set_failure(Op::Connect, None);
    assert!(
        !rig.fake.platform(&rig.root).paths.state_dir.exists(),
        "no claim was sent"
    );

    for usage in [
        &[][..],
        &["bogus"],
        &["status", "--bogus"],
        &["status", "--json", "x"],
    ] {
        let (code, _, err) = rig.run(usage);
        assert_eq!(code, USAGE, "{usage:?}");
        assert!(err.contains("Usage:"), "{err}");
    }
    let unsupported = || Err(Error::Unsupported);
    let (mut out, mut err) = (Vec::new(), Vec::new());
    assert_eq!(run(&["status"], &unsupported, &mut out, &mut err), FAILED);
    assert_eq!(rig.run(&["help"]).0, 0);
}

// A service from another version answers the hello and hangs up. The user
// is told to update, not shown a broken connection.
#[test]
fn a_service_of_another_version_means_please_update() {
    let rig = Rig::new();
    let listener = rig.fake.listen(&paths(&rig.root).channel_name).unwrap();
    let service = std::thread::spawn(move || {
        let (conn, _) = listener.accept().unwrap();
        conn.read_line().unwrap();
        let reply = HelloReply {
            protocol_version: PROTOCOL_VERSION + 1,
            service_version: "9.9.9".to_string(),
            owner_claimed: true,
        };
        conn.write_line(encode(&reply).unwrap().trim_end()).unwrap();
    });
    let (code, out, err) = rig.run(&["status"]);
    service.join().unwrap();
    assert_eq!((code, out.as_str()), (MISMATCH, ""));
    assert!(
        err.contains("9.9.9") && err.contains("Please update"),
        "{err}"
    );
}

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
    use ubc_vpn_core::protocol::{Request, Response, ServerMessage};

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
    assert_eq!(client.next_event(), Ok(kept));
    // Nothing more was queued, and the service has gone.
    assert!(matches!(client.next_event(), Err(ClientError::Lost(_))));
}
