//! The `status` command and the channel client, against the real service
//! running on the platform fake and the engine fake.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use ubc_vpn_core::protocol::{
    ErrorCode, Event, HelloReply, Outcome, PROTOCOL_VERSION, Request, Response, ServerMessage,
    decode,
};
use ubc_vpn_engine::fake::{FakeEngine, Script};
use ubc_vpn_platform::fake::{Fake, Op, paths};
use ubc_vpn_platform::{Connection, Error, Transport};
use ubc_vpn_service::{Service, Timeouts};

use super::*;
use crate::client::Limits;

/// A fake machine with the files of one service in a folder of its own.
pub(crate) struct Rig {
    pub(crate) fake: Fake,
    pub(crate) root: PathBuf,
}

impl Rig {
    pub(crate) fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let unique = (std::process::id(), NEXT.fetch_add(1, Ordering::SeqCst));
        let root = std::env::temp_dir().join(format!("ubc-vpn-cli-test-{unique:?}"));
        let fake = Fake::new();
        Self { fake, root }
    }

    pub(crate) fn service(&self) -> Service {
        let key = format!("pin-sha256:{}=", "A".repeat(43));
        self.service_on(FakeEngine::new(Script::new(key.try_into().unwrap())))
    }

    /// A service whose tunnels are opened by `engine`.
    pub(crate) fn service_on(&self, engine: FakeEngine) -> Service {
        let platform = self.fake.platform(&self.root);
        let state = ubc_vpn_platform::StateDir::unchecked(&platform.paths.state_dir).unwrap();
        Service::start(platform, state, Arc::new(engine), Timeouts::default()).unwrap()
    }

    /// Runs the command line as the fake's own user, `fake-user`.
    pub(crate) fn run(&self, args: &[&str]) -> (u8, String, String) {
        let platform = || Ok(self.fake.platform(&self.root));
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = run(args, &platform, &mut out, &mut err);
        let text = |bytes| String::from_utf8(bytes).unwrap();
        (code, text(out), text(err))
    }

    /// Makes another user the owner.
    pub(crate) fn claim_as_someone_else(&self) {
        let other = "someone-else".parse().unwrap();
        let name = paths(&self.root).channel_name;
        let conn = self.fake.connect_as(&name, &other).unwrap();
        let mut client = Client::over(conn, ClientKind::App, Limits::default()).unwrap();
        client.claim_if_unowned().unwrap();
    }
}

/// Makes a settings folder as this program would: on Unix for the user
/// alone, whatever the umask of whoever runs the tests.
/// A settings file's text as the settings were before profiles: the active
/// profile's username (when it has one), routes and `save_password` (when
/// set), beside the file's other top-level fields. So a test of what a
/// command keeps and changes reads the same whichever version wrote it.
pub(crate) fn as_v1(text: &str) -> serde_json::Value {
    let profiles = ubc_vpn_core::profiles::Profiles::read(Some(text))
        .expect("readable settings")
        .profiles;
    let active = profiles.v1_view();
    let mut v1 = profiles.other.clone();
    if let Some(name) = active.username {
        v1.insert("username".to_string(), name.into());
    }
    let routes = serde_json::to_value(&active.routes).unwrap();
    v1.insert("routes".to_string(), routes);
    if active.save_password {
        v1.insert("save_password".to_string(), true.into());
    }
    serde_json::Value::Object(v1)
}

pub(crate) fn settings_folder(dir: &std::path::Path) {
    std::fs::create_dir_all(dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
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

/// Writes a policy where the installer would, as an installed UBC VPN has.
fn install_policy(rig: &Rig) {
    let dir = paths(&rig.root).policy_dir;
    std::fs::create_dir_all(&dir).unwrap();
    let pin = format!("pin-sha256:{}=", "A".repeat(43));
    let policy = format!(r#"{{"gateway":"vpn.example.test","pins":["{pin}"]}}"#);
    std::fs::write(dir.join("policy.json"), policy).unwrap();
}

// When `status` cannot reach the service it says which of the three it is,
// and what to do next: install UBC VPN, start its service, or ask the
// owner or an administrator.
#[test]
fn status_says_why_it_cannot_reach_the_service_and_what_to_do() {
    // Nothing installed: no service and no policy.
    let rig = Rig::new();
    let (code, out, err) = rig.run(&["status"]);
    assert_eq!((code, out.as_str()), (NOT_RUNNING, ""));
    assert!(err.contains("UBC VPN is not installed"), "{err}");
    assert!(err.contains("Install UBC VPN"), "{err}");

    // Installed, so its policy is there, but the service is stopped.
    install_policy(&rig);
    let (code, out, err) = rig.run(&["status"]);
    assert_eq!((code, out.as_str()), (NOT_RUNNING, ""));
    assert!(err.contains("installed but not running"), "{err}");
    assert!(err.contains("restart the computer"), "{err}");
    #[cfg(windows)]
    assert!(err.contains("sc start ubc-vpn"), "{err}");

    // Running, but the channel is kept to another user.
    let rig = Rig::new();
    install_policy(&rig);
    let _service = rig.service();
    rig.claim_as_someone_else();
    let (code, out, err) = rig.run(&["status"]);
    assert_eq!((code, out.as_str()), (NOT_OWNER, ""));
    assert!(err.contains("belongs to another user"), "{err}");
    assert!(
        err.contains("administrator can make you the owner"),
        "{err}"
    );
}

#[test]
fn each_failure_has_its_own_exit_code_and_message() {
    let rig = Rig::new();
    let (code, out, err) = rig.run(&["status"]);
    assert_eq!((code, out.as_str()), (NOT_RUNNING, ""));
    assert!(err.contains("not installed"), "{err}");

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
        !rig.fake
            .platform(&rig.root)
            .paths
            .state_dir
            .join("state.json")
            .exists(),
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

    // A request the service refuses is a failure too, with its reason: here
    // the first claim, which the service cannot store.
    let rig = Rig::new();
    let _service = rig.service();
    let state = rig.fake.platform(&rig.root).paths.state_dir;
    std::fs::create_dir_all(state.join(".state.json.new")).unwrap();
    let (code, out, err) = rig.run(&["status"]);
    assert_eq!((code, out.as_str()), (FAILED, ""));
    assert!(err.contains("The owner could not be saved"), "{err}");

    // The help says what the statuses mean and that the first use claims.
    let (code, help, _) = rig.run(&["help"]);
    assert_eq!(code, 0);
    for line in [
        "3  UBC VPN is not installed, or its service is not running",
        "6  another program",
        "9  cancelled",
        "connect, disconnect or status becomes the owner",
        "The bridge claims nothing itself",
        "never taken from an argument, a variable or a file",
        "is told to disconnect before the program ends.",
        "connect [--profile <id>] [--json]  Log in and connect",
        "which is sent only for the username it\nwas saved for",
        "A\ncancel line, or standard input closing, stops the login.",
        "bridge            Carry messages",
        "logs [--json] [--follow]  Show what the service has logged",
        "they do not make
anyone the owner",
        "settings reset [--force] --json  Start afresh",
    ] {
        assert!(help.contains(line), "{help}");
    }
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

/// How long a pretend service keeps going when the client does not hang up.
/// A client that has lost its deadline then fails its test late, and does
/// not hang it.
const PATIENCE: Duration = Duration::from_secs(5);

/// Stands in for the service on `rig`'s channel: accepts one connection and
/// hands it to `script`. Its own reads give up after [`PATIENCE`].
pub(crate) fn scripted(
    rig: &Rig,
    script: impl FnOnce(&Connection) + Send + 'static,
) -> std::thread::JoinHandle<()> {
    let listener = rig.fake.listen(&paths(&rig.root).channel_name).unwrap();
    std::thread::spawn(move || {
        let (conn, _) = listener.accept().unwrap();
        conn.set_read_timeout(Some(PATIENCE)).unwrap();
        script(&conn);
    })
}

/// Reads the hello and answers it as an owned service of this version.
pub(crate) fn greet(conn: &Connection) {
    conn.read_line().unwrap();
    let reply = HelloReply {
        protocol_version: PROTOCOL_VERSION,
        service_version: "0.1.0".to_string(),
        owner_claimed: true,
    };
    conn.write_line(encode(&reply).unwrap().trim_end()).unwrap();
}

/// Sends one message from the pretend service. False once the client is gone.
pub(crate) fn tell(conn: &Connection, message: &ServerMessage) -> bool {
    conn.write_line(encode(message).unwrap().trim_end()).is_ok()
}

/// Runs `status` against a pretend service that answers it with `answer`.
fn status_answered_with(answer: ResponseBody, args: &[&str]) -> (u8, String, String) {
    let rig = Rig::new();
    let service = scripted(&rig, move |conn| {
        greet(conn);
        let asked: Request = decode(&conn.read_line().unwrap().unwrap()).unwrap();
        let outcome = Outcome::Ok(answer);
        let response = Response {
            id: asked.id,
            outcome,
        };
        tell(conn, &ServerMessage::Response(response));
    });
    let result = rig.run(args);
    service.join().unwrap();
    result
}

// `status` is how a person or a script learns whether traffic goes through
// the tunnel, so every state has its exact words and its exact JSON.
#[test]
fn every_state_is_printed_exactly() {
    let tunnel = ubc_vpn_core::state::TunnelInfo {
        interface: "utun4".to_string(),
        address: "10.255.0.2".to_string(),
        subnets: vec![
            "10.19.0.0/16".parse().unwrap(),
            "142.103.0.0/16".parse().unwrap(),
        ],
        dns_domains: vec![
            "ece.example.test".to_string(),
            "cs.example.test".to_string(),
        ],
    };
    let failed = ConnState::Failed {
        code: ErrorCode::VerificationFailed,
        // Whatever an OS error may hold, the terminal gets no control codes
        // and nothing that reorders the line. Ordinary Unicode is kept.
        message:
            "10.19.0.0/16 is \u{1b}[2Jnot routed \u{202e}(réseau 網, می\u{200c}خواهم)\u{200b}\r\n"
                .to_string(),
    };
    let states = [
        (
            ConnState::Disconnected,
            "Disconnected\n",
            r#"{"state":"disconnected"}"#,
        ),
        (
            ConnState::Connecting,
            "Connecting\n",
            r#"{"state":"connecting"}"#,
        ),
        (
            ConnState::Disconnecting,
            "Disconnecting\n",
            r#"{"state":"disconnecting"}"#,
        ),
        (
            ConnState::LoginNeeded,
            "Login needed: the session has ended.\n",
            r#"{"state":"login_needed"}"#,
        ),
        (
            failed,
            "Failed: 10.19.0.0/16 is [2Jnot routed (réseau 網, می\u{200c}خواهم)\n",
            "{\"state\":\"failed\",\"code\":\"verification_failed\",\"message\":\"10.19.0.0/16 is \\u001b[2Jnot routed (réseau 網, می\u{200c}خواهم)\\r\\n\"}",
        ),
        (
            ConnState::Connected { tunnel },
            "Connected (utun4 as 10.255.0.2)\n  Subnets: 10.19.0.0/16, 142.103.0.0/16\n  \
             DNS domains: ece.example.test, cs.example.test\n",
            r#"{"state":"connected","tunnel":{"interface":"utun4","address":"10.255.0.2","subnets":["10.19.0.0/16","142.103.0.0/16"],"dns_domains":["ece.example.test","cs.example.test"]}}"#,
        ),
    ];
    for (state, words, json) in states {
        let answer = ResponseBody::Status(state);
        let said = status_answered_with(answer.clone(), &["status"]);
        assert_eq!(said, (0, words.to_string(), String::new()));
        let said = status_answered_with(answer, &["status", "--json"]);
        assert_eq!(said, (0, format!("{json}\n"), String::new()));
    }
}

// An answer to `status` that is not a status is an error. Nothing is printed
// as if it were the state.
#[test]
fn an_answer_that_is_not_a_status_is_an_error() {
    for args in [&["status"][..], &["status", "--json"]] {
        let (code, out, err) = status_answered_with(ResponseBody::Claimed, args);
        assert_eq!((code, out.as_str()), (FAILED, ""));
        assert!(err.contains("unexpected answer"), "{err}");
    }
}

// A service of a later version may answer the hello in a shape this version
// cannot read. That is still "please update", not a broken connection.
#[test]
fn a_reply_this_version_cannot_read_still_means_please_update() {
    let rig = Rig::new();
    let service = scripted(&rig, |conn| {
        // The command-line client says which program it is.
        let hello: ubc_vpn_core::protocol::Hello =
            decode(&conn.read_line().unwrap().unwrap()).unwrap();
        assert_eq!(hello.client, ClientKind::Cli);
        let later = r#"{"protocol_version":99,"service":{"version":"9.9.9"}}"#;
        conn.write_line(later).unwrap();
    });
    let (code, out, err) = rig.run(&["status"]);
    service.join().unwrap();
    assert_eq!((code, out.as_str()), (MISMATCH, ""));
    assert!(
        err.contains("another version") && err.contains("Please update"),
        "{err}"
    );
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
