//! Shared by the test files: a service running on the platform fake and the
//! engine fake, and a client that speaks the channel in raw lines.
#![allow(
    dead_code,
    unused_imports,
    reason = "each test file uses its own part of this"
)]

use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub use ubc_vpn_core::protocol::{ErrorCode, RequestBody, ResponseBody};
pub use ubc_vpn_core::state::ConnState;
pub use ubc_vpn_platform::fake::{Fake, Op};
pub use ubc_vpn_platform::{Connection, Error, UserId};

use ubc_vpn_core::VERSION;
use ubc_vpn_core::protocol::{
    ClientKind, ConnectParams, Event, Hello, HelloReply, Outcome, PROTOCOL_VERSION, Request,
    ServerMessage, decode, encode,
};
use ubc_vpn_core::redact::Secret;
use ubc_vpn_core::routes::RouteSet;
pub use ubc_vpn_engine::fake::{FakeEngine, Script};
use ubc_vpn_engine::{
    Cancel, Gateway, LogLevel, LogSink, Session, Tunnel, TunnelEngine, TunnelError, TunnelEvent,
};
use ubc_vpn_platform::fake::paths;
use ubc_vpn_service::{Service, Timeouts};

/// The cookie the pretend gateway accepts. Made up.
pub const COOKIE: &str = "Zq7-made-up-0123456789";
/// Where the pretend gateway lives.
pub const GATEWAY: [u8; 4] = [192, 0, 2, 1];
/// Longer than anything here should take. A regression fails, not hangs.
pub const WAIT: Duration = Duration::from_secs(10);

pub fn pin(letter: char) -> String {
    format!("pin-sha256:{}=", letter.to_string().repeat(43))
}

/// A policy file pinning the key `letter`, with `extra` fields appended.
pub fn policy(letter: char, extra: &str) -> Option<String> {
    let pin = pin(letter);
    Some(format!(
        r#"{{"gateway":"vpn.example.test","pins":["{pin}"]{extra}}}"#
    ))
}

pub fn user(name: &str) -> UserId {
    name.parse().unwrap()
}

pub fn connect(cookie: &str, addr: [u8; 4], subnets: &[&str], domains: &[&str]) -> RequestBody {
    RequestBody::Connect(ConnectParams {
        cookie: Secret::new(cookie),
        gateway_addr: Ipv4Addr::from(addr),
        routes: RouteSet {
            subnets: subnets.iter().map(|s| s.parse().unwrap()).collect(),
            dns_domains: domains.iter().map(|d| d.to_string()).collect(),
        },
    })
}

/// A request that connects: the second subnet holds the gateway and the first
/// holds the DNS server the pretend gateway assigns.
pub fn good() -> RequestBody {
    let subnets = ["10.255.0.0/24", "192.0.2.0/24"];
    connect(COOKIE, GATEWAY, &subnets, &["ece.example.test"])
}

/// Wraps the engine fake to record, for every `open`, the gateway it was
/// given and the OS calls made before it. It also logs the cookie as a
/// careless library would: at a level that is kept, with no marker word, and
/// before the engine has hidden it.
pub struct Spy {
    engine: FakeEngine,
    fake: Fake,
    opens: Mutex<Vec<(Gateway, Vec<Op>)>>,
}

impl Spy {
    pub fn opens(&self) -> Vec<(Gateway, Vec<Op>)> {
        self.opens.lock().unwrap().clone()
    }
}

impl TunnelEngine for Spy {
    fn open(
        &self,
        gateway: &Gateway,
        session: &Session,
        cancel: &Cancel,
        events: Sender<TunnelEvent>,
        logs: LogSink,
    ) -> Result<Box<dyn Tunnel>, TunnelError> {
        let seen = (gateway.clone(), self.fake.calls());
        self.opens.lock().unwrap().push(seen);
        logs.log(LogLevel::Info, &format!("> {}", session.cookie.expose()));
        self.engine.open(gateway, session, cancel, events, logs)
    }
}

/// A service on fakes, with its files in a folder of its own.
pub struct Rig {
    pub fake: Fake,
    pub engine: FakeEngine,
    pub spy: Arc<Spy>,
    pub root: PathBuf,
    pub timeouts: Timeouts,
    pub service: Option<Service>,
}

/// A running service with a valid policy that pins the key `A`, which is the
/// key the pretend gateway presents.
pub fn rig() -> Rig {
    let mut rig = Rig::stopped(policy('A', ""));
    rig.start().unwrap();
    rig
}

impl Rig {
    /// A service that has not started, with `policy` as its policy file.
    pub fn stopped(policy: Option<String>) -> Self {
        Self::scripted(policy, |_| {})
    }

    /// The same, with a pretend gateway that `edit` has changed.
    pub fn scripted(policy: Option<String>, edit: impl FnOnce(&mut Script)) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let unique = (std::process::id(), NEXT.fetch_add(1, Ordering::SeqCst));
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("svc-{unique:?}"));
        std::fs::create_dir_all(root.join("policy")).unwrap();
        if let Some(policy) = policy {
            std::fs::write(root.join("policy/policy.json"), policy).unwrap();
        }
        let fake = Fake::new();
        let mut script = Script::new(pin('A').try_into().unwrap());
        edit(&mut script);
        let engine = FakeEngine::new(script);
        let spy = Arc::new(Spy {
            engine: engine.clone(),
            fake: fake.clone(),
            opens: Mutex::default(),
        });
        Self {
            fake,
            engine,
            spy,
            root,
            timeouts: Timeouts::default(),
            service: None,
        }
    }

    pub fn start(&mut self) -> Result<(), String> {
        let platform = self.fake.platform(&self.root);
        self.service = Some(Service::start(platform, self.spy.clone(), self.timeouts)?);
        Ok(())
    }

    pub fn stop(&mut self) {
        self.service = None;
    }

    pub fn logs(&self) -> Vec<String> {
        self.service.as_ref().unwrap().logs()
    }

    /// Whether nothing is applied and no tunnel is open.
    pub fn is_clean(&self) -> bool {
        self.fake.applied() == Default::default() && !self.engine.tunnel_is_open()
    }

    /// Connects as `name` without saying hello.
    pub fn raw(&self, name: &str) -> Result<Connection, Error> {
        let channel = paths(&self.root).channel_name;
        let conn = self.fake.connect_as(&channel, &user(name))?;
        conn.set_read_timeout(Some(WAIT)).unwrap();
        Ok(conn)
    }

    /// Connects as `name` and completes the handshake.
    pub fn peer(&self, name: &str) -> Peer {
        let conn = self.raw(name).unwrap();
        let hello = Hello {
            protocol_version: PROTOCOL_VERSION,
            client: ClientKind::App,
            client_version: VERSION.to_string(),
        };
        conn.write_line(encode(&hello).unwrap().trim_end()).unwrap();
        let hello = decode(&conn.read_line().unwrap().unwrap()).unwrap();
        Peer {
            conn,
            hello,
            events: VecDeque::new(),
            lines: Vec::new(),
            id: 0,
        }
    }

    /// Connects as `alice`, makes her the owner, and reads the first state.
    pub fn owner(&self) -> Peer {
        let mut alice = self.peer("alice");
        assert_eq!(alice.ask(RequestBody::Claim), Ok(ResponseBody::Claimed));
        assert_eq!(alice.state(), ConnState::Disconnected);
        alice
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        // So that a failed test ends, and does not wait on a held engine.
        self.engine.release();
        self.stop();
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// A client after the handshake.
pub struct Peer {
    pub conn: Connection,
    pub hello: HelloReply,
    events: VecDeque<ConnState>,
    /// Every line received after the handshake, as sent.
    pub lines: Vec<String>,
    id: u32,
}

impl Peer {
    fn read(&mut self) -> Option<ServerMessage> {
        let line = self.conn.read_line().expect("an answer in time")?;
        self.lines.push(line.clone());
        Some(decode(&line).unwrap())
    }

    /// Sends a request and waits for its response, keeping events for later.
    pub fn ask(&mut self, body: RequestBody) -> Result<ResponseBody, ErrorCode> {
        self.id += 1;
        let request = Request { id: self.id, body };
        let line = encode(&request).unwrap();
        self.conn.write_line(line.trim_end()).unwrap();
        loop {
            match self.read().expect("a response before the close") {
                ServerMessage::Event(Event::StateChanged(state)) => self.events.push_back(state),
                ServerMessage::Response(response) => {
                    assert_eq!(response.id, self.id);
                    return match response.outcome {
                        Outcome::Ok(body) => Ok(body),
                        Outcome::Error(error) => Err(error.code),
                    };
                }
            }
        }
    }

    /// The next state event.
    pub fn state(&mut self) -> ConnState {
        if let Some(state) = self.events.pop_front() {
            return state;
        }
        match self.read() {
            Some(ServerMessage::Event(Event::StateChanged(state))) => state,
            other => panic!("expected a state event, got {other:?}"),
        }
    }

    /// Sends a connect request and returns the state it ends in.
    pub fn connect_ends(&mut self, body: RequestBody) -> ConnState {
        assert_eq!(self.ask(body), Ok(ResponseBody::Accepted));
        assert_eq!(self.state(), ConnState::Connecting);
        self.state()
    }

    /// Whether the service closed the connection, with nothing left unread.
    pub fn is_closed(&mut self) -> bool {
        matches!(self.conn.read_line(), Ok(None) | Err(Error::Closed))
    }

    /// Whether the service sends nothing for a while.
    pub fn is_quiet(&mut self) -> bool {
        let short = Some(Duration::from_millis(300));
        self.conn.set_read_timeout(short).unwrap();
        let quiet = self.events.is_empty() && self.conn.read_line() == Err(Error::TimedOut);
        self.conn.set_read_timeout(Some(WAIT)).unwrap();
        quiet
    }
}
