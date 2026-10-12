//! The channel server: start-up, the listener, and one thread per connection
//! doing the handshake and the owner check on every request.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use ubc_vpn_core::VERSION;
use ubc_vpn_core::protocol::{
    ErrorCode, ErrorInfo, Hello, HelloReply, Outcome, PROTOCOL_VERSION, Request, RequestBody,
    Response, ResponseBody, ServerMessage, decode, encode, peek_protocol_version,
};
use ubc_vpn_engine::TunnelEngine;
use ubc_vpn_platform::{Connection, Error, Listener, Platform, UserId};

use crate::hub::{Hub, send};
use crate::session::{Session, error};
use crate::{Logs, lock, owner, policy};

/// The most connections served at once. Each one holds a thread.
pub const MAX_CONNECTIONS: usize = 32;

/// The most of those that may come from users who were not the owner when
/// they connected. It is lower than [`MAX_CONNECTIONS`], so strangers can
/// never use up the threads the owner needs. Until someone claims the service
/// everyone is a stranger, and this is the whole limit.
pub const MAX_STRANGERS: usize = 8;

/// The most of the strangers' places one user may hold, so that a single
/// user cannot take them all and keep the first real user from claiming.
pub const MAX_PER_STRANGER: usize = 2;

/// How long the service waits on a client.
///
/// The limits exist so that a caller the service has no reason to trust
/// cannot hold one of its threads. They are not idle timeouts: the owner's
/// app sends nothing for hours while it waits for events, so once a caller is
/// known to be the owner its reads wait for ever. A dead owner connection is
/// noticed when the OS closes it or when a pushed event is not taken.
#[derive(Debug, Clone, Copy)]
pub struct Timeouts {
    /// How long anyone may take to send the hello, the owner included, and
    /// how long anyone who is not the owner may take over each later line.
    pub stranger: Duration,
    /// How long any client may take to accept a line. One that does not is
    /// closed. Events are written by a thread of the connection's own, so a
    /// client that stops reading delays nobody but itself.
    pub write: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            stranger: Duration::from_secs(5),
            write: Duration::from_secs(5),
        }
    }
}

/// The running service. Dropping it shuts it down.
pub struct Service {
    shared: Arc<Shared>,
    accepting: Option<JoinHandle<()>>,
}

/// How many connections are being served.
#[derive(Default)]
struct Serving {
    total: usize,
    /// Those of users who were not the owner when they connected, by user.
    strangers: HashMap<UserId, usize>,
}

/// One connection's place. Dropping it closes the connection, forgets it
/// and gives the place back, so a thread that panics or never starts cannot
/// leak any of the three.
struct Place {
    shared: Arc<Shared>,
    conn: Arc<Connection>,
    user: UserId,
    stranger: bool,
}

impl Drop for Place {
    fn drop(&mut self) {
        self.shared.hub.remove(&self.conn);
        self.conn.close();
        let mut serving = lock(&self.shared.serving);
        serving.total -= 1;
        if !self.stranger {
            return;
        }
        let held = serving.strangers.get(&self.user).copied().unwrap_or(1);
        match held {
            1 => serving.strangers.remove(&self.user),
            more => serving.strangers.insert(self.user.clone(), more - 1),
        };
    }
}

struct Shared {
    listener: Box<dyn Listener>,
    hub: Arc<Hub>,
    session: Session,
    serving: Mutex<Serving>,
    /// Whether the OS has yet to be told to refuse everyone but the owner.
    narrowing_due: AtomicBool,
    /// Requests from non-owners that could not be understood.
    unreadable: AtomicUsize,
    logs: Logs,
    state_dir: PathBuf,
    timeouts: Timeouts,
}

impl Service {
    /// Starts the service: loads the policy, removes whatever an earlier run
    /// left applied, loads the owner, and only then opens the channel.
    ///
    /// A missing or invalid policy does not stop it: it then serves `status`
    /// and refuses every `connect`. A state file it cannot read or understand
    /// does, and so does a channel it cannot open or cannot narrow to the
    /// owner it has stored; the error is a sentence for the log.
    pub fn start(
        platform: Platform,
        engine: Arc<dyn TunnelEngine>,
        timeouts: Timeouts,
    ) -> Result<Self, String> {
        let logs = Logs::default();
        let policy = policy::load(&platform.paths.policy_dir);
        if let Err(message) = &policy {
            logs.push(message);
        }
        let cleaned = [platform.routes.remove_all(), platform.dns.clear_split_dns()];
        for error in cleaned.into_iter().filter_map(Result::err) {
            logs.push(&format!("start-up cleanup failed: {error}"));
        }
        let owner = owner::load(&platform.paths.state_dir)?;
        let listener = platform.transport.listen(&platform.paths.channel_name);
        let listener = listener.map_err(|e| format!("The channel could not be opened: {e}."))?;
        if let Some(owner) = &owner {
            let narrowed = listener.restrict_to(owner);
            narrowed.map_err(|e| format!("The channel could not be kept to the owner: {e}."))?;
        }
        let hub = Arc::new(Hub::new(owner));
        let session = Session::start(&platform, engine, policy, hub.clone(), logs.clone())?;
        let shared = Arc::new(Shared {
            session,
            serving: Mutex::default(),
            narrowing_due: AtomicBool::new(false),
            unreadable: AtomicUsize::new(0),
            listener,
            hub,
            logs,
            state_dir: platform.paths.state_dir,
            timeouts,
        });
        let accepting = shared.clone();
        let accepting = Some(thread::spawn(move || accepting.accept()));
        Ok(Self { shared, accepting })
    }

    /// The service's log, oldest line first.
    pub fn logs(&self) -> Vec<String> {
        self.shared.logs.lines()
    }

    /// Serves until accepting ends, and returns why that is a failure. It
    /// always is one: nothing closes the channel on purpose while the
    /// caller waits here, so a service that returns from this has stopped
    /// serving and must not look healthy.
    pub fn wait(mut self) -> String {
        self.join();
        "The service stopped accepting connections unexpectedly.".to_string()
    }

    fn join(&mut self) {
        if let Some(accepting) = self.accepting.take() {
            let _ = accepting.join();
        }
    }
}

impl Drop for Service {
    /// Stops accepting, tears the tunnel down and closes every connection.
    fn drop(&mut self) {
        self.shared.listener.close();
        self.join();
        self.shared.session.stop();
        self.shared.hub.close_all();
    }
}

impl Shared {
    fn accept(self: Arc<Self>) {
        loop {
            match self.listener.accept() {
                Ok((conn, user)) => {
                    if self.narrowing_due.load(Ordering::SeqCst)
                        && let Some(owner) = self.hub.owner()
                    {
                        self.narrow(&owner);
                    }
                    // Decided here, on the one accepting thread, so a burst
                    // of connections cannot slip past the limits.
                    let stranger = self.hub.owner().as_ref() != Some(&user);
                    let conn = Arc::new(conn);
                    if !self.admit(&user, stranger) {
                        conn.close();
                        continue;
                    }
                    let shared = self.clone();
                    let place = Place {
                        shared,
                        conn,
                        user,
                        stranger,
                    };
                    // If the OS refuses a thread, the place is dropped and
                    // the connection closed; accepting carries on.
                    let serve = move || place.shared.serve(&place.conn, &place.user);
                    if let Err(error) = thread::Builder::new().spawn(serve) {
                        self.logs
                            .push(&format!("a connection got no thread: {error}"));
                    }
                }
                Err(Error::Closed) => return,
                Err(error) => {
                    self.logs.push(&format!("accepting failed: {error}"));
                    thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }

    /// Takes a place for a new connection, unless it would be one too many.
    /// The place is given back when its [`Place`] is dropped.
    fn admit(&self, user: &UserId, stranger: bool) -> bool {
        let mut serving = lock(&self.serving);
        let strangers: usize = serving.strangers.values().sum();
        let own = serving.strangers.get(user).copied().unwrap_or(0);
        let crowded = strangers >= MAX_STRANGERS || own >= MAX_PER_STRANGER;
        let full = serving.total >= MAX_CONNECTIONS || (stranger && crowded);
        if !full {
            serving.total += 1;
            if stranger {
                *serving.strangers.entry(user.clone()).or_default() += 1;
            }
        }
        !full
    }

    fn serve(&self, conn: &Arc<Connection>, user: &UserId) {
        let limits = [
            conn.set_read_timeout(Some(self.timeouts.stranger)),
            conn.set_write_timeout(Some(self.timeouts.write)),
        ];
        if limits.iter().all(Result::is_ok) && self.handshake(conn) {
            self.hub.add(user, conn);
            self.requests(conn, user);
        }
    }

    /// Always answers, so a client that cannot be served learns why. Returns
    /// whether the client speaks this version and sent a proper hello.
    fn handshake(&self, conn: &Connection) -> bool {
        let line = conn.read_line().ok().flatten().unwrap_or_default();
        let compatible =
            peek_protocol_version(&line) == Ok(PROTOCOL_VERSION) && decode::<Hello>(&line).is_ok();
        let reply = encode(&HelloReply {
            protocol_version: PROTOCOL_VERSION,
            service_version: VERSION.to_string(),
            owner_claimed: self.hub.owner().is_some(),
        });
        let sent = reply.is_ok_and(|line| conn.write_line(line.trim_end()).is_ok());
        sent && compatible
    }

    fn requests(&self, conn: &Connection, user: &UserId) {
        loop {
            let line = match conn.read_line() {
                Ok(Some(line)) => line,
                // A read that began before this caller became the owner still
                // carried the stranger's limit.
                Err(Error::TimedOut) if self.hub.owner().as_ref() == Some(user) => continue,
                _ => return,
            };
            // Nothing from a request is ever logged: it may hold a cookie.
            let Ok(Request { id, body }) = decode(&line) else {
                return self.unreadable(user);
            };
            let (answer, keep) = self.answer(user, body);
            let outcome = answer.map_or_else(Outcome::Error, Outcome::Ok);
            let sent = send(conn, &ServerMessage::Response(Response { id, outcome }));
            if !(sent && keep) {
                return;
            }
        }
    }

    /// Decides one request from the identity the OS reported for the caller,
    /// never from anything the caller sent. Also says whether the connection
    /// stays open.
    fn answer(&self, user: &UserId, body: RequestBody) -> (Result<ResponseBody, ErrorInfo>, bool) {
        let owner = self.hub.owner();
        let accepted = |done: Result<(), ErrorInfo>| done.map(|()| ResponseBody::Accepted);
        let answer = match body {
            // Every claim takes the one path that decides who the owner is.
            RequestBody::Claim => self.claim(user),
            _ if owner.is_none() => {
                let message = "Nobody owns the service yet. Claim it first.";
                Err(error(ErrorCode::NotClaimed, message))
            }
            _ if owner.as_ref() != Some(user) => self.not_owner(),
            RequestBody::Status => Ok(ResponseBody::Status(self.hub.state())),
            RequestBody::Connect(params) => accepted(self.session.connect(params)),
            RequestBody::Disconnect => accepted(self.session.disconnect()),
            // The contract for these is in the protocol; the service's side
            // of it comes next. Until then the owner is told so, and anyone
            // else is refused above like for any other request.
            RequestBody::Logs(_)
            | RequestBody::WatchLogs(_)
            | RequestBody::Diagnostics
            | RequestBody::AddLog(_) => {
                let message = "This service does not keep a log that can be read yet.";
                Err(error(ErrorCode::BadRequest, message))
            }
        };
        let stranger = matches!(&answer, Err(refusal) if refusal.code == ErrorCode::NotOwner);
        (answer, !stranger)
    }

    /// Notes a request that could not be understood, without its content.
    /// The owner's gets a line each. Anyone else's are counted, with one line
    /// for the first, so a stranger cannot push everything else out of the
    /// log.
    fn unreadable(&self, user: &UserId) {
        if self.hub.owner().as_ref() == Some(user) {
            self.logs
                .push("a request from the owner could not be understood");
        } else if self.unreadable.fetch_add(1, Ordering::SeqCst) == 0 {
            let line = "a request from a user who is not the owner could not be understood; \
                        later ones are only counted";
            self.logs.push(line);
        }
    }

    fn not_owner(&self) -> Result<ResponseBody, ErrorInfo> {
        let message = "Only the owner, the first user of UBC VPN on this computer, may do this.";
        Err(error(ErrorCode::NotOwner, message))
    }

    /// Makes `user` the owner if nobody is: stored first, so an owner is never
    /// forgotten by a restart, then enforced by the OS as well. Anyone but
    /// the owner is refused, whether they came second in a race or years
    /// later.
    fn claim(&self, user: &UserId) -> Result<ResponseBody, ErrorInfo> {
        let persist = || owner::save(&self.state_dir, user);
        match self.hub.claim(user, persist) {
            Ok(true) => {
                self.narrow(user);
                Ok(ResponseBody::Claimed)
            }
            Ok(false) => self.not_owner(),
            Err(message) => Err(error(ErrorCode::Internal, message)),
        }
    }

    /// Asks the OS to refuse everyone but the owner. If it cannot, the check
    /// in [`Shared::answer`] still stands, the failure is logged once, and
    /// the next accepted connection tries again.
    fn narrow(&self, owner: &UserId) {
        let narrowed = self.listener.restrict_to(owner);
        let was_due = self.narrowing_due.swap(narrowed.is_err(), Ordering::SeqCst);
        if let (Err(error), false) = (narrowed, was_due) {
            let line = format!("the channel could not be narrowed to the owner: {error}");
            self.logs.push(&line);
        }
    }
}
