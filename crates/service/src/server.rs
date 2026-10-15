//! The channel server: start-up, the listener, and one thread per connection
//! doing the handshake and the owner check on every request.

use std::collections::HashMap;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use ubc_vpn_core::VERSION;
use ubc_vpn_core::protocol::{
    AddLogParams, ClientKind, ErrorCode, ErrorInfo, Hello, HelloReply, LogText,
    MAX_ADDED_LOG_LINES, Outcome, PROTOCOL_VERSION, Request, RequestBody, Response, ResponseBody,
    ServerMessage, decode, encode, peek_protocol_version,
};
use ubc_vpn_engine::TunnelEngine;
use ubc_vpn_platform::{Connection, Error, Listener, Platform, StateDir, UserId};

use crate::diagnostics::About;
use crate::hub::{Hub, send};
use crate::session::{Attempt, Session, error};
use crate::words::counted;
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
    /// How long the service waits at start for its channel's name while
    /// another program holds it. Any local user can create the name while
    /// it is free, as during an update or a restart; past this the service
    /// gives up.
    pub claim: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            stranger: Duration::from_secs(5),
            write: Duration::from_secs(5),
            claim: Duration::from_secs(60),
        }
    }
}

/// Claims the channel's name for the service's own listener. While another
/// program holds the name, which any local user can create while it is
/// free, it tries again with a growing pause, for `limit` at most, and says
/// once that the name was held. It only ever creates a channel of its own:
/// creating one is exclusive, so it never uses or connects to another.
fn claim(platform: &Platform, limit: Duration, logs: &Logs) -> Result<Box<dyn Listener>, String> {
    let name = &platform.paths.channel_name;
    let until = Instant::now() + limit;
    let mut pause = Duration::from_millis(50);
    let mut said = false;
    loop {
        match platform.transport.listen(name) {
            Ok(listener) => return Ok(listener),
            Err(Error::AlreadyExists) if Instant::now() < until => {
                if !said {
                    let line = "the channel's name is held by another program; waiting for it";
                    logs.warn(line);
                    said = true;
                }
                thread::sleep(pause.min(until.saturating_duration_since(Instant::now())));
                pause = (pause * 2).min(Duration::from_secs(1));
            }
            Err(Error::AlreadyExists) => {
                return Err(
                    "The channel's name is held by another program, which kept it \
                     too long. Restart the computer, then start the service again."
                        .to_string(),
                );
            }
            Err(e) => return Err(format!("The channel could not be opened: {e}.")),
        }
    }
}

/// Why serving ended when nothing asked it to.
const UNEXPECTED: &str = "The service stopped accepting connections unexpectedly.";

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
    logs: Logs,
    about: About,
    state: StateDir,
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
    ///
    /// `state` is the state folder, opened by the caller: the installed
    /// service opens it with [`StateDir::open`], which checks who may change
    /// it. The owner is read and written through it and nothing else.
    pub fn start(
        platform: Platform,
        state: StateDir,
        engine: Arc<dyn TunnelEngine>,
        timeouts: Timeouts,
    ) -> Result<Self, String> {
        Self::start_in(platform, state, engine, timeouts, false)
    }

    /// [`Service::start`], saying in its first log line whether this is a
    /// dev-mode run.
    pub fn start_in(
        platform: Platform,
        state: StateDir,
        engine: Arc<dyn TunnelEngine>,
        timeouts: Timeouts,
        dev_mode: bool,
    ) -> Result<Self, String> {
        let logs = Logs::default();
        let how = match dev_mode {
            true => "dev mode",
            false => "installed",
        };
        logs.info(&format!(
            "service started: version {VERSION}, protocol {PROTOCOL_VERSION}, {how}"
        ));
        let policy = policy::load(&platform.paths.policy_dir);
        match &policy {
            Ok(policy) => logs.info(&format!(
                "policy read: gateway {}, {}",
                policy.gateway,
                counted(policy.pins.len(), "pin")
            )),
            Err(message) => logs.error(message),
        }
        let about = About::new(&policy);
        let cleaned = [platform.routes.remove_all(), platform.dns.clear_split_dns()];
        for error in cleaned.into_iter().filter_map(Result::err) {
            logs.error(&format!("start-up cleanup failed: {error}"));
        }
        let owner = owner::load(&state)?;
        let listener = claim(&platform, timeouts.claim, &logs)?;
        if let Some(owner) = &owner {
            let narrowed = listener.restrict_to(owner);
            narrowed.map_err(|e| format!("The channel could not be kept to the owner: {e}."))?;
        }
        let hub = Arc::new(Hub::new(owner));
        let watching = hub.clone();
        logs.tell(move |line| watching.log(line));
        let session = Session::start(&platform, engine, policy, hub.clone(), logs.clone())?;
        let shared = Arc::new(Shared {
            session,
            serving: Mutex::default(),
            narrowing_due: AtomicBool::new(false),
            listener,
            hub,
            logs,
            about,
            state,
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

    /// The text of each line a client handed over, oldest first.
    pub fn login_lines(&self) -> Vec<String> {
        let added = |line: &ubc_vpn_core::protocol::LogLine| {
            line.source == ubc_vpn_core::protocol::LogSource::Login
        };
        let lines = self.shared.logs.all().into_iter().filter(added);
        lines.map(|line| line.text.as_str().to_string()).collect()
    }

    /// Serves until accepting ends, and returns why that is a failure. It
    /// always is one: nothing closes the channel on purpose while the
    /// caller waits here, so a service that returns from this has stopped
    /// serving and must not look healthy.
    pub fn wait(mut self) -> String {
        self.join();
        UNEXPECTED.to_string()
    }

    /// Serves until `stop` receives a request, then shuts down as dropping
    /// it does: the tunnel is torn down and every connection closed. For a
    /// service manager, which asks a service to stop when someone stops it
    /// and when the computer shuts down.
    ///
    /// If accepting ends first, nothing asked for that, and the error is
    /// the one [`Service::wait`] gives. A `stop` whose sender is dropped
    /// without a request asks for nothing.
    pub fn serve_until(mut self, stop: Receiver<()>) -> Result<(), String> {
        let asked = Arc::new(AtomicBool::new(false));
        let (shared, asking) = (self.shared.clone(), asked.clone());
        thread::spawn(move || {
            if stop.recv().is_ok() {
                asking.store(true, Ordering::SeqCst);
                shared.listener.close();
            }
        });
        self.join();
        match asked.load(Ordering::SeqCst) {
            true => Ok(()),
            false => Err(UNEXPECTED.to_string()),
        }
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
                        let line = format!("a connection got no thread: {error}");
                        self.logs.error_about("no thread", &line);
                    }
                }
                Err(Error::Closed) => return,
                Err(error) => {
                    let line = format!("accepting failed: {error}");
                    self.logs.error_about("accepting", &line);
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
        if !limits.iter().all(Result::is_ok) {
            return;
        }
        if let Some(kind) = self.handshake(conn) {
            self.hub.add(user, conn);
            self.requests(conn, user, kind);
        }
    }

    /// Always answers, so a client that cannot be served learns why. Returns
    /// whether the client speaks this version and sent a proper hello.
    fn handshake(&self, conn: &Connection) -> Option<ClientKind> {
        let line = conn.read_line().ok().flatten().unwrap_or_default();
        let hello = match peek_protocol_version(&line) == Ok(PROTOCOL_VERSION) {
            true => decode::<Hello>(&line).ok(),
            false => None,
        };
        let reply = encode(&HelloReply {
            protocol_version: PROTOCOL_VERSION,
            service_version: VERSION.to_string(),
            owner_claimed: self.hub.owner().is_some(),
        });
        let sent = reply.is_ok_and(|line| conn.write_line(line.trim_end()).is_ok());
        hello.filter(|_| sent).map(|hello| hello.client)
    }

    /// `kind` is what the client said it is. Nothing checks it: it is only
    /// ever written as what the client said.
    fn requests(&self, conn: &Arc<Connection>, user: &UserId, kind: ClientKind) {
        // How many log lines this connection has added.
        let mut added = 0;
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
            let (answer, keep, admitted) = self.answer(user, conn, kind, &mut added, body);
            let outcome = answer.map_or_else(Outcome::Error, Outcome::Ok);
            let sent = send(conn, &ServerMessage::Response(Response { id, outcome }));
            // The connect's worker does nothing until it hears whether the
            // client was told. One that went before it was is watching
            // nothing, and nobody would undo it: the worker undoes it.
            if let Some(attempt) = admitted {
                attempt.settle(sent);
            }
            if !(sent && keep) {
                return;
            }
        }
    }

    /// Decides one request from the identity the OS reported for the caller,
    /// never from anything the caller sent. Also says whether the connection
    /// stays open, and which connect it admitted, if any. `added` counts the
    /// log lines this connection has added.
    fn answer(
        &self,
        user: &UserId,
        conn: &Arc<Connection>,
        kind: ClientKind,
        added: &mut usize,
        body: RequestBody,
    ) -> (Result<ResponseBody, ErrorInfo>, bool, Option<Attempt>) {
        let owner = self.hub.owner();
        let accepted = |done: Result<(), ErrorInfo>| done.map(|()| ResponseBody::Accepted);
        let mut admitted = None;
        let answer = match body {
            // Every claim takes the one path that decides who the owner is.
            RequestBody::Claim => self.claim(user),
            _ if owner.is_none() => {
                let message = "Nobody owns the service yet. Claim it first.";
                Err(error(ErrorCode::NotClaimed, message))
            }
            _ if owner.as_ref() != Some(user) => self.not_owner(),
            RequestBody::Status => Ok(ResponseBody::Status(self.hub.state())),
            RequestBody::Connect(params) => {
                let attempt = self.session.connect(params);
                let answer = attempt.as_ref().map(drop).map_err(Clone::clone);
                admitted = attempt.ok();
                accepted(answer)
            }
            RequestBody::Disconnect => {
                let said = match kind {
                    ClientKind::App => "the app",
                    ClientKind::Cli => "the command line",
                };
                accepted(self.session.disconnect(said))
            }
            // The log is the owner's alone: anyone else was refused above.
            RequestBody::Logs(params) => Ok(ResponseBody::Logs(self.logs.page(params.after))),
            RequestBody::WatchLogs(params) => {
                self.hub.watch(conn, params.on);
                Ok(ResponseBody::Accepted)
            }
            RequestBody::Diagnostics => {
                let report = self.about.report(&self.hub);
                Ok(ResponseBody::Diagnostics(Box::new(report)))
            }
            RequestBody::AddLog(params) => accepted(self.add_log(&params, added)),
            // Part of protocol 4; the service learns to apply it next.
            RequestBody::UpdateRoutes(_) => Err(error(
                ErrorCode::BadRequest,
                "This service cannot change the routes of a live connection yet. \
                 Disconnect and connect again to use the saved routes.",
            )),
        };
        let stranger = matches!(&answer, Err(refusal) if refusal.code == ErrorCode::NotOwner);
        (answer, !stranger, admitted)
    }

    /// Keeps a line a client hands over, cleaned like any other. A text
    /// that is not one plain line of a length that can be kept is refused
    /// whole, and so is any line once this connection has added all it may.
    ///
    /// Nothing of the request is written anywhere on the way: not when it
    /// is refused, and not as debug output. Its text reaches the log only
    /// through [`Logs::add`], which removes secrets from it first.
    fn add_log(&self, params: &AddLogParams, added: &mut usize) -> Result<(), ErrorInfo> {
        let refused = |message: &str| Err(error(ErrorCode::BadRequest, message));
        let Ok(text) = LogText::new(&params.text) else {
            return refused("A log line must be one plain line of at most 512 bytes.");
        };
        if *added >= MAX_ADDED_LOG_LINES {
            return refused("This connection has added all the log lines it may.");
        }
        *added += 1;
        self.logs.add(params.level, &text);
        Ok(())
    }

    /// Notes a request that could not be understood, without its content.
    /// The owner's and everyone else's each have one line, which is in the
    /// log once however many there are: no number of them, from anyone, can
    /// push everything else out of the log.
    fn unreadable(&self, user: &UserId) {
        let (what, line) = match self.hub.owner().as_ref() == Some(user) {
            true => (
                "the owner's request",
                "a request from the owner could not be understood; later ones are not noted \
                 while this line is in the log",
            ),
            false => (
                "a stranger's request",
                "a request from a user who is not the owner could not be understood; later \
                 ones are not noted while this line is in the log",
            ),
        };
        self.logs.warn_about(what, line);
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
        let mut recorded = false;
        let persist = || {
            owner::save(&self.state, user)?;
            recorded = true;
            Ok(())
        };
        match self.hub.claim(user, persist) {
            Ok(true) => {
                // Who it is, is not written: only that there now is one.
                if recorded {
                    self.logs.info("an owner was recorded");
                }
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
            self.logs.error_about("narrowing", &line);
        }
    }
}
