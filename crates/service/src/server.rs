//! The channel server: start-up, the listener, and one thread per connection
//! doing the handshake and the owner check on every request.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use ubc_vpn_core::VERSION;
use ubc_vpn_core::protocol::{
    ErrorCode, ErrorInfo, Hello, HelloReply, Outcome, PROTOCOL_VERSION, Request, RequestBody,
    Response, ResponseBody, ServerMessage, decode, encode, peek_protocol_version,
};
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
    /// closed, so a client that stops reading delays a state change by at
    /// most this long, once.
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

struct Shared {
    listener: Box<dyn Listener>,
    hub: Arc<Hub>,
    session: Session,
    /// How many connections are being served: all of them, and strangers'.
    serving: Mutex<(usize, usize)>,
    logs: Logs,
    state_dir: PathBuf,
    timeouts: Timeouts,
}

impl Service {
    /// Starts the service: loads the policy, removes whatever an earlier run
    /// left applied, loads the owner, and only then opens the channel.
    ///
    /// A missing or invalid policy does not stop it: it then serves `status`
    /// and refuses every `connect`. A state file it cannot understand, or a
    /// channel it cannot open, does; the error is a sentence for the log.
    pub fn start(platform: Platform, timeouts: Timeouts) -> Result<Self, String> {
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
        let hub = Arc::new(Hub::new(owner.clone()));
        let shared = Arc::new(Shared {
            session: Session::start(policy),
            serving: Mutex::default(),
            listener,
            hub,
            logs,
            state_dir: platform.paths.state_dir,
            timeouts,
        });
        if let Some(owner) = &owner {
            shared.narrow(owner);
        }
        let accepting = shared.clone();
        let accepting = Some(thread::spawn(move || accepting.accept()));
        Ok(Self { shared, accepting })
    }

    /// The service's log, oldest line first.
    pub fn logs(&self) -> Vec<String> {
        self.shared.logs.lines()
    }

    /// Serves until the channel is closed.
    pub fn wait(mut self) {
        self.join();
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
                    // Decided here, on the one accepting thread, so a burst
                    // of connections cannot slip past the limits.
                    let stranger = self.hub.owner().as_ref() != Some(&user);
                    if !self.admit(stranger) {
                        conn.close();
                        continue;
                    }
                    let shared = self.clone();
                    thread::spawn(move || {
                        shared.serve(&Arc::new(conn), &user);
                        shared.release(stranger);
                    });
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
    fn admit(&self, stranger: bool) -> bool {
        let mut serving = lock(&self.serving);
        let full = serving.0 >= MAX_CONNECTIONS || (stranger && serving.1 >= MAX_STRANGERS);
        if !full {
            *serving = (serving.0 + 1, serving.1 + usize::from(stranger));
        }
        !full
    }

    fn release(&self, stranger: bool) {
        let mut serving = lock(&self.serving);
        *serving = (serving.0 - 1, serving.1 - usize::from(stranger));
    }

    fn serve(&self, conn: &Arc<Connection>, user: &UserId) {
        let limits = [
            conn.set_read_timeout(Some(self.timeouts.stranger)),
            conn.set_write_timeout(Some(self.timeouts.write)),
        ];
        if limits.iter().all(Result::is_ok) && self.handshake(conn) {
            self.hub.add(user, conn);
            self.requests(conn, user);
            self.hub.remove(conn);
        }
        conn.close();
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
            let Ok(Request { id, body }) = decode(&line) else {
                return self.logs.push("a request could not be understood");
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
        let refused = |code, message| Err(error(code, message));
        match self.hub.owner() {
            None if body == RequestBody::Claim => (self.claim(user), true),
            None => {
                let message = "Nobody owns the service yet. Claim it first.";
                (refused(ErrorCode::NotClaimed, message), true)
            }
            Some(owner) if owner != *user => (self.not_owner(), false),
            Some(_) => {
                let accepted = |done: Result<(), ErrorInfo>| done.map(|()| ResponseBody::Accepted);
                let answer = match body {
                    RequestBody::Claim => Ok(ResponseBody::Claimed),
                    RequestBody::Status => Ok(ResponseBody::Status(self.hub.state())),
                    RequestBody::Connect(params) => accepted(self.session.connect(params)),
                    RequestBody::Disconnect => accepted(self.session.disconnect()),
                };
                (answer, true)
            }
        }
    }

    fn not_owner(&self) -> Result<ResponseBody, ErrorInfo> {
        let message = "Only the owner, the first user of UBC VPN on this computer, may do this.";
        Err(error(ErrorCode::NotOwner, message))
    }

    /// Makes `user` the owner: stored first, so an owner is never forgotten
    /// by a restart, then enforced by the OS as well.
    fn claim(&self, user: &UserId) -> Result<ResponseBody, ErrorInfo> {
        let persist = || owner::save(&self.state_dir, user);
        match self.hub.claim(user, persist) {
            Ok(true) => {
                self.narrow(user);
                Ok(ResponseBody::Claimed)
            }
            // Someone else's claim got there first.
            Ok(false) => self.not_owner(),
            Err(message) => Err(error(ErrorCode::Internal, message)),
        }
    }

    /// Asks the OS to refuse everyone but the owner. If it cannot, the check
    /// in [`Shared::answer`] still stands.
    fn narrow(&self, owner: &UserId) {
        if let Err(error) = self.listener.restrict_to(owner) {
            let line = format!("the channel could not be narrowed to the owner: {error}");
            self.logs.push(&line);
        }
    }
}
