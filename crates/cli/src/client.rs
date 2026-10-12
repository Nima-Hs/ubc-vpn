//! The client side of the channel: connecting, the handshake, matching each
//! response to its request, and receiving events. Every command uses this.
//!
//! How it waits. An answer has one deadline: the hello reply, and the
//! response to each request, must arrive within [`Limits::answer`] of being
//! asked for, however many events arrive first. Between requests there is no
//! deadline: a program that only listens, as the app's bridge does, waits for
//! the next event for as long as it takes, and learns that the service has
//! gone from the connection closing.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use ubc_vpn_core::VERSION;
use ubc_vpn_core::protocol::{
    ClientKind, ErrorCode, ErrorInfo, Event, FrameError, Hello, HelloReply, Outcome,
    PROTOCOL_VERSION, Request, RequestBody, ResponseBody, ServerMessage, decode, encode,
    peek_protocol_version,
};
use ubc_vpn_platform::{Connection, Error, Transport};

/// How long, and how much, a client lets the service take.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// How long the service may take over a whole answer, so that a stuck
    /// service cannot hang a command. Requests are answered at once;
    /// progress arrives as events.
    pub answer: Duration,
    /// How long the service may take to accept one line.
    pub write: Duration,
    /// How many events may arrive while an answer is awaited and be kept
    /// for later. State changes are few; more than this is not a service
    /// that is working.
    pub kept_events: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            answer: Duration::from_secs(10),
            write: Duration::from_secs(10),
            kept_events: 64,
        }
    }
}

/// Why talking to the service did not work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientError {
    /// Nothing is listening: the service is not installed or not running.
    NotRunning,
    /// The service belongs to another user.
    NotOwner,
    /// Something is listening where the service should be, and it is not
    /// the service. Nothing was sent to it.
    NotTheService,
    /// The service speaks another protocol version. Holds its product
    /// version when the reply could be read that far.
    Mismatch(Option<String>),
    /// The service refused or failed the request.
    Refused(ErrorInfo),
    /// The connection broke, the service did not answer in time, or it sent
    /// something unreadable.
    Lost(String),
}

impl From<Error> for ClientError {
    fn from(error: Error) -> Self {
        match error {
            Error::NotFound => Self::NotRunning,
            Error::PermissionDenied => Self::NotOwner,
            Error::NotTheService => Self::NotTheService,
            Error::TimedOut => Self::Lost("the service did not answer in time".to_string()),
            other => Self::Lost(other.to_string()),
        }
    }
}

impl From<FrameError> for ClientError {
    fn from(error: FrameError) -> Self {
        Self::Lost(error.to_string())
    }
}

/// Reads one line, waiting no later than `deadline`, or for ever without one.
fn read_line(conn: &Connection, deadline: Option<Instant>) -> Result<String, ClientError> {
    let left = deadline.map(|at| at.saturating_duration_since(Instant::now()));
    if left.is_some_and(|left| left.is_zero()) {
        return Err(Error::TimedOut.into());
    }
    conn.set_read_timeout(left)?;
    let closed = || ClientError::Lost("the service closed the connection".to_string());
    conn.read_line()?.ok_or_else(closed)
}

/// Does the handshake: sends the hello and reads the reply, within the
/// limits. A service of another protocol version is [`ClientError::Mismatch`],
/// even when the rest of its reply is not something this version can read.
pub fn hello(
    conn: &Connection,
    client: ClientKind,
    limits: Limits,
) -> Result<HelloReply, ClientError> {
    conn.set_write_timeout(Some(limits.write))?;
    let deadline = Instant::now() + limits.answer;
    let hello = Hello {
        protocol_version: PROTOCOL_VERSION,
        client,
        client_version: VERSION.to_string(),
    };
    conn.write_line(encode(&hello)?.trim_end())?;
    let line = read_line(conn, Some(deadline))?;
    let reply = decode::<HelloReply>(&line);
    if peek_protocol_version(&line)? != PROTOCOL_VERSION {
        return Err(ClientError::Mismatch(reply.ok().map(|r| r.service_version)));
    }
    Ok(reply?)
}

/// A connection to the service, after the handshake.
pub struct Client {
    conn: Connection,
    limits: Limits,
    owner_claimed: bool,
    last_id: u32,
    /// Events that arrived while a response was being waited for.
    events: VecDeque<Event>,
}

impl Client {
    /// Connects to the service listening on `name` and says hello, with the
    /// usual limits.
    pub fn connect(
        transport: &dyn Transport,
        name: &str,
        kind: ClientKind,
    ) -> Result<Self, ClientError> {
        Self::over(transport.connect(name)?, kind, Limits::default())
    }

    /// Says hello on a connection that is already open.
    pub fn over(conn: Connection, client: ClientKind, limits: Limits) -> Result<Self, ClientError> {
        let reply = hello(&conn, client, limits)?;
        Ok(Self {
            conn,
            limits,
            owner_claimed: reply.owner_claimed,
            last_id: 0,
            events: VecDeque::new(),
        })
    }

    /// Claims the service if nobody owns it yet, which makes this user the
    /// owner. Every command starts with this.
    pub fn claim_if_unowned(&mut self) -> Result<(), ClientError> {
        if !self.owner_claimed {
            self.request(RequestBody::Claim)?;
            self.owner_claimed = true;
        }
        Ok(())
    }

    /// Sends a request and waits for the response with its id, no longer
    /// than [`Limits::answer`] in all. Events that arrive first are kept for
    /// [`Client::next_event`], up to [`Limits::kept_events`] of them.
    pub fn request(&mut self, body: RequestBody) -> Result<ResponseBody, ClientError> {
        self.last_id += 1;
        let id = self.last_id;
        let deadline = Instant::now() + self.limits.answer;
        self.conn
            .write_line(encode(&Request { id, body })?.trim_end())?;
        loop {
            match decode(&read_line(&self.conn, Some(deadline))?)? {
                ServerMessage::Event(_) if self.events.len() >= self.limits.kept_events => {
                    let flood = "the service sent events without end and no answer";
                    return Err(ClientError::Lost(flood.to_string()));
                }
                ServerMessage::Event(event) => self.events.push_back(event),
                ServerMessage::Response(response) if response.id == id => {
                    return match response.outcome {
                        Outcome::Ok(body) => Ok(body),
                        Outcome::Error(error) if error.code == ErrorCode::NotOwner => {
                            Err(ClientError::NotOwner)
                        }
                        Outcome::Error(error) => Err(ClientError::Refused(error)),
                    };
                }
                // An answer to a request this client no longer waits for.
                ServerMessage::Response(_) => {}
            }
        }
    }

    /// The next event: one kept while an answer was awaited, or else the
    /// next to arrive, waited for as long as it takes.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "for `connect`, which comes next")
    )]
    pub fn next_event(&mut self) -> Result<Event, ClientError> {
        loop {
            if let Some(event) = self.events.pop_front() {
                return Ok(event);
            }
            // An answer nobody waits for any more is skipped, as in `request`.
            if let ServerMessage::Event(event) = decode(&read_line(&self.conn, None)?)? {
                return Ok(event);
            }
        }
    }
}
