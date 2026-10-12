//! The client side of the channel: connecting, the handshake, matching each
//! response to its request, and receiving events. Every command uses this.

use std::collections::VecDeque;
use std::time::Duration;

use ubc_vpn_core::VERSION;
use ubc_vpn_core::protocol::{
    ClientKind, ErrorCode, ErrorInfo, Event, FrameError, Hello, HelloReply, Outcome,
    PROTOCOL_VERSION, Request, RequestBody, ResponseBody, ServerMessage, decode, encode,
};
use ubc_vpn_platform::{Connection, Error, Transport};

/// How long the service may take to answer, so a stuck service cannot hang
/// the command. Requests are answered at once; progress arrives as events.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(10);

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
    /// The service speaks another protocol version. Holds its product version.
    Mismatch(String),
    /// The service refused or failed the request.
    Refused(ErrorInfo),
    /// The connection broke or the service sent something unreadable.
    Lost(String),
}

impl From<Error> for ClientError {
    fn from(error: Error) -> Self {
        match error {
            Error::NotFound => Self::NotRunning,
            Error::PermissionDenied => Self::NotOwner,
            Error::NotTheService => Self::NotTheService,
            other => Self::Lost(other.to_string()),
        }
    }
}

impl From<FrameError> for ClientError {
    fn from(error: FrameError) -> Self {
        Self::Lost(error.to_string())
    }
}

/// A connection to the service, after the handshake.
pub struct Client {
    conn: Connection,
    owner_claimed: bool,
    last_id: u32,
    /// Events that arrived while a response was being waited for.
    events: VecDeque<Event>,
}

impl Client {
    /// Connects to the service listening on `name` and says hello.
    pub fn connect(
        transport: &dyn Transport,
        name: &str,
        kind: ClientKind,
    ) -> Result<Self, ClientError> {
        Self::over(transport.connect(name)?, kind)
    }

    /// Says hello on a connection that is already open.
    pub fn over(conn: Connection, client: ClientKind) -> Result<Self, ClientError> {
        conn.set_read_timeout(Some(ANSWER_TIMEOUT))?;
        conn.set_write_timeout(Some(ANSWER_TIMEOUT))?;
        let hello = Hello {
            protocol_version: PROTOCOL_VERSION,
            client,
            client_version: VERSION.to_string(),
        };
        conn.write_line(encode(&hello)?.trim_end())?;
        let closed = || ClientError::Lost("the service closed the connection".to_string());
        let reply: HelloReply = decode(&conn.read_line()?.ok_or_else(closed)?)?;
        if !reply.is_compatible() {
            return Err(ClientError::Mismatch(reply.service_version));
        }
        Ok(Self {
            conn,
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

    /// Sends a request and waits for the response with its id. Events that
    /// arrive first are kept for [`Client::next_event`].
    pub fn request(&mut self, body: RequestBody) -> Result<ResponseBody, ClientError> {
        self.last_id += 1;
        let id = self.last_id;
        self.conn
            .write_line(encode(&Request { id, body })?.trim_end())?;
        loop {
            match self.read()? {
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

    /// Waits, for as long as it takes, for the next event.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "for `connect`, which comes next")
    )]
    pub fn next_event(&mut self) -> Result<Event, ClientError> {
        if let Some(event) = self.events.pop_front() {
            return Ok(event);
        }
        self.conn.set_read_timeout(None)?;
        let message = self.read();
        self.conn.set_read_timeout(Some(ANSWER_TIMEOUT))?;
        match message? {
            ServerMessage::Event(event) => Ok(event),
            ServerMessage::Response(_) => Err(ClientError::Lost("unexpected response".to_string())),
        }
    }

    fn read(&mut self) -> Result<ServerMessage, ClientError> {
        let closed = || ClientError::Lost("the service closed the connection".to_string());
        Ok(decode(&self.conn.read_line()?.ok_or_else(closed)?)?)
    }
}
