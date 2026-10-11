//! The channel protocol between a client (the app or the command-line client)
//! and the service.
//!
//! Messages are JSON, one per line. The client opens with a [`Hello`] and the
//! service answers with a [`HelloReply`]. After that the client sends
//! [`Request`]s and the service sends [`ServerMessage`]s: one response per
//! request, plus events whenever the connection state changes.
//!
//! This module is the reference for the wire format. The TypeScript types the
//! app uses are generated from it.

use std::fmt;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::redact::Secret;
use crate::routes::RouteSet;
use crate::state::ConnState;

/// Bumped whenever the wire format changes in a way an older peer could not
/// understand. A client and a service with different versions refuse to talk.
pub const PROTOCOL_VERSION: u32 = 1;

/// The longest line either side accepts, newline included. The service drops a
/// connection that sends more.
pub const MAX_LINE_BYTES: usize = 64 * 1024;

/// Which program is on the client end.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub enum ClientKind {
    /// The Electron app.
    App,
    /// The command-line client.
    Cli,
}

/// The first line a client sends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct Hello {
    /// The client's [`PROTOCOL_VERSION`].
    pub protocol_version: u32,
    /// Which program is connecting.
    pub client: ClientKind,
    /// The client's product version, for logs and "please update" messages.
    pub client_version: String,
}

/// The service's answer to a [`Hello`]. It is sent even when the versions
/// differ, so the client can explain why the connection is then closed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct HelloReply {
    /// The service's [`PROTOCOL_VERSION`].
    pub protocol_version: u32,
    /// The service's product version.
    pub service_version: String,
    /// Whether an owner has claimed the service. Until one has, the only
    /// request the service accepts is `claim`.
    pub owner_claimed: bool,
}

impl HelloReply {
    /// Whether the two sides can talk.
    pub fn is_compatible(&self) -> bool {
        self.protocol_version == PROTOCOL_VERSION
    }
}

/// A request from a client. The service answers with a [`Response`] carrying
/// the same `id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct Request {
    /// Chosen by the client and echoed in the response.
    pub id: u32,
    /// What is being asked.
    pub body: RequestBody,
}

/// What a client can ask for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "method", content = "params", rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub enum RequestBody {
    /// Become the owner. Accepted from any local user while no owner exists,
    /// and from the owner afterwards; refused for everyone else.
    Claim,
    /// Report the current connection state.
    Status,
    /// Open the tunnel with a session cookie obtained by logging in.
    Connect(ConnectParams),
    /// Close the tunnel and remove its routes and DNS.
    Disconnect,
}

/// What the service needs to open a tunnel.
///
/// The gateway and its certificate pins are deliberately absent: the service
/// takes those from its own policy file and from nowhere else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct ConnectParams {
    /// The session cookie the gateway issued at login.
    pub cookie: Secret,
    /// The subnets and DNS domains to send through the tunnel.
    pub routes: RouteSet,
}

/// Anything the service sends after the handshake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub enum ServerMessage {
    /// The answer to one request.
    Response(Response),
    /// Something that happened without being asked for.
    Event(Event),
}

/// The answer to the [`Request`] with the same `id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct Response {
    /// The `id` of the request being answered.
    pub id: u32,
    /// Whether it worked.
    pub outcome: Outcome,
}

/// Success or failure of a request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", content = "value", rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub enum Outcome {
    /// The request was carried out or accepted.
    Ok(ResponseBody),
    /// The request was refused or failed.
    Error(ErrorInfo),
}

/// What a successful request returns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub enum ResponseBody {
    /// The caller is now, or already was, the owner.
    Claimed,
    /// The current connection state.
    Status(ConnState),
    /// The request was accepted. Progress follows as [`Event`]s.
    Accepted,
}

/// Something the service reports without being asked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub enum Event {
    /// The connection state changed.
    StateChanged(ConnState),
}

/// Why a request failed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct ErrorInfo {
    /// For the client to act on.
    pub code: ErrorCode,
    /// For the user to read. Never contains a secret.
    pub message: String,
}

/// The kinds of failure a client can act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub enum ErrorCode {
    /// The caller is not the owner.
    NotOwner,
    /// No owner exists yet, and the request was not `claim`.
    NotClaimed,
    /// The client and the service speak different protocol versions.
    ProtocolMismatch,
    /// The message could not be understood.
    BadRequest,
    /// The service refused one of the chosen routes or DNS domains.
    RouteRefused,
    /// The gateway's certificate matched none of the policy's pins.
    PinMismatch,
    /// The session is no longer valid. The user must log in again.
    LoginNeeded,
    /// The VPN engine could not open or keep the tunnel.
    EngineFailed,
    /// Routes or DNS could not be confirmed, so everything was removed.
    VerificationFailed,
    /// Another connect or disconnect is still in progress.
    Busy,
    /// The service's policy file is missing or unusable.
    PolicyInvalid,
    /// Something unexpected went wrong inside the service.
    Internal,
}

/// Why a line could not be written or read.
#[derive(Debug)]
pub enum FrameError {
    /// The line is longer than [`MAX_LINE_BYTES`].
    TooLong,
    /// The line is not the expected JSON.
    Json(serde_json::Error),
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong => write!(f, "line is longer than {MAX_LINE_BYTES} bytes"),
            // serde_json's message can quote the input, which may hold a
            // secret, so only the position is reported.
            Self::Json(e) => write!(f, "invalid message at column {}", e.column()),
        }
    }
}

impl std::error::Error for FrameError {}

/// Turns a message into one line, newline included.
pub fn encode<T: Serialize>(message: &T) -> Result<String, FrameError> {
    let mut line = serde_json::to_string(message).map_err(FrameError::Json)?;
    line.push('\n');
    if line.len() > MAX_LINE_BYTES {
        return Err(FrameError::TooLong);
    }
    Ok(line)
}

/// Reads a message from one line, with or without its newline.
///
/// The length is checked before any parsing, so an oversized line costs
/// nothing to refuse.
pub fn decode<T: DeserializeOwned>(line: &str) -> Result<T, FrameError> {
    if line.len() > MAX_LINE_BYTES {
        return Err(FrameError::TooLong);
    }
    serde_json::from_str(line.trim_end_matches(['\r', '\n'])).map_err(FrameError::Json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::Ipv4Net;

    fn connect() -> Request {
        Request {
            id: 7,
            body: RequestBody::Connect(ConnectParams {
                cookie: Secret::new("s3cr3t-cookie"),
                routes: RouteSet {
                    subnets: vec!["142.103.0.0/16".parse::<Ipv4Net>().unwrap()],
                    dns_domains: vec!["ece.ubc.ca".to_string()],
                },
            }),
        }
    }

    #[test]
    fn request_wire_format_is_stable() {
        let line = encode(&connect()).unwrap();
        assert_eq!(
            line,
            concat!(
                r#"{"id":7,"body":{"method":"connect","params":{"cookie":"s3cr3t-cookie","#,
                r#""routes":{"subnets":["142.103.0.0/16"],"dns_domains":["ece.ubc.ca"]}}}}"#,
                "\n"
            )
        );
        assert_eq!(decode::<Request>(&line).unwrap(), connect());
    }

    #[test]
    fn unit_requests_have_no_params() {
        let line = encode(&Request {
            id: 1,
            body: RequestBody::Status,
        })
        .unwrap();
        assert_eq!(line, "{\"id\":1,\"body\":{\"method\":\"status\"}}\n");
    }

    #[test]
    fn server_messages_round_trip() {
        let messages = [
            ServerMessage::Response(Response {
                id: 1,
                outcome: Outcome::Ok(ResponseBody::Status(ConnState::Disconnected)),
            }),
            ServerMessage::Response(Response {
                id: 2,
                outcome: Outcome::Error(ErrorInfo {
                    code: ErrorCode::NotOwner,
                    message: "only the owner may do this".to_string(),
                }),
            }),
            ServerMessage::Event(Event::StateChanged(ConnState::Connecting)),
        ];
        for message in messages {
            let line = encode(&message).unwrap();
            assert_eq!(decode::<ServerMessage>(&line).unwrap(), message);
        }
    }

    // Security rule: the service accepts exactly the expected fields. A request
    // must not be able to smuggle in a gateway or a pin.
    #[test]
    fn requests_with_unknown_fields_are_refused() {
        let smuggled = [
            r#"{"id":1,"body":{"method":"status"},"gateway":"evil.example"}"#,
            r#"{"id":1,"body":{"method":"connect","params":{"cookie":"c","routes":{"subnets":[]},"gateway":"evil.example"}}}"#,
            r#"{"id":1,"body":{"method":"connect","params":{"cookie":"c","routes":{"subnets":[],"pins":[]}}}}"#,
            r#"{"protocol_version":1,"client":"app","client_version":"0.1.0","owner":"me"}"#,
        ];
        assert!(decode::<Request>(smuggled[0]).is_err());
        assert!(decode::<Request>(smuggled[1]).is_err());
        assert!(decode::<Request>(smuggled[2]).is_err());
        assert!(decode::<Hello>(smuggled[3]).is_err());
    }

    #[test]
    fn unknown_methods_are_refused() {
        assert!(decode::<Request>(r#"{"id":1,"body":{"method":"set_gateway"}}"#).is_err());
    }

    // Security rule: an oversized line is refused before it is parsed.
    #[test]
    fn oversized_lines_are_refused() {
        let huge = format!(r#"{{"id":1,"pad":"{}"}}"#, "x".repeat(MAX_LINE_BYTES));
        assert!(matches!(decode::<Request>(&huge), Err(FrameError::TooLong)));

        let big_cookie = Request {
            id: 1,
            body: RequestBody::Connect(ConnectParams {
                cookie: Secret::new("x".repeat(MAX_LINE_BYTES)),
                routes: RouteSet::default(),
            }),
        };
        assert!(matches!(encode(&big_cookie), Err(FrameError::TooLong)));
    }

    // Security rule: neither a request's debug output nor a decode error may
    // reveal the cookie.
    #[test]
    fn the_cookie_never_reaches_debug_output_or_errors() {
        assert!(!format!("{:?}", connect()).contains("s3cr3t-cookie"));

        let broken = r#"{"id":1,"body":{"method":"connect","params":{"cookie":"s3cr3t-cookie","routes":7}}}"#;
        let error = decode::<Request>(broken).unwrap_err();
        assert!(!error.to_string().contains("s3cr3t-cookie"));
        assert!(!format!("{error}").contains("cookie"));
    }

    #[test]
    fn hello_reply_reports_compatibility() {
        let reply = |v| HelloReply {
            protocol_version: v,
            service_version: "0.1.0".to_string(),
            owner_claimed: true,
        };
        assert!(reply(PROTOCOL_VERSION).is_compatible());
        assert!(!reply(PROTOCOL_VERSION + 1).is_compatible());
    }
}
