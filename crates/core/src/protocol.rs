//! The channel protocol between a client and the service.
//!
//! The client is always the command-line client. It opens the channel for
//! itself, or for the app when run as `ubc-vpn bridge` (see
//! [`crate::bridge`]); the app never opens the channel.
//!
//! Messages are JSON, one per line. The client opens with a [`Hello`] and the
//! service answers with a [`HelloReply`]. After that the client sends
//! [`Request`]s and the service sends [`ServerMessage`]s: one response per
//! request, plus events whenever the connection state changes.
//!
//! This module is the reference for the wire format. The TypeScript types the
//! app uses are generated from it.
//!
//! # Changing the protocol
//!
//! Requests refuse unknown fields and every enum is closed, so an older peer
//! cannot read a message that uses anything new. Any change to these types,
//! including adding a variant or a field, must bump [`PROTOCOL_VERSION`]. That
//! is cheap, because the app and the service are installed together.
//!
//! So that a mismatch gives a clear "please update" and not a dropped
//! connection, the service reads only the version from the first line with
//! [`peek_protocol_version`], which tolerates fields it does not know. It
//! always answers with a [`HelloReply`], and parses the [`Hello`] strictly only
//! when the versions match.

use std::fmt;
use std::net::Ipv4Addr;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::redact::Secret;
use crate::routes::{Ipv4Net, RouteSet};
use crate::state::ConnState;

/// Bumped whenever the wire format changes in a way an older peer could not
/// understand. A client and a service with different versions refuse to talk.
pub const PROTOCOL_VERSION: u32 = 2;

/// The longest line either side accepts, newline included. The service drops a
/// connection that sends more.
pub const MAX_LINE_BYTES: usize = 64 * 1024;

/// Which program the client end is working for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub enum ClientKind {
    /// The Electron app, through `ubc-vpn bridge`.
    App,
    /// The command-line client run by itself, or to log in and connect.
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
#[serde(
    tag = "method",
    content = "params",
    rename_all = "snake_case",
    deny_unknown_fields
)]
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
/// The gateway's name and its certificate pins are deliberately absent: the
/// service takes those from its own policy file and from nowhere else. The
/// one thing a client does supply is which of the gateway's addresses issued
/// the cookie, and that is an untrusted hint; see
/// [`ConnectParams::gateway_addr`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct ConnectParams {
    /// The session cookie the gateway issued at login.
    pub cookie: Secret,
    /// Which of the gateway's addresses issued the cookie. A gateway behind a
    /// load balancer has several, and the cookie is only good at this one.
    ///
    /// This comes from an unprivileged client, so the service treats it as a
    /// hint about where to connect and nothing more: it refuses addresses that
    /// cannot be a gateway (see [`is_plausible_gateway_addr`]), and whatever
    /// answers there must still present a key that matches a pin in the
    /// service's own policy before anything is sent to it.
    #[cfg_attr(test, ts(type = "string"))]
    pub gateway_addr: Ipv4Addr,
    /// The subnets and DNS domains to send through the tunnel.
    pub routes: RouteSet,
}

/// Whether an address could be a VPN gateway at all.
///
/// The service calls this on [`ConnectParams::gateway_addr`] before it opens
/// any connection. It refuses the same reserved ranges that routes may not
/// touch ("this network", loopback, link-local, multicast, and the reserved
/// block that includes broadcast), so a client cannot aim the privileged
/// service at the machine's loopback or at a whole network segment.
///
/// It does not make an address trusted: the certificate pin does that. And it
/// cannot know this machine's own addresses, so the service must also refuse
/// its own interface addresses and the tunnel's address, and must add the
/// route to the gateway only after the pin has matched.
pub fn is_plausible_gateway_addr(addr: Ipv4Addr) -> bool {
    Ipv4Net::new(addr, 32).is_ok_and(|host| !host.is_reserved())
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
    /// The gateway could not be reached over the network.
    GatewayUnreachable,
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
///
/// It deliberately does not keep `serde_json`'s own error. That error's text
/// can quote the input, and the input may hold a cookie or a password, so only
/// the kind of problem and its position survive. Both `Display` and `Debug` are
/// therefore safe to log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// The line is longer than [`MAX_LINE_BYTES`].
    TooLong,
    /// The line is not the expected JSON.
    Invalid {
        /// What kind of problem it was.
        kind: InvalidKind,
        /// The column where parsing stopped, counted from 1.
        column: usize,
    },
}

/// What was wrong with a line that is not the expected JSON.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidKind {
    /// Not JSON at all, or cut short.
    Syntax,
    /// Valid JSON of the wrong shape: a wrong type, an unknown field or method,
    /// or a value that failed validation.
    Shape,
}

impl From<serde_json::Error> for FrameError {
    fn from(e: serde_json::Error) -> Self {
        let kind = match e.classify() {
            serde_json::error::Category::Data => InvalidKind::Shape,
            _ => InvalidKind::Syntax,
        };
        Self::Invalid {
            kind,
            column: e.column(),
        }
    }
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong => write!(f, "line is longer than {MAX_LINE_BYTES} bytes"),
            Self::Invalid {
                kind: InvalidKind::Syntax,
                column,
            } => write!(f, "message is not valid JSON at column {column}"),
            Self::Invalid {
                kind: InvalidKind::Shape,
                column,
            } => write!(f, "message has an unexpected shape at column {column}"),
        }
    }
}

impl std::error::Error for FrameError {}

/// Turns a message into one line, newline included.
pub fn encode<T: Serialize>(message: &T) -> Result<String, FrameError> {
    let mut line = serde_json::to_string(message)?;
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
    Ok(serde_json::from_str(line.trim_end_matches(['\r', '\n']))?)
}

/// Reads only the protocol version from a client's first line.
///
/// Unlike [`decode`] of a [`Hello`], this ignores every other field, so the
/// service can tell a newer or older client "please update" even when it
/// cannot read the rest of that client's `Hello`.
pub fn peek_protocol_version(line: &str) -> Result<u32, FrameError> {
    #[derive(Deserialize)]
    struct VersionOnly {
        protocol_version: u32,
    }
    Ok(decode::<VersionOnly>(line)?.protocol_version)
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
                gateway_addr: Ipv4Addr::new(192, 0, 2, 1),
                routes: RouteSet {
                    subnets: vec!["142.103.0.0/16".parse::<Ipv4Net>().unwrap()],
                    dns_domains: vec!["ece.ubc.ca".to_string()],
                },
            }),
        }
    }

    #[test]
    fn request_wire_format_is_stable() {
        // If the snapshot below has to change, so does this number: an older
        // peer could no longer read the message.
        assert_eq!(PROTOCOL_VERSION, 2);
        let line = encode(&connect()).unwrap();
        assert_eq!(
            line,
            concat!(
                r#"{"id":7,"body":{"method":"connect","params":{"cookie":"s3cr3t-cookie","gateway_addr":"192.0.2.1","#,
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
    // must not be able to smuggle in a gateway name or a pin.
    #[test]
    fn requests_with_unknown_fields_are_refused() {
        let smuggled = [
            r#"{"id":1,"body":{"method":"status"},"gateway":"evil.example"}"#,
            r#"{"id":1,"body":{"method":"connect","params":{"cookie":"c","gateway_addr":"192.0.2.1","routes":{"subnets":[]},"gateway":"evil.example"}}}"#,
            r#"{"id":1,"body":{"method":"connect","params":{"cookie":"c","gateway_addr":"192.0.2.1","routes":{"subnets":[],"pins":[]}}}}"#,
            r#"{"protocol_version":1,"client":"app","client_version":"0.1.0","owner":"me"}"#,
        ];
        assert!(decode::<Request>(smuggled[0]).is_err());
        assert!(decode::<Request>(smuggled[1]).is_err());
        assert!(decode::<Request>(smuggled[2]).is_err());
        assert!(decode::<Hello>(smuggled[3]).is_err());

        // Beside the method, where a `deny_unknown_fields` on the outer struct
        // alone would not reach.
        let beside_method = [
            r#"{"id":1,"body":{"method":"status","gateway":"evil.example"}}"#,
            r#"{"id":1,"body":{"method":"connect","params":{"cookie":"c","gateway_addr":"192.0.2.1","routes":{"subnets":[]}},"pins":["x"]}}"#,
        ];
        for line in beside_method {
            assert!(decode::<Request>(line).is_err(), "{line} must be refused");
        }
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
                gateway_addr: Ipv4Addr::new(192, 0, 2, 1),
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

        // In each of these the secret sits where another type is expected,
        // which is exactly when serde_json quotes the offending value in its
        // own error message.
        let broken = [
            r#"{"id":"s3cr3t-cookie","body":{"method":"status"}}"#,
            r#"{"id":1,"body":{"method":"connect","params":{"cookie":"x","gateway_addr":"192.0.2.1","routes":"s3cr3t-cookie"}}}"#,
            r#"{"id":1,"body":{"method":"s3cr3t-cookie"}}"#,
            r#"{"id":1,"body":{"method":"status"},"s3cr3t-cookie":1}"#,
        ];
        for line in broken {
            let error = decode::<Request>(line).unwrap_err();
            assert!(
                matches!(
                    error,
                    FrameError::Invalid {
                        kind: InvalidKind::Shape,
                        ..
                    }
                ),
                "{line} should be a shape error, got {error:?}"
            );
            for shown in [format!("{error}"), format!("{error:?}")] {
                assert!(!shown.contains("s3cr3t"), "{shown} reveals the input");
            }
        }
    }

    #[test]
    fn syntax_and_shape_errors_are_told_apart() {
        assert!(matches!(
            decode::<Request>("{not json"),
            Err(FrameError::Invalid {
                kind: InvalidKind::Syntax,
                ..
            })
        ));
        assert!(matches!(
            decode::<Request>(r#"{"id":1}"#),
            Err(FrameError::Invalid {
                kind: InvalidKind::Shape,
                ..
            })
        ));
    }

    // A client from another version must still get a "please update" answer,
    // so its version is readable even when the rest of its hello is not.
    #[test]
    fn the_version_is_readable_from_a_hello_this_version_cannot_parse() {
        let future =
            r#"{"protocol_version":2,"client":"tray","client_version":"9.0.0","new":true}"#;
        assert!(decode::<Hello>(future).is_err());
        assert_eq!(peek_protocol_version(future).unwrap(), 2);
        assert!(peek_protocol_version(r#"{"client":"app"}"#).is_err());
    }

    // Security rule: the service must not be aimed at itself, at a network
    // segment, or at a non-address. Weakening the check, or removing any
    // range from the reserved list in routes.rs, makes
    // this test fail.
    #[test]
    fn implausible_gateway_addresses_are_refused() {
        for bad in [
            "0.0.0.0",
            "0.1.2.3",
            "127.0.0.1",
            "169.254.1.1",
            "224.0.0.1",
            "239.255.255.255",
            "240.0.0.1",
            "255.255.255.255",
        ] {
            let addr: Ipv4Addr = bad.parse().unwrap();
            assert!(!is_plausible_gateway_addr(addr), "{bad} must be refused");
        }
        for good in [
            "142.103.1.1",
            "10.0.0.1",
            "192.168.1.1",
            "1.1.1.1",
            "223.255.255.254",
        ] {
            let addr: Ipv4Addr = good.parse().unwrap();
            assert!(is_plausible_gateway_addr(addr), "{good} must be accepted");
        }
    }

    #[test]
    fn a_connect_request_needs_a_well_formed_gateway_address() {
        let without = r#"{"id":1,"body":{"method":"connect","params":{"cookie":"c","routes":{"subnets":[]}}}}"#;
        assert!(decode::<Request>(without).is_err());
        for bad in ["myvpn.ubc.ca", "::1", "1.2.3", "1.2.3.4:443", ""] {
            let line = format!(
                r#"{{"id":1,"body":{{"method":"connect","params":{{"cookie":"c","gateway_addr":"{bad}","routes":{{"subnets":[]}}}}}}}}"#
            );
            assert!(decode::<Request>(&line).is_err(), "{bad:?} must be refused");
        }
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
