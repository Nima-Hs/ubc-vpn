//! The lines between the app and `ubc-vpn bridge`.
//!
//! The app never opens the service's pipe or socket itself. It starts the
//! command-line client in bridge mode and talks to it over standard input and
//! output, one JSON message per line. The client opens the channel, which is
//! where the checks that matter live: it confirms the other end really is the
//! service before sending anything, and it opens the channel in a way that
//! does not let the other end act as the user.
//!
//! # Starting
//!
//! The bridge opens the channel and sends a
//! [`Hello`](crate::protocol::Hello) with
//! [`ClientKind::App`](crate::protocol::ClientKind::App), because it speaks
//! for the app. It then writes exactly one first [`BridgeLine`]:
//! [`Ready`](BridgeLine::Ready), or the reason there is no channel. Every
//! line other than `ready` and `server` is the bridge's last: it exits after
//! writing it.
//!
//! # While running
//!
//! - The app writes [`Request`](crate::protocol::Request)s on the bridge's
//!   standard input. The bridge forwards them unchanged, ids included, and
//!   every message from the service arrives as a [`BridgeLine::Server`].
//! - The bridge sends no requests of its own. In particular it does not claim
//!   ownership: the app sends `claim` itself.
//! - A `connect` request is not forwarded (see [`bridge_allows`]): the app
//!   must never hold a session cookie. The bridge answers it itself with a
//!   `server` line holding a response with the request's id and a
//!   `bad_request` error, and carries on. Connecting goes through
//!   `ubc-vpn connect --json`, described in [`crate::login`].
//! - A line on standard input that is longer than
//!   [`MAX_LINE_BYTES`](crate::protocol::MAX_LINE_BYTES), or is not a valid
//!   request, is a bug in the app. No id can be recovered from it, so the
//!   bridge writes [`BridgeLine::BadLine`] and exits. It never echoes the
//!   line.
//!
//! # Stopping
//!
//! - When the service goes away the bridge writes
//!   [`BridgeLine::ServiceUnavailable`] and exits. The app starts a new
//!   bridge after a pause.
//! - When standard input closes, the app has gone. The bridge closes the
//!   channel and exits without writing anything.
//!
//! The exit status is 0 when standard input closed and 1 in every other case.
//! The app acts on the last line, not on the status; an exit with no line at
//! all is treated as `service_unavailable`.
//!
//! Standard output carries nothing but these lines.

use serde::{Deserialize, Serialize};

use crate::protocol::{RequestBody, ServerMessage};

/// A line the bridge writes for the app.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub enum BridgeLine {
    /// The channel is open and the handshake succeeded. Requests may now be
    /// sent.
    Ready {
        /// The service's product version.
        service_version: String,
        /// Whether an owner has claimed the service.
        owner_claimed: bool,
    },
    /// The service is not running, or the channel closed.
    ServiceUnavailable,
    /// The service speaks a different protocol version.
    UpdateNeeded {
        /// The service's product version, to show the user.
        service_version: String,
    },
    /// Something is listening where the service should be, but it is not the
    /// service. Nothing was sent to it.
    UntrustedService,
    /// The service is running but its channel is reserved for another user of
    /// this computer, its owner. Starting a new bridge will not help.
    NotOwner,
    /// The app wrote a line that was too long or was not a valid request.
    BadLine,
    /// A message for the app: one the service sent, passed on unchanged, or
    /// the bridge's own refusal of a `connect` request.
    Server {
        /// The response or event.
        message: ServerMessage,
    },
}

/// Whether the bridge will forward a request from the app.
///
/// A `connect` carries the session cookie, and the app must never hold one,
/// so the bridge answers it with a `bad_request` error and sends nothing to
/// the service.
///
/// Every request is listed, with no catch-all, so a request added later does
/// not compile until someone decides whether the app may send it.
pub fn bridge_allows(request: &RequestBody) -> bool {
    match request {
        RequestBody::Claim | RequestBody::Status | RequestBody::Disconnect => true,
        RequestBody::Connect(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::protocol::{ConnectParams, Event, decode, encode};
    use crate::redact::Secret;
    use crate::routes::RouteSet;
    use crate::state::ConnState;

    #[test]
    fn status_lines_have_a_stable_wire_format() {
        let ready = BridgeLine::Ready {
            service_version: "0.1.0".to_string(),
            owner_claimed: true,
        };
        assert_eq!(
            encode(&ready).unwrap(),
            "{\"type\":\"ready\",\"service_version\":\"0.1.0\",\"owner_claimed\":true}\n"
        );
        let update_needed = BridgeLine::UpdateNeeded {
            service_version: "0.2.0".to_string(),
        };
        assert_eq!(
            encode(&update_needed).unwrap(),
            "{\"type\":\"update_needed\",\"service_version\":\"0.2.0\"}\n"
        );
        for (line, name) in [
            (BridgeLine::ServiceUnavailable, "service_unavailable"),
            (BridgeLine::UntrustedService, "untrusted_service"),
            (BridgeLine::NotOwner, "not_owner"),
            (BridgeLine::BadLine, "bad_line"),
        ] {
            assert_eq!(encode(&line).unwrap(), format!("{{\"type\":\"{name}\"}}\n"));
        }
    }

    #[test]
    fn service_messages_are_wrapped_unchanged() {
        let event = ServerMessage::Event(Event::StateChanged(ConnState::Connecting));
        let line = BridgeLine::Server {
            message: event.clone(),
        };
        let text = encode(&line).unwrap();
        assert!(text.starts_with("{\"type\":\"server\",\"message\":"));
        assert!(text.contains(encode(&event).unwrap().trim_end()));
        assert_eq!(decode::<BridgeLine>(&text).unwrap(), line);
    }

    // Security rule: the app must never be able to send a session cookie
    // through the bridge. Removing the check makes this test fail.
    #[test]
    fn the_bridge_refuses_connect_and_allows_the_rest() {
        let connect = RequestBody::Connect(ConnectParams {
            cookie: Secret::new("c"),
            gateway_addr: Ipv4Addr::new(192, 0, 2, 1),
            routes: RouteSet::default(),
        });
        assert!(!bridge_allows(&connect));
        for allowed in [
            RequestBody::Claim,
            RequestBody::Status,
            RequestBody::Disconnect,
        ] {
            assert!(bridge_allows(&allowed), "{allowed:?} should be forwarded");
        }
    }
}
