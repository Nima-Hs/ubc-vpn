//! The lines between the app and `ubc-vpn bridge`.
//!
//! The app never opens the service's pipe or socket itself. It starts the
//! command-line client in bridge mode and talks to it over standard input and
//! output, one JSON message per line. The client opens the channel, which is
//! where the checks that matter live: it confirms the other end really is the
//! service before sending anything, and it opens the channel in a way that
//! does not let the other end act as the user.
//!
//! - The client writes [`BridgeLine`]s on its standard output. The first one
//!   says whether the channel is ready; if it is not, it is also the last.
//! - Once ready, the app writes [`Request`](crate::protocol::Request)s on the
//!   client's standard input, and every message from the service arrives as a
//!   [`BridgeLine::Server`].
//! - The bridge refuses a `connect` request (see [`bridge_allows`]): the app
//!   must never hold a session cookie. Connecting goes through
//!   `ubc-vpn connect --json`, described in [`crate::login`].
//! - When the service goes away the client writes
//!   [`BridgeLine::ServiceUnavailable`] and exits. The app starts a new bridge
//!   after a pause.

use serde::{Deserialize, Serialize};

use crate::protocol::{RequestBody, ServerMessage};

/// A line the bridge writes for the app.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub enum BridgeLine {
    /// The channel is open and the handshake succeeded. Always the first line
    /// when it comes at all. Requests may now be sent.
    Ready {
        /// The service's product version.
        service_version: String,
        /// Whether an owner has claimed the service.
        owner_claimed: bool,
    },
    /// The service is not running, or the channel closed. The bridge exits
    /// after this line.
    ServiceUnavailable,
    /// The service speaks a different protocol version. The bridge exits
    /// after this line.
    UpdateNeeded {
        /// The service's product version, to show the user.
        service_version: String,
    },
    /// Something is listening where the service should be, but it is not the
    /// service. Nothing was sent to it. The bridge exits after this line.
    UntrustedService,
    /// A message from the service, passed on unchanged.
    Server {
        /// The response or event.
        message: ServerMessage,
    },
}

/// Whether the bridge will forward a request from the app.
///
/// Everything but `connect` is forwarded. A `connect` carries the session
/// cookie, and the app must never hold one, so the bridge answers it with a
/// `bad_request` error and sends nothing to the service.
pub fn bridge_allows(request: &RequestBody) -> bool {
    !matches!(request, RequestBody::Connect(_))
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
        assert_eq!(
            encode(&BridgeLine::ServiceUnavailable).unwrap(),
            "{\"type\":\"service_unavailable\"}\n"
        );
        assert_eq!(
            encode(&BridgeLine::UntrustedService).unwrap(),
            "{\"type\":\"untrusted_service\"}\n"
        );
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
