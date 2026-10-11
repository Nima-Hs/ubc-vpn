//! The connection state the service reports.

use serde::{Deserialize, Serialize};

use crate::protocol::ErrorCode;
use crate::routes::Ipv4Net;

/// Where the connection stands. The service pushes a new value whenever it
/// changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub enum ConnState {
    /// No tunnel, and nothing in progress.
    Disconnected,
    /// The tunnel is being opened and its routes applied and verified.
    Connecting,
    /// The tunnel is up and its routes and DNS were verified.
    Connected {
        /// What was applied.
        tunnel: TunnelInfo,
    },
    /// The tunnel is being closed and its routes and DNS removed.
    Disconnecting,
    /// The session ended and the service will not retry by itself. The user
    /// must log in again.
    LoginNeeded,
    /// The last attempt failed. Nothing was left applied.
    Failed {
        /// What went wrong, for the app to act on.
        code: ErrorCode,
        /// What went wrong, for the user to read. Never contains a secret.
        message: String,
    },
}

/// What the service applied for a live tunnel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct TunnelInfo {
    /// The tunnel device's name, such as `utun4`.
    pub interface: String,
    /// The address the gateway assigned to this machine.
    pub address: String,
    /// The subnets routed through the tunnel.
    #[cfg_attr(test, ts(type = "Array<string>"))]
    pub subnets: Vec<Ipv4Net>,
    /// The DNS domains resolved through the tunnel.
    pub dns_domains: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn states_are_tagged_snake_case() {
        let json = serde_json::to_string(&ConnState::LoginNeeded).unwrap();
        assert_eq!(json, r#"{"state":"login_needed"}"#);

        let failed = ConnState::Failed {
            code: ErrorCode::RouteRefused,
            message: "0.0.0.0/0 is wider than /8".to_string(),
        };
        let json = serde_json::to_string(&failed).unwrap();
        assert_eq!(
            json,
            r#"{"state":"failed","code":"route_refused","message":"0.0.0.0/0 is wider than /8"}"#
        );
        assert_eq!(serde_json::from_str::<ConnState>(&json).unwrap(), failed);
    }
}
