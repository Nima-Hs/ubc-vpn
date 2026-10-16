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
    /// How much traffic the tunnel carries: the chosen subnets and domains
    /// only, or everything. In full mode the subnets and domains are still
    /// applied, and are carried by the tunnel along with the rest.
    pub mode: TunnelMode,
}

/// How much of this machine's traffic the tunnel carries. One setting for
/// every profile.
///
/// Switching while connected keeps the VPN up and never interrupts traffic
/// to the chosen UBC subnets, and nothing leaks while it happens. A
/// connection that was open to a host outside them may be reset: its
/// packets start to leave by another way, from another address.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub enum TunnelMode {
    /// Only the chosen subnets go through the tunnel, and only names in the
    /// chosen DNS domains are resolved by UBC's DNS servers. Everything
    /// else, IPv6 included, goes over the usual network.
    #[default]
    Split,
    /// All IPv4 traffic goes through the tunnel, and every name the
    /// operating system resolves goes to UBC's DNS servers, through the
    /// tunnel. IPv6 is blocked, so programs fall back to IPv4 at once. The
    /// local network stays reachable directly: the network the computer is
    /// on, and its router.
    ///
    /// What it cannot do: a program that resolves names itself, such as a
    /// browser using DNS over HTTPS, still sends that through the tunnel
    /// but not to UBC's servers; names only the local network knows (`.lan`,
    /// `.home`) and captive portals do not resolve. mDNS, LLMNR and NetBIOS
    /// names still work.
    Full,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tunnel_modes_have_a_stable_wire_format() {
        assert_eq!(TunnelMode::default(), TunnelMode::Split);
        for (mode, word) in [
            (TunnelMode::Split, "\"split\""),
            (TunnelMode::Full, "\"full\""),
        ] {
            assert_eq!(serde_json::to_string(&mode).unwrap(), word);
            assert_eq!(serde_json::from_str::<TunnelMode>(word).unwrap(), mode);
        }
        assert!(serde_json::from_str::<TunnelMode>("\"Full\"").is_err());
        assert!(serde_json::from_str::<TunnelMode>("\"all\"").is_err());
    }

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
