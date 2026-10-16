//! The service's policy: which gateway it may connect to and how it
//! recognises it.
//!
//! The policy file is written by the installer and is writable by an admin
//! only. The service trusts nothing else for the gateway address and pins.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::routes::{Ipv4Net, is_valid_domain};

const PIN_PREFIX: &str = "pin-sha256:";
/// A SHA-256 hash in base64 is always 44 characters, the last being `=`.
const PIN_HASH_LEN: usize = 44;

/// A certificate pin: the SHA-256 hash of the gateway's public key, written
/// `pin-sha256:<base64>`.
///
/// Only full-length pins are accepted. `libopenconnect` would match a pin as
/// short as four characters, so the length is enforced here.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Pin(String);

/// Why a string is not a valid [`Pin`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinError;

impl fmt::Display for PinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("expected pin-sha256: followed by a 44-character base64 hash")
    }
}

impl std::error::Error for PinError {}

impl Pin {
    /// The pin in the form `libopenconnect` reports and accepts.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Pin {
    type Error = PinError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        let hash = s.strip_prefix(PIN_PREFIX).ok_or(PinError)?;
        let is_base64 = |b: u8| b.is_ascii_alphanumeric() || b == b'+' || b == b'/';
        let body_ok = hash.len() == PIN_HASH_LEN
            && hash.ends_with('=')
            && hash.bytes().take(PIN_HASH_LEN - 1).all(is_base64);
        if body_ok { Ok(Self(s)) } else { Err(PinError) }
    }
}

impl From<Pin> for String {
    fn from(pin: Pin) -> Self {
        pin.0
    }
}

/// The contents of `policy.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// The gateway's host name, with no scheme, port or path.
    pub gateway: String,
    /// Pins the gateway's certificate may match. More than one lets a planned
    /// certificate change happen without locking users out.
    pub pins: Vec<Pin>,
    /// When present, the only networks the user's routes may fall inside.
    /// It says nothing of full mode, which is not a route the user chose:
    /// see `full_tunnel`.
    #[serde(default)]
    pub allowed_routes: Option<Vec<Ipv4Net>>,
    /// Whether users may send all their traffic through the tunnel. Left
    /// out, they may.
    #[serde(default)]
    pub full_tunnel: FullTunnel,
}

/// What a [`Policy`] says of full mode.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FullTunnel {
    /// Users may choose it.
    #[default]
    Allowed,
    /// It is refused: at connect, on a switch, and when it would be saved.
    Forbidden,
}

/// Why a [`Policy`] is unusable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    /// The gateway is not a bare host name.
    BadGateway,
    /// There are no pins, so no certificate could ever be accepted safely.
    NoPins,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::BadGateway => "gateway must be a host name with no scheme, port or path",
            Self::NoPins => "policy must list at least one certificate pin",
        })
    }
}

impl std::error::Error for PolicyError {}

impl Policy {
    /// Checks the policy is safe to act on. The service calls this before it
    /// accepts any connection.
    pub fn validate(&self) -> Result<(), PolicyError> {
        if !is_valid_domain(&self.gateway) {
            return Err(PolicyError::BadGateway);
        }
        if self.pins.is_empty() {
            return Err(PolicyError::NoPins);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD_PIN: &str = "pin-sha256:fTzrkd+T2QOdSW5oSF7vp4M6JCp1hHMbYY2Q+IX4x5o=";

    fn pin(s: &str) -> Result<Pin, PinError> {
        Pin::try_from(s.to_string())
    }

    #[test]
    fn accepts_a_full_length_pin() {
        assert_eq!(pin(GOOD_PIN).unwrap().as_str(), GOOD_PIN);
    }

    // Security rule: a short or malformed pin must never be accepted, because
    // libopenconnect would treat it as a prefix and match many certificates.
    #[test]
    fn refuses_short_and_malformed_pins() {
        for bad in [
            "",
            "pin-sha256:",
            "pin-sha256:fTzr",
            // Short and over-long, but still ending in `=` like a real hash.
            "pin-sha256:fTz=",
            "pin-sha256:fTzrkd+T2QOdSW5oSF7vp4M6JCp1hHMbYY2Q+IX4x5oAAAA=",
            "pin-sha256:fTzrkd+T2QOdSW5oSF7vp4M6JCp1hHMbYY2Q+IX4x5o",
            "pin-sha256:fTzrkd+T2QOdSW5oSF7vp4M6JCp1hHMbYY2Q+IX4x5oA",
            "pin-sha256:fTzrkd T2QOdSW5oSF7vp4M6JCp1hHMbYY2Q+IX4x5o=",
            "sha256:fTzrkd+T2QOdSW5oSF7vp4M6JCp1hHMbYY2Q+IX4x5o=",
            "fTzrkd+T2QOdSW5oSF7vp4M6JCp1hHMbYY2Q+IX4x5o=",
        ] {
            assert_eq!(pin(bad), Err(PinError), "{bad:?} must be refused");
        }
    }

    fn policy(gateway: &str, pins: &[&str]) -> Policy {
        Policy {
            gateway: gateway.to_string(),
            pins: pins.iter().map(|p| pin(p).unwrap()).collect(),
            allowed_routes: None,
            full_tunnel: FullTunnel::Allowed,
        }
    }

    // Full mode is allowed unless the policy says otherwise, and the policy
    // says so with exactly these words.
    #[test]
    fn full_mode_is_allowed_unless_forbidden() {
        let json =
            |extra: &str| format!(r#"{{"gateway":"myvpn.ubc.ca","pins":["{GOOD_PIN}"]{extra}}}"#);
        let read = |extra| serde_json::from_str::<Policy>(&json(extra));
        assert_eq!(read("").unwrap().full_tunnel, FullTunnel::Allowed);
        let allowed = read(r#","full_tunnel":"allowed""#).unwrap();
        assert_eq!(allowed.full_tunnel, FullTunnel::Allowed);
        let forbidden = read(r#","full_tunnel":"forbidden""#).unwrap();
        assert_eq!(forbidden.full_tunnel, FullTunnel::Forbidden);
        assert!(read(r#","full_tunnel":true"#).is_err());
        assert!(read(r#","full_tunnel":"Forbidden""#).is_err());
    }

    #[test]
    fn validates_a_normal_policy() {
        assert_eq!(policy("myvpn.ubc.ca", &[GOOD_PIN]).validate(), Ok(()));
    }

    #[test]
    fn refuses_a_gateway_that_is_not_a_bare_host() {
        for bad in [
            "",
            "https://myvpn.ubc.ca",
            "myvpn.ubc.ca/path",
            "a b",
            "host:443",
            ".",
            "..",
            "a..b",
            "-oProxyCommand",
            "localhost",
            "MyVPN.ubc.ca",
            "198.19.1.1",
        ] {
            assert_eq!(
                policy(bad, &[GOOD_PIN]).validate(),
                Err(PolicyError::BadGateway),
                "{bad:?} must be refused"
            );
        }
    }

    // Security rule: a policy with no pins must be unusable.
    #[test]
    fn refuses_a_policy_with_no_pins() {
        assert_eq!(
            policy("myvpn.ubc.ca", &[]).validate(),
            Err(PolicyError::NoPins)
        );
    }

    #[test]
    fn parses_the_file_format_and_rejects_unknown_fields() {
        let json = format!(r#"{{"gateway":"myvpn.ubc.ca","pins":["{GOOD_PIN}"]}}"#);
        let parsed: Policy = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, policy("myvpn.ubc.ca", &[GOOD_PIN]));

        let extra = format!(r#"{{"gateway":"g.ca","pins":["{GOOD_PIN}"],"owner":"x"}}"#);
        assert!(serde_json::from_str::<Policy>(&extra).is_err());
        assert!(
            serde_json::from_str::<Policy>(r#"{"gateway":"g.ca","pins":["pin-sha256:ab"]}"#)
                .is_err()
        );
    }
}
