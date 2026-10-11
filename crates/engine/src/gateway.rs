//! The gateway an engine may talk to.
//!
//! This type lives in a file of its own so that its fields are private to
//! this file. Rust privacy is per module: code anywhere else in the crate,
//! the `libopenconnect` binding included, can obtain a [`Gateway`] only
//! through [`Gateway::from_policy`].
//!
//! **Never put an engine, the binding or any other code in this file, and
//! never widen a field's visibility.** A test fails if a field becomes
//! reachable.

use ubc_vpn_core::policy::{Pin, Policy, PolicyError};

/// The gateway an engine may talk to: a host name and the pins that identify
/// it. It always holds a valid host name and at least one pin.
///
/// The fields cannot be set or read directly:
///
/// ```compile_fail
/// fn pins(g: ubc_vpn_engine::Gateway) { let _ = &g.pins; }
/// ```
///
/// ```compile_fail
/// fn host(g: ubc_vpn_engine::Gateway) { let _ = &g.host; }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gateway {
    host: String,
    pins: Vec<Pin>,
}

impl Gateway {
    /// Takes the gateway from a policy, refusing a policy that is not valid.
    /// This is the only way to make one, so an engine is never called with a
    /// bad host name or without pins.
    pub fn from_policy(policy: &Policy) -> Result<Self, PolicyError> {
        policy.validate()?;
        Ok(Self {
            host: policy.gateway.clone(),
            pins: policy.pins.clone(),
        })
    }

    /// The gateway's host name.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The pins the gateway's key may match. Never empty.
    pub fn pins(&self) -> &[Pin] {
        &self.pins
    }

    /// Whether `key`, the hash of the key a server presented, matches a pin.
    /// An engine must refuse a server for which this is false.
    pub fn accepts(&self, key: &Pin) -> bool {
        self.pins.contains(key)
    }
}
