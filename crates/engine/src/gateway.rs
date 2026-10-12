//! The gateway an engine may talk to.
//!
//! This type lives in a file of its own so that its fields are private to
//! this file. Rust privacy is per module: code anywhere else in the crate,
//! the `libopenconnect` binding included, can obtain a [`Gateway`] only
//! through [`Gateway::from_policy`], or in tests through
//! [`Gateway::for_test`], which calls it.
//!
//! **Never put an engine, the binding or any other code in this file, and
//! never widen a field's visibility.** A test fails if a field becomes
//! reachable.

use std::net::SocketAddrV4;

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
    /// Where a test gateway listens. The field does not exist in a build
    /// without the `fake` feature, so a shipped engine can only resolve
    /// `host` and use port 443.
    #[cfg(any(test, feature = "fake"))]
    test_endpoint: Option<SocketAddrV4>,
}

impl Gateway {
    /// For tests of a real engine: the policy's gateway, reached at a local
    /// test server instead of by resolving its name. The host name and the
    /// pins still come from the policy and are checked the same way; only
    /// where the connection goes changes. Anything but a loopback address
    /// is refused, so not even a development build can be pointed at
    /// another machine.
    #[cfg(any(test, feature = "fake"))]
    pub fn for_test(policy: &Policy, endpoint: SocketAddrV4) -> Result<Self, PolicyError> {
        if !endpoint.ip().is_loopback() {
            return Err(PolicyError::BadGateway);
        }
        let mut gateway = Self::from_policy(policy)?;
        gateway.test_endpoint = Some(endpoint);
        Ok(gateway)
    }

    /// The address and port to connect to instead of resolving the host name
    /// and using port 443. Always `None` without the `fake` feature:
    ///
    /// ```compile_fail
    /// # #[cfg(feature = "fake")]
    /// # compile_error!("only meaningful without the fake feature");
    /// let _ = ubc_vpn_engine::Gateway::for_test;
    /// ```
    pub fn test_endpoint(&self) -> Option<SocketAddrV4> {
        #[cfg(any(test, feature = "fake"))]
        return self.test_endpoint;
        #[cfg(not(any(test, feature = "fake")))]
        None
    }

    /// Takes the gateway from a policy, refusing a policy that is not valid.
    /// Every gateway is made through this, so an engine is never called with
    /// a bad host name or without pins.
    pub fn from_policy(policy: &Policy) -> Result<Self, PolicyError> {
        policy.validate()?;
        Ok(Self {
            host: policy.gateway.clone(),
            pins: policy.pins.clone(),
            #[cfg(any(test, feature = "fake"))]
            test_endpoint: None,
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
