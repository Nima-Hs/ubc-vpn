//! Connecting and disconnecting. The state machine that opens the tunnel is
//! not built yet, so both requests are refused with an error that says so.
//! Nothing here pretends to connect.

use ubc_vpn_core::policy::Policy;
use ubc_vpn_core::protocol::{ConnectParams, ErrorCode, ErrorInfo};

/// Builds the error a request is refused with.
pub(crate) fn error(code: ErrorCode, message: impl Into<String>) -> ErrorInfo {
    let message = message.into();
    ErrorInfo { code, message }
}

/// The requests' side of the connection state machine.
pub(crate) struct Session {
    /// Why the policy is unusable, if it is.
    policy: Result<(), String>,
}

impl Session {
    pub(crate) fn start(policy: Result<Policy, String>) -> Self {
        let policy = policy.map(|_| ());
        Self { policy }
    }

    /// Refuses: with `policy_invalid` when the service has no usable policy,
    /// which stays true once connecting exists. The request, and the cookie
    /// in it, is dropped here.
    pub(crate) fn connect(&self, params: ConnectParams) -> Result<(), ErrorInfo> {
        drop(params);
        if let Err(message) = &self.policy {
            return Err(error(ErrorCode::PolicyInvalid, message));
        }
        Err(not_yet("Connecting"))
    }

    pub(crate) fn disconnect(&self) -> Result<(), ErrorInfo> {
        Err(not_yet("Disconnecting"))
    }

    /// Tears everything down at shutdown. There is nothing to tear down yet.
    pub(crate) fn stop(&self) {}
}

fn not_yet(what: &str) -> ErrorInfo {
    let message = format!("{what} is not available in this version yet.");
    error(ErrorCode::Internal, message)
}
