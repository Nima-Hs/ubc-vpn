//! Loading the service's own policy file, the only source of the gateway's
//! name and pins.

use std::fs;
use std::path::Path;

use ubc_vpn_core::policy::Policy;

/// The policy file's name inside the policy folder.
pub const FILE: &str = "policy.json";

/// Reads and validates the policy in `dir`. The error is a sentence for the
/// user and the log.
pub fn load(dir: &Path) -> Result<Policy, String> {
    let unreadable = |e: std::io::Error| format!("The policy file cannot be read: {}.", e.kind());
    let text = fs::read_to_string(dir.join(FILE)).map_err(unreadable)?;
    parse(&text)
}

/// Parses and validates a policy. The error is a sentence for the user and
/// the log.
pub fn parse(text: &str) -> Result<Policy, String> {
    let invalid = |why: String| format!("The policy file is not valid: {why}.");
    let policy: Policy =
        serde_json::from_str(text).map_err(|e| invalid(format!("line {}", e.line())))?;
    policy.validate().map_err(|e| invalid(e.to_string()))?;
    Ok(policy)
}
