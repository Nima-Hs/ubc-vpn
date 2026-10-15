//! The owner, kept in `state.json` in the state folder so it survives a
//! restart and an update.
//!
//! The file is read and written only through [`StateDir`], never with plain
//! file calls. On Windows that checks, before every read and write, that
//! only the system's administrators made or can change the folder and the
//! file, so a standard user who created the folder first cannot name
//! themselves the owner. It also writes a new file and moves it into place,
//! so a crash leaves the old owner or the new one.

use serde_json::{Value, json};
use ubc_vpn_platform::{StateDir, UserId};

const FILE: &str = "state.json";

/// Reads the owner. A missing file means nobody has claimed the service. A
/// file that cannot be read or understood is an error, never "no owner":
/// treating it as unclaimed would let any local user take the service over.
/// So is a state folder that fails its checks.
pub(crate) fn load(state: &StateDir) -> Result<Option<UserId>, String> {
    let bytes = match state.read(FILE) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return Ok(None),
        Err(e) => return Err(format!("The state file cannot be read: {e}.")),
    };
    let value: Option<Value> = serde_json::from_slice(&bytes).ok();
    let owner = value.as_ref().and_then(|v| v.get("owner")?.as_str());
    let owner = owner.and_then(|text| text.parse().ok());
    owner.map(Some).ok_or_else(|| {
        "The state file is damaged. An administrator must delete it to reset the owner.".to_string()
    })
}

/// Writes the owner.
pub(crate) fn save(state: &StateDir, owner: &UserId) -> Result<(), String> {
    let text = json!({ "owner": owner.to_string() }).to_string();
    let written = state.write(FILE, text.as_bytes());
    written.map_err(|e| format!("The owner could not be saved: {e}."))
}
