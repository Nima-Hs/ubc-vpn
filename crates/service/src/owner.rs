//! The owner, kept in `state.json` in the state folder so it survives a
//! restart and an update.

use std::fs;
use std::io;
use std::path::Path;

use serde_json::{Value, json};
use ubc_vpn_platform::UserId;

const FILE: &str = "state.json";

/// Reads the owner. A missing file means nobody has claimed the service. A
/// file that cannot be read or understood is an error, never "no owner":
/// treating it as unclaimed would let any local user take the service over.
pub(crate) fn load(dir: &Path) -> Result<Option<UserId>, String> {
    let text = match fs::read_to_string(dir.join(FILE)) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("The state file cannot be read: {}.", e.kind())),
    };
    let value: Option<Value> = serde_json::from_str(&text).ok();
    let owner = value.as_ref().and_then(|v| v.get("owner")?.as_str());
    let owner = owner.and_then(|text| text.parse().ok());
    owner.map(Some).ok_or_else(|| {
        "The state file is damaged. An administrator must delete it to reset the owner.".to_string()
    })
}

/// Writes the owner, replacing the file in one step so a crash leaves either
/// the old content or the new.
pub(crate) fn save(dir: &Path, owner: &UserId) -> Result<(), String> {
    let text = json!({ "owner": owner.to_string() }).to_string();
    let write = || {
        fs::create_dir_all(dir)?;
        let partial = dir.join("state.json.tmp");
        fs::write(&partial, text)?;
        fs::rename(partial, dir.join(FILE))
    };
    write().map_err(|e| format!("The owner could not be saved: {}.", e.kind()))
}
