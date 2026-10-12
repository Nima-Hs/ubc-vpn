//! The owner, kept in `state.json` in the state folder so it survives a
//! restart and an update.
//!
//! The state folder must be writable by an admin only. Making it so is the
//! installer's job, and checking it needs OS code this crate does not have;
//! nothing here verifies who owns the folder or the file.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

use serde_json::{Value, json};
use ubc_vpn_platform::UserId;

const FILE: &str = "state.json";
const PARTIAL: &str = "state.json.tmp";

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

/// Writes the owner so that a crash or a power loss leaves either no file or
/// the whole new one: a fresh partial file, synced, then renamed into place.
pub(crate) fn save(dir: &Path, owner: &UserId) -> Result<(), String> {
    let text = json!({ "owner": owner.to_string() }).to_string();
    let write = || {
        fs::create_dir_all(dir)?;
        let partial = dir.join(PARTIAL);
        // A partial file left by a crash is removed. Anything else at that
        // name, a link above all, is not written through.
        match fs::symlink_metadata(&partial) {
            Ok(found) if found.is_file() => fs::remove_file(&partial)?,
            Ok(_) => return Err(io::Error::other("the partial state file is not a file")),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        // `create_new` fails if anything appeared there in the meantime.
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&partial)?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        drop(file);
        fs::rename(&partial, dir.join(FILE))?;
        // Makes the rename itself last, where the OS lets a folder be
        // opened and synced. Windows does not.
        if let Ok(folder) = File::open(dir) {
            let _ = folder.sync_all();
        }
        Ok(())
    };
    write().map_err(|e| format!("The owner could not be saved: {}.", e.kind()))
}
