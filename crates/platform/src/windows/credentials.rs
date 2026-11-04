//! Saved passwords in Windows Credential Manager, kept on this computer.
//!
//! The `keyring` crate hard-codes `CRED_PERSIST_ENTERPRISE`, so on a domain
//! with roaming profiles each entry would follow the user to other computers.
//! This store writes `CRED_PERSIST_LOCAL_MACHINE` instead, and otherwise keeps
//! the entries as that crate did, so what it saved is still found: the target
//! name is `{account}.{service}`, the type `CRED_TYPE_GENERIC`, the username
//! the account, and the value little-endian UTF-16 with no terminator.
//!
//! - **Entries the old code saved are moved** on the first use in each run
//!   ([`Store::settle`]). The entry is rewritten in place at the new type with
//!   `CRED_PRESERVE_CREDENTIAL_BLOB`, and read back. It is never deleted
//!   first: a failure leaves the old entry as it was, to be tried again in the
//!   next run, and neither loses the password nor gets in the way of a login.
//! - **What the OS returns is wiped** before it is given back, and so is
//!   anything made from a password here.
//! - **Errors are fixed text.** No OS message or code gets out of this module.
//!
//! What this does not change: any program running as the user, and any
//! administrator, can still get at the entries, as with any other credential
//! of the user's. A copy that already roamed to another computer cannot be
//! recalled from here.

use std::ptr::null_mut;

use ubc_vpn_core::redact::Secret;
use windows_sys::Win32::Foundation::{
    ERROR_INVALID_FLAGS, ERROR_INVALID_PARAMETER, ERROR_NO_SUCH_LOGON_SESSION, ERROR_NOT_FOUND,
    FILETIME, GetLastError,
};
use windows_sys::Win32::Security::Credentials::{
    CRED_PERSIST_LOCAL_MACHINE, CRED_PERSIST_NONE, CRED_PERSIST_SESSION,
    CRED_PRESERVE_CREDENTIAL_BLOB, CRED_TYPE_GENERIC, CRED_TYPE_MAXIMUM, CREDENTIALW, CredDeleteW,
    CredFree, CredGetSessionTypes, CredReadW, CredWriteW,
};
use zeroize::{Zeroize, Zeroizing};

use super::{Store, failed};
use crate::{Error, Result};

/// What an OS call answers: its result, or the code `GetLastError` gave.
type Os<T> = std::result::Result<T, u32>;

/// Credential Manager, under one service name.
pub(super) struct Credentials {
    service: String,
    /// `CredWriteW`, or what a test has in its place to make a write fail.
    write: fn(&CREDENTIALW, u32) -> Os<()>,
    /// The longest a generic credential may be kept in this logon session.
    limit: fn() -> Os<u32>,
}

impl Credentials {
    pub(super) fn new(service: &str) -> Self {
        Self {
            service: service.to_string(),
            write: write_credential,
            limit: session_limit,
        }
    }

    /// The entry's target name and username, each with its terminator. A nul
    /// would end the name early, and so name some other entry.
    fn names(&self, account: &str) -> Result<(Vec<u16>, Vec<u16>)> {
        let target = format!("{account}.{}", self.service);
        match target.contains('\0') {
            true => Err(failed()),
            false => Ok((wide(&target), wide(account))),
        }
    }

    /// Whether this session lets a credential be kept as long as `needed`.
    fn allows(&self, needed: u32) -> Result<()> {
        allowed((self.limit)(), needed)
    }

    /// Moves `account`'s entry to this computer if it is kept any other way.
    /// `Err` means it did not happen, and the old entry is still there unless
    /// another process has since changed it.
    fn migrate(&self, account: &str) -> Result<()> {
        self.allows(CRED_PERSIST_LOCAL_MACHINE)?;
        let (target, _) = self.names(account)?;
        let Some(old) = Found::read(&target)? else {
            return Ok(());
        };
        if old.persist() == CRED_PERSIST_LOCAL_MACHINE {
            return Ok(());
        }
        // The same credential at the new type. Written over the old one, so
        // there is no moment with neither.
        let same = CREDENTIALW {
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            ..*old.credential()
        };
        let keeping_value = CREDENTIALW {
            CredentialBlob: null_mut(),
            CredentialBlobSize: 0,
            ..same
        };
        match (self.write)(&keeping_value, CRED_PRESERVE_CREDENTIAL_BLOB) {
            Ok(()) => {}
            // The flag itself refused: write the value too, from the OS's own
            // buffer, which is wiped when `old` goes.
            Err(ERROR_INVALID_FLAGS | ERROR_INVALID_PARAMETER) => {
                (self.write)(&same, 0).map_err(os_error)?;
            }
            Err(code) => return Err(os_error(code)),
        }
        let Some(back) = Found::read(&target)? else {
            return Err(failed());
        };
        // The OS said yes and lost the value. It is still in `old`.
        if back.blob().is_empty() && !old.blob().is_empty() {
            (self.write)(&same, 0).map_err(os_error)?;
            return Err(failed());
        }
        match back.persist() == CRED_PERSIST_LOCAL_MACHINE && back.blob() == old.blob() {
            true => Ok(()),
            false => Err(failed()),
        }
    }
}

impl Store for Credentials {
    fn get(&self, account: &str) -> Result<Option<Secret>> {
        self.allows(CRED_PERSIST_SESSION)?;
        let (target, _) = self.names(account)?;
        let found = Found::read(&target)?;
        // Not text: not one of this product's.
        Ok(found.and_then(|found| text_of(found.blob())))
    }

    fn set(&self, account: &str, value: &str) -> Result<()> {
        self.allows(CRED_PERSIST_LOCAL_MACHINE)?;
        let (mut target, mut username) = self.names(account)?;
        let mut blob = blob_of(value);
        let credential = CREDENTIALW {
            Flags: 0,
            Type: CRED_TYPE_GENERIC,
            TargetName: target.as_mut_ptr(),
            Comment: null_mut(),
            LastWritten: FILETIME {
                dwLowDateTime: 0,
                dwHighDateTime: 0,
            },
            CredentialBlobSize: u32::try_from(blob.len()).map_err(|_| failed())?,
            CredentialBlob: blob.as_mut_ptr(),
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            AttributeCount: 0,
            Attributes: null_mut(),
            TargetAlias: null_mut(),
            UserName: username.as_mut_ptr(),
        };
        (self.write)(&credential, 0).map_err(os_error)
    }

    fn delete(&self, account: &str) -> Result<()> {
        self.allows(CRED_PERSIST_SESSION)?;
        let (target, _) = self.names(account)?;
        // SAFETY: `target` ends in a nul and outlives the call, which keeps
        // nothing it is given.
        let deleted = unsafe { CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0) };
        match (deleted, last_error()) {
            (0, ERROR_NOT_FOUND) => Ok(()),
            (0, code) => Err(os_error(code)),
            _ => Ok(()),
        }
    }

    fn settle(&self, accounts: &dyn Fn() -> Result<Vec<String>>) {
        // A failure changes nothing, and the next run tries again. The rest
        // are still tried: each entry stands alone.
        let _ = self.migrate(super::INDEX);
        for account in accounts().unwrap_or_default() {
            let _ = self.migrate(&account);
        }
    }
}

/// A credential as `CredReadW` returned it. Its value is wiped and its memory
/// given back when this goes.
struct Found(*mut CREDENTIALW);

impl Found {
    /// The generic credential named `target`, or `None` if there is none.
    fn read(target: &[u16]) -> Result<Option<Self>> {
        let mut found = null_mut();
        // SAFETY: `target` ends in a nul and outlives the call, and `found`
        // is somewhere the call may write one pointer.
        let read = unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut found) };
        match (read, last_error()) {
            (0, ERROR_NOT_FOUND) => Ok(None),
            (0, code) => Err(os_error(code)),
            _ => Ok(Some(Self(found))),
        }
    }

    fn credential(&self) -> &CREDENTIALW {
        // SAFETY: a successful `CredReadW` gave this pointer, and only `drop`
        // gives it back.
        unsafe { &*self.0 }
    }

    fn persist(&self) -> u32 {
        self.credential().Persist
    }

    fn blob(&self) -> &[u8] {
        let credential = self.credential();
        match credential.CredentialBlob.is_null() {
            true => &[],
            // SAFETY: the OS says this many bytes are at this address, and
            // they live as long as the credential does.
            false => unsafe {
                std::slice::from_raw_parts(
                    credential.CredentialBlob,
                    credential.CredentialBlobSize as usize,
                )
            },
        }
    }
}

impl Drop for Found {
    fn drop(&mut self) {
        let (blob, size) = {
            let credential = self.credential();
            (credential.CredentialBlob, credential.CredentialBlobSize)
        };
        if !blob.is_null() {
            // SAFETY: as in `blob`, and this is the last use of these bytes.
            unsafe { std::slice::from_raw_parts_mut(blob, size as usize) }.zeroize();
        }
        #[cfg(test)]
        tests::wiped(self.blob());
        // SAFETY: `CredReadW` gave this pointer, and nothing uses it after.
        unsafe { CredFree(self.0.cast()) };
    }
}

/// `CredWriteW`.
fn write_credential(credential: &CREDENTIALW, flags: u32) -> Os<()> {
    // SAFETY: the credential's pointers are each null or valid for the call,
    // which only reads through them and keeps none.
    match unsafe { CredWriteW(credential, flags) } {
        0 => Err(last_error()),
        _ => Ok(()),
    }
}

/// The longest this logon session may keep a generic credential.
fn session_limit() -> Os<u32> {
    let mut limits = [CRED_PERSIST_NONE; CRED_TYPE_MAXIMUM as usize];
    // SAFETY: the call writes at most the count it is given, the array's own.
    match unsafe { CredGetSessionTypes(CRED_TYPE_MAXIMUM, limits.as_mut_ptr()) } {
        0 => Err(last_error()),
        _ => Ok(limits[CRED_TYPE_GENERIC as usize]),
    }
}

/// Whether `limit` lets a credential be kept as long as `needed`. A session
/// that cannot is a keyring that cannot be used.
fn allowed(limit: Os<u32>, needed: u32) -> Result<()> {
    match limit.map_err(os_error)? >= needed {
        true => Ok(()),
        false => Err(Error::Unsupported),
    }
}

/// The error for what an OS call answered, in fixed text.
fn os_error(code: u32) -> Error {
    match code {
        ERROR_NO_SUCH_LOGON_SESSION => Error::Unsupported,
        _ => failed(),
    }
}

fn last_error() -> u32 {
    // SAFETY: it takes nothing and reads only this thread's last error.
    unsafe { GetLastError() }
}

/// `text` as a string for the OS, with its terminator. Only ever a name.
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// `value` as it is stored. Twice its length in UTF-8 is always room enough,
/// so the buffer never moves and leaves a copy behind.
fn blob_of(value: &str) -> Zeroizing<Vec<u8>> {
    let mut blob = Zeroizing::new(Vec::with_capacity(value.len() * 2));
    for unit in value.encode_utf16() {
        blob.extend_from_slice(&unit.to_le_bytes());
    }
    blob
}

/// A stored value as text, or `None` when it cannot be text. Three bytes to
/// each UTF-16 unit is always room enough, so the string never moves and
/// leaves a copy behind.
fn text_of(blob: &[u8]) -> Option<Secret> {
    let (units, odd) = blob.as_chunks();
    if !odd.is_empty() {
        return None;
    }
    let units = units.iter().map(|pair| u16::from_le_bytes(*pair));
    let mut text = Zeroizing::new(String::with_capacity(blob.len() / 2 * 3));
    for unit in char::decode_utf16(units) {
        text.push(unit.ok()?);
    }
    Some(Secret::new(std::mem::take(&mut *text)))
}

#[cfg(test)]
#[path = "credentials_tests.rs"]
mod tests;
