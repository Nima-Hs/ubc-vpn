//! Saved passwords in Windows Credential Manager, kept on this computer.
//!
//! The `keyring` crate hard-codes `CRED_PERSIST_ENTERPRISE`, so on a domain
//! with roaming profiles each entry would follow the user to other computers.
//! This store writes `CRED_PERSIST_LOCAL_MACHINE` instead, and otherwise keeps
//! the entries as that crate did, so what it saved is still found: the target
//! name is `{account}.{service}`, the type `CRED_TYPE_GENERIC`, the username
//! the account, and the value little-endian UTF-16 with no terminator.
//!
//! **An entry cannot simply be rewritten at the new type.** Windows keeps a
//! file for each type, and writing over an entry of the old type leaves the
//! old file behind. At the next logon that file brings the old entry back, with
//! the old password, even if the entry has since been replaced or forgotten.
//! Only deleting the entry while it is still of the old type removes its file.
//! So [`Credentials::place`] moves an entry in four steps, each confirmed:
//!
//! 1. Write a spare copy at the new type, and read it back.
//! 2. Delete the old entry.
//! 3. Write the entry at the new type, and read it back.
//! 4. Delete the spare.
//!
//! A saved copy exists at every step, so a failure or a crash at any of them
//! loses nothing. The first use in each run ([`Store::settle`]) finishes or
//! undoes what it finds: an entry of the new type wins over a spare, a spare
//! with no entry becomes the entry, and an entry of the old type moves. Until
//! then a spare with no entry is read as the entry, so a login is not blocked.
//!
//! **The spare cannot be taken for an account.** Its target name is
//! `{account}.{service}.moving`, which ends with neither the service name nor
//! any target name an account has, whatever the account is called. It is never
//! in the index. Forgetting an account deletes its spare first, so a forgotten
//! password cannot come back from one.
//!
//! - **What the OS returns is wiped** before it is given back, and so is
//!   anything made from a password here.
//! - **Errors are fixed text.** No OS message or code gets out of this module.
//!
//! What this does not change: any program running as the user, and any
//! administrator, can still get at the entries, as with any other credential
//! of the user's. A copy that already roamed to another computer cannot be
//! recalled from here. It has been tested across new logons of a local account
//! on CI, not on real interactive or domain sign-ins or with real roaming.

use std::ptr::null_mut;

use ubc_vpn_core::redact::Secret;
use windows_sys::Win32::Foundation::{
    ERROR_NO_SUCH_LOGON_SESSION, ERROR_NOT_FOUND, FILETIME, GetLastError,
};
use windows_sys::Win32::Security::Credentials::{
    CRED_PERSIST_LOCAL_MACHINE, CRED_PERSIST_NONE, CRED_PERSIST_SESSION, CRED_TYPE_GENERIC,
    CRED_TYPE_MAXIMUM, CREDENTIALW, CredDeleteW, CredFree, CredGetSessionTypes, CredReadW,
    CredWriteW,
};
use zeroize::{Zeroize, Zeroizing};

use super::{Store, failed};
use crate::{Error, Result};

/// What an OS call answers: its result, or the code `GetLastError` gave.
type Os<T> = std::result::Result<T, u32>;

/// What ends a spare's target name.
const SPARE: &str = ".moving";

/// Credential Manager, under one service name.
pub(super) struct Credentials {
    service: String,
    /// `CredWriteW`, or what a test has in its place to make a write fail.
    write: fn(&CREDENTIALW) -> Os<()>,
    /// `CredDeleteW`, or what a test has in its place.
    delete: fn(&[u16]) -> Os<()>,
    /// The longest a generic credential may be kept in this logon session.
    limit: fn() -> Os<u32>,
}

/// The names an account's entry goes by, each with its terminator.
struct Names {
    target: Vec<u16>,
    spare: Vec<u16>,
    username: Vec<u16>,
}

impl Credentials {
    pub(super) fn new(service: &str) -> Self {
        Self {
            service: service.to_string(),
            write: write_credential,
            delete: delete_credential,
            limit: session_limit,
        }
    }

    /// The names of `account`'s entry. A nul would end a name early, and so
    /// name some other entry.
    fn names(&self, account: &str) -> Result<Names> {
        let target = format!("{account}.{}", self.service);
        match target.contains('\0') {
            true => Err(failed()),
            false => Ok(Names {
                spare: wide(&format!("{target}{SPARE}")),
                target: wide(&target),
                username: wide(account),
            }),
        }
    }

    /// Whether this session lets a credential be kept as long as `needed`.
    fn allows(&self, needed: u32) -> Result<()> {
        allowed((self.limit)(), needed)
    }

    /// Deletes what `target` names. None there is fine.
    fn gone(&self, target: &[u16]) -> Result<()> {
        match (self.delete)(target) {
            Ok(()) | Err(ERROR_NOT_FOUND) => Ok(()),
            Err(code) => Err(os_error(code)),
        }
    }

    /// Writes `credential` under `target` and reads it back: the same value,
    /// kept on this computer.
    fn write_confirmed(&self, credential: &CREDENTIALW, target: &[u16]) -> Result<()> {
        let at_target = CREDENTIALW {
            TargetName: target.as_ptr().cast_mut(),
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            ..*credential
        };
        (self.write)(&at_target).map_err(os_error)?;
        let back = Found::read(target)?.ok_or_else(failed)?;
        let same = back.blob() == blob_in(credential);
        match back.persist() == CRED_PERSIST_LOCAL_MACHINE && same {
            true => Ok(()),
            false => Err(failed()),
        }
    }

    /// Steps 1 to 3 of the move, for an entry of the old type: `credential` is
    /// what it is to hold afterwards. The caller deletes the spare, step 4.
    fn place(&self, names: &Names, credential: &CREDENTIALW) -> Result<()> {
        self.write_confirmed(credential, &names.spare)?;
        self.gone(&names.target)?;
        self.write_confirmed(credential, &names.target)
    }

    /// Brings `account`'s entry to where it belongs: on this computer, with no
    /// spare. `Err` means it did not get there, and it can still be read.
    fn migrate(&self, account: &str) -> Result<()> {
        self.allows(CRED_PERSIST_LOCAL_MACHINE)?;
        let names = self.names(account)?;
        match Found::read(&names.target)? {
            // Moved already. A spare is left from a crash, and this is newer.
            Some(found) if found.persist() == CRED_PERSIST_LOCAL_MACHINE => {}
            // The entry is what the user last had, whatever a spare says.
            Some(old) => self.place(&names, old.credential())?,
            None => match Found::read(&names.spare)? {
                Some(spare) => self.write_confirmed(spare.credential(), &names.target)?,
                None => return Ok(()),
            },
        }
        self.gone(&names.spare)
    }
}

impl Store for Credentials {
    fn get(&self, account: &str) -> Result<Option<Secret>> {
        self.allows(CRED_PERSIST_SESSION)?;
        let names = self.names(account)?;
        let found = match Found::read(&names.target)? {
            Some(found) => Some(found),
            // A move that stopped half way: this is the password until the
            // next run finishes it.
            None => Found::read(&names.spare)?,
        };
        // Not text: not one of this product's.
        Ok(found.and_then(|found| text_of(found.blob())))
    }

    fn set(&self, account: &str, value: &str) -> Result<()> {
        self.allows(CRED_PERSIST_LOCAL_MACHINE)?;
        let names = self.names(account)?;
        let mut blob = blob_of(value);
        let credential = CREDENTIALW {
            Flags: 0,
            Type: CRED_TYPE_GENERIC,
            TargetName: names.target.as_ptr().cast_mut(),
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
            UserName: names.username.as_ptr().cast_mut(),
        };
        let old_type = Found::read(&names.target)?
            .is_some_and(|found| found.persist() != CRED_PERSIST_LOCAL_MACHINE);
        match old_type {
            true => self.place(&names, &credential)?,
            false => self.write_confirmed(&credential, &names.target)?,
        }
        // Saved. A spare left behind holds nothing newer, and the next run
        // deletes it.
        let _ = self.gone(&names.spare);
        Ok(())
    }

    fn delete(&self, account: &str) -> Result<()> {
        self.allows(CRED_PERSIST_SESSION)?;
        let names = self.names(account)?;
        // The spare first: with it gone, nothing can bring the entry back.
        self.gone(&names.spare)?;
        self.gone(&names.target)
    }

    fn settle(&self, accounts: &dyn Fn() -> Result<Vec<String>>) {
        // A failure loses nothing, and the next run tries again. The rest are
        // still tried: each entry stands alone. The index first, since it
        // names the rest.
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
        blob_in(self.credential())
    }
}

impl Drop for Found {
    fn drop(&mut self) {
        let (blob, size) = {
            let credential = self.credential();
            (credential.CredentialBlob, credential.CredentialBlobSize)
        };
        if !blob.is_null() {
            // SAFETY: as in `blob_in`, and this is the last use of these bytes.
            unsafe { std::slice::from_raw_parts_mut(blob, size as usize) }.zeroize();
        }
        #[cfg(test)]
        tests::wiped(self.blob());
        // SAFETY: `CredReadW` gave this pointer, and nothing uses it after.
        unsafe { CredFree(self.0.cast()) };
    }
}

/// The value a credential holds.
fn blob_in(credential: &CREDENTIALW) -> &[u8] {
    match credential.CredentialBlob.is_null() {
        true => &[],
        // SAFETY: whoever filled in the credential, the OS or `set`, says this
        // many bytes are at this address, for as long as it is borrowed.
        false => unsafe {
            std::slice::from_raw_parts(
                credential.CredentialBlob,
                credential.CredentialBlobSize as usize,
            )
        },
    }
}

/// `CredWriteW`.
fn write_credential(credential: &CREDENTIALW) -> Os<()> {
    // SAFETY: the credential's pointers are each null or valid for the call,
    // which only reads through them and keeps none.
    match unsafe { CredWriteW(credential, 0) } {
        0 => Err(last_error()),
        _ => Ok(()),
    }
}

/// `CredDeleteW`.
fn delete_credential(target: &[u16]) -> Os<()> {
    // SAFETY: `target` ends in a nul and outlives the call, which keeps nothing
    // it is given.
    match unsafe { CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0) } {
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
