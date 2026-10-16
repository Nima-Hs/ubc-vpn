//! Saved passwords, in the user's OS keyring: Credential Manager on
//! Windows, the Keychain on macOS, Secret Service on Linux.
//!
//! Only the command-line client uses this, as the user. The service never
//! does: it runs as another account, whose keyring is not the user's, and
//! it never sees a password.
//!
//! - **One entry per profile,** under the service name [`SERVICE`] and the
//!   profile's id as the account. It holds the password and the username
//!   it was saved for ([`Saved`]), so a password is never sent for another
//!   username than its own.
//! - **An index entry** ([`INDEX`]) lists the accounts that have an entry.
//!   An account is added to it before its entry is written, and removed
//!   only once its entry is gone, so the index always names every entry.
//!   [`Secrets::forget_all`] works from it, and so forgets every password
//!   this product saved, whatever the settings file says now.
//! - **A password can be in doubt.** When the gateway refuses a login that
//!   used a saved password together with a one-time code, it does not say
//!   which was wrong. The password is then kept but marked in doubt
//!   ([`Saved::in_doubt`]), and the next login asks for it instead of
//!   sending it. A mark this version does not know reads as in doubt: the
//!   safe side.
//! - **Nothing secret leaves this module in an error.** Errors are fixed
//!   text; neither the password, the username nor the OS's own message is
//!   in them.
//! - **Tests never use the user's keyring.** They use [`FakeSecrets`] in
//!   memory, or, to share one between processes, [`file_backed`], which
//!   keeps entries as files in a folder of the test's and exists only in a
//!   debug build. Only one CI step uses the real keyring, under a
//!   throwaway service name.

use std::sync::Arc;

use ubc_vpn_core::redact::Secret;

use crate::{Error, Result};

/// The service name every entry of this product is kept under.
pub const SERVICE: &str = "io.github.nima-hs.ubc-vpn";

/// The account of the index entry. Profile ids are hex digits, so no
/// profile can have it.
pub const INDEX: &str = "index";

/// A saved password and the username it was saved for.
pub struct Saved {
    /// The username the password belongs to.
    pub username: String,
    /// The password.
    pub password: Secret,
    /// Whether a login that used it was refused without it being known
    /// which answer was wrong. One in doubt is not sent again: the user is
    /// asked, and a typed password that works replaces it.
    pub in_doubt: bool,
}

impl std::fmt::Debug for Saved {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Saved { .. }")
    }
}

/// The keyring, as far as this product uses it.
pub trait Secrets: Send + Sync {
    /// The password saved for `account`, or `None` when there is none or
    /// what is there cannot be read as one.
    fn load(&self, account: &str) -> Result<Option<Saved>>;

    /// Saves `saved` for `account`, replacing what was there.
    fn save(&self, account: &str, saved: &Saved) -> Result<()>;

    /// Forgets the password saved for `account`. None saved is fine.
    fn forget(&self, account: &str) -> Result<()>;

    /// Forgets every password this product saved.
    fn forget_all(&self) -> Result<()>;

    /// The accounts that have a password saved, as the index names them.
    /// No password is read for this.
    fn saved(&self) -> Result<Vec<String>>;
}

/// The first line of an entry, which says what form it is in.
const FORM: &str = "ubc-vpn 1";

/// The mark on the first line of an entry whose password is in doubt.
const IN_DOUBT: &str = "in-doubt";

/// An entry as stored: [`FORM`] (followed by [`IN_DOUBT`] when it is), the
/// username and the password, each after a line break. A username that may
/// be saved holds no line break, so the password is everything after the
/// second one.
fn entry(saved: &Saved) -> Option<Secret> {
    let username = &saved.username;
    let form = match saved.in_doubt {
        true => format!("{FORM} {IN_DOUBT}"),
        false => FORM.to_string(),
    };
    match username.contains(['\n', '\r']) {
        true => None,
        false => Some(Secret::new(format!(
            "{form}\n{username}\n{}",
            saved.password.expose()
        ))),
    }
}

/// An entry read back, or `None` when it is not in [`FORM`]. Any mark after
/// the form, known or not, reads as in doubt.
fn read_entry(text: &str) -> Option<Saved> {
    let (first, rest) = text.split_once('\n')?;
    let in_doubt = match first.strip_prefix(FORM)? {
        "" => false,
        mark if mark.starts_with(' ') => true,
        // Another form, such as a later version's: not one to trust.
        _ => return None,
    };
    let (username, password) = rest.split_once('\n')?;
    Some(Saved {
        username: username.to_string(),
        password: Secret::new(password),
        in_doubt,
    })
}

/// The keyring as one store of named strings: what [`Native`] and the fake
/// share, so that the rules about entries and the index are written once.
trait Store: Send + Sync {
    fn get(&self, account: &str) -> Result<Option<Secret>>;
    fn set(&self, account: &str, value: &str) -> Result<()>;
    fn delete(&self, account: &str) -> Result<()>;
}

/// [`Secrets`] over any [`Store`].
///
/// Every change to the index is made under one lock, so two saves at once
/// in this process cannot each rewrite it and drop the other's line. Two
/// processes are kept apart by their caller: the command-line client
/// changes saved passwords only while it holds the settings lock.
struct Kept<S> {
    store: S,
    changing: std::sync::Mutex<()>,
}

impl<S: Store> Kept<S> {
    fn new(store: S) -> Self {
        Self {
            store,
            changing: std::sync::Mutex::new(()),
        }
    }
}

impl<S: Store> Kept<S> {
    fn index(&self) -> Result<Vec<String>> {
        let Some(text) = self.store.get(INDEX)? else {
            return Ok(Vec::new());
        };
        // One account to a line.
        let accounts = text.expose().lines().filter(|a| !a.is_empty());
        Ok(accounts.map(str::to_string).collect())
    }

    fn set_index(&self, accounts: &[String]) -> Result<()> {
        if accounts.is_empty() {
            return self.store.delete(INDEX);
        }
        self.store.set(INDEX, &accounts.join("\n"))
    }
}

impl<S: Store> Secrets for Kept<S> {
    fn load(&self, account: &str) -> Result<Option<Saved>> {
        let Some(text) = self.store.get(account)? else {
            return Ok(None);
        };
        // An entry in another form is not one this product can trust.
        Ok(read_entry(text.expose()))
    }

    fn save(&self, account: &str, saved: &Saved) -> Result<()> {
        let text = entry(saved).ok_or_else(failed)?;
        if account == INDEX || account.is_empty() || account.contains(['\n', '\r']) {
            return Err(failed());
        }
        let _changing = crate::lock(&self.changing);
        // In the index first: an entry is never there without its line.
        let mut accounts = self.index()?;
        if !accounts.iter().any(|a| a == account) {
            accounts.push(account.to_string());
            self.set_index(&accounts)?;
        }
        self.store.set(account, text.expose())
    }

    fn forget(&self, account: &str) -> Result<()> {
        let _changing = crate::lock(&self.changing);
        // The entry first: its line goes only once it is gone.
        self.store.delete(account)?;
        let mut accounts = self.index()?;
        if accounts.iter().any(|a| a == account) {
            accounts.retain(|a| a != account);
            self.set_index(&accounts)?;
        }
        Ok(())
    }

    fn forget_all(&self) -> Result<()> {
        let _changing = crate::lock(&self.changing);
        for account in self.index()? {
            if account != INDEX {
                self.store.delete(&account)?;
            }
        }
        self.store.delete(INDEX)
    }

    fn saved(&self) -> Result<Vec<String>> {
        // `save` never takes the index's own account, so it is never named.
        self.index()
    }
}

/// The error for anything that went wrong in the keyring, in fixed text.
fn failed() -> Error {
    Error::Failed("the OS keyring could not be used".to_string())
}

/// The user's OS keyring, under [`SERVICE`].
pub fn native() -> Arc<dyn Secrets> {
    under(SERVICE)
}

/// The user's OS keyring under `service`. Tests on CI use a throwaway name
/// of their own; nothing else does.
pub fn under(service: &str) -> Arc<dyn Secrets> {
    Arc::new(Kept::new(Native(service.to_string())))
}

/// A keyring kept as files in `dir`, one to an entry, for tests that run
/// several processes of the command-line client and need them to share
/// one. It touches nothing but that folder: never the OS keyring. It exists
/// only in a debug build, so a program that ships cannot use it.
///
/// With `slow_index`, reading the index comes back a moment late, so that
/// changes from two processes overlap unless something keeps them apart.
#[cfg(debug_assertions)]
pub fn file_backed(dir: &std::path::Path, slow_index: bool) -> Arc<dyn Secrets> {
    Arc::new(Kept::new(Files(dir.to_path_buf(), slow_index)))
}

/// The keyring as files in a folder: see [`file_backed`].
#[cfg(debug_assertions)]
struct Files(std::path::PathBuf, bool);

#[cfg(debug_assertions)]
impl Files {
    /// The file for `account`. Accounts are profile ids and the index:
    /// letters and digits only, so no account can name a path elsewhere.
    fn path(&self, account: &str) -> Result<std::path::PathBuf> {
        let plain = !account.is_empty() && account.bytes().all(|b| b.is_ascii_alphanumeric());
        match plain {
            true => Ok(self.0.join(account)),
            false => Err(failed()),
        }
    }
}

#[cfg(debug_assertions)]
impl Store for Files {
    fn get(&self, account: &str) -> Result<Option<Secret>> {
        let read = match std::fs::read_to_string(self.path(account)?) {
            Ok(text) => Some(Secret::new(text)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => return Err(failed()),
        };
        if self.1 && account == INDEX {
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        Ok(read)
    }

    fn set(&self, account: &str, value: &str) -> Result<()> {
        std::fs::create_dir_all(&self.0).map_err(|_| failed())?;
        std::fs::write(self.path(account)?, value).map_err(|_| failed())
    }

    fn delete(&self, account: &str) -> Result<()> {
        match std::fs::remove_file(self.path(account)?) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(failed()),
        }
    }
}

/// The OS keyring, through the `keyring` crate.
struct Native(String);

impl Native {
    fn entry(&self, account: &str) -> Result<keyring::Entry> {
        keyring::Entry::new(&self.0, account).map_err(unusable)
    }
}

/// A keyring that cannot be used at all is unsupported: passwords are then
/// asked for each time. Anything else is a failure. Neither keeps the OS's
/// own message.
fn unusable(error: keyring::Error) -> Error {
    match error {
        keyring::Error::NoStorageAccess(_) | keyring::Error::PlatformFailure(_) => {
            Error::Unsupported
        }
        _ => failed(),
    }
}

impl Store for Native {
    fn get(&self, account: &str) -> Result<Option<Secret>> {
        match self.entry(account)?.get_password() {
            Ok(text) => Ok(Some(Secret::new(text))),
            Err(keyring::Error::NoEntry) => Ok(None),
            // Not text: not one of this product's.
            Err(keyring::Error::BadEncoding(_)) => Ok(None),
            Err(error) => Err(unusable(error)),
        }
    }

    fn set(&self, account: &str, value: &str) -> Result<()> {
        self.entry(account)?.set_password(value).map_err(unusable)
    }

    fn delete(&self, account: &str) -> Result<()> {
        match self.entry(account)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(unusable(error)),
        }
    }
}

/// What [`FakeSecrets::on_change`] calls.
#[cfg(any(test, feature = "fake"))]
pub type Hook = Arc<dyn Fn(&str) + Send + Sync>;

/// A keyring in memory, for tests. Clones share one store.
#[cfg(any(test, feature = "fake"))]
#[derive(Clone, Default)]
pub struct FakeSecrets(Arc<std::sync::Mutex<FakeStore>>);

#[cfg(any(test, feature = "fake"))]
#[derive(Default)]
struct FakeStore {
    entries: std::collections::BTreeMap<String, String>,
    unusable: bool,
    /// Writes and deletes of these accounts fail.
    failing: std::collections::BTreeSet<String>,
    /// Deletes of these accounts fail; writes work.
    failing_deletes: std::collections::BTreeSet<String>,
    /// Writes of these accounts fail; deletes work.
    failing_saves: std::collections::BTreeSet<String>,
    /// Called with the account after every write and delete that worked.
    on_change: Option<Hook>,
    /// Reading the index takes a moment, so that two changes at once
    /// overlap.
    slow_index: bool,
}

#[cfg(any(test, feature = "fake"))]
impl FakeSecrets {
    /// An empty keyring.
    pub fn new() -> Self {
        Self::default()
    }

    /// Makes the keyring one that cannot be used, or usable again.
    pub fn set_unusable(&self, unusable: bool) {
        crate::lock(&self.0).unusable = unusable;
    }

    /// Makes writing and deleting `account` fail, or work again.
    pub fn fail_writes_to(&self, account: &str, failing: bool) {
        let mut store = crate::lock(&self.0);
        match failing {
            true => store.failing.insert(account.to_string()),
            false => store.failing.remove(account),
        };
    }

    /// Makes deleting `account` fail, or work again, while writing it
    /// still works.
    pub fn fail_deletes_of(&self, account: &str, failing: bool) {
        let mut store = crate::lock(&self.0);
        match failing {
            true => store.failing_deletes.insert(account.to_string()),
            false => store.failing_deletes.remove(account),
        };
    }

    /// Makes writing `account` fail, or work again, while deleting it
    /// still works.
    pub fn fail_saves_to(&self, account: &str, failing: bool) {
        let mut store = crate::lock(&self.0);
        match failing {
            true => store.failing_saves.insert(account.to_string()),
            false => store.failing_saves.remove(account),
        };
    }

    /// Has `hook` called with the account after every write and delete
    /// that worked, or no longer with `None`: for a test to look at what
    /// else holds at the moment of each change.
    pub fn on_change(&self, hook: Option<Hook>) {
        crate::lock(&self.0).on_change = hook;
    }

    /// Makes reading the index take a moment, so that changes overlap.
    pub fn slow_index(&self, slow: bool) {
        crate::lock(&self.0).slow_index = slow;
    }

    /// Every account and what it holds, as stored, for tests to look at.
    pub fn entries(&self) -> Vec<(String, String)> {
        let store = crate::lock(&self.0);
        store
            .entries
            .iter()
            .map(|(a, v)| (a.clone(), v.clone()))
            .collect()
    }

    /// Stores `value` for `account` directly, as another version or a
    /// leftover would have.
    pub fn put(&self, account: &str, value: &str) {
        crate::lock(&self.0)
            .entries
            .insert(account.to_string(), value.to_string());
    }

    /// The keyring as [`Secrets`].
    pub fn secrets(&self) -> Arc<dyn Secrets> {
        Arc::new(Kept::new(self.clone()))
    }
}

#[cfg(any(test, feature = "fake"))]
impl Store for FakeSecrets {
    fn get(&self, account: &str) -> Result<Option<Secret>> {
        let (read, slow) = {
            let store = crate::lock(&self.0);
            if store.unusable {
                return Err(Error::Unsupported);
            }
            let read = store.entries.get(account).map(|v| Secret::new(v.clone()));
            (read, account == INDEX && store.slow_index)
        };
        // What was read comes back a moment later, as from a slow keyring,
        // so another change can read the same before this one writes.
        if slow {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        Ok(read)
    }

    fn set(&self, account: &str, value: &str) -> Result<()> {
        let hook = {
            let mut store = crate::lock(&self.0);
            if store.unusable {
                return Err(Error::Unsupported);
            }
            if store.failing.contains(account) || store.failing_saves.contains(account) {
                return Err(failed());
            }
            store.entries.insert(account.to_string(), value.to_string());
            store.on_change.clone()
        };
        // Called with the store let go, so the hook may use the keyring.
        if let Some(hook) = hook {
            hook(account);
        }
        Ok(())
    }

    fn delete(&self, account: &str) -> Result<()> {
        let hook = {
            let mut store = crate::lock(&self.0);
            if store.unusable {
                return Err(Error::Unsupported);
            }
            if store.failing.contains(account) || store.failing_deletes.contains(account) {
                return Err(failed());
            }
            store.entries.remove(account);
            store.on_change.clone()
        };
        if let Some(hook) = hook {
            hook(account);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "secrets_tests.rs"]
mod tests;
