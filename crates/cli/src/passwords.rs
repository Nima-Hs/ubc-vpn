//! A connect's saved password: whether one may be sent, and what becomes of
//! it after the gateway has answered.
//!
//! - **Bound to its username.** A password is sent only for the username it
//!   was saved for, compared without regard to case. One saved for another
//!   username, or for a profile that has none, is forgotten and the user is
//!   asked.
//! - **Never sent twice in a row after a refusal.** The gateway does not say
//!   which answer it refused. With no one-time code entered only the saved
//!   password can have been wrong, and it is forgotten at once. With a code
//!   entered it may have been the code: the password is kept but marked in
//!   doubt, and is not sent again. The user is asked, and a typed password
//!   that then works replaces it.
//! - **Saved only after it worked.** A typed password is saved after the
//!   login succeeded and the service accepted the connect, and only when
//!   the profile still asks for that, with the same username.
//!
//! Every change to the keyring here is made under the settings lock, after
//! the settings are read again, so it is judged by what they say now.

use std::io::Write;
use std::path::Path;

use ubc_vpn_core::profiles::{Profile, ProfileId};
use ubc_vpn_core::redact::Secret;
use ubc_vpn_core::settings_cli::SettingsFailureCode;
use ubc_vpn_platform::secrets::Saved;

use crate::keys;
use crate::settings::read_profiles;
use crate::settings_lock::change;

/// What a user whose keyring cannot be used is told: the password is asked
/// for each time.
pub(crate) const NO_KEYRING: &str = "The keyring cannot be used, so the password \
                                     cannot be saved and is asked for each time.";

/// What the user is told when a password that worked could not be saved.
pub(crate) const NOT_SAVED: &str = "The password could not be saved in the keyring. \
                                    It will be asked for next time.";

/// Whether `saved_for` is `username`, without regard to case.
pub(crate) fn same_username(username: &str, saved_for: &str) -> bool {
    username.to_lowercase() == saved_for.to_lowercase()
}

/// What a connect found in the keyring before logging in.
pub(crate) struct Found {
    /// The saved password it may send, if any.
    pub(crate) password: Option<Secret>,
    /// Whether a password that works may be saved afterwards: the profile
    /// saves its password, and the keyring could be read.
    pub(crate) may_save: bool,
}

/// What a connect with `profile` finds in the keyring. A profile that does
/// not save its password never reaches it. Says on `err` when the keyring
/// cannot be used.
pub(crate) fn usable(dir: &Path, profile: &Profile, err: &mut dyn Write) -> Found {
    let nothing = |may_save| Found {
        password: None,
        may_save,
    };
    if !profile.save_password {
        return nothing(false);
    }
    let saved = match keys::keyring().load(profile.id.as_str()) {
        Ok(Some(saved)) => saved,
        Ok(None) => return nothing(true),
        Err(_) => {
            let _ = writeln!(err, "ubc-vpn: {NO_KEYRING}");
            return nothing(false);
        }
    };
    let bound = |username: &str| same_username(username, &saved.username);
    if !profile.username.as_deref().is_some_and(bound) {
        // Not the profile's username's: never sent, and not kept.
        let _ = forget_unbound(dir, &profile.id);
        return nothing(true);
    }
    // In doubt: not sent again. The user is asked.
    Found {
        password: (!saved.in_doubt).then_some(saved.password),
        may_save: true,
    }
}

/// Forgets the password saved for `id` if it is not bound to the profile's
/// username as the settings say now, or the profile is gone.
pub(crate) fn forget_unbound(dir: &Path, id: &ProfileId) -> Result<(), SettingsFailureCode> {
    let _changing = change(dir)?;
    let keyring = keys::keyring();
    let Some(saved) = keyring.load(id.as_str()).ok().flatten() else {
        return Ok(());
    };
    let profiles = read_profiles(dir)?.profiles;
    let username = profiles.profile(id).ok().and_then(|p| p.username.clone());
    let bound = username.is_some_and(|name| same_username(&name, &saved.username));
    if !bound {
        let _ = keyring.forget(id.as_str());
    }
    Ok(())
}

/// After the gateway refused a login that sent `sent`, the password saved
/// for `id`: forgotten when `code_entered` is false, marked in doubt when it
/// is true. Only if it is still the one that was sent. Should the keyring
/// not do the one, the other is tried, so that it is not sent again either
/// way.
pub(crate) fn refused(
    dir: &Path,
    id: &ProfileId,
    sent: &Secret,
    code_entered: bool,
) -> Result<(), SettingsFailureCode> {
    let _changing = change(dir)?;
    let keyring = keys::keyring();
    let Some(saved) = keyring.load(id.as_str()).ok().flatten() else {
        return Ok(());
    };
    if saved.password != *sent {
        // Replaced since by another connect: not this one's to settle.
        return Ok(());
    }
    let account = id.as_str();
    let doubted = Saved {
        in_doubt: true,
        ..saved
    };
    let settled = match code_entered {
        false => keyring
            .forget(account)
            .or_else(|_| keyring.save(account, &doubted)),
        true => keyring
            .save(account, &doubted)
            .or_else(|_| keyring.forget(account)),
    };
    settled.map_err(|_| SettingsFailureCode::Unwritable)
}

/// After a login with a typed `password` succeeded and the service accepted
/// the connect: saves it for `id`, replacing what was there, if the profile
/// still saves its password and still has `username`. Says on `err` when it
/// should have been saved and could not be.
pub(crate) fn keep(
    dir: &Path,
    id: &ProfileId,
    username: &str,
    password: &Secret,
    err: &mut dyn Write,
) {
    let kept = keep_locked(dir, id, username, password);
    if kept.is_err() {
        let _ = writeln!(err, "ubc-vpn: {NOT_SAVED}");
    }
}

fn keep_locked(
    dir: &Path,
    id: &ProfileId,
    username: &str,
    password: &Secret,
) -> Result<(), SettingsFailureCode> {
    let _changing = change(dir)?;
    let profiles = read_profiles(dir)?.profiles;
    let Ok(profile) = profiles.profile(id) else {
        return Ok(());
    };
    let Some(theirs) = profile.username.as_deref() else {
        return Ok(());
    };
    if !profile.save_password || !same_username(theirs, username) {
        return Ok(());
    }
    let saved = Saved {
        username: theirs.to_string(),
        password: password.clone(),
        in_doubt: false,
    };
    let keyring = keys::keyring();
    keyring
        .save(id.as_str(), &saved)
        .map_err(|_| SettingsFailureCode::Unwritable)
}
