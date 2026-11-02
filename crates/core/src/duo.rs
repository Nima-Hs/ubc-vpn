//! The Duo method: how a login is confirmed.
//!
//! UBC's gateway reads the method from a suffix on the username: `@app`
//! sends a push to Duo Mobile, `@call` (and its old name `@phone`) rings the
//! phone, `@sms` texts passcodes, and `@` followed by a passcode sends that
//! passcode. A department pool comes before the `@`: `user.dept@app`.
//!
//! A profile keeps the username without the suffix and the method on its
//! own ([`DuoMethod`]). The suffix is put back only for the gateway, at
//! login ([`gateway_username`]). A passcode is asked for at each login and
//! never stored, and a username that carries one is secret: see
//! [`crate::redact`].

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

use crate::redact::Secret;

/// How the user confirms a login.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub enum DuoMethod {
    /// A push to Duo Mobile: `@app`.
    #[default]
    Push,
    /// A phone call: `@call`. UBC offers it to faculty and staff.
    Call,
    /// Passcodes by text message: `@sms`. The gateway refuses that login
    /// and texts the codes; the login is made again with one of them.
    Sms,
    /// A passcode from Duo Mobile or a token, asked for at each login and
    /// sent as `@<code>`.
    Passcode,
}

impl DuoMethod {
    /// The suffix that names the method, for the methods that need no code.
    fn suffix(self) -> Option<&'static str> {
        match self {
            Self::Push => Some("app"),
            Self::Call => Some("call"),
            Self::Sms => Some("sms"),
            Self::Passcode => None,
        }
    }
}

/// How many digits a passcode from Duo Mobile or a token has.
pub const PASSCODE_DIGITS: usize = 6;

/// The fewest and the most digits a code from a text message may have.
/// UBC does not document them, so this is wider than a passcode.
pub const TEXTED_CODE_DIGITS: (usize, usize) = (6, 8);

/// Whether `text` is a passcode: exactly [`PASSCODE_DIGITS`] ASCII digits.
pub fn is_passcode(text: &str) -> bool {
    text.len() == PASSCODE_DIGITS && text.bytes().all(|b| b.is_ascii_digit())
}

/// Whether `text` is a code from a text message: only ASCII digits, as many
/// as [`TEXTED_CODE_DIGITS`] allows.
pub fn is_texted_code(text: &str) -> bool {
    let (fewest, most) = TEXTED_CODE_DIGITS;
    (fewest..=most).contains(&text.len()) && text.bytes().all(|b| b.is_ascii_digit())
}

/// Where `username` ends in a suffix UBC documents, or in a passcode: the
/// username before it and the method it names. Letters are compared without
/// regard to case. A username with another `@` before the suffix has none.
pub fn known_suffix(username: &str) -> Option<(&str, DuoMethod)> {
    let (account, suffix) = username.rsplit_once('@')?;
    if account.contains('@') {
        return None;
    }
    let method = match suffix.to_ascii_lowercase().as_str() {
        "app" => DuoMethod::Push,
        "call" | "phone" => DuoMethod::Call,
        "sms" => DuoMethod::Sms,
        code if is_passcode(code) => DuoMethod::Passcode,
        _ => return None,
    };
    Some((account, method))
}

/// The account a username names: the username without a suffix UBC
/// documents. A password is saved for the account, so changing the method
/// does not forget it.
pub fn account(username: &str) -> &str {
    known_suffix(username).map_or(username, |(account, _)| account)
}

/// A username from before the method was a setting, split into the
/// username to keep and the method.
///
/// - A known suffix is taken off and becomes the method; `@phone` is
///   `call`. A passcode becomes `passcode`, and the code itself is dropped.
/// - Any other `@something` is left as it is, with no method: the username
///   is sent as typed, so nobody is locked out.
/// - A username with no `@`, or none at all, gets the default, `push`.
pub fn migrate(username: Option<&str>) -> (Option<String>, Option<DuoMethod>) {
    match username {
        None => (None, Some(DuoMethod::default())),
        Some(name) => match known_suffix(name) {
            Some((account, method)) => (Some(account.to_string()), Some(method)),
            None if name.contains('@') => (Some(name.to_string()), None),
            None => (Some(name.to_string()), Some(DuoMethod::default())),
        },
    }
}

/// Whether `username` holds a passcode in its suffix.
pub fn holds_code(username: &str) -> bool {
    known_suffix(username).is_some_and(|(_, method)| method == DuoMethod::Passcode)
}

/// Why a gateway username could not be made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoUsername {
    /// The method is `passcode`, and no passcode was given.
    NoCode,
    /// The code given is not one: see [`is_passcode`] and
    /// [`is_texted_code`].
    BadCode,
}

/// The username to send the gateway: `username` with the suffix `method`
/// names, or as it is when there is no method. `code` is the passcode for
/// [`DuoMethod::Passcode`], or the texted code for the second login with
/// [`DuoMethod::Sms`]; it is ignored for the other methods.
///
/// The result is a [`Secret`]: with a code in it, it must be kept out of
/// every log as the password is.
pub fn gateway_username(
    username: &str,
    method: Option<DuoMethod>,
    code: Option<&Secret>,
) -> Result<Secret, NoUsername> {
    let with_code = |code: Option<&Secret>, valid: fn(&str) -> bool| {
        let code = code.ok_or(NoUsername::NoCode)?.expose();
        match valid(code) {
            true => Ok(Secret::new(format!("{username}@{code}"))),
            false => Err(NoUsername::BadCode),
        }
    };
    match (method, code) {
        (None, _) => Ok(Secret::new(username)),
        (Some(DuoMethod::Passcode), code) => with_code(code, is_passcode),
        (Some(DuoMethod::Sms), Some(code)) => with_code(Some(code), is_texted_code),
        (Some(method), _) => {
            let suffix = method.suffix().unwrap_or_default();
            Ok(Secret::new(format!("{username}@{suffix}")))
        }
    }
}

/// Reads a method, taking anything that is not one, such as a method a
/// newer version knows, as none: the username is then sent as typed.
pub(crate) fn lenient_method<'de, D: Deserializer<'de>>(
    reader: D,
) -> Result<Option<DuoMethod>, D::Error> {
    let value = Value::deserialize(reader)?;
    Ok(serde_json::from_value(value).unwrap_or(None))
}

#[cfg(test)]
#[path = "duo_tests.rs"]
mod tests;
