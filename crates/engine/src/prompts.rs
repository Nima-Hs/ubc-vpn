//! Asking the user during login, with the no-retry rule built in.
//!
//! [`Prompts`] lives in a file of its own so that its fields are private to
//! this file. Rust privacy is per module: code anywhere else in the crate,
//! the `libopenconnect` binding included, cannot call the user's callback
//! directly or erase the record of what was asked.
//!
//! **Never put an engine, the binding or any other code in this file, and
//! never widen a field's visibility.** A test fails if a field becomes
//! reachable.

use ubc_vpn_core::login::PromptKind;
use ubc_vpn_core::redact::Secret;

use crate::LoginError;

/// A question the gateway asks during login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prompt {
    /// What kind of answer is wanted.
    pub kind: PromptKind,
    /// The gateway's wording for this field.
    pub label: String,
    /// The message or error text the gateway showed with the form, if any,
    /// such as "Login failed." or instructions for the MFA step.
    pub message: Option<String>,
}

/// The engine's only way to ask the user something during login.
///
/// It wraps the caller's callback and enforces the no-retry rule: the username
/// and the password are each asked for at most once in a login. A gateway that
/// asks for either again has rejected the login, so the second request does
/// not reach the caller and fails with [`LoginError::WrongPassword`]. One-time
/// codes and free text may be asked for again; each is typed afresh.
///
/// The callback and the record of what was asked cannot be reached directly:
///
/// ```compile_fail
/// fn callback(p: ubc_vpn_engine::Prompts<'_>) { let _ = &p.ask; }
/// ```
///
/// ```compile_fail
/// fn record(mut p: ubc_vpn_engine::Prompts<'_>) { p.asked.clear(); }
/// ```
pub struct Prompts<'a> {
    ask: &'a mut dyn FnMut(&Prompt) -> Option<Secret>,
    asked: Vec<PromptKind>,
}

impl<'a> Prompts<'a> {
    /// Wraps the caller's callback. The callback returns the user's answer,
    /// or `None` to cancel the login. Make a new `Prompts` for every login.
    pub fn new(ask: &'a mut dyn FnMut(&Prompt) -> Option<Secret>) -> Self {
        Self {
            ask,
            asked: Vec::new(),
        }
    }

    /// For engines: asks the user one question. An error must be returned
    /// from the login as it is, without contacting the gateway again.
    pub fn ask(&mut self, prompt: &Prompt) -> Result<Secret, LoginError> {
        let once_only = matches!(prompt.kind, PromptKind::Username | PromptKind::Password);
        if once_only && self.asked(prompt.kind) {
            return Err(LoginError::WrongPassword);
        }
        self.asked.push(prompt.kind);
        (self.ask)(prompt).ok_or(LoginError::Cancelled)
    }

    /// Whether the user was asked a question of this kind in this login.
    ///
    /// After [`LoginError::WrongPassword`], `asked(PromptKind::Code)` tells
    /// the caller that a mistyped code may be to blame, so a saved password
    /// should not be thrown away.
    pub fn asked(&self, kind: PromptKind) -> bool {
        self.asked.contains(&kind)
    }
}
