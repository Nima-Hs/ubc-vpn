//! Keeping secrets out of logs and debug output.

use std::fmt;

use serde::{Deserialize, Serialize};

/// A secret string: a password, an MFA code or a session cookie.
///
/// It serialises as a plain string, because it has to cross the channel, but
/// its `Debug` output never shows the value, and it has no `Display`. Reading
/// the value takes an explicit call to [`Secret::expose`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct Secret(String);

impl Secret {
    /// Wraps a secret value.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Returns the secret. Call this only where the value is actually needed,
    /// never to build a log line or an error message.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([redacted])")
    }
}

/// What a redacted line ends with.
pub const REDACTED: &str = "[redacted]";

/// Words that mark a line as possibly carrying a secret. Matching is
/// case-insensitive.
const MARKERS: [&str; 7] = [
    "cookie",
    "webvpn",
    "password",
    "passwd",
    "secret",
    "token",
    "authorization",
];

/// Removes anything that might be a secret from one line of third-party
/// output, such as a line logged by `libopenconnect`.
///
/// If the line mentions any marker word, everything from that word onward is
/// dropped. This throws away more than strictly necessary on purpose: losing
/// part of a log line is cheap, and leaking a session cookie is not.
pub fn redact_line(line: &str) -> String {
    let lower = line.to_ascii_lowercase();
    match MARKERS.iter().filter_map(|m| lower.find(m)).min() {
        Some(at) => format!("{}{REDACTED}", &line[..at]),
        None => line.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_shows_the_value() {
        let secret = Secret::new("hunter2");
        assert_eq!(format!("{secret:?}"), "Secret([redacted])");
        assert!(!format!("{:?}", Some(&secret)).contains("hunter2"));
    }

    #[test]
    fn serialises_as_a_plain_string() {
        let secret = Secret::new("abc");
        assert_eq!(serde_json::to_string(&secret).unwrap(), r#""abc""#);
        let back: Secret = serde_json::from_str(r#""abc""#).unwrap();
        assert_eq!(back.expose(), "abc");
    }

    // Security rule: lines that libopenconnect really prints must not leak the
    // cookie. These are taken from its debug output.
    #[test]
    fn redacts_cookie_lines_from_libopenconnect() {
        let leaks = [
            "Set-Cookie: webvpncontext=AI+g/Fmd4GDAJxwFBFTPVu=; Secure; HttpOnly",
            "Set-Cookie: webvpn=<elided>; Secure; HttpOnly",
            "Cookie: webvpn=0123456789abcdef",
            "X-CSTP-Something: webvpnc=bu:/&p:t&iu:1/&sh:22B20E",
            "POST https://vpn.example/auth?password=hunter2",
        ];
        for line in leaks {
            let out = redact_line(line);
            assert!(out.ends_with(REDACTED), "{line:?} was not redacted");
            for secret in ["AI+g", "0123456789abcdef", "22B20E", "hunter2"] {
                assert!(!out.contains(secret), "{out:?} still contains {secret}");
            }
        }
    }

    #[test]
    fn matching_is_case_insensitive() {
        assert_eq!(redact_line("COOKIE: abc"), REDACTED);
        assert_eq!(redact_line("got Token=xyz"), format!("got {REDACTED}"));
    }

    #[test]
    fn leaves_ordinary_lines_alone() {
        let line = "CSTP connected. DPD 60, Keepalive 300";
        assert_eq!(redact_line(line), line);
    }
}
