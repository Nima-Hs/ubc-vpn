//! Keeping secrets out of logs and debug output.

use std::fmt;

use serde::{Deserialize, Serialize};

/// A secret string: a password, an MFA code or a session cookie.
///
/// Its `Debug` output never shows the value, and it has no `Display`. Reading
/// the value takes an explicit call to [`Secret::expose`].
///
/// It does serialise as a plain string, because it has to cross the channel.
/// So a serialised message is itself secret: never log an encoded line that
/// may contain one. Log the message's `Debug` form instead.
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

/// Text that marks a line as possibly carrying a secret. Matching is
/// case-insensitive and by substring, so `pass` also covers `password` and
/// `passwd`, and `auth` covers `Authorization` and `auth-handle`.
const MARKERS: [&str; 11] = [
    "cookie", "webvpn", "pass", "pwd", "secret", "token", "auth", "session", "sid=", "answer",
    "username",
];

/// Removes anything that might be a secret from one line of third-party
/// output, such as a line logged by `libopenconnect`.
///
/// If the line mentions any marker, everything from the marker onward is
/// dropped. This throws away more than strictly necessary on purpose: losing
/// part of a log line is cheap, and leaking a session cookie is not.
///
/// This is a second line of defence, not the first. It only sees one line at a
/// time, so it cannot catch a secret that sits on the line after its marker, or
/// in a hex dump. The service must therefore never ask `libopenconnect` for
/// output that dumps request or response bodies, and must drop the library's
/// debug-level lines altogether in release builds.
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

    // Security rule: every marker must actually redact. Each line below holds
    // exactly one marker, so removing or changing any entry in MARKERS makes
    // this test fail.
    #[test]
    fn every_marker_redacts_what_follows_it() {
        let lines = [
            ("cookie", "Cookie: LEAK"),
            ("webvpn", "webvpn=LEAK"),
            ("pass", "<pass>LEAK</pass>"),
            ("pwd", "pwd=LEAK"),
            ("secret", "shared secret is LEAK"),
            ("token", "<token>LEAK"),
            ("auth", "<auth>LEAK"),
            ("session", "X-Session: LEAK"),
            ("sid=", "sid=LEAK"),
            ("answer", "> answer=LEAK"),
            ("username", "> username=LEAK"),
        ];
        assert_eq!(lines.len(), MARKERS.len(), "one line per marker");
        for (marker, line) in lines {
            let lower = line.to_ascii_lowercase();
            let hits: Vec<_> = MARKERS.iter().filter(|m| lower.contains(**m)).collect();
            assert_eq!(hits, [&marker], "{line:?} should contain only {marker}");
            assert!(!redact_line(line).contains("LEAK"), "{line:?} leaked");
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
