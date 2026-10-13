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
///
/// When a `Secret` is dropped, the bytes of its value are overwritten with
/// zeros, in a way the compiler may not leave out, before the memory is
/// given back. Each clone is a copy of its own and is wiped when it is
/// dropped. What this does not reach, so that nobody assumes more:
///
/// - copies made before the value became a `Secret`, or after
///   [`Secret::expose`] was used to copy it: a line read from the channel
///   or a terminal, a string `serde` builds while it decodes or encodes a
///   message, and an encoded message that holds one;
/// - the copies an engine or a library makes of what it is given;
/// - memory the string gave back as it grew, before it became a `Secret`;
/// - whatever the OS keeps, such as a page swapped to disk.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct Secret(String);

impl Drop for Secret {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        // Security rule: the value does not stay behind in freed memory.
        // Its own bytes first, in place, where a test can see them...
        let mut bytes = std::mem::take(&mut self.0).into_bytes();
        bytes.as_mut_slice().zeroize();
        #[cfg(test)]
        tests::wiped(&bytes);
        // ...then the whole of the memory it holds, spare room included.
        bytes.zeroize();
    }
}

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
    use std::cell::RefCell;

    use super::*;

    thread_local! {
        /// The bytes each `Secret` dropped on this thread held at the
        /// moment its memory was to be given back.
        static WIPED: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
    }

    /// Called by `Secret`'s drop in a test build.
    pub(super) fn wiped(bytes: &[u8]) {
        WIPED.with(|wiped| wiped.borrow_mut().push(bytes.to_vec()));
    }

    fn take_wiped() -> Vec<Vec<u8>> {
        WIPED.with(|wiped| std::mem::take(&mut *wiped.borrow_mut()))
    }

    // Security rule: a secret's bytes are overwritten before its memory is
    // given back, for the secret and for each of its clones, and on every
    // way it can go: dropped, replaced, or decoded off the wire.
    #[test]
    fn a_secret_is_wiped_when_it_is_dropped() {
        take_wiped();
        let secret = Secret::new("made-up-secret-0123");
        let copy = secret.clone();
        drop(secret);
        let mut kept = Some(copy);
        assert!(kept.is_some());
        kept = None;
        assert!(kept.is_none());
        let decoded: Secret = serde_json::from_str(r#""another-made-up-value""#).unwrap();
        drop(decoded);
        let wiped = take_wiped();
        let lengths: Vec<usize> = wiped.iter().map(Vec::len).collect();
        assert_eq!(lengths, [19, 19, 21], "one record per secret dropped");
        for bytes in wiped {
            assert!(bytes.iter().all(|byte| *byte == 0), "{bytes:?}");
        }
    }

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
