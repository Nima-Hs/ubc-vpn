//! `ubc-vpn settings`: how the app reads the user's settings and checks and
//! saves routes. The rules are in `ubc_vpn_core::settings_cli`, whose module
//! documentation ("The cases") is the reference; this file only reads the
//! files, calls those rules, and writes one line.
//!
//! The policy is read from the platform's policy folder and validated. No
//! argument and no environment variable can point this at another file.

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, Read, Write};
use std::path::Path;

use serde_json::{Map, Value};
use ubc_vpn_core::policy::Policy;
use ubc_vpn_core::protocol::{MAX_LINE_BYTES, decode, encode};
use ubc_vpn_core::settings::Settings;
use ubc_vpn_core::settings_cli::{
    RouteInput, RoutesReply, SettingsFailure, SettingsFailureCode, SettingsView, check_input,
    replace_routes,
};
use ubc_vpn_platform::{Paths, Platform};

const SETTINGS: &str = "settings.json";
const PARTIAL: &str = "settings.json.tmp";

/// The three commands. Each is spelled with `--json`, the only form so far.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// `settings get --json`
    Get,
    /// `settings check-routes --json`
    CheckRoutes,
    /// `settings set-routes --json`
    SetRoutes,
}

impl Command {
    /// Reads the arguments after `settings`, or `None` for wrong usage.
    pub fn parse(args: &[&str]) -> Option<Self> {
        match args {
            ["get", "--json"] => Some(Self::Get),
            ["check-routes", "--json"] => Some(Self::CheckRoutes),
            ["set-routes", "--json"] => Some(Self::SetRoutes),
            _ => None,
        }
    }
}

/// Runs one command: writes exactly one line on `out` and returns the exit
/// status, 0 unless that line is a failure.
pub fn run(
    command: Command,
    platform: &dyn Fn() -> ubc_vpn_platform::Result<Platform>,
    input: &mut dyn BufRead,
    out: &mut dyn Write,
) -> u8 {
    // A system this program cannot place its files on has no settings to
    // read and nowhere to save them.
    let paths = platform().ok().map(|platform| platform.paths);
    let answered = answer(command, paths.as_ref(), input);
    let failed = answered.is_err();
    let line = answered.or_else(|error| encode(&SettingsFailure { error }));
    let written = out.write_all(line.unwrap_or_default().as_bytes());
    let unsaid = written.and_then(|()| out.flush()).is_err();
    u8::from(failed || unsaid)
}

/// The line to write for `command`, or why there is none.
fn answer(
    command: Command,
    paths: Option<&Paths>,
    input: &mut dyn BufRead,
) -> Result<String, SettingsFailureCode> {
    let policy = paths.and_then(|paths| policy(&paths.policy_dir));
    let settings_dir = paths.map(|paths| paths.settings_dir.as_path());
    let unencodable = |_| SettingsFailureCode::Unreadable;
    if command == Command::Get {
        let dir = settings_dir.ok_or(SettingsFailureCode::Unreadable)?;
        let settings = match stored(dir)? {
            Some(text) => understood(&text)?,
            None => Settings::default(),
        };
        return encode(&SettingsView::new(settings, policy.as_ref())).map_err(unencodable);
    }
    let typed = typed(input)?;
    // Without a readable policy everything but the allow-list is checked.
    let allowed = policy.as_ref().and_then(|p| p.allowed_routes.as_deref());
    let reply = match check_input(&typed, allowed) {
        Err(problems) => RoutesReply::Invalid { problems },
        Ok(routes) if command == Command::CheckRoutes => RoutesReply::Ok { routes },
        Ok(routes) => {
            let dir = settings_dir.ok_or(SettingsFailureCode::Unwritable)?;
            let current = stored(dir)?;
            if let Some(text) = &current {
                understood(text)?;
            }
            let text = replace_routes(current.as_deref(), &routes)?;
            save(dir, &text).map_err(|_| SettingsFailureCode::Unwritable)?;
            RoutesReply::Ok { routes }
        }
    };
    encode(&reply).map_err(unencodable)
}

/// The policy, if its file is there and valid. Nothing fails for want of
/// one: the service refuses to connect without it.
fn policy(dir: &Path) -> Option<Policy> {
    let text = fs::read_to_string(dir.join("policy.json")).ok()?;
    let policy: Policy = serde_json::from_str(&text).ok()?;
    policy.validate().ok().map(|()| policy)
}

/// The one line of input, read without ever taking in more than the limit.
fn typed(input: &mut dyn BufRead) -> Result<RouteInput, SettingsFailureCode> {
    let bad = SettingsFailureCode::BadInput;
    let mut line = Vec::new();
    let limit = MAX_LINE_BYTES as u64 + 1;
    let read = input.take(limit).read_until(b'\n', &mut line);
    if !read.is_ok_and(|n| n > 0) {
        return Err(bad);
    }
    let text = String::from_utf8(line).map_err(|_| bad)?;
    decode(&text).map_err(|_| bad)
}

/// The text of `settings.json`, or `None` when there is no such file. One
/// that is there and cannot be read is an error, not "no settings".
fn stored(dir: &Path) -> Result<Option<String>, SettingsFailureCode> {
    match fs::read_to_string(dir.join(SETTINGS)) {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(SettingsFailureCode::Unreadable),
    }
}

/// The settings in `text`. Anything but a JSON object is refused, although
/// the settings type alone would read some other shapes as defaults.
fn understood(text: &str) -> Result<Settings, SettingsFailureCode> {
    let unreadable = |_| SettingsFailureCode::Unreadable;
    serde_json::from_str::<Map<String, Value>>(text).map_err(unreadable)?;
    serde_json::from_str(text).map_err(unreadable)
}

/// Opens a new file that only the user can read. On Unix that is mode 0600,
/// whatever the umask. On Windows a new file takes the access list of its
/// folder: under the user's profile that is the user, administrators and the
/// system, and nobody else.
fn create_private(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)
}

/// Replaces `settings.json` with `text` in one step: the new file is written
/// beside the old one, synced, and renamed over it. If anything fails the
/// old file is untouched.
fn save(dir: &Path, text: &str) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    let partial = dir.join(PARTIAL);
    // Whatever is at the partial file's name goes first: one a crash left,
    // or a link, which is removed and never written through.
    match fs::remove_file(&partial) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let written = create_private(&partial).and_then(|mut file| {
        file.write_all(text.as_bytes())?;
        file.sync_all()
    });
    let saved = written.and_then(|()| fs::rename(&partial, dir.join(SETTINGS)));
    if saved.is_err() {
        let _ = fs::remove_file(&partial);
    }
    saved
}
