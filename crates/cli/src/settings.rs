//! `ubc-vpn settings`: how the app reads the user's settings and checks and
//! saves routes. The rules are in `ubc_vpn_core::settings_cli`, whose module
//! documentation ("The cases") is the reference; this file only reads the
//! files, calls those rules, and writes one line.
//!
//! The policy is read from the platform's policy folder and validated. No
//! argument and no environment variable can point this at another file.

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

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
/// How long a partial file is left alone. No save takes this long, so an
/// older one was left by a save that was cut short.
const STALE: Duration = Duration::from_secs(3600);

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
    let routes = match check_input(&typed, allowed) {
        Ok(routes) => routes,
        Err(problems) => return encode(&RoutesReply::Invalid { problems }).map_err(unencodable),
    };
    // The reply repeats the routes and so is a little longer than the input,
    // and what `get` prints is longer again. Routes whose reply, or whose
    // settings, would not fit in one line are refused here, before anything
    // is saved: a save must never be reported as a failure, and `get` must
    // never be left unable to answer by what `set-routes` accepted.
    //
    // The two commands can disagree here. `check-routes` does not read the
    // file, so it reckons with default settings; `set-routes` reckons with
    // the settings that are stored, and so may refuse routes that
    // `check-routes` accepted when, say, the saved username is very long.
    let too_long = |_| SettingsFailureCode::BadInput;
    let line = encode(&RoutesReply::Ok {
        routes: routes.clone(),
    })
    .map_err(too_long)?;
    let mut settings = Settings::default();
    let mut current = None;
    if command == Command::SetRoutes {
        let dir = settings_dir.ok_or(SettingsFailureCode::Unwritable)?;
        current = stored(dir)?;
        if let Some(text) = &current {
            settings = understood(text)?;
            // A file `get` cannot show is unreadable here as well, unless
            // its own routes are what makes it too long. Those are about to
            // be replaced, and saving shorter ones is how it is repaired.
            let mut kept = settings.clone();
            kept.routes = Settings::default().routes;
            encode(&SettingsView::new(kept, policy.as_ref())).map_err(unencodable)?;
        }
    }
    settings.routes = routes.clone();
    encode(&SettingsView::new(settings, policy.as_ref())).map_err(too_long)?;
    if let Some(dir) = settings_dir.filter(|_| command == Command::SetRoutes) {
        let text = replace_routes(current.as_deref(), &routes)?;
        save(dir, &text).map_err(|_| SettingsFailureCode::Unwritable)?;
    }
    Ok(line)
}

/// The policy, if its file is there and valid. Nothing fails for want of
/// one: the service refuses to connect without it.
pub(crate) fn policy(dir: &Path) -> Option<Policy> {
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
pub(crate) fn stored(dir: &Path) -> Result<Option<String>, SettingsFailureCode> {
    match fs::read_to_string(dir.join(SETTINGS)) {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(SettingsFailureCode::Unreadable),
    }
}

/// The settings in `text`. Anything but a JSON object is refused, although
/// the settings type alone would read some other shapes as defaults.
pub(crate) fn understood(text: &str) -> Result<Settings, SettingsFailureCode> {
    let unreadable = |_| SettingsFailureCode::Unreadable;
    serde_json::from_str::<Map<String, Value>>(text).map_err(unreadable)?;
    serde_json::from_str(text).map_err(unreadable)
}

/// Opens a new file for the settings. On Unix it is created with mode 0600,
/// whatever the umask, so only the user can read it. On Windows a new file
/// takes the access list of the folder it is in, whatever that is: under a
/// user's profile that is usually the user, administrators and the system,
/// and on a domain machine it can include other accounts. The file holds
/// the username and the routes, and no secret.
fn create_private(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    // The one piece of OS-specific code outside the platform crate, kept
    // here on purpose: it is the standard library's own open option, with no
    // unsafe code, and a platform operation for it would be more code than
    // these lines.
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)
}

/// A name for one save's partial file, unlike that of any other save in
/// this process or another.
pub(crate) fn partial_name() -> String {
    static SAVES: AtomicU64 = AtomicU64::new(0);
    let (pid, nth) = (std::process::id(), SAVES.fetch_add(1, Ordering::Relaxed));
    let since = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH);
    let nanos = since.map_or(0, |d| d.subsec_nanos());
    format!("{SETTINGS}.{pid}-{nth}-{nanos:08x}.tmp")
}

/// Replaces `settings.json` with `text` in one step: the new file is written
/// beside the old one, synced, and renamed over it. If anything fails the
/// old file is untouched.
fn save(dir: &Path, text: &str) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    sweep(dir, STALE);
    let partial = write_partial(dir, text, &mut partial_name)?;
    place(&partial, dir)
}

/// Writes `text` to a new file beside the settings and returns its path.
/// The file is this save's alone: its name comes from `name`, and a name
/// that is taken belongs to another save, or is a link someone put there.
/// What is there is left alone, never written through, and another name is
/// tried.
pub(crate) fn write_partial(
    dir: &Path,
    text: &str,
    name: &mut dyn FnMut() -> String,
) -> io::Result<PathBuf> {
    let mut tries = 0;
    let (partial, mut file) = loop {
        let partial = dir.join(name());
        match create_private(&partial) {
            Ok(file) => break (partial, file),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists && tries < 4 => tries += 1,
            Err(e) => return Err(e),
        }
    };
    let written = file
        .write_all(text.as_bytes())
        .and_then(|()| file.sync_all());
    drop(file);
    if let Err(error) = written {
        let _ = fs::remove_file(&partial);
        return Err(error);
    }
    Ok(partial)
}

/// Makes the finished `partial` the settings file. If that fails the
/// partial file is removed.
pub(crate) fn place(partial: &Path, dir: &Path) -> io::Result<()> {
    let placed = fs::rename(partial, dir.join(SETTINGS));
    if placed.is_err() {
        let _ = fs::remove_file(partial);
    }
    placed
}

/// Whether `name` is one [`partial_name`] makes, or the one name versions
/// before it used. Nothing else in the folder is this program's to remove.
fn is_partial_name(name: &str) -> bool {
    let ours = || {
        let middle = name.strip_prefix("settings.json.")?.strip_suffix(".tmp")?;
        let mut parts = middle.split('-');
        let (pid, nth, nanos) = (parts.next()?, parts.next()?, parts.next()?);
        let digits = |part: &str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
        let hex = nanos.len() == 8 && nanos.bytes().all(|b| b.is_ascii_hexdigit());
        Some(parts.next().is_none() && digits(pid) && digits(nth) && hex)
    };
    name == "settings.json.tmp" || ours() == Some(true)
}

/// Removes the partial files that saves cut short have left in `dir`. One
/// that is not yet `stale` may be a save in progress and is left alone.
pub(crate) fn sweep(dir: &Path, stale: Duration) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        // What is known of the entry itself. A link is not followed, and is
        // not a regular file, so it is never removed.
        let Ok(known) = fs::symlink_metadata(entry.path()) else {
            continue;
        };
        let age = known.modified().ok().and_then(|at| at.elapsed().ok());
        let old = age.is_some_and(|age| age > stale);
        if known.is_file() && old && is_partial_name(&name.to_string_lossy()) {
            // One that cannot be removed is left; the save goes on.
            let _ = fs::remove_file(entry.path());
        }
    }
}
