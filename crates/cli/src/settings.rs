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
use ubc_vpn_core::routes::RouteSet;
use ubc_vpn_core::settings::Settings;
use ubc_vpn_core::settings_cli::{
    ResetReply, RouteInput, RoutesReply, SettingsFailure, SettingsFailureCode, SettingsView,
    check_input, replace_routes, replace_username,
};
use ubc_vpn_platform::{Paths, Platform};

use crate::live;
use crate::settings_lock::change;

const SETTINGS: &str = "settings.json";
/// How long a partial file is left alone. No save takes this long, so an
/// older one was left by a save that was cut short.
const STALE: Duration = Duration::from_secs(3600);

/// How many old settings files `reset` keeps aside. It replaces none of
/// them: with all the names taken, a reset fails and changes nothing.
const KEPT_ASIDE: usize = 3;

/// The commands. Each is spelled with `--json`, the only form so far.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// `settings get --json`
    Get,
    /// `settings check-routes --json`
    CheckRoutes,
    /// `settings set-routes --json`
    SetRoutes,
    /// `settings reset --json`, or with `force` `settings reset --force
    /// --json`, which also resets settings that can be read.
    Reset {
        /// Whether a settings file that can be read is reset too.
        force: bool,
    },
}

impl Command {
    /// Reads the arguments after `settings`, or `None` for wrong usage.
    pub fn parse(args: &[&str]) -> Option<Self> {
        match args {
            ["get", "--json"] => Some(Self::Get),
            ["check-routes", "--json"] => Some(Self::CheckRoutes),
            ["set-routes", "--json"] => Some(Self::SetRoutes),
            ["reset", "--json"] => Some(Self::Reset { force: false }),
            ["reset", "--force", "--json"] => Some(Self::Reset { force: true }),
            _ => None,
        }
    }
}

/// Runs one command: writes exactly one line on `out` and returns the exit
/// status, 0 unless that line is a failure. When the failure is that the
/// settings folder is not safe to use, `err` is told why.
pub fn run(
    command: Command,
    platform: &dyn Fn() -> ubc_vpn_platform::Result<Platform>,
    input: &mut dyn BufRead,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    // A system this program cannot place its files on has no settings to
    // read and nowhere to save them.
    let platform = platform().ok();
    let paths = platform.as_ref().map(|platform| &platform.paths);
    let answered = answer(command, paths, input).map(|(line, saved)| {
        // Routes just saved go to the live connection too, once the lock
        // on the settings is let go: the service may take a moment.
        match (saved, &platform) {
            (Some(routes), Some(platform)) => {
                let live = live::apply(platform, &routes, crate::client::Limits::default());
                let reply = RoutesReply::Ok {
                    routes,
                    live: Some(live),
                };
                // The routes fit in a line before; a reply that would not
                // with what the service said is given without it.
                encode(&reply).unwrap_or(line)
            }
            _ => line,
        }
    });
    let failed = answered.is_err();
    let about_files = [
        Err(SettingsFailureCode::Unreadable),
        Err(SettingsFailureCode::Unwritable),
    ];
    let dir = paths.as_ref().map(|paths| paths.settings_dir.as_path());
    if let Some(why) = dir
        .filter(|_| about_files.contains(&answered))
        .and_then(folder_problem)
    {
        let _ = writeln!(err, "ubc-vpn: {why}");
    }
    let unwritten = answered == Err(SettingsFailureCode::Unwritable);
    if let Some(why) = dir.and_then(|dir| kept_notice(command, unwritten, dir)) {
        let _ = writeln!(err, "ubc-vpn: {why}");
    }
    let line = answered.or_else(|error| encode(&SettingsFailure { error }));
    let written = out.write_all(line.unwrap_or_default().as_bytes());
    let unsaid = written.and_then(|()| out.flush()).is_err();
    u8::from(failed || unsaid)
}

/// For tests only: something to do in the middle of a save.
#[cfg(test)]
pub(crate) type Look = Box<dyn Fn(&Path)>;

// For tests only: what to do in the middle of every save made on this
// thread, to look at what the one saving holds at that moment.
#[cfg(test)]
thread_local! {
    pub(crate) static DURING_A_SAVE: std::cell::RefCell<Option<Look>> =
        const { std::cell::RefCell::new(None) };
}

/// What to say about the kept files, if anything: only when it was a reset
/// that could not write, and only when their names being taken is why.
pub(crate) fn kept_notice(command: Command, unwritten: bool, dir: &Path) -> Option<String> {
    let reset = matches!(command, Command::Reset { .. });
    nowhere_to_keep(dir).filter(|_| reset && unwritten)
}

/// The line to write for `command`, or why there is none.
fn answer(
    command: Command,
    paths: Option<&Paths>,
    input: &mut dyn BufRead,
) -> Result<(String, Option<RouteSet>), SettingsFailureCode> {
    let policy = paths.and_then(|paths| policy(&paths.policy_dir));
    let settings_dir = paths.map(|paths| paths.settings_dir.as_path());
    let unencodable = |_| SettingsFailureCode::Unreadable;
    if command == Command::Get {
        let dir = settings_dir.ok_or(SettingsFailureCode::Unreadable)?;
        let settings = match stored(dir)? {
            Some(text) => understood(&text)?,
            None => Settings::default(),
        };
        let line = encode(&SettingsView::new(settings, policy.as_ref())).map_err(unencodable)?;
        return Ok((line, None));
    }
    if let Command::Reset { force } = command {
        let dir = settings_dir.ok_or(SettingsFailureCode::Unwritable)?;
        let line = encode(&reset(dir, policy.as_ref(), force)?).map_err(unencodable)?;
        return Ok((line, None));
    }
    let typed = typed(input)?;
    // Without a readable policy everything but the allow-list is checked.
    let allowed = policy.as_ref().and_then(|p| p.allowed_routes.as_deref());
    let routes = match check_input(&typed, allowed) {
        Ok(routes) => routes,
        Err(problems) => {
            let line = encode(&RoutesReply::Invalid { problems }).map_err(unencodable)?;
            return Ok((line, None));
        }
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
        live: None,
    })
    .map_err(too_long)?;
    let mut settings = Settings::default();
    let mut current = None;
    // Held from the read of the stored settings to the save below, so that
    // no other change to them can fall in between and be undone by it.
    let mut _changing = None;
    if command == Command::SetRoutes {
        let dir = settings_dir.ok_or(SettingsFailureCode::Unwritable)?;
        _changing = Some(change(dir)?);
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
    let saved = (command == Command::SetRoutes).then_some(routes);
    Ok((line, saved))
}

/// Saves `username` in the settings in `dir`, or removes the saved one when
/// it is `None`, changing nothing else in the file. Nothing is saved that
/// would leave `settings get` unable to show the file.
pub(crate) fn remember_username(
    dir: &Path,
    policy: Option<&Policy>,
    username: Option<&str>,
) -> Result<(), SettingsFailureCode> {
    let _changing = change(dir)?;
    let current = stored(dir)?;
    let text = replace_username(current.as_deref(), username)?;
    let too_long = |_| SettingsFailureCode::BadInput;
    encode(&SettingsView::new(understood(&text)?, policy)).map_err(too_long)?;
    save(dir, &text).map_err(|_| SettingsFailureCode::Unwritable)
}

/// Starts the settings afresh when the file cannot be read, or whatever it
/// holds with `force`. The old file is never destroyed: it is moved aside,
/// as it is, under one of [`KEPT_ASIDE`] names that nothing here removes or
/// replaces. With every name taken nothing is changed and the answer is
/// [`SettingsFailureCode::Unwritable`].
///
/// If the fresh file cannot be written after the move the answer is also
/// [`SettingsFailureCode::Unwritable`], with the old file already aside.
/// There is then no settings file, which reads as the defaults all the same.
fn reset(
    dir: &Path,
    policy: Option<&Policy>,
    force: bool,
) -> Result<ResetReply, SettingsFailureCode> {
    let fresh = |dir: &Path| save(dir, "{}\n");
    reset_with(dir, policy, force, &keep_aside, &fresh)
}

/// [`reset`], with the two things it does to the files given by the caller:
/// `aside` moves the settings file away and returns its new name, and
/// `fresh` writes the new one.
pub(crate) fn reset_with(
    dir: &Path,
    policy: Option<&Policy>,
    force: bool,
    aside: &dyn Fn(&Path) -> io::Result<String>,
    fresh: &dyn Fn(&Path) -> io::Result<()>,
) -> Result<ResetReply, SettingsFailureCode> {
    // A folder others can write to is not touched, to reset it either.
    if folder_problem(dir).is_some() {
        return Err(SettingsFailureCode::Unreadable);
    }
    // With no settings folder there are no settings to reset, and none is
    // made for the asking.
    if !dir.is_dir() {
        return Ok(ResetReply::NotNeeded);
    }
    let _changing = change(dir)?;
    // Whatever is at the name counts, a link or a folder too. The link
    // itself is asked about and later moved, and never followed. With
    // nothing there, there is nothing to reset and nothing is made.
    match fs::symlink_metadata(dir.join(SETTINGS)) {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(ResetReply::NotNeeded),
        Err(_) => return Err(SettingsFailureCode::Unwritable),
    }
    // "Can be read" means what it means to `get`: it loads, and fits a line.
    let shown = stored(dir).and_then(|text| {
        let settings = understood(&text.unwrap_or_default())?;
        let unshowable = |_| SettingsFailureCode::Unreadable;
        encode(&SettingsView::new(settings, policy)).map_err(unshowable)
    });
    if shown.is_ok() && !force {
        return Ok(ResetReply::NotNeeded);
    }
    let unwritable = |_| SettingsFailureCode::Unwritable;
    let kept = aside(dir).map_err(unwritable)?;
    fresh(dir).map_err(unwritable)?;
    Ok(ResetReply::Reset { kept })
}

/// The names a reset keeps old settings files under, lowest first.
fn kept_names() -> impl Iterator<Item = String> {
    (1..=KEPT_ASIDE).map(|n| format!("{SETTINGS}.damaged-{n}"))
}

/// Moves `settings.json` to the lowest of those names that is free and
/// returns the name. Anything at a name takes it, a folder or a link too,
/// and nothing that is there is ever replaced: with no name free this fails
/// and moves nothing.
fn keep_aside(dir: &Path) -> io::Result<String> {
    let free = |name: &String| {
        let found = fs::symlink_metadata(dir.join(name));
        found.is_err_and(|e| e.kind() == io::ErrorKind::NotFound)
    };
    let name = kept_names()
        .find(free)
        .ok_or(io::ErrorKind::AlreadyExists)?;
    fs::rename(dir.join(SETTINGS), dir.join(&name))?;
    Ok(name)
}

/// What to tell the user when a reset fails because every name it keeps old
/// settings under is taken, if that is so.
pub(crate) fn nowhere_to_keep(dir: &Path) -> Option<String> {
    let taken = |name: String| fs::symlink_metadata(dir.join(name)).is_ok();
    let (first, last) = (kept_names().next()?, kept_names().last()?);
    let folder = crate::clean(&dir.to_string_lossy());
    kept_names().all(taken).then(|| {
        format!(
            "Nothing was reset. Earlier settings files are kept as {first} to {last} in \
             {folder}, and a reset never replaces one. Remove those you no longer need, \
             then reset again."
        )
    })
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

/// Why the settings folder is not used, when it is not. On Unix that is a
/// folder its group, or anyone, may write to: whoever can write there can
/// replace the settings, and with them the routes the next connect asks
/// for. A link is judged by the folder it leads to, which is the one used. On Windows a folder takes its access list from the profile it is in,
/// and nothing is checked.
pub(crate) fn folder_problem(dir: &Path) -> Option<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let open = |found: fs::Metadata| found.permissions().mode() & 0o022 != 0;
        if fs::metadata(dir).is_ok_and(open) {
            // Quoted for a shell as it stands, whatever the path holds.
            let folder = crate::clean(&dir.to_string_lossy()).replace('\'', r"'\''");
            return Some(format!(
                "The settings folder can be changed by other users of this computer, so it \
                 is not used. To stop them, run: chmod go-w '{folder}'"
            ));
        }
    }
    let _ = dir;
    None
}

/// Makes the settings folder if it is not there. On Unix a folder made here
/// is the user's alone, mode 0700, whatever the umask; one that is already
/// there is left as it is, and must pass [`folder_problem`].
pub(crate) fn create_folder(dir: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(dir)?;
    match folder_problem(dir) {
        Some(_) => Err(io::ErrorKind::PermissionDenied.into()),
        None => Ok(()),
    }
}

/// The text of `settings.json`, or `None` when there is no such file. One
/// that is there and cannot be read is an error, not "no settings".
pub(crate) fn stored(dir: &Path) -> Result<Option<String>, SettingsFailureCode> {
    if folder_problem(dir).is_some() {
        return Err(SettingsFailureCode::Unreadable);
    }
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
    create_folder(dir)?;
    #[cfg(test)]
    DURING_A_SAVE.with(|look| look.borrow().as_ref().map(|look| look(dir)));
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
            Err(e) if taken(&e) && tries < 4 => tries += 1,
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

/// Whether creating a new file failed because something is at its name.
/// Windows says "access is denied" when that something is a folder.
fn taken(error: &io::Error) -> bool {
    let denied = cfg!(windows) && error.kind() == io::ErrorKind::PermissionDenied;
    error.kind() == io::ErrorKind::AlreadyExists || denied
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
