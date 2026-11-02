//! Installing and removing the service on Linux: the systemd unit, and the
//! folders that hold the policy and the state.
//!
//! The packages' scripts run `ubc-vpn-service install` and `uninstall` as
//! root (decision G9), as the Windows setup program does, and the service
//! crate decides the order. The calls are the ones Windows has. What is done
//! here:
//!
//! - **The unit.** `packaging/linux/ubc-vpn.service`, built into this
//!   program and written as it is to `/etc/systemd/system/ubc-vpn.service`,
//!   root's, mode 0644. It starts the service from [`INSTALLED_SERVICE`],
//!   quoted, and `register` refuses a program anywhere else, so the unit
//!   never starts a program the folder check has not passed. The unit
//!   explains each of its settings.
//! - **systemctl** is run as `/usr/bin/systemctl`, by its absolute path,
//!   with an empty environment and `/` as its folder, so nothing the caller
//!   set reaches it.
//! - **Two folders.** The policy is in `/etc/ubc-vpn` (root's, 0755, so the
//!   command-line client can read it as the user) as `policy.json` (root's,
//!   0644). The state is in `/var/lib/ubc-vpn` (root's, 0700). The calls
//!   that take the data folder are given the policy folder, and do the same
//!   to the state folder: on a fresh install both are emptied, since
//!   anyone may have made them; on an update their contents are kept. The
//!   policy folder's owner and mode are set on every install, as Windows
//!   sets its access list. The state folder is never fixed: one that others
//!   could change cannot be trusted afterwards, so the check after it fails
//!   and the install stops (see `unix::state`).
//! - **Stopping.** `systemctl stop` and `disable --now` send the service
//!   SIGTERM and wait until it has removed its routes and DNS and ended, for
//!   as long as the unit's `TimeoutStopSec` allows.

use std::fs::{self, DirBuilder, OpenOptions, Permissions};
use std::io::{self, Write};
use std::os::unix::fs::{
    DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt, fchown, lchown,
};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use rustix::fs::OFlags;

use crate::{Error, Mode, Result};

/// The unit, as `install` writes it.
pub const UNIT: &str = include_str!("../../../../packaging/linux/ubc-vpn.service");

/// The unit's file name: the service's name for systemd.
pub const UNIT_NAME: &str = "ubc-vpn.service";

/// The one name the service is registered by. The command-line client tells
/// users to run `systemctl start ubc-vpn`.
const SERVICE_NAME: &str = "ubc-vpn";

/// Where the packages install the service, and where the unit starts it.
pub const INSTALLED_SERVICE: &str = "/opt/UBC VPN/resources/bin/ubc-vpn-service";

/// The folder for units the administrator installs.
const UNIT_DIR: &str = "/etc/systemd/system";

/// The folder of links `systemctl enable` makes for the unit's `WantedBy=`.
const WANTED_BY: &str = "multi-user.target.wants";

/// systemctl, by its absolute path, never looked for.
pub(crate) const SYSTEMCTL: &str = "/usr/bin/systemctl";

/// The policy file's name in the policy folder.
const POLICY: &str = "policy.json";

/// The policy folder: every user reads the policy.
const POLICY_FOLDER_MODE: u32 = 0o755;
/// `policy.json`: root writes it, every user reads it.
const POLICY_MODE: u32 = 0o644;
/// The state folder: root's alone. The same as `StateDirectoryMode`.
const STATE_FOLDER_MODE: u32 = 0o700;
/// The unit: root writes it, systemd and anyone may read it.
const UNIT_MODE: u32 = 0o644;

/// How long to wait for the service to start, at most. It waits up to a
/// minute itself for its channel's name when another program holds it.
const START_WAIT: Duration = Duration::from_secs(90);

/// systemctl's exit code for a unit that is not loaded, as for `stop` of a
/// unit systemd does not know.
const NOT_LOADED: i32 = 5;

/// What the service is registered as.
pub struct Registration<'a> {
    /// The name the service manager knows it by.
    pub name: &'a str,
    /// The name shown to people. The unit's `Description=` says it.
    pub display_name: &'a str,
    /// The text shown beside it. Unused here: a unit has no such text.
    pub description: &'a str,
    /// The full command line, the program's path quoted.
    pub command_line: String,
}

/// The command line for `program` with no arguments, as a unit's
/// `ExecStart=` takes it: its path in double quotes.
///
/// Refused, since systemd would read them as something else: a path that is
/// not absolute or not UTF-8, and one with a quote, a backslash, `%` (a
/// specifier), `$` (a variable) or a control character in it.
pub fn quoted(program: &Path) -> Result<String> {
    let text = program.to_str().ok_or(Error::InvalidInput)?;
    let special = |c: char| matches!(c, '"' | '\\' | '%' | '$') || c.is_control();
    if !program.is_absolute() || text.chars().any(special) {
        return Err(Error::InvalidInput);
    }
    Ok(format!("\"{text}\""))
}

/// Brings the unit up to date, after stopping the service if it runs. It is
/// not started.
///
/// Only `ubc-vpn`, and only with the command line the unit has: the unit is
/// the one the packages ship, and it starts the service from
/// [`INSTALLED_SERVICE`] alone.
pub fn register(registration: &Registration) -> Result<()> {
    register_with(&Systemctl, Path::new(UNIT_DIR), registration)
}

/// Starts the service, and enables it so that it starts with the system,
/// then waits until it runs and listens.
pub fn start(name: &str) -> Result<()> {
    if name != SERVICE_NAME {
        return Err(Error::InvalidInput);
    }
    start_with(&Systemctl, Path::new(super::CHANNEL))
}

/// Stops the service, which removes its routes and DNS first, disables it
/// and removes the unit. A service that is not installed is fine.
pub fn unregister(name: &str) -> Result<()> {
    if name != SERVICE_NAME {
        return Err(Error::InvalidInput);
    }
    unregister_with(&Systemctl, Path::new(UNIT_DIR))
}

/// Makes the policy folder `dir` and the state folder, or on a `fresh`
/// install empties them first. The policy folder's owner and mode are set.
pub fn prepare_data_folder(dir: &Path, fresh: bool) -> Result<()> {
    prepare_in(&Folders::with_policy(dir), fresh)
}

/// Writes `policy` as `policy.json` in the policy folder `dir`.
pub fn write_policy(dir: &Path, policy: &[u8]) -> Result<()> {
    write_root_file(dir, POLICY, policy, POLICY_MODE)
}

/// Checks the policy folder `dir` and the state folder once they are
/// prepared and the policy written, as the service and the client will
/// check them, and after a fresh install that they hold the policy alone.
pub fn verify_data_folder(dir: &Path, fresh: bool) -> Result<()> {
    verify_in(&Folders::with_policy(dir), fresh)
}

/// Removes the policy folder `dir` and the state folder, and everything in
/// them. Missing folders are fine.
pub fn remove_data_folder(dir: &Path) -> Result<()> {
    remove_in(&Folders::with_policy(dir))
}

/// The two folders, apart for the tests.
pub(crate) struct Folders {
    pub(crate) policy: PathBuf,
    pub(crate) state: PathBuf,
}

impl Folders {
    fn with_policy(policy: &Path) -> Self {
        Self {
            policy: policy.to_path_buf(),
            state: PathBuf::from(super::STATE),
        }
    }
}

/// What systemctl said.
pub(crate) struct Said {
    /// Its exit code, or `None` when a signal ended it.
    pub(crate) code: Option<i32>,
    pub(crate) out: String,
    pub(crate) err: String,
}

/// Runs systemctl. The tests record the calls instead.
pub(crate) trait Systemd {
    fn run(&self, args: &[&str]) -> Result<Said>;
}

struct Systemctl;

impl Systemd for Systemctl {
    fn run(&self, args: &[&str]) -> Result<Said> {
        let done = match command(args).output() {
            Ok(done) => done,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(Error::Unsupported);
            }
            Err(error) => return Err(Error::Failed(format!("systemctl did not start: {error}"))),
        };
        Ok(Said {
            code: done.status.code(),
            out: String::from_utf8_lossy(&done.stdout).into_owned(),
            err: String::from_utf8_lossy(&done.stderr).into_owned(),
        })
    }
}

/// systemctl with `args`. Security rule: by its absolute path, with nothing
/// of the caller's environment, from `/`, reading nothing.
pub(crate) fn command(args: &[&str]) -> Command {
    let mut command = Command::new(SYSTEMCTL);
    command
        .env_clear()
        .current_dir("/")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

/// Runs systemctl with `args` and fails unless it succeeded, or ended with
/// one of the codes in `also`.
fn must(systemd: &dyn Systemd, args: &[&str], also: &[i32]) -> Result<()> {
    let said = systemd.run(args)?;
    match said.code {
        Some(0) => Ok(()),
        Some(code) if also.contains(&code) => Ok(()),
        code => {
            let text = [said.err.trim(), said.out.trim()];
            let why = text.into_iter().find(|text| !text.is_empty()).unwrap_or("");
            let why = why.lines().next().unwrap_or_default();
            let code = code.map_or("a signal".to_string(), |code| format!("code {code}"));
            Err(Error::Failed(format!(
                "`systemctl {}` failed ({code}): {why}",
                args.join(" ")
            )))
        }
    }
}

/// The program a unit's `ExecStart=` names, as it is written there.
pub(crate) fn exec_start(unit: &str) -> Option<&str> {
    let mut found = unit
        .lines()
        .filter_map(|line| line.strip_prefix("ExecStart="));
    match (found.next(), found.next()) {
        (Some(only), None) => Some(only),
        _ => None,
    }
}

pub(crate) fn register_with(
    systemd: &dyn Systemd,
    units: &Path,
    registration: &Registration,
) -> Result<()> {
    if registration.name != SERVICE_NAME {
        return Err(Error::InvalidInput);
    }
    // Security rule: the unit starts only the program at the installed
    // place, which `install` checked before it changed anything.
    if exec_start(UNIT) != Some(registration.command_line.as_str()) {
        return Err(Error::Failed(format!(
            "the service can be registered only from {INSTALLED_SERVICE}, where the unit starts it"
        )));
    }
    // A service that is running is stopped first, which removes its routes
    // and DNS, so the new program starts afresh. One that is not loaded is
    // fine.
    must(systemd, &["stop", UNIT_NAME], &[NOT_LOADED])?;
    write_root_file(units, UNIT_NAME, UNIT.as_bytes(), UNIT_MODE)?;
    must(systemd, &["daemon-reload"], &[])
}

pub(crate) fn start_with(systemd: &dyn Systemd, channel: &Path) -> Result<()> {
    // Earlier failures would count towards the unit's limit on starts.
    let _ = systemd.run(&["reset-failed", UNIT_NAME]);
    must(systemd, &["enable", "--now", UNIT_NAME], &[])?;
    let started = Instant::now();
    loop {
        let state = systemd.run(&["is-active", UNIT_NAME])?;
        let listening =
            fs::symlink_metadata(channel).is_ok_and(|found| found.file_type().is_socket());
        match state.out.trim() {
            "active" if listening => return Ok(()),
            // `enable --now` waited for the start, so a service that is not
            // running now has ended already: with an error ("failed"), or
            // by itself ("inactive"), which it never does unasked.
            "failed" | "inactive" => {
                return Err(Error::Failed(
                    "the service stopped as it started; `journalctl -u ubc-vpn` says why"
                        .to_string(),
                ));
            }
            _ if started.elapsed() > START_WAIT => return Err(Error::TimedOut),
            _ => thread::sleep(Duration::from_millis(200)),
        }
    }
}

pub(crate) fn unregister_with(systemd: &dyn Systemd, units: &Path) -> Result<()> {
    let unit = units.join(UNIT_NAME);
    // Stopped before anything is removed, and waited for: SIGTERM, then its
    // teardown. With no unit file it may still be loaded from one removed
    // by hand, so it is stopped all the same.
    match fs::symlink_metadata(&unit) {
        Ok(_) => must(systemd, &["disable", "--now", UNIT_NAME], &[])?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            must(systemd, &["stop", UNIT_NAME], &[NOT_LOADED])?;
        }
        Err(error) => return Err(error.into()),
    }
    remove_file(&unit)?;
    // `disable` removes the link that starts it with the system, but only
    // while the unit file is there to say where it is. One whose unit was
    // removed by hand keeps it, so it is removed here. Only a link: a file
    // there is not ours.
    let wanted = units.join(WANTED_BY).join(UNIT_NAME);
    if fs::symlink_metadata(&wanted).is_ok_and(|found| found.file_type().is_symlink()) {
        remove_file(&wanted)?;
    }
    must(systemd, &["daemon-reload"], &[])?;
    // Nothing to say if it has no failure to forget.
    let _ = systemd.run(&["reset-failed", UNIT_NAME]);
    Ok(())
}

pub(crate) fn prepare_in(folders: &Folders, fresh: bool) -> Result<()> {
    if fresh {
        clear(&folders.policy)?;
        clear(&folders.state)?;
    }
    // The policy folder is set as it must be, whoever made it.
    match real_folder(&folders.policy)? {
        true => {}
        false => make(&folders.policy, POLICY_FOLDER_MODE)?,
    }
    lchown(&folders.policy, Some(0), Some(0))?;
    fs::set_permissions(&folders.policy, Permissions::from_mode(POLICY_FOLDER_MODE))?;
    // The state folder is made when missing, and otherwise left as it is.
    if !real_folder(&folders.state)? {
        make(&folders.state, STATE_FOLDER_MODE)?;
        lchown(&folders.state, Some(0), Some(0))?;
        fs::set_permissions(&folders.state, Permissions::from_mode(STATE_FOLDER_MODE))?;
    }
    Ok(())
}

/// Whether `path` is a real folder: `false` when there is nothing there,
/// and an error when something else is, a link included.
fn real_folder(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(found) if found.is_dir() => Ok(true),
        Ok(_) => Err(Error::Failed(format!(
            "{} is not a folder; run a fresh install",
            path.display()
        ))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

/// Removes whatever is at `path`. A link is removed itself, never what it
/// points to.
fn clear(path: &Path) -> Result<()> {
    let removed = match fs::symlink_metadata(path) {
        Ok(found) if found.is_dir() => fs::remove_dir_all(path),
        Ok(_) => fs::remove_file(path),
        Err(error) => Err(error),
    };
    match removed {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error.into()),
        _ => Ok(()),
    }
}

/// Removes the file or link `path`. Nothing there is fine.
fn remove_file(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error.into()),
        _ => Ok(()),
    }
}

/// Makes the folder `path` with `mode`. Its owner and mode are set after.
fn make(path: &Path, mode: u32) -> Result<()> {
    Ok(DirBuilder::new().mode(mode).create(path)?)
}

/// Writes `bytes` as `name` in `dir`, root's with `mode` whatever the umask,
/// replacing any. It is written beside it first and then moved into place,
/// so a reader never sees half of it. A file or link left in the way by an
/// earlier run is removed, never followed.
pub(crate) fn write_root_file(dir: &Path, name: &str, bytes: &[u8], mode: u32) -> Result<()> {
    let next = dir.join(format!(".{name}.new"));
    remove_file(&next)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(OFlags::NOFOLLOW.bits() as i32)
        .open(&next)?;
    file.write_all(bytes)?;
    fchown(&file, Some(0), Some(0))?;
    file.set_permissions(Permissions::from_mode(mode))?;
    file.sync_all()?;
    drop(file);
    fs::rename(&next, dir.join(name))?;
    Ok(())
}

pub(crate) fn verify_in(folders: &Folders, fresh: bool) -> Result<()> {
    let (policy_dir, state) = (&folders.policy, &folders.state);
    // Every user's client reads the policy: the folder and every folder
    // above it are root's and changed by root alone.
    crate::unix::state::check_folder(Mode::Installed, policy_dir)
        .map_err(|error| Error::Failed(format!("{}: {error}", policy_dir.display())))?;
    let exactly = |path: &Path, mode: u32, file: bool| -> Result<()> {
        let found = fs::symlink_metadata(path)?;
        let kind = if file {
            found.is_file()
        } else {
            found.is_dir()
        };
        if !kind || found.uid() != 0 || found.gid() != 0 || found.mode() & 0o7777 != mode {
            return Err(Error::Failed(format!(
                "{} is not root's with mode {mode:o}",
                path.display()
            )));
        }
        Ok(())
    };
    exactly(policy_dir, POLICY_FOLDER_MODE, false)?;
    exactly(&policy_dir.join(POLICY), POLICY_MODE, true)?;
    // The same check the service makes of its state folder.
    crate::unix::state::check_folder(Mode::Installed, state)
        .map_err(|error| Error::Failed(format!("{}: {error}", state.display())))?;
    if fresh {
        exactly(state, STATE_FOLDER_MODE, false)?;
        let names = |dir: &Path| -> Result<Vec<String>> {
            let mut found = Vec::new();
            for entry in fs::read_dir(dir)? {
                found.push(entry?.file_name().to_string_lossy().into_owned());
            }
            found.sort();
            Ok(found)
        };
        let (policies, states) = (names(policy_dir)?, names(state)?);
        if policies != [POLICY] || !states.is_empty() {
            let mut extra: Vec<String> = policies.into_iter().filter(|n| n != POLICY).collect();
            extra.extend(states);
            return Err(Error::Failed(format!(
                "the policy and state folders hold {} as well as the policy, so something else \
                 made or changed them during the install",
                extra.join(", ")
            )));
        }
    }
    Ok(())
}

pub(crate) fn remove_in(folders: &Folders) -> Result<()> {
    clear(&folders.policy)?;
    clear(&folders.state)
}

#[cfg(test)]
#[path = "install_tests.rs"]
mod tests;
