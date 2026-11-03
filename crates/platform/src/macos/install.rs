//! Installing and removing the service on macOS: its registration with
//! launchd, and the folder that holds the policy and the state.
//!
//! The package's scripts run `ubc-vpn-service install` and `uninstall` as
//! root, as the Windows setup program does, and the service crate decides
//! the order there too. The calls are the ones Windows has, so that the
//! service crate's steps are the same on every OS. What is done here:
//!
//! - **The job.** `packaging/macos/io.github.nima-hs.ubc-vpn.plist`, built
//!   into this program and written as it is to `/Library/LaunchDaemons`,
//!   root's, mode 0644. It starts the service from [`INSTALLED_SERVICE`], and
//!   `register` refuses a program anywhere else, so launchd never starts a
//!   program the folder check has not passed. The file explains each setting.
//! - **launchctl** is run as `/bin/launchctl`, by its absolute path, with an
//!   empty environment and `/` as its folder, so nothing the caller set
//!   reaches it.
//! - **The data folder.** `/Library/Application Support/UBC VPN` holds the
//!   policy, the state and the channel's socket, so every user's client must
//!   reach it and only root may change it: root's, 0755, with `policy.json`
//!   root's, 0644. The folders above it are checked before anything is
//!   touched, so nobody can swap the folder while root works on it. On a fresh
//!   install it is emptied, since anyone may have made it; on an update its
//!   contents are kept. Because the state is in it, a folder that is there
//!   already is never fixed: one that others could change cannot be trusted
//!   afterwards, so the check after it fails and the install stops (see
//!   `unix::state`). Its group alone is set on one that passes that check: a
//!   group without write changes nothing about who can write, and a folder the
//!   service remade itself has the group of the folder above.
//! - **Stopping.** `launchctl bootout` sends the service SIGTERM. It may
//!   return before the service has ended, so launchd is asked until it no
//!   longer knows the job, which it stops knowing once the service has
//!   removed its routes and DNS and ended, or `ExitTimeOut` has passed.

use std::io;
use std::os::unix::fs::lchown;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::unix::root_files::{
    Expected, check_root, clear, make_root_folder, names_in, real_folder, remove_file,
    write_root_file,
};
use crate::{Error, Mode, Result};

/// The job, as `install` writes it.
pub const PLIST: &str = include_str!("../../../../packaging/macos/io.github.nima-hs.ubc-vpn.plist");

/// The job's name for launchd. The command-line client tells users to run
/// `launchctl kickstart` with it.
pub const LABEL: &str = "io.github.nima-hs.ubc-vpn";

/// The job's file name.
const PLIST_NAME: &str = "io.github.nima-hs.ubc-vpn.plist";

/// The job in launchd's system domain.
const JOB: &str = "system/io.github.nima-hs.ubc-vpn";

/// The one name the service is registered by.
const SERVICE_NAME: &str = "ubc-vpn";

/// Where the package installs the service, and where the job starts it.
pub const INSTALLED_SERVICE: &str =
    "/Library/PrivilegedHelperTools/io.github.nima-hs.ubc-vpn/ubc-vpn-service";

/// The folder for daemons the administrator installs.
const DAEMONS: &str = "/Library/LaunchDaemons";

/// launchctl, by its absolute path, never looked for.
pub(crate) const LAUNCHCTL: &str = "/bin/launchctl";

/// What the service writes when it cannot start. The job's `StandardErrorPath`.
const LOG: &str = "/Library/Application Support/UBC VPN/service.log";

/// The policy file's name in the data folder.
const POLICY: &str = "policy.json";

/// The data folder: every user reads the policy and reaches the channel.
const FOLDER_MODE: u32 = 0o755;
/// `policy.json`: root writes it, every user reads it.
const POLICY_MODE: u32 = 0o644;
/// The job: root writes it. launchd refuses one that others can change.
const PLIST_MODE: u32 = 0o644;

/// How long to wait for the service to start, at most. It waits up to a
/// minute itself for its channel's name when another program holds it.
const START_WAIT: Duration = Duration::from_secs(90);

/// How long to wait for the service to stop, at most: the job's `ExitTimeOut`,
/// after which launchd kills it, and some time for that.
const STOP_WAIT: Duration = Duration::from_secs(45);

/// launchctl's exit code for a job it does not know.
const NOT_LOADED: i32 = 113;

/// `launchctl bootout`'s exit code when the job has not ended yet (`EINPROGRESS`).
const STILL_ENDING: i32 = 36;

/// `launchctl bootout`'s exit code when the job ended just before it asked
/// (`ESRCH`).
const ALREADY_GONE: i32 = 3;

/// What the service is registered as.
pub struct Registration<'a> {
    /// The name the service manager knows it by.
    pub name: &'a str,
    /// The name shown to people. Unused here: a job has no such name.
    pub display_name: &'a str,
    /// The text shown beside it. Unused here: a job has no such text.
    pub description: &'a str,
    /// The full command line, as the job's `ProgramArguments` holds it.
    pub command_line: String,
}

/// The command line for `program` with no arguments, as a job's
/// `ProgramArguments` takes it: its path, since launchd runs no shell.
///
/// Refused: a path that is not absolute or not UTF-8, and one with a control
/// character in it.
pub fn quoted(program: &Path) -> Result<String> {
    let text = program.to_str().ok_or(Error::InvalidInput)?;
    if !program.is_absolute() || text.chars().any(char::is_control) {
        return Err(Error::InvalidInput);
    }
    Ok(text.to_string())
}

/// Brings the job up to date, after stopping the service if it runs. It is
/// not started.
///
/// Only `ubc-vpn`, and only with the command line the job has: the job is the
/// one the package ships, and it starts the service from
/// [`INSTALLED_SERVICE`] alone.
pub fn register(registration: &Registration) -> Result<()> {
    register_with(&Launchctl, Path::new(DAEMONS), registration, STOP_WAIT)
}

/// Loads the job, which starts the service and starts it with the system from
/// now on, and waits until it runs and listens.
pub fn start(name: &str) -> Result<()> {
    if name != SERVICE_NAME {
        return Err(Error::InvalidInput);
    }
    start_with(
        &Launchctl,
        Path::new(DAEMONS),
        Path::new(super::CHANNEL),
        START_WAIT,
    )
}

/// Stops the service, which removes its routes and DNS first, and removes the
/// job. A service that is not installed is fine.
pub fn unregister(name: &str) -> Result<()> {
    if name != SERVICE_NAME {
        return Err(Error::InvalidInput);
    }
    unregister_with(&Launchctl, Path::new(DAEMONS), STOP_WAIT)
}

/// Makes the data folder `dir`, or on a `fresh` install empties it first.
/// Nothing is touched unless only root can change the folders above it. A
/// folder that is kept is left as it is found, for [`verify_data_folder`] to
/// judge, but for the group of one that is safe.
pub fn prepare_data_folder(dir: &Path, fresh: bool) -> Result<()> {
    let above = dir.parent().ok_or(Error::InvalidInput)?;
    check_data_folder(above)?;
    if fresh {
        clear(dir)?;
    }
    if !real_folder(dir)? {
        make_root_folder(dir, FOLDER_MODE)?;
    } else if check_data_folder(dir).is_ok() {
        lchown(dir, None, Some(0))?;
    }
    Ok(())
}

/// The check the service makes of its state folder: `dir` and every folder
/// above it are root's and changed by root alone.
fn check_data_folder(dir: &Path) -> Result<()> {
    crate::unix::state::check_folder(Mode::Installed, dir)
        .map_err(|error| Error::Failed(format!("{}: {error}", dir.display())))
}

/// Writes `policy` as `policy.json` in the data folder `dir`.
pub fn write_policy(dir: &Path, policy: &[u8]) -> Result<()> {
    write_root_file(dir, POLICY, policy, POLICY_MODE)
}

/// Checks the data folder `dir` once it is prepared and the policy written,
/// as the service and the client will check it, and after a fresh install
/// that it holds the policy alone.
pub fn verify_data_folder(dir: &Path, fresh: bool) -> Result<()> {
    check_data_folder(dir)?;
    check_root(dir, Expected::Folder, FOLDER_MODE)?;
    check_root(&dir.join(POLICY), Expected::File, POLICY_MODE)?;
    if fresh {
        let found = names_in(dir)?;
        if found != [POLICY] {
            let extra: Vec<String> = found.into_iter().filter(|name| name != POLICY).collect();
            return Err(Error::Failed(format!(
                "the data folder holds {} as well as the policy, so something else made or \
                 changed it during the install",
                extra.join(", ")
            )));
        }
    }
    Ok(())
}

/// Removes the data folder `dir` and everything in it. A missing folder is
/// fine.
pub fn remove_data_folder(dir: &Path) -> Result<()> {
    clear(dir)
}

/// What launchctl said.
pub(crate) struct Said {
    /// Its exit code, or `None` when a signal ended it.
    pub(crate) code: Option<i32>,
    pub(crate) out: String,
    pub(crate) err: String,
}

/// Runs launchctl. The tests record the calls instead.
pub(crate) trait Launchd {
    fn run(&self, args: &[&str]) -> Result<Said>;
}

struct Launchctl;

impl Launchd for Launchctl {
    fn run(&self, args: &[&str]) -> Result<Said> {
        let done = match command(args).output() {
            Ok(done) => done,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(Error::Unsupported);
            }
            Err(error) => return Err(Error::Failed(format!("launchctl did not start: {error}"))),
        };
        Ok(Said {
            code: done.status.code(),
            out: String::from_utf8_lossy(&done.stdout).into_owned(),
            err: String::from_utf8_lossy(&done.stderr).into_owned(),
        })
    }
}

/// launchctl with `args`. Security rule: by its absolute path, with nothing
/// of the caller's environment, from `/`, reading nothing.
pub(crate) fn command(args: &[&str]) -> Command {
    let mut command = Command::new(LAUNCHCTL);
    command
        .env_clear()
        .current_dir("/")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

/// The failure of launchctl `args`, which said `said`.
fn failed(args: &[&str], said: &Said) -> Error {
    let text = [said.err.trim(), said.out.trim()];
    let why = text.into_iter().find(|text| !text.is_empty()).unwrap_or("");
    let why = why.lines().next().unwrap_or_default();
    let code = said
        .code
        .map_or("a signal".to_string(), |code| format!("code {code}"));
    Error::Failed(format!(
        "`launchctl {}` failed ({code}): {why}",
        args.join(" ")
    ))
}

/// Runs launchctl with `args` and fails unless it succeeded, or ended with
/// one of the codes in `also`.
fn must(launchd: &dyn Launchd, args: &[&str], also: &[i32]) -> Result<()> {
    let said = launchd.run(args)?;
    match said.code {
        Some(0) => Ok(()),
        Some(code) if also.contains(&code) => Ok(()),
        _ => Err(failed(args, &said)),
    }
}

/// What launchd says of the job.
#[derive(Debug, PartialEq)]
pub(crate) enum Job {
    /// It does not know the job.
    NotLoaded,
    /// It runs.
    Running,
    /// It has ended with an error, and may be started again later.
    Failed,
    /// Anything else, such as still starting.
    Waiting,
}

/// The value of a setting of the job itself in `launchctl print`'s output.
/// Those are the lines one tab in: lines further in are about something else.
fn setting<'a>(print: &'a str, name: &str) -> Option<&'a str> {
    print
        .lines()
        .filter_map(|line| line.strip_prefix('\t'))
        .find_map(|line| line.strip_prefix(name)?.strip_prefix(" = "))
}

/// Asks launchd about the job. An answer it cannot read is an error, not
/// "not loaded", so that a stop never counts as done on a guess.
pub(crate) fn job(launchd: &dyn Launchd) -> Result<Job> {
    let args = ["print", JOB];
    let said = launchd.run(&args)?;
    match said.code {
        Some(NOT_LOADED) => Ok(Job::NotLoaded),
        Some(0) => Ok(match setting(&said.out, "state") {
            Some("running") => Job::Running,
            _ => match setting(&said.out, "last exit code").map(str::parse::<i32>) {
                Some(Ok(code)) if code != 0 => Job::Failed,
                _ => Job::Waiting,
            },
        }),
        _ => Err(failed(&args, &said)),
    }
}

/// Whether launchd has the job marked as not to be loaded, as
/// `launchctl disable` leaves it, for good.
pub(crate) fn is_disabled(print_disabled: &str) -> bool {
    let quoted = format!("\"{LABEL}\" => ");
    print_disabled
        .lines()
        .filter_map(|line| line.trim_start().strip_prefix(quoted.as_str()))
        // `disabled` on newer systems, `true` on older ones.
        .any(|value| matches!(value.trim(), "disabled" | "true"))
}

/// Unloads the job if it is loaded, and waits until it has ended. launchd
/// knows the job until then. Waits up to `wait`.
fn stop_with(launchd: &dyn Launchd, wait: Duration) -> Result<()> {
    if job(launchd)? == Job::NotLoaded {
        return Ok(());
    }
    must(
        launchd,
        &["bootout", JOB],
        &[NOT_LOADED, STILL_ENDING, ALREADY_GONE],
    )?;
    let started = Instant::now();
    while job(launchd)? != Job::NotLoaded {
        if started.elapsed() > wait {
            return Err(Error::TimedOut);
        }
        thread::sleep(Duration::from_millis(200));
    }
    Ok(())
}

pub(crate) fn register_with(
    launchd: &dyn Launchd,
    daemons: &Path,
    registration: &Registration,
    wait: Duration,
) -> Result<()> {
    if registration.name != SERVICE_NAME {
        return Err(Error::InvalidInput);
    }
    // Security rule: the job starts only the program at the installed place,
    // which `install` checked before it changed anything.
    if registration.command_line != INSTALLED_SERVICE {
        return Err(Error::Failed(format!(
            "the service can be registered only from {INSTALLED_SERVICE}, where the job starts it"
        )));
    }
    // A service that is running is stopped first, which removes its routes
    // and DNS, so the new program starts afresh.
    stop_with(launchd, wait)?;
    write_root_file(daemons, PLIST_NAME, PLIST.as_bytes(), PLIST_MODE)
}

pub(crate) fn start_with(
    launchd: &dyn Launchd,
    daemons: &Path,
    channel: &Path,
    wait: Duration,
) -> Result<()> {
    // Installing means wanting it to run, as `systemctl enable` does on
    // Linux. Only when it is marked, since this leaves a record behind.
    let args = ["print-disabled", "system"];
    let said = launchd.run(&args)?;
    if said.code != Some(0) {
        return Err(failed(&args, &said));
    }
    if is_disabled(&said.out) {
        must(launchd, &["enable", JOB], &[])?;
    }
    let plist = daemons.join(PLIST_NAME);
    let plist = plist.to_str().ok_or(Error::InvalidInput)?;
    must(launchd, &["bootstrap", "system", plist], &[])?;
    let started = Instant::now();
    loop {
        match job(launchd)? {
            // A socket can be left from a service that was killed, so only a
            // connection shows that it listens. It claims nothing: a client
            // claims the service with a request, and this sends none.
            Job::Running if UnixStream::connect(channel).is_ok() => return Ok(()),
            Job::NotLoaded => {
                return Err(Error::Failed(
                    "the service's job went away as it started".to_string(),
                ));
            }
            Job::Failed => {
                return Err(Error::Failed(format!(
                    "the service stopped as it started; {LOG} says why"
                )));
            }
            _ if started.elapsed() > wait => return Err(Error::TimedOut),
            _ => thread::sleep(Duration::from_millis(200)),
        }
    }
}

pub(crate) fn unregister_with(launchd: &dyn Launchd, daemons: &Path, wait: Duration) -> Result<()> {
    // Stopped before anything is removed, and waited for: SIGTERM, then its
    // teardown. A job whose file was removed by hand may still be loaded, so
    // it is stopped all the same. A stop that fails removes nothing.
    stop_with(launchd, wait)?;
    remove_file(&daemons.join(PLIST_NAME))
}

#[cfg(test)]
#[path = "install_tests.rs"]
mod tests;
