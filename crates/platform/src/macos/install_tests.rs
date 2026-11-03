//! Tests of installing the service on macOS.
//!
//! None of them touches launchd or the real data folder: launchctl is replaced
//! by a recorder, and the folders are made for each test. The ones that need
//! root, to make files root's and to play a stranger's, run in a process of
//! their own, so that no other test's switch of user or umask reaches them,
//! and say `RAN AS ROOT: install <name>` when they passed. CI requires those
//! lines (`.github/ran/platform-unix/macos/install.txt`). The real launchd is
//! tried by `packaging/macos/tests/launchd.sh`.

use std::cell::{Cell, RefCell};
use std::ffi::OsStr;
use std::fs::{self, Permissions};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt, lchown, symlink};
use std::os::unix::net::UnixListener;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

use super::*;
use crate::unix::root_files::set_root_folder;

/// Set in a test's own process to the test's name.
const CHILD: &str = "UBC_VPN_INSTALL_TEST_CHILD";
/// A user that is neither root nor whoever runs the tests. Root can give a
/// file to any user ID, so it needs no account.
const STRANGER: u32 = 54_321;
const SOME_POLICY: &[u8] = br#"{"gateway":"vpn.example.test","pins":["pin-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="]}"#;

static NEXT: AtomicU32 = AtomicU32::new(0);

/// Writes one whole line in one call: CI looks for these lines.
fn say(line: &str) {
    let line = format!("\n{line}\n");
    std::io::stderr().write_all(line.as_bytes()).expect("say");
}

/// A folder for one test, removed afterwards: in a folder only root can
/// change. Its `data` is where the data folder goes.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let count = NEXT.fetch_add(1, Ordering::SeqCst);
        let name = format!("uvt-install-{}-{count}", std::process::id());
        let dir = Path::new(crate::os::ROOT_ONLY).join(name);
        fs::create_dir(&dir).expect("make the scratch folder");
        // Not the group of the folder above, which macOS hands on.
        lchown(&dir, Some(0), Some(0)).expect("its owner");
        fs::set_permissions(&dir, Permissions::from_mode(0o755)).expect("its mode");
        Self(dir)
    }

    fn data(&self) -> PathBuf {
        self.0.join("data")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Runs `body` as root in a process of its own that runs the test function
/// `test` alone, with a scratch folder, and says `RAN AS ROOT: install
/// {name}` when it passed.
fn as_root(name: &str, test: &str, body: impl FnOnce(&Scratch)) {
    if std::env::var(CHILD).as_deref() == Ok(test) {
        let scratch = Scratch::new();
        body(&scratch);
        return;
    }
    if rustix::process::getuid().as_raw() != 0 {
        let required = std::env::var_os("UBC_VPN_REQUIRE_ROOT").is_some();
        assert!(!required, "install {name} needs root");
        say(&format!("SKIPPED, needs root: install {name}"));
        return;
    }
    let module = module_path!();
    let local = module.split_once("::").map_or(module, |(_, rest)| rest);
    let status = Command::new(std::env::current_exe().expect("this program"))
        .args([
            "--exact",
            &format!("{local}::{test}"),
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, test)
        // Root again, should another test have switched the effective user
        // for a moment just as this one started.
        .uid(0)
        .status()
        .expect("start the test's own process");
    assert!(status.success(), "install {name} failed: {status}");
    say(&format!("RAN AS ROOT: install {name}"));
}

/// Sets the umask of this process, which is the test's own.
fn umask(mask: u32) {
    // SAFETY: the call has no memory-safety conditions.
    unsafe { libc::umask(mask as libc::mode_t) };
}

fn owner_group_and_mode(path: &Path) -> (u32, u32, u32) {
    let found = fs::symlink_metadata(path).expect("it exists");
    (found.uid(), found.gid(), found.mode() & 0o7777)
}

fn set_mode(path: &Path, mode: u32) {
    fs::set_permissions(path, Permissions::from_mode(mode)).expect("set a mode");
}

fn folder(path: &Path, mode: u32) {
    fs::create_dir(path).expect("make a folder");
    set_mode(path, mode);
}

/// The data folder prepared afresh, the policy in place, and checked.
fn installed(data: &Path) {
    prepare_data_folder(data, true).expect("prepare");
    write_policy(data, SOME_POLICY).expect("policy");
    verify_data_folder(data, true).expect("verify");
}

fn ok() -> Said {
    Said {
        code: Some(0),
        out: String::new(),
        err: String::new(),
    }
}

fn code(code: i32) -> Said {
    Said {
        code: Some(code),
        ..ok()
    }
}

/// `launchctl print`'s answer for a job in `state`, as the real one looks:
/// the job's own lines one tab in, and others further in.
fn printed(state: &str, last_exit: &str) -> Said {
    Said {
        out: format!(
            "system/{LABEL} = {{\n\tactive count = 1\n\tstate = {state}\n\tlast exit code = \
             {last_exit}\n\tendpoints = {{\n\t\tstate = active\n\t}}\n}}\n"
        ),
        ..ok()
    }
}

/// What a [`Recorder`] answers each call with.
type Answer<'a> = Box<dyn Fn(&[&str]) -> Said + 'a>;

/// Stands in for launchctl: records each call, with whether the job's file
/// was still there when the service was unloaded, and answers with `answer`.
struct Recorder<'a> {
    calls: RefCell<Vec<String>>,
    plist: Option<PathBuf>,
    answer: Answer<'a>,
}

impl<'a> Recorder<'a> {
    fn new(answer: impl Fn(&[&str]) -> Said + 'a) -> Self {
        Self {
            calls: RefCell::new(Vec::new()),
            plist: None,
            answer: Box::new(answer),
        }
    }

    fn watching(daemons: &Path, answer: impl Fn(&[&str]) -> Said + 'a) -> Self {
        Self {
            plist: Some(daemons.join(PLIST_NAME)),
            ..Self::new(answer)
        }
    }

    fn calls(&self) -> Vec<String> {
        self.calls.borrow().clone()
    }
}

impl Launchd for Recorder<'_> {
    fn run(&self, args: &[&str]) -> Result<Said> {
        let mut call = args.join(" ");
        if let Some(plist) = &self.plist
            && args.first() == Some(&"bootout")
        {
            let there = fs::symlink_metadata(plist).is_ok();
            call.push_str(if there {
                " (file there)"
            } else {
                " (file gone)"
            });
        }
        self.calls.borrow_mut().push(call);
        Ok((self.answer)(args))
    }
}

/// A folder for a test that needs no root.
fn plain_scratch() -> PathBuf {
    let count = NEXT.fetch_add(1, Ordering::SeqCst);
    let name = format!("uvt-install-plain-{}-{count}", std::process::id());
    let dir = std::env::temp_dir().join(name);
    fs::create_dir(&dir).expect("make the scratch folder");
    dir
}

/// A launchd that loads the job at once and reports it as gone once asked to
/// unload it: `running` until `bootout`, then not loaded.
fn loaded_until_bootout() -> impl Fn(&[&str]) -> Said {
    let unloaded = Cell::new(false);
    move |args: &[&str]| match args {
        ["print", _] if unloaded.get() => code(NOT_LOADED),
        ["print", _] => printed("running", "(never exited)"),
        ["bootout", _] => {
            unloaded.set(true);
            ok()
        }
        _ => ok(),
    }
}

fn registration(command_line: &str) -> Registration<'static> {
    Registration {
        name: "ubc-vpn",
        display_name: "UBC VPN Service",
        description: "made up",
        command_line: command_line.to_string(),
    }
}

// The job as shipped: what launchd starts, how it stops it, and what reaches
// it. The real launchd reads it in packaging/macos/tests/launchd.sh.
#[test]
fn the_job_starts_the_installed_service_and_gives_it_time_to_stop() {
    assert!(PLIST.contains(&format!("<string>{LABEL}</string>")));
    assert!(PLIST.contains(&format!("<string>{INSTALLED_SERVICE}</string>")));
    assert_eq!(JOB, format!("system/{LABEL}"));
    assert_eq!(PLIST_NAME, format!("{LABEL}.plist"));
    assert!(INSTALLED_SERVICE.starts_with("/Library/PrivilegedHelperTools/"));
    assert!(PLIST.contains("<key>ExitTimeOut</key>\n  <integer>30</integer>"));
    // launchd kills it after ExitTimeOut, and the wait outlasts that.
    assert!(STOP_WAIT > Duration::from_secs(30));
    assert_eq!(
        PLIST.matches(&format!("<string>{LOG}</string>")).count(),
        2,
        "its output goes to the log in the data folder"
    );
    assert_eq!(Path::new(LOG).parent().map(Path::as_os_str), {
        Some(std::ffi::OsStr::new(crate::os::SYSTEM))
    });
    // Security rule: nothing from outside the program reaches it, and it
    // runs as root from the folder `install` checked.
    for refused in [
        "EnvironmentVariables",
        "UserName",
        "GroupName",
        "WorkingDirectory",
        "RootDirectory",
        "Program</key>",
        "inetdCompatibility",
    ] {
        assert!(!PLIST.contains(refused), "{refused}");
    }
    // Every setting has its reason on the line above: a comment's end.
    let lines: Vec<&str> = PLIST.lines().collect();
    for (n, line) in lines.iter().enumerate() {
        // Only the job's own settings, not the ones nested in KeepAlive.
        if line.starts_with("  <key>") {
            assert!(lines[n - 1].ends_with("-->"), "{line} has no reason");
        }
    }
}

// Only the path itself is ever given to launchd.
#[test]
fn quoted_takes_only_a_plain_path() {
    assert_eq!(
        quoted(Path::new(INSTALLED_SERVICE)).unwrap(),
        INSTALLED_SERVICE
    );
    for bad in ["relative/ubc-vpn-service", "/a\nb", "/a\tb"] {
        assert_eq!(quoted(Path::new(bad)), Err(Error::InvalidInput), "{bad:?}");
    }
    let not_utf8 = Path::new(OsStr::from_bytes(b"/a\xffb"));
    assert_eq!(quoted(not_utf8), Err(Error::InvalidInput));
}

// Security rule: launchctl is named by its absolute path and runs from `/`.
#[test]
fn launchctl_is_run_by_its_path() {
    let command = command(&["print", JOB]);
    assert_eq!(command.get_program(), LAUNCHCTL);
    assert!(Path::new(LAUNCHCTL).is_absolute());
    let args: Vec<&OsStr> = command.get_args().collect();
    assert_eq!(args, ["print", JOB]);
    assert_eq!(command.get_current_dir(), Some(Path::new("/")));
    assert_eq!(command.get_envs().count(), 0, "nothing is set for it");

    // What the program really gets: `get_envs` above does not show whether
    // the caller's environment is passed on.
    assert!(std::env::vars_os().next().is_some(), "this test has one");
    let seen = command_for("/usr/bin/env", &[]).output().expect("run env");
    assert!(seen.status.success());
    let seen = String::from_utf8_lossy(&seen.stdout);
    assert_eq!(seen, "", "the caller's environment reached it");
}

// launchd's words for a job, and an answer it cannot read is not "not loaded".
#[test]
fn what_launchd_says_of_the_job() {
    let says = |said: fn() -> Said| job(&Recorder::new(move |_| said()));
    assert_eq!(says(|| code(NOT_LOADED)), Ok(Job::NotLoaded));
    assert_eq!(
        says(|| printed("running", "(never exited)")),
        Ok(Job::Running)
    );
    // A job that ran before and now runs again.
    assert_eq!(says(|| printed("running", "1")), Ok(Job::Running));
    assert_eq!(says(|| printed("spawn scheduled", "1")), Ok(Job::Failed));
    assert_eq!(says(|| printed("not running", "78")), Ok(Job::Failed));
    assert_eq!(says(|| printed("not running", "0")), Ok(Job::Waiting));
    assert_eq!(
        says(|| printed("spawn scheduled", "(never exited)")),
        Ok(Job::Waiting)
    );
    // `state` further in is about something else.
    let nested = || Said {
        out: "x = {\n\t\tstate = running\n}\n".to_string(),
        ..ok()
    };
    assert_eq!(says(nested), Ok(Job::Waiting));
    let broken = || Said {
        code: Some(64),
        err: "Usage: launchctl\n".to_string(),
        ..ok()
    };
    assert!(matches!(says(broken), Err(Error::Failed(why)) if why.contains("Usage")));
}

#[test]
fn a_disabled_job_is_told_from_any_other() {
    let list = |value: &str| {
        format!(
            "disabled services = {{\n\t\"com.example.other\" => disabled\n\t\"{LABEL}\" => \
             {value}\n}}\nlogin item associations = {{\n}}\n"
        )
    };
    assert!(is_disabled(&list("disabled")));
    assert!(is_disabled(&list("true")));
    assert!(!is_disabled(&list("enabled")));
    assert!(!is_disabled(&list("false")));
    assert!(!is_disabled(
        "disabled services = {\n\t\"com.example.other\" => disabled\n}\n"
    ));
    let longer = format!("\t\"{LABEL}.other\" => disabled\n");
    assert!(!is_disabled(&longer), "another job with a longer name");
}

// Security rule: only the shipped job, for the program at the installed
// place, is ever registered. Anything else changes nothing.
#[test]
fn another_name_or_program_is_refused_before_anything_changes() {
    let daemons = plain_scratch();
    let recorder = Recorder::new(|_| ok());
    let mut other = registration(INSTALLED_SERVICE);
    other.name = "other";
    let wait = Duration::ZERO;
    assert_eq!(
        register_with(&recorder, &daemons, &other, wait),
        Err(Error::InvalidInput)
    );
    for command_line in ["/usr/local/bin/ubc-vpn-service", "", "ubc-vpn-service"] {
        let refused = register_with(&recorder, &daemons, &registration(command_line), wait);
        assert!(
            matches!(&refused, Err(Error::Failed(why)) if why.contains(INSTALLED_SERVICE)),
            "{command_line:?}: {refused:?}"
        );
    }
    assert_eq!(recorder.calls(), [""; 0]);
    assert_eq!(names_in(&daemons).unwrap(), [""; 0]);
    assert_eq!(start("other"), Err(Error::InvalidInput));
    assert_eq!(unregister("other"), Err(Error::InvalidInput));
    fs::remove_dir_all(&daemons).unwrap();
}

// The service counts as started only once something answers on its socket: a
// socket file left behind is not enough.
#[test]
fn start_waits_until_the_service_listens() {
    let scratch = plain_scratch();
    let channel = scratch.join("s");
    let asked = Cell::new(0);
    let listener = RefCell::new(None);
    // A socket file nothing listens on, as a service that was killed leaves.
    drop(UnixListener::bind(&channel).expect("bind"));
    assert!(fs::symlink_metadata(&channel).is_ok());
    let recorder = Recorder::new(|args| match args {
        ["print", _] => {
            asked.set(asked.get() + 1);
            if asked.get() == 3 {
                fs::remove_file(&channel).expect("the old socket");
                *listener.borrow_mut() = Some(UnixListener::bind(&channel).expect("bind"));
            }
            printed("running", "(never exited)")
        }
        _ => ok(),
    });
    start_with(&recorder, &scratch, &channel, Duration::from_secs(30)).expect("start");
    let calls = recorder.calls();
    let plist = scratch.join(PLIST_NAME);
    let bootstrap = format!("bootstrap system {}", plist.display());
    assert_eq!(calls[..2], ["print-disabled system".to_string(), bootstrap]);
    assert_eq!(calls.len(), 2 + 3, "{calls:?}");
    fs::remove_dir_all(&scratch).unwrap();
}

// One that fails as it starts is an error, said at once and not after the
// wait, and so is one launchd refuses or never starts.
#[test]
fn a_start_that_fails_says_so() {
    let scratch = plain_scratch();
    let none = scratch.join("none.sock");
    let long = Duration::from_secs(60);
    let at = Instant::now();

    let failing = Recorder::new(|args| match args {
        ["print", _] => printed("spawn scheduled", "1"),
        _ => ok(),
    });
    let refused = start_with(&failing, &scratch, &none, long);
    assert!(
        matches!(&refused, Err(Error::Failed(why)) if why.contains(LOG)),
        "{refused:?}"
    );

    let gone = Recorder::new(|args| match args {
        ["print", _] => code(NOT_LOADED),
        _ => ok(),
    });
    assert!(matches!(
        start_with(&gone, &scratch, &none, long),
        Err(Error::Failed(_))
    ));
    assert!(at.elapsed() < Duration::from_secs(5), "it waited");

    let no_load = Recorder::new(|args| match args {
        ["bootstrap", ..] => Said {
            code: Some(5),
            err: "Bootstrap failed: 5: Input/output error\n".to_string(),
            ..ok()
        },
        _ => ok(),
    });
    let refused = start_with(&no_load, &scratch, &none, long);
    assert!(
        matches!(&refused, Err(Error::Failed(why)) if why.contains("Input/output")),
        "{refused:?}"
    );
    assert_eq!(no_load.calls().len(), 2, "nothing after the failure");

    // Never listens: gives up at the limit.
    let silent = Recorder::new(|args| match args {
        ["print", _] => printed("running", "(never exited)"),
        _ => ok(),
    });
    let wait = Duration::from_millis(300);
    assert_eq!(
        start_with(&silent, &scratch, &none, wait),
        Err(Error::TimedOut)
    );
    fs::remove_dir_all(&scratch).unwrap();
}

// A job someone disabled is enabled, since installing means wanting it to
// run; any other is left out of launchd's list, where this leaves a record.
#[test]
fn only_a_disabled_job_is_enabled() {
    let scratch = plain_scratch();
    let channel = scratch.join("s");
    let _listener = UnixListener::bind(&channel).expect("bind");
    let disabled = Recorder::new(|args| match args {
        ["print-disabled", _] => Said {
            out: format!("\t\"{LABEL}\" => disabled\n"),
            ..ok()
        },
        ["print", _] => printed("running", "(never exited)"),
        _ => ok(),
    });
    start_with(&disabled, &scratch, &channel, Duration::ZERO).expect("start");
    let calls = disabled.calls();
    assert_eq!(calls[1], format!("enable {JOB}"), "{calls:?}");
    assert!(calls[2].starts_with("bootstrap "), "{calls:?}");

    let enabled = Recorder::new(|args| match args {
        ["print", _] => printed("running", "(never exited)"),
        _ => ok(),
    });
    start_with(&enabled, &scratch, &channel, Duration::ZERO).expect("start");
    assert!(
        !enabled
            .calls()
            .iter()
            .any(|call| call.starts_with("enable")),
        "{:?}",
        enabled.calls()
    );
    fs::remove_dir_all(&scratch).unwrap();
}

// Security rule: the service has ended, and so has removed its routes and
// DNS, before its job's file goes. launchd knows the job until then, so a
// bootout that returns early is waited for, and one that never ends removes
// nothing.
#[test]
fn uninstall_stops_the_service_before_it_removes_the_job() {
    let daemons = plain_scratch();
    let plist = daemons.join(PLIST_NAME);
    fs::write(&plist, PLIST).expect("a job");
    let wait = Duration::from_secs(30);

    // Still ending for three more questions after it was asked to.
    let asked = Cell::new(0);
    let ending = Recorder::watching(&daemons, |args| match args {
        ["print", _] => {
            asked.set(asked.get() + 1);
            match asked.get() {
                5.. => code(NOT_LOADED),
                _ => printed("running", "(never exited)"),
            }
        }
        ["bootout", _] => code(STILL_ENDING),
        _ => ok(),
    });
    unregister_with(&ending, &daemons, wait).expect("unregister");
    let calls = ending.calls();
    assert_eq!(calls[1], format!("bootout {JOB} (file there)"), "{calls:?}");
    assert_eq!(calls.len(), 6, "asked until it was gone: {calls:?}");
    assert!(fs::symlink_metadata(&plist).is_err(), "the file is gone");

    // One launchd does not know: nothing to unload, and no file is fine.
    let not_loaded = Recorder::new(|_| code(NOT_LOADED));
    unregister_with(&not_loaded, &daemons, wait).expect("unregister again");
    assert_eq!(not_loaded.calls(), [format!("print {JOB}")]);

    // A file left with no job loaded is removed, and a link is removed itself.
    let elsewhere = daemons.join("elsewhere");
    fs::write(&elsewhere, "kept").unwrap();
    symlink(&elsewhere, &plist).unwrap();
    unregister_with(&not_loaded, &daemons, wait).expect("a link");
    assert!(fs::symlink_metadata(&plist).is_err());
    assert_eq!(fs::read_to_string(&elsewhere).unwrap(), "kept");

    // A stop that fails, or never ends, removes nothing.
    fs::write(&plist, PLIST).expect("a job again");
    let stuck = Recorder::watching(&daemons, |args| match args {
        ["bootout", _] => Said {
            code: Some(5),
            err: "Boot-out failed: 5: Input/output error\n".to_string(),
            ..ok()
        },
        _ => printed("running", "(never exited)"),
    });
    let refused = unregister_with(&stuck, &daemons, wait);
    assert!(
        matches!(&refused, Err(Error::Failed(why)) if why.contains("Boot-out failed")),
        "{refused:?}"
    );
    assert!(plist.exists(), "a service that did not stop keeps its job");

    let never = Recorder::new(|args| match args {
        ["print", _] => printed("running", "(never exited)"),
        _ => code(STILL_ENDING),
    });
    assert_eq!(
        unregister_with(&never, &daemons, Duration::from_millis(300)),
        Err(Error::TimedOut)
    );
    assert!(plist.exists(), "a service that never ended keeps its job");

    // An answer launchctl gives that cannot be read stops it too.
    let broken = Recorder::new(|_| code(64));
    assert!(unregister_with(&broken, &daemons, wait).is_err());
    assert!(plist.exists(), "nothing is removed on a guess");
    fs::remove_dir_all(&daemons).unwrap();
}

// Security rule: launchd reads the job as root, so it is root's, 0644,
// whatever the umask, holds the shipped job exactly, and is written after the
// service has stopped. A link left in its way is not followed.
#[test]
fn install_job_as_root() {
    as_root("job", "install_job_as_root", |scratch| {
        let daemons = scratch.0.join("daemons");
        folder(&daemons, 0o755);
        let plist = daemons.join(PLIST_NAME);
        let target = scratch.0.join("target");
        fs::write(&target, "untouched").unwrap();
        symlink(&target, daemons.join(format!(".{PLIST_NAME}.new"))).unwrap();
        for mask in [0o777, 0] {
            umask(mask);
            let recorder = Recorder::watching(&daemons, loaded_until_bootout());
            register_with(
                &recorder,
                &daemons,
                &registration(INSTALLED_SERVICE),
                Duration::from_secs(5),
            )
            .expect("register");
            umask(0);
            assert_eq!(owner_group_and_mode(&plist), (0, 0, PLIST_MODE));
            assert_eq!(fs::read_to_string(&plist).unwrap(), PLIST);
            assert_eq!(names_in(&daemons).unwrap(), [PLIST_NAME]);
            let unloaded = if mask == 0o777 {
                "(file gone)"
            } else {
                "(file there)"
            };
            let calls = recorder.calls();
            assert_eq!(calls[1], format!("bootout {JOB} {unloaded}"), "{calls:?}");
        }
        assert_eq!(fs::read_to_string(&target).unwrap(), "untouched");
    });
}

// Security rule: the policy every user's client trusts is root's, 0644, in a
// folder root's with 0755, whatever the umask and whatever group the folder
// above hands on, and a link left where it is written is not followed.
#[test]
fn install_policy_as_root() {
    as_root("policy", "install_policy_as_root", |scratch| {
        let data = scratch.data();
        // macOS hands on the group of the folder above, as an admin's folder
        // would.
        lchown(&scratch.0, None, Some(80)).expect("the group above");
        umask(0o777);
        prepare_data_folder(&data, false).expect("prepare");
        assert_eq!(owner_group_and_mode(&data), (0, 0, FOLDER_MODE));
        umask(0);

        let target = scratch.0.join("target");
        fs::write(&target, "untouched").unwrap();
        symlink(&target, data.join(".policy.json.new")).unwrap();
        for mask in [0o777, 0] {
            umask(mask);
            write_policy(&data, SOME_POLICY).expect("write");
            umask(0);
            let policy = data.join(POLICY);
            assert_eq!(owner_group_and_mode(&policy), (0, 0, POLICY_MODE));
            assert_eq!(fs::read(&policy).unwrap(), SOME_POLICY);
            assert_eq!(names_in(&data).unwrap(), [POLICY]);
        }
        assert_eq!(fs::read_to_string(&target).unwrap(), "untouched");
        verify_data_folder(&data, true).expect("verify");
    });
}

// Security rule: a fresh install empties the folder, whoever made it and
// whatever it holds, so a planted state.json never names the owner. A link in
// the folder's place is removed, never followed.
#[test]
fn install_fresh_as_root() {
    as_root("fresh", "install_fresh_as_root", |scratch| {
        let data = scratch.data();
        folder(&data, 0o777);
        fs::write(data.join("state.json"), br#"{"owner":"54321"}"#).unwrap();
        lchown(&data, Some(STRANGER), Some(STRANGER)).unwrap();

        umask(0o777);
        prepare_data_folder(&data, true).expect("prepare");
        umask(0);
        write_policy(&data, SOME_POLICY).expect("policy");
        verify_data_folder(&data, true).expect("verify");
        assert_eq!(names_in(&data).unwrap(), [POLICY]);
        assert_eq!(owner_group_and_mode(&data), (0, 0, FOLDER_MODE));

        let elsewhere = scratch.0.join("elsewhere");
        folder(&elsewhere, 0o755);
        fs::write(elsewhere.join("state.json"), b"kept").unwrap();
        fs::remove_dir_all(&data).unwrap();
        symlink(&elsewhere, &data).unwrap();
        installed(&data);
        assert!(fs::symlink_metadata(&data).unwrap().is_dir());
        assert_eq!(fs::read(elsewhere.join("state.json")).unwrap(), b"kept");
    });
}

// An update keeps what is in the folder, and never fixes a folder others
// could change: the check after it fails instead.
#[test]
fn install_update_as_root() {
    as_root("update", "install_update_as_root", |scratch| {
        let data = scratch.data();
        installed(&data);
        let state = data.join("state.json");
        fs::write(&state, br#"{"owner":"501"}"#).unwrap();
        prepare_data_folder(&data, false).expect("prepare");
        write_policy(&data, SOME_POLICY).expect("policy");
        verify_data_folder(&data, false).expect("verify");
        assert_eq!(fs::read(&state).unwrap(), br#"{"owner":"501"}"#);

        set_mode(&data, 0o777);
        prepare_data_folder(&data, false).expect("prepare");
        assert_eq!(owner_group_and_mode(&data), (0, 0, 0o777), "left as found");
        assert!(verify_data_folder(&data, false).is_err());
        set_mode(&data, 0o755);

        lchown(&data, Some(STRANGER), None).unwrap();
        prepare_data_folder(&data, false).expect("prepare");
        assert_eq!(owner_group_and_mode(&data).0, STRANGER, "left as found");
        assert!(verify_data_folder(&data, false).is_err());

        fs::remove_dir_all(&data).unwrap();
        symlink(&scratch.0, &data).unwrap();
        assert!(
            prepare_data_folder(&data, false).is_err(),
            "a link is refused"
        );
        assert!(
            fs::symlink_metadata(&data)
                .unwrap()
                .file_type()
                .is_symlink(),
            "and left as found"
        );
    });
}

// Security rule: after a fresh install the folder holds the policy alone, and
// the policy and the folder are root's with their modes.
#[test]
fn install_verify_as_root() {
    as_root("verify", "install_verify_as_root", |scratch| {
        let data = scratch.data();
        installed(&data);
        let policy = data.join(POLICY);

        let planted = data.join("state.json");
        fs::write(&planted, b"{}").unwrap();
        assert!(verify_data_folder(&data, true).is_err(), "state on a fresh");
        verify_data_folder(&data, false).expect("an update keeps what is there");
        fs::remove_file(&planted).unwrap();
        verify_data_folder(&data, true).expect("as installed");

        set_mode(&policy, 0o664);
        assert!(
            verify_data_folder(&data, false).is_err(),
            "a policy others can change"
        );
        set_mode(&policy, 0o644);
        lchown(&policy, Some(STRANGER), None).unwrap();
        assert!(
            verify_data_folder(&data, false).is_err(),
            "a policy root does not own"
        );
        lchown(&policy, Some(0), None).unwrap();
        lchown(&policy, None, Some(80)).unwrap();
        assert!(
            verify_data_folder(&data, false).is_err(),
            "a policy in another group"
        );
        lchown(&policy, None, Some(0)).unwrap();
        fs::remove_file(&policy).unwrap();
        symlink(data.join("elsewhere"), &policy).unwrap();
        assert!(
            verify_data_folder(&data, false).is_err(),
            "a link for a policy"
        );
        fs::remove_file(&policy).unwrap();
        assert!(verify_data_folder(&data, false).is_err(), "no policy");
        write_policy(&data, SOME_POLICY).expect("policy again");

        set_mode(&data, 0o775);
        assert!(
            verify_data_folder(&data, false).is_err(),
            "a folder others can change"
        );
        set_mode(&data, 0o700);
        assert!(
            verify_data_folder(&data, false).is_err(),
            "a folder other users cannot reach"
        );
        set_mode(&data, 0o755);
        lchown(&data, None, Some(80)).unwrap();
        assert!(
            verify_data_folder(&data, false).is_err(),
            "a folder in another group"
        );
        lchown(&data, None, Some(0)).unwrap();
        verify_data_folder(&data, true).expect("as installed again");

        // A folder above it that others can change.
        set_mode(&scratch.0, 0o775);
        assert!(
            verify_data_folder(&data, false).is_err(),
            "a folder above it others can change"
        );
        set_mode(&scratch.0, 0o755);
    });
}

fn add_entry(path: &Path, entry: &str) {
    let status = Command::new("/bin/chmod")
        .arg("+a")
        .arg(entry)
        .arg(path)
        .status()
        .expect("run chmod");
    assert!(status.success(), "chmod +a {entry}");
}

fn clear_entries(path: &Path) {
    let status = Command::new("/bin/chmod")
        .arg("-N")
        .arg(path)
        .status()
        .expect("run chmod");
    assert!(status.success(), "chmod -N");
}

// Security rule: an access list can let a user write whatever the mode says,
// so an entry that allows anything is refused on the folder, a folder above it
// and the policy, even behind an entry that denies. Entries that only deny
// pass. A folder emptied and made again does not lose what the folder above
// hands on, so that is refused before anything is touched.
#[test]
fn install_access_list_as_root() {
    as_root("access list", "install_access_list_as_root", |scratch| {
        let data = scratch.data();
        installed(&data);
        let policy = data.join(POLICY);
        let places = [
            (data.as_path(), "the folder"),
            (scratch.0.as_path(), "the folder above"),
            (policy.as_path(), "the policy"),
        ];
        for (place, name) in places {
            add_entry(place, "everyone deny delete");
            verify_data_folder(&data, true)
                .unwrap_or_else(|why| panic!("deny entries alone on {name}: {why}"));
            add_entry(place, "everyone allow write");
            assert!(
                verify_data_folder(&data, true).is_err(),
                "an allow entry behind a deny entry on {name}"
            );
            clear_entries(place);
            add_entry(place, "everyone allow write");
            assert!(
                verify_data_folder(&data, true).is_err(),
                "an allow entry on {name}"
            );
            clear_entries(place);
            verify_data_folder(&data, true).expect("as installed again");
        }

        // A folder above that hands an allow entry on to what is made in it.
        let state = data.join("state.json");
        fs::write(&state, b"kept").unwrap();
        add_entry(
            &scratch.0,
            "everyone allow add_file,file_inherit,directory_inherit,only_inherit",
        );
        assert!(
            prepare_data_folder(&data, true).is_err(),
            "an inherited one"
        );
        assert_eq!(fs::read(&state).unwrap(), b"kept", "nothing was emptied");
        clear_entries(&scratch.0);
    });
}

// Security rule: nothing is touched while someone else could swap the folder,
// which root is about to empty, make and write into, for something else.
#[test]
fn install_folder_above_as_root() {
    as_root("folder above", "install_folder_above_as_root", |scratch| {
        let data = scratch.data();
        installed(&data);
        let state = data.join("state.json");
        fs::write(&state, b"kept").unwrap();
        let untouched = || {
            assert_eq!(fs::read(&state).unwrap(), b"kept", "it was emptied");
            assert_eq!(names_in(&data).unwrap(), [POLICY, "state.json"]);
            assert_eq!(owner_group_and_mode(&data), (0, 0, FOLDER_MODE));
        };

        for fresh in [true, false] {
            set_mode(&scratch.0, 0o775);
            assert!(prepare_data_folder(&data, fresh).is_err(), "group write");
            untouched();
            set_mode(&scratch.0, 0o755);

            lchown(&scratch.0, Some(STRANGER), None).unwrap();
            assert!(prepare_data_folder(&data, fresh).is_err(), "another owner");
            untouched();
            lchown(&scratch.0, Some(0), None).unwrap();

            add_entry(&scratch.0, "everyone allow delete_child");
            assert!(prepare_data_folder(&data, fresh).is_err(), "an access list");
            untouched();
            clear_entries(&scratch.0);
        }

        // Setting a folder's owner and mode refuses a link put in its place,
        // and leaves what it points to as it is.
        let target = scratch.0.join("target");
        folder(&target, 0o700);
        let swapped = scratch.0.join("swapped");
        symlink(&target, &swapped).unwrap();
        assert!(set_root_folder(&swapped, FOLDER_MODE).is_err(), "a link");
        assert_eq!(owner_group_and_mode(&target).2, 0o700, "followed the link");

        // Nothing is made either, and a folder above that is a link is refused.
        let missing = scratch.0.join("missing");
        let above = scratch.0.join("above");
        symlink(&missing, &above).unwrap();
        assert!(prepare_data_folder(&above.join("data"), true).is_err());
        assert!(fs::symlink_metadata(&missing).is_err());

        set_mode(&scratch.0, 0o775);
        let another = scratch.0.join("another");
        assert!(prepare_data_folder(&another, true).is_err(), "group write");
        assert!(fs::symlink_metadata(&another).is_err(), "it was made");
        set_mode(&scratch.0, 0o755);
    });
}

// A folder the service remade has the group of the folder above, and may hold
// an owner, so a fresh install keeps it. It is safe, so an install gets past
// it, with what is in it. A group that comes with anything unsafe is not fixed.
#[test]
fn install_group_as_root() {
    as_root("group", "install_group_as_root", |scratch| {
        let data = scratch.data();
        installed(&data);
        let state = data.join("state.json");
        fs::write(&state, br#"{"owner":"501"}"#).unwrap();

        lchown(&data, None, Some(80)).unwrap();
        prepare_data_folder(&data, false).expect("prepare");
        write_policy(&data, SOME_POLICY).expect("policy");
        verify_data_folder(&data, false).expect("verify");
        assert_eq!(owner_group_and_mode(&data), (0, 0, FOLDER_MODE));
        assert_eq!(fs::read(&state).unwrap(), br#"{"owner":"501"}"#);

        set_mode(&data, 0o775);
        lchown(&data, None, Some(80)).unwrap();
        prepare_data_folder(&data, false).expect("prepare");
        assert_eq!(owner_group_and_mode(&data), (0, 80, 0o775), "group write");
        assert!(verify_data_folder(&data, false).is_err());
        set_mode(&data, 0o755);

        add_entry(&data, "everyone allow add_file");
        prepare_data_folder(&data, false).expect("prepare");
        assert_eq!(owner_group_and_mode(&data).1, 80, "an access list");
        assert!(verify_data_folder(&data, false).is_err());
        clear_entries(&data);

        lchown(&data, Some(STRANGER), None).unwrap();
        prepare_data_folder(&data, false).expect("prepare");
        assert_eq!(owner_group_and_mode(&data).1, 80, "another owner");
        assert!(verify_data_folder(&data, false).is_err());
    });
}

// Removing the data removes the folder and all of it; a missing one is fine,
// and a link is removed, never followed.
#[test]
fn install_remove_as_root() {
    as_root("remove", "install_remove_as_root", |scratch| {
        let data = scratch.data();
        installed(&data);
        fs::write(data.join("state.json"), b"{}").unwrap();
        remove_data_folder(&data).expect("remove");
        assert!(fs::symlink_metadata(&data).is_err());
        remove_data_folder(&data).expect("remove again");

        let elsewhere = scratch.0.join("elsewhere");
        folder(&elsewhere, 0o755);
        fs::write(elsewhere.join("kept"), b"").unwrap();
        symlink(&elsewhere, &data).unwrap();
        remove_data_folder(&data).expect("remove a link");
        assert!(fs::symlink_metadata(&data).is_err());
        assert!(elsewhere.join("kept").exists(), "what it pointed to stays");
    });
}
