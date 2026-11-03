//! Tests of installing the service on Linux.
//!
//! None of them touches systemd, `/etc` or `/var/lib`: systemctl is replaced
//! by a recorder, and the folders are made for each test. The ones that need
//! root, to make files root's and to play a stranger's, run in a process of
//! their own, so that no other test's switch of user or umask reaches them,
//! and say `RAN AS ROOT: install <name>` when they passed. CI requires those
//! lines (`.github/ran/platform-unix/linux/install.txt`). The installed unit
//! itself is tried under systemd by `packaging/linux/tests/systemd.sh`.

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

/// A folder for one test, removed afterwards: in `/run`, which only root
/// can change, when root; in the temporary folder otherwise.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let base = match rustix::process::geteuid().as_raw() {
            0 => PathBuf::from(super::super::ROOT_ONLY),
            _ => std::env::temp_dir(),
        };
        let count = NEXT.fetch_add(1, Ordering::SeqCst);
        let dir = base.join(format!("uvt-install-{}-{count}", std::process::id()));
        fs::create_dir(&dir).expect("make the scratch folder");
        fs::set_permissions(&dir, Permissions::from_mode(0o755)).expect("its mode");
        Self(dir)
    }

    fn folders(&self) -> Folders {
        Folders {
            policy: self.0.join("policy"),
            state: self.0.join("state"),
        }
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

fn owner_and_mode(path: &Path) -> (u32, u32) {
    let found = fs::symlink_metadata(path).expect("it exists");
    (found.uid(), found.mode() & 0o7777)
}

fn set_mode(path: &Path, mode: u32) {
    fs::set_permissions(path, Permissions::from_mode(mode)).expect("set a mode");
}

fn folder(path: &Path, mode: u32) {
    fs::create_dir(path).expect("make a folder");
    set_mode(path, mode);
}

fn names(dir: &Path) -> Vec<String> {
    let mut found: Vec<String> = fs::read_dir(dir)
        .expect("list")
        .map(|entry| {
            entry
                .expect("an entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    found.sort();
    found
}

/// Both folders prepared afresh, the policy in place, and checked.
fn installed(folders: &Folders) {
    prepare_in(folders, true).expect("prepare");
    write_root_file(&folders.policy, POLICY, SOME_POLICY, POLICY_MODE).expect("policy");
    verify_in(folders, true).expect("verify");
}

fn ok() -> Said {
    Said {
        code: Some(0),
        out: String::new(),
        err: String::new(),
    }
}

/// What a [`Recorder`] answers each call with.
type Answer<'a> = Box<dyn Fn(&[&str]) -> Said + 'a>;

/// Stands in for systemctl: records each call, with whether the unit file
/// was still there when the service was stopped, and answers with `answer`.
struct Recorder<'a> {
    calls: RefCell<Vec<String>>,
    unit: Option<PathBuf>,
    answer: Answer<'a>,
}

impl<'a> Recorder<'a> {
    fn new(answer: impl Fn(&[&str]) -> Said + 'a) -> Self {
        Self {
            calls: RefCell::new(Vec::new()),
            unit: None,
            answer: Box::new(answer),
        }
    }

    fn watching(units: &Path, answer: impl Fn(&[&str]) -> Said + 'a) -> Self {
        Self {
            unit: Some(units.join(UNIT_NAME)),
            ..Self::new(answer)
        }
    }

    fn calls(&self) -> Vec<String> {
        self.calls.borrow().clone()
    }
}

impl Systemd for Recorder<'_> {
    fn run(&self, args: &[&str]) -> Result<Said> {
        let mut call = args.join(" ");
        if let Some(unit) = &self.unit
            && matches!(args.first(), Some(&"stop" | &"disable"))
        {
            let there = fs::symlink_metadata(unit).is_ok();
            call.push_str(if there {
                " (unit there)"
            } else {
                " (unit gone)"
            });
        }
        self.calls.borrow_mut().push(call);
        Ok((self.answer)(args))
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

fn installed_command_line() -> String {
    quoted(Path::new(INSTALLED_SERVICE)).expect("the installed path can be quoted")
}

/// The unit's settings, as `(key, value)`, each with the line before it.
fn settings() -> Vec<(&'static str, &'static str, &'static str)> {
    let lines: Vec<&str> = UNIT.lines().collect();
    let mut found = Vec::new();
    for (n, line) in lines.iter().enumerate() {
        if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
            continue;
        }
        let (key, value) = line.split_once('=').expect("a setting is key=value");
        found.push((key, value, if n == 0 { "" } else { lines[n - 1] }));
    }
    found
}

// Security rule: the folder's name has a space, so the unit quotes the
// program's path; unquoted, systemd would run `/opt/UBC` with arguments.
#[test]
fn the_unit_starts_the_installed_service_by_its_quoted_path() {
    assert!(INSTALLED_SERVICE.contains(' '), "the case this is about");
    assert_eq!(
        exec_start(UNIT),
        Some(installed_command_line().as_str()),
        "ExecStart"
    );
    assert_eq!(exec_start("ExecStart=a\nExecStart=b\n"), None, "two");
    assert_eq!(exec_start("Type=exec\n"), None, "none");
}

// Security rule: the unit gives the service what it needs and nothing else.
#[test]
fn the_unit_is_hardened_as_the_service_needs() {
    let settings = settings();
    let value = |key: &str| -> Vec<&str> {
        let found = settings.iter().filter(|(k, _, _)| *k == key);
        found.map(|(_, value, _)| *value).collect()
    };
    let expected = [
        ("Type", "exec"),
        ("RuntimeDirectory", "ubc-vpn"),
        ("RuntimeDirectoryMode", "0755"),
        ("StateDirectory", "ubc-vpn"),
        ("StateDirectoryMode", "0700"),
        ("CapabilityBoundingSet", "CAP_NET_ADMIN CAP_CHOWN"),
        ("NoNewPrivileges", "yes"),
        ("ProtectSystem", "strict"),
        ("ProtectHome", "yes"),
        ("DevicePolicy", "closed"),
        ("DeviceAllow", "/dev/net/tun rw"),
        ("ProtectProc", "invisible"),
        ("ProcSubset", "pid"),
        (
            "RestrictAddressFamilies",
            "AF_UNIX AF_NETLINK AF_INET AF_INET6",
        ),
        ("KillMode", "mixed"),
        ("TimeoutStopSec", "30s"),
        ("WantedBy", "multi-user.target"),
    ];
    for (key, wanted) in expected {
        assert_eq!(value(key), [wanted], "{key}");
    }
    // Where `enable` puts the link that `uninstall` may have to remove.
    assert_eq!(WANTED_BY, format!("{}.wants", value("WantedBy")[0]));
    // The state folder `install` makes is the one systemd expects.
    assert_eq!(
        value("StateDirectoryMode"),
        [format!("{STATE_FOLDER_MODE:04o}")]
    );
    // Nothing from outside the program reaches it, it runs as root with the
    // bounded capabilities alone, writes nowhere else, and sees the tun
    // device.
    for refused in [
        "Environment",
        "EnvironmentFile",
        "PassEnvironment",
        "User",
        "AmbientCapabilities",
        "ReadWritePaths",
        "PrivateDevices",
    ] {
        assert_eq!(value(refused), [""; 0], "{refused}");
    }
    // Each setting once, with its reason on the line above.
    let mut keys: Vec<&str> = settings.iter().map(|(key, _, _)| *key).collect();
    keys.sort_unstable();
    let count = keys.len();
    keys.dedup();
    assert_eq!(keys.len(), count, "a setting is repeated");
    for (key, _, before) in &settings {
        assert!(before.starts_with("# "), "{key} has no reason above it");
    }
}

// Security rule: a path systemd would read as something other than the
// path is refused, not quoted.
#[test]
fn quoted_takes_only_a_path_systemd_reads_as_it_is() {
    assert_eq!(
        installed_command_line(),
        "\"/opt/UBC VPN/resources/bin/ubc-vpn-service\""
    );
    for bad in [
        "relative/ubc-vpn-service",
        "/a\"b",
        "/a\\b",
        "/a%nb",
        "/a$HOME",
        "/a\nb",
        "/a\tb",
    ] {
        assert_eq!(quoted(Path::new(bad)), Err(Error::InvalidInput), "{bad:?}");
    }
    let not_utf8 = Path::new(OsStr::from_bytes(b"/a\xffb"));
    assert_eq!(quoted(not_utf8), Err(Error::InvalidInput));
}

// Security rule: systemctl is named by its absolute path and runs from `/`.
#[test]
fn systemctl_is_run_by_its_path() {
    let command = command(&["daemon-reload"]);
    assert_eq!(command.get_program(), SYSTEMCTL);
    assert!(Path::new(SYSTEMCTL).is_absolute());
    let args: Vec<&OsStr> = command.get_args().collect();
    assert_eq!(args, ["daemon-reload"]);
    assert_eq!(command.get_current_dir(), Some(Path::new("/")));
    assert_eq!(command.get_envs().count(), 0, "nothing is set for it");
}

// Security rule: only the shipped unit, for the program at the installed
// place, is ever registered. Anything else changes nothing.
#[test]
fn another_name_or_program_is_refused_before_anything_changes() {
    let scratch = Scratch::new();
    let recorder = Recorder::new(|_| ok());
    let mut other = registration(&installed_command_line());
    other.name = "other";
    assert_eq!(
        register_with(&recorder, &scratch.0, &other),
        Err(Error::InvalidInput)
    );
    let elsewhere = quoted(Path::new("/usr/local/bin/ubc-vpn-service")).unwrap();
    for command_line in [elsewhere.as_str(), INSTALLED_SERVICE, ""] {
        let refused = register_with(&recorder, &scratch.0, &registration(command_line));
        assert!(
            matches!(&refused, Err(Error::Failed(why)) if why.contains(INSTALLED_SERVICE)),
            "{command_line:?}: {refused:?}"
        );
    }
    assert_eq!(recorder.calls(), [""; 0]);
    assert_eq!(names(&scratch.0), [""; 0]);
    assert_eq!(start("other"), Err(Error::InvalidInput));
    assert_eq!(unregister("other"), Err(Error::InvalidInput));
}

// The service is started and enabled, and counts as started only once it
// listens; one that fails as it starts is an error.
#[test]
fn start_waits_until_the_service_listens() {
    let scratch = Scratch::new();
    let channel = scratch.0.join("service.sock");
    let asked = Cell::new(0);
    let listener = RefCell::new(None);
    let recorder = Recorder::new(|args| match args {
        ["is-active", _] => {
            asked.set(asked.get() + 1);
            if asked.get() == 3 {
                *listener.borrow_mut() = Some(UnixListener::bind(&channel).expect("bind"));
            }
            Said {
                out: "active\n".to_string(),
                ..ok()
            }
        }
        _ => ok(),
    });
    start_with(&recorder, &channel).expect("start");
    let calls = recorder.calls();
    assert_eq!(
        &calls[..2],
        [
            "reset-failed ubc-vpn.service",
            "enable --now ubc-vpn.service"
        ]
    );
    assert_eq!(calls.len(), 2 + 3, "{calls:?}");

    // Ended with an error, or by itself: said at once, not after the wait.
    for ended in ["failed", "inactive"] {
        let stopped = Recorder::new(|args| match args {
            ["is-active", _] => Said {
                code: Some(3),
                out: format!("{ended}\n"),
                ..ok()
            },
            _ => ok(),
        });
        let at = std::time::Instant::now();
        let refused = start_with(&stopped, &scratch.0.join("none.sock"));
        assert!(
            matches!(&refused, Err(Error::Failed(why)) if why.contains("journalctl -u ubc-vpn")),
            "{ended}: {refused:?}"
        );
        assert!(at.elapsed() < Duration::from_secs(5), "{ended}: it waited");
        assert_eq!(stopped.calls().len(), 3, "{ended}: asked once");
    }

    let no_enable = Recorder::new(|args| match args {
        ["enable", ..] => Said {
            code: Some(1),
            err: "Failed to enable unit: made up\n".to_string(),
            ..ok()
        },
        _ => ok(),
    });
    let refused = start_with(&no_enable, &channel);
    assert!(
        matches!(&refused, Err(Error::Failed(why)) if why.contains("made up")),
        "{refused:?}"
    );
    assert_eq!(no_enable.calls().len(), 2, "nothing after the failure");
}

// Security rule: the service is stopped, and has removed its routes and DNS,
// before its unit is removed; a stop that fails removes nothing.
#[test]
fn uninstall_stops_the_service_before_it_removes_the_unit() {
    let scratch = Scratch::new();
    let unit = scratch.0.join(UNIT_NAME);
    fs::write(&unit, UNIT).expect("a unit");
    let recorder = Recorder::watching(&scratch.0, |_| ok());
    unregister_with(&recorder, &scratch.0).expect("unregister");
    assert_eq!(
        recorder.calls(),
        [
            "disable --now ubc-vpn.service (unit there)",
            "daemon-reload",
            "reset-failed ubc-vpn.service",
        ]
    );
    assert!(fs::symlink_metadata(&unit).is_err(), "the unit is gone");

    // No unit file: stopped all the same, and one systemd does not know is
    // fine. The link that would start it with the system, left behind when
    // the unit was removed by hand, is removed; a file there is not ours.
    let wants = scratch.0.join(WANTED_BY);
    fs::create_dir(&wants).expect("the wants folder");
    let wanted = wants.join(UNIT_NAME);
    symlink(&unit, &wanted).expect("a dangling link");
    let not_ours = wants.join("other.service");
    fs::write(&not_ours, "").expect("another file");
    let not_loaded = Recorder::watching(&scratch.0, |args| match args {
        ["stop", _] | ["reset-failed", _] => Said {
            code: Some(NOT_LOADED),
            ..ok()
        },
        _ => ok(),
    });
    unregister_with(&not_loaded, &scratch.0).expect("unregister again");
    assert_eq!(
        not_loaded.calls(),
        [
            "stop ubc-vpn.service (unit gone)",
            "daemon-reload",
            "reset-failed ubc-vpn.service",
        ]
    );
    assert!(fs::symlink_metadata(&wanted).is_err(), "the link is gone");
    assert!(not_ours.exists(), "another unit's file is kept");
    // A file in the link's place is not removed.
    fs::write(&wanted, "").expect("a file in its place");
    unregister_with(&Recorder::new(|_| ok()), &scratch.0).expect("unregister");
    assert!(wanted.exists(), "a file that is not a link is kept");

    fs::write(&unit, UNIT).expect("a unit again");
    let stuck = Recorder::watching(&scratch.0, |args| match args {
        ["disable", ..] => Said {
            code: Some(1),
            err: "Job for ubc-vpn.service failed\n".to_string(),
            ..ok()
        },
        _ => ok(),
    });
    assert!(unregister_with(&stuck, &scratch.0).is_err());
    assert_eq!(
        stuck.calls(),
        ["disable --now ubc-vpn.service (unit there)"]
    );
    assert!(unit.exists(), "a service that did not stop keeps its unit");
}

// Security rule: the policy every user's client trusts is root's, 0644, in
// a folder root's with 0755, whoever made the folder and whatever the umask,
// and a link left where it is written is not followed.
#[test]
fn install_policy_as_root() {
    as_root("policy", "install_policy_as_root", |scratch| {
        let folders = scratch.folders();
        folder(&folders.policy, 0o777);
        lchown(&folders.policy, Some(STRANGER), Some(STRANGER)).unwrap();
        let target = scratch.0.join("target");
        fs::write(&target, "untouched").unwrap();
        symlink(&target, folders.policy.join(".policy.json.new")).unwrap();

        umask(0o777);
        prepare_in(&folders, false).expect("prepare");
        assert_eq!(owner_and_mode(&folders.policy), (0, POLICY_FOLDER_MODE));
        write_root_file(&folders.policy, POLICY, SOME_POLICY, POLICY_MODE).expect("write");
        let policy = folders.policy.join(POLICY);
        assert_eq!(owner_and_mode(&policy), (0, 0o644));
        assert_eq!(fs::read(&policy).unwrap(), SOME_POLICY);
        assert_eq!(fs::read_to_string(&target).unwrap(), "untouched");
        assert_eq!(names(&folders.policy), [POLICY]);
        assert_eq!(owner_and_mode(&folders.state), (0, STATE_FOLDER_MODE));
        verify_in(&folders, false).expect("verify");

        umask(0);
        write_root_file(&folders.policy, POLICY, b"{}", POLICY_MODE).expect("replace");
        assert_eq!(fs::read(&policy).unwrap(), b"{}");
        assert_eq!(owner_and_mode(&policy), (0, 0o644));
    });
}

// Security rule: a fresh install empties both folders, whoever made them
// and whatever they hold, so a planted state.json never names the owner. A
// link in a folder's place is removed, never followed.
#[test]
fn install_fresh_as_root() {
    as_root("fresh", "install_fresh_as_root", |scratch| {
        let folders = scratch.folders();
        folder(&folders.policy, 0o755);
        fs::write(folders.policy.join(POLICY), b"{}").unwrap();
        fs::write(folders.policy.join("extra"), b"").unwrap();
        folder(&folders.state, 0o777);
        fs::write(folders.state.join("state.json"), br#"{"owner":"54321"}"#).unwrap();
        lchown(&folders.state, Some(STRANGER), Some(STRANGER)).unwrap();

        umask(0o777);
        installed(&folders);
        assert_eq!(names(&folders.policy), [POLICY]);
        assert_eq!(names(&folders.state), [""; 0]);
        assert_eq!(owner_and_mode(&folders.state), (0, STATE_FOLDER_MODE));
        assert_eq!(owner_and_mode(&folders.policy), (0, POLICY_FOLDER_MODE));

        let elsewhere = scratch.0.join("elsewhere");
        folder(&elsewhere, 0o755);
        fs::write(elsewhere.join("state.json"), b"kept").unwrap();
        fs::remove_dir_all(&folders.state).unwrap();
        symlink(&elsewhere, &folders.state).unwrap();
        installed(&folders);
        assert!(fs::symlink_metadata(&folders.state).unwrap().is_dir());
        assert_eq!(fs::read(elsewhere.join("state.json")).unwrap(), b"kept");
    });
}

// An update keeps the state, and never fixes a state folder others could
// change: the check after it fails instead.
#[test]
fn install_update_as_root() {
    as_root("update", "install_update_as_root", |scratch| {
        let folders = scratch.folders();
        installed(&folders);
        let state = folders.state.join("state.json");
        fs::write(&state, br#"{"owner":"1000"}"#).unwrap();
        prepare_in(&folders, false).expect("prepare");
        write_root_file(&folders.policy, POLICY, SOME_POLICY, POLICY_MODE).expect("policy");
        verify_in(&folders, false).expect("verify");
        assert_eq!(fs::read(&state).unwrap(), br#"{"owner":"1000"}"#);

        set_mode(&folders.state, 0o777);
        prepare_in(&folders, false).expect("prepare");
        assert_eq!(owner_and_mode(&folders.state), (0, 0o777), "left as found");
        assert!(verify_in(&folders, false).is_err());

        fs::remove_dir_all(&folders.state).unwrap();
        symlink(&scratch.0, &folders.state).unwrap();
        assert!(prepare_in(&folders, false).is_err(), "a link is refused");
    });
}

// Security rule: after a fresh install the folders hold the policy alone,
// and the policy and its folder are root's with their modes.
#[test]
fn install_verify_as_root() {
    as_root("verify", "install_verify_as_root", |scratch| {
        let folders = scratch.folders();
        installed(&folders);
        let policy = folders.policy.join(POLICY);

        let extra = folders.policy.join("extra");
        fs::write(&extra, b"").unwrap();
        assert!(
            verify_in(&folders, true).is_err(),
            "something beside the policy"
        );
        verify_in(&folders, false).expect("an update keeps what is there");
        fs::remove_file(&extra).unwrap();

        let planted = folders.state.join("state.json");
        fs::write(&planted, b"{}").unwrap();
        assert!(
            verify_in(&folders, true).is_err(),
            "state on a fresh install"
        );
        fs::remove_file(&planted).unwrap();
        verify_in(&folders, true).expect("as installed");

        set_mode(&policy, 0o664);
        assert!(
            verify_in(&folders, false).is_err(),
            "a policy others can change"
        );
        set_mode(&policy, 0o644);
        lchown(&policy, Some(STRANGER), None).unwrap();
        assert!(
            verify_in(&folders, false).is_err(),
            "a policy root does not own"
        );
        lchown(&policy, Some(0), None).unwrap();
        set_mode(&folders.policy, 0o775);
        assert!(
            verify_in(&folders, false).is_err(),
            "a folder others can change"
        );
        set_mode(&folders.policy, 0o755);
        verify_in(&folders, true).expect("as installed again");
    });
}

// Security rule: the unit is root's, 0644, whatever the umask, holds the
// shipped unit exactly, and is written after the service has stopped.
#[test]
fn install_unit_as_root() {
    as_root("unit", "install_unit_as_root", |scratch| {
        let units = scratch.0.join("units");
        folder(&units, 0o755);
        let unit = units.join(UNIT_NAME);
        for mask in [0o777, 0] {
            umask(mask);
            let recorder = Recorder::watching(&units, |_| ok());
            register_with(&recorder, &units, &registration(&installed_command_line()))
                .expect("register");
            assert_eq!(owner_and_mode(&unit), (0, 0o644), "umask {mask:o}");
            assert_eq!(fs::read_to_string(&unit).unwrap(), UNIT);
            assert_eq!(names(&units), [UNIT_NAME]);
            let stopped = match mask {
                0o777 => "stop ubc-vpn.service (unit gone)",
                _ => "stop ubc-vpn.service (unit there)",
            };
            assert_eq!(recorder.calls(), [stopped, "daemon-reload"]);
        }
        // A service systemd does not know is fine to stop.
        let not_loaded = Recorder::new(|args| match args {
            ["stop", _] => Said {
                code: Some(NOT_LOADED),
                ..ok()
            },
            _ => ok(),
        });
        register_with(
            &not_loaded,
            &units,
            &registration(&installed_command_line()),
        )
        .expect("register over a unit systemd does not know");
    });
}

// Removing the data removes both folders; missing ones are fine.
#[test]
fn install_remove_as_root() {
    as_root("remove", "install_remove_as_root", |scratch| {
        let folders = scratch.folders();
        installed(&folders);
        fs::write(folders.state.join("state.json"), b"{}").unwrap();
        remove_in(&folders).expect("remove");
        assert!(fs::symlink_metadata(&folders.policy).is_err());
        assert!(fs::symlink_metadata(&folders.state).is_err());
        remove_in(&folders).expect("remove again");
    });
}
