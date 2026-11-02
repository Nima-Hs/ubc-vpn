//! One change to the settings at a time: each writer waits for the lock,
//! holds it while it reads and writes, and goes ahead without it only where
//! it cannot be had.

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

use ubc_vpn_core::profiles::ProfileId;
use ubc_vpn_core::settings_cli::SettingsFailureCode;
use ubc_vpn_platform::fake::Fake;

use crate::settings::{Command, DURING_A_SAVE, remember_username, run};
use crate::settings_lock::{Tried, WAIT, change, change_with, change_within};
use crate::test_support::settings_folder;

const ROUTES: &str = r#"{"subnets":["10.19.0.0/16"],"dns_domains":["dept.example.test"]}"#;
const SHORT: Duration = Duration::from_millis(100);
const HELD: Result<bool, SettingsFailureCode> = Err(SettingsFailureCode::Unwritable);

/// A settings folder of its own for one test, removed afterwards.
struct Folder(PathBuf);

impl Folder {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let unique = (std::process::id(), NEXT.fetch_add(1, Ordering::SeqCst));
        let root = std::env::temp_dir().join(format!("ubc-vpn-lock-test-{unique:?}"));
        // Left by an earlier run whose process ID this one was given.
        let _ = std::fs::remove_dir_all(&root);
        settings_folder(&root.join("settings"));
        Self(root)
    }

    fn dir(&self) -> PathBuf {
        self.0.join("settings")
    }

    fn text(&self) -> String {
        std::fs::read_to_string(self.dir().join("settings.json")).unwrap()
    }

    fn value(&self) -> serde_json::Value {
        crate::test_support::as_v1(&self.text())
    }

    /// Runs a settings command here, on this thread.
    fn run(&self, command: Command, typed: &str) -> (u8, String) {
        let platform = || Ok(Fake::new().platform(&self.0));
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let status = run(
            command,
            &platform,
            &mut typed.as_bytes(),
            &mut out,
            &mut err,
        );
        (status, String::from_utf8(out).unwrap())
    }
}

impl Drop for Folder {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Tries for the real lock for a short while. `Ok(true)` is "went ahead
/// without it".
fn tries(dir: &Path) -> Result<bool, SettingsFailureCode> {
    change_within(dir, SHORT).map(|changing| changing.unlocked())
}

/// Runs a settings command on a thread of its own and returns where its
/// exit status and its line will arrive.
fn command(folder: &Folder, command: Command, typed: &'static str) -> Receiver<(u8, String)> {
    let (root, (done, ended)) = (folder.0.clone(), channel());
    std::thread::spawn(move || {
        let platform = || Ok(Fake::new().platform(&root));
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let status = run(
            command,
            &platform,
            &mut typed.as_bytes(),
            &mut out,
            &mut err,
        );
        let _ = done.send((status, String::from_utf8(out).unwrap()));
    });
    ended
}

/// Shows that `writer` waits while another change holds the lock, and that
/// it then works on the file as that change left it. The caller checks that
/// what the other change wrote was not lost.
fn waits_its_turn(folder: &Folder, writer: impl FnOnce() -> Receiver<(u8, String)>) {
    let dir = folder.dir();
    let held = change(&dir).expect("the lock is free");
    assert!(!held.unlocked());
    let ended = writer();
    // The other change is still under way: the writer has done nothing.
    let early = ended.recv_timeout(Duration::from_millis(300));
    assert!(early.is_err(), "it did not wait: {early:?}");
    // The other change writes its field, and only then lets go.
    let theirs = r#"{"theme":"dark","made_by":"the other change"}"#;
    std::fs::write(dir.join("settings.json"), theirs).unwrap();
    drop(held);
    let ended = ended.recv_timeout(Duration::from_secs(10));
    let (status, line) = ended.expect("its turn came");
    assert_eq!(status, 0, "{line}");
}

// The gap this closes: saving routes while another change to the settings is
// under way. The routes are saved after it, on top of what it wrote, and do
// not undo it.
#[test]
fn saving_routes_waits_for_a_change_under_way() {
    let folder = Folder::new();
    waits_its_turn(&folder, || command(&folder, Command::SetRoutes, ROUTES));
    assert_eq!(folder.value()["routes"]["subnets"][0], "10.19.0.0/16");
    assert_eq!(folder.value()["made_by"], "the other change");
}

// The same for the other two writers: a reset, and the saving of a username.
#[test]
fn a_reset_and_a_username_wait_too() {
    let folder = Folder::new();
    waits_its_turn(&folder, || {
        command(&folder, Command::Reset { force: true }, "")
    });
    let kept = std::fs::read_to_string(folder.dir().join("settings.json.damaged-1")).unwrap();
    assert!(kept.contains("the other change"), "{kept}");

    let folder = Folder::new();
    waits_its_turn(&folder, || {
        let (dir, (done, ended)) = (folder.dir(), channel());
        std::thread::spawn(move || {
            let saved = remember_username(&dir, None, &ProfileId::first(), Some("jdoe"));
            let _ = done.send((u8::from(saved.is_err()), format!("{saved:?}")));
        });
        ended
    });
    assert_eq!(folder.value()["username"], "jdoe");
    assert_eq!(folder.value()["made_by"], "the other change");
}

// Waiting for the lock is half of it. Each writer must also still hold the
// lock when it writes: one that took it and let go at once would wait its
// turn and then read and write unguarded.
#[test]
fn every_writer_holds_the_lock_while_it_writes() {
    let folder = Folder::new();
    let found = Rc::new(RefCell::new(Vec::new()));
    let looked = found.clone();
    // In the middle of each save, somebody else tries for the lock.
    let look = move |dir: &Path| looked.borrow_mut().push(tries(dir));
    DURING_A_SAVE.with(|during| *during.borrow_mut() = Some(Box::new(look)));

    assert_eq!(folder.run(Command::SetRoutes, ROUTES).0, 0);
    assert_eq!(
        remember_username(&folder.dir(), None, &ProfileId::first(), Some("jdoe")),
        Ok(())
    );
    assert_eq!(folder.run(Command::Reset { force: true }, "").0, 0);

    DURING_A_SAVE.with(|during| *during.borrow_mut() = None);
    assert_eq!(*found.borrow(), [HELD, HELD, HELD]);
    // And each let go when it was done.
    assert_eq!(tries(&folder.dir()), Ok(false));
}

// A change that holds the lock too long does not hang the next one for
// ever: it gives up and says the settings could not be written. Once the
// lock is free it can be had again.
#[test]
fn a_lock_held_too_long_is_given_up_on() {
    let folder = Folder::new();
    let dir = folder.dir();
    let held = change(&dir).expect("the lock is free");
    let (wait, started) = (Duration::from_millis(300), Instant::now());
    // On a thread of its own, so that a wait with no end fails this test
    // and does not hang it.
    let (waiting, (done, ended)) = (dir.clone(), channel());
    std::thread::spawn(move || done.send(change_within(&waiting, wait).map(|c| c.unlocked())));
    let refused = ended.recv_timeout(Duration::from_secs(4));
    let refused = refused.expect("it gave up");
    let waited = started.elapsed();
    assert_eq!(refused, HELD);
    assert!(waited >= wait, "{waited:?}");
    drop(held);
    assert_eq!(tries(&dir), Ok(false));
    // The real wait is long enough for a save and short enough to bear.
    assert_eq!(WAIT, Duration::from_secs(5));
}

/// What a lock that is held lets go of. The test hears when it is dropped.
struct Lock(Sender<&'static str>);

impl Drop for Lock {
    fn drop(&mut self) {
        let _ = self.0.send("let go");
    }
}

// Only a lock that another change holds refuses the change. Where the lock
// cannot be had at all, as on a file system without locks, the change goes
// ahead without it: losing every save would be far worse than the rare
// lost field the lock is there for.
#[test]
fn a_lock_that_cannot_be_had_does_not_stop_the_change() {
    let folder = Folder::new();
    let dir = folder.dir();
    let with = |attempt: fn() -> std::io::Result<Tried>| {
        change_with(&dir, SHORT, attempt).map(|changing| changing.unlocked())
    };
    assert_eq!(with(|| Ok(Tried::Held(Box::new(())))), Ok(false));
    assert_eq!(with(|| Ok(Tried::Busy)), HELD);
    // There is nothing to wait for then, so it does not wait: with a wait
    // far longer than a loaded machine could take over one try, the answer
    // still comes long before it is up.
    let no_locks = || Err(std::io::ErrorKind::Unsupported.into());
    let long = Duration::from_secs(60);
    let started = Instant::now();
    let unlocked = change_with(&dir, long, no_locks).map(|changing| changing.unlocked());
    assert_eq!(unlocked, Ok(true));
    assert!(
        started.elapsed() < long / 4,
        "there was nothing to wait for"
    );

    // A try that is busy at first and then succeeds is tried again.
    let tries = AtomicUsize::new(0);
    let third_time = move || match tries.fetch_add(1, Ordering::SeqCst) {
        0 | 1 => Ok(Tried::Busy),
        _ => Ok(Tried::Held(Box::new(()))),
    };
    let had = change_with(&dir, Duration::from_secs(2), third_time);
    assert_eq!(had.map(|changing| changing.unlocked()), Ok(false));
}

// On some file systems the lock call does not come back. The change waits
// for it no longer than for a held lock, and then goes ahead without it. If
// the call does come back later, with the lock, nobody is waiting for it and
// it is let go at once: it is not left held with nobody to release it.
#[test]
fn a_lock_call_that_never_returns_is_not_waited_for() {
    let folder = Folder::new();
    let (come_back, waiting) = channel::<()>();
    let (dropped, let_go) = channel();
    let hangs = move || {
        let _ = waiting.recv();
        Ok(Tried::Held(Box::new(Lock(dropped.clone()))))
    };
    let started = Instant::now();
    // Asked for on a thread of its own, so that a change which waited for
    // ever fails this test and does not hang it.
    let (dir, (done, ended)) = (folder.dir(), channel());
    std::thread::spawn(move || {
        let changing = change_with(&dir, SHORT, hangs);
        done.send(changing.map(|changing| changing.unlocked()))
    });
    let went_ahead = ended.recv_timeout(Duration::from_secs(4));
    assert_eq!(went_ahead, Ok(Ok(true)), "it did not go ahead in time");
    assert!(started.elapsed() >= SHORT);

    come_back.send(()).unwrap();
    let late = let_go.recv_timeout(Duration::from_secs(4));
    assert_eq!(late, Ok("let go"), "the late lock was not kept");
}

// The lock is taken on a plain file and nothing else, and the file is left
// where it is: it is never written, and nothing removes it, however old.
#[test]
fn the_lock_is_a_plain_file_that_stays() {
    let folder = Folder::new();
    let lock = folder.dir().join("settings.json.lock");
    assert_eq!(tries(&folder.dir()), Ok(false));
    assert_eq!(std::fs::read(&lock).unwrap(), b"");
    // Taking the lock never writes the file, whatever is in it.
    std::fs::write(&lock, "left as found").unwrap();
    assert_eq!(tries(&folder.dir()), Ok(false));
    assert_eq!(std::fs::read(&lock).unwrap(), b"left as found");
    // A save sweeps old partial files, and leaves this, old as it is.
    let long_ago = std::time::SystemTime::now() - Duration::from_secs(48 * 3600);
    let file = std::fs::File::options().write(true).open(&lock).unwrap();
    file.set_modified(long_ago).unwrap();
    drop(file);
    assert_eq!(folder.run(Command::SetRoutes, ROUTES).0, 0);
    assert_eq!(std::fs::read(&lock).unwrap(), b"left as found");

    // A folder in its place cannot be locked. The save goes ahead without.
    std::fs::remove_file(&lock).unwrap();
    std::fs::create_dir(&lock).unwrap();
    assert_eq!(tries(&folder.dir()), Ok(true));
    std::fs::remove_file(folder.dir().join("settings.json")).unwrap();
    assert_eq!(folder.run(Command::SetRoutes, ROUTES).0, 0);
    assert_eq!(folder.value()["routes"]["subnets"][0], "10.19.0.0/16");
    assert!(lock.is_dir());
}

// Security rule: a link where the lock should be is not followed. Whatever
// it leads to is neither opened nor locked, and the change goes ahead
// without a lock.
#[test]
fn a_link_in_place_of_the_lock_is_not_followed() {
    fn link(target: &Path, link: &Path) -> std::io::Result<()> {
        #[cfg(unix)]
        return std::os::unix::fs::symlink(target, link);
        #[cfg(windows)]
        return std::os::windows::fs::symlink_file(target, link);
    }
    let folder = Folder::new();
    let target = folder.0.join("someone-elses-file");
    std::fs::write(&target, "precious").unwrap();
    if let Err(error) = link(&target, &folder.dir().join("settings.json.lock")) {
        let skipped = format!("SKIPPED a_link_in_place_of_the_lock_is_not_followed: {error}\n");
        std::io::Write::write_all(&mut std::io::stderr(), skipped.as_bytes()).unwrap();
        return;
    }
    let held = change_within(&folder.dir(), SHORT).expect("it goes ahead");
    assert!(held.unlocked());
    // Had the link been followed and its target locked, this would fail.
    let free = std::fs::File::options().write(true).open(&target).unwrap();
    assert!(free.try_lock().is_ok());
    drop(free);
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "precious");
}
