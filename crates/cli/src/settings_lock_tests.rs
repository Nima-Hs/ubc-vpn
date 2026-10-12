//! One change to the settings at a time: each writer waits for the lock,
//! and what it then reads is what the writer before it wrote.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, channel};
use std::time::{Duration, Instant};

use ubc_vpn_core::settings_cli::SettingsFailureCode;
use ubc_vpn_platform::fake::Fake;

use crate::settings::{Command, remember_username, run};
use crate::settings_lock::{change, change_within};
use crate::tests::settings_folder;

const ROUTES: &str = r#"{"subnets":["10.19.0.0/16"],"dns_domains":["ece.example.test"]}"#;

/// A settings folder of its own for one test, removed afterwards.
struct Folder(PathBuf);

impl Folder {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let unique = (std::process::id(), NEXT.fetch_add(1, Ordering::SeqCst));
        let root = std::env::temp_dir().join(format!("ubc-vpn-lock-test-{unique:?}"));
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
        serde_json::from_str(&self.text()).unwrap()
    }
}

impl Drop for Folder {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
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
    let ended = writer();
    // The other change is still under way: the writer has done nothing.
    let early = ended.recv_timeout(Duration::from_millis(300));
    assert!(early.is_err(), "it did not wait: {early:?}");
    // The other change writes its field, and only then lets go.
    let theirs = r#"{"theme":"dark","made_by":"the other change"}"#;
    std::fs::write(dir.join("settings.json"), theirs).unwrap();
    drop(held);
    let (status, line) = ended
        .recv_timeout(Duration::from_secs(10))
        .expect("its turn came");
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
            let saved = remember_username(&dir, None, Some("jdoe"));
            let _ = done.send((u8::from(saved.is_err()), format!("{saved:?}")));
        });
        ended
    });
    assert_eq!(folder.value()["username"], "jdoe");
    assert_eq!(folder.value()["made_by"], "the other change");
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
    std::thread::spawn(move || done.send(change_within(&waiting, wait).map(drop)));
    let refused = ended.recv_timeout(Duration::from_secs(4));
    let refused = refused.expect("it gave up");
    let waited = started.elapsed();
    assert_eq!(refused, Err(SettingsFailureCode::Unwritable));
    assert!(
        waited >= wait && waited < Duration::from_secs(4),
        "{waited:?}"
    );
    drop(held);
    assert!(change_within(&dir, wait).is_ok());
}

// The lock is taken on a plain file and nothing else, and the file is left
// where it is: it holds nothing, and nothing removes it.
#[test]
fn the_lock_is_a_plain_file_that_stays() {
    let folder = Folder::new();
    let lock = folder.dir().join("settings.json.lock");
    drop(change(&folder.dir()).unwrap());
    assert_eq!(std::fs::read(&lock).unwrap(), b"");
    // Taking the lock never writes the file, whatever is in it.
    std::fs::write(&lock, "left as found").unwrap();
    drop(change(&folder.dir()).unwrap());
    assert_eq!(std::fs::read(&lock).unwrap(), b"left as found");
    std::fs::write(&lock, "").unwrap();
    // A save sweeps old partial files, and leaves this.
    let (status, _) = command(&folder, Command::SetRoutes, ROUTES).recv().unwrap();
    assert_eq!(status, 0);
    assert_eq!(std::fs::read(&lock).unwrap(), b"");

    // A folder in its place cannot be locked, and nothing is saved.
    let before = folder.text();
    std::fs::remove_file(&lock).unwrap();
    std::fs::create_dir(&lock).unwrap();
    let refused = change_within(&folder.dir(), Duration::from_millis(50)).map(drop);
    assert_eq!(refused, Err(SettingsFailureCode::Unwritable));
    let (status, line) = command(&folder, Command::SetRoutes, ROUTES).recv().unwrap();
    assert_eq!((status, line.as_str()), (1, "{\"error\":\"unwritable\"}\n"));
    assert_eq!(folder.text(), before);
}

// Security rule: a link where the lock should be is not followed. Whatever
// it leads to is neither opened nor locked.
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
    let refused = change_within(&folder.dir(), Duration::from_millis(50)).map(drop);
    assert_eq!(refused, Err(SettingsFailureCode::Unwritable));
    // Had it been followed and locked, this would have to wait.
    let free = std::fs::File::options().write(true).open(&target).unwrap();
    assert!(free.try_lock().is_ok());
}
