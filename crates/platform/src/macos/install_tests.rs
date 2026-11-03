//! Tests of installing the service on macOS.
//!
//! None of them touches launchd or the real data folder: the folders are made
//! for each test. The ones that need root, to make files root's and to play a
//! stranger's, run in a process of their own, so that no other test's switch
//! of user or umask reaches them, and say `RAN AS ROOT: install <name>` when
//! they passed. CI requires those lines
//! (`.github/ran/platform-unix/macos/install.txt`).

use std::fs::{self, Permissions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt, lchown, symlink};
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

// Security rule: launchd's calls say they are not built, so `install` stops
// at `quoted`, before anything is changed.
#[test]
fn registering_is_not_built_yet() {
    let dir = Path::new("/nonexistent/ubc-vpn-test");
    let registration = Registration {
        name: "made-up",
        display_name: "Made Up",
        description: "made up",
        command_line: String::new(),
    };
    assert_eq!(quoted(dir), Err(Error::Unsupported));
    let results = [
        register(&registration),
        start("made-up"),
        unregister("made-up"),
    ];
    for (n, result) in results.into_iter().enumerate() {
        assert_eq!(result, Err(Error::Unsupported), "call {n}");
    }
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
