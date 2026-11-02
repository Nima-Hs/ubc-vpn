//! Tests of the program folder's rule on macOS and Linux: the installed
//! service runs only from a folder that root alone can change, with every
//! file in it root's, inside folders only root can change, and no link on
//! the way. They build their folders in the sandbox, under a folder only
//! root can change, never under `/tmp` or the runner's home, which the rule
//! rightly refuses.

use crate::unix::program::{self, FILE_OPEN, FILE_OWNER, NOT_A_FILE, NOT_FULL_PATH, check};

use super::*;

const SERVICE: &str = "ubc-vpn-service";
const LIBRARY: &str = "libopenconnect.5.dylib";

fn checked(service: &Path) -> Option<Error> {
    check(service).err()
}

/// A file at `path` with mode `mode`.
fn file(path: &Path, mode: u32) {
    fs::write(path, b"x").expect("write a file");
    set_mode(path, mode).expect("set a file's mode");
}

/// A service folder `name` in `parent`, laid out as installed: the folder
/// and the service 0755, a library 0644 and a folder of resources. Returns
/// the service's path.
fn layout(parent: &Path, name: &str) -> PathBuf {
    let folder = parent.join(name);
    fs::create_dir(&folder).expect("make the service's folder");
    set_mode(&folder, 0o755).expect("set the folder's mode");
    file(&folder.join(SERVICE), 0o755);
    file(&folder.join(LIBRARY), 0o644);
    let resources = folder.join("resources");
    fs::create_dir(&resources).expect("make a folder inside");
    set_mode(&resources, 0o755).expect("set its mode");
    folder.join(SERVICE)
}

/// The folder the service `service` is in.
fn folder_of(service: &Path) -> &Path {
    service.parent().expect("a folder")
}

// Security rule: a folder only root can change, with files only root can
// change, passes, including under a sticky root-owned folder at 1755 as
// macOS's `/Library/PrivilegedHelperTools` may be.
#[test]
fn a_folder_only_root_can_change_passes() {
    let Some(sandbox) = Sandbox::root("program passes", Mode::Installed) else {
        return;
    };
    let service = layout(&sandbox.dir, "app");
    assert_eq!(checked(&service), None, "a correct layout");
    let sticky = sandbox.folder("sticky", 0o1755);
    let service = layout(&sticky, "app");
    assert_eq!(checked(&service), None, "under a sticky folder");
}

// Security rule: the service's folder is refused when someone other than
// root owns it or may write to it, or when it is a link or not a plain
// path. Nothing is changed.
#[test]
fn a_folder_others_could_change_is_refused() {
    let Some(sandbox) = Sandbox::root("program folder refused", Mode::Installed) else {
        return;
    };
    for (name, mode) in [("group", 0o775), ("world", 0o757)] {
        let service = layout(&sandbox.dir, name);
        set_mode(folder_of(&service), mode).expect("open it");
        assert_eq!(
            checked(&service),
            failed(program::TOO_OPEN),
            "{name}-writable"
        );
        assert_eq!(owner_and_mode(folder_of(&service)), (0, mode), "changed it");
    }

    let service = layout(&sandbox.dir, "foreign");
    chown(folder_of(&service), Some(STRANGER), None).expect("hand over");
    assert_eq!(
        checked(&service),
        failed(program::WRONG_OWNER),
        "another user's"
    );
    assert_eq!(owner_and_mode(folder_of(&service)), (STRANGER, 0o755));

    let real = layout(&sandbox.dir, "real");
    let link = sandbox.dir.join("link");
    symlink(folder_of(&real), &link).expect("link");
    let through = link.join(SERVICE);
    assert_eq!(checked(&through), failed(program::NOT_A_FOLDER), "a link");

    let plain = sandbox.dir.join("plain");
    file(&plain, 0o755);
    let inside = plain.join(SERVICE);
    assert_eq!(checked(&inside), failed(program::NOT_A_FOLDER), "a file");

    let back = sandbox
        .dir
        .join("real")
        .join("..")
        .join("real")
        .join(SERVICE);
    assert_eq!(checked(&back), failed(NOT_FULL_PATH), "a path with ..");
    assert_eq!(
        checked(Path::new(SERVICE)),
        failed(NOT_FULL_PATH),
        "relative"
    );
}

// Security rule: every folder above the service's, up to `/`, is refused
// when someone other than root owns it or may write to it, sticky or not,
// or when it is a link.
#[test]
fn a_folder_above_others_could_change_is_refused() {
    let Some(sandbox) = Sandbox::root("program ancestors refused", Mode::Installed) else {
        return;
    };
    // World-writable, as `/tmp` is, and group-writable.
    for (name, mode) in [("world", 0o777), ("tmp", 0o1777), ("group", 0o775)] {
        let above = sandbox.folder(name, mode);
        let service = layout(&above, "app");
        assert_eq!(checked(&service), failed(program::TOO_OPEN), "{name}");
        assert_eq!(owner_and_mode(&above), (0, mode), "changed it");
    }
    // Two folders up, so it is not only the parent that is checked.
    let high = sandbox.folder("high", 0o777);
    let middle = high.join("middle");
    fs::create_dir(&middle).expect("make a folder");
    set_mode(&middle, 0o755).expect("set its mode");
    let service = layout(&middle, "app");
    assert_eq!(checked(&service), failed(program::TOO_OPEN), "two up");

    let foreign = sandbox.folder("foreign", 0o755);
    let service = layout(&foreign, "app");
    chown(&foreign, Some(STRANGER), None).expect("hand over");
    assert_eq!(
        checked(&service),
        failed(program::WRONG_OWNER),
        "another user's"
    );

    let real = sandbox.folder("real", 0o755);
    layout(&real, "app");
    let link = sandbox.dir.join("link");
    symlink(&real, &link).expect("link");
    let through = link.join("app").join(SERVICE);
    assert_eq!(
        checked(&through),
        failed(program::NOT_A_FOLDER),
        "a link above"
    );
}

// Security rule: every file in the service's folder, the service and the
// libraries beside it, is a real file that root owns and root alone may
// change. A link is not followed, and a pipe does not hold the check.
#[test]
fn a_file_others_could_change_is_refused() {
    let Some(sandbox) = Sandbox::root("program files refused", Mode::Installed) else {
        return;
    };
    let service = layout(&sandbox.dir, "user-library");
    let library = folder_of(&service).join(LIBRARY);
    chown(&library, Some(STRANGER), None).expect("hand over");
    assert_eq!(checked(&service), failed(FILE_OWNER), "a user's library");
    assert_eq!(owner_and_mode(&library), (STRANGER, 0o644), "took it");

    let service = layout(&sandbox.dir, "user-service");
    chown(&service, Some(STRANGER), None).expect("hand over");
    assert_eq!(checked(&service), failed(FILE_OWNER), "a user's service");

    for (name, mode) in [("group", 0o664), ("world", 0o646)] {
        let service = layout(&sandbox.dir, name);
        let library = folder_of(&service).join(LIBRARY);
        set_mode(&library, mode).expect("open it");
        assert_eq!(checked(&service), failed(FILE_OPEN), "{name}-writable");
        assert_eq!(owner_and_mode(&library), (0, mode), "changed it");
    }

    // A link to a library root owns, in a folder only root can change: the
    // link is refused all the same, since it could point anywhere.
    let service = layout(&sandbox.dir, "linked");
    let library = folder_of(&service).join(LIBRARY);
    let elsewhere = sandbox.dir.join("elsewhere.dylib");
    file(&elsewhere, 0o644);
    fs::remove_file(&library).expect("remove the library");
    symlink(&elsewhere, &library).expect("link");
    assert_eq!(checked(&service), failed(NOT_A_FILE), "a linked library");

    let service = layout(&sandbox.dir, "linked-folder");
    symlink(&sandbox.dir, folder_of(&service).join("lib")).expect("link");
    assert_eq!(
        checked(&service),
        failed(NOT_A_FILE),
        "a linked folder inside"
    );

    let service = layout(&sandbox.dir, "pipe");
    let pipe = std::ffi::CString::new(folder_of(&service).join("p").as_os_str().as_encoded_bytes())
        .expect("a path");
    // SAFETY: the path is a valid C string for the length of the call.
    let made = unsafe { libc::mkfifo(pipe.as_ptr(), 0o644) };
    assert_eq!(made, 0, "make a pipe");
    let refused = within("the check", move || checked(&service));
    assert_eq!(refused, failed(NOT_A_FILE), "a pipe");
}

// Security rule: on macOS an access list entry that lets anyone write is
// refused on the folder, a folder above it and a file in it, whatever the
// mode says. An entry that only denies passes.
#[cfg(target_os = "macos")]
#[test]
fn an_access_list_that_lets_others_write_is_refused() {
    let Some(sandbox) = Sandbox::root("program access list", Mode::Installed) else {
        return;
    };
    let add = |path: &Path, entry: &str| {
        let status = std::process::Command::new("/bin/chmod")
            .arg("+a")
            .arg(entry)
            .arg(path)
            .status()
            .expect("run chmod");
        assert!(status.success(), "chmod +a {entry}");
    };

    let service = layout(&sandbox.dir, "denied");
    add(folder_of(&service), "everyone deny delete");
    assert_eq!(checked(&service), None, "a deny entry");

    let service = layout(&sandbox.dir, "folder");
    add(folder_of(&service), "everyone allow add_file");
    assert_eq!(checked(&service), failed(program::TOO_OPEN), "the folder");

    let above = sandbox.folder("above", 0o755);
    let service = layout(&above, "app");
    add(&above, "everyone allow delete_child");
    assert_eq!(
        checked(&service),
        failed(program::TOO_OPEN),
        "a folder above"
    );

    let service = layout(&sandbox.dir, "file");
    add(&folder_of(&service).join(LIBRARY), "everyone allow write");
    assert_eq!(checked(&service), failed(FILE_OPEN), "a library");
}

// Security rule: a folder that cannot be checked is refused, as is one in
// the temporary folder, which root alone cannot be the only one to change.
// Runs as anyone.
#[test]
fn a_folder_that_cannot_be_checked_is_refused() {
    let _turn = turn();
    let missing = Path::new("/ubc-vpn-no-such-folder").join(SERVICE);
    assert!(checked(&missing).is_some(), "a missing folder");
    let temp = std::env::temp_dir().join(SERVICE);
    assert!(checked(&temp).is_some(), "the temporary folder");
}
