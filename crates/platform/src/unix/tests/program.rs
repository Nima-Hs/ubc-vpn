//! Tests of the program folder's rule on macOS and Linux: the installed
//! service runs only from a folder that root alone can change, with every
//! file in it root's, inside folders only root can change, and no link on
//! the way. They build their folders in the sandbox, under a folder only
//! root can change, never under `/tmp` or the runner's home, which the rule
//! rightly refuses.

use crate::unix::program::{
    CANNOT_CHECK, FILE_OPEN, FILE_OWNER, NOT_A_FILE, NOT_FULL_PATH, check, refusal,
};
use crate::unix::program::{NOT_A_FOLDER as NOT_FOLDER, TOO_OPEN as OPEN, WRONG_OWNER as OWNED};

use super::*;

const SERVICE: &str = "ubc-vpn-service";
const LIBRARY: &str = "libopenconnect.5.dylib";

fn checked(service: &Path) -> Option<Error> {
    check(service).err()
}

/// The refusal for the rule `why`, naming `path`.
fn refused(why: &str, path: &Path) -> Option<Error> {
    Some(Error::Failed(refusal(why, path)))
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
// path. The refusal names the folder. Nothing is changed.
#[test]
fn a_folder_others_could_change_is_refused() {
    let Some(sandbox) = Sandbox::root("program folder refused", Mode::Installed) else {
        return;
    };
    for (name, mode) in [("group", 0o775), ("world", 0o757)] {
        let service = layout(&sandbox.dir, name);
        let folder = folder_of(&service);
        set_mode(folder, mode).expect("open it");
        let why = refused(OPEN, folder);
        assert_eq!(checked(&service), why, "{name}-writable");
        assert_eq!(owner_and_mode(folder), (0, mode), "changed it");
    }

    let service = layout(&sandbox.dir, "foreign");
    let folder = folder_of(&service);
    chown(folder, Some(STRANGER), None).expect("hand over");
    let why = refused(OWNED, folder);
    assert_eq!(checked(&service), why, "another user's");
    assert_eq!(owner_and_mode(folder), (STRANGER, 0o755));

    let real = layout(&sandbox.dir, "real");
    let link = sandbox.dir.join("link");
    symlink(folder_of(&real), &link).expect("link");
    let through = link.join(SERVICE);
    assert_eq!(checked(&through), refused(NOT_FOLDER, &link), "a link");

    let plain = sandbox.dir.join("plain");
    file(&plain, 0o755);
    let inside = plain.join(SERVICE);
    assert_eq!(checked(&inside), refused(NOT_FOLDER, &plain), "a file");

    let back = sandbox.dir.join("real/../real").join(SERVICE);
    let why = refused(NOT_FULL_PATH, &back);
    assert_eq!(checked(&back), why, "a path with ..");
    let relative = Path::new(SERVICE);
    let why = refused(NOT_FULL_PATH, relative);
    assert_eq!(checked(relative), why, "relative");
}

// Security rule: every folder above the service's, up to `/`, is refused
// when someone other than root owns it or may write to it, sticky or not,
// or when it is a link. The refusal names that folder.
#[test]
fn a_folder_above_others_could_change_is_refused() {
    let Some(sandbox) = Sandbox::root("program ancestors refused", Mode::Installed) else {
        return;
    };
    // World-writable, as `/tmp` is, and group-writable.
    for (name, mode) in [("world", 0o777), ("tmp", 0o1777), ("group", 0o775)] {
        let above = sandbox.folder(name, mode);
        let service = layout(&above, "app");
        assert_eq!(checked(&service), refused(OPEN, &above), "{name}");
        assert_eq!(owner_and_mode(&above), (0, mode), "changed it");
    }
    // Two folders up, so it is not only the parent that is checked.
    let high = sandbox.folder("high", 0o777);
    let middle = high.join("middle");
    fs::create_dir(&middle).expect("make a folder");
    set_mode(&middle, 0o755).expect("set its mode");
    let service = layout(&middle, "app");
    assert_eq!(checked(&service), refused(OPEN, &high), "two up");

    let foreign = sandbox.folder("foreign", 0o755);
    let service = layout(&foreign, "app");
    chown(&foreign, Some(STRANGER), None).expect("hand over");
    let why = refused(OWNED, &foreign);
    assert_eq!(checked(&service), why, "another user's");

    let real = sandbox.folder("real", 0o755);
    layout(&real, "app");
    let link = sandbox.dir.join("link");
    symlink(&real, &link).expect("link");
    let through = link.join("app").join(SERVICE);
    let why = refused(NOT_FOLDER, &link);
    assert_eq!(checked(&through), why, "a link above");
}

// Security rule: every file in the service's folder, the service and the
// libraries beside it, is a real file that root owns and root alone may
// change. A link is not followed, and a pipe does not hold the check. The
// refusal names the file.
#[test]
fn a_file_others_could_change_is_refused() {
    let Some(sandbox) = Sandbox::root("program files refused", Mode::Installed) else {
        return;
    };
    let service = layout(&sandbox.dir, "user-library");
    let library = folder_of(&service).join(LIBRARY);
    chown(&library, Some(STRANGER), None).expect("hand over");
    let why = refused(FILE_OWNER, &library);
    assert_eq!(checked(&service), why, "a user's library");
    assert_eq!(owner_and_mode(&library), (STRANGER, 0o644), "took it");

    let service = layout(&sandbox.dir, "user-service");
    chown(&service, Some(STRANGER), None).expect("hand over");
    let why = refused(FILE_OWNER, &service);
    assert_eq!(checked(&service), why, "a user's service");

    for (name, mode) in [("group", 0o664), ("world", 0o646)] {
        let service = layout(&sandbox.dir, name);
        let library = folder_of(&service).join(LIBRARY);
        set_mode(&library, mode).expect("open it");
        let why = refused(FILE_OPEN, &library);
        assert_eq!(checked(&service), why, "{name}-writable");
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
    let why = refused(NOT_A_FILE, &library);
    assert_eq!(checked(&service), why, "a linked library");

    let service = layout(&sandbox.dir, "linked-folder");
    let lib = folder_of(&service).join("lib");
    symlink(&sandbox.dir, &lib).expect("link");
    let why = refused(NOT_A_FILE, &lib);
    assert_eq!(checked(&service), why, "a linked folder inside");

    let service = layout(&sandbox.dir, "pipe");
    let path = folder_of(&service).join("p");
    let pipe = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).expect("a path");
    // SAFETY: the path is a valid C string for the length of the call.
    let made = unsafe { libc::mkfifo(pipe.as_ptr(), 0o644) };
    assert_eq!(made, 0, "make a pipe");
    let refused_now = within("the check", move || checked(&service));
    assert_eq!(refused_now, refused(NOT_A_FILE, &path), "a pipe");
}

// Security rule: on macOS an access list entry that lets anyone write is
// refused on the folder, a folder above it and a file in it, whatever the
// mode says, even behind an entry that denies. Entries that only deny pass.
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
    add(folder_of(&service), "everyone deny add_subdirectory");
    let library = folder_of(&service).join(LIBRARY);
    add(&library, "everyone deny delete");
    add(&library, "everyone deny write");
    assert_eq!(checked(&service), None, "deny entries alone");

    let service = layout(&sandbox.dir, "folder");
    let folder = folder_of(&service);
    add(folder, "everyone allow add_file");
    assert_eq!(checked(&service), refused(OPEN, folder), "the folder");

    // macOS keeps deny entries first, so the allow entry is the second.
    let service = layout(&sandbox.dir, "folder-second");
    let folder = folder_of(&service);
    add(folder, "everyone deny delete");
    add(folder, "everyone allow add_file");
    assert_eq!(checked(&service), refused(OPEN, folder), "the second entry");

    let above = sandbox.folder("above", 0o755);
    let service = layout(&above, "app");
    add(&above, "everyone allow delete_child");
    assert_eq!(checked(&service), refused(OPEN, &above), "a folder above");

    let service = layout(&sandbox.dir, "file");
    let library = folder_of(&service).join(LIBRARY);
    add(&library, "everyone allow write");
    let why = refused(FILE_OPEN, &library);
    assert_eq!(checked(&service), why, "a library");

    let service = layout(&sandbox.dir, "file-second");
    let library = folder_of(&service).join(LIBRARY);
    add(&library, "everyone deny delete");
    add(&library, "everyone allow write");
    let why = refused(FILE_OPEN, &library);
    assert_eq!(checked(&service), why, "a library's second entry");
}

// Security rule: a folder that cannot be checked is refused, naming it, as
// is one in the temporary folder, which root alone cannot be the only one
// to change. Runs as anyone.
#[test]
fn a_folder_that_cannot_be_checked_is_refused() {
    let _turn = turn();
    let missing = Path::new("/ubc-vpn-no-such-folder");
    let Some(Error::Failed(why)) = checked(&missing.join(SERVICE)) else {
        panic!("a missing folder passed or failed otherwise");
    };
    let start = refusal(CANNOT_CHECK, missing);
    assert!(why.starts_with(&format!("{start} (")), "{why}");
    let temp = std::env::temp_dir().join(SERVICE);
    assert!(checked(&temp).is_some(), "the temporary folder");
}
