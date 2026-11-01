//! Tests of the state folder's rule on macOS and Linux: nobody but the
//! service's user can change the folder or the files read from it, and what
//! breaks that is refused and left as it was found, never fixed.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;

use super::*;
use crate::StateDir;
use crate::unix::state::{FILE_OPEN, FILE_OWNER, NOT_A_FILE, NOT_A_FOLDER, TOO_OPEN, WRONG_OWNER};

/// The state folder `dir`, opened as the service opens it.
fn open(mode: Mode, dir: &Path) -> Result<StateDir, Error> {
    let paths = crate::Paths {
        policy_dir: dir.join("policy"),
        state_dir: dir.to_path_buf(),
        settings_dir: dir.join("settings"),
        channel_name: socket_in(dir),
    };
    StateDir::open(mode, &paths)
}

fn refused(message: &str) -> Result<(), Error> {
    Err(Error::Failed(message.to_string()))
}

/// Root when installed, the current user in dev mode.
fn said() {
    if me() == 0 {
        say("RAN AS ROOT: state folder");
    }
}

// Security rule: a state folder the service makes is closed to others'
// writing whatever the umask, so are its temporary folder and its files, and
// what it writes it reads back.
#[test]
fn a_state_folder_is_made_for_the_service_alone() {
    let Some(sandbox) = Sandbox::any("state folder made") else {
        return;
    };
    let mode = sandbox.mode;
    let dir = sandbox.dir.join("state");
    let state = with_umask(0o777, || open(mode, &dir)).expect("make");
    let made = if mode == Mode::Installed {
        0o755
    } else {
        0o700
    };
    assert_eq!(owner_and_mode(&dir), (me(), made), "the umask won");
    open(mode, &dir).expect("open again");

    let temp = with_umask(0o777, || state.temp_dir()).expect("temp");
    assert_eq!(temp, dir.join("temp"));
    assert_eq!(owner_and_mode(&temp), (me(), 0o700), "the temporary folder");

    assert_eq!(state.read("state.json"), Ok(None), "a missing file");
    with_umask(0o022, || state.write("state.json", b"{}")).expect("write");
    let file = dir.join("state.json");
    assert_eq!(owner_and_mode(&file), (me(), 0o600), "others may read it");
    assert_eq!(state.read("state.json"), Ok(Some(b"{}".to_vec())));
    assert!(!dir.join(".state.json.new").exists());
}

// Security rule: a folder anyone else owns or may change is refused, before
// anything is read or written there, and left as it is.
#[test]
fn a_state_folder_others_could_change_is_refused() {
    let Some(sandbox) = Sandbox::any("state folder refused") else {
        return;
    };
    said();
    let mode = sandbox.mode;
    let installed = mode == Mode::Installed;
    let opened = |dir: &Path| open(mode, dir).map(drop);

    for (name, bit) in [("group", 0o020), ("world", 0o002)] {
        let wide = sandbox.folder(name, 0o700 | bit);
        assert_eq!(opened(&wide), refused(TOO_OPEN), "{name}-writable");
        assert_eq!(owner_and_mode(&wide), (me(), 0o700 | bit), "changed it");
    }
    let real = sandbox.folder("real", 0o700);
    let link = sandbox.dir.join("link");
    symlink(&real, &link).expect("link");
    assert_eq!(opened(&link), refused(NOT_A_FOLDER), "a link");
    // Another user's folder: one handed to a stranger as root, and the root
    // folder for anyone else.
    let foreign = if me() == 0 {
        let foreign = sandbox.folder("foreign", 0o700);
        chown(&foreign, Some(STRANGER), None).expect("hand over");
        foreign
    } else {
        PathBuf::from("/")
    };
    assert_eq!(opened(&foreign), refused(WRONG_OWNER), "another user's");
    if me() == 0 {
        assert_eq!(owner_and_mode(&foreign), (STRANGER, 0o700), "took it");
    }
    // Installed, the same holds for every folder on the way, and nothing is
    // made inside one that breaks it.
    if installed {
        let wide = sandbox.folder("open", 0o777);
        let inside = wide.join("state");
        assert_eq!(opened(&inside), refused(TOO_OPEN), "an open parent");
        assert!(!inside.exists(), "made a folder in it");
        set_mode(&real, 0o755).expect("open the real folder");
        let through = link.join("state");
        assert_eq!(opened(&through), refused(NOT_A_FOLDER), "a linked parent");
        assert!(!real.join("state").exists(), "made a folder through a link");
    }

    // A folder opened to others after the service opened it: nothing is
    // read or written there, and its temporary folder is refused.
    let dir = sandbox.dir.join("state");
    let state = open(mode, &dir).expect("open");
    state.write("state.json", b"{}").expect("write");
    set_mode(&dir, 0o777).expect("open it");
    assert_eq!(
        state.read("state.json"),
        Err(Error::Failed(TOO_OPEN.into()))
    );
    let written = state.write("state.json", b"changed");
    assert_eq!(written, refused(TOO_OPEN), "written");
    assert_eq!(fs::read(dir.join("state.json")).unwrap(), b"{}");
    assert_eq!(state.temp_dir(), Err(Error::Failed(TOO_OPEN.into())));
    set_mode(&dir, 0o700).expect("close it");
    // A temporary folder anyone may change is refused too.
    let temp = dir.join("temp");
    fs::create_dir(&temp).expect("make the temporary folder");
    set_mode(&temp, 0o777).expect("open the temporary folder");
    assert_eq!(state.temp_dir(), Err(Error::Failed(TOO_OPEN.into())));
    assert_eq!(owner_and_mode(&temp), (me(), 0o777), "changed it");
}

// Security rule: a state file is read only when it is a real file that
// nobody but the service's user owns or may change. A link is not followed,
// and a pipe does not hold the service.
#[test]
fn a_state_file_others_could_change_is_not_read() {
    let Some(sandbox) = Sandbox::any("state file") else {
        return;
    };
    said();
    let mode = sandbox.mode;
    let dir = sandbox.dir.join("state");
    let state = open(mode, &dir).expect("open");
    let read = |name: &str| state.read(name).map(drop);
    let file = dir.join("state.json");
    fs::write(&file, "{}").expect("write");
    set_mode(&file, 0o644).expect("mode");
    assert_eq!(read("state.json"), Ok(()), "a file of the service's own");

    for bit in [0o020, 0o002] {
        set_mode(&file, 0o644 | bit).expect("open it");
        assert_eq!(read("state.json"), refused(FILE_OPEN), "{bit:o}");
        assert_eq!(owner_and_mode(&file), (me(), 0o644 | bit), "changed it");
    }
    set_mode(&file, 0o600).expect("close it");
    // A link to a file that would itself pass.
    symlink(&file, dir.join("linked.json")).expect("link");
    assert_eq!(read("linked.json"), refused(NOT_A_FILE), "a link");
    fs::create_dir(dir.join("folder.json")).expect("a folder");
    assert_eq!(read("folder.json"), refused(NOT_A_FILE), "a folder");
    let pipe = CString::new(dir.join("pipe.json").as_os_str().as_bytes()).unwrap();
    // SAFETY: `pipe` is a valid C string for the length of the call.
    assert_eq!(unsafe { libc::mkfifo(pipe.as_ptr(), 0o600) }, 0, "a pipe");
    let at = dir.clone();
    let piped = within("reading a pipe", move || {
        open(mode, &at).expect("open").read("pipe.json").map(drop)
    });
    assert_eq!(piped, refused(NOT_A_FILE), "a pipe");
    if me() == 0 {
        chown(&file, Some(STRANGER), None).expect("hand over");
        assert_eq!(read("state.json"), refused(FILE_OWNER), "another user's");
        assert_eq!(owner_and_mode(&file), (STRANGER, 0o600), "took it");
    }
}
