//! Tests of the Unix socket channel and the paths.
//!
//! Tests that touch the file system take turns (`Sandbox`), because some
//! switch the whole process to another user for a moment. As root they use
//! the installed rules in a folder only root can change; otherwise dev mode
//! in the temporary folder. Tests that need a second user need root: they say
//! `SKIPPED, needs root` without it, and CI runs them under `sudo` with
//! `UBC_VPN_REQUIRE_ROOT` set, which turns a skip into a failure.

use std::ffi::OsString;
use std::fs;
use std::io::{ErrorKind, Write};
use std::net::Ipv4Addr;
use std::os::unix::fs::{MetadataExt, chown, symlink};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use rustix::process::geteuid;
use ubc_vpn_core::protocol::MAX_LINE_BYTES;

use super::{NOT_A_FOLDER, SocketTransport, TOO_OPEN, WRONG_OWNER, set_mode};
use crate::{
    Connection, Error, Listener, Mode, PhysicalNetwork, Platform, SplitDns, Transport, UserId,
    Verified, lock, os, suite,
};

/// Two users that are neither root nor whoever runs the tests. Root can
/// become any user ID, so they need no account.
const STRANGER: u32 = 54_321;
const OWNER: u32 = 54_322;
const PAUSE: Duration = Duration::from_millis(100);
/// Longer than anything here takes unless it is stuck.
const STUCK: Duration = Duration::from_secs(20);

static SERIAL: Mutex<()> = Mutex::new(());
static NEXT: AtomicU32 = AtomicU32::new(0);

#[cfg(feature = "dev-mode")]
const DEV: Option<Mode> = Some(Mode::Dev);
#[cfg(not(feature = "dev-mode"))]
const DEV: Option<Mode> = None;

fn me() -> u32 {
    geteuid().as_raw()
}

fn id(user: u32) -> UserId {
    user.to_string().parse().expect("a user ID")
}

fn failed(message: &str) -> Option<Error> {
    Some(Error::Failed(message.to_string()))
}

/// The turn to use the file system, and to ask or change who the process
/// runs as. Asking first would race with a test that is another user for a
/// moment.
fn turn() -> MutexGuard<'static, ()> {
    lock(&SERIAL)
}

/// Runs `act` with the process's effective user set to `user`. Only root can.
fn as_user<T>(user: u32, act: impl FnOnce() -> T) -> T {
    struct Back;
    impl Drop for Back {
        fn drop(&mut self) {
            become_user(0);
        }
    }
    become_user(user);
    let _back = Back;
    act()
}

fn become_user(user: u32) {
    // SAFETY: the call has no memory-safety conditions.
    let status = unsafe { libc::seteuid(user) };
    assert_eq!(status, 0, "could not switch to user {user}");
}

/// Runs `act` on its own thread and fails if it does not finish.
fn within<T: Send + 'static>(what: &str, act: impl FnOnce() -> T + Send + 'static) -> T {
    let (done, wait) = mpsc::channel();
    thread::spawn(move || done.send(act()));
    let outcome = wait.recv_timeout(STUCK);
    outcome.unwrap_or_else(|_| panic!("{what} did not finish"))
}

/// A private folder for one test, removed afterwards, and the turn to use the
/// file system.
struct Sandbox {
    dir: PathBuf,
    mode: Mode,
    _turn: MutexGuard<'static, ()>,
}

impl Sandbox {
    fn new(mode: Mode) -> Self {
        Self::make(turn(), mode)
    }

    fn make(turn: MutexGuard<'static, ()>, mode: Mode) -> Self {
        let base = match me() {
            0 => PathBuf::from(os::ROOT_ONLY),
            _ => std::env::temp_dir(),
        };
        let count = NEXT.fetch_add(1, Ordering::SeqCst);
        let dir = base.join(format!("uvt-{}-{count}", std::process::id()));
        fs::create_dir(&dir).expect("make the sandbox");
        set_mode(&dir, 0o755).expect("set the sandbox's mode");
        Self {
            dir,
            mode,
            _turn: turn,
        }
    }

    /// With the installed rules as root, or dev mode's otherwise. Without
    /// either there is nowhere this user may listen.
    fn any(test: &str) -> Option<Self> {
        let turn = turn();
        let mode = if me() == 0 {
            Some(Mode::Installed)
        } else {
            DEV
        };
        if mode.is_none() {
            say(&format!("SKIPPED, needs dev mode or root: {test}"));
        }
        mode.map(|mode| Self::make(turn, mode))
    }

    /// For a test that needs root. It says whether it ran, and CI checks
    /// what it said.
    fn root(test: &str, mode: Mode) -> Option<Self> {
        let turn = turn();
        if me() == 0 {
            say(&format!("RAN AS ROOT: {test}"));
            return Some(Self::make(turn, mode));
        }
        let required = std::env::var_os("UBC_VPN_REQUIRE_ROOT").is_some();
        assert!(!required, "{test} needs root");
        say(&format!("SKIPPED, needs root: {test}"));
        None
    }

    fn transport(&self) -> SocketTransport {
        SocketTransport { mode: self.mode }
    }

    fn folder(&self, name: &str, mode: u32) -> PathBuf {
        let folder = self.dir.join(name);
        fs::create_dir(&folder).expect("make a folder");
        set_mode(&folder, mode).expect("set a folder's mode");
        folder
    }

    /// A channel name in a folder `listen` will make.
    fn name(&self) -> String {
        socket_in(&self.dir.join("ch"))
    }

    fn pair(&self) -> (Box<dyn Listener>, Connection, Connection) {
        let listener = self.transport().listen(&self.name()).expect("listen");
        let client = self.transport().connect(&self.name()).expect("connect");
        let (server, _) = listener.accept().expect("accept");
        (listener, client, server)
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// Writes one whole line in one call, so that nothing another thread prints
/// can land inside it: CI looks for these lines.
fn say(line: &str) {
    let line = format!("\n{line}\n");
    std::io::stderr().write_all(line.as_bytes()).expect("say");
}

/// Runs `act` with the process's umask set to `mask`. Tests that create
/// files take turns, so no other one sees it.
fn with_umask<T>(mask: u32, act: impl FnOnce() -> T) -> T {
    // SAFETY: the call has no memory-safety conditions.
    let before = unsafe { libc::umask(mask as libc::mode_t) };
    let result = act();
    // SAFETY: as above.
    unsafe { libc::umask(before) };
    result
}

fn socket_in(folder: &Path) -> String {
    folder.join("s.sock").to_str().expect("UTF-8").to_string()
}

fn owner_and_mode(path: impl AsRef<Path>) -> (u32, u32) {
    let found = fs::symlink_metadata(path).expect("it exists");
    (found.uid(), found.mode() & 0o7777)
}

/// Connects as `user` with nothing of ours in the way, to see what the
/// kernel alone decides.
fn kernel_connect(user: u32, name: &str) -> Result<UnixStream, ErrorKind> {
    as_user(user, || UnixStream::connect(name)).map_err(|error| error.kind())
}

/// Writes lines to a peer that never reads until one fails.
fn write_until_stuck(connection: &Connection) -> Error {
    let line = "a".repeat(MAX_LINE_BYTES - 1);
    loop {
        if let Err(error) = connection.write_line(&line) {
            return error;
        }
    }
}

// Security rule: one listener per name, and a live listener's socket is
// never removed by a second one.
#[test]
fn a_second_listener_is_refused_and_the_first_keeps_its_socket() {
    let Some(sandbox) = Sandbox::any("second listener") else {
        return;
    };
    let (transport, name) = (sandbox.transport(), sandbox.name());
    let first = transport.listen(&name).expect("listen");
    let inode = fs::metadata(&name).expect("the socket").ino();
    assert_eq!(transport.listen(&name).err(), Some(Error::AlreadyExists));
    assert_eq!(fs::metadata(&name).expect("still there").ino(), inode);
    let _client = transport.connect(&name).expect("the first still answers");
    first.accept().expect("accept");
}

/// A process made by `fork`, ended when the test is done with it.
struct Forked(libc::pid_t);

impl Drop for Forked {
    fn drop(&mut self) {
        // SAFETY: plain system calls on a process this test started.
        unsafe {
            libc::kill(self.0, libc::SIGKILL);
            libc::waitpid(self.0, std::ptr::null_mut(), 0);
        }
    }
}

// Closing frees the name there and then. A process started while the
// listener was open holds a copy of the open lock file, for a moment if it
// goes on to run a program of its own and for good if it does not, and a
// lock that was only let go by closing the file would last as long as the
// copy. The tests start programs all the time, which is how this was found:
// now and then the next `listen` on a name just closed was refused.
#[test]
fn closing_frees_the_name_whatever_a_started_process_still_holds() {
    let Some(sandbox) = Sandbox::any("held by a child") else {
        return;
    };
    let (transport, name) = (sandbox.transport(), sandbox.name());
    let listener = transport.listen(&name).expect("listen");
    // SAFETY: the child only makes system calls and never returns.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork");
    if pid == 0 {
        loop {
            // SAFETY: as above.
            unsafe { libc::pause() };
        }
    }
    let _child = Forked(pid);
    // Security rule: while the listener is open the name is still taken.
    assert_eq!(transport.listen(&name).err(), Some(Error::AlreadyExists));
    listener.close();
    let again = transport.listen(&name);
    assert_eq!(again.err(), None, "the name stayed taken after the close");
}

// A `listen` that fails after taking the name gives it back: the next one
// succeeds once what stood in the way is gone.
#[test]
fn a_listen_that_fails_gives_the_name_back() {
    let Some(sandbox) = Sandbox::any("failed listen") else {
        return;
    };
    let (transport, name) = (sandbox.transport(), sandbox.name());
    drop(transport.listen(&name).expect("make the folder"));
    // Something that is not a socket where the socket goes.
    fs::create_dir(&name).expect("put a folder in the way");
    let taken = failed("the channel's path is taken");
    assert_eq!(transport.listen(&name).err(), taken);
    assert_eq!(transport.listen(&name).err(), taken, "the second try");
    fs::remove_dir(&name).expect("clear the way");
    let listener = transport.listen(&name);
    assert_eq!(listener.err(), None, "the name stayed taken");
}

// A crashed run leaves its socket file behind. It must not block the next
// run, and nothing but a socket is ever removed to make room.
#[test]
fn a_stale_socket_file_is_recovered() {
    let Some(sandbox) = Sandbox::any("stale socket") else {
        return;
    };
    let (transport, name) = (sandbox.transport(), sandbox.name());
    drop(transport.listen(&name).expect("make the folder"));
    drop(UnixListener::bind(&name).expect("leave a socket file behind"));
    assert_eq!(transport.connect(&name).err(), Some(Error::NotFound));
    let listener = transport.listen(&name).expect("listen over the leftover");
    let _client = transport.connect(&name).expect("connect");
    listener.accept().expect("accept");
    drop(listener);

    fs::write(&name, "not a socket").expect("put a file in the way");
    assert!(matches!(transport.listen(&name), Err(Error::Failed(_))));
    assert_eq!(
        fs::read_to_string(&name).expect("untouched"),
        "not a socket"
    );
}

// Security rule: no other user can open the lock file, or they could hold
// the lock and keep the service from listening.
#[test]
fn the_lock_file_is_closed_to_other_users() {
    let Some(sandbox) = Sandbox::any("lock file") else {
        return;
    };
    let (transport, name) = (sandbox.transport(), sandbox.name());
    let lock = PathBuf::from(format!("{name}.lock"));
    // An ordinary umask, under which a file made carelessly is readable.
    drop(with_umask(0o022, || transport.listen(&name)).expect("listen"));
    assert_eq!(owner_and_mode(&lock), (me(), 0o600), "as made");
    // One left open by an earlier run is closed again.
    set_mode(&lock, 0o644).expect("open it");
    let listener = transport.listen(&name).expect("listen again");
    assert_eq!(owner_and_mode(&lock), (me(), 0o600), "as found");
    if me() == 0 {
        let opened = as_user(STRANGER, || fs::File::open(&lock));
        let refused = opened.err().map(|error| error.kind());
        assert_eq!(refused, Some(ErrorKind::PermissionDenied));
    }
    drop(listener);

    // A link in its place is refused, and what it points to is left alone.
    let target = sandbox.dir.join("target");
    fs::write(&target, "").expect("a file");
    set_mode(&target, 0o644).expect("set its mode");
    fs::remove_file(&lock).expect("remove the lock file");
    symlink(&target, &lock).expect("link");
    assert!(transport.listen(&name).is_err(), "followed a link");
    assert_eq!(owner_and_mode(&target), (me(), 0o644));
}

// A bad name is refused before anything is made for it.
#[test]
fn a_channel_name_is_a_short_absolute_path() {
    let Some(sandbox) = Sandbox::any("channel name") else {
        return;
    };
    let transport = sandbox.transport();
    let bad = failed("not a channel name");
    assert_eq!(transport.connect("relative/s.sock").err(), bad);
    assert_eq!(transport.connect("").err(), bad);
    let long = sandbox.dir.join("a".repeat(os::LONGEST_PATH));
    assert_eq!(transport.listen(&socket_in(&long)).err(), bad);
    assert_eq!(transport.connect(&socket_in(&long)).err(), bad);
    assert!(!long.exists(), "made a folder for a name it refused");
    // The longest that fits is taken.
    let fits = sandbox.folder("fits", 0o700);
    let room = os::LONGEST_PATH - fits.as_os_str().len() - 1;
    let name = fits.join("s".repeat(room));
    let listener = transport.listen(name.to_str().expect("UTF-8"));
    listener.expect("listen on the longest name");
}

// A service that stopped accepting must not hold its clients for ever.
#[cfg(target_os = "linux")]
#[test]
fn a_client_gives_up_on_a_service_that_stopped_accepting() {
    let Some(sandbox) = Sandbox::any("connect wait") else {
        return;
    };
    let (transport, name) = (sandbox.transport(), sandbox.name());
    drop(transport.listen(&name).expect("make the folder"));
    let stalled = UnixListener::bind(&name).expect("bind");
    rustix::net::listen(&stalled, 1).expect("shorten the queue");
    let started = Instant::now();
    let outcome = within("connecting", move || {
        let mut held = Vec::new();
        for _ in 0..64 {
            match transport.connect(&name) {
                Ok(connection) => held.push(connection),
                Err(error) => return Some(error),
            }
        }
        None
    });
    assert_eq!(outcome, Some(Error::TimedOut));
    assert!(started.elapsed() >= super::CONNECT_WAIT, "gave up early");
}

// Security rule: the owner a socket was narrowed to cannot stop the service.
// On macOS a file's owner can mark it unchangeable, which holds off even
// root until the mark is cleared.
#[cfg(target_os = "macos")]
#[test]
fn an_owner_cannot_pin_the_socket_file() {
    let Some(sandbox) = Sandbox::root("flags", Mode::Installed) else {
        return;
    };
    let (transport, name) = (sandbox.transport(), sandbox.name());
    let pin = || {
        let path = std::ffi::CString::new(name.as_str()).expect("no NUL");
        // SAFETY: `path` is a NUL-terminated string that outlives the call.
        let status = as_user(OWNER, || unsafe {
            libc::chflags(path.as_ptr(), libc::UF_IMMUTABLE)
        });
        assert_eq!(status, 0, "the owner could not set the flag");
    };
    let listener = transport.listen(&name).expect("listen");
    listener.restrict_to(&id(OWNER)).expect("narrow");
    pin();
    assert!(fs::remove_file(&name).is_err(), "the flag holds nobody off");
    listener.restrict_to(&id(STRANGER)).expect("narrow again");
    assert_eq!(owner_and_mode(&name), (STRANGER, 0o600));

    listener.restrict_to(&id(OWNER)).expect("narrow back");
    pin();
    listener.close();
    assert!(!Path::new(&name).exists(), "close left the socket behind");

    // The leftover of a run that crashed.
    drop(UnixListener::bind(&name).expect("leave a socket file behind"));
    chown(&name, Some(OWNER), None).expect("hand over");
    pin();
    transport
        .listen(&name)
        .expect("listen over a pinned leftover");
}

// Security rule: nor can an owner who keeps marking the file. Clearing the
// mark and then acting are two calls, and a program that marks in a loop
// gets between them nearly every time; the file has to be taken back first.
#[cfg(target_os = "macos")]
#[test]
fn an_owner_who_keeps_pinning_cannot_stop_the_service() {
    let Some(sandbox) = Sandbox::root("flags loop", Mode::Installed) else {
        return;
    };
    let (transport, name) = (sandbox.transport(), sandbox.name());
    drop(transport.listen(&name).expect("make the folder"));
    let path = std::ffi::CString::new(name.as_str()).expect("no NUL");
    // SAFETY: the child only makes system calls, on memory made before the
    // fork, and never returns.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork");
    if pid == 0 {
        // SAFETY: as above.
        unsafe {
            libc::setuid(OWNER);
            loop {
                libc::chflags(path.as_ptr(), libc::UF_IMMUTABLE);
            }
        }
    }
    let _child = Forked(pid);
    for round in 0..300 {
        // The leftover of a run that crashed, the owner's and soon marked.
        drop(UnixListener::bind(&name).expect("leave a socket file behind"));
        chown(&name, Some(OWNER), None).expect("hand over");
        thread::sleep(Duration::from_micros(200));
        let listener = transport.listen(&name);
        let listener = listener.unwrap_or_else(|error| panic!("listen, round {round}: {error}"));
        // The owner's again, marked again, then handed on and closed.
        listener.restrict_to(&id(OWNER)).expect("narrow");
        thread::sleep(Duration::from_micros(200));
        let handed_on = listener.restrict_to(&id(STRANGER));
        handed_on.unwrap_or_else(|error| panic!("narrow again, round {round}: {error}"));
        listener.restrict_to(&id(OWNER)).expect("narrow back");
        thread::sleep(Duration::from_micros(200));
        listener.close();
        assert!(!Path::new(&name).exists(), "close left it, round {round}");
    }
}

// Taking a file back is tried again only while that can help, and never for
// ever. Root keeps trying for a bounded time, because a mark on the file
// can pass. Anyone else is refused for good, and is told so at once.
#[test]
fn taking_a_file_back_gives_up() {
    let Some(sandbox) = Sandbox::any("take-back bound") else {
        return;
    };
    let name = sandbox.name();
    let listener = sandbox.transport().listen(&name).expect("listen");
    let path = PathBuf::from(&name);
    let started = Instant::now();
    let outcome = within("taking a file back", move || {
        let refuse = || Err::<(), _>(std::io::Error::from(ErrorKind::PermissionDenied));
        super::take_back(&path, refuse).map_err(|error| error.kind())
    });
    assert_eq!(outcome, Err(ErrorKind::PermissionDenied));
    let waited = started.elapsed();
    if me() == 0 {
        assert!(waited >= super::TAKE_BACK_WAIT, "root gave up at once");
    } else {
        assert!(waited < super::TAKE_BACK_WAIT, "kept trying to no purpose");
        // The real thing: only root can hand a file to someone else.
        let started = Instant::now();
        let narrowed = listener.restrict_to(&id(STRANGER));
        assert_eq!(narrowed, Err(Error::PermissionDenied));
        assert!(started.elapsed() < super::TAKE_BACK_WAIT, "kept trying");
    }
}

// A client's socket must not stay open in a program the client starts.
#[test]
fn a_clients_socket_is_closed_on_exec() {
    let socket = os::socket().expect("a socket");
    let flags = rustix::io::fcntl_getfd(&socket).expect("its flags");
    assert!(flags.contains(rustix::io::FdFlags::CLOEXEC));
}

// Security rule: the socket's folder cannot be changed by anyone else.
#[test]
fn listen_refuses_a_folder_others_could_change() {
    let Some(sandbox) = Sandbox::any("unsafe folders") else {
        return;
    };
    let installed = sandbox.mode == Mode::Installed;
    let listen = |folder: &Path| sandbox.transport().listen(&socket_in(folder)).err();

    for (name, bit) in [("group", 0o020), ("world", 0o002)] {
        let open = sandbox.folder(name, 0o700 | bit);
        assert_eq!(listen(&open), failed(TOO_OPEN), "{name}-writable");
        assert_eq!(fs::read_dir(&open).expect("list").count(), 0, "left a file");
    }

    // Dev mode's folder is the user's alone: not even readable by others.
    if !installed {
        for (name, bit) in [("group-read", 0o040), ("world-search", 0o001)] {
            let open = sandbox.folder(name, 0o700 | bit);
            assert_eq!(listen(&open), failed(TOO_OPEN), "{name}");
        }
    }

    let real = sandbox.folder("real", 0o700);
    let link = sandbox.dir.join("link");
    symlink(&real, &link).expect("link");
    assert_eq!(listen(&link), failed(NOT_A_FOLDER));

    // A folder of another user's: one handed to a stranger as root, and the
    // root folder for anyone else.
    let foreign = if me() == 0 {
        let foreign = sandbox.folder("foreign", 0o700);
        chown(&foreign, Some(STRANGER), None).expect("hand over");
        foreign
    } else {
        PathBuf::from("/")
    };
    assert_eq!(listen(&foreign), failed(WRONG_OWNER));

    // Installed, the same holds for every folder on the way.
    if installed {
        let open = sandbox.folder("open", 0o777);
        assert_eq!(listen(&open.join("ch")), failed(TOO_OPEN), "parent");
        set_mode(&real, 0o755).expect("open the real folder");
        assert_eq!(listen(&link.join("ch")), failed(NOT_A_FOLDER), "parent");
        assert!(!real.join("ch").exists(), "made a folder through a link");
    }
}

// Security rule: the folder's and the socket's owner and mode are set
// outright, whatever the umask, and narrowing hands the socket to the owner.
#[test]
fn the_folder_and_socket_have_exactly_the_intended_owner_and_mode() {
    let Some(sandbox) = Sandbox::any("owner and mode") else {
        return;
    };
    let (folder_mode, socket_mode) = match sandbox.mode {
        Mode::Installed => (0o755, 0o666),
        #[cfg(feature = "dev-mode")]
        Mode::Dev => (0o700, 0o600),
    };
    let name = sandbox.name();
    let listener = with_umask(0o277, || sandbox.transport().listen(&name));
    let listener = listener.expect("listen");
    assert_eq!(owner_and_mode(sandbox.dir.join("ch")), (me(), folder_mode));
    assert_eq!(owner_and_mode(&name), (me(), socket_mode));

    // The last one is the value that tells the OS to leave the owner alone.
    for odd in ["01", "+1", "0x1", "S-1-5", "4294967295"] {
        let odd = odd.parse().expect("an identity");
        assert!(listener.restrict_to(&odd).is_err(), "{odd}");
    }
    assert_eq!(owner_and_mode(&name), (me(), socket_mode));
    listener.restrict_to(&id(me())).expect("narrow to myself");
    assert_eq!(owner_and_mode(&name), (me(), 0o600));
    if me() == 0 {
        listener
            .restrict_to(&id(OWNER))
            .expect("narrow to the owner");
        assert_eq!(owner_and_mode(&name), (OWNER, 0o600));
    }
    listener.close();
    assert_eq!(listener.restrict_to(&id(me())), Err(Error::Closed));
}

// Security rule: the caller's identity is the kernel's record of who
// connected. Nothing the caller sends changes it.
#[test]
fn the_identity_is_the_kernels_and_not_the_callers_word() {
    let Some(sandbox) = Sandbox::any("identity") else {
        return;
    };
    let (transport, name) = (sandbox.transport(), sandbox.name());
    let listener = transport.listen(&name).expect("listen");
    let client = transport.connect(&name).expect("connect");
    client.write_line(r#"{"user":"4242"}"#).expect("lie");
    let (_server, caller) = listener.accept().expect("accept");
    assert_eq!(caller, id(me()));
    if me() == 0 {
        // Still root in every way but the effective user.
        let _stranger = kernel_connect(STRANGER, &name).expect("connect");
        let (_server, caller) = listener.accept().expect("accept");
        assert_eq!(caller, id(STRANGER));
    }
}

// Security rule: a silent client cannot hold a reader, and one that never
// reads cannot hold a writer.
#[test]
fn timeouts_fire_against_a_silent_and_a_non_reading_peer() {
    let Some(sandbox) = Sandbox::any("timeouts") else {
        return;
    };
    let (_listener, _client, server) = sandbox.pair();
    server.set_read_timeout(Some(PAUSE)).expect("set");
    server.set_write_timeout(Some(PAUSE)).expect("set");
    let started = Instant::now();
    let (read, written) = within("a read and a write with timeouts", move || {
        (server.read_line(), write_until_stuck(&server))
    });
    assert_eq!(read, Err(Error::TimedOut));
    assert_eq!(written, Error::TimedOut);
    assert!(started.elapsed() >= PAUSE * 2, "gave up early");
}

#[test]
fn close_ends_a_blocked_read_write_and_accept() {
    let Some(sandbox) = Sandbox::any("close") else {
        return;
    };
    let (listener, _client, server) = sandbox.pair();
    let (listener, server): (Arc<dyn Listener>, _) = (listener.into(), Arc::new(server));
    let later = |close: Box<dyn FnOnce() + Send>| {
        thread::spawn(move || {
            thread::sleep(PAUSE);
            close();
        })
    };

    let reader = server.clone();
    later(Box::new(move || reader.close()));
    let reader = server.clone();
    let read = within("a blocked read", move || reader.read_line());
    assert_eq!(read, Err(Error::Closed));

    let (_client, second) = {
        let client = sandbox.transport().connect(&sandbox.name());
        (
            client.expect("connect"),
            listener.accept().expect("accept").0,
        )
    };
    let second = Arc::new(second);
    let writer = second.clone();
    later(Box::new(move || writer.close()));
    let written = within("a blocked write", move || write_until_stuck(&second));
    assert_eq!(written, Error::Closed);

    let waiting = listener.clone();
    later(Box::new(move || waiting.close()));
    let waiting = listener.clone();
    let accepted = within("a blocked accept", move || waiting.accept().err());
    assert_eq!(accepted, Some(Error::Closed));
    assert_eq!(listener.accept().err(), Some(Error::Closed));
}

// Security rule: a client that goes away must not kill the service. With the
// signal at its default, as in a program that is not Rust's own, an
// unguarded write would end this test process.
#[test]
fn writing_to_a_vanished_peer_is_an_error_and_not_sigpipe() {
    let Some(sandbox) = Sandbox::any("sigpipe") else {
        return;
    };
    // Both kinds of socket: one the listener accepted, one a client made.
    let (listener, gone, accepted) = sandbox.pair();
    let connected = sandbox.transport().connect(&sandbox.name());
    let connected = connected.expect("connect");
    drop(listener.accept().expect("accept"));
    drop(gone);
    assert_eq!(accepted.read_line(), Ok(None), "the peer left");
    // SAFETY: installing the default action runs no code of ours.
    let before = unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
    let written = [accepted, connected].map(|end| end.write_line("anyone there?"));
    // SAFETY: puts back the action that was there before.
    unsafe { libc::signal(libc::SIGPIPE, before) };
    assert_eq!(written, [Err(Error::Closed), Err(Error::Closed)]);
}

// Security rule: a socket in a folder that is not root's alone may be anyone's.
#[test]
fn an_installed_client_refuses_a_socket_in_a_folder_that_is_not_roots() {
    let sandbox = Sandbox::new(Mode::Installed);
    let folder = sandbox.folder("ch", 0o755);
    let _squatter = UnixListener::bind(socket_in(&folder)).expect("squat");
    let connect = || sandbox.transport().connect(&socket_in(&folder)).err();
    if me() == 0 {
        sandbox
            .transport()
            .connect(&socket_in(&folder))
            .expect("root's own");
        chown(&folder, Some(STRANGER), None).expect("hand over");
        assert_eq!(connect(), Some(Error::NotTheService), "a stranger's folder");
        chown(&folder, Some(0), None).expect("take back");
        set_mode(&folder, 0o775).expect("open to a group");
        assert_eq!(connect(), Some(Error::NotTheService), "a group's folder");
    } else {
        // The temporary folder is this user's, or under one anyone can write.
        assert_eq!(connect(), Some(Error::NotTheService));
    }
}

// Security rule: the session cookie only ever goes to the service. A socket
// that is not the service's file, or not answered by the service, is refused.
#[test]
fn a_client_refuses_a_squatted_socket() {
    let Some(sandbox) = Sandbox::root("squatted socket", Mode::Installed) else {
        return;
    };
    let transport = sandbox.transport();

    // Someone else's socket file, though root answers it.
    let folder = sandbox.folder("file", 0o755);
    let name = socket_in(&folder);
    let _squatter = UnixListener::bind(&name).expect("bind");
    transport
        .connect(&name)
        .expect("root's own socket is accepted");
    // Open to all, so that the kernel would let the caller in and only the
    // client's own check can refuse.
    set_mode(Path::new(&name), 0o666).expect("open it");
    chown(&name, Some(STRANGER), None).expect("hand over");
    let other = as_user(OWNER, || transport.connect(&name));
    assert_eq!(other.err(), Some(Error::PermissionDenied));
    // Root is let through, as after narrowing.
    transport.connect(&name).expect("root");

    // Root's folder and root's file, but a stranger answers.
    let folder = sandbox.folder("peer", 0o777);
    let name = socket_in(&folder);
    let _squatter = as_user(STRANGER, || UnixListener::bind(&name)).expect("bind");
    set_mode(&folder, 0o755).expect("close the folder");
    chown(&name, Some(0), None).expect("take the file");
    assert_eq!(transport.connect(&name).err(), Some(Error::NotTheService));

    // A link to a real service's socket is not that socket.
    let name = socket_in(&sandbox.dir);
    symlink(socket_in(&sandbox.dir.join("file")), &name).expect("link");
    assert_eq!(transport.connect(&name).err(), Some(Error::NotTheService));
}

// Security rule: once narrowed, the OS itself refuses everyone but the owner
// (and root). Connections made earlier stay, which is why the service checks
// the identity on every request.
#[test]
fn narrowing_admits_the_owner_and_refuses_everyone_else() {
    let Some(sandbox) = Sandbox::root("narrowing", Mode::Installed) else {
        return;
    };
    let (transport, name) = (sandbox.transport(), sandbox.name());
    let listener = transport.listen(&name).expect("listen");
    let _queued = kernel_connect(STRANGER, &name).expect("open before an owner exists");
    listener.restrict_to(&id(OWNER)).expect("narrow");

    let denied = Some(ErrorKind::PermissionDenied);
    assert_eq!(kernel_connect(STRANGER, &name).err(), denied, "the kernel");
    let stranger = as_user(STRANGER, || transport.connect(&name));
    assert_eq!(stranger.err(), Some(Error::PermissionDenied));

    let (_server, caller) = listener.accept().expect("the queued caller");
    assert_eq!(caller, id(STRANGER), "a queued caller was dropped");
    // Narrowing never shuts root out, here or in the OS. The service still
    // learns that it is root and not the owner.
    let _root = transport.connect(&name).expect("root is let through");
    let (_server, caller) = listener.accept().expect("accept root");
    assert_eq!(caller, id(0));
    let _owner = as_user(OWNER, || transport.connect(&name)).expect("the owner");
    let (_server, caller) = listener.accept().expect("accept the owner");
    assert_eq!(caller, id(OWNER));

    // Security rule: the file is changed only once it is no longer the
    // owner's, who could otherwise get in the way of the change.
    assert_eq!(owner_and_mode(&name).0, OWNER);
    let seen = || Ok(owner_and_mode(&name).0);
    let seen = super::take_back(Path::new(&name), seen);
    assert_eq!(seen.ok(), Some(0), "changed while still the owner's");
}

#[test]
fn the_installed_channel_passes_the_suite_with_a_second_user() {
    let Some(sandbox) = Sandbox::root("suite", Mode::Installed) else {
        return;
    };
    let transport = sandbox.transport();
    let stranger = |name: &str| as_user(STRANGER, || transport.connect(name));
    suite::check_transport(&transport, &sandbox.name(), &stranger);
}

// Security rule: a dev-mode channel admits its own user only, from the
// start, and a dev-mode client only talks to its own user's service.
#[cfg(feature = "dev-mode")]
#[test]
fn a_dev_channel_refuses_another_user_from_the_start() {
    let Some(sandbox) = Sandbox::root("dev", Mode::Dev) else {
        return;
    };
    let transport = sandbox.transport();
    let shared = sandbox.folder("shared", 0o777);
    let name = socket_in(&shared.join("ch"));
    let listener = as_user(OWNER, || transport.listen(&name)).expect("listen");
    assert_eq!(owner_and_mode(shared.join("ch")), (OWNER, 0o700));
    assert_eq!(owner_and_mode(&name), (OWNER, 0o600));

    let denied = Some(ErrorKind::PermissionDenied);
    assert_eq!(kernel_connect(STRANGER, &name).err(), denied, "the kernel");
    let stranger = as_user(STRANGER, || transport.connect(&name));
    assert_eq!(stranger.err(), Some(Error::NotTheService));
    let _owner = as_user(OWNER, || transport.connect(&name)).expect("the owner");
    let (_server, caller) = listener.accept().expect("accept");
    assert_eq!(caller, id(OWNER));

    // This user's folder and file, but another user answers.
    chown(shared.join("ch"), Some(0), None).expect("take the folder");
    chown(&name, Some(0), None).expect("take the file");
    assert_eq!(transport.connect(&name).err(), Some(Error::NotTheService));
}

fn env(pairs: &'static [(&str, &str)]) -> impl Fn(&str) -> Option<OsString> {
    |name| {
        let found = pairs.iter().find(|(variable, _)| *variable == name);
        found.map(|(_, value)| OsString::from(value))
    }
}

const PLAIN: &[(&str, &str)] = &[("HOME", "/home/someone")];
const HOSTILE: &[(&str, &str)] = &[
    ("HOME", "/evil/home"),
    ("XDG_CONFIG_HOME", "/evil/config"),
    ("XDG_RUNTIME_DIR", "/evil/run"),
    ("TMPDIR", "/evil/tmp"),
];

// Security rule: where the installed service keeps its files and listens
// does not depend on the environment, which whoever starts a process chooses.
#[test]
fn installed_system_paths_ignore_the_environment() {
    let plain = os::paths(Mode::Installed, &env(PLAIN)).expect("paths");
    let hostile = os::paths(Mode::Installed, &env(HOSTILE)).expect("paths");
    let system = if cfg!(target_os = "macos") {
        let folder = "/Library/Application Support/UBC VPN";
        [
            folder,
            folder,
            "/Library/Application Support/UBC VPN/service.sock",
        ]
    } else {
        [
            "/etc/ubc-vpn",
            "/var/lib/ubc-vpn",
            "/run/ubc-vpn/service.sock",
        ]
    };
    for paths in [&plain, &hostile] {
        assert_eq!(paths.policy_dir, Path::new(system[0]));
        assert_eq!(paths.state_dir, Path::new(system[1]));
        assert_eq!(paths.channel_name, system[2]);
    }
    // The settings are the user's own, so they follow the user.
    assert!(plain.settings_dir.starts_with("/home/someone"));
    assert!(hostile.settings_dir.starts_with("/evil"));
}

#[test]
fn per_user_folders_cope_with_unset_and_relative_variables() {
    let paths = |pairs| os::paths(Mode::Installed, &env(pairs));
    // Unset: the user database answers, as for a service.
    let unset = paths(&[]).expect("paths without HOME");
    assert!(unset.settings_dir.is_absolute());
    let relative = paths(&[("HOME", "relative"), ("XDG_CONFIG_HOME", "/config")]);
    if cfg!(target_os = "linux") {
        let expected = Path::new("/config/ubc-vpn");
        assert_eq!(relative.expect("HOME is not needed").settings_dir, expected);
        let ignored = paths(&[("HOME", "/home/someone"), ("XDG_CONFIG_HOME", "relative")]);
        let expected = Path::new("/home/someone/.config/ubc-vpn");
        assert_eq!(ignored.expect("paths").settings_dir, expected);
    }
    assert!(matches!(
        paths(&[("HOME", "relative")]),
        Err(Error::Failed(_))
    ));
    assert!(matches!(paths(&[("HOME", "")]), Err(Error::Failed(_))));
}

#[cfg(feature = "dev-mode")]
#[test]
fn dev_paths_never_collide_with_the_installed_ones() {
    const INSIDE: &[(&str, &str)] = &[
        ("HOME", "/"),
        ("XDG_CONFIG_HOME", "/etc/ubc-vpn"),
        ("XDG_RUNTIME_DIR", "/run/ubc-vpn"),
        ("TMPDIR", "relative"),
    ];
    // The dev socket's folder is named after whoever the process runs as.
    let _turn = turn();
    for pairs in [PLAIN, HOSTILE, INSIDE] {
        let installed = os::paths(Mode::Installed, &env(pairs)).expect("paths");
        match os::paths(Mode::Dev, &env(pairs)) {
            Ok(dev) => suite::check_paths(&installed, &dev),
            // Refusing is the other way not to collide.
            Err(error) => assert!(matches!(error, Error::Failed(_)), "{error}"),
        }
    }
    let runtime = if cfg!(target_os = "macos") {
        "tmp"
    } else {
        "run"
    };
    let dev = os::paths(Mode::Dev, &env(HOSTILE)).expect("paths");
    let per_user = format!("/evil/{runtime}/ubc-vpn-dev-{}/service.sock", me());
    assert_eq!(dev.channel_name, per_user);
    // Relative, in the variable each system reads.
    const RELATIVE: &[(&str, &str)] = &[
        ("HOME", "/h"),
        ("TMPDIR", "tmp"),
        ("XDG_RUNTIME_DIR", "run"),
    ];
    let dev = os::paths(Mode::Dev, &env(RELATIVE));
    let fallback = format!("/tmp/ubc-vpn-dev-{}/service.sock", me());
    assert_eq!(dev.expect("paths").channel_name, fallback);
}

// The counterpart of `the_unimplemented_os_reports_unsupported`: the channel
// and the paths are real here. Everything else must still say it is
// unsupported, and its checks must still fail closed.
#[test]
fn native_has_a_real_channel_and_nothing_else_yet() {
    let unsupported = Some(Error::Unsupported);
    let gateway = Ipv4Addr::new(192, 0, 2, 1);
    let physical = PhysicalNetwork {
        interface: "eth0".to_string(),
        next_hop: None,
    };
    let dns = SplitDns {
        resolvers: vec![gateway],
        domains: vec!["ece.example".to_string()],
    };
    let _turn = turn();
    let modes = [Some(Mode::Installed), DEV];
    for mode in modes.into_iter().flatten() {
        let native = Platform::native(mode).expect("a platform");
        assert_eq!(native.routes.capture_physical(gateway).err(), unsupported);
        assert_eq!(native.routes.remove_all().err(), unsupported);
        let routed = native.routes.uses_interface(gateway, "tun0");
        assert_eq!(routed, Verified::Unknown);
        assert_eq!(native.dns.clear_split_dns().err(), unsupported);
        assert_eq!(native.dns.split_dns_matches(&dns), Verified::Unknown);
        assert_eq!(native.events.subscribe(&physical).err(), unsupported);
        // Nothing listens there, and the transport can tell.
        let absent = native.transport.connect("/ubc-vpn-nobody/listens.sock");
        assert_eq!(absent.err(), Some(Error::NotFound));
        assert!(Path::new(&native.paths.channel_name).is_absolute());
    }
}
