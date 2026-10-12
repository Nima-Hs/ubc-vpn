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
use std::io::ErrorKind;
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

use super::{NOT_A_FOLDER, NOT_THE_SERVICE, SocketTransport, TOO_OPEN, WRONG_OWNER, set_mode};
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

/// Whether a test that needs root may run. It says so either way, and CI
/// checks what it said.
fn root(test: &str) -> bool {
    if me() == 0 {
        eprintln!("RAN AS ROOT: {test}");
        return true;
    }
    let required = std::env::var_os("UBC_VPN_REQUIRE_ROOT").is_some();
    assert!(!required, "{test} needs root");
    eprintln!("SKIPPED, needs root: {test}");
    false
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
        let turn = lock(&SERIAL);
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
        let mode = if me() == 0 {
            Some(Mode::Installed)
        } else {
            DEV
        };
        if mode.is_none() {
            eprintln!("SKIPPED, needs dev mode or root: {test}");
        }
        mode.map(Self::new)
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
    // SAFETY: the call has no memory-safety conditions. Tests that create
    // files take turns, so no other one sees this umask.
    let umask = unsafe { libc::umask(0o277) };
    let listener = sandbox.transport().listen(&name);
    // SAFETY: as above.
    unsafe { libc::umask(umask) };
    let listener = listener.expect("listen");
    assert_eq!(owner_and_mode(sandbox.dir.join("ch")), (me(), folder_mode));
    assert_eq!(owner_and_mode(&name), (me(), socket_mode));

    for odd in ["01", "+1", "0x1", "S-1-5"] {
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
    let (_listener, client, server) = sandbox.pair();
    drop(client);
    assert_eq!(server.read_line(), Ok(None), "the peer left");
    // SAFETY: installing the default action runs no code of ours.
    let before = unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
    let written = server.write_line("anyone there?");
    // SAFETY: puts back the action that was there before.
    unsafe { libc::signal(libc::SIGPIPE, before) };
    assert_eq!(written, Err(Error::Closed));
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
        assert_eq!(connect(), failed(WRONG_OWNER));
        chown(&folder, Some(0), None).expect("take back");
        set_mode(&folder, 0o775).expect("open to a group");
        assert_eq!(connect(), failed(TOO_OPEN));
    } else {
        // The temporary folder is this user's, or under one anyone can write.
        let refusals = [NOT_A_FOLDER, WRONG_OWNER, TOO_OPEN].map(failed);
        assert!(refusals.contains(&connect()), "{:?}", connect());
    }
}

// Security rule: the session cookie only ever goes to the service. A socket
// that is not the service's file, or not answered by the service, is refused.
#[test]
fn a_client_refuses_a_squatted_socket() {
    if !root("squatted socket") {
        return;
    }
    let sandbox = Sandbox::new(Mode::Installed);
    let transport = sandbox.transport();

    // Someone else's socket file, though root answers it.
    let folder = sandbox.folder("file", 0o755);
    let name = socket_in(&folder);
    let _squatter = UnixListener::bind(&name).expect("bind");
    transport
        .connect(&name)
        .expect("root's own socket is accepted");
    chown(&name, Some(STRANGER), None).expect("hand over");
    assert_eq!(
        transport.connect(&name).err(),
        Some(Error::PermissionDenied)
    );

    // Root's folder and root's file, but a stranger answers.
    let folder = sandbox.folder("peer", 0o777);
    let name = socket_in(&folder);
    let _squatter = as_user(STRANGER, || UnixListener::bind(&name)).expect("bind");
    set_mode(&folder, 0o755).expect("close the folder");
    chown(&name, Some(0), None).expect("take the file");
    assert_eq!(transport.connect(&name).err(), failed(NOT_THE_SERVICE));

    // A link to a real service's socket is not that socket.
    let name = socket_in(&sandbox.dir);
    symlink(socket_in(&sandbox.dir.join("file")), &name).expect("link");
    assert_eq!(transport.connect(&name).err(), failed(NOT_THE_SERVICE));
}

// Security rule: once narrowed, the OS itself refuses everyone but the owner
// (and root). Connections made earlier stay, which is why the service checks
// the identity on every request.
#[test]
fn narrowing_admits_the_owner_and_refuses_everyone_else() {
    if !root("narrowing") {
        return;
    }
    let sandbox = Sandbox::new(Mode::Installed);
    let (transport, name) = (sandbox.transport(), sandbox.name());
    let listener = transport.listen(&name).expect("listen");
    let _queued = kernel_connect(STRANGER, &name).expect("open before an owner exists");
    listener.restrict_to(&id(OWNER)).expect("narrow");

    let denied = Some(ErrorKind::PermissionDenied);
    assert_eq!(kernel_connect(STRANGER, &name).err(), denied, "the kernel");
    let stranger = as_user(STRANGER, || transport.connect(&name));
    assert_eq!(stranger.err(), Some(Error::PermissionDenied));
    // Root is not the owner either: the OS would let it in, the client
    // itself declines.
    assert_eq!(
        transport.connect(&name).err(),
        Some(Error::PermissionDenied)
    );

    let (_server, caller) = listener.accept().expect("the queued caller");
    assert_eq!(caller, id(STRANGER), "a queued caller was dropped");
    let _owner = as_user(OWNER, || transport.connect(&name)).expect("the owner");
    let (_server, caller) = listener.accept().expect("accept the owner");
    assert_eq!(caller, id(OWNER));
}

#[test]
fn the_installed_channel_passes_the_suite_with_a_second_user() {
    if !root("suite") {
        return;
    }
    let sandbox = Sandbox::new(Mode::Installed);
    let transport = sandbox.transport();
    let stranger = |name: &str| as_user(STRANGER, || transport.connect(name));
    suite::check_transport(&transport, &sandbox.name(), &stranger);
}

// Security rule: a dev-mode channel admits its own user only, from the
// start, and a dev-mode client only talks to its own user's service.
#[cfg(feature = "dev-mode")]
#[test]
fn a_dev_channel_refuses_another_user_from_the_start() {
    if !root("dev") {
        return;
    }
    let sandbox = Sandbox::new(Mode::Dev);
    let transport = sandbox.transport();
    let shared = sandbox.folder("shared", 0o777);
    let name = socket_in(&shared.join("ch"));
    let listener = as_user(OWNER, || transport.listen(&name)).expect("listen");
    assert_eq!(owner_and_mode(shared.join("ch")), (OWNER, 0o700));
    assert_eq!(owner_and_mode(&name), (OWNER, 0o600));

    let denied = Some(ErrorKind::PermissionDenied);
    assert_eq!(kernel_connect(STRANGER, &name).err(), denied, "the kernel");
    let stranger = as_user(STRANGER, || transport.connect(&name));
    assert_eq!(stranger.err(), failed(WRONG_OWNER));
    let _owner = as_user(OWNER, || transport.connect(&name)).expect("the owner");
    let (_server, caller) = listener.accept().expect("accept");
    assert_eq!(caller, id(OWNER));

    // This user's folder and file, but another user answers.
    chown(shared.join("ch"), Some(0), None).expect("take the folder");
    chown(&name, Some(0), None).expect("take the file");
    assert_eq!(transport.connect(&name).err(), failed(NOT_THE_SERVICE));
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
    let dev = os::paths(Mode::Dev, &env(&[("HOME", "/h"), ("TMPDIR", "tmp")]));
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
