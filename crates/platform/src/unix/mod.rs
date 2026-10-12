//! The channel on Linux and macOS: a Unix stream socket, named by its
//! absolute path. Each OS module adds its paths and the two calls that differ
//! (who the peer is, and writing without `SIGPIPE`).
//!
//! How the socket keeps the channel's promises:
//!
//! - **One listener.** A listener holds an exclusive lock on `<socket>.lock`
//!   for as long as it lives. The lock dies with its process, so whoever holds
//!   it knows a socket file already there is a leftover and may replace it,
//!   and nobody ever removes the socket of a listener that is alive. The lock
//!   file itself is never removed.
//! - **Local callers only**: a Unix socket has no remote callers.
//! - **A folder nobody else can change.** Installed: the socket's folder and
//!   every folder above it are real folders (no symlinks) owned by root and
//!   writable by root alone. Dev: the folder is the current user's, mode
//!   0700. `listen` creates the last folder when it is missing, and both
//!   `listen` and `connect` refuse a folder that breaks the rule. The lock
//!   file is the listener's alone (0600), so no other user can hold the lock.
//! - **The caller is who the kernel says**: the peer's effective user ID,
//!   recorded by the kernel when the connection was made.
//! - **Narrowing** hands the socket file to the owner with mode 0600. The
//!   kernel checks that when a client connects, so it only affects later
//!   connections. Root is still let in. The file is then the owner's, so the
//!   owner can open it to others again: narrowing is a first line only, and
//!   the service's check of the caller on every request is the guard.
//! - **The owner cannot keep the service from listening.** On macOS a file's
//!   owner can mark it unchangeable, which holds off even root. So before the
//!   socket file is removed or handed on, it is taken back: the mark is
//!   cleared, the file made root's and the change tried, repeated while the
//!   OS refuses. Once it is root's it is no longer the owner's to mark, bar
//!   a mark already on its way. This defeats a mark set once
//!   and a program that sets it in a loop. It is bounded: an owner who won
//!   every try for a second would get an error reported, by `listen` and
//!   `restrict_to`; `close` has nobody to tell, and the next `listen` tries
//!   again. The lock file is never anyone's but the listener's, and no
//!   release may ever make it open to others: a user who opened it then
//!   could hold the lock for as long as their program runs.
//! - **A busy service does not hold a client for ever.** `connect` gives up
//!   after five seconds. With a full queue Linux makes the caller wait, so
//!   that limit ends it with [`Error::TimedOut`]; macOS refuses at once,
//!   which reads as [`Error::NotFound`].
//! - **A client checks the server**: the folder rule above, a socket file
//!   that belongs to the service or to the caller, and a peer that is the
//!   service (root when installed, the current user in dev mode). The peer
//!   check is the one that cannot be raced: it describes the very socket the
//!   client is connected to. A client that finds otherwise reports
//!   [`Error::NotTheService`] and has sent nothing. The one exception is a
//!   socket file handed to another user, which only narrowing does in a
//!   folder like that: it reports [`Error::PermissionDenied`].
//!
//! What the installer and the service's start-up must guarantee, because
//! `listen` refuses otherwise:
//!
//! - macOS: `/Library/Application Support/UBC VPN` is root's with mode 0755.
//!   A folder left 0775, as some installers make it, is refused.
//! - Linux: `/run/ubc-vpn` is root's with mode 0755. systemd's
//!   `RuntimeDirectory=ubc-vpn` makes it so on every start; `listen` makes it
//!   too when it is missing.
//!
//! A client inside a user namespace (Flatpak, snap, a rootless container)
//! sees root's files and root's processes as user 65534, so it reports
//! [`Error::NotTheService`]. That fails closed, and packaging has to keep the
//! clients outside such a sandbox.

pub(crate) mod terminal;
#[cfg(test)]
mod tests;

use std::ffi::OsString;
use std::fs::{self, DirBuilder, File, OpenOptions, Permissions, TryLockError};
use std::io;
use std::net::Shutdown;
use std::os::unix::fs::{
    DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt, chown, lchown,
};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::fs::OFlags;
use rustix::io::Errno;
use rustix::net::sockopt::{self, Timeout};
use rustix::net::{RecvFlags, SocketAddrUnix, connect, recv};
use rustix::process::geteuid;

use crate::unsupported::Native;
use crate::{
    Connection, Error, Listener, Mode, Paths, Platform, RawConnection, Result, Transport, UserId,
    lock, os,
};

/// What `listen` reports for a folder that breaks the rule. A client reports
/// [`Error::NotTheService`] for all three.
pub(crate) const NOT_A_FOLDER: &str = "the channel's folder is a link or not a folder";
pub(crate) const WRONG_OWNER: &str = "the channel's folder belongs to the wrong user";
pub(crate) const TOO_OPEN: &str = "the channel's folder can be changed by other users";

/// How the OS modules read the environment. Tests pass their own.
pub(crate) type Env<'a> = &'a dyn Fn(&str) -> Option<OsString>;

pub(crate) fn real_env(name: &str) -> Option<OsString> {
    std::env::var_os(name)
}

/// The current user's home folder: `HOME`, or the user database when it is
/// unset, as for a service. A relative `HOME` is refused, not guessed at.
pub(crate) fn home(env: Env<'_>) -> Result<PathBuf> {
    let home = env("HOME").map(PathBuf::from).or_else(std::env::home_dir);
    home.filter(|home| home.is_absolute())
        .ok_or_else(|| Error::Failed("HOME is not an absolute path".to_string()))
}

/// Dev mode's paths: its files under `dev`, and its socket in the per-user
/// folder `variable` names, or in `/tmp` when that is unset or relative. The
/// user ID in the socket folder's name keeps two users apart there, and
/// `listen` refuses a folder someone else made.
#[cfg(feature = "dev-mode")]
pub(crate) fn dev_paths(dev: &Path, env: Env<'_>, variable: &str) -> Paths {
    let base = env(variable).map(PathBuf::from);
    let base = base.filter(|base| base.is_absolute());
    let folder = format!("ubc-vpn-dev-{}", geteuid().as_raw());
    let socket = base.unwrap_or_else(|| PathBuf::from("/tmp")).join(folder);
    Paths {
        policy_dir: dev.join("policy"),
        state_dir: dev.join("state"),
        settings_dir: dev.join("settings"),
        channel_name: socket.join("service.sock").to_string_lossy().into_owned(),
    }
}

pub(crate) fn native(mode: Mode, paths: Paths) -> Platform {
    Platform {
        routes: Arc::new(Native),
        dns: Arc::new(Native),
        events: Arc::new(Native),
        transport: Arc::new(SocketTransport { mode }),
        paths,
    }
}

pub(crate) struct SocketTransport {
    pub(crate) mode: Mode,
}

/// The user the service runs as: root when installed, `me` in dev mode.
fn service_user(mode: Mode, me: u32) -> u32 {
    match mode {
        Mode::Installed => {
            let _ = me;
            0
        }
        #[cfg(feature = "dev-mode")]
        Mode::Dev => me,
    }
}

/// The modes of the socket's folder and of the socket before it is narrowed.
/// Installed, any local user may connect until an owner exists.
fn modes(mode: Mode) -> (u32, u32) {
    match mode {
        Mode::Installed => (0o755, 0o666),
        #[cfg(feature = "dev-mode")]
        Mode::Dev => (0o700, 0o600),
    }
}

/// Security rule: the socket lives where no other user can replace it.
fn check_folder(mode: Mode, folder: &Path, me: u32) -> Result<()> {
    match mode {
        Mode::Installed => {
            let _ = me;
            let mut chain: Vec<&Path> = folder.ancestors().collect();
            chain.reverse();
            chain.into_iter().try_for_each(|at| check_one(at, 0, 0o022))
        }
        #[cfg(feature = "dev-mode")]
        Mode::Dev => check_one(folder, me, 0o077),
    }
}

fn check_one(folder: &Path, owner: u32, forbidden: u32) -> Result<()> {
    // Not followed: a link here could be pointed anywhere later.
    let found = fs::symlink_metadata(folder)?;
    let broken = if !found.is_dir() {
        NOT_A_FOLDER
    } else if found.uid() != owner {
        WRONG_OWNER
    } else if found.mode() & forbidden != 0 {
        TOO_OPEN
    } else {
        return Ok(());
    };
    Err(Error::Failed(broken.to_string()))
}

/// A channel name is the socket's absolute path, short enough for a socket
/// address. Anything else is refused before a folder or file is made for it.
fn split(name: &str) -> Result<(&Path, &Path)> {
    let path = Path::new(name);
    let fits = name.len() <= os::LONGEST_PATH && !name.contains('\0');
    match path.parent() {
        Some(folder) if fits && path.is_absolute() && path.file_name().is_some() => {
            Ok((path, folder))
        }
        _ => Err(Error::Failed("not a channel name".to_string())),
    }
}

/// The lock file is the listener's alone.
const LOCK_MODE: u32 = 0o600;
/// How long a client waits for a service too busy to take the connection.
const CONNECT_WAIT: Duration = Duration::from_secs(5);

/// Opens the lock file, making it when it is missing.
///
/// Security rule: no other user can open it, or they could hold the lock and
/// keep the service from ever listening. A new file is made closed, and one
/// left open by an earlier run is closed before the lock is tried. A link in
/// its place is refused, not followed.
fn open_lock(path: &Path) -> io::Result<File> {
    let no_follow = OFlags::NOFOLLOW.bits() as i32;
    let mut new = OpenOptions::new();
    new.write(true).create_new(true).mode(LOCK_MODE);
    match new.open(path) {
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let mut existing = OpenOptions::new();
            let lock = existing.read(true).custom_flags(no_follow).open(path)?;
            lock.set_permissions(Permissions::from_mode(LOCK_MODE))?;
            Ok(lock)
        }
        opened => opened,
    }
}

/// How long [`take_back`] keeps trying against an owner who keeps marking the
/// file. One try takes microseconds, and one win is enough.
const TAKE_BACK_WAIT: Duration = Duration::from_secs(1);

/// Makes a socket file this process's own again and then does `act` to it:
/// removes it, or hands it to someone else. Only for the holder of its lock.
///
/// Security rule: the owner a socket was narrowed to cannot stop the service
/// by marking the file unchangeable (macOS, see `clear_flags` there). Clearing
/// the mark is not enough, because the owner can set it again before the next
/// call. So the mark is cleared, the file taken back and `act` tried, again
/// and again while the OS refuses. Once taking it back has worked the file
/// is not the owner's to mark; a mark the owner was already in the middle of
/// setting can still land after that, which is why `act` is inside the loop.
/// An owner who wins every try for [`TAKE_BACK_WAIT`] gets an error reported,
/// not a service that waits for ever.
fn take_back<T>(path: &Path, act: impl Fn() -> io::Result<T>) -> io::Result<T> {
    let me = geteuid().as_raw();
    let deadline = Instant::now() + TAKE_BACK_WAIT;
    loop {
        os::clear_flags(path)?;
        match lchown(path, Some(me), None).and_then(|()| act()) {
            // Only root is refused for a reason that passes. Anyone else is
            // refused for good, and is told so at once.
            Err(error) if me == 0 && refused(&error) && Instant::now() < deadline => {}
            done => return done,
        }
    }
}

fn refused(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::PermissionDenied
}

/// Removes a socket file. Only for the holder of its lock.
fn remove_socket(path: &Path) -> io::Result<()> {
    take_back(path, || fs::remove_file(path))
}

/// Connects, giving up after [`CONNECT_WAIT`]: a service that has stopped
/// accepting would otherwise hold a client for ever.
///
/// The limit is the socket's own send timeout, which a connect obeys. What a
/// full queue does differs: Linux makes the caller wait, so the limit is what
/// ends it, with [`Error::TimedOut`]; macOS refuses at once, which reads as
/// [`Error::NotFound`], the same as nothing listening.
fn connect_within(path: &Path) -> Result<UnixStream> {
    let address = SocketAddrUnix::new(path).map_err(io::Error::from)?;
    let socket = os::socket()?;
    let limit = sockopt::set_socket_timeout(&socket, Timeout::Send, Some(CONNECT_WAIT));
    limit.map_err(io::Error::from)?;
    loop {
        match connect(&socket, &address) {
            Ok(()) => return Ok(UnixStream::from(socket)),
            Err(Errno::INTR) => {}
            Err(Errno::AGAIN) => return Err(Error::TimedOut),
            // A leftover socket file with no listener behind it.
            Err(Errno::CONNREFUSED) => return Err(Error::NotFound),
            Err(error) => return Err(io::Error::from(error).into()),
        }
    }
}

fn set_mode(path: &Path, mode: u32) -> Result<()> {
    Ok(fs::set_permissions(path, Permissions::from_mode(mode))?)
}

impl Transport for SocketTransport {
    fn listen(&self, name: &str) -> Result<Box<dyn Listener>> {
        let (path, folder) = split(name)?;
        let me = geteuid().as_raw();
        let (folder_mode, socket_mode) = modes(self.mode);
        if check_folder(self.mode, folder, me) == Err(Error::NotFound) {
            // The mode is set again because the umask may have narrowed it,
            // and only on a folder this call made.
            match DirBuilder::new().mode(folder_mode).create(folder) {
                Ok(()) => set_mode(folder, folder_mode)?,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        check_folder(self.mode, folder, me)?;

        let mut lock_path = path.as_os_str().to_owned();
        lock_path.push(".lock");
        let claim = open_lock(Path::new(&lock_path))?;
        // Security rule: one listener. A live one holds this lock.
        match claim.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Err(Error::AlreadyExists),
            Err(TryLockError::Error(error)) => return Err(error.into()),
        }
        // Holding the lock, a socket file here belongs to no one.
        match fs::symlink_metadata(path) {
            Ok(stale) if stale.file_type().is_socket() => remove_socket(path)?,
            Ok(_) => return Err(Error::Failed("the channel's path is taken".to_string())),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let socket = UnixListener::bind(path)?;
        let (wake, waker) = UnixStream::pair()?;
        let listener = SocketListener {
            socket,
            wake,
            path: path.to_path_buf(),
            claim: Mutex::new(Some((claim, waker))),
        };
        // Set outright, whatever the umask made of it.
        set_mode(path, socket_mode)?;
        listener.socket.set_nonblocking(true)?;
        Ok(Box::new(listener))
    }

    fn connect(&self, name: &str) -> Result<Connection> {
        let (path, folder) = split(name)?;
        let me = geteuid().as_raw();
        let service = service_user(self.mode, me);
        // Security rule: a socket anyone else could have put there is not
        // the service's.
        match check_folder(self.mode, folder, me) {
            Err(Error::Failed(_)) => return Err(Error::NotTheService),
            checked => checked?,
        }
        let file = fs::symlink_metadata(path)?;
        if !file.file_type().is_socket() {
            return Err(Error::NotTheService);
        }
        // Security rule: the socket is the service's, or was handed to this
        // user by narrowing. Anyone else's is narrowed to them. Root is let
        // through, as the OS itself lets it through.
        if file.uid() != service && file.uid() != me && me != 0 {
            return Err(Error::PermissionDenied);
        }
        let stream = connect_within(path)?;
        // Security rule: whoever answers must be the service itself.
        if os::peer_user(&stream)? != service {
            return Err(Error::NotTheService);
        }
        Ok(Connection::new(Box::new(SocketConnection::new(stream))))
    }
}

struct SocketListener {
    socket: UnixListener,
    /// Becomes readable when the listener closes, to end a waiting `accept`.
    wake: UnixStream,
    path: PathBuf,
    /// The lock file and the other end of `wake`. `None` once closed.
    claim: Mutex<Option<(File, UnixStream)>>,
}

impl SocketListener {
    fn closed(&self) -> bool {
        lock(&self.claim).is_none()
    }
}

impl Listener for SocketListener {
    fn accept(&self) -> Result<(Connection, UserId)> {
        loop {
            let waiting = PollFlags::IN;
            let mut ready = [
                PollFd::new(&self.socket, waiting),
                PollFd::new(&self.wake, waiting),
            ];
            match poll(&mut ready, None) {
                Ok(_) | Err(Errno::INTR) => {}
                Err(error) => return Err(io::Error::from(error).into()),
            }
            if self.closed() {
                return Err(Error::Closed);
            }
            let stream = match self.socket.accept() {
                Ok((stream, _)) => stream,
                Err(error) if GONE.contains(&error.kind()) => continue,
                Err(error) => return Err(error.into()),
            };
            // Security rule: the identity is the kernel's record of who
            // connected, never anything the caller sent. A caller the kernel
            // cannot name, such as one already gone, is dropped without
            // ending the listener.
            let Ok(caller) = os::peer_user(&stream) else {
                continue;
            };
            let connection = SocketConnection::new(stream);
            return Ok((Connection::new(Box::new(connection)), user_id(caller)?));
        }
    }

    fn restrict_to(&self, owner: &UserId) -> Result<()> {
        let text = owner.to_string();
        let user = text.parse::<u32>().ok();
        let user = user.filter(|user| user.to_string() == text);
        // The one value that would mean "leave the owner as it is".
        let user = user.filter(|user| *user != u32::MAX);
        let user = user.ok_or_else(|| Error::Failed("not a user ID".to_string()))?;
        // Held so the path cannot stop being this listener's meanwhile.
        let claim = lock(&self.claim);
        if claim.is_none() {
            return Err(Error::Closed);
        }
        // Taken back from an earlier owner, closed to everyone but root,
        // then handed over.
        let narrow = || {
            fs::set_permissions(&self.path, Permissions::from_mode(0o600))?;
            chown(&self.path, Some(user), None)
        };
        Ok(take_back(&self.path, narrow)?)
    }

    fn close(&self) {
        // Removed while the lock is still held, so it is ours to remove.
        // Dropping the claim then frees the name and wakes `accept`. There
        // is nobody to tell if removing fails: the next `listen` removes the
        // leftover the same way, and reports a failure.
        if let Some(_claim) = lock(&self.claim).take() {
            let _ = remove_socket(&self.path);
        }
    }
}

impl Drop for SocketListener {
    fn drop(&mut self) {
        self.close();
    }
}

/// What `accept` reports when there is no caller after all: another thread
/// took it, a signal arrived, or the caller left.
const GONE: [io::ErrorKind; 3] = [
    io::ErrorKind::WouldBlock,
    io::ErrorKind::Interrupted,
    io::ErrorKind::ConnectionAborted,
];

fn user_id(user: u32) -> Result<UserId> {
    user.to_string().parse()
}

/// No single wait is longer than this; a longer timeout is waited in parts.
const LONGEST_WAIT: Duration = Duration::from_secs(3600);

struct SocketConnection {
    stream: UnixStream,
    read_timeout: Mutex<Option<Duration>>,
    write_timeout: Mutex<Option<Duration>>,
    closed: AtomicBool,
}

impl SocketConnection {
    fn new(stream: UnixStream) -> Self {
        Self {
            stream,
            read_timeout: Mutex::default(),
            write_timeout: Mutex::default(),
            closed: AtomicBool::new(false),
        }
    }

    /// Waits until the socket can take a read or a write, as `wanted` says,
    /// or the peer is gone. Fails with [`Error::TimedOut`] at `deadline`.
    ///
    /// Timeouts are waited for here and never set on the socket: macOS
    /// refuses to change a socket whose peer has gone. The reads and writes
    /// themselves never wait.
    fn wait(&self, wanted: PollFlags, deadline: Option<Instant>) -> Result<()> {
        loop {
            if self.closed.load(Ordering::SeqCst) {
                return Err(Error::Closed);
            }
            let left = deadline.map(|at| at.saturating_duration_since(Instant::now()));
            if left.is_some_and(|left| left.is_zero()) {
                return Err(Error::TimedOut);
            }
            let part = left.map(|left| Timespec::try_from(left.min(LONGEST_WAIT)));
            let part = part.transpose().map_err(|_| Error::TimedOut)?;
            let mut ready = [PollFd::new(&self.stream, wanted)];
            match poll(&mut ready, part.as_ref()) {
                Ok(0) | Err(Errno::INTR) => {}
                Ok(_) => return Ok(()),
                Err(error) => return Err(io::Error::from(error).into()),
            }
        }
    }
}

fn deadline(timeout: &Mutex<Option<Duration>>) -> Option<Instant> {
    lock(timeout).map(|timeout| Instant::now() + timeout)
}

impl RawConnection for SocketConnection {
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let deadline = deadline(&self.read_timeout);
        loop {
            self.wait(PollFlags::IN, deadline)?;
            match recv(&self.stream, &mut *buf, RecvFlags::DONTWAIT) {
                Ok((read, _)) => return Ok(read),
                Err(Errno::INTR | Errno::AGAIN) => {}
                Err(error) => return Err(io::Error::from(error).into()),
            }
        }
    }

    fn write_all(&self, mut bytes: &[u8]) -> Result<()> {
        let deadline = deadline(&self.write_timeout);
        while !bytes.is_empty() {
            self.wait(PollFlags::OUT, deadline)?;
            match os::send(&self.stream, bytes) {
                Ok(sent) => bytes = &bytes[sent..],
                Err(Errno::INTR | Errno::AGAIN) => {}
                Err(error) => return Err(io::Error::from(error).into()),
            }
        }
        Ok(())
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        *lock(&self.read_timeout) = timeout;
        Ok(())
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        *lock(&self.write_timeout) = timeout;
        Ok(())
    }

    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        // Ends a read or write waiting on another thread and tells the peer.
        // The descriptor itself stays until drop, so no thread can find
        // itself using a number the OS has given to something else.
        let _ = self.stream.shutdown(Shutdown::Both);
    }
}
