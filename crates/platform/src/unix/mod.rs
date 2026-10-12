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
//!   `listen` and `connect` refuse a folder that breaks the rule.
//! - **The caller is who the kernel says**: the peer's effective user ID,
//!   recorded by the kernel when the connection was made.
//! - **Narrowing** hands the socket file to the owner with mode 0600. The
//!   kernel checks that when a client connects, so it only affects later
//!   connections.
//! - **A client checks the server**: the folder rule above, a socket file
//!   that belongs to the service or to the caller, and a peer that is the
//!   service (root when installed, the current user in dev mode). The peer
//!   check is the one that cannot be raced: it describes the very socket the
//!   client is connected to.

#[cfg(test)]
mod tests;

use std::ffi::OsString;
use std::fs::{self, DirBuilder, File, OpenOptions, Permissions, TryLockError};
use std::io::{self, Read};
use std::net::Shutdown;
use std::os::unix::fs::{
    DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt, chown,
};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, poll};
use rustix::io::Errno;
use rustix::process::geteuid;

use crate::unsupported::Native;
use crate::{
    Connection, Error, Listener, Mode, Paths, Platform, RawConnection, Result, Transport, UserId,
    lock, os,
};

/// What `listen` and `connect` report for a folder that breaks the rule.
pub(crate) const NOT_A_FOLDER: &str = "the channel's folder is a link or not a folder";
pub(crate) const WRONG_OWNER: &str = "the channel's folder belongs to the wrong user";
pub(crate) const TOO_OPEN: &str = "the channel's folder can be changed by other users";
/// What a client reports when the socket is held by something else.
pub(crate) const NOT_THE_SERVICE: &str = "the channel is held by a program that is not the service";

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

/// The dev-mode socket: in the per-user folder `variable` names, or in `/tmp`
/// when it is unset or relative. The user ID in the folder's name keeps two
/// users apart there, and `listen` refuses a folder someone else made.
#[cfg(feature = "dev-mode")]
pub(crate) fn dev_channel(env: Env<'_>, variable: &str) -> String {
    let base = env(variable).map(PathBuf::from);
    let base = base.filter(|base| base.is_absolute());
    let folder = format!("ubc-vpn-dev-{}", geteuid().as_raw());
    let socket = base.unwrap_or_else(|| PathBuf::from("/tmp")).join(folder);
    socket.join("service.sock").to_string_lossy().into_owned()
}

/// Refuses dev-mode folders inside the installed product's, wherever the
/// environment pointed.
#[cfg(feature = "dev-mode")]
pub(crate) fn dev_folders(dev: &Path, installed: &[&str]) -> Result<Paths> {
    if installed.iter().any(|system| dev.starts_with(system)) {
        let message = "dev mode cannot live in the installed product's folders";
        return Err(Error::Failed(message.to_string()));
    }
    Ok(Paths {
        policy_dir: dev.join("policy"),
        state_dir: dev.join("state"),
        settings_dir: dev.join("settings"),
        channel_name: String::new(),
    })
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

/// A channel name is the socket's absolute path.
fn split(name: &str) -> Result<(&Path, &Path)> {
    let path = Path::new(name);
    match path.parent() {
        Some(folder) if path.is_absolute() && path.file_name().is_some() => Ok((path, folder)),
        _ => Err(Error::Failed(
            "a channel name must be an absolute path".to_string(),
        )),
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
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(false).mode(0o600);
        let claim = options.open(lock_path)?;
        // Security rule: one listener. A live one holds this lock.
        match claim.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Err(Error::AlreadyExists),
            Err(TryLockError::Error(error)) => return Err(error.into()),
        }
        // Holding the lock, a socket file here belongs to no one.
        match fs::symlink_metadata(path) {
            Ok(stale) if stale.file_type().is_socket() => fs::remove_file(path)?,
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
        check_folder(self.mode, folder, me)?;
        let file = fs::symlink_metadata(path)?;
        if !file.file_type().is_socket() {
            return Err(Error::Failed(NOT_THE_SERVICE.to_string()));
        }
        // Security rule: the socket is the service's, or was handed to this
        // user by narrowing. Anyone else's is narrowed to them.
        if file.uid() != service && file.uid() != me {
            return Err(Error::PermissionDenied);
        }
        let stream = match UnixStream::connect(path) {
            // A leftover socket file with no listener behind it.
            Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                return Err(Error::NotFound);
            }
            connected => connected?,
        };
        // Security rule: whoever answers must be the service itself.
        if os::peer_user(&stream)? != service {
            return Err(Error::Failed(NOT_THE_SERVICE.to_string()));
        }
        Ok(Connection::new(Box::new(SocketConnection::new(stream)?)))
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
            // A caller that fails from here on, such as one already gone, is
            // dropped without ending the listener.
            // Security rule: the identity is the kernel's record of who
            // connected, never anything the caller sent.
            let Ok(caller) = os::peer_user(&stream) else {
                continue;
            };
            let unblocked = stream.set_nonblocking(false);
            let Ok(connection) = unblocked.and_then(|()| SocketConnection::new(stream)) else {
                continue;
            };
            return Ok((Connection::new(Box::new(connection)), user_id(caller)?));
        }
    }

    fn restrict_to(&self, owner: &UserId) -> Result<()> {
        let text = owner.to_string();
        let user = text.parse::<u32>().ok();
        let user = user.filter(|user| user.to_string() == text);
        let user = user.ok_or_else(|| Error::Failed("not a user ID".to_string()))?;
        // Held so the path cannot stop being this listener's meanwhile.
        let claim = lock(&self.claim);
        if claim.is_none() {
            return Err(Error::Closed);
        }
        // Closed to everyone but root first, then handed over.
        set_mode(&self.path, 0o600)?;
        Ok(chown(&self.path, Some(user), None)?)
    }

    fn close(&self) {
        // Removed while the lock is still held, so it is ours to remove.
        // Dropping the claim then frees the name and wakes `accept`.
        if let Some(_claim) = lock(&self.claim).take() {
            let _ = fs::remove_file(&self.path);
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

struct SocketConnection {
    stream: UnixStream,
    write_timeout: Mutex<Option<Duration>>,
    closed: AtomicBool,
}

impl SocketConnection {
    fn new(stream: UnixStream) -> io::Result<Self> {
        os::no_sigpipe(&stream)?;
        Ok(Self {
            stream,
            write_timeout: Mutex::default(),
            closed: AtomicBool::new(false),
        })
    }

    fn check_open(&self) -> Result<()> {
        match self.closed.load(Ordering::SeqCst) {
            true => Err(Error::Closed),
            false => Ok(()),
        }
    }
}

impl RawConnection for SocketConnection {
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        loop {
            self.check_open()?;
            match (&self.stream).read(buf) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                read => return Ok(read?),
            }
        }
    }

    fn write_all(&self, mut bytes: &[u8]) -> Result<()> {
        let timeout = *lock(&self.write_timeout);
        let deadline = timeout.map(|timeout| Instant::now() + timeout);
        while !bytes.is_empty() {
            self.check_open()?;
            let left = deadline.map(|at| at.saturating_duration_since(Instant::now()));
            if left.is_some_and(|left| left.is_zero()) {
                return Err(Error::TimedOut);
            }
            self.stream.set_write_timeout(left)?;
            match os::send(&self.stream, bytes) {
                Ok(sent) => bytes = &bytes[sent..],
                Err(Errno::INTR) => {}
                Err(error) => return Err(io::Error::from(error).into()),
            }
        }
        Ok(())
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        Ok(self.stream.set_read_timeout(timeout)?)
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
