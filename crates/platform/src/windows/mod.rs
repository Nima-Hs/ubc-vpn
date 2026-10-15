//! Windows: the channel is a named pipe, and the well-known folders come from
//! the shell's known-folder API. Routes, DNS and network events are not
//! implemented yet and report that they are unsupported.
//!
//! How the pipe keeps the channel's promises:
//!
//! - **One listener.** The first instance is created with
//!   `FILE_FLAG_FIRST_PIPE_INSTANCE`, and the access list lets nobody but the
//!   service create another. The listener always holds one free instance, so
//!   the name never becomes free while it is open.
//! - **Local callers only**: every instance has `PIPE_REJECT_REMOTE_CLIENTS`.
//! - **The caller is who Windows says**: the token of the pipe's client.
//! - **Narrowing** replaces the access list of the pipe. A pipe has one
//!   descriptor, shared by all its instances; Windows 11 was seen to ignore
//!   the one passed when a later instance is created, and it is passed all
//!   the same in case another version does not. Windows checks the list when
//!   a client opens the pipe, so a client that already opened it stays
//!   attached, and one still waiting for a free instance is refused.
//! - **Callers must open the pipe as [`Transport::connect`] does.** One that
//!   asks for generic write access is refused, because that includes rights
//!   to write attributes which the access list does not grant; one that does
//!   not state how far the server may impersonate it cannot be identified
//!   before it has sent data, and is dropped.
//! - **A client checks the server** by the pipe's owner, and lends it no more
//!   than its name (identification-level impersonation).
//!
//! One difference from a socket: a pipe's name stays taken while any instance
//! is open, so closing the listener also closes the connections it accepted.

pub(crate) mod interrupt;
mod journal;
mod pipe;
mod routes;
#[cfg(test)]
mod routes_tests;
mod security;
pub(crate) mod state;
pub(crate) mod terminal;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod wintun;

use std::path::PathBuf;
use std::ptr::{null, null_mut};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    ERROR_NO_DATA, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, OPEN_EXISTING,
    PIPE_ACCESS_DUPLEX, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT, WRITE_DAC,
};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
    PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT, WaitNamedPipeW,
};
use windows_sys::Win32::UI::Shell::{
    FOLDERID_ProgramData, FOLDERID_RoamingAppData, KF_FLAG_DONT_VERIFY, SHGetKnownFolderPath,
};
use windows_sys::core::GUID;

use self::pipe::{End, Pipe, Stop};
use self::security::{Descriptor, Handle, last_error, os_error, wide};
use crate::unsupported::Native;
use crate::{Connection, Error, Listener, Mode, Paths, Platform, Result, Transport, UserId, lock};

/// The installed service's pipe. A dev-mode pipe has the user's SID appended,
/// so it can never be this one, nor another user's.
const INSTALLED_PIPE: &str = "ubc-vpn";
const FOLDER: &str = "UBC VPN";

/// What every instance is created with, besides the first-instance flag.
const OPEN_MODE: u32 = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | WRITE_DAC;
const PIPE_MODE: u32 = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;
/// How a client opens the pipe: overlapped, and letting the server learn who
/// is calling but not act as them.
const CLIENT_FLAGS: u32 = FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION;
/// Room for one line of the longest length in each direction.
const BUFFER_BYTES: u32 = 64 * 1024;
/// How long a client waits for a free instance when the service is busy.
const BUSY_WAIT: Duration = Duration::from_secs(5);

pub(crate) fn native(mode: Mode) -> Result<Platform> {
    let me = security::process_user()?;
    let paths = paths(mode, &me)?;
    Ok(Platform {
        routes: Arc::new(routes::WinRoutes::new(mode, &paths)),
        dns: Arc::new(Native),
        events: Arc::new(Native),
        paths,
        transport: Arc::new(PipeTransport { mode, me }),
    })
}

/// A folder as Windows itself locates it. For the machine-wide folders the
/// service relies on, that does not involve environment variables, which
/// whoever starts a process chooses. A per-user folder is the caller's own.
///
/// With `must_exist` the lookup fails for a folder that is not there. Without
/// it the path is given all the same, and nothing is created.
fn known_folder(id: &GUID, must_exist: bool) -> Result<PathBuf> {
    let flags = if must_exist {
        0
    } else {
        KF_FLAG_DONT_VERIFY as u32
    };
    let mut path = null_mut();
    // SAFETY: `id` is a valid GUID, a null token means the current user, and
    // the out pointer is valid.
    let status = unsafe { SHGetKnownFolderPath(id, flags, null_mut(), &mut path) };
    let found = (status >= 0).then(|| {
        // SAFETY: on success `path` is a NUL-terminated string, so every
        // offset up to and including the NUL is readable.
        let len = (0..).find(|at| unsafe { *path.add(*at) } == 0).unwrap_or(0);
        // SAFETY: those `len` code units were just read.
        PathBuf::from(String::from_utf16_lossy(unsafe {
            std::slice::from_raw_parts(path, len)
        }))
    });
    // SAFETY: the API allocates `path` for the caller to free this way, also
    // when it fails; null is accepted.
    unsafe { CoTaskMemFree(path.cast()) };
    found.ok_or_else(|| Error::Failed(format!("known folder lookup failed: {status:#x}")))
}

fn paths(mode: Mode, me: &str) -> Result<Paths> {
    match mode {
        Mode::Installed => {
            let _ = me;
            // The machine-wide folder must be there: an installed service
            // that cannot find it should fail. The user's roaming folder
            // need not be: a new profile may not have one yet, and whoever
            // saves settings creates it.
            let machine = known_folder(&FOLDERID_ProgramData, true)?.join(FOLDER);
            let roaming = known_folder(&FOLDERID_RoamingAppData, false)?;
            Ok(Paths {
                policy_dir: machine.clone(),
                state_dir: machine,
                settings_dir: roaming.join(FOLDER),
                channel_name: INSTALLED_PIPE.to_string(),
            })
        }
        #[cfg(feature = "dev-mode")]
        Mode::Dev => {
            let root = known_folder(&windows_sys::Win32::UI::Shell::FOLDERID_LocalAppData, true)?
                .join(format!("{FOLDER} Dev"));
            Ok(Paths {
                policy_dir: root.join("policy"),
                state_dir: root.join("state"),
                settings_dir: root.join("settings"),
                channel_name: format!("{INSTALLED_PIPE}-dev-{me}"),
            })
        }
    }
}

/// The full pipe path for a channel name, which must be a plain name.
fn pipe_path(name: &str) -> Result<Vec<u16>> {
    let plain = |c: char| c.is_ascii_graphic() && c != '\\' && c != '/';
    if name.is_empty() || name.len() > 200 || !name.chars().all(plain) {
        return Err(Error::Failed("not a channel name".to_string()));
    }
    Ok(wide(&format!(r"\\.\pipe\{name}")))
}

/// Creates one instance of the service's pipe, protected by `sddl`.
fn create_instance(path: &[u16], sddl: &str, first: bool) -> Result<Pipe> {
    let descriptor = Descriptor::parse(sddl)?;
    let open_mode = OPEN_MODE
        | if first {
            FILE_FLAG_FIRST_PIPE_INSTANCE
        } else {
            0
        };
    let created = create_pipe(path, &descriptor, open_mode, PIPE_MODE);
    Pipe::new(created.map_err(|code| match code {
        // How Windows refuses a first instance of a name that exists.
        5 if first => Error::AlreadyExists,
        code => os_error(code),
    })?)
}

/// Creates a pipe instance, or reports the Windows error code.
fn create_pipe(
    path: &[u16],
    descriptor: &Descriptor,
    open_mode: u32,
    pipe_mode: u32,
) -> std::result::Result<Handle, u32> {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.as_ptr(),
        bInheritHandle: 0,
    };
    // SAFETY: `path` is NUL-terminated, and it and `attributes`, with the
    // descriptor it points to, outlive the call.
    let handle = unsafe {
        CreateNamedPipeW(
            path.as_ptr(),
            open_mode,
            pipe_mode,
            PIPE_UNLIMITED_INSTANCES,
            BUFFER_BYTES,
            BUFFER_BYTES,
            0,
            &attributes,
        )
    };
    match handle {
        INVALID_HANDLE_VALUE => Err(last_error()),
        handle => Ok(Handle(handle)),
    }
}

struct PipeTransport {
    mode: Mode,
    /// The user this process runs as.
    me: String,
}

impl PipeTransport {
    fn listener(&self, name: &str) -> Result<PipeListener> {
        let path = pipe_path(name)?;
        let sddl = security::sddl(self.mode, &self.me, None)?;
        let first = create_instance(&path, &sddl, true)?;
        Ok(PipeListener {
            path,
            mode: self.mode,
            me: self.me.clone(),
            sddl: Mutex::new(sddl),
            free: Mutex::new(Some(Arc::new(first))),
            accepting: Mutex::default(),
            accepted: Mutex::default(),
        })
    }
}

impl Transport for PipeTransport {
    fn listen(&self, name: &str) -> Result<Box<dyn Listener>> {
        Ok(Box::new(self.listener(name)?))
    }

    /// The server is checked by the pipe's owner, read through the handle
    /// just opened, so the answer is about the very pipe that would receive
    /// what the caller sends. See [`security::is_the_service`].
    fn connect(&self, name: &str) -> Result<Connection> {
        let path = pipe_path(name)?;
        // Read and write data, and read the owner: exactly what the access
        // list grants a caller. Generic write would be refused, because it
        // also asks for the rights to write attributes.
        let access = security::CONNECT_RIGHTS;
        let deadline = Instant::now() + BUSY_WAIT;
        let handle = loop {
            // SAFETY: `path` is NUL-terminated and outlives the call; the
            // optional pointers are null.
            let handle = unsafe {
                CreateFileW(
                    path.as_ptr(),
                    access,
                    0,
                    null(),
                    OPEN_EXISTING,
                    CLIENT_FLAGS,
                    null_mut(),
                )
            };
            if handle != INVALID_HANDLE_VALUE {
                break Handle(handle);
            }
            let left = deadline.saturating_duration_since(Instant::now());
            match last_error() {
                ERROR_PIPE_BUSY if left.is_zero() => return Err(Error::TimedOut),
                // SAFETY: `path` is NUL-terminated and outlives the call.
                ERROR_PIPE_BUSY => unsafe {
                    WaitNamedPipeW(path.as_ptr(), left.as_millis().max(1) as u32);
                },
                code => return Err(os_error(code)),
            }
        };
        let owner = security::owner_of(handle.0)?;
        if !security::is_the_service(self.mode, &self.me, &owner) {
            return Err(Error::NotTheService);
        }
        Ok(Connection::new(Box::new(End(Arc::new(Pipe::new(handle)?)))))
    }
}

struct PipeListener {
    path: Vec<u16>,
    mode: Mode,
    me: String,
    /// The descriptor for instances created from now on. Held while one is
    /// created and while the pipe is narrowed, so neither overtakes the other.
    sddl: Mutex<String>,
    /// The instance the next caller connects to. `None` once closed.
    free: Mutex<Option<Arc<Pipe>>>,
    /// Held for the length of an `accept`.
    accepting: Mutex<()>,
    accepted: Mutex<Vec<Weak<Pipe>>>,
}

impl Listener for PipeListener {
    fn accept(&self) -> Result<(Connection, UserId)> {
        let _accepting = lock(&self.accepting);
        loop {
            let pipe = lock(&self.free).clone().ok_or(Error::Closed)?;
            let connected = pipe.io(&pipe.reading, None, |handle, overlapped| {
                // SAFETY: the handle is an open server end, and `overlapped`
                // stays alive until `io` has seen the operation end.
                unsafe { ConnectNamedPipe(handle, overlapped) }
            });
            match connected {
                // A caller arrived; it may have been there already, and may
                // have left again.
                Ok(_) | Err(Stop::Os(ERROR_PIPE_CONNECTED | ERROR_NO_DATA)) => {}
                Err(stop) => return Err(stop.into()),
            }
            // Put a fresh instance in its place before anything else, so the
            // name stays held and the next caller has somewhere to go. If
            // that fails, this one stays and the next accept finds it.
            {
                let sddl = lock(&self.sddl);
                let mut free = lock(&self.free);
                if free.is_none() {
                    return Err(Error::Closed);
                }
                *free = Some(Arc::new(create_instance(&self.path, &sddl, false)?));
            }
            // A caller whose identity Windows will not give (it left, or it
            // opened the pipe anonymously) is dropped; the wait goes on.
            if let Ok(Ok(caller)) = pipe.with_handle(security::pipe_client) {
                let mut accepted = lock(&self.accepted);
                accepted.retain(|pipe| pipe.strong_count() > 0);
                accepted.push(Arc::downgrade(&pipe));
                return Ok((Connection::new(Box::new(End(pipe))), caller));
            }
        }
    }

    fn restrict_to(&self, owner: &UserId) -> Result<()> {
        let mut sddl = lock(&self.sddl);
        let narrowed = security::sddl(self.mode, &self.me, Some(owner))?;
        let free = lock(&self.free).clone().ok_or(Error::Closed)?;
        free.with_handle(|handle| security::set_access(handle, &narrowed))??;
        *sddl = narrowed;
        Ok(())
    }

    /// Also closes every connection this listener accepted. Windows keeps a
    /// pipe's name taken while any instance of it is open, and each accepted
    /// connection is one, so the name could not be released otherwise: a new
    /// listener would be refused until the last old client had gone.
    fn close(&self) {
        if let Some(free) = lock(&self.free).take() {
            free.shut_down();
        }
        // An accept in progress was just woken and finds no free instance;
        // wait for it, so no instance is left when this returns.
        let _accepting = lock(&self.accepting);
        for pipe in lock(&self.accepted)
            .drain(..)
            .filter_map(|pipe| pipe.upgrade())
        {
            pipe.shut_down();
        }
    }
}

impl Drop for PipeListener {
    fn drop(&mut self) {
        self.close();
    }
}
