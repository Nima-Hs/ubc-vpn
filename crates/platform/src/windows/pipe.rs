//! One end of a named pipe, with overlapped I/O: every wait can be ended by a
//! timeout or by `close` on another thread, and a read never holds up a write.

use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Threading::{
    CreateEventW, INFINITE, SetEvent, WaitForMultipleObjects,
};
use windows_sys::core::BOOL;

use super::security::{Handle, last_error, os_error};
use crate::{Error, RawConnection, Result, lock};

const ERROR_IO_PENDING: u32 = 997;

/// Why an overlapped operation did not complete.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Stop {
    Closed,
    TimedOut,
    Os(u32),
}

impl From<Stop> for Error {
    fn from(stop: Stop) -> Self {
        match stop {
            Stop::Closed => Self::Closed,
            Stop::TimedOut => Self::TimedOut,
            Stop::Os(code) => os_error(code),
        }
    }
}

/// A manual-reset event, not signalled.
fn event() -> Result<Handle> {
    // SAFETY: all four arguments are plain values or null, which the API
    // accepts: default security, manual reset, not signalled, no name.
    let handle = unsafe { CreateEventW(null(), 1, 0, null()) };
    match handle.is_null() {
        true => Err(os_error(last_error())),
        false => Ok(Handle(handle)),
    }
}

/// A wait in milliseconds: never zero, and never the value meaning for ever.
fn millis(timeout: Option<Duration>) -> u32 {
    let Some(timeout) = timeout else {
        return INFINITE;
    };
    let whole = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);
    whole.clamp(1, INFINITE - 1)
}

pub(super) struct Pipe {
    /// `None` once closed. Every operation holds the read side while it uses
    /// the handle, so `close` can only close it when nobody does.
    handle: RwLock<Option<Handle>>,
    /// Signalled by `close`; every wait also waits on this.
    shut: Handle,
    closed: AtomicBool,
    /// The completion event for each direction. Holding the lock is what
    /// keeps a direction to one operation at a time.
    pub(super) reading: Mutex<Handle>,
    writing: Mutex<Handle>,
    read_timeout: Mutex<Option<Duration>>,
    write_timeout: Mutex<Option<Duration>>,
}

impl Pipe {
    /// Takes ownership of an open pipe handle that was opened for overlapped
    /// I/O.
    pub(super) fn new(handle: Handle) -> Result<Self> {
        Ok(Self {
            handle: RwLock::new(Some(handle)),
            shut: event()?,
            closed: AtomicBool::new(false),
            reading: Mutex::new(event()?),
            writing: Mutex::new(event()?),
            read_timeout: Mutex::default(),
            write_timeout: Mutex::default(),
        })
    }

    /// Runs `call` with the handle, which stays open for as long as it runs.
    pub(super) fn with_handle<T>(&self, call: impl FnOnce(HANDLE) -> T) -> Result<T> {
        let handle = self.handle.read().unwrap_or_else(PoisonError::into_inner);
        let handle = handle.as_ref().ok_or(Error::Closed)?;
        Ok(call(handle.0))
    }

    /// Starts one overlapped operation and stays until it has ended: by
    /// completing, or cancelled because `timeout` passed or the pipe was
    /// closed. Returns the bytes transferred, which may be non-zero even when
    /// the wait was cut short, so nothing that arrived is lost.
    pub(super) fn io(
        &self,
        direction: &Mutex<Handle>,
        timeout: Option<Duration>,
        start: impl FnOnce(HANDLE, *mut OVERLAPPED) -> BOOL,
    ) -> std::result::Result<u32, Stop> {
        let done = lock(direction);
        let handle = self.handle.read().unwrap_or_else(PoisonError::into_inner);
        let handle = match handle.as_ref() {
            Some(handle) if !self.closed.load(Ordering::SeqCst) => handle.0,
            _ => return Err(Stop::Closed),
        };
        // SAFETY: OVERLAPPED is plain data for which all zeroes is valid.
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        overlapped.hEvent = done.0;
        if start(handle, &mut overlapped) == 0 {
            let code = last_error();
            if code != ERROR_IO_PENDING {
                return Err(Stop::Os(code));
            }
        }
        let events = [done.0, self.shut.0];
        // SAFETY: both handles are open events owned by `self` and the guard.
        let woke = unsafe { WaitForMultipleObjects(2, events.as_ptr(), 0, millis(timeout)) };
        let stop = match woke {
            WAIT_OBJECT_0 => None,
            WAIT_TIMEOUT => Some(Stop::TimedOut),
            _ => Some(Stop::Closed),
        };
        if stop.is_some() {
            // SAFETY: the handle is open and `overlapped` is the operation
            // started on it above. Failure means it had already completed.
            unsafe { CancelIoEx(handle, &overlapped) };
        }
        let mut transferred = 0;
        // SAFETY: as above. Waiting (the last argument) is what makes it safe
        // to return: the kernel no longer uses `overlapped`, nor the buffer
        // the operation was given, once this call is back.
        let ok = unsafe { GetOverlappedResult(handle, &overlapped, &mut transferred, 1) };
        match (ok, stop) {
            (0, None) => Err(Stop::Os(last_error())),
            (0, Some(stop)) => Err(stop),
            _ => Ok(transferred),
        }
    }

    pub(super) fn shut_down(&self) {
        self.closed.store(true, Ordering::SeqCst);
        // SAFETY: the event is open for as long as `self` is.
        unsafe { SetEvent(self.shut.0) };
        // Every operation was just woken, so this wait is short. Closing the
        // handle is what tells the peer; bytes already sent stay readable.
        *self.handle.write().unwrap_or_else(PoisonError::into_inner) = None;
    }
}

/// A connection's end of a pipe. The listener keeps a weak reference to the
/// same pipe so it can close it.
pub(super) struct End(pub(super) std::sync::Arc<Pipe>);

impl RawConnection for End {
    /// `Ok(0)` also covers a peer that wrote zero bytes: retrying would let
    /// it stretch the timeout, so it is treated as having closed.
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let pipe = &*self.0;
        let (at, len) = (
            buf.as_mut_ptr(),
            u32::try_from(buf.len()).unwrap_or(u32::MAX),
        );
        let read = pipe.io(
            &pipe.reading,
            *lock(&pipe.read_timeout),
            |handle, overlapped| {
                // SAFETY: `buf` is writable for `len` bytes and, like
                // `overlapped`, stays alive until `io` has seen the operation end.
                unsafe { ReadFile(handle, at, len, null_mut(), overlapped) }
            },
        );
        match read {
            Ok(n) => Ok(n as usize),
            // The peer closed its end.
            Err(Stop::Os(109 | 233)) => Ok(0),
            Err(stop) => Err(stop.into()),
        }
    }

    fn write_all(&self, mut bytes: &[u8]) -> Result<()> {
        let pipe = &*self.0;
        let deadline = lock(&pipe.write_timeout).map(|timeout| Instant::now() + timeout);
        while !bytes.is_empty() {
            let left = deadline.map(|at| at.saturating_duration_since(Instant::now()));
            if left.is_some_and(|left| left.is_zero()) {
                return Err(Error::TimedOut);
            }
            let (at, len) = (
                bytes.as_ptr(),
                u32::try_from(bytes.len()).unwrap_or(u32::MAX),
            );
            let sent = pipe.io(&pipe.writing, left, |handle, overlapped| {
                // SAFETY: `bytes` is readable for `len` bytes and, like
                // `overlapped`, stays alive until `io` has seen the operation
                // end.
                unsafe { WriteFile(handle, at, len, null_mut(), overlapped) }
            })?;
            bytes = &bytes[sent as usize..];
        }
        Ok(())
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        *lock(&self.0.read_timeout) = timeout;
        Ok(())
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        *lock(&self.0.write_timeout) = timeout;
        Ok(())
    }

    fn close(&self) {
        self.0.shut_down();
    }
}
