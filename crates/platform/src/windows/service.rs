//! Running under Windows' service manager.
//!
//! The installed service is started by the service manager, not from a
//! console. Windows then expects it to connect within 30 seconds, report
//! when it is running, and answer requests to stop; one that does not is
//! ended and reported as failed to start. [`run`] does that for one service
//! in this process:
//!
//! 1. It hands the calling thread to the service manager. A program that was
//!    not started by the service manager gets an error at once.
//! 2. On the service manager's thread, it reports "starting" and calls the
//!    body with a [`Control`] and a receiver of stop requests.
//! 3. The body starts the service, calls [`Control::running`], and waits for
//!    a request on the receiver. A request comes when someone stops the
//!    service and when Windows shuts down; it is sent once.
//! 4. When the body returns, [`run`] reports "stopped": with no error if the
//!    body returned `Ok`, and as a failure if it returned `Err` or panicked.
//!    Then [`run`] returns the body's result.
//!
//! A stop request is reported to Windows as "stopping" at once, and the body
//! takes as long as its cleanup needs. Until it returns, "stopping" is
//! reported again every second with a rising checkpoint, so Windows sees
//! progress and does not take a long cleanup for a hung service. "Stopped"
//! is reported only after the body has returned. Accepting the pre-shutdown request
//! makes Windows wait for that cleanup before it shuts down, up to its own
//! limit.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr::{null, null_mut};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    ERROR_CALL_NOT_IMPLEMENTED, ERROR_FAILED_SERVICE_CONTROLLER_CONNECT,
    ERROR_SERVICE_SPECIFIC_ERROR, NO_ERROR,
};
use windows_sys::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SERVICE_ACCEPT_PRESHUTDOWN, SERVICE_ACCEPT_SHUTDOWN,
    SERVICE_ACCEPT_STOP, SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_PRESHUTDOWN,
    SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_RUNNING, SERVICE_START_PENDING,
    SERVICE_STATUS, SERVICE_STATUS_CURRENT_STATE, SERVICE_STATUS_HANDLE, SERVICE_STOP_PENDING,
    SERVICE_STOPPED, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS, SetServiceStatus,
    StartServiceCtrlDispatcherW,
};
use windows_sys::core::PWSTR;

use super::security::{last_error, os_error, wide};
use crate::{Error, Result, lock};

/// What the service does once the service manager has started it.
type Body = Box<dyn FnOnce(&Control, Receiver<()>) -> std::result::Result<(), String> + Send>;

/// How long Windows is told to allow before it hears from the service again,
/// while it starts and while it stops.
const WAIT_HINT_MS: u32 = 30_000;

/// How often "stopping" is reported again while the body cleans up.
const PROGRESS: Duration = Duration::from_secs(1);

/// The service code's exit code, reported with `ERROR_SERVICE_SPECIFIC_ERROR`
/// when the body fails. Its reason is in the body's own result.
const FAILED: u32 = 1;

/// The body, from [`run`] until the service manager calls [`service_main`].
static BODY: Mutex<Option<Body>> = Mutex::new(None);
/// The body's result, from [`service_main`] back to [`run`].
static OUTCOME: Mutex<Option<std::result::Result<(), String>>> = Mutex::new(None);
/// Where the control handler reports and sends a stop request.
static HANDLER: Mutex<Option<Handler>> = Mutex::new(None);

struct Handler {
    status: Arc<Status>,
    /// Taken by the first stop request, so the body hears of it once.
    stop: Option<Sender<()>>,
}

/// Runs this process as the service the service manager started, and
/// returns the body's result once it has reported the service stopped.
///
/// It fails at once, without calling the body, if the program was not
/// started by the service manager, or if another thread of this process is
/// already in here.
pub fn run(
    body: impl FnOnce(&Control, Receiver<()>) -> std::result::Result<(), String> + Send + 'static,
) -> Result<std::result::Result<(), String>> {
    {
        let mut slot = lock(&BODY);
        if slot.is_some() {
            return Err(Error::Failed(
                "the service is already being run".to_string(),
            ));
        }
        *slot = Some(Box::new(body));
    }
    // A service that runs in a process of its own may give any name here.
    let mut name = wide("");
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_mut_ptr(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: null_mut(),
            lpServiceProc: None,
        },
    ];
    // SAFETY: the table ends with the null entry, and it and the name it
    // points to outlive the call, which returns only once the service has
    // stopped.
    let connected = unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) };
    lock(&BODY).take();
    if connected == 0 {
        return Err(match last_error() {
            ERROR_FAILED_SERVICE_CONTROLLER_CONNECT => Error::Failed(
                "this program runs as a Windows service, started by the service manager"
                    .to_string(),
            ),
            code => os_error(code),
        });
    }
    lock(&OUTCOME)
        .take()
        .ok_or_else(|| Error::Failed("the service manager never started the service".to_string()))
}

/// What the body can tell the service manager.
pub struct Control {
    status: Arc<Status>,
    name: String,
}

impl Control {
    /// The name the service is registered under.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Tells the service manager the service is running and takes stop
    /// requests. Until then it is "starting", and Windows gives up on it
    /// after about 30 seconds without news.
    pub fn running(&self) -> Result<()> {
        let accepts = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_PRESHUTDOWN;
        self.status.report(SERVICE_RUNNING, accepts, NO_ERROR, 0)
    }
}

/// Reports the service's state. One per service, shared by the body's
/// thread, the control handler's and the thread that reports progress
/// while stopping.
struct Status {
    handle: SERVICE_STATUS_HANDLE,
    reported: Mutex<Reported>,
}

/// What has been reported so far.
#[derive(Default)]
struct Reported {
    /// Counts reports of a pending state, as Windows asks, so it can see
    /// progress.
    checkpoint: u32,
    /// Once stopping, the service is never reported running again.
    stopping: bool,
    /// Once stopped, nothing more is reported.
    stopped: bool,
}

// SAFETY: the handle is an opaque value the service manager gives for this
// process's service, which may be used from any thread. It needs no closing.
unsafe impl Send for Status {}
// SAFETY: as above; what has been reported is behind a mutex.
unsafe impl Sync for Status {}

impl Status {
    fn report(
        &self,
        state: SERVICE_STATUS_CURRENT_STATE,
        accepts: u32,
        exit: u32,
        specific: u32,
    ) -> Result<()> {
        let mut reported = lock(&self.reported);
        if reported.stopped || (reported.stopping && state == SERVICE_RUNNING) {
            return Ok(());
        }
        reported.stopping |= state == SERVICE_STOP_PENDING;
        reported.stopped = state == SERVICE_STOPPED;
        let pending = state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING;
        reported.checkpoint = if pending { reported.checkpoint + 1 } else { 0 };
        let status = SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: state,
            dwControlsAccepted: accepts,
            dwWin32ExitCode: exit,
            dwServiceSpecificExitCode: specific,
            dwCheckPoint: reported.checkpoint,
            dwWaitHint: if pending { WAIT_HINT_MS } else { 0 },
        };
        // SAFETY: the handle came from RegisterServiceCtrlHandlerExW, and the
        // status lives until the call returns.
        match unsafe { SetServiceStatus(self.handle, &status) } {
            0 => Err(os_error(last_error())),
            _ => Ok(()),
        }
    }
}

/// The service's entry point, called by the service manager on a thread of
/// its own. The first argument is the name the service was started under.
unsafe extern "system" fn service_main(argc: u32, argv: *mut PWSTR) {
    // SAFETY: Windows passes `argc` valid NUL-terminated strings in `argv`.
    let name = unsafe { first_argument(argc, argv) };
    let Some(body) = lock(&BODY).take() else {
        return;
    };
    let wide_name = wide(&name);
    // SAFETY: the name is NUL-terminated and outlives the call; the handler
    // is a function with the expected signature, and it takes no context.
    let handle =
        unsafe { RegisterServiceCtrlHandlerExW(wide_name.as_ptr(), Some(handler), null()) };
    if handle.is_null() {
        let why = format!(
            "the control handler could not be registered: {}",
            os_error(last_error())
        );
        *lock(&OUTCOME) = Some(Err(why));
        return;
    }
    let status = Arc::new(Status {
        handle,
        reported: Mutex::default(),
    });
    let (stop, stop_requests) = mpsc::channel();
    *lock(&HANDLER) = Some(Handler {
        status: status.clone(),
        stop: Some(stop),
    });
    let _ = status.report(SERVICE_START_PENDING, 0, NO_ERROR, 0);
    let control = Control { status, name };
    let outcome = catch_unwind(AssertUnwindSafe(|| body(&control, stop_requests)))
        .unwrap_or_else(|_| Err("the service panicked".to_string()));
    let (exit, specific) = match outcome {
        Ok(()) => (NO_ERROR, 0),
        Err(_) => (ERROR_SERVICE_SPECIFIC_ERROR, FAILED),
    };
    *lock(&OUTCOME) = Some(outcome);
    lock(&HANDLER).take();
    // Once this is reported, Windows may end the process at any moment, so
    // it is the last thing done here.
    let _ = control.status.report(SERVICE_STOPPED, 0, exit, specific);
}

/// Reports "stopping" again every [`PROGRESS`] until "stopped" has been
/// reported.
fn report_progress(status: &Status) {
    loop {
        thread::sleep(PROGRESS);
        if lock(&status.reported).stopped {
            return;
        }
        let _ = status.report(SERVICE_STOP_PENDING, 0, NO_ERROR, 0);
    }
}

/// The first of `argc` strings in `argv`, or nothing.
///
/// # Safety
///
/// `argv` must hold `argc` valid NUL-terminated UTF-16 strings.
unsafe fn first_argument(argc: u32, argv: *mut PWSTR) -> String {
    if argc == 0 || argv.is_null() {
        return String::new();
    }
    // SAFETY: there is at least one entry, per the caller.
    let first = unsafe { *argv };
    if first.is_null() {
        return String::new();
    }
    // SAFETY: the string is NUL-terminated, so every offset up to and
    // including the NUL is readable.
    let len = (0..)
        .find(|at| unsafe { *first.add(*at) } == 0)
        .unwrap_or(0);
    // SAFETY: those `len` code units were just read.
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(first, len) })
}

/// Answers the service manager's requests, on the service manager's thread.
unsafe extern "system" fn handler(
    control: u32,
    _event: u32,
    _data: *mut core::ffi::c_void,
    _context: *mut core::ffi::c_void,
) -> u32 {
    match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN | SERVICE_CONTROL_PRESHUTDOWN => {
            let mut handler = lock(&HANDLER);
            if let Some(handler) = handler.as_mut() {
                let _ = handler.status.report(SERVICE_STOP_PENDING, 0, NO_ERROR, 0);
                if let Some(stop) = handler.stop.take() {
                    let _ = stop.send(());
                    let status = handler.status.clone();
                    thread::spawn(move || report_progress(&status));
                }
            }
            NO_ERROR
        }
        SERVICE_CONTROL_INTERROGATE => NO_ERROR,
        _ => ERROR_CALL_NOT_IMPLEMENTED,
    }
}

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;
