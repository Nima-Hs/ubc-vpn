//! Tests of [`run`] under the real service manager.
//!
//! This test program is its own service: an elevated test registers it with
//! the service manager under a throwaway name, asking it to run only
//! [`hosted`], and then starts and stops it. Registering a service needs an
//! elevated process, so without one that test is skipped with a message,
//! unless `UBC_VPN_REQUIRE_ELEVATED` is set, as it is in CI.

use std::ptr::{null, null_mut};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{ERROR_SERVICE_SPECIFIC_ERROR, NO_ERROR};
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, ControlService, CreateServiceW, DeleteService, OpenSCManagerW,
    QueryServiceStatus, SC_HANDLE, SC_MANAGER_CREATE_SERVICE, SERVICE_ALL_ACCESS,
    SERVICE_CONTROL_STOP, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, StartServiceW,
};

use super::*;

/// A service name that says what the hosted test is to do, and belongs to
/// this run alone.
fn name(scenario: &str) -> String {
    format!("ubc-vpn-test-{scenario}-{}", std::process::id())
}

/// What [`hosted`] does when its service name contains this.
const FAIL: &str = "-fails-";

/// How long [`hosted`] takes to clean up after a stop request: long enough
/// for several progress reports.
const CLEANUP: Duration = Duration::from_secs(3);

/// The file [`hosted`] writes when its cleanup is done, beside this test
/// program and named after the service.
fn marker(service: &str) -> std::path::PathBuf {
    let program = std::env::current_exe().expect("the test program's path");
    program.with_file_name(format!("{service}.cleaned-up"))
}

fn skip(what: &str) {
    let required = std::env::var_os("UBC_VPN_REQUIRE_ELEVATED").is_some();
    assert!(!required, "{what}, and this run requires it");
    println!("SKIPPED: {what}");
}

/// CI searches the log for this line to prove the elevated test ran.
fn ran(test: &str) {
    println!("RAN: {test}");
}

// Run by `cargo test`, this is not under the service manager, and `run` must
// say so at once without calling the body. Run by the service manager, as
// the test below has it, it is the service: it reports itself running, then
// either fails at once or waits for the stop request, then takes a while to
// clean up and leaves a marker when it is done.
#[test]
fn hosted() {
    let outcome = run(|control, stop| {
        control.running().map_err(|e| e.to_string())?;
        if control.name().contains(FAIL) {
            return Err("asked to fail".to_string());
        }
        stop.recv()
            .map_err(|_| "the stop request never came".to_string())?;
        std::thread::sleep(CLEANUP);
        std::fs::write(marker(control.name()), b"done").map_err(|e| e.to_string())
    });
    match outcome {
        Err(Error::Failed(why)) => assert!(why.contains("service manager"), "{why}"),
        // Under the service manager, which has already been told the result.
        Ok(_) => {}
        Err(other) => panic!("{other:?}"),
    }
}

/// A handle to the service manager or a service. Dropping it closes it.
struct Sc(SC_HANDLE);

impl Drop for Sc {
    fn drop(&mut self) {
        // SAFETY: the handle is open and owned by this value alone.
        unsafe { CloseServiceHandle(self.0) };
    }
}

/// A service registered for one test. Dropping it stops it if it still runs
/// and removes it.
struct Registered(Sc);

impl Registered {
    fn status(&self) -> SERVICE_STATUS {
        let mut status = SERVICE_STATUS::default();
        // SAFETY: the handle is open with query access, and the out pointer
        // is valid.
        let ok = unsafe { QueryServiceStatus(self.0.0, &mut status) };
        assert_ne!(ok, 0, "querying the service: {}", last_error());
        status
    }

    /// Waits until the service is in `state`, and returns its status.
    fn wait_for(&self, state: u32) -> SERVICE_STATUS {
        let started = Instant::now();
        loop {
            let status = self.status();
            if status.dwCurrentState == state {
                return status;
            }
            assert!(
                started.elapsed() < Duration::from_secs(60),
                "the service stayed in state {}, not {state}",
                status.dwCurrentState
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn control(&self, control: u32) {
        let mut status = SERVICE_STATUS::default();
        // SAFETY: the handle is open with full access, and the out pointer
        // is valid.
        let ok = unsafe { ControlService(self.0.0, control, &mut status) };
        assert_ne!(ok, 0, "sending control {control}: {}", last_error());
    }
}

impl Drop for Registered {
    fn drop(&mut self) {
        let mut status = SERVICE_STATUS::default();
        // SAFETY: as in `control`. Failing is fine: it may have stopped.
        unsafe { ControlService(self.0.0, SERVICE_CONTROL_STOP, &mut status) };
        // SAFETY: the handle is open with full access, which includes delete.
        unsafe { DeleteService(self.0.0) };
    }
}

/// Registers this test program as the service `name`, to run [`hosted`] only.
fn register(manager: &Sc, name: &str) -> Registered {
    let program = std::env::current_exe().expect("the test program's path");
    let module = module_path!().split_once("::").map_or("", |(_, rest)| rest);
    let command = format!(
        "\"{}\" {module}::hosted --exact --nocapture --test-threads=1",
        program.display()
    );
    let (name, command) = (wide(name), wide(&command));
    // SAFETY: the strings are NUL-terminated and outlive the call; the
    // optional pointers are null, and a null account means LocalSystem.
    let handle = unsafe {
        CreateServiceW(
            manager.0,
            name.as_ptr(),
            name.as_ptr(),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            command.as_ptr(),
            null(),
            null_mut(),
            null(),
            null(),
            null(),
        )
    };
    assert!(
        !handle.is_null(),
        "registering the service: {}",
        last_error()
    );
    Registered(Sc(handle))
}

fn start(service: &Registered) {
    // SAFETY: the handle is open with start access, and no arguments are
    // passed.
    let ok = unsafe { StartServiceW(service.0.0, 0, null()) };
    assert_ne!(ok, 0, "starting the service: {}", last_error());
}

// Started by the service manager, the service reports itself running, hears
// the stop request, and is reported stopped with no error. A body that fails
// is reported stopped with a service-specific error.
#[test]
fn the_service_manager_starts_it_and_stops_it() {
    // SAFETY: null names mean this computer's active database.
    let manager = unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_CREATE_SERVICE) };
    if manager.is_null() {
        skip("registering a service needs an elevated process");
        return;
    }
    let manager = Sc(manager);

    // "Stopped" comes only once the cleanup is done, and until then
    // "stopping" is reported with a rising checkpoint.
    let stops = name("stops");
    let done = marker(&stops);
    let _ = std::fs::remove_file(&done);
    let service = register(&manager, &stops);
    start(&service);
    service.wait_for(SERVICE_RUNNING);
    service.control(SERVICE_CONTROL_STOP);
    let (mut checkpoints, started) = (Vec::new(), Instant::now());
    let stopped = loop {
        let status = service.status();
        match status.dwCurrentState {
            SERVICE_STOPPED => break status,
            SERVICE_STOP_PENDING => {
                assert!(
                    !done.exists(),
                    "the cleanup was done before stopping was over"
                );
                checkpoints.push(status.dwCheckPoint);
            }
            state => panic!("state {state} after the stop request"),
        }
        assert!(started.elapsed() < Duration::from_secs(60), "never stopped");
        std::thread::sleep(Duration::from_millis(100));
    };
    assert!(
        done.exists(),
        "reported stopped before the cleanup was done"
    );
    let _ = std::fs::remove_file(&done);
    assert_eq!(stopped.dwWin32ExitCode, NO_ERROR);
    checkpoints.dedup();
    assert!(
        checkpoints.len() >= 2,
        "no progress while stopping: {checkpoints:?}"
    );
    assert!(checkpoints.is_sorted(), "{checkpoints:?}");
    drop(service);

    let service = register(&manager, &name(&format!("x{FAIL}x")));
    start(&service);
    let stopped = service.wait_for(SERVICE_STOPPED);
    assert_eq!(stopped.dwWin32ExitCode, ERROR_SERVICE_SPECIFIC_ERROR);
    assert_eq!(stopped.dwServiceSpecificExitCode, FAILED);
    drop(service);

    ran("service manager");
}
