//! Installing and removing the service on Windows: its registration with the
//! service manager, and the machine-wide data folder that holds the policy
//! and the state.
//!
//! The setup program runs `ubc-vpn-service install` and `uninstall`, as an
//! administrator; the service crate decides the order. What is done here:
//!
//! - **Registration.** The service runs as LocalSystem in a process of its
//!   own and starts with Windows. Its path is quoted, so a space in it can
//!   never be read as the end of the program's name. If it stops with an
//!   error it is restarted twice, five seconds apart. Windows waits up to
//!   [`PRESHUTDOWN_TIMEOUT_MS`] at shutdown for it to remove its routes and
//!   DNS. Its access list is left as Windows makes it: ordinary users can
//!   ask its status but can neither start nor stop it.
//! - **The data folder.** Owned by the Administrators group, with a
//!   protected access list: SYSTEM and Administrators have full control of
//!   it and of everything in it, and Users may list and read the folder
//!   itself and nothing more. `policy.json` gets read access for Users of
//!   its own, because the command-line client reads it as the user. The
//!   state the service writes inherits only the administrators' entries.
//!   On a first install a folder that is already there is emptied, since
//!   anyone may have made it; on an update its contents are kept.

use std::path::Path;
use std::ptr::{null, null_mut};
use std::thread;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    ERROR_INVALID_SERVICE_CONTROL, ERROR_SERVICE_ALREADY_RUNNING, ERROR_SERVICE_CANNOT_ACCEPT_CTRL,
    ERROR_SERVICE_DOES_NOT_EXIST, ERROR_SERVICE_MARKED_FOR_DELETE, ERROR_SERVICE_NOT_ACTIVE,
};
use windows_sys::Win32::Security::Authorization::{SE_FILE_OBJECT, SetNamedSecurityInfoW};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner,
    OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
};
use windows_sys::Win32::System::Services::{
    ChangeServiceConfig2W, ChangeServiceConfigW, CloseServiceHandle, ControlService,
    CreateServiceW, DeleteService, OpenSCManagerW, OpenServiceW, QueryServiceStatus, SC_ACTION,
    SC_ACTION_NONE, SC_ACTION_RESTART, SC_HANDLE, SC_MANAGER_CONNECT, SC_MANAGER_CREATE_SERVICE,
    SERVICE_ALL_ACCESS, SERVICE_AUTO_START, SERVICE_CONFIG_DESCRIPTION,
    SERVICE_CONFIG_FAILURE_ACTIONS, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
    SERVICE_CONFIG_PRESHUTDOWN_INFO, SERVICE_CONTROL_STOP, SERVICE_DESCRIPTIONW,
    SERVICE_ERROR_NORMAL, SERVICE_FAILURE_ACTIONS_FLAG, SERVICE_FAILURE_ACTIONSW,
    SERVICE_PRESHUTDOWN_INFO, SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS,
    SERVICE_STOP_PENDING, SERVICE_STOPPED, SERVICE_WIN32_OWN_PROCESS, StartServiceW,
};

use super::security::{Descriptor, last_error, os_error, wide};
use crate::{Error, Result};

/// How long Windows waits at shutdown for the service to clean up, in
/// milliseconds. Set explicitly: the default differs between versions.
pub const PRESHUTDOWN_TIMEOUT_MS: u32 = 30_000;

/// How long to wait for the service to start or stop.
const STATE_WAIT: Duration = Duration::from_secs(90);

/// The data folder: owned by Administrators, nothing inherited; full control
/// for SYSTEM and Administrators, passed on; list and read for Users, on the
/// folder only.
pub const DATA_FOLDER_SDDL: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200a9;;;BU)";

/// `policy.json`: the same, and read for Users.
pub const POLICY_SDDL: &str = "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)";

/// The policy file's name in the data folder.
const POLICY: &str = "policy.json";

/// What the service is registered as.
pub struct Registration<'a> {
    /// The name the service manager knows it by.
    pub name: &'a str,
    /// The name shown in the Services console.
    pub display_name: &'a str,
    /// The text shown beside it.
    pub description: &'a str,
    /// The full command line, the program's path quoted.
    pub command_line: String,
}

/// The command line for `program` with no arguments: its path in quotes.
/// A path with a quote in it is refused, since it could not be quoted.
pub fn quoted(program: &Path) -> Result<String> {
    let text = program.to_str().ok_or(Error::InvalidInput)?;
    if !program.is_absolute() || text.contains('"') {
        return Err(Error::InvalidInput);
    }
    Ok(format!("\"{text}\""))
}

/// A handle to the service manager or a service. Dropping it closes it.
struct Sc(SC_HANDLE);

impl Drop for Sc {
    fn drop(&mut self) {
        // SAFETY: the handle is open and owned by this value alone.
        unsafe { CloseServiceHandle(self.0) };
    }
}

fn manager(access: u32) -> Result<Sc> {
    // SAFETY: null names mean this computer's active database.
    let handle = unsafe { OpenSCManagerW(null(), null(), access) };
    match handle.is_null() {
        true => Err(os_error(last_error())),
        false => Ok(Sc(handle)),
    }
}

/// The service `name`, or nothing if it is not registered.
fn open_service(manager: &Sc, name: &str) -> Result<Option<Sc>> {
    let name = wide(name);
    // SAFETY: the manager is open, and the name is NUL-terminated and
    // outlives the call.
    let handle = unsafe { OpenServiceW(manager.0, name.as_ptr(), SERVICE_ALL_ACCESS) };
    if !handle.is_null() {
        return Ok(Some(Sc(handle)));
    }
    match last_error() {
        ERROR_SERVICE_DOES_NOT_EXIST => Ok(None),
        code => Err(os_error(code)),
    }
}

fn state_of(service: &Sc) -> Result<SERVICE_STATUS> {
    let mut status = SERVICE_STATUS::default();
    // SAFETY: the handle is open with query access, and the out pointer
    // is valid.
    match unsafe { QueryServiceStatus(service.0, &mut status) } {
        0 => Err(os_error(last_error())),
        _ => Ok(status),
    }
}

/// Waits until the service is in `wanted`, or has stopped. Returns its
/// last status.
fn wait_for(service: &Sc, wanted: u32) -> Result<SERVICE_STATUS> {
    let started = Instant::now();
    loop {
        let status = state_of(service)?;
        if status.dwCurrentState == wanted || status.dwCurrentState == SERVICE_STOPPED {
            return Ok(status);
        }
        if started.elapsed() > STATE_WAIT {
            return Err(Error::TimedOut);
        }
        thread::sleep(Duration::from_millis(200));
    }
}

/// Asks the service to stop and waits until it has. A service that is not
/// running is fine.
///
/// While it is still starting or already stopping, it takes no requests,
/// so the request is made again until it takes it or has stopped, for up to
/// [`STATE_WAIT`]. A service that is starting may take a while: it waits
/// for its channel's name when another program holds it.
fn stop(service: &Sc) -> Result<()> {
    let started = Instant::now();
    loop {
        let mut status = SERVICE_STATUS::default();
        // SAFETY: the handle is open with full access, and the out pointer
        // is valid.
        if unsafe { ControlService(service.0, SERVICE_CONTROL_STOP, &mut status) } != 0 {
            return wait_for(service, SERVICE_STOPPED).map(drop);
        }
        match last_error() {
            ERROR_SERVICE_NOT_ACTIVE => return Ok(()),
            // A service that is starting accepts no requests yet, which
            // Windows reports as either of these.
            code @ (ERROR_SERVICE_CANNOT_ACCEPT_CTRL | ERROR_INVALID_SERVICE_CONTROL) => {
                match state_of(service)?.dwCurrentState {
                    SERVICE_STOPPED => return Ok(()),
                    SERVICE_START_PENDING | SERVICE_STOP_PENDING => {}
                    _ => return Err(os_error(code)),
                }
                if started.elapsed() > STATE_WAIT {
                    return Err(Error::TimedOut);
                }
                thread::sleep(Duration::from_millis(200));
            }
            code => return Err(os_error(code)),
        }
    }
}

/// Registers the service, or, if it is registered already, stops it and
/// brings its settings up to date. It is not started.
pub fn register(registration: &Registration) -> Result<()> {
    let manager = manager(SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE)?;
    let name = wide(registration.name);
    let display = wide(registration.display_name);
    let command = wide(&registration.command_line);
    let service = match open_service(&manager, registration.name)? {
        Some(service) => {
            stop(&service)?;
            // SAFETY: the handle is open with full access; the strings are
            // NUL-terminated and outlive the call; null leaves a setting as
            // it is, and a null account keeps LocalSystem.
            let changed = unsafe {
                ChangeServiceConfigW(
                    service.0,
                    SERVICE_WIN32_OWN_PROCESS,
                    SERVICE_AUTO_START,
                    SERVICE_ERROR_NORMAL,
                    command.as_ptr(),
                    null(),
                    null_mut(),
                    null(),
                    null(),
                    null(),
                    display.as_ptr(),
                )
            };
            if changed == 0 {
                return Err(os_error(last_error()));
            }
            (service, false)
        }
        None => (create(&manager, &name, &display, &command)?, true),
    };
    let (service, created) = service;
    if let Err(error) = configure(&service, registration.description) {
        // A service this run created is not left half set up: it is
        // deleted, so the next install starts from nothing. One that was
        // there before keeps its registration, as before this run.
        if created {
            // SAFETY: the handle is open with full access, which includes
            // delete.
            unsafe { DeleteService(service.0) };
        }
        return Err(error);
    }
    Ok(())
}

/// Creates the service. One that was just removed may still be marked for
/// deletion for a moment, so that is tried again for a while.
fn create(manager: &Sc, name: &[u16], display: &[u16], command: &[u16]) -> Result<Sc> {
    let started = Instant::now();
    loop {
        // SAFETY: the manager is open with create access; the strings are
        // NUL-terminated and outlive the call; the optional pointers are
        // null, and a null account means LocalSystem.
        let handle = unsafe {
            CreateServiceW(
                manager.0,
                name.as_ptr(),
                display.as_ptr(),
                SERVICE_ALL_ACCESS,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_AUTO_START,
                SERVICE_ERROR_NORMAL,
                command.as_ptr(),
                null(),
                null_mut(),
                null(),
                null(),
                null(),
            )
        };
        if !handle.is_null() {
            return Ok(Sc(handle));
        }
        match last_error() {
            ERROR_SERVICE_MARKED_FOR_DELETE if started.elapsed() < STATE_WAIT => {
                thread::sleep(Duration::from_millis(500));
            }
            code => return Err(os_error(code)),
        }
    }
}

/// The description, the restarts after a failure and the shutdown time.
fn configure(service: &Sc, description: &str) -> Result<()> {
    #[cfg(test)]
    if tests::FAIL_CONFIGURE.with(std::cell::Cell::get) {
        return Err(Error::Failed(
            "configuring failed, as the test asked".to_string(),
        ));
    }
    let mut text = wide(description);
    let described = SERVICE_DESCRIPTIONW {
        lpDescription: text.as_mut_ptr(),
    };
    let mut actions = [
        SC_ACTION {
            Type: SC_ACTION_RESTART,
            Delay: 5_000,
        },
        SC_ACTION {
            Type: SC_ACTION_RESTART,
            Delay: 5_000,
        },
        SC_ACTION {
            Type: SC_ACTION_NONE,
            Delay: 0,
        },
    ];
    let failures = SERVICE_FAILURE_ACTIONSW {
        // The count of failures goes back to zero after a day.
        dwResetPeriod: 24 * 60 * 60,
        lpRebootMsg: null_mut(),
        lpCommand: null_mut(),
        cActions: actions.len() as u32,
        lpsaActions: actions.as_mut_ptr(),
    };
    // Also when it stops with an error, not only when it crashes.
    let on_errors = SERVICE_FAILURE_ACTIONS_FLAG {
        fFailureActionsOnNonCrashFailures: 1,
    };
    let shutdown = SERVICE_PRESHUTDOWN_INFO {
        dwPreshutdownTimeout: PRESHUTDOWN_TIMEOUT_MS,
    };
    let settings: [(u32, *const core::ffi::c_void); 4] = [
        (SERVICE_CONFIG_DESCRIPTION, (&raw const described).cast()),
        (SERVICE_CONFIG_FAILURE_ACTIONS, (&raw const failures).cast()),
        (
            SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
            (&raw const on_errors).cast(),
        ),
        (
            SERVICE_CONFIG_PRESHUTDOWN_INFO,
            (&raw const shutdown).cast(),
        ),
    ];
    for (level, info) in settings {
        // SAFETY: the handle is open with full access, and each pointer is
        // to the structure its level names, alive, with what it points to,
        // until after the call.
        if unsafe { ChangeServiceConfig2W(service.0, level, info) } == 0 {
            return Err(os_error(last_error()));
        }
    }
    Ok(())
}

/// Starts the service and waits until it runs. One that stops instead is an
/// error naming its exit code.
///
/// What a failed start leaves behind: the service stays registered, set up
/// and stopped, and the data folder and policy stay as written. Nothing is
/// undone here, because the setup program that ran `install` undoes the
/// whole install when it fails (packaging/windows/installer.nsh): its undo
/// runs `uninstall`, which removes the registration and the data folder.
/// Until then Windows may try to start it again, as its failure actions
/// say; `uninstall` stops any such attempt before it deletes the service.
pub fn start(name: &str) -> Result<()> {
    let manager = manager(SC_MANAGER_CONNECT)?;
    let service = open_service(&manager, name)?.ok_or(Error::NotFound)?;
    // SAFETY: the handle is open with full access, and no arguments are
    // passed.
    if unsafe { StartServiceW(service.0, 0, null()) } == 0 {
        match last_error() {
            ERROR_SERVICE_ALREADY_RUNNING => return Ok(()),
            code => return Err(os_error(code)),
        }
    }
    let status = wait_for(&service, SERVICE_RUNNING)?;
    match status.dwCurrentState {
        SERVICE_RUNNING => Ok(()),
        _ => Err(Error::Failed(format!(
            "the service stopped as it started (exit code {}, service code {})",
            status.dwWin32ExitCode, status.dwServiceSpecificExitCode
        ))),
    }
}

/// Stops the service, waiting for it to clean up, and removes its
/// registration. A service that is not registered is fine.
pub fn unregister(name: &str) -> Result<()> {
    let manager = manager(SC_MANAGER_CONNECT)?;
    let Some(service) = open_service(&manager, name)? else {
        return Ok(());
    };
    stop(&service)?;
    // SAFETY: the handle is open with full access, which includes delete.
    if unsafe { DeleteService(service.0) } == 0 {
        match last_error() {
            ERROR_SERVICE_MARKED_FOR_DELETE => {}
            code => return Err(os_error(code)),
        }
    }
    Ok(())
}

/// Sets the owner and the protected access list of `path` from `sddl`.
fn set_security(path: &Path, sddl: &str) -> Result<()> {
    let descriptor = Descriptor::parse(sddl)?;
    let (mut owner, mut defaulted) = (null_mut(), 0);
    let (mut present, mut dacl) = (0, null_mut());
    // SAFETY: the descriptor is valid, and the out pointers are valid. What
    // they receive points into the descriptor, which outlives its use below.
    let read = unsafe {
        GetSecurityDescriptorOwner(descriptor.as_ptr(), &mut owner, &mut defaulted) != 0
            && GetSecurityDescriptorDacl(
                descriptor.as_ptr(),
                &mut present,
                &mut dacl,
                &mut defaulted,
            ) != 0
    };
    if !read || present == 0 || owner.is_null() {
        return Err(Error::Failed(
            "the access list could not be built".to_string(),
        ));
    }
    let name = wide(&path.to_string_lossy());
    let what = OWNER_SECURITY_INFORMATION
        | DACL_SECURITY_INFORMATION
        | PROTECTED_DACL_SECURITY_INFORMATION;
    // SAFETY: the name is NUL-terminated; the owner and access list point into
    // the descriptor, alive until after the call; the group and SACL are
    // null and not asked for.
    let status = unsafe {
        SetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            what,
            owner,
            null_mut(),
            dacl,
            null(),
        )
    };
    match status {
        0 => Ok(()),
        code => Err(os_error(code)),
    }
}

/// Makes the data folder `dir` and sets its owner and access list. With
/// `fresh`, whatever is there already, a link included, is removed first.
/// Without it the contents are kept, but a link is refused.
pub fn prepare_data_folder(dir: &Path, fresh: bool) -> Result<()> {
    match std::fs::symlink_metadata(dir) {
        // `remove_dir_all` removes a link itself, never what it points to.
        Ok(_) if fresh => std::fs::remove_dir_all(dir)?,
        Ok(found) if found.file_type().is_symlink() || !found.is_dir() => {
            return Err(Error::Failed(format!(
                "{} is not a folder; run a fresh install",
                dir.display()
            )));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    if !dir.exists() {
        // Made with the access list it keeps, so it is never open to others.
        let descriptor = Descriptor::parse(DATA_FOLDER_SDDL)?;
        let attributes = windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
            nLength: size_of::<windows_sys::Win32::Security::SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.as_ptr(),
            bInheritHandle: 0,
        };
        let name = wide(&dir.to_string_lossy());
        // SAFETY: the name is NUL-terminated, and it and the attributes, with
        // the descriptor they point to, outlive the call.
        let made = unsafe {
            windows_sys::Win32::Storage::FileSystem::CreateDirectoryW(name.as_ptr(), &attributes)
        };
        if made == 0 {
            return Err(os_error(last_error()));
        }
    }
    set_security(dir, DATA_FOLDER_SDDL)
}

/// Writes `policy` as the data folder's `policy.json`, replacing any, and
/// gives it its access list. It is written beside it first and then moved
/// into place, so a reader never sees half of it.
pub fn write_policy(dir: &Path, policy: &[u8]) -> Result<()> {
    let target = dir.join(POLICY);
    let next = dir.join(format!("{POLICY}.new"));
    std::fs::write(&next, policy)?;
    set_security(&next, POLICY_SDDL)?;
    std::fs::rename(&next, &target)?;
    Ok(())
}

/// Checks the data folder once it is prepared and the policy written: the
/// same check of its owner and access list the service makes of its state
/// folder, and, after a fresh install, that it holds the policy and nothing
/// else. The folder is removed and made again on a fresh install; whoever
/// managed to make it in between, or to put something in it, makes this an
/// error rather than a folder the service would trust.
pub fn verify_data_folder(dir: &Path, fresh: bool) -> Result<()> {
    drop(super::state::check_folder(crate::Mode::Installed, dir)?);
    if fresh {
        let mut found = Vec::new();
        for entry in std::fs::read_dir(dir)? {
            found.push(entry?.file_name().to_string_lossy().into_owned());
        }
        if found != [POLICY] {
            return Err(Error::Failed(format!(
                "{} holds {} as well as the policy, so something else made or changed it during the install",
                dir.display(),
                found.join(", ")
            )));
        }
    }
    Ok(())
}

/// Removes the data folder and everything in it. A missing folder is fine.
pub fn remove_data_folder(dir: &Path) -> Result<()> {
    match std::fs::remove_dir_all(dir) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error.into()),
        _ => Ok(()),
    }
}

#[cfg(test)]
#[path = "install_tests.rs"]
mod tests;
