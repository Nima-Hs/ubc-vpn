//! Who is who: user SIDs, the pipe's security descriptor, and the two checks
//! built on them (who called, and who owns the pipe a client opened).

use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_INVALID_OWNER, GetLastError, HANDLE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SDDL_REVISION_1, SE_KERNEL_OBJECT,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, GetTokenInformation, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, RevertToSelf, SetKernelObjectSecurity, TOKEN_QUERY, TOKEN_USER,
    TokenUser,
};
use windows_sys::Win32::System::Pipes::ImpersonateNamedPipeClient;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
};

use crate::{Error, Mode, Result, UserId};

/// SYSTEM and the Administrators group: the only owners an installed
/// service's pipe can have.
const PRIVILEGED: [&str; 2] = ["S-1-5-18", "S-1-5-32-544"];

/// What a client needs to connect, read and write: `FILE_GENERIC_READ` plus
/// `FILE_WRITE_DATA`. Deliberately not `FILE_GENERIC_WRITE`, which contains
/// `FILE_CREATE_PIPE_INSTANCE` and would let a client serve the pipe itself.
pub(super) const CONNECT_RIGHTS: u32 = 0x0012_008b;

/// The error for the last failed call on this thread, by its Windows code.
pub(super) fn last_error() -> u32 {
    // SAFETY: reads thread-local state and has no preconditions.
    unsafe { GetLastError() }
}

/// A Windows error as this crate's error. The message is only the code.
pub(super) fn os_error(code: u32) -> Error {
    match code {
        2 | 3 => Error::NotFound,
        5 | ERROR_INVALID_OWNER => Error::PermissionDenied,
        // Broken pipe, pipe being closed, pipe not connected.
        109 | 232 | 233 => Error::Closed,
        code => Error::Failed(format!("Windows error {code}")),
    }
}

/// `text` as a NUL-terminated UTF-16 string.
pub(super) fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain([0]).collect()
}

/// A kernel handle this process owns. Dropping it closes it.
pub(super) struct Handle(pub(super) HANDLE);

// SAFETY: a kernel handle is a process-wide index, valid on any thread, and
// every call made on one here is thread-safe in the kernel.
unsafe impl Send for Handle {}
// SAFETY: as above.
unsafe impl Sync for Handle {}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: the handle is open and owned by this value alone, so it is
        // closed exactly once.
        unsafe { CloseHandle(self.0) };
    }
}

/// Memory Windows allocated with `LocalAlloc`. Dropping it frees it.
struct Local(*mut core::ffi::c_void);

impl Drop for Local {
    fn drop(&mut self) {
        // SAFETY: the pointer came from an API documented to need LocalFree
        // and is freed exactly once; LocalFree accepts null.
        unsafe { LocalFree(self.0) };
    }
}

/// A security descriptor built from SDDL text.
pub(super) struct Descriptor(Local);

impl Descriptor {
    pub(super) fn parse(sddl: &str) -> Result<Self> {
        let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
        let text = wide(sddl);
        // SAFETY: `text` is NUL-terminated and outlives the call; the out
        // pointer is valid, and the size out-parameter may be null.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        };
        match ok {
            0 => Err(os_error(last_error())),
            _ => Ok(Self(Local(descriptor))),
        }
    }

    pub(super) fn as_ptr(&self) -> PSECURITY_DESCRIPTOR {
        self.0.0
    }
}

/// The security descriptor for the pipe, as SDDL.
///
/// Installed: owned by Administrators; SYSTEM and Administrators have full
/// control, which includes creating further instances and changing this
/// descriptor; nobody else has either. Until there is an owner, interactive
/// users may connect; afterwards only the owner may. A process that is
/// neither SYSTEM nor an elevated administrator cannot make Administrators
/// the owner, so it cannot create this pipe at all.
///
/// Dev: owned by the current user, who has full control; an owner other than
/// that user may connect once named. Nobody else.
pub(super) fn sddl(mode: Mode, me: &str, owner: Option<&UserId>) -> Result<String> {
    let owner = owner.map(ToString::to_string);
    // The owner is pasted into SDDL, so it must be a SID and nothing else.
    let is_sid = |sid: &String| {
        let rest = sid.strip_prefix("S-1-").unwrap_or("");
        !rest.is_empty()
            && rest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b'-')
    };
    if owner.as_ref().is_some_and(|sid| !is_sid(sid)) {
        return Err(Error::Failed("the owner is not a SID".to_string()));
    }
    let connect = |sid: &str| format!("(A;;{CONNECT_RIGHTS:#x};;;{sid})");
    Ok(match mode {
        Mode::Installed => {
            let _ = me;
            let caller = owner.as_deref().unwrap_or("IU");
            format!("O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA){}", connect(caller))
        }
        #[cfg(feature = "dev-mode")]
        Mode::Dev => {
            let other = owner.filter(|owner| owner != me);
            let other = other.map(|sid| connect(&sid)).unwrap_or_default();
            format!("O:{me}D:P(A;;FA;;;{me}){other}")
        }
    })
}

/// Whether a pipe owned by `owner` can only have been created by the service
/// a client in `mode` expects: SYSTEM or an administrator when installed, the
/// current user in dev mode. An ordinary user cannot give an object an owner
/// other than themselves, so a pipe someone else squatted never passes.
pub(super) fn is_the_service(mode: Mode, me: &str, owner: &str) -> bool {
    match mode {
        Mode::Installed => {
            let _ = me;
            PRIVILEGED.contains(&owner)
        }
        #[cfg(feature = "dev-mode")]
        Mode::Dev => owner == me,
    }
}

/// A SID as canonical text: `S-1-…`, upper case.
fn sid_text(sid: PSID) -> Result<String> {
    let mut text = null_mut();
    // SAFETY: the caller passes a valid SID; the out pointer is valid.
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(os_error(last_error()));
    }
    let text = Local(text.cast());
    let start: *const u16 = text.0.cast();
    // SAFETY: on success the API wrote a NUL-terminated string, so every
    // offset up to and including the NUL is readable.
    let len = (0..)
        .find(|at| unsafe { *start.add(*at) } == 0)
        .unwrap_or(0);
    // SAFETY: `len` code units before the NUL were just read from this
    // allocation, which `text` keeps alive.
    let units = unsafe { std::slice::from_raw_parts(start, len) };
    Ok(String::from_utf16_lossy(units).to_ascii_uppercase())
}

/// The user a token stands for.
pub(super) fn token_user(token: &Handle) -> Result<String> {
    // A TOKEN_USER is a pointer pair followed by its SID (68 bytes at most);
    // u64 elements give the buffer the alignment the struct needs.
    let mut buffer = [0u64; 16];
    let (size, mut used) = (size_of_val(&buffer) as u32, 0);
    // SAFETY: the buffer is writable for `size` bytes and `used` is a valid
    // out pointer.
    let ok = unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            size,
            &mut used,
        )
    };
    if ok == 0 {
        return Err(os_error(last_error()));
    }
    // SAFETY: on success the buffer starts with an initialised TOKEN_USER and
    // is aligned for it.
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    sid_text(user.User.Sid)
}

/// The user this process runs as.
pub(super) fn process_user() -> Result<String> {
    let mut token = null_mut();
    // SAFETY: the pseudo-handle for this process is always valid, and the
    // out pointer is valid.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(os_error(last_error()));
    }
    token_user(&Handle(token))
}

/// Ends impersonation when dropped, on every path including a panic.
struct Impersonating;

impl Drop for Impersonating {
    fn drop(&mut self) {
        // SAFETY: no preconditions; affects only the calling thread.
        if unsafe { RevertToSelf() } == 0 {
            // The thread would go on acting as the client, with the service's
            // work ahead of it. There is no safe way to continue.
            std::process::abort();
        }
    }
}

/// The user at the other end of the server pipe `pipe`, as Windows reports
/// it: the thread briefly takes the client's identity, copies its token, and
/// gives the identity back before anything else runs.
pub(super) fn pipe_client(pipe: HANDLE) -> Result<UserId> {
    let mut token = null_mut();
    {
        // SAFETY: `pipe` is an open server end of a named pipe.
        if unsafe { ImpersonateNamedPipeClient(pipe) } == 0 {
            return Err(os_error(last_error()));
        }
        let _reverts = Impersonating;
        // SAFETY: the pseudo-handle for this thread is always valid and the
        // out pointer is valid. The token is opened with the process's own
        // rights (the third argument), not the client's.
        if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } == 0 {
            return Err(os_error(last_error()));
        }
    }
    token_user(&Handle(token))?.parse()
}

/// The SID that owns the kernel object behind `handle`.
pub(super) fn owner_of(handle: HANDLE) -> Result<String> {
    let (mut owner, mut descriptor) = (null_mut(), null_mut());
    // SAFETY: `handle` is open with READ_CONTROL; the two out pointers asked
    // for are valid and the others may be null.
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(os_error(status));
    }
    // `owner` points into the descriptor, which this keeps alive.
    let _descriptor = Local(descriptor);
    sid_text(owner)
}

/// Replaces the access list of the pipe behind `handle` with the one in
/// `sddl`. The owner stays as it is.
pub(super) fn set_access(handle: HANDLE, sddl: &str) -> Result<()> {
    let descriptor = Descriptor::parse(sddl)?;
    // SAFETY: `handle` is open with WRITE_DAC and the descriptor is valid for
    // the call.
    let ok =
        unsafe { SetKernelObjectSecurity(handle, DACL_SECURITY_INFORMATION, descriptor.as_ptr()) };
    match ok {
        0 => Err(os_error(last_error())),
        _ => Ok(()),
    }
}
