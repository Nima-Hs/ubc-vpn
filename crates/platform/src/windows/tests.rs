//! Tests against real pipes. Every blocking test runs under a time limit.
//!
//! Serving the installed pipe needs an elevated process, and telling two
//! users apart needs a second user, whose name and password the CI workflow
//! passes in `UBC_VPN_TEST_USER` and `UBC_VPN_TEST_PASSWORD`. Without them
//! those parts are skipped with a message, unless `UBC_VPN_REQUIRE_ELEVATED`
//! is set, as it is in CI, where a skip is a failure.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc;
use std::thread;

use ubc_vpn_core::protocol::MAX_LINE_BYTES;
use windows_sys::Win32::Foundation::{ERROR_BAD_IMPERSONATION_LEVEL, ERROR_NO_TOKEN, HANDLE};
use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_KERNEL_OBJECT,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, DuplicateTokenEx, ImpersonateLoggedOnUser,
    LABEL_SECURITY_INFORMATION, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, LogonUserW,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, RevertToSelf, SetTokenInformation,
    TOKEN_ALL_ACCESS, TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TokenImpersonation, TokenIntegrityLevel,
};
use windows_sys::Win32::System::Pipes::ImpersonateNamedPipeClient;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
};

use super::security::{CONNECT_RIGHTS, is_the_service, process_user, sddl, token_user};
use super::*;
use crate::suite;

const SHORT: Duration = Duration::from_millis(100);
const WHAT: u32 =
    OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION;
const LABEL: &str = "S:(ML;;NWNR;;;ME)";
const OTHER: &str = "S-1-5-21-1-2-3-1001";

/// Runs `work` on its own thread and fails if it has not ended in time.
fn within<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> T {
    let (done, result) = mpsc::channel();
    thread::spawn(move || done.send(work()));
    let limit = Duration::from_secs(30);
    result
        .recv_timeout(limit)
        .expect("the test hung or panicked")
}

fn unique(tag: &str) -> String {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let (id, n) = (std::process::id(), NEXT.fetch_add(1, Ordering::SeqCst));
    format!("ubc-vpn-test-{tag}-{id}-{n}")
}

fn skip(what: &str) {
    let required = std::env::var_os("UBC_VPN_REQUIRE_ELEVATED").is_some();
    assert!(!required, "{what}, and this run requires it");
    println!("SKIPPED: {what}");
}

fn transport(mode: Mode) -> PipeTransport {
    let me = process_user().expect("the current user");
    PipeTransport { mode, me }
}

/// The installed transport, when this process may serve its pipe.
fn installed() -> Option<PipeTransport> {
    let service = transport(Mode::Installed);
    let refused = service.listener(&unique("probe")).err();
    // Security rule: an unprivileged process cannot serve the installed pipe.
    let refused = refused.inspect(|error| assert_eq!(*error, Error::PermissionDenied));
    if refused.is_some() {
        skip("serving the installed pipe needs an elevated process");
    }
    refused.is_none().then_some(service)
}

/// Runs `test` once for each mode this build and this process can serve.
fn each(test: fn(PipeTransport)) {
    #[cfg(feature = "dev-mode")]
    within(move || test(transport(Mode::Dev)));
    if let Some(service) = installed() {
        within(move || test(service));
    }
}

fn pair(transport: &PipeTransport, listener: &PipeListener) -> (Connection, Connection, UserId) {
    let client = transport.connect(&listener.name()).expect("connect");
    let (server, caller) = listener.accept().expect("accept");
    (client, server, caller)
}

impl PipeListener {
    fn name(&self) -> String {
        let path = String::from_utf16_lossy(&self.path);
        path.trim_end_matches('\0')
            .rsplit('\\')
            .next()
            .unwrap()
            .to_string()
    }
}

/// Opens `path` as a client would, or reports the Windows error code.
fn open(path: &str, access: u32, flags: u32) -> std::result::Result<Handle, u32> {
    let path = wide(path);
    // SAFETY: `path` is NUL-terminated and outlives the call; the optional
    // pointers are null.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            access,
            7,
            null(),
            OPEN_EXISTING,
            flags,
            null_mut(),
        )
    };
    match handle {
        INVALID_HANDLE_VALUE => Err(last_error()),
        handle => Ok(Handle(handle)),
    }
}

/// A security descriptor's owner and access list as Windows prints them.
fn text_of(descriptor: PSECURITY_DESCRIPTOR) -> String {
    let mut text = null_mut();
    // SAFETY: the descriptor is valid and the out pointer is valid; the
    // length out-parameter may be null.
    let ok = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            SDDL_REVISION_1,
            WHAT,
            &mut text,
            null_mut(),
        )
    };
    assert_ne!(ok, 0);
    // SAFETY: on success `text` is NUL-terminated, so every offset up to the
    // NUL is readable.
    let len = (0..).find(|at| unsafe { *text.add(*at) } == 0).unwrap();
    // SAFETY: those `len` code units were just read.
    let printed = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, len) });
    // SAFETY: the API allocated `text` for the caller to free this way.
    unsafe { windows_sys::Win32::Foundation::LocalFree(text.cast()) };
    printed
}

/// The descriptor actually on the pipe behind `handle`.
fn on_pipe(handle: HANDLE) -> String {
    let mut descriptor = null_mut();
    // SAFETY: the handle is open with READ_CONTROL and the one out pointer
    // asked for is valid.
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            WHAT,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            &mut descriptor,
        )
    };
    assert_eq!(status, 0);
    let printed = text_of(descriptor);
    // SAFETY: the API allocated the descriptor for the caller to free.
    unsafe { windows_sys::Win32::Foundation::LocalFree(descriptor) };
    printed
}

/// A second, ordinary user, logged on for the length of a test.
struct Stranger {
    token: Handle,
    sid: String,
}

fn stranger() -> Option<Stranger> {
    let var = |name| std::env::var(name).ok().map(|value| wide(&value));
    let both = var("UBC_VPN_TEST_USER").zip(var("UBC_VPN_TEST_PASSWORD"));
    let Some((user, password)) = both else {
        skip("no second user was provided");
        return None;
    };
    let (mut token, here) = (null_mut(), wide("."));
    let (kind, provider) = (LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT);
    // SAFETY: the three strings are NUL-terminated and outlive the call, and
    // the out pointer is valid.
    let ok = unsafe {
        LogonUserW(
            user.as_ptr(),
            here.as_ptr(),
            password.as_ptr(),
            kind,
            provider,
            &mut token,
        )
    };
    assert_ne!(ok, 0, "logging the second user on failed: {}", last_error());
    let token = Handle(token);
    let sid = token_user(&token).expect("the second user's SID");
    Some(Stranger { token, sid })
}

impl Stranger {
    /// Runs `work` on a thread that acts as this user.
    fn run<T: Send>(&self, work: impl FnOnce() -> T + Send) -> T {
        let acting = || {
            // SAFETY: the token is an open logon token; this changes only the
            // identity of this short-lived thread.
            assert_ne!(unsafe { ImpersonateLoggedOnUser(self.token.0) }, 0);
            let result = work();
            // SAFETY: no preconditions; affects only this thread.
            assert_ne!(unsafe { RevertToSelf() }, 0);
            result
        };
        thread::scope(|scope| {
            scope
                .spawn(acting)
                .join()
                .expect("the second user's thread")
        })
    }
}

/// This process's own user, at low integrity: what a sandboxed program of
/// that user runs as. Lowering one's own level needs no privilege.
fn low_integrity() -> Stranger {
    let (mut own, mut copy, mut low) = (null_mut(), null_mut(), null_mut());
    let level = wide("S-1-16-4096");
    // SAFETY: the pseudo-handle is always valid, the out pointers are valid,
    // and `level` is NUL-terminated.
    let ok = unsafe {
        OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &mut own) != 0
            && DuplicateTokenEx(
                own,
                TOKEN_ALL_ACCESS,
                null(),
                2,
                TokenImpersonation,
                &mut copy,
            ) != 0
            && ConvertStringSidToSidW(level.as_ptr(), &mut low) != 0
    };
    assert!(ok, "copying the process token failed: {}", last_error());
    let (_own, token) = (Handle(own), Handle(copy));
    let mut label = TOKEN_MANDATORY_LABEL::default();
    label.Label.Sid = low;
    label.Label.Attributes = 0x20; // SE_GROUP_INTEGRITY
    let size = size_of::<TOKEN_MANDATORY_LABEL>() as u32 + 12;
    // SAFETY: `label` and the SID it points to are valid for the call.
    let ok = unsafe {
        SetTokenInformation(
            token.0,
            TokenIntegrityLevel,
            (&raw const label).cast(),
            size,
        )
    };
    assert_ne!(
        ok,
        0,
        "lowering the integrity level failed: {}",
        last_error()
    );
    // SAFETY: the API allocated the SID for the caller to free this way.
    unsafe { windows_sys::Win32::Foundation::LocalFree(low) };
    let sid = token_user(&token).unwrap();
    Stranger { token, sid }
}

// Security rule: a low-integrity program of an admitted user cannot attach,
// not even to listen to what the service sends. Windows alone would only stop
// it writing.
#[test]
fn a_low_integrity_program_cannot_even_read() {
    each(|transport| {
        let listener = transport.listener(&unique("low")).unwrap();
        let path = format!(r"\\.\pipe\{}", listener.name());
        let low = low_integrity();
        let read_only = 0x0012_0089; // FILE_GENERIC_READ
        for access in [read_only, CONNECT_RIGHTS] {
            let attached = low.run(|| open(&path, access, CLIENT_FLAGS).map(drop));
            assert_eq!(attached, Err(5), "{access:#x}");
        }
        // The same open at this process's own level gets in, so it was the
        // integrity level that refused.
        open(&path, read_only, CLIENT_FLAGS).expect("the same user, not lowered");
    });
}

/// CI searches the log for these lines to prove that the tests which can
/// be skipped ran.
fn ran(test: &str) {
    println!("RAN: {test}");
}

// The whole contract, with a real second user. It runs against the installed
// descriptor: the suite needs a second user to get in before the channel is
// narrowed, which dev mode never allows.
#[test]
fn passes_the_shared_suite_with_a_second_user() {
    let Some((service, stranger)) = installed().zip(stranger()) else {
        return;
    };
    within(move || {
        let as_stranger = |name: &str| stranger.run(|| service.connect(name));
        suite::check_transport(&service, &unique("suite"), &as_stranger);
        ran("suite");
    });
}

// Security rules: the caller is the user Windows reports, whatever they
// write; once narrowed, the owner gets in and others do not.
#[test]
fn each_user_is_reported_by_their_own_sid_and_narrowing_follows_the_owner() {
    let Some((service, stranger)) = installed().zip(stranger()) else {
        return;
    };
    within(move || {
        let listener = service.listener(&unique("users")).unwrap();
        let name = listener.name();
        let call = || stranger.run(|| service.connect(&name));
        let client = call().expect("the second user connects");
        client
            .write_line(&format!("{{\"user\":\"{}\"}}", service.me))
            .unwrap();
        let (_server, caller) = listener.accept().unwrap();
        assert_eq!(caller.to_string(), stranger.sid);
        assert_ne!(stranger.sid, service.me);
        assert_eq!(pair(&service, &listener).2.to_string(), service.me);
        // A user who may connect may still not serve the pipe.
        let open_to_all = "D:P(A;;FA;;;WD)";
        let serving = stranger.run(|| create_instance(&listener.path, open_to_all, false).err());
        assert_eq!(serving, Some(Error::PermissionDenied));

        listener
            .restrict_to(&stranger.sid.parse().unwrap())
            .unwrap();
        assert_eq!(call().map(drop), Ok(()), "the owner was refused");
        listener.accept().unwrap();
        listener.restrict_to(&service.me.parse().unwrap()).unwrap();
        assert_eq!(call().err(), Some(Error::PermissionDenied));
        assert_eq!(pair(&service, &listener).2.to_string(), service.me);
        ran("users");
    });
}

// Security rules: a dev-mode pipe admits its own user and nobody else, even
// before it is narrowed, and no client takes another user's pipe for the
// service.
#[cfg(feature = "dev-mode")]
#[test]
fn dev_mode_admits_and_trusts_only_the_current_user() {
    let Some(stranger) = stranger() else { return };
    within(move || {
        let dev = transport(Mode::Dev);
        let listener = dev.listener(&unique("dev")).unwrap();
        let refused = stranger.run(|| dev.connect(&listener.name()).err());
        assert_eq!(refused, Some(Error::PermissionDenied));

        let squatted = unique("dev-squat");
        let path = pipe_path(&squatted).unwrap();
        let open_to_all = "D:P(A;;FA;;;WD)";
        let _theirs = stranger
            .run(|| create_instance(&path, open_to_all, true))
            .unwrap();
        let not_the_service = Some(Error::Failed(NOT_THE_SERVICE.to_string()));
        assert_eq!(dev.connect(&squatted).err(), not_the_service);
        ran("dev");
    });
}

// Security rule: one listener per name. Also: several callers at once, and
// closing the listener ends them and frees the name.
#[test]
fn a_name_has_one_listener_until_it_closes() {
    each(|transport| {
        let listener = transport.listener(&unique("one")).unwrap();
        let name = listener.name();
        assert_eq!(transport.listener(&name).err(), Some(Error::AlreadyExists));
        let pairs = [(); 3].map(|()| pair(&transport, &listener));
        for (client, server, caller) in &pairs {
            client.write_line("{\"user\":\"S-1-5-18\"}").unwrap();
            assert_eq!(caller.to_string(), transport.me);
            assert!(server.read_line().unwrap().is_some());
        }
        listener.close();
        let (client, server, _) = &pairs[0];
        assert_eq!(server.read_line(), Err(Error::Closed));
        assert_eq!(client.read_line(), Ok(None));
        assert_eq!(listener.accept().err(), Some(Error::Closed));
        assert_eq!(transport.connect(&name).err(), Some(Error::NotFound));
        transport.listener(&name).expect("the name is free again");
    });
}

// Security rule: while the service is down any user can create a pipe with
// its name. The service must not share it, and a client must not talk to it.
#[test]
fn a_squatted_name_is_refused_by_listen_and_by_connect() {
    within(|| {
        let (service, name) = (transport(Mode::Installed), unique("squat"));
        let path = pipe_path(&name).unwrap();
        // Owned by this user, who is not SYSTEM, and open to everyone.
        let squat = format!("O:{}D:P(A;;FA;;;WD)", service.me);
        let _squatter = [true, false].map(|first| create_instance(&path, &squat, first).unwrap());
        assert_eq!(service.listener(&name).err(), Some(Error::AlreadyExists));
        let refused = Some(Error::Failed(NOT_THE_SERVICE.to_string()));
        assert_eq!(service.connect(&name).err(), refused);
        // The same pipe passes where its owner is the expected one, so it
        // was the owner check that refused it.
        #[cfg(feature = "dev-mode")]
        transport(Mode::Dev)
            .connect(&name)
            .expect("dev mode expects this user");
    });
}

#[test]
fn only_a_privileged_owner_passes_for_the_service() {
    let (me, users, local_service) = (OTHER, "S-1-5-32-545", "S-1-5-19");
    for owner in ["S-1-5-18", "S-1-5-32-544"] {
        assert!(is_the_service(Mode::Installed, me, owner), "{owner}");
    }
    for owner in [me, users, local_service, "S-1-1-0", "S-1-5-180", ""] {
        assert!(!is_the_service(Mode::Installed, me, owner), "{owner}");
    }
    #[cfg(feature = "dev-mode")]
    for (owner, passes) in [(me, true), ("S-1-5-18", false), ("S-1-5-32-544", false)] {
        assert_eq!(is_the_service(Mode::Dev, me, owner), passes, "{owner}");
    }
}

// Security rule: the descriptors, spelled out. Nobody but SYSTEM and
// Administrators (or, in dev mode, the user) can create an instance or change
// the descriptor: a caller's rights contain neither.
#[test]
fn the_descriptors_are_exactly_these() {
    let owner: UserId = OTHER.parse().unwrap();
    let text = |mode, owner| sddl(mode, "S-1-5-21-9-9-9-500", owner).unwrap();
    let open = "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x12008b;;;IU)";
    assert_eq!(text(Mode::Installed, None), format!("{open}{LABEL}"));
    let narrowed = format!("O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x12008b;;;{OTHER}){LABEL}");
    assert_eq!(text(Mode::Installed, Some(&owner)), narrowed);
    #[cfg(feature = "dev-mode")]
    {
        let dev = "O:S-1-5-21-9-9-9-500D:P(A;;FA;;;S-1-5-21-9-9-9-500)";
        assert_eq!(text(Mode::Dev, None), format!("{dev}{LABEL}"));
        let narrowed = format!("{dev}(A;;0x12008b;;;{OTHER}){LABEL}");
        assert_eq!(text(Mode::Dev, Some(&owner)), narrowed);
    }
    let (create_instance, write_dac, write_owner) = (0x4, 0x4_0000, 0x8_0000);
    assert_eq!(
        CONNECT_RIGHTS & (create_instance | write_dac | write_owner),
        0
    );
    // Text that is not a SID could add entries of its own.
    for injected in ["WD", "S-1-1-0)(A;;FA;;;WD", "S-1-"] {
        let injected: UserId = injected.parse().unwrap();
        assert!(sddl(Mode::Installed, OTHER, Some(&injected)).is_err());
    }
    for name in ["", r"a\b", "a/b", "a b"] {
        assert!(pipe_path(name).is_err(), "{name:?}");
    }
}

// Security rule: the pipe really carries the intended descriptor, not the
// default one, before and after it is narrowed, on every instance.
#[test]
fn the_pipe_carries_its_descriptor_before_and_after_narrowing() {
    each(|transport| {
        let listener = transport.listener(&unique("descriptor")).unwrap();
        // Windows marks the label "auto-inherited" (AI) when it stores it,
        // which says nothing about who may do what.
        let actual = || {
            let free = lock(&listener.free).clone().unwrap();
            free.with_handle(on_pipe).unwrap().replace("S:AI(", "S:(")
        };
        let intended = |owner| {
            let text = sddl(transport.mode, &transport.me, owner).unwrap();
            text_of(Descriptor::parse(&text).unwrap().as_ptr())
        };
        assert_eq!(actual(), intended(None));
        let owner: UserId = OTHER.parse().unwrap();
        listener.restrict_to(&owner).unwrap();
        assert_eq!(actual(), intended(Some(&owner)));
        let _attached = pair(&transport, &listener);
        assert_eq!(actual(), intended(Some(&owner)), "a later instance");
    });
}

// Security rule: remote clients are rejected. The same pipe without the flag
// is reachable through the loopback network, which proves the flag is what
// refuses.
#[test]
fn a_caller_from_the_network_is_refused() {
    let served = within(|| {
        let open_to_all = Descriptor::parse("D:P(A;;FA;;;WD)").unwrap();
        let reach = |name: &str, mode| {
            let path = pipe_path(name).unwrap();
            let pipe = create_pipe(&path, &open_to_all, OPEN_MODE, mode).unwrap();
            let remote = format!(r"\\localhost\pipe\{name}");
            (open(&remote, CONNECT_RIGHTS, CLIENT_FLAGS).map(drop), pipe)
        };
        let (control, _pipe) = reach(&unique("lan"), PIPE_MODE & !PIPE_REJECT_REMOTE_CLIENTS);
        if control.is_err() {
            skip("this machine does not serve pipes over the loopback network");
            return false;
        }
        let (ours, _pipe) = reach(&unique("lan"), PIPE_MODE);
        assert_eq!(ours, Err(5), "a remote caller got in");
        true
    });
    // Without the loopback network every open below would fail, whatever
    // the listener did, so there is nothing to learn from them.
    if !served {
        return;
    }
    // The listener's own instances: the first, and one created by an accept.
    each(|transport| {
        let listener = transport.listener(&unique("lan")).unwrap();
        let remote = format!(r"\\localhost\pipe\{}", listener.name());
        let reach = || open(&remote, CONNECT_RIGHTS, CLIENT_FLAGS).map(drop);
        assert_eq!(
            reach(),
            Err(5),
            "a remote caller reached the first instance"
        );
        let _attached = pair(&transport, &listener);
        assert_eq!(reach(), Err(5), "a remote caller reached a later instance");
    });
    ran("remote");
}

// Security rules: a client that says nothing cannot hold a reader, and one
// that never reads cannot hold a writer.
#[test]
fn a_silent_or_deaf_peer_cannot_hold_the_other_end() {
    each(|transport| {
        let listener = transport.listener(&unique("timeouts")).unwrap();
        let (_client, server, _) = pair(&transport, &listener);
        server.set_read_timeout(Some(SHORT)).unwrap();
        let started = Instant::now();
        assert_eq!(server.read_line(), Err(Error::TimedOut));
        assert!(started.elapsed() >= SHORT - Duration::from_millis(20));

        server.set_write_timeout(Some(SHORT)).unwrap();
        let line = "a".repeat(MAX_LINE_BYTES - 1);
        let stopped = (0..8)
            .map(|_| server.write_line(&line))
            .find(|sent| sent.is_err());
        assert_eq!(stopped, Some(Err(Error::TimedOut)));
    });
}

#[test]
fn close_ends_a_blocked_read_write_and_accept() {
    each(|transport| {
        let listener = transport.listener(&unique("close")).unwrap();
        let (_client, server, _) = pair(&transport, &listener);
        let line = "a".repeat(MAX_LINE_BYTES - 1);
        thread::scope(|scope| {
            let reader = scope.spawn(|| server.read_line());
            let fill = || {
                (0..8)
                    .map(|_| server.write_line(&line))
                    .find(|sent| sent.is_err())
            };
            let writer = scope.spawn(fill);
            let accepting = scope.spawn(|| listener.accept().err());
            thread::sleep(SHORT);
            server.close();
            listener.close();
            assert_eq!(reader.join().unwrap(), Err(Error::Closed));
            assert_eq!(writer.join().unwrap(), Some(Err(Error::Closed)));
            assert_eq!(accepting.join().unwrap(), Some(Error::Closed));
        });
        // Afterwards nothing waits, also below the line layer.
        assert_eq!(server.raw().read(&mut [0; 8]), Err(Error::Closed));
        assert_eq!(server.raw().write_all(b"late"), Err(Error::Closed));
    });
}

// The service pushes events while it waits for the next request.
#[test]
fn a_blocked_read_does_not_hold_up_a_write() {
    each(|transport| {
        let listener = transport.listener(&unique("duplex")).unwrap();
        let (client, server, _) = pair(&transport, &listener);
        thread::scope(|scope| {
            let reader = scope.spawn(|| server.read_line());
            thread::sleep(SHORT);
            server.write_line("event").unwrap();
            assert_eq!(client.read_line(), Ok(Some("event".to_string())));
            client.write_line("request").unwrap();
            assert_eq!(reader.join().unwrap(), Ok(Some("request".to_string())));
        });
    });
}

/// Why this thread has no identity of its own to open, or `None` if it has
/// one, which means it is acting as somebody else.
fn no_borrowed_identity() -> Option<u32> {
    let mut token = null_mut();
    // SAFETY: the pseudo-handle is always valid and the out pointer is valid.
    let ok = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) };
    if ok != 0 {
        drop(Handle(token));
        return None;
    }
    Some(last_error())
}

// Security rule: the service thread never goes on running as the client.
#[test]
fn accept_leaves_the_thread_with_its_own_identity() {
    each(|transport| {
        let listener = transport.listener(&unique("revert")).unwrap();
        let _attached = pair(&transport, &listener);
        assert_eq!(no_borrowed_identity(), Some(ERROR_NO_TOKEN));
    });
}

// Security rule: a client lends the server its name and nothing more. This
// server passes the client's check, then tries to open a file as the client.
#[test]
fn a_server_learns_who_calls_but_cannot_act_as_them() {
    each(|transport| {
        let name = unique("lend");
        let descriptor = sddl(transport.mode, &transport.me, None).unwrap();
        let server = create_instance(&pipe_path(&name).unwrap(), &descriptor, true).unwrap();
        let _client = transport.connect(&name).unwrap();
        let program = std::env::current_exe().unwrap();
        let read = 0x8000_0000;
        let attempt = server.with_handle(|handle| {
            // SAFETY: the handle is an open, connected server end.
            assert_ne!(unsafe { ImpersonateNamedPipeClient(handle) }, 0);
            let opened = open(program.to_str().unwrap(), read, 0).map(drop);
            // SAFETY: no preconditions; affects only this thread.
            assert_ne!(unsafe { RevertToSelf() }, 0);
            opened
        });
        assert_eq!(attempt, Ok(Err(ERROR_BAD_IMPERSONATION_LEVEL)));
        assert_eq!(
            server
                .with_handle(security::pipe_client)
                .unwrap()
                .unwrap()
                .to_string(),
            transport.me
        );
    });
}

// A caller that hides its identity is dropped, and does not end the accept.
#[test]
fn a_caller_who_hides_is_dropped_and_the_next_is_served() {
    each(|transport| {
        let listener = transport.listener(&unique("hidden")).unwrap();
        let path = format!(r"\\.\pipe\{}", listener.name());
        let anonymous = FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT;
        let _hidden = open(&path, CONNECT_RIGHTS, anonymous).expect("open anonymously");
        thread::scope(|scope| {
            let accepted = scope.spawn(|| listener.accept());
            let client = transport.connect(&listener.name()).unwrap();
            let (server, caller) = accepted.join().unwrap().unwrap();
            assert_eq!(caller.to_string(), transport.me);
            // The connection handed out is the real caller's, not the hidden
            // one's under somebody's name.
            client.write_line("from the real caller").unwrap();
            server.set_read_timeout(Some(SHORT * 10)).unwrap();
            let line = server.read_line();
            assert_eq!(line, Ok(Some("from the real caller".to_string())));
        });
    });
}

#[test]
fn paths_follow_the_table_and_ignore_the_environment() {
    let me = process_user().unwrap();
    let before = paths(Mode::Installed, &me).unwrap();
    assert_eq!(before.channel_name, "ubc-vpn");
    assert_eq!(before.policy_dir, before.state_dir);
    assert_ne!(before.policy_dir, before.settings_dir);
    for dir in [&before.policy_dir, &before.settings_dir] {
        assert!(dir.is_absolute() && dir.ends_with("UBC VPN"), "{dir:?}");
        assert!(dir.parent().unwrap().is_dir(), "{dir:?}");
    }
    // Whoever starts the service chooses its environment, so the folders
    // only an administrator may write are not looked up there. (The settings
    // folder is the caller's own, wherever Windows says their profile is.)
    for variable in ["ProgramData", "ALLUSERSPROFILE"] {
        // SAFETY: Windows guards the environment block with its own lock, and
        // no other test reads these variables.
        unsafe { std::env::set_var(variable, r"C:\attacker") };
    }
    let after = paths(Mode::Installed, &me).unwrap();
    assert_eq!(
        (after.policy_dir, after.state_dir),
        (before.policy_dir.clone(), before.state_dir.clone())
    );
    #[cfg(feature = "dev-mode")]
    {
        let dev = paths(Mode::Dev, &me).unwrap();
        suite::check_paths(&before, &dev);
        assert!(dev.channel_name.ends_with(&me) && dev.policy_dir.is_absolute());
        assert!(!dev.policy_dir.starts_with(r"C:\attacker"));
    }
}
