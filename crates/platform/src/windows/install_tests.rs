//! Installing and removing, for real, under throwaway names: a service that
//! is this test program running its `hosted` test (see `service_tests.rs`),
//! and a data folder in ProgramData named after this run. Both need an
//! elevated process; without one the test is skipped with a message, unless
//! `UBC_VPN_REQUIRE_ELEVATED` is set, as it is in CI.

use std::path::PathBuf;

use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW, SDDL_REVISION_1,
};
use windows_sys::Win32::System::Services::{
    QUERY_SERVICE_CONFIGW, QueryServiceConfig2W, QueryServiceConfigW, QueryServiceObjectSecurity,
    SERVICE_START_PENDING,
};

use super::*;
use crate::Mode;

thread_local! {
    /// Makes `configure` fail on this thread, as a real failure would.
    pub(super) static FAIL_CONFIGURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Whether this run may register services and write under ProgramData:
/// only on CI, and only elevated. Says why not when it may not.
fn may_change_the_system() -> bool {
    if std::env::var_os("CI").is_none() {
        println!("SKIPPED: it changes ProgramData and the services, so it runs on CI only");
        return false;
    }
    if manager(SC_MANAGER_CREATE_SERVICE).is_err() {
        let required = std::env::var_os("UBC_VPN_REQUIRE_ELEVATED").is_some();
        assert!(
            !required,
            "registering a service needs an elevated process, and this run requires it"
        );
        println!("SKIPPED: registering a service needs an elevated process");
        return false;
    }
    true
}

/// The owner and access list of `path`, as SDDL.
fn security(path: &Path) -> String {
    let name = wide(&path.to_string_lossy());
    let what = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    let mut descriptor = null_mut();
    // SAFETY: the name is NUL-terminated; only the descriptor is asked for.
    let status = unsafe {
        GetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            what,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            &mut descriptor,
        )
    };
    assert_eq!(status, 0, "reading the security of {}", path.display());
    let mut text = null_mut();
    // SAFETY: the descriptor is valid; the out pointer is valid and the
    // length may be null.
    let ok = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            SDDL_REVISION_1,
            what,
            &mut text,
            null_mut(),
        )
    };
    assert_ne!(ok, 0);
    // SAFETY: the text is NUL-terminated, so every offset to the NUL is
    // readable; both allocations are the caller's to free.
    let sddl = unsafe {
        let len = (0..).find(|at| *text.add(*at) == 0).unwrap_or(0);
        let sddl = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
        LocalFree(text.cast());
        LocalFree(descriptor);
        sddl
    };
    // Windows adds that the list was set with inheritance in mind.
    sddl.replace("D:PAI(", "D:P(")
}

/// The registered command line, start type and account of `name`, and its
/// pre-shutdown timeout.
fn config(name: &str) -> (String, u32, String, u32) {
    let manager = manager(SC_MANAGER_CONNECT).unwrap();
    let service = open_service(&manager, name).unwrap().expect("registered");
    let mut buffer = vec![0u64; 1024];
    let mut needed = 0;
    let config = buffer.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>();
    // SAFETY: the buffer is 8 KiB, aligned for the structure, and the out
    // pointer is valid.
    let ok = unsafe { QueryServiceConfigW(service.0, config, 8192, &mut needed) };
    assert_ne!(ok, 0, "querying the service: {}", last_error());
    let text = |p: *mut u16| {
        // SAFETY: the strings the call filled in are NUL-terminated and live
        // in the buffer.
        unsafe {
            let len = (0..).find(|at| *p.add(*at) == 0).unwrap_or(0);
            String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
        }
    };
    // SAFETY: the call filled in the structure.
    let (command, start, account) = unsafe {
        (
            text((*config).lpBinaryPathName),
            (*config).dwStartType,
            text((*config).lpServiceStartName),
        )
    };
    let mut shutdown = SERVICE_PRESHUTDOWN_INFO::default();
    // SAFETY: the out buffer is the structure this level fills in.
    let ok = unsafe {
        QueryServiceConfig2W(
            service.0,
            SERVICE_CONFIG_PRESHUTDOWN_INFO,
            (&raw mut shutdown).cast(),
            size_of::<SERVICE_PRESHUTDOWN_INFO>() as u32,
            &mut needed,
        )
    };
    assert_ne!(ok, 0);
    (command, start, account, shutdown.dwPreshutdownTimeout)
}

/// The rights the service's own access list gives anyone who is not
/// SYSTEM, an administrator or the service itself, beyond asking about it:
/// querying its status and settings, enumerating, interrogating, sending a
/// user-defined control, and reading the access list. The list is left as
/// Windows makes it, so this should be empty: ordinary users can neither
/// start nor stop the service, nor change it.
fn ordinary_rights(name: &str) -> Vec<String> {
    let manager = manager(SC_MANAGER_CONNECT).unwrap();
    let service = open_service(&manager, name).unwrap().expect("registered");
    let mut buffer = vec![0u64; 1024];
    let mut needed = 0;
    // SAFETY: the buffer is 8 KiB and aligned, and the out pointer is valid.
    let ok = unsafe {
        QueryServiceObjectSecurity(
            service.0,
            DACL_SECURITY_INFORMATION,
            buffer.as_mut_ptr().cast(),
            8192,
            &mut needed,
        )
    };
    assert_ne!(ok, 0, "reading the service's access list: {}", last_error());
    let mut text = null_mut();
    // SAFETY: the buffer holds a valid descriptor; the out pointer is valid
    // and the length may be null.
    let ok = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            buffer.as_mut_ptr().cast(),
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &mut text,
            null_mut(),
        )
    };
    assert_ne!(ok, 0);
    // SAFETY: the text is NUL-terminated and the caller's to free.
    let sddl = unsafe {
        let len = (0..).find(|at| *text.add(*at) == 0).unwrap_or(0);
        let sddl = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
        LocalFree(text.cast());
        sddl
    };
    println!("service access list: {sddl}");
    let trusted = ["SY", "BA", "S-1-5-18", "S-1-5-32-544"];
    let harmless = ["CC", "LC", "SW", "LO", "CR", "RC"];
    let mut found = Vec::new();
    for entry in sddl.split('(').skip(1) {
        let fields: Vec<&str> = entry.trim_end_matches(')').split(';').collect();
        let (kind, rights, sid) = (fields[0], fields[2], fields[5]);
        // Entries for the service's own SID, if any, are its own business.
        if kind != "A" || trusted.contains(&sid) || sid.starts_with("S-1-5-80-") {
            continue;
        }
        let pairs = rights
            .as_bytes()
            .chunks(2)
            .map(|p| String::from_utf8_lossy(p).into_owned());
        found.extend(
            pairs
                .filter(|right| !harmless.contains(&right.as_str()))
                .map(|right| format!("{sid}: {right}")),
        );
    }
    found
}

fn is_registered(name: &str) -> bool {
    let manager = manager(SC_MANAGER_CONNECT).unwrap();
    open_service(&manager, name).unwrap().is_some()
}

fn status(name: &str) -> u32 {
    let manager = manager(SC_MANAGER_CONNECT).unwrap();
    let service = open_service(&manager, name).unwrap().expect("registered");
    state_of(&service).unwrap().dwCurrentState
}

/// Removes what a failed run left.
struct Cleanup(String, PathBuf);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = unregister(&self.0);
        let _ = remove_data_folder(&self.1);
        // The marker the hosted service leaves when it stops.
        let program = std::env::current_exe().unwrap();
        let _ = std::fs::remove_file(program.with_file_name(format!("{}.cleaned-up", self.0)));
    }
}

#[test]
fn quotes_the_path_and_refuses_what_cannot_be() {
    let path = Path::new(r"C:\Program Files\UBC VPN\resources\bin\ubc-vpn-service.exe");
    assert_eq!(
        quoted(path).unwrap(),
        r#""C:\Program Files\UBC VPN\resources\bin\ubc-vpn-service.exe""#
    );
    assert!(quoted(Path::new("ubc-vpn-service.exe")).is_err());
    assert!(quoted(Path::new(r#"C:\a"b\ubc-vpn-service.exe"#)).is_err());
}

// The whole cycle, as the setup program drives it: a fresh install over a
// folder someone made first, an update that keeps the state, and an
// uninstall that keeps or removes the data.
#[test]
fn installs_updates_and_uninstalls() {
    if !may_change_the_system() {
        return;
    }
    let name = format!("ubc-vpn-test-install-{}", std::process::id());
    let program_data = std::env::var_os("ProgramData").expect("ProgramData is set");
    let data = Path::new(&program_data).join(&name);
    let _cleanup = Cleanup(name.clone(), data.clone());

    // Someone made the folder before the first install and left a file.
    std::fs::create_dir_all(&data).unwrap();
    std::fs::write(data.join("state.json"), b"planted").unwrap();
    prepare_data_folder(&data, true).unwrap();
    assert!(
        !data.join("state.json").exists(),
        "a fresh install kept what it found"
    );
    assert_eq!(security(&data), DATA_FOLDER_SDDL);
    // The service's own check of its state folder accepts it.
    super::super::state::check_folder(Mode::Installed, &data).unwrap();

    let policy = br#"{"gateway":"vpn.example.test","pins":["pin-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="]}"#;
    write_policy(&data, policy).unwrap();
    assert_eq!(std::fs::read(data.join(POLICY)).unwrap(), policy);
    assert_eq!(security(&data.join(POLICY)), POLICY_SDDL);
    assert!(!data.join("policy.json.new").exists());

    // The check at the end of the folder's setup: it passes as made, and a
    // fresh install refuses anything else in the folder, as something made
    // in the moment between removing and making it again would be.
    verify_data_folder(&data, true).unwrap();
    std::fs::write(data.join("planted.json"), b"{}").unwrap();
    let why = verify_data_folder(&data, true).unwrap_err().to_string();
    assert!(why.contains("planted.json"), "{why}");
    verify_data_folder(&data, false).unwrap();
    std::fs::remove_file(data.join("planted.json")).unwrap();

    // This test program, running only `hosted`, stands in for the service.
    let program = std::env::current_exe().unwrap();
    let module = module_path!().split_once("::").map_or("", |(_, rest)| rest);
    let hosted = module.replace("install::tests", "service::tests::hosted");
    let command_line = format!(
        "{} {hosted} --exact --nocapture --test-threads=1",
        quoted(&program).unwrap()
    );
    let registration = Registration {
        name: &name,
        display_name: "UBC VPN test service",
        description: "A test of UBC VPN's installer. Not made by or affiliated with UBC.",
        command_line: command_line.clone(),
    };
    register(&registration).unwrap();
    let (command, start_type, account, preshutdown) = config(&name);
    assert_eq!(command, command_line);
    assert_eq!(start_type, SERVICE_AUTO_START);
    assert_eq!(account, "LocalSystem");
    assert_eq!(preshutdown, PRESHUTDOWN_TIMEOUT_MS);
    assert_eq!(ordinary_rights(&name), Vec::<String>::new());
    start(&name).unwrap();
    assert_eq!(status(&name), SERVICE_RUNNING);

    // A user-defined control code (128, the first one) is not a stop: the
    // service turns it down and keeps running.
    {
        let manager = manager(SC_MANAGER_CONNECT).unwrap();
        let service = open_service(&manager, &name).unwrap().expect("registered");
        let mut answer = SERVICE_STATUS::default();
        // SAFETY: the handle is open with full access, and the out pointer
        // is valid.
        let sent = unsafe { ControlService(service.0, 128, &mut answer) };
        println!("control 128: {}", if sent == 0 { last_error() } else { 0 });
    }
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(status(&name), SERVICE_RUNNING);

    // An update: the state written meanwhile is kept, the folder's access
    // list is set again, and the running service is stopped and registered
    // again.
    std::fs::write(data.join("state.json"), b"{}").unwrap();
    prepare_data_folder(&data, false).unwrap();
    assert_eq!(std::fs::read(data.join("state.json")).unwrap(), b"{}");
    assert_eq!(security(&data), DATA_FOLDER_SDDL);
    write_policy(&data, policy).unwrap();
    register(&registration).unwrap();
    assert_eq!(status(&name), SERVICE_STOPPED);
    start(&name).unwrap();

    // An uninstall as part of an update keeps the data; a real one does not.
    unregister(&name).unwrap();
    assert!(!is_registered(&name) || status(&name) == SERVICE_STOPPED);
    assert!(data.join(POLICY).exists());
    unregister(&name).unwrap();
    remove_data_folder(&data).unwrap();
    assert!(!data.exists());
    remove_data_folder(&data).unwrap();
    println!("RAN: install");
}

// A service that is still starting takes no stop request. Removing it then
// waits until it does, and stops and removes it, instead of failing before
// it is removed.
#[test]
fn a_service_still_starting_is_stopped_and_removed() {
    if !may_change_the_system() {
        return;
    }
    // The hosted service takes a few seconds to start when its name says
    // "-slow-start-" (see `service_tests.rs`).
    let name = format!("ubc-vpn-test-slow-start-{}", std::process::id());
    let _cleanup = Cleanup(name.clone(), PathBuf::from("does-not-exist"));
    let program = std::env::current_exe().unwrap();
    let module = module_path!().split_once("::").map_or("", |(_, rest)| rest);
    let hosted = module.replace("install::tests", "service::tests::hosted");
    let registration = Registration {
        name: &name,
        display_name: "UBC VPN test service",
        description: "A test of UBC VPN's installer. Not made by or affiliated with UBC.",
        command_line: format!(
            "{} {hosted} --exact --nocapture --test-threads=1",
            quoted(&program).unwrap()
        ),
    };
    register(&registration).unwrap();
    {
        let manager = manager(SC_MANAGER_CONNECT).unwrap();
        let service = open_service(&manager, &name).unwrap().expect("registered");
        // SAFETY: the handle is open with full access, and no arguments are
        // passed.
        let ok = unsafe { StartServiceW(service.0, 0, null()) };
        assert_ne!(ok, 0, "starting the service: {}", last_error());
    }
    assert_eq!(status(&name), SERVICE_START_PENDING);
    unregister(&name).unwrap();
    // Deleting takes effect once it has stopped and no handle is open.
    let started = Instant::now();
    while is_registered(&name) {
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "the service was left registered"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    println!("RAN: install while starting");
}

// A service this run created, and could not then set up, is deleted, so a
// failed install never leaves a half set-up service behind.
#[test]
fn a_service_it_cannot_set_up_is_removed_again() {
    if !may_change_the_system() {
        return;
    }
    let name = format!("ubc-vpn-test-unconfigured-{}", std::process::id());
    let _cleanup = Cleanup(name.clone(), PathBuf::from("does-not-exist"));
    let program = std::env::current_exe().unwrap();
    let registration = Registration {
        name: &name,
        display_name: "UBC VPN test service",
        description: "A test of UBC VPN's installer. Not made by or affiliated with UBC.",
        command_line: quoted(&program).unwrap(),
    };
    FAIL_CONFIGURE.with(|fail| fail.set(true));
    let registered = register(&registration);
    FAIL_CONFIGURE.with(|fail| fail.set(false));
    assert!(registered.is_err());
    // Deleting takes effect once no handle is open; it was the only one.
    let started = Instant::now();
    while is_registered(&name) {
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "the service was left registered"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    println!("RAN: install unconfigured");
}
