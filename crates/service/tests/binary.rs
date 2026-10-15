//! The service binary itself, run as a program.
//!
//! Where the OS has a real channel the binary can really start, so nothing
//! here runs it in a way that should succeed. A run that does not end by
//! itself is a failure and is stopped, even if the test panics first.

use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use ubc_vpn_engine::DANGEROUS_VARIABLES;

/// A refusal is immediate, so a run still going after this is a failure, and
/// is not left running for long.
const LIMIT: Duration = Duration::from_secs(5);

/// The running program. Dropping it stops it.
struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Runs the binary with none of the forbidden variables but `set`, and none
/// that steers the loader: Cargo sets one of those for the tests it runs. Returns
/// whether it ended by itself with an error, and what it printed to standard
/// error. One that is still running at the limit is stopped.
fn run(args: &[&str], set: Option<&str>) -> (bool, String) {
    run_program(env!("CARGO_BIN_EXE_ubc-vpn-service").as_ref(), args, set)
}

/// The same, for a copy of the binary at `program`.
fn run_program(program: &std::path::Path, args: &[&str], set: Option<&str>) -> (bool, String) {
    let mut command = Command::new(program);
    for (name, _) in DANGEROUS_VARIABLES {
        command.env_remove(name);
    }
    let loader = |name: &std::ffi::OsString| {
        let name = name.to_string_lossy();
        name.starts_with("LD_") || name.starts_with("DYLD_")
    };
    for (name, _) in std::env::vars_os().filter(|(name, _)| loader(name)) {
        command.env_remove(name);
    }
    command.args(args).envs(set.map(|name| (name, "1")));
    command.stdin(Stdio::null()).stdout(Stdio::null());
    let mut running = Running(command.stderr(Stdio::piped()).spawn().unwrap());
    let started = Instant::now();
    let mut refused = false;
    while started.elapsed() < LIMIT {
        if let Some(status) = running.0.try_wait().unwrap() {
            refused = !status.success();
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let mut pipe = running.0.stderr.take().unwrap();
    // Stopped before its output is read, so the read cannot wait on it.
    drop(running);
    let mut stderr = String::new();
    pipe.read_to_string(&mut stderr).unwrap();
    (refused, stderr)
}

// Security rule (architecture): dev mode is compiled out of a build without
// the `dev-mode` feature, so such a build does not know the flag.
#[cfg(not(feature = "dev-mode"))]
#[test]
fn a_build_without_dev_mode_rejects_the_dev_flag() {
    let (refused, stderr) = run(&["--dev"], None);
    assert!(
        refused && stderr.contains("unknown argument: --dev"),
        "{stderr}"
    );
}

// With the feature the flag is known: the run gets past the arguments and is
// refused for the variable instead, at once and before anything starts.
#[cfg(feature = "dev-mode")]
#[test]
fn a_build_with_dev_mode_knows_the_dev_flag() {
    let (refused, stderr) = run(&["--dev"], Some("SSLKEYLOGFILE"));
    assert!(
        refused && stderr.contains("refusing to start while SSLKEYLOGFILE is set"),
        "{stderr}"
    );
    let (refused, stderr) = run(&["--dev", "--more"], Some("SSLKEYLOGFILE"));
    assert!(
        refused && stderr.contains("unknown argument: --more"),
        "{stderr}"
    );
}

// Security rule: a build with dev mode has the fake engine in it, so it
// never runs as the installed service, even with the real engine built in.
// It stops before it touches the system's folders or loads anything.
#[cfg(feature = "dev-mode")]
#[test]
fn a_build_with_dev_mode_never_runs_as_the_installed_service() {
    let (refused, stderr) = run(&[], None);
    let because = "a build with dev mode cannot run as the installed service";
    assert!(refused && stderr.contains(because), "{stderr}");
}

// A build without the real engine has nothing to connect with, and says so
// instead of starting. On Windows a run from a console stops earlier, because
// only the service manager starts the installed service; that is tested by
// on_windows_the_installed_service_needs_the_service_manager.
#[cfg(all(not(feature = "real-engine"), not(feature = "dev-mode"), not(windows)))]
#[test]
fn a_build_without_the_real_engine_does_not_run_as_the_installed_service() {
    let (refused, stderr) = run(&[], None);
    assert!(refused && stderr.contains("no VPN engine"), "{stderr}");
}

// Security rule: the service does not start while a variable is set that
// makes a TLS library write out session keys or weaken its settings.
#[test]
fn refuses_to_start_while_a_tls_variable_is_set() {
    // The four the service has always refused, spelled out so that dropping
    // one from the engine's list is noticed here too.
    let always = [
        "SSLKEYLOGFILE",
        "GNUTLS_KEYLOGFILE",
        "GNUTLS_SYSTEM_PRIORITY_FILE",
        "GNUTLS_DEBUG_LEVEL",
    ];
    let names: Vec<&str> = DANGEROUS_VARIABLES.iter().map(|(name, _)| *name).collect();
    assert!(always.iter().all(|name| names.contains(name)), "{names:?}");
    for name in names {
        let (refused, stderr) = run(&[], Some(name));
        let because = format!("refusing to start while {name} is set");
        assert!(refused && stderr.contains(&because), "{stderr}");
    }
}

// Security rule, macOS and Linux: the installed service does not start while
// a variable that steers the system loader is set, and does not repeat the
// variable's name, which whoever set it chose.
#[cfg(unix)]
#[test]
fn refuses_to_start_while_a_loader_variable_is_set() {
    // Names the loader itself does nothing with when the value is no path.
    for name in ["LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH", "LD_ANYTHING"] {
        let (refused, stderr) = run(&[], Some(name));
        let because = "refusing to start while a variable that steers the system loader is set";
        assert!(refused && stderr.contains(because), "{name}: {stderr}");
        assert!(!stderr.contains(name), "{stderr}");
    }
}

// On Windows the installed service runs only under the service manager. Run
// from a console, from a folder only administrators may change, it stops at
// once and says so, before it opens anything. A build with dev mode stops
// even before that (see the test above).
#[cfg(all(windows, not(feature = "dev-mode")))]
#[test]
fn on_windows_the_installed_service_needs_the_service_manager() {
    let Some(program) = safe_copy("needs-manager") else {
        return;
    };
    let (refused, stderr) = run_program(&program, &[], None);
    let _ = std::fs::remove_dir_all(program.parent().unwrap());
    assert!(
        refused && stderr.contains("started by the service manager"),
        "{stderr}"
    );
}

/// A copy of the binary in a new folder under ProgramData that only SYSTEM
/// and the administrators may change, or nothing, with a message, when this
/// process may not make one: making Administrators the owner needs an
/// elevated process. CI's Windows runners are elevated, and only they run it.
#[cfg(all(windows, not(feature = "dev-mode")))]
fn safe_copy(tag: &str) -> Option<std::path::PathBuf> {
    // It writes under ProgramData, which only CI runners may have changed.
    if std::env::var_os("CI").is_none() {
        println!("SKIPPED: it changes ProgramData, so it runs on CI only");
        return None;
    }
    let program_data = std::env::var_os("ProgramData").expect("ProgramData is set");
    let folder = std::path::Path::new(&program_data)
        .join(format!("ubc-vpn-test-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&folder).unwrap();
    let program = folder.join("ubc-vpn-service.exe");
    std::fs::copy(env!("CARGO_BIN_EXE_ubc-vpn-service"), &program).unwrap();
    let icacls = |args: &[&str]| {
        let mut icacls = Command::new("icacls");
        icacls.arg(&folder).args(args).stdout(Stdio::null());
        icacls.status().unwrap().success()
    };
    let secured = icacls(&["/setowner", "*S-1-5-32-544", "/T", "/Q"])
        && icacls(&[
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F",
            "*S-1-5-32-545:(OI)(CI)RX",
            "/Q",
        ]);
    // The copy inherits just that, as an installed file does.
    let reset = Command::new("icacls")
        .arg(&program)
        .args(["/reset", "/Q"])
        .stdout(Stdio::null())
        .status()
        .unwrap();
    let secured = secured && reset.success();
    if !secured {
        let _ = std::fs::remove_dir_all(&folder);
        println!("SKIPPED: a folder only administrators may change needs an elevated process");
        return None;
    }
    Some(program)
}

// Security rule (architecture): on Windows the installed service does not
// run from a folder that others could change. A copy in a folder every user
// may change is refused at once, before anything else is opened. (A build
// with dev mode is refused before that, whatever its folder.)
#[cfg(all(windows, not(feature = "dev-mode")))]
#[test]
fn on_windows_the_installed_service_refuses_a_folder_others_could_change() {
    let folder = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("open-to-all-{}", std::process::id()));
    std::fs::create_dir_all(&folder).unwrap();
    // Every user gets full control of the folder and what is in it.
    let granted = Command::new("icacls")
        .arg(&folder)
        .args(["/grant", "*S-1-5-32-545:(OI)(CI)F", "/Q"])
        .status()
        .unwrap();
    assert!(granted.success());
    let program = folder.join("ubc-vpn-service.exe");
    std::fs::copy(env!("CARGO_BIN_EXE_ubc-vpn-service"), &program).unwrap();
    let (refused, stderr) = run_program(&program, &[], None);
    let _ = std::fs::remove_dir_all(&folder);
    assert!(
        refused && stderr.contains("folder is not safe to use"),
        "{stderr}"
    );
}

/// A 64-bit Windows program, read for what its headers say about loading.
#[cfg(all(windows, target_env = "msvc"))]
struct Image(Vec<u8>);

#[cfg(all(windows, target_env = "msvc"))]
impl Image {
    fn read(program: &std::path::Path) -> Self {
        let image = Self(std::fs::read(program).unwrap());
        let pe = image.u32_at(0x3c) as usize;
        assert_eq!(&image.0[pe..pe + 4], b"PE\0\0", "not a Windows program");
        assert_eq!(
            image.u16_at(image.optional()),
            0x20b,
            "not a 64-bit program"
        );
        image
    }

    fn u16_at(&self, at: usize) -> u16 {
        u16::from_le_bytes([self.0[at], self.0[at + 1]])
    }

    fn u32_at(&self, at: usize) -> u32 {
        u32::from_le_bytes(self.0[at..at + 4].try_into().unwrap())
    }

    /// Where the optional header starts, after the signature and COFF header.
    fn optional(&self) -> usize {
        self.u32_at(0x3c) as usize + 4 + 20
    }

    /// The file offset of data directory `index`: its start and size. A
    /// 64-bit program's directories start 112 bytes into its optional header.
    fn directory(&self, index: usize) -> (usize, u32) {
        let entry = self.optional() + 112 + index * 8;
        let (rva, size) = (self.u32_at(entry), self.u32_at(entry + 4));
        assert!(size > 0, "the program has no data directory {index}");
        (self.offset(rva), size)
    }

    /// The file offset of a relative virtual address.
    fn offset(&self, rva: u32) -> usize {
        let coff = self.u32_at(0x3c) as usize + 4;
        let sections = usize::from(self.u16_at(coff + 2));
        let table = self.optional() + usize::from(self.u16_at(coff + 16));
        for section in (0..sections).map(|n| table + n * 40) {
            let (length, address, raw) = (
                self.u32_at(section + 8),
                self.u32_at(section + 12),
                self.u32_at(section + 20),
            );
            if (address..address + length).contains(&rva) {
                return (rva - address + raw) as usize;
            }
        }
        panic!("address {rva:#x} is in no section");
    }

    /// `DependentLoadFlags` from the load configuration (directory 10): where
    /// Windows looks for the DLLs the program imports. It sits at offset 78
    /// of IMAGE_LOAD_CONFIG_DIRECTORY64, whose first field is its size.
    fn dependent_load_flags(&self) -> u16 {
        let (config, _) = self.directory(10);
        assert!(
            self.u32_at(config) >= 80,
            "the load configuration is too short"
        );
        self.u16_at(config + 78)
    }
}

// Security rule: the program's own imports come from System32 only, never
// from its folder, the working folder or PATH (build.rs).
#[cfg(all(windows, target_env = "msvc"))]
#[test]
fn imports_are_loaded_from_system32_only() {
    let program = Image::read(std::path::Path::new(env!("CARGO_BIN_EXE_ubc-vpn-service")));
    assert_eq!(program.dependent_load_flags(), 0x800);
}
