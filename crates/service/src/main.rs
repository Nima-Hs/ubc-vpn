//! The privileged service. It opens the tunnel, applies routes and DNS,
//! verifies them, and cleans up. All of that lives in the library; this file
//! only chooses the parts and starts it.

use std::process::ExitCode;
use std::sync::Arc;

use ubc_vpn_engine::TunnelEngine;
use ubc_vpn_platform::{Platform, StateDir};
use ubc_vpn_service::args::{self, Command, Run};
use ubc_vpn_service::{Service, Timeouts};

type Parts = (Platform, StateDir, Arc<dyn TunnelEngine>);

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("ubc-vpn-service: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mode = match args::command(std::env::args_os().skip(1))? {
        Command::Run(mode) => mode,
        // Run by the setup program, as an administrator, with the same
        // checks of the environment as the service.
        Command::Install { policy, fresh } => {
            args::check_environment(Run::Installed)?;
            return setup::install(&policy, fresh);
        }
        Command::Uninstall { keep_data } => {
            args::check_environment(Run::Installed)?;
            return setup::uninstall(keep_data);
        }
    };
    args::check_environment(mode)?;
    // A build with dev mode has the fake engine in it and never runs as the
    // installed service. Said here, before anything else and before the
    // service manager is joined, as well as where the engine is chosen.
    if mode == Run::Installed && cfg!(feature = "dev-mode") {
        return Err("a build with dev mode cannot run as the installed service".to_string());
    }
    // The installed service runs only from a folder that no one but SYSTEM,
    // the Administrators and TrustedInstaller could change, held so that
    // it cannot be swapped while the service runs.
    #[cfg(windows)]
    let _folder = match mode {
        Run::Installed => Some(program_folder()?),
        #[cfg(feature = "dev-mode")]
        Run::Dev => None,
    };
    // On Windows the installed service is started by the service manager,
    // and stops when it asks.
    #[cfg(windows)]
    if mode == Run::Installed {
        return ubc_vpn_platform::service::run(move |control, stop| {
            let service = start(mode)?;
            control.running().map_err(|e| {
                format!("The service manager could not be told the service is running: {e}.")
            })?;
            service.serve_until(stop)
        })
        .map_err(|e| e.to_string())?;
    }
    let service = start(mode)?;
    eprintln!("ubc-vpn-service {} is running", ubc_vpn_core::VERSION);
    Err(service.wait())
}

/// Checks the folder this program runs from; see `ubc_vpn_platform::program`.
/// The path is used as Windows gives it, not canonicalised, which would make
/// it a verbatim path that the engine refuses.
#[cfg(windows)]
fn program_folder() -> Result<ubc_vpn_platform::program::ProgramFolder, String> {
    let program = std::env::current_exe()
        .map_err(|e| format!("The service cannot tell where it runs from: {e}."))?;
    ubc_vpn_platform::program::check(&program).map_err(|e| e.to_string())
}

fn start(mode: Run) -> Result<Service, String> {
    let (platform, state, engine) = parts(mode)?;
    let dev_mode = mode != Run::Installed;
    Service::start_in(platform, state, engine, Timeouts::default(), dev_mode)
}

fn parts(mode: Run) -> Result<Parts, String> {
    match mode {
        Run::Installed => installed(),
        #[cfg(feature = "dev-mode")]
        Run::Dev => dev(),
    }
}

#[cfg(not(feature = "real-engine"))]
fn installed() -> Result<Parts, String> {
    Err("this build has no VPN engine, so it cannot run".to_string())
}

/// The installed service: the real platform, the state folder checked for
/// who may change it, and `libopenconnect` loaded from this program's own
/// folder. Nothing before this has started a thread, and the environment
/// is dealt with before the library is loaded, as the engine requires.
#[cfg(feature = "real-engine")]
fn installed() -> Result<Parts, String> {
    use ubc_vpn_engine::{OpenConnect, Role, prepare_environment};
    use ubc_vpn_platform::Mode;

    // A build with dev mode also has the fake engine in it, which must
    // never be what the installed service could run.
    if cfg!(feature = "dev-mode") {
        return Err("a build with dev mode cannot run as the installed service".to_string());
    }
    let platform = Platform::native(Mode::Installed)
        .map_err(|e| format!("The system's network cannot be managed: {e}."))?;
    let state = StateDir::open(Mode::Installed, &platform.paths)
        .map_err(|e| format!("The state folder cannot be used: {e}."))?;
    // The library's temporary files go where only the system and
    // administrators can write.
    let temp = state.temp_dir();
    let temp = temp.map_err(|e| format!("The state folder cannot be used: {e}."))?;
    let prepared =
        prepare_environment(Role::Service, Some(&temp)).map_err(args::environment_message)?;
    let exe =
        std::env::current_exe().map_err(|e| format!("This program's folder is unknown: {e}."))?;
    let dir = exe.parent().ok_or("This program's folder is unknown.")?;
    let engine = OpenConnect::load(dir, &prepared).map_err(|e| e.to_string())?;
    Ok((platform, state, Arc::new(engine)))
}

/// Dev mode: the real channel and files for `Mode::Dev`, with fake routing,
/// fake DNS and the fake engine.
#[cfg(feature = "dev-mode")]
fn dev() -> Result<Parts, String> {
    use ubc_vpn_engine::fake::{FakeEngine, Script};
    use ubc_vpn_platform::{Mode, fake::Fake};

    let native = Platform::native(Mode::Dev).map_err(|e| {
        format!(
            "dev mode cannot run yet: the channel for this system is not implemented, \
             so no other program could reach the service ({e})"
        )
    })?;
    let fake = Fake::new();
    let platform = Platform {
        routes: Arc::new(fake.clone()),
        dns: Arc::new(fake.clone()),
        events: Arc::new(fake),
        ..native
    };
    // The pretend gateway presents the dev policy's first pin, so that
    // policy accepts it. A valid policy always has one.
    let mut policy = ubc_vpn_service::policy::load(&platform.paths.policy_dir)?;
    let script = Script::new(policy.pins.remove(0));
    // Checked as the installed service's is, but for this user: see `StateDir`.
    let state = StateDir::open(Mode::Dev, &platform.paths)
        .map_err(|e| format!("The state folder cannot be used: {e}."))?;
    // Logging in happens in another process, so this fake keeps accepting
    // the dev cookie after a log-off. Otherwise dev mode would connect once.
    Ok((platform, state, Arc::new(FakeEngine::for_dev_mode(script))))
}

/// `install` and `uninstall`, run by the Windows setup program.
#[cfg(windows)]
mod setup {
    use std::path::{Path, PathBuf};

    use ubc_vpn_platform::install::{self as os, Registration};
    use ubc_vpn_platform::{Mode, Platform};
    use ubc_vpn_service::install::{self, DESCRIPTION, DISPLAY_NAME, SERVICE_NAME};

    /// The machine-wide folder that holds the policy and the state.
    fn data_folder() -> Result<PathBuf, String> {
        let platform = Platform::native(Mode::Installed)
            .map_err(|e| format!("The data folder cannot be found: {e}."))?;
        Ok(platform.paths.policy_dir)
    }

    /// Checks the policy and this program's folder, makes the data folder
    /// and writes the policy into it, registers the service from where this
    /// program is, and starts it. Nothing is changed if the policy is not
    /// valid or the folder is not safe.
    pub fn install(policy: &Path, fresh: bool) -> Result<(), String> {
        let policy = install::read_policy(policy)?;
        let program = std::env::current_exe()
            .map_err(|e| format!("The service cannot tell where it is: {e}."))?;
        // Never register a service whose folder others could change: the
        // same check the service makes when it starts, done before anything
        // is changed.
        let _folder = ubc_vpn_platform::program::check(&program).map_err(|e| e.to_string())?;
        let command_line = os::quoted(&program)
            .map_err(|_| format!("The service's path cannot be used: {}.", program.display()))?;
        let data = data_folder()?;
        os::prepare_data_folder(&data, fresh)
            .map_err(|e| format!("The data folder could not be prepared: {e}."))?;
        os::write_policy(&data, &policy)
            .map_err(|e| format!("The policy could not be written: {e}."))?;
        let registration = Registration {
            name: SERVICE_NAME,
            display_name: DISPLAY_NAME,
            description: DESCRIPTION,
            command_line,
        };
        os::register(&registration)
            .map_err(|e| format!("The service could not be registered: {e}."))?;
        os::start(SERVICE_NAME).map_err(|e| format!("The service could not be started: {e}."))
    }

    /// Stops the service, which removes its routes and DNS first, removes
    /// it, and, unless `keep_data`, removes the data folder.
    pub fn uninstall(keep_data: bool) -> Result<(), String> {
        os::unregister(SERVICE_NAME)
            .map_err(|e| format!("The service could not be removed: {e}."))?;
        if keep_data {
            return Ok(());
        }
        os::remove_data_folder(&data_folder()?)
            .map_err(|e| format!("The data folder could not be removed: {e}."))
    }
}

/// On macOS and Linux the packages' own scripts do this.
#[cfg(not(windows))]
mod setup {
    const ONLY: &str = "install and uninstall are for the Windows setup program only";

    pub fn install(_policy: &std::path::Path, _fresh: bool) -> Result<(), String> {
        Err(ONLY.to_string())
    }

    pub fn uninstall(_keep_data: bool) -> Result<(), String> {
        Err(ONLY.to_string())
    }
}
