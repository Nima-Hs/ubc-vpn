//! The privileged service. It opens the tunnel, applies routes and DNS,
//! verifies them, and cleans up. All of that lives in the library; this file
//! only chooses the parts and starts it.

use std::process::ExitCode;
use std::sync::Arc;

use ubc_vpn_engine::TunnelEngine;
use ubc_vpn_platform::{Platform, StateDir};
use ubc_vpn_service::Service;
use ubc_vpn_service::args::{self, Command, Run};

/// What the service is built from. In dev mode, also the fake that stands
/// in for routing and DNS, so that what is left on it can be told at the
/// end.
struct Parts {
    platform: Platform,
    state: StateDir,
    engine: Arc<dyn TunnelEngine>,
    #[cfg(all(unix, feature = "dev-mode"))]
    fake: Option<ubc_vpn_platform::fake::Fake>,
}

/// What a build without the real engine says when asked to run installed.
#[cfg(not(feature = "real-engine"))]
const NO_ENGINE: &str = "this build has no VPN engine, so it cannot run";

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
        // A build with dev mode has the fake engine in it and never installs
        // or removes the installed service, before anything else.
        Command::Install { .. } | Command::Uninstall { .. } if cfg!(feature = "dev-mode") => {
            return Err("a build with dev mode cannot install or remove the service".to_string());
        }
        // Run by the Windows setup program or the packages' scripts, as an
        // administrator or root, with the same checks of the environment as
        // the service.
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
    // On Linux and macOS a build without the engine loads nothing from its
    // folder and cannot run at all, so it says that first. On Windows the
    // folder and the service manager come first, as they always have.
    #[cfg(all(unix, not(feature = "real-engine")))]
    if mode == Run::Installed {
        return Err(NO_ENGINE.to_string());
    }
    // The installed service runs only from a folder that no one but the
    // system's own accounts could change (see `ubc_vpn_platform::program`),
    // held so that it cannot be swapped while the service runs.
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
            let service = start(mode, parts(mode)?)?;
            control.running().map_err(|e| {
                format!("The service manager could not be told the service is running: {e}.")
            })?;
            service.serve_until(stop)
        })
        .map_err(|e| e.to_string())?;
    }
    serve(mode)
}

/// On Linux and macOS: serves until asked to stop, by launchd or systemd
/// with `SIGTERM`, or with Ctrl-C in dev mode, and removes everything it
/// applied before it exits.
#[cfg(unix)]
fn serve(mode: Run) -> Result<(), String> {
    let parts = parts(mode)?;
    // Watched from before the service starts, so that no request to stop
    // can find routes applied and nobody listening, which would end the
    // program where it stands. After the engine is loaded, which must
    // happen before any thread starts.
    let stops = ubc_vpn_platform::interrupt::watch()
        .map_err(|e| format!("Requests to stop cannot be watched for: {e}."))?;
    #[cfg(feature = "dev-mode")]
    let fake = parts.fake.clone();
    let service = start(mode, parts)?;
    #[cfg(feature = "dev-mode")]
    let log = service.log_book();
    eprintln!("ubc-vpn-service {} is running", ubc_vpn_core::VERSION);
    let served = service.serve_until_stopped(stops);
    #[cfg(feature = "dev-mode")]
    if let Some(fake) = fake {
        the_end_in_dev_mode(&fake, &log)?;
    }
    served?;
    eprintln!("ubc-vpn-service {} has stopped", ubc_vpn_core::VERSION);
    Ok(())
}

/// On Windows, outside the service manager: dev mode, which serves until
/// the program is ended.
#[cfg(not(unix))]
fn serve(mode: Run) -> Result<(), String> {
    let service = start(mode, parts(mode)?)?;
    eprintln!("ubc-vpn-service {} is running", ubc_vpn_core::VERSION);
    Err(service.wait())
}

/// Dev mode, once the service has stopped, for whoever ran it: what the
/// service logged from the request to stop on, which no client can read
/// any more, and whether anything is left on the fake routing and DNS,
/// which for the installed service would be the system's own. Anything
/// left is a failure. The log holds no secret, as everywhere.
#[cfg(all(unix, feature = "dev-mode"))]
fn the_end_in_dev_mode(
    fake: &ubc_vpn_platform::fake::Fake,
    log: &ubc_vpn_service::Logs,
) -> Result<(), String> {
    let lines = log.lines();
    let asked = lines
        .iter()
        .position(|line| line.starts_with("asked to stop"));
    for line in &lines[asked.unwrap_or(lines.len())..] {
        eprintln!("ubc-vpn-service: dev mode: logged at the end: {line}");
    }
    let applied = fake.applied();
    if applied != Default::default() {
        return Err(format!(
            "dev mode: routes or DNS were left applied: {applied:?}"
        ));
    }
    eprintln!("ubc-vpn-service: dev mode: no routes or DNS are left applied");
    Ok(())
}

/// Checks the folder this program runs from; see `ubc_vpn_platform::program`.
/// The path is used as the OS gives it, not canonicalised, which on Windows
/// would make it a verbatim path that the engine refuses.
fn program_folder() -> Result<ubc_vpn_platform::program::ProgramFolder, String> {
    let program = std::env::current_exe()
        .map_err(|e| format!("The service cannot tell where it runs from: {e}."))?;
    ubc_vpn_platform::program::check(&program).map_err(|e| e.to_string())
}

fn start(mode: Run, parts: Parts) -> Result<Service, String> {
    let dev_mode = mode != Run::Installed;
    let timeouts = args::timeouts(mode);
    Service::start_in(
        parts.platform,
        parts.state,
        parts.engine,
        timeouts,
        dev_mode,
    )
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
    Err(NO_ENGINE.to_string())
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
    Ok(Parts {
        platform,
        state,
        engine: Arc::new(engine),
        #[cfg(all(unix, feature = "dev-mode"))]
        fake: None,
    })
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
        events: Arc::new(fake.clone()),
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
    Ok(Parts {
        platform,
        state,
        engine: Arc::new(FakeEngine::for_dev_mode(script)),
        #[cfg(unix)]
        fake: Some(fake),
    })
}

/// `install` and `uninstall`, run as an administrator by the Windows setup
/// program, and as root by the macOS and Linux packages' scripts. The same
/// steps on every OS; `ubc_vpn_platform::install` does each of them. On
/// macOS it cannot register the service yet, so there it stops before
/// anything is changed. On Linux the policy and the state are in two folders,
/// and the calls given the data folder, which is the policy's, do the same to
/// the state's.
mod setup {
    use std::path::{Path, PathBuf};

    use ubc_vpn_platform::install::{self as os, Registration};
    use ubc_vpn_platform::{Mode, Paths, Platform, StateDir};
    use ubc_vpn_service::install::{self, DESCRIPTION, DISPLAY_NAME, SERVICE_NAME};

    /// Where the installed service keeps its policy and its state: one
    /// machine-wide data folder.
    fn paths() -> Result<Paths, String> {
        let platform = Platform::native(Mode::Installed)
            .map_err(|e| format!("The data folder cannot be found: {e}."))?;
        Ok(platform.paths)
    }

    /// The machine-wide folder that holds the policy and the state.
    fn data_folder() -> Result<PathBuf, String> {
        Ok(paths()?.policy_dir)
    }

    /// Checks the policy and this program's folder, makes the data folder
    /// and writes the policy into it, registers the service from where this
    /// program is, and starts it. Nothing is changed if the policy is not
    /// valid or the folder is not safe.
    pub fn install(policy: &Path, fresh: bool) -> Result<(), String> {
        let policy = install::read_policy(policy)?;
        let paths = paths()?;
        let mut steps = System {
            data: paths.policy_dir.clone(),
            paths,
            command_line: String::new(),
            _folder: None,
        };
        install::install(&mut steps, &policy, fresh)
    }

    /// The steps of an install on this computer (see `install::install`).
    struct System {
        data: PathBuf,
        paths: Paths,
        command_line: String,
        /// This program's folder as checked, held until the install ends.
        _folder: Option<ubc_vpn_platform::program::ProgramFolder>,
    }

    impl install::Steps for System {
        fn check_program(&mut self) -> Result<(), String> {
            let program = std::env::current_exe()
                .map_err(|e| format!("The service cannot tell where it is: {e}."))?;
            // Never register a service whose folder others could change: the
            // same check the service makes when it starts, done before
            // anything is changed.
            let folder = ubc_vpn_platform::program::check(&program).map_err(|e| e.to_string())?;
            self._folder = Some(folder);
            self.command_line = os::quoted(&program).map_err(|_| {
                format!("The service's path cannot be used: {}.", program.display())
            })?;
            Ok(())
        }

        fn holds_an_owner(&mut self) -> bool {
            // `StateDir::open` makes the folder when it is missing; only one
            // that is already there can hold an owner.
            if std::fs::symlink_metadata(&self.paths.state_dir).is_err() {
                return false;
            }
            StateDir::open(Mode::Installed, &self.paths)
                .is_ok_and(|state| install::holds_an_owner(&state))
        }

        fn prepare_data_folder(&mut self, fresh: bool) -> Result<(), String> {
            os::prepare_data_folder(&self.data, fresh)
                .map_err(|e| format!("The data folder could not be prepared: {e}."))
        }

        fn write_policy(&mut self, policy: &[u8]) -> Result<(), String> {
            os::write_policy(&self.data, policy)
                .map_err(|e| format!("The policy could not be written: {e}."))
        }

        fn verify_data_folder(&mut self, fresh: bool) -> Result<(), String> {
            os::verify_data_folder(&self.data, fresh)
                .map_err(|e| format!("The data folder is not as it was set up: {e}"))
        }

        fn register(&mut self) -> Result<(), String> {
            let registration = Registration {
                name: SERVICE_NAME,
                display_name: DISPLAY_NAME,
                description: DESCRIPTION,
                command_line: self.command_line.clone(),
            };
            os::register(&registration)
                .map_err(|e| format!("The service could not be registered: {e}."))
        }

        fn start(&mut self) -> Result<(), String> {
            os::start(SERVICE_NAME).map_err(|e| format!("The service could not be started: {e}."))
        }
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
