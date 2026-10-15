//! The privileged service. It opens the tunnel, applies routes and DNS,
//! verifies them, and cleans up. All of that lives in the library; this file
//! only chooses the parts and starts it.

use std::process::ExitCode;
use std::sync::Arc;

use ubc_vpn_engine::TunnelEngine;
use ubc_vpn_platform::{Platform, StateDir};
use ubc_vpn_service::args::{self, Run};
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
    let mode = args::parse(std::env::args_os().skip(1))?;
    args::check_environment(mode)?;
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
