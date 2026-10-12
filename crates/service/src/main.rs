//! The privileged service. It opens the tunnel, applies routes and DNS,
//! verifies them, and cleans up. All of that lives in the library; this file
//! only chooses the parts and starts it.

use std::process::ExitCode;
use std::sync::Arc;

use ubc_vpn_engine::TunnelEngine;
use ubc_vpn_platform::Platform;
use ubc_vpn_service::args::{self, Run};
use ubc_vpn_service::{Service, Timeouts};

type Parts = (Platform, Arc<dyn TunnelEngine>);

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
    if let Some(name) = args::forbidden_env() {
        return Err(format!("refusing to start while {name} is set"));
    }
    let (platform, engine) = parts(mode)?;
    let service = Service::start(platform, engine, Timeouts::default())?;
    eprintln!("ubc-vpn-service {} is running", ubc_vpn_core::VERSION);
    Err(service.wait())
}

fn parts(mode: Run) -> Result<Parts, String> {
    match mode {
        Run::Installed => Err("this build has no VPN engine yet, so it cannot run".to_string()),
        #[cfg(feature = "dev-mode")]
        Run::Dev => dev(),
    }
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
    Ok((platform, Arc::new(FakeEngine::new(script))))
}
