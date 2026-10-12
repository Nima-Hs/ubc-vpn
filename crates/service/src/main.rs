//! The privileged service. It opens the tunnel, applies routes and DNS,
//! verifies them, and cleans up. All of that lives in the library; this file
//! only chooses the parts and starts it.

use std::process::ExitCode;

use ubc_vpn_platform::{Mode, Platform};
use ubc_vpn_service::args::{self, Run};
use ubc_vpn_service::{Service, Timeouts};

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
    let mode = args::parse(std::env::args().skip(1))?;
    if let Some(name) = args::forbidden_env() {
        return Err(format!("refusing to start while {name} is set"));
    }
    let service = Service::start(platform(mode)?, Timeouts::default())?;
    eprintln!("ubc-vpn-service {} is running", ubc_vpn_core::VERSION);
    service.wait();
    Ok(())
}

fn platform(mode: Run) -> Result<Platform, String> {
    match mode {
        Run::Installed => Platform::native(Mode::Installed)
            .map_err(|e| format!("the service cannot run on this system yet ({e})")),
        #[cfg(feature = "dev-mode")]
        Run::Dev => dev(),
    }
}

/// Dev mode: the real channel and files for `Mode::Dev`, with fake routing
/// and fake DNS.
#[cfg(feature = "dev-mode")]
fn dev() -> Result<Platform, String> {
    use std::sync::Arc;
    use ubc_vpn_platform::fake::Fake;

    let native = Platform::native(Mode::Dev).map_err(|e| {
        format!(
            "dev mode cannot run yet: the channel for this system is not implemented, \
             so no other program could reach the service ({e})"
        )
    })?;
    let fake = Fake::new();
    Ok(Platform {
        routes: Arc::new(fake.clone()),
        dns: Arc::new(fake.clone()),
        events: Arc::new(fake),
        ..native
    })
}
