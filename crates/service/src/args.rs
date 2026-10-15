//! The service binary's command line and the environment it accepts.

use std::ffi::OsString;

use ubc_vpn_engine::{EnvironmentError, Role};

/// How the binary was asked to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Run {
    /// As the installed, privileged service.
    Installed,
    /// Unprivileged, in the foreground, on fakes. Exists only in a build with
    /// the `dev-mode` feature.
    #[cfg(feature = "dev-mode")]
    Dev,
}

/// Reads the arguments after the program name. Anything unknown is an error,
/// an argument that is not Unicode included, and `--dev` is unknown to a
/// build without the `dev-mode` feature.
pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Run, String> {
    let read = |_run, arg: OsString| match arg.to_str() {
        #[cfg(feature = "dev-mode")]
        Some("--dev") => Ok(Run::Dev),
        Some(other) => Err(format!("unknown argument: {other}")),
        None => Err("unknown argument: it is not valid Unicode".to_string()),
    };
    args.into_iter().try_fold(Run::Installed, read)
}

/// How strictly a run checks its environment. The engine crate holds the one
/// list of variables that would expose or weaken the tunnel's TLS, and both
/// levels refuse every one of them.
///
/// The installed service also refuses any variable that steers the system
/// loader. Dev mode does not: it runs unprivileged on the fake engine and
/// loads no native library, and Cargo, which starts it, sets such a variable
/// (`LD_LIBRARY_PATH` on Linux) for everything it runs.
pub fn environment_role(run: Run) -> Role {
    match run {
        Run::Installed => Role::Service,
        #[cfg(feature = "dev-mode")]
        Run::Dev => Role::Client,
    }
}

/// Checks the environment for this run. The service refuses to start while
/// it is not safe: this crate forbids unsafe code and so cannot remove a
/// variable itself. The message names a variable only when the name is one
/// of the engine's own list, never text taken from the environment.
pub fn check_environment(run: Run) -> Result<(), String> {
    ubc_vpn_engine::check_environment(environment_role(run)).map_err(environment_message)
}

/// What the service says when the environment is not safe.
pub fn environment_message(error: EnvironmentError) -> String {
    match error {
        EnvironmentError::Set(name) => format!("refusing to start while {name} is set"),
        EnvironmentError::LoaderVariable => "refusing to start while a variable that steers \
            the system loader is set (LD_* or DYLD_*)"
            .to_string(),
        _ => "refusing to start: the environment is not safe".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Security rule: the installed service checks its environment at the
    // strict level, which also refuses the loader's variables.
    #[test]
    fn the_installed_service_checks_at_the_service_level() {
        assert_eq!(environment_role(Run::Installed), Role::Service);
        #[cfg(feature = "dev-mode")]
        assert_eq!(environment_role(Run::Dev), Role::Client);
    }
}
