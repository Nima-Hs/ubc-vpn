//! The service binary's command line and the environment it accepts.

use std::ffi::OsString;
use std::path::PathBuf;

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

/// What the binary was asked to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Run the service.
    Run(Run),
    /// `install --policy <file> [--fresh]`: register the service, make its
    /// data folder, write the policy from `file` into it, and start it. With
    /// `--fresh`, for a first install, a data folder that is already there
    /// is emptied first, unless it holds an owner the service would accept
    /// (as a failed update leaves it). Windows only; the setup program runs it.
    Install { policy: PathBuf, fresh: bool },
    /// `uninstall [--keep-data]`: stop the service, which cleans up first,
    /// and remove it and the data folder. With `--keep-data`, for an update,
    /// the data folder stays. Windows only; the setup program runs it.
    Uninstall { keep_data: bool },
}

/// Reads the arguments after the program name: `install` or `uninstall`
/// and their options, or the arguments of a run (see [`parse`]). Anything
/// unknown or repeated is an error.
pub fn command(args: impl IntoIterator<Item = OsString>) -> Result<Command, String> {
    let args: Vec<OsString> = args.into_iter().collect();
    match args.first().and_then(|first| first.to_str()) {
        Some("install") => install(&args[1..]),
        Some("uninstall") => uninstall(&args[1..]),
        _ => parse(args).map(Command::Run),
    }
}

fn install(args: &[OsString]) -> Result<Command, String> {
    let (mut policy, mut fresh) = (None, false);
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--fresh") if !fresh => fresh = true,
            Some("--policy") if policy.is_none() => {
                let path = args.next().ok_or("--policy needs a file")?;
                policy = Some(PathBuf::from(path));
            }
            _ => return Err(unknown(arg)),
        }
    }
    let policy = policy.ok_or("install needs --policy <file>")?;
    Ok(Command::Install { policy, fresh })
}

fn uninstall(args: &[OsString]) -> Result<Command, String> {
    let mut keep_data = false;
    for arg in args {
        match arg.to_str() {
            Some("--keep-data") if !keep_data => keep_data = true,
            _ => return Err(unknown(arg)),
        }
    }
    Ok(Command::Uninstall { keep_data })
}

fn unknown(arg: &OsString) -> String {
    match arg.to_str() {
        Some(arg) => format!("unknown or repeated argument: {arg}"),
        None => "unknown argument: it is not valid Unicode".to_string(),
    }
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

    fn command_of(args: &[&str]) -> Result<Command, String> {
        command(args.iter().map(OsString::from))
    }

    #[test]
    fn reads_install_and_uninstall() {
        let policy = PathBuf::from("policy.json");
        assert_eq!(
            command_of(&["install", "--policy", "policy.json"]),
            Ok(Command::Install {
                policy: policy.clone(),
                fresh: false
            })
        );
        assert_eq!(
            command_of(&["install", "--fresh", "--policy", "policy.json"]),
            Ok(Command::Install {
                policy,
                fresh: true
            })
        );
        assert_eq!(
            command_of(&["uninstall"]),
            Ok(Command::Uninstall { keep_data: false })
        );
        assert_eq!(
            command_of(&["uninstall", "--keep-data"]),
            Ok(Command::Uninstall { keep_data: true })
        );
        assert_eq!(command_of(&[]), Ok(Command::Run(Run::Installed)));
    }

    #[test]
    fn refuses_what_install_and_uninstall_do_not_know() {
        let refused: [&[&str]; 8] = [
            &["install"],
            &["install", "--policy"],
            &["install", "--policy", "a", "--policy", "b"],
            &["install", "--fresh", "--fresh", "--policy", "a"],
            &["install", "--policy", "a", "--keep-data"],
            &["uninstall", "--keep-data", "--keep-data"],
            &["uninstall", "--fresh"],
            &["status"],
        ];
        for args in refused {
            assert!(command_of(args).is_err(), "{args:?}");
        }
    }
}
