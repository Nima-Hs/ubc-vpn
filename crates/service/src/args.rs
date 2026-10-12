//! The service binary's command line and the environment it accepts.

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
/// and `--dev` is unknown to a build without the `dev-mode` feature.
pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Run, String> {
    let read = |_run, arg: String| match arg.as_str() {
        #[cfg(feature = "dev-mode")]
        "--dev" => Ok(Run::Dev),
        other => Err(format!("unknown argument: {other}")),
    };
    args.into_iter().try_fold(Run::Installed, read)
}

/// Variables GnuTLS honours that would expose or weaken the tunnel's TLS.
pub const FORBIDDEN_ENV: [&str; 3] = [
    "SSLKEYLOGFILE",
    "GNUTLS_SYSTEM_PRIORITY_FILE",
    "GNUTLS_DEBUG_LEVEL",
];

/// The first of [`FORBIDDEN_ENV`] that is set, if any. The service refuses to
/// start while one is: this crate forbids unsafe code and so cannot remove a
/// variable itself.
pub fn forbidden_env() -> Option<&'static str> {
    let is_set = |name: &&str| std::env::var_os(name).is_some();
    FORBIDDEN_ENV.into_iter().find(is_set)
}
