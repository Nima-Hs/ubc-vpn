//! Which environment variables must not reach the VPN library.
//!
//! This file has no `unsafe` code and is built in every configuration, so
//! the service can check its environment whichever engine it runs. Changing
//! the environment is a different matter: see `prepare_environment`, which
//! exists only with the `libopenconnect` feature.

/// Environment variables the bundled libraries read, each with what it does.
/// The names come from the string scan of the Windows build and a reading of
/// the sources (`native/windows/README.md`).
///
/// `USER` and `NTLMUSER` are left out on purpose: the library reads them only
/// for a proxy that asks for NTLM, the engine never sets a proxy, and `USER`
/// is set on every Unix system.
pub const DANGEROUS_VARIABLES: [(&str, &str); 11] = [
    ("SSLKEYLOGFILE", "GnuTLS writes session keys to the file"),
    ("GNUTLS_KEYLOGFILE", "an older name for the same file"),
    ("GNUTLS_SYSTEM_PRIORITY_FILE", "replaces GnuTLS's settings"),
    ("GNUTLS_DEBUG_LEVEL", "makes GnuTLS log, secrets included"),
    ("GNUTLS_CPUID_OVERRIDE", "changes which cipher code runs"),
    ("GNUTLS_BUFFER_RECLAIM", "changes how GnuTLS frees memory"),
    ("GNUTLS_NO_EXPLICIT_INIT", "changes how GnuTLS starts up"),
    ("GNUTLS_NO_IMPLICIT_INIT", "changes how GnuTLS starts up"),
    ("NETTLE_FAT_VERBOSE", "makes Nettle print to standard error"),
    ("XML_CATALOG_FILES", "names files for libxml2 to read"),
    ("XML_DEBUG_CATALOG", "makes libxml2 print to standard error"),
];

/// Which program is checking its environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The privileged service. Its environment comes from the system's
    /// service manager, so anything that steers the loader is refused too.
    Service,
    /// The command-line client, run by ordinary users. They may have
    /// `LD_LIBRARY_PATH` set for reasons of their own.
    Client,
}

/// Why the environment is not safe for the library.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvironmentError {
    /// This one of [`DANGEROUS_VARIABLES`] is set.
    Set(&'static str),
    /// A variable that steers the system loader is set. Its name is left
    /// out: it is text chosen by whoever set the environment.
    LoaderVariable,
    /// The temporary folder is not an absolute path to a folder that exists.
    /// Windows only.
    BadTemp,
    /// The C runtime the libraries use could not be told of a change, so
    /// they may still see a variable that was to be removed. Windows only.
    Runtime,
}

/// Whether a variable of this name steers the system loader on macOS or
/// Linux: `LD_*`, and `DYLD_*` other than the two `DYLD_FALLBACK_*` ones,
/// which Cargo sets and which the loader does not use for a full path.
fn steers_the_loader(name: &str) -> bool {
    name.starts_with("LD_") || (name.starts_with("DYLD_") && !name.starts_with("DYLD_FALLBACK_"))
}

/// Checks that the environment is safe for the library, and says what is
/// wrong with it. It reads the environment and changes nothing.
///
/// For both roles none of [`DANGEROUS_VARIABLES`] may be set. On macOS and
/// Linux the service also refuses every variable that steers the loader.
/// The client does not: loading the library refuses the `DYLD_*` ones for
/// it, and an ordinary user's `LD_*` variables are that user's own business.
pub fn check_environment(role: Role) -> Result<(), EnvironmentError> {
    let listed = |(name, _): &&(&'static str, &str)| std::env::var_os(name).is_some();
    if let Some((name, _)) = DANGEROUS_VARIABLES.iter().find(listed) {
        return Err(EnvironmentError::Set(name));
    }
    // A name that is not Unicode is checked by what can be read of it.
    let steers = |(name, _): (std::ffi::OsString, _)| steers_the_loader(&name.to_string_lossy());
    if cfg!(unix) && role == Role::Service && std::env::vars_os().any(steers) {
        return Err(EnvironmentError::LoaderVariable);
    }
    Ok(())
}
