//! The command-line client. It logs in and talks to the service. Only
//! `status` and `bridge` exist so far.

use std::io::Write;
use std::process::ExitCode;

use ubc_vpn_core::VERSION;
use ubc_vpn_core::policy::Policy;
use ubc_vpn_core::protocol::{ClientKind, RequestBody, ResponseBody, encode};
use ubc_vpn_core::state::ConnState;
use ubc_vpn_engine::LoginEngine;
use ubc_vpn_platform::interrupt::Stop;
use ubc_vpn_platform::{Mode, Platform};

use client::{Client, ClientError};

mod bridge;
mod client;
mod connect;
mod connect_json;
#[cfg(test)]
mod connect_json_tests;
#[cfg(test)]
mod connect_tests;
mod interrupt;
#[cfg(test)]
mod interrupt_tests;
mod logs;
mod settings;
mod settings_lock;
#[cfg(test)]
mod settings_lock_tests;
#[cfg(test)]
mod settings_tests;
mod terminal;
#[cfg(test)]
mod terminal_tests;
#[cfg(test)]
mod tests;

/// Exit codes. Scripts and the app tell failures apart by these.
const FAILED: u8 = 1;
const USAGE: u8 = 2;
const NOT_RUNNING: u8 = 3;
const MISMATCH: u8 = 4;
const NOT_OWNER: u8 = 5;
const NOT_THE_SERVICE: u8 = 6;

const HELP: &str = "\
Usage: ubc-vpn <command>

Commands:
  connect [--json]  Log in and connect the VPN, using the saved routes
  disconnect        Disconnect the VPN
  status [--json]   Show whether the VPN is connected
  logs [--json] [--follow]  Show what the service has logged
  diagnostics [--json]      Show the service's version, state and last failure
  bridge            Carry messages between the app and the service
  settings get --json            Print the settings and the route limits
  settings check-routes --json   Check the routes given on standard input
  settings set-routes --json     Check them and, if they pass, save them
  settings reset [--force] --json  Start afresh when the settings cannot be read
  help              Show this text
  version           Show the version

The first user to run connect, disconnect or status becomes the owner of the
service, and from then on only that user can control UBC VPN on this computer.
The bridge claims nothing itself; it leaves that to the app. The settings
commands do not talk to the service at all.

connect asks for the password and the one-time code in the terminal. They are
never taken from an argument, a variable or a file. Ctrl-C stops a
connect: at a question nothing has been sent, and after the login the service
is told to disconnect before the program ends.

With --json, connect is for the app: it writes each question as one line of
JSON, reads each answer as one line from standard input, and ends with a
done line once the service has accepted the request, or with an error line. A
cancel line, or standard input closing, stops the login.

logs and diagnostics are for the owner and only read: they do not make
anyone the owner. The log holds no password, code or session cookie. With
--follow, logs goes on printing lines as the service writes them, until it
is interrupted. With --json, logs prints each line of the log as one line of
JSON, and diagnostics prints one line of JSON.

With --json, status prints the connection state as one line of JSON. Each
settings command prints one line of JSON, and exits with status 1 only when
that line is an error.

Exit status:
  0  done
  1  failed for another reason
  2  wrong usage
  3  UBC VPN is not installed, or its service is not running
  4  version mismatch: update UBC VPN
  5  you are not the owner
  6  another program is answering in place of the service
  7  the VPN is connected already, or is connecting or disconnecting
  8  the login was refused, or the session has ended
  9  cancelled";

/// Whether the arguments start with `--dev`, and the arguments after it. The
/// flag exists only in a build with the `dev-mode` feature; in any other it
/// is an argument like any unknown one.
fn dev_flag<'a>(args: &'a [&'a str]) -> (bool, &'a [&'a str]) {
    #[cfg(feature = "dev-mode")]
    if let ["--dev", rest @ ..] = args {
        return (true, rest);
    }
    (false, args)
}

/// The platform for this run: the installed product's, or with `--dev` the
/// dev-mode service's channel and files.
fn platform(dev: bool) -> ubc_vpn_platform::Result<Platform> {
    #[cfg(feature = "dev-mode")]
    if dev {
        return Platform::native(Mode::Dev);
    }
    let _ = dev;
    Platform::native(Mode::Installed)
}

const NO_ENGINE: &str = "This build has no VPN engine, so it cannot connect.";

/// The engine that logs in: the VPN library this program loaded at start,
/// or why there is none. With `--dev` it is a pretend gateway that presents
/// the dev policy's first pin and asks for a username, a password and a
/// one-time code.
fn login_engine(dev: bool, policy: &Policy, real: &Real) -> Result<Box<dyn LoginEngine>, String> {
    #[cfg(feature = "dev-mode")]
    if dev {
        use ubc_vpn_engine::fake::{FakeEngine, Script};
        let no_pin = || "The dev policy has no pin.".to_string();
        let mut script = Script::new(policy.pins.first().ok_or_else(no_pin)?.clone());
        let mut code = script.form[1].clone();
        code.0.kind = ubc_vpn_core::login::PromptKind::Code;
        code.0.label = "One-time code".to_string();
        code.1 = ubc_vpn_core::redact::Secret::new(DEV_CODE);
        script.form.push(code);
        return Ok(Box::new(FakeEngine::new(script)));
    }
    let _ = (dev, policy);
    real.engine()
}

/// The real VPN engine, when this build has one and the command logs in.
#[cfg(feature = "real-engine")]
struct Real(Option<Result<std::sync::Arc<ubc_vpn_engine::OpenConnect>, String>>);

#[cfg(not(feature = "real-engine"))]
struct Real;

impl Real {
    /// Prepares the environment and loads `libopenconnect` from this
    /// program's own folder, for a command that logs in for real. It must
    /// run first in `main`, before any thread exists: GnuTLS reads the
    /// environment while it is being loaded. A failure is kept and given as
    /// the reason the command cannot log in; nothing of the library is used
    /// after one.
    fn load(logs_in: bool) -> Self {
        #[cfg(feature = "real-engine")]
        return Self(logs_in.then(load_beside_program));
        #[cfg(not(feature = "real-engine"))]
        {
            let _ = logs_in;
            Self
        }
    }

    fn engine(&self) -> Result<Box<dyn LoginEngine>, String> {
        #[cfg(feature = "real-engine")]
        return match &self.0 {
            Some(Ok(engine)) => Ok(Box::new(Loaded(engine.clone()))),
            Some(Err(why)) => Err(why.clone()),
            None => Err(NO_ENGINE.to_string()),
        };
        #[cfg(not(feature = "real-engine"))]
        Err(NO_ENGINE.to_string())
    }

    /// Why loading failed, if it was tried and did. The command then ends
    /// at once: nothing of a library that failed to load is used.
    fn failure(&self) -> Option<&str> {
        #[cfg(feature = "real-engine")]
        return match &self.0 {
            Some(Err(why)) => Some(why),
            _ => None,
        };
        #[cfg(not(feature = "real-engine"))]
        None
    }
}

/// The folder this program was installed in, where the VPN library and the
/// libraries it needs are. It never comes from the environment, a setting or
/// an argument.
#[cfg(feature = "real-engine")]
fn program_dir() -> Result<std::path::PathBuf, String> {
    let exe = std::env::current_exe().map_err(|_| LIBRARY_FAILED.to_string())?;
    let dir = exe.parent().ok_or(LIBRARY_FAILED)?;
    Ok(dir.to_path_buf())
}

#[cfg(feature = "real-engine")]
const LIBRARY_FAILED: &str = "The VPN library could not be loaded.";

#[cfg(feature = "real-engine")]
fn load_beside_program() -> Result<std::sync::Arc<ubc_vpn_engine::OpenConnect>, String> {
    use ubc_vpn_engine::{EnvironmentError, OpenConnect, Role, prepare_environment};
    let prepared = prepare_environment(Role::Client, None).map_err(|error| match error {
        EnvironmentError::Set(name) => {
            format!("Refusing to log in while {name} is set. Unset it and try again.")
        }
        _ => "Refusing to log in: the environment is not safe.".to_string(),
    })?;
    let engine = OpenConnect::load(&program_dir()?, &prepared);
    engine.map(std::sync::Arc::new).map_err(|e| e.to_string())
}

/// The loaded library as a login engine for one command. Every login made
/// through it uses the one library this process loaded.
#[cfg(feature = "real-engine")]
struct Loaded(std::sync::Arc<ubc_vpn_engine::OpenConnect>);

#[cfg(feature = "real-engine")]
impl LoginEngine for Loaded {
    fn login(
        &self,
        gateway: &ubc_vpn_engine::Gateway,
        prompts: &mut ubc_vpn_engine::Prompts<'_>,
        cancel: &ubc_vpn_engine::Cancel,
        logs: &ubc_vpn_engine::LogSink,
    ) -> Result<ubc_vpn_engine::Session, ubc_vpn_engine::LoginError> {
        self.0.login(gateway, prompts, cancel, logs)
    }
}

/// The one-time code the pretend gateway of dev mode accepts. Made up, and
/// compiled only into a dev-mode build.
#[cfg(feature = "dev-mode")]
const DEV_CODE: &str = "123456";

/// Ends the program as one stopped by `stop` ends, having printed nothing.
fn leave(stop: Stop) -> ! {
    std::process::exit(ubc_vpn_platform::interrupt::exit_status(stop))
}

const UNWATCHED: &str = "Ctrl-C cannot be handled cleanly here. If you interrupt this \
                         connect, run `ubc-vpn disconnect` afterwards.";

/// How long a connect that is being stopped waits for the service to take
/// its disconnect. The user has asked to leave; this is not a time to hang.
const UNDO: std::time::Duration = std::time::Duration::from_secs(3);

/// Starts handling Ctrl-C and requests to end for a connect, and returns
/// what the connect reports its progress to. See [`interrupt`].
///
/// If the platform cannot watch for them, they end the program where it
/// stands, as they always did, and the user is told so once.
fn watch_for_a_stop(dev: bool, err: &mut dyn Write) -> interrupt::Progress {
    let progress = interrupt::Progress::default();
    let Ok(requests) = ubc_vpn_platform::interrupt::watch() else {
        let _ = writeln!(err, "ubc-vpn: {UNWATCHED}");
        return progress;
    };
    {
        let shared = progress.clone();
        let undo = move || {
            let limits = client::Limits {
                answer: UNDO,
                write: UNDO,
                ..client::Limits::default()
            };
            connect::undo(&|| platform(dev), limits);
        };
        std::thread::spawn(move || interrupt::serve(requests, &shared, undo, |stop| leave(stop)));
    }
    progress
}

fn main() -> ExitCode {
    let (mut out, mut err) = (std::io::stdout(), std::io::stderr());
    // An argument that is not Unicode is no command this program has.
    let args: Option<Vec<String>> = std::env::args_os()
        .skip(1)
        .map(|arg| arg.into_string().ok())
        .collect();
    let Some(args) = args else {
        return ExitCode::from(say(&mut err, HELP, USAGE));
    };
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let (dev, args) = dev_flag(&args);
    // First, before anything starts a thread.
    let logs_in = !dev && matches!(args, ["connect"] | ["connect", "--json"]);
    let real = Real::load(logs_in);
    if let Some(why) = real.failure() {
        return ExitCode::from(match args {
            ["connect", "--json"] => connect_json::refuse(why, &mut out),
            _ => say(&mut err, &format!("ubc-vpn: {why}"), FAILED),
        });
    }
    let chosen = || platform(dev);
    // The commands that read standard input are started here. The bridge
    // only for exactly this spelling.
    if args == ["bridge"] {
        let input = std::io::BufReader::new(std::io::stdin());
        let limits = client::Limits::default();
        let status = bridge::run(&chosen, input, limits, &mut out, &mut err);
        return ExitCode::from(status);
    }
    // The settings commands read standard input too.
    if let ["settings", rest @ ..] = args {
        let Some(command) = settings::Command::parse(rest) else {
            return ExitCode::from(say(&mut err, HELP, USAGE));
        };
        let mut input = std::io::stdin().lock();
        let status = settings::run(command, &chosen, &mut input, &mut out, &mut err);
        return ExitCode::from(status);
    }
    if args == ["connect", "--json"] {
        let engines = |policy: &Policy| login_engine(dev, policy, &real);
        let input = std::io::BufReader::new(std::io::stdin());
        let limits = client::Limits::default();
        let status = connect_json::connect(&chosen, &engines, input, limits, &mut out, &mut err);
        return ExitCode::from(status);
    }
    if args == ["connect"] {
        let engines = |policy: &Policy| login_engine(dev, policy, &real);
        let (mut ask, limits) = (terminal::Terminal::real(), client::Limits::default());
        let progress = watch_for_a_stop(dev, &mut err);
        let ended = connect::connect(
            &chosen, &engines, &mut ask, &progress, limits, &mut out, &mut err,
        );
        match ended {
            connect::Ended::Status(status) => return ExitCode::from(status),
            connect::Ended::Interrupted => leave(Stop::Interrupt),
            // Whoever is handling the request ends the program, once the
            // service has been told to disconnect. Until then, wait.
            connect::Ended::Stopping => loop {
                std::thread::park();
            },
        }
    }
    ExitCode::from(run(args, &chosen, &mut out, &mut err))
}

/// Runs one command and returns the exit code. `platform` is asked for only
/// when the command needs the service.
fn run(
    args: &[&str],
    platform: &dyn Fn() -> ubc_vpn_platform::Result<Platform>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    let json = match args {
        ["help" | "--help" | "-h"] => return say(out, HELP, 0),
        ["version" | "--version" | "-V"] => return say(out, &format!("ubc-vpn {VERSION}"), 0),
        ["disconnect"] => {
            return connect::disconnect(platform, client::Limits::default(), out, err);
        }
        ["diagnostics"] => return logs::diagnostics(false, platform, out, err),
        ["diagnostics", "--json"] => return logs::diagnostics(true, platform, out, err),
        ["logs", options @ ..] => {
            return match logs::Options::parse(options) {
                Some(options) => logs::logs(options, platform, out, err),
                None => say(err, HELP, USAGE),
            };
        }
        ["status"] => false,
        ["status", "--json"] => true,
        _ => return say(err, HELP, USAGE),
    };
    let shown = status(platform).and_then(|state| match json {
        // One JSON line, as the service reports the state, less any
        // character that could mislead whoever reads it in a terminal. JSON
        // writes control characters as escapes; the unseen ones it does not.
        true => Ok(clean(encode(&state)?.trim_end())),
        false => Ok(describe(&state)),
    });
    match shown {
        Ok(text) => say(out, &text, 0),
        Err(error) => {
            let (code, message) = explain(&error);
            say(err, &format!("ubc-vpn: {message}"), code)
        }
    }
}

fn say(to: &mut dyn Write, text: &str, code: u8) -> u8 {
    let _ = writeln!(to, "{text}");
    code
}

/// Asks the service for the connection state, claiming the service first if
/// nobody owns it.
fn status(
    platform: &dyn Fn() -> ubc_vpn_platform::Result<Platform>,
) -> Result<ConnState, ClientError> {
    let platform = platform()?;

    let mut client = Client::reach(&platform, ClientKind::Cli, client::Limits::default())?;
    client.claim_if_unowned()?;
    match client.request(RequestBody::Status)? {
        ResponseBody::Status(state) => Ok(state),
        other => Err(ClientError::Lost(format!("unexpected answer: {other:?}"))),
    }
}

/// Text that came from the service, made safe to print: without control
/// characters, which could do anything to a terminal, and without the
/// invisible characters that reorder or hide text, which could make a line
/// read differently from what it says. Other Unicode is kept.
///
/// Which characters those are is said once, by
/// [`ubc_vpn_core::settings_cli::misleads`], which also decides what may be
/// saved as a username.
fn clean(text: &str) -> String {
    let shown = |c: &char| !ubc_vpn_core::settings_cli::misleads(*c);
    text.chars().filter(shown).collect()
}

/// The state in words.
fn describe(state: &ConnState) -> String {
    match state {
        ConnState::Disconnected => "Disconnected".to_string(),
        ConnState::Connecting => "Connecting".to_string(),
        ConnState::Disconnecting => "Disconnecting".to_string(),
        ConnState::LoginNeeded => "Login needed: the session has ended.".to_string(),
        ConnState::Failed { message, .. } => format!("Failed: {}", clean(message)),
        ConnState::Connected { tunnel } => {
            let subnets: Vec<String> = tunnel.subnets.iter().map(ToString::to_string).collect();
            format!(
                "Connected ({} as {})\n  Subnets: {}\n  DNS domains: {}",
                clean(&tunnel.interface),
                clean(&tunnel.address),
                subnets.join(", "),
                clean(&tunnel.dns_domains.join(", "))
            )
        }
    }
}

/// What to do when the service is installed but stopped. The Windows
/// service is registered as `ubc-vpn` ("UBC VPN Service") by the service's
/// install command.
#[cfg(windows)]
const START_THE_SERVICE: &str = "Start it from an administrator's command prompt with \
     `sc start ubc-vpn`, or restart the computer.";
#[cfg(not(windows))]
const START_THE_SERVICE: &str = "Start the UBC VPN service as an administrator, or \
     restart the computer.";

/// The exit code and the sentence for each way of failing.
fn explain(error: &ClientError) -> (u8, String) {
    match error {
        ClientError::NotInstalled => (
            NOT_RUNNING,
            "UBC VPN is not installed on this computer: there is no UBC VPN service. \
             Install UBC VPN, then try again."
                .to_string(),
        ),
        ClientError::NotRunning => (
            NOT_RUNNING,
            format!("The UBC VPN service is installed but not running. {START_THE_SERVICE}"),
        ),
        ClientError::Mismatch(service) => {
            let service = service
                .as_deref()
                .map_or("another version".to_string(), clean);
            let message = format!(
                "Version mismatch: the service is {service} and this program is {VERSION}. \
                 Please update UBC VPN."
            );
            (MISMATCH, message)
        }
        ClientError::NotOwner => (
            NOT_OWNER,
            "You are not the owner: UBC VPN on this computer belongs to another user, the \
             first to use it, and only that user can control it. Ask them, or an \
             administrator can make you the owner by deleting the file state.json in \
             UBC VPN's state folder and restarting the service."
                .to_string(),
        ),
        ClientError::NotTheService => (
            NOT_THE_SERVICE,
            "Another program is answering in place of the UBC VPN service. Nothing was sent \
             to it. Restart the service, or reinstall UBC VPN."
                .to_string(),
        ),
        ClientError::Refused(error) => (FAILED, clean(&error.message)),
        ClientError::Lost(why) => (FAILED, format!("Lost contact with the service: {why}.")),
    }
}
