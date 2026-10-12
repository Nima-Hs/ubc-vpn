//! The command-line client. It logs in and talks to the service. Only
//! `status` exists so far.

use std::io::Write;
use std::process::ExitCode;

use ubc_vpn_core::VERSION;
use ubc_vpn_core::protocol::{ClientKind, RequestBody, ResponseBody, encode};
use ubc_vpn_core::state::ConnState;
use ubc_vpn_platform::{Mode, Platform};

use client::{Client, ClientError};

mod client;
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
  status [--json]   Show whether the VPN is connected
  help              Show this text
  version           Show the version";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let installed = || Platform::native(Mode::Installed);
    let (mut out, mut err) = (std::io::stdout(), std::io::stderr());
    ExitCode::from(run(&args, &installed, &mut out, &mut err))
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
        ["status"] => false,
        ["status", "--json"] => true,
        _ => return say(err, HELP, USAGE),
    };
    let shown = status(platform).and_then(|state| match json {
        // One JSON line, exactly as the service reports the state.
        true => Ok(encode(&state)?.trim_end().to_string()),
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
    let name = &platform.paths.channel_name;
    let mut client = Client::connect(&*platform.transport, name, ClientKind::Cli)?;
    client.claim_if_unowned()?;
    match client.request(RequestBody::Status)? {
        ResponseBody::Status(state) => Ok(state),
        other => Err(ClientError::Lost(format!("unexpected answer: {other:?}"))),
    }
}

/// Text that came from the service, made safe to print: without control
/// characters, which could do anything to a terminal.
fn clean(text: &str) -> String {
    text.chars().filter(|c| !c.is_control()).collect()
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

/// The exit code and the sentence for each way of failing.
fn explain(error: &ClientError) -> (u8, String) {
    match error {
        ClientError::NotRunning => (
            NOT_RUNNING,
            "The UBC VPN service is not running.".to_string(),
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
            "You are not the owner. Only the first user of UBC VPN on this computer can \
             control it."
                .to_string(),
        ),
        ClientError::NotTheService => (
            NOT_THE_SERVICE,
            "Another program is answering in place of the UBC VPN service. Nothing was sent \
             to it. Restart the service, or reinstall UBC VPN."
                .to_string(),
        ),
        ClientError::Refused(error) => (FAILED, clean(&error.message)),
        ClientError::Lost(why) => (FAILED, format!("The service did not answer: {why}.")),
    }
}
