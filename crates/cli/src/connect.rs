//! `ubc-vpn connect` and `ubc-vpn disconnect`, as a person runs them in a
//! terminal.
//!
//! A connect logs in to the gateway named by the service's policy, then hands
//! the service the session cookie, the address that issued it and the routes
//! the user saved. Everything that can be checked without logging in is
//! checked first, so that a connect which could not succeed asks nothing and
//! sends no MFA request.
//!
//! The password, the one-time code and the cookie are [`Secret`]s. They are
//! never printed or put in a message, they are registered with the engine's
//! log sink, and the cookie leaves this program only inside the one request
//! to the service.

use std::io::Write;
use std::sync::{Arc, Mutex};

use ubc_vpn_core::login::PromptKind;
use ubc_vpn_core::policy::Policy;
use ubc_vpn_core::protocol::{
    ClientKind, ConnectParams, ErrorCode, Event, RequestBody, ResponseBody,
};
use ubc_vpn_core::redact::{REDACTED, Secret};
use ubc_vpn_core::settings::Settings;
use ubc_vpn_core::state::ConnState;
use ubc_vpn_engine::{
    Cancel, Gateway, LogLevel, LogSink, LoginEngine, LoginError, Prompt, Prompts, Session,
};
use ubc_vpn_platform::Platform;

use std::time::Instant;

use crate::client::{Client, ClientError, Limits};
use crate::{FAILED, clean, describe, explain, say, settings};

/// The VPN is connected, or a connect or disconnect is in progress.
pub const BUSY: u8 = 7;
/// The gateway refused the login, or the session has ended.
pub const LOGIN_REFUSED: u8 = 8;
/// The user gave up.
pub const CANCELLED: u8 = 9;

/// How the user is asked for what the gateway wants to know.
///
/// In a terminal the answer to a password or code question is typed with
/// nothing shown, and is never read from a pipe or a file.
pub trait Ask {
    /// Why the user cannot be asked at all, if that is so. A connect checks
    /// this before it does anything else.
    fn unusable(&self) -> Option<String>;

    /// One answer, or `None` when the user gave up.
    fn ask(&mut self, prompt: &Prompt) -> Option<Secret>;
}

/// The engine that logs in to the gateway `policy` names, if this build has
/// one.
pub type Engines<'a> = &'a dyn Fn(&Policy) -> Option<Box<dyn LoginEngine>>;

/// Why a command stopped: its exit status and a sentence for the user.
type Stop = (u8, String);

fn stop(error: ClientError) -> Stop {
    match &error {
        ClientError::Refused(refusal) if refusal.code == ErrorCode::Busy => busy(),
        _ => explain(&error),
    }
}

fn busy() -> Stop {
    let message = "The VPN is connected, or is connecting or disconnecting. \
                   Run `ubc-vpn disconnect` first.";
    (BUSY, message.to_string())
}

/// Runs `connect` and returns the exit status.
pub fn connect(
    platform: &dyn Fn() -> ubc_vpn_platform::Result<Platform>,
    engines: Engines,
    ask: &mut dyn Ask,
    limits: Limits,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    let ended = try_connect(platform, engines, ask, limits, err);
    report(ended, &ConnState::Connecting, out, err)
}

/// Runs `disconnect` and returns the exit status.
pub fn disconnect(
    platform: &dyn Fn() -> ubc_vpn_platform::Result<Platform>,
    limits: Limits,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    let ended = service(platform, limits).and_then(|mut client| {
        client.request(RequestBody::Disconnect).map_err(stop)?;
        follow(&mut client, &ConnState::Disconnecting)
    });
    report(ended, &ConnState::Disconnecting, out, err)
}

/// Says how a command ended. The state it was after goes to standard output;
/// anything else is a failure and goes to standard error.
fn report(
    ended: Result<ConnState, Stop>,
    during: &ConnState,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    let connecting = *during == ConnState::Connecting;
    let (code, message) = match ended {
        Ok(state @ ConnState::Connected { .. }) if connecting => {
            return say(out, &describe(&state), 0);
        }
        Ok(state @ ConnState::Disconnected) if !connecting => {
            return say(out, &describe(&state), 0);
        }
        Ok(state @ ConnState::LoginNeeded) => (LOGIN_REFUSED, describe(&state)),
        Ok(state) => (FAILED, describe(&state)),
        Err(stop) => stop,
    };
    say(err, &format!("ubc-vpn: {message}"), code)
}

/// Connects to the service as its owner, claiming it on first use.
fn service(
    platform: &dyn Fn() -> ubc_vpn_platform::Result<Platform>,
    limits: Limits,
) -> Result<Client, Stop> {
    let platform = platform().map_err(|e| stop(e.into()))?;
    owner(&platform, limits)
}

fn owner(platform: &Platform, limits: Limits) -> Result<Client, Stop> {
    let (transport, name) = (&*platform.transport, &platform.paths.channel_name);
    let connected = Client::connect_within(transport, name, ClientKind::Cli, limits);
    let mut client = connected.map_err(stop)?;
    client.claim_if_unowned().map_err(stop)?;
    Ok(client)
}

fn try_connect(
    platform: &dyn Fn() -> ubc_vpn_platform::Result<Platform>,
    engines: Engines,
    ask: &mut dyn Ask,
    limits: Limits,
    err: &mut dyn Write,
) -> Result<ConnState, Stop> {
    let failed = |message: &str| (FAILED, message.to_string());
    if let Some(why) = ask.unusable() {
        return Err((FAILED, why));
    }
    let platform = platform().map_err(|e| stop(e.into()))?;

    // What can be known without logging in is checked before logging in.
    let no_policy = "The policy file is missing or not valid. Reinstall UBC VPN.";
    let policy = settings::policy(&platform.paths.policy_dir).ok_or_else(|| failed(no_policy))?;
    let gateway = Gateway::from_policy(&policy).map_err(|_| failed(no_policy))?;
    let no_engine = "This build has no VPN engine yet, so it cannot connect.";
    let engine = engines(&policy).ok_or_else(|| failed(no_engine))?;
    let saved = saved(&platform)?;
    // The routes come from the user's settings and from nowhere else.
    if let Err(why) = saved.routes.check(policy.allowed_routes.as_deref()) {
        // The reason can quote the settings file. It does so with every
        // control character written out as an escape, which a test checks.
        let message = format!("The saved routes cannot be used: {why}. Change them in the app.");
        return Err((FAILED, message));
    }
    let mut client = owner(&platform, limits)?;
    let now = client.request(RequestBody::Status).map_err(stop)?;
    let idle = [
        ResponseBody::Status(ConnState::Disconnected),
        ResponseBody::Status(ConnState::LoginNeeded),
    ];
    if !idle.contains(&now) && !matches!(now, ResponseBody::Status(ConnState::Failed { .. })) {
        return Err(busy());
    }

    let Session {
        cookie,
        gateway_addr,
    } = login(&*engine, &gateway, saved.username.as_deref(), ask, err)?;
    // The cookie goes into the request and nowhere else.
    let params = ConnectParams {
        cookie,
        gateway_addr,
        routes: saved.routes,
    };
    client.request(RequestBody::Connect(params)).map_err(stop)?;
    follow(&mut client, &ConnState::Connecting)
}

/// The user's settings, or the defaults when none are saved.
fn saved(platform: &Platform) -> Result<Settings, Stop> {
    let unreadable = |_| (FAILED, "The settings file cannot be read.".to_string());
    let text = settings::stored(&platform.paths.settings_dir).map_err(unreadable)?;
    match text {
        Some(text) => settings::understood(&text).map_err(unreadable),
        None => Ok(Settings::default()),
    }
}

/// Logs in, asking the user what the gateway asks. A saved username answers
/// the question for it; everything else is asked, and nothing is asked twice
/// (the engine's [`Prompts`] sees to that).
fn login(
    engine: &dyn LoginEngine,
    gateway: &Gateway,
    username: Option<&str>,
    ask: &mut dyn Ask,
    err: &mut dyn Write,
) -> Result<Session, Stop> {
    let lines = Arc::new(Mutex::new(Vec::new()));
    let kept = lines.clone();
    let keep = move |_, line: &str| kept.lock().unwrap().push(line.to_string());
    let logs = LogSink::new(LogLevel::Error, keep);
    let mut answer = |prompt: &Prompt| {
        let given = match (prompt.kind, username) {
            (PromptKind::Username, Some(name)) => Some(Secret::new(name)),
            _ => ask.ask(prompt),
        };
        // Whatever was typed is kept out of every log line from here on.
        given.inspect(|secret| logs.hide(secret))
    };
    let mut prompts = Prompts::new(&mut answer);
    let result = engine.login(gateway, &mut prompts, &Cancel::new(), &logs);
    // The engine held the cookie before this code did, so a line it wrote on
    // the way may show it. The lines are printed only now, with it removed.
    // They can also carry text the gateway sent, some of it from before its
    // certificate was judged, so they go through `clean` like any text that
    // is not this program's own.
    let cookie = result.as_ref().ok().map(|session| session.cookie.expose());
    for line in lines.lock().unwrap().iter() {
        let line = match cookie {
            Some(cookie) if !cookie.is_empty() => line.replace(cookie, REDACTED),
            _ => line.clone(),
        };
        let _ = writeln!(err, "ubc-vpn: {}", clean(&line));
    }
    result.map_err(|error| {
        let code = match error {
            LoginError::WrongPassword => LOGIN_REFUSED,
            LoginError::Cancelled => CANCELLED,
            _ => FAILED,
        };
        (code, error.to_string())
    })
}

/// Waits for the state the service ends in, after it has reported `during`,
/// for no longer than [`Limits::outcome`]. States from before the request
/// are passed over.
fn follow(client: &mut Client, during: &ConnState) -> Result<ConnState, Stop> {
    let deadline = Instant::now() + client.limits().outcome;
    let mut started = false;
    loop {
        let Event::StateChanged(state) = client.next_event(Some(deadline)).map_err(stop)?;
        match (state == *during, started) {
            (true, _) => started = true,
            (false, true) => return Ok(state),
            (false, false) => {}
        }
    }
}
