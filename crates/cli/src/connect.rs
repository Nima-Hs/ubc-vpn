//! `ubc-vpn connect` and `ubc-vpn disconnect`, as a person runs them in a
//! terminal.
//!
//! A connect logs in to the gateway named by the service's policy, then hands
//! the service the session cookie, the address that issued it and the routes
//! the user saved. Everything that can be checked without logging in is
//! checked first, so that a connect which could not succeed asks nothing and
//! sends no MFA request.
//!
//! A username the user typed is saved in their settings once the service
//! has accepted a connect made with it, so it is not asked for again. A
//! saved username that the gateway refuses is removed, so the next connect
//! asks for it: until there is a way to forget it on purpose, that is how a
//! wrong one is corrected. Nothing is saved after a login that failed or
//! was given up.
//!
//! The password, the one-time code and the cookie are [`Secret`]s. They are
//! never printed or put in a message, they are registered with the engine's
//! log sink, and the cookie leaves this program only inside the one request
//! to the service.

use std::io::Write;
use std::sync::{Arc, Mutex};

use ubc_vpn_core::login::{LoginErrorCode, PromptKind};
use ubc_vpn_core::policy::Policy;
use ubc_vpn_core::protocol::CERTIFICATE_CHANGED;
use ubc_vpn_core::protocol::LogLevel as LineLevel;
use ubc_vpn_core::protocol::{
    AddLogParams, ClientKind, ConnectParams, ErrorCode, Event, LogText, MAX_ADDED_LOG_LINES,
    RequestBody, ResponseBody,
};
use ubc_vpn_core::redact::{REDACTED, Secret};
use ubc_vpn_core::settings::Settings;
use ubc_vpn_core::settings_cli::SettingsFailureCode;
use ubc_vpn_core::state::ConnState;
use ubc_vpn_engine::{
    Cancel, Gateway, LogLevel, LogSink, LoginEngine, LoginError, Prompt, Prompts, Session,
};
use ubc_vpn_platform::Platform;

use std::time::Instant;

use crate::client::{Client, ClientError, Limits};
use crate::interrupt::{Progress, Steps};
use crate::{FAILED, clean, describe, explain, say, settings};

/// The VPN is connected, or a connect or disconnect is in progress.
pub const BUSY: u8 = 7;
/// The gateway refused the login, or the session has ended.
pub const LOGIN_REFUSED: u8 = 8;

/// What a user is told when the gateway did not take the login in a way that
/// points at the username. UBC's gateway reads the way to confirm the login
/// from the username, so a username in another form is the usual cause. The
/// example is made up.
pub const CHECK_USERNAME: &str = "The gateway did not take the login. Check your username: \
UBC's gateway expects your CWL username, your department and the way to confirm, \
as CWL.dept@method, for example user.ece@app.";
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

    /// One answer, or `None` to stop the login: the user gave up, or
    /// [`Ask::failure`] says what went wrong.
    fn ask(&mut self, prompt: &Prompt) -> Option<Secret>;

    /// Why the last `None` was not the user giving up, if it was not.
    fn failure(&self) -> Option<String> {
        None
    }

    /// Whether the last `None` was the user pressing Ctrl-C at a question.
    fn interrupted(&self) -> bool {
        false
    }
}

/// How a connect ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ended {
    /// With this exit status, having said what there was to say.
    Status(u8),
    /// The user pressed Ctrl-C at a question. Nothing was sent to the
    /// service and the outcome is not reported; the program ends with the
    /// status that is usual for that.
    Interrupted,
    /// A request to stop came from outside while the connect was under way,
    /// and whoever handles those is ending the program. The outcome is not
    /// reported and nothing more should be done here.
    Stopping,
}

/// The most of a question's label and of its message that is shown, in
/// UTF-16 code units, which is how the app counts them. The gateway words
/// both, and a question must always fit in one line.
pub(crate) const MAX_LABEL: usize = 200;
pub(crate) const MAX_MESSAGE: usize = 1000;

/// A piece of the gateway's wording made fit to show: without control
/// characters, and no longer than `most`.
pub(crate) fn worded(text: &str, most: usize) -> String {
    cut(&clean(text), most)
}

/// The start of `text`: as many whole characters as fit in `most` UTF-16
/// code units.
fn cut(text: &str, most: usize) -> String {
    let mut room = most;
    let fits = |c: &char| {
        let fit = c.len_utf16() <= room;
        room = room.saturating_sub(c.len_utf16());
        fit
    };
    text.chars().take_while(fits).collect()
}

/// The engine that logs in to the gateway `policy` names, or why there is
/// none: this build has no engine, or the VPN library could not be loaded.
pub type Engines<'a> = &'a dyn Fn(&Policy) -> Result<Box<dyn LoginEngine>, String>;

/// Why a command stopped.
pub(crate) struct Stop {
    /// The exit status.
    pub exit: u8,
    /// The same reason as the app is told it by `connect --json`.
    pub code: LoginErrorCode,
    /// A sentence for the user.
    pub message: String,
}

/// A failure that has no exit status of its own.
fn failed(code: LoginErrorCode, message: &str) -> Stop {
    Stop {
        exit: FAILED,
        code,
        message: message.to_string(),
    }
}

pub(crate) fn stop(error: ClientError) -> Stop {
    let code = match &error {
        ClientError::Refused(refusal) => match refusal.code {
            ErrorCode::Busy => return busy(),
            ErrorCode::NotOwner => LoginErrorCode::NotOwner,
            ErrorCode::RouteRefused => LoginErrorCode::RouteRefused,
            _ => LoginErrorCode::Internal,
        },
        ClientError::NotOwner => LoginErrorCode::NotOwner,
        // Not running, another version, another program in its place, or
        // gone part-way: each has its own sentence.
        _ => LoginErrorCode::ServiceUnavailable,
    };
    let (exit, message) = explain(&error);
    Stop {
        exit,
        code,
        message,
    }
}

fn cancelled() -> Stop {
    Stop {
        exit: CANCELLED,
        ..failed(
            LoginErrorCode::Cancelled,
            &LoginError::Cancelled.to_string(),
        )
    }
}

fn busy() -> Stop {
    let message = "The VPN is connected, or is connecting or disconnecting. \
                   Run `ubc-vpn disconnect` first.";
    Stop {
        exit: BUSY,
        ..failed(LoginErrorCode::Busy, message)
    }
}

/// Runs `connect` and says how it ended. `progress` is told when the
/// connect request goes to the service, and is asked whether a request to
/// stop has come.
pub fn connect(
    platform: &dyn Fn() -> ubc_vpn_platform::Result<Platform>,
    engines: Engines,
    ask: &mut dyn Ask,
    progress: &Progress,
    limits: Limits,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Ended {
    let started = start(
        platform,
        engines,
        ask,
        &Cancel::new(),
        limits,
        progress,
        err,
    );
    // The request never went, or failed: an undo waiting for its answer
    // need wait no longer. An answered one was marked as soon as the
    // answer came, inside `start`.
    progress.settled();
    let ended = started.and_then(|mut client| follow(&mut client, &ConnState::Connecting));
    // A stop from outside is being handled elsewhere, and what this saw of
    // it (a disconnect, say) is not news. Ctrl-C at a question is the user
    // leaving. Neither is reported. Otherwise the outcome is the user's to
    // see, and from this step on a stop no longer undoes it.
    if !progress.finish() {
        return Ended::Stopping;
    }
    if ask.interrupted() {
        return Ended::Interrupted;
    }
    Ended::Status(report(ended, &ConnState::Connecting, out, err))
}

/// Tells the service to disconnect, for a connect that was stopped after
/// its request had gone. It waits only for the service to take the request,
/// and says nothing: the program is about to end.
pub fn undo(platform: &dyn Fn() -> ubc_vpn_platform::Result<Platform>, limits: Limits) {
    let _ = service(platform, limits).and_then(|mut client| {
        let asked = client.request(RequestBody::Disconnect);
        asked.map_err(stop)
    });
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
        Err(stop) => (stop.exit, stop.message),
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
    let connected = Client::reach(platform, ClientKind::Cli, limits);
    let mut client = connected.map_err(stop)?;
    client.claim_if_unowned().map_err(stop)?;
    Ok(client)
}

/// Does everything up to the service accepting the connect request: the
/// checks, the login, and the request. `cancel` stops the login. `steps`
/// is asked just before the request would go to the service, and the
/// request goes only if it says so; it is told as soon as the answer
/// comes; and it says whether the user has stopped the command.
pub(crate) fn start(
    platform: &dyn Fn() -> ubc_vpn_platform::Result<Platform>,
    engines: Engines,
    ask: &mut dyn Ask,
    cancel: &Cancel,
    limits: Limits,
    steps: &dyn Steps,
    err: &mut dyn Write,
) -> Result<Client, Stop> {
    let internal = |message: &str| failed(LoginErrorCode::Internal, message);
    if let Some(why) = ask.unusable() {
        return Err(internal(&why));
    }
    let platform = platform().map_err(|e| stop(e.into()))?;

    // What can be known without logging in is checked before logging in.
    let no_policy = "The policy file is missing or not valid. Reinstall UBC VPN.";
    let policy = settings::policy(&platform.paths.policy_dir).ok_or_else(|| internal(no_policy))?;
    let gateway = Gateway::from_policy(&policy).map_err(|_| internal(no_policy))?;

    let engine = engines(&policy).map_err(|why| internal(&why))?;
    let saved = saved(&platform)?;
    // The routes come from the user's settings and from nowhere else.
    if let Err(why) = saved.routes.check(policy.allowed_routes.as_deref()) {
        // The reason can quote the settings file. It does so with every
        // control character written out as an escape, which a test checks.
        let message = format!("The saved routes cannot be used: {why}. Change them in the app.");
        return Err(failed(LoginErrorCode::RouteRefused, &message));
    }
    // A user already known to have given up is not made the owner of
    // anything. This catches only a cancel that has been seen by now: one
    // still on its way, from another thread, is caught before the request.
    if cancel.is_cancelled() {
        return Err(cancelled());
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

    let (mut typed, mut said) = (None, Vec::new());
    let name = saved.username.as_deref();
    let asked = Asked {
        username: name,
        typed: &mut typed,
        said: &mut said,
    };
    let logged_in = login(&*engine, &gateway, asked, ask, cancel, err);
    let Session {
        cookie,
        gateway_addr,
    } = match logged_in {
        Ok(session) => session,
        Err(stop) => {
            // Why a login failed is what the log is most wanted for: the
            // lines the login printed, and how it ended. A user who gave up
            // is told only that, since nothing went wrong; and one who
            // pressed Ctrl-C at a question is leaving at once, and is not
            // kept waiting for it.
            let outcome = (
                LineLevel::Error,
                format!("login failed: {}", word(&stop.code)),
            );
            match stop.code {
                LoginErrorCode::Cancelled if ask.interrupted() => {}
                LoginErrorCode::Cancelled => hand_over(&mut client, &[], outcome),
                _ => hand_over(&mut client, &said, outcome),
            }
            // The gateway does not say which answer it refused. A saved
            // username may be the one, and nothing else lets the user
            // change it, so it is forgotten and asked for next time.
            let refused = [LoginErrorCode::WrongPassword, LoginErrorCode::CheckUsername];
            if refused.contains(&stop.code) && name.is_some() {
                remember(&platform, &policy, None, err);
            }
            return Err(stop);
        }
    };
    // The cookie goes into the request and nowhere else.
    let params = ConnectParams {
        cookie,
        gateway_addr,
        routes: saved.routes,
    };
    // The last moment a cancel can still stop the connect. A login that was
    // cancelled too late to stop still yields a session; it is thrown away
    // here, because the user gave up.
    if cancel.is_cancelled() {
        return Err(cancelled());
    }
    // A request to stop that has come by now found nothing to undo, so
    // there must be nothing: the request is not sent.
    if !steps.sending() {
        return Err(cancelled());
    }
    let asked = client.request(RequestBody::Connect(params));
    // At once, before anything else is sent or saved: an undo waiting for
    // this answer may go now.
    steps.answered();
    // After the request, so that the service holds the cookie by now and
    // removes it from these lines as well, should one have kept it.
    let outcome = (LineLevel::Info, "login succeeded".to_string());
    hand_over(&mut client, &said, outcome);
    asked.map_err(stop)?;
    // Only now, with the login good and the connect accepted, is a username
    // the user typed worth keeping. Not if the user has stopped the
    // command: it is being undone, and the settings stay as they were.
    if let Some(typed) = typed.filter(|_| !steps.stopped()) {
        remember(&platform, &policy, Some(typed.expose()), err);
    }
    Ok(client)
}

/// Saves `username` in the user's settings, or forgets the saved one. A
/// connect never fails over this: the user is told, and is asked for the
/// username again next time. A name too odd to keep is quietly not kept.
fn remember(platform: &Platform, policy: &Policy, username: Option<&str>, err: &mut dyn Write) {
    let dir = &platform.paths.settings_dir;
    let kept = settings::remember_username(dir, Some(policy), username);
    if kept.is_err_and(|why| why != SettingsFailureCode::BadInput) {
        let _ = writeln!(
            err,
            "ubc-vpn: The username could not be saved in the settings."
        );
    }
}

/// The user's settings, or the defaults when none are saved.
fn saved(platform: &Platform) -> Result<Settings, Stop> {
    let dir = &platform.paths.settings_dir;
    let unreadable = |_| {
        let unsafe_folder = settings::folder_problem(dir);
        let why = unsafe_folder.unwrap_or_else(|| "The settings file cannot be read.".to_string());
        failed(LoginErrorCode::Internal, &why)
    };
    let text = settings::stored(dir).map_err(unreadable)?;
    match text {
        Some(text) => settings::understood(&text).map_err(unreadable),
        None => Ok(Settings::default()),
    }
}

/// Gives the service what the login wrote, for its log: its lines, each at
/// its own level and as cleaned as the printed ones, the last of them if
/// there are more than one connection may add. A line too long to keep is
/// left out with the marker. This never fails a connect: it stops at the
/// first line the service does not take, and whatever broke shows at the
/// next request.
pub(crate) fn hand_over(
    client: &mut Client,
    said: &[(LineLevel, String)],
    outcome: (LineLevel, String),
) {
    let said: Vec<&(LineLevel, String)> = said
        .iter()
        .filter(|(_, line)| !line.trim().is_empty())
        .collect();
    // The outcome is always sent, and last, so the lines before it leave
    // room for it.
    let from = said.len().saturating_sub(MAX_ADDED_LOG_LINES - 1);
    let kept = said[from..]
        .iter()
        .map(|(level, line)| (*level, line.as_str()));
    let (level, text) = (outcome.0, outcome.1.as_str());
    for (level, line) in kept.chain([(level, text)]) {
        let text = LogText::cleaned(line).unwrap_or_else(|_| LogText::left_out());
        let add = RequestBody::AddLog(AddLogParams {
            level,
            text: text.into(),
        });
        if client.request(add).is_err() {
            return;
        }
    }
}

/// How a login failed, for the log: the word the protocol sends, such as
/// `gateway_unreachable`. Not for a refused login, or one whose name is to
/// be checked: their words hold `pass` and `username`, which the log takes
/// for the start of a secret and cuts, so those are said in other words.
fn word(code: &LoginErrorCode) -> String {
    match code {
        LoginErrorCode::WrongPassword => return "refused by the gateway".to_string(),
        LoginErrorCode::CheckUsername => {
            return "refused by the gateway, check the name's form".to_string();
        }
        _ => {}
    }
    let quoted = serde_json::to_string(code).unwrap_or_default();
    quoted.trim_matches('"').to_string()
}

/// What a login starts with and what it leaves behind.
struct Asked<'a> {
    /// The saved username, which answers that question for the user.
    username: Option<&'a str>,
    /// A username the user was asked for.
    typed: &'a mut Option<Secret>,
    /// The lines the login wrote, each with its level, cleaned as a printed
    /// line is.
    said: &'a mut Vec<(LineLevel, String)>,
}

/// Logs in, asking the user what the gateway asks. A saved username answers
/// the question for it; everything else is asked, and nothing is asked twice
/// (the engine's [`Prompts`] sees to that).
fn login(
    engine: &dyn LoginEngine,
    gateway: &Gateway,
    asked: Asked,
    ask: &mut dyn Ask,
    cancel: &Cancel,
    err: &mut dyn Write,
) -> Result<Session, Stop> {
    let Asked {
        username,
        typed,
        said,
    } = asked;
    let lines = Arc::new(Mutex::new(Vec::new()));
    let kept = lines.clone();
    let keep = move |level, line: &str| kept.lock().unwrap().push((level, line.to_string()));
    // Progress as well as errors, for the service's log. Only errors are
    // printed: the engine reports the library's own complaints as progress,
    // since many do not end a login, and says itself what failed.
    let logs = LogSink::new(LogLevel::Info, keep);
    let mut answer = |prompt: &Prompt| {
        let given = match (prompt.kind, username) {
            (PromptKind::Username, Some(name)) => Some(Secret::new(name)),
            (PromptKind::Username, None) => {
                *typed = ask.ask(prompt);
                typed.clone()
            }
            _ => ask.ask(prompt),
        };
        // Whatever was typed is kept out of every log line from here on.
        given.inspect(|secret| logs.hide(secret))
    };
    let mut prompts = Prompts::new(&mut answer);
    let result = engine.login(gateway, &mut prompts, cancel, &logs);
    // The engine held the cookie before this code did, so a line it wrote on
    // the way may show it. The lines are printed only now, with it removed.
    // They can also carry text the gateway sent, some of it from before its
    // certificate was judged, so they go through `clean` like any text that
    // is not this program's own.
    let cookie = result.as_ref().ok().map(|session| session.cookie.expose());
    for (level, line) in lines.lock().unwrap().iter() {
        let line = match cookie {
            Some(cookie) if !cookie.is_empty() => line.replace(cookie, REDACTED),
            _ => line.clone(),
        };
        let line = clean(&line);
        let level = match level {
            LogLevel::Error => LineLevel::Error,
            _ => LineLevel::Info,
        };
        if level == LineLevel::Error {
            let _ = writeln!(err, "ubc-vpn: {line}");
        }
        said.push((level, line));
    }
    // A login that stopped at a question was given up by the user, unless
    // the one asking says otherwise.
    let stopped = ask.failure();
    result.map_err(|error| {
        if let Some(why) = &stopped {
            return failed(LoginErrorCode::Internal, why);
        }
        let (exit, code) = match error {
            LoginError::WrongPassword => (LOGIN_REFUSED, LoginErrorCode::WrongPassword),
            LoginError::CheckUsername => (LOGIN_REFUSED, LoginErrorCode::CheckUsername),
            LoginError::Cancelled => return cancelled(),
            LoginError::PinMismatch => (FAILED, LoginErrorCode::PinMismatch),
            LoginError::GatewayUnreachable => (FAILED, LoginErrorCode::GatewayUnreachable),
            LoginError::Failed => (FAILED, LoginErrorCode::Internal),
        };
        // A key the policy does not pin almost always means the gateway's
        // certificate was replaced: the user is told to update.
        let message = match error {
            LoginError::PinMismatch => CERTIFICATE_CHANGED.to_string(),
            LoginError::CheckUsername => CHECK_USERNAME.to_string(),
            other => other.to_string(),
        };
        Stop {
            exit,
            ..failed(code, &message)
        }
    })
}

/// Waits for the state the service ends in, after it has reported `during`,
/// for no longer than [`Limits::outcome`]. States from before the request
/// are passed over.
fn follow(client: &mut Client, during: &ConnState) -> Result<ConnState, Stop> {
    let deadline = Instant::now() + client.limits().outcome;
    let mut started = false;
    loop {
        // A log line is not a state. None is sent unless asked for, and
        // this asks for none.
        let Event::StateChanged(state) = client.next_event(Some(deadline)).map_err(stop)? else {
            continue;
        };
        match (state == *during, started) {
            (true, _) => started = true,
            (false, true) => return Ok(state),
            (false, false) => {}
        }
    }
}
