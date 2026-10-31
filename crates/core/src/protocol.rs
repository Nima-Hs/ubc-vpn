//! The channel protocol between a client and the service.
//!
//! The client is always the command-line client. It opens the channel for
//! itself, or for the app when run as `ubc-vpn bridge` (see
//! [`crate::bridge`]); the app never opens the channel.
//!
//! Messages are JSON, one per line. The client opens with a [`Hello`] and the
//! service answers with a [`HelloReply`]. After that the client sends
//! [`Request`]s and the service sends [`ServerMessage`]s: one response per
//! request, plus events whenever the connection state changes, and when a
//! switch of tunnel mode was undone ([`Event::SwitchUndone`]).
//!
//! # The service's log
//!
//! The owner can read what the service has logged, and ask to be sent new
//! lines as they come. A [`LogLine`] is one line of text that is safe to
//! show: the service has already removed every secret it held and every
//! character that could mislead, and the type refuses anything else.
//!
//! - Lines are numbered by `seq`, from 1, within one run of the service.
//!   A service that restarts starts again at 1 with a new `run`, so a place
//!   in the log is a [`LogCursor`]: a run and a number. Numbers are given
//!   out without gaps, but a page may skip the numbers of lines that are
//!   no longer held.
//! - `logs` answers with a [`LogPage`]: the lines whose `seq` is greater
//!   than the cursor's, oldest first, as many as fit. No cursor means
//!   after 0, and so does a cursor from another run: the page then starts
//!   from the oldest line held, and the client sees the run changed by
//!   comparing `run`. `next` is the `seq` of the last line in the page, or
//!   the cursor that was used when the page is empty. Ask again from
//!   `next` until a page is empty.
//! - `dropped` means exactly this: at least one line of this run with a
//!   `seq` greater than the cursor that was used existed and is no longer
//!   held, whichever kind of line it was. So the first read of a run that
//!   has already lost lines says `dropped`, and a cursor from another run
//!   does not by itself.
//! - Every number here stays below 2^53, so it is exact as a JavaScript
//!   `number`, which is how the generated TypeScript carries it. A count
//!   of milliseconds or of lines does not reach that in any real run.
//! - `watch_logs` turns [`Event::Log`] on or off for one connection, and
//!   is answered with `accepted` ([`ResponseBody::Accepted`]). To miss
//!   nothing, turn it on first, then fetch with `logs`, and drop whatever
//!   arrives twice, by `seq`.
//! - A log event is not a promise. When a client is slow to take its
//!   events the service drops log events for it, never state changes. No
//!   number of log events waiting for a client closes its connection; a
//!   write that fails after the write limit closes it, as for any message.
//!   The gap shows in `seq`, and `logs` fills it.
//! - `add_log` lets the command-line client hand over what its login
//!   wrote. The service removes secrets from it as it does from its own
//!   lines, and keeps it as [`LogSource::Login`]. Such lines are kept apart from the service's
//!   own, [`KEPT_ADDED_LOG_LINES`] of them, so no client can push a line
//!   of the service's out; and one connection may add
//!   [`MAX_ADDED_LOG_LINES`]. A line that is kept is answered with
//!   `accepted` ([`ResponseBody::Accepted`]). A text that is not a
//!   [`LogText`], because it is too long or is not one plain line, and
//!   any line from a connection that has added all it may, is answered
//!   with the error `bad_request` ([`ErrorCode::BadRequest`]); nothing of
//!   it is kept and the connection stays open.
//! - `diagnostics` answers with a [`Diagnostics`]: what a person helping
//!   the user would ask first, with no path and no user name in it. It is
//!   small whatever the state: it counts what the tunnel carries and does
//!   not list it.
//!
//! All of these are for the owner only.
//!
//! This module is the reference for the wire format. The TypeScript types the
//! app uses are generated from it.
//!
//! # Changing the protocol
//!
//! Requests refuse unknown fields and every enum is closed, so an older peer
//! cannot read a message that uses anything new. Any change to these types,
//! including adding a variant or a field, must bump [`PROTOCOL_VERSION`]. That
//! is cheap, because the app and the service are installed together.
//!
//! The app passes over an event of a kind it does not know, and still
//! refuses a response of a kind it does not know. That is a second line of
//! defence for the app, not a way to add an event without a new version:
//! the rule above holds for events as for everything else, and the Rust
//! peers here refuse an unknown event.
//!
//! So that a mismatch gives a clear "please update" and not a dropped
//! connection, the service reads only the version from the first line with
//! [`peek_protocol_version`], which tolerates fields it does not know. It
//! always answers with a [`HelloReply`], and parses the [`Hello`] strictly only
//! when the versions match.

use std::fmt;
use std::net::Ipv4Addr;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::redact::Secret;
use crate::routes::{Ipv4Net, RouteSet};
use crate::settings_cli::misleads;
use crate::state::{ConnState, TunnelMode};

/// Bumped whenever the wire format changes in a way an older peer could not
/// understand. A client and a service with different versions refuse to talk.
pub const PROTOCOL_VERSION: u32 = 6;

/// The longest line either side accepts, newline included. The service drops a
/// connection that sends more.
pub const MAX_LINE_BYTES: usize = 64 * 1024;

/// Which program the client end is working for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub enum ClientKind {
    /// The Electron app, through `ubc-vpn bridge`.
    App,
    /// The command-line client run by itself, or to log in and connect.
    Cli,
}

/// The first line a client sends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct Hello {
    /// The client's [`PROTOCOL_VERSION`].
    pub protocol_version: u32,
    /// Which program is connecting.
    pub client: ClientKind,
    /// The client's product version, for logs and "please update" messages.
    pub client_version: String,
}

/// The service's answer to a [`Hello`]. It is sent even when the versions
/// differ, so the client can explain why the connection is then closed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct HelloReply {
    /// The service's [`PROTOCOL_VERSION`].
    pub protocol_version: u32,
    /// The service's product version.
    pub service_version: String,
    /// Whether an owner has claimed the service. Until one has, the only
    /// request the service accepts is `claim`.
    pub owner_claimed: bool,
}

impl HelloReply {
    /// Whether the two sides can talk.
    pub fn is_compatible(&self) -> bool {
        self.protocol_version == PROTOCOL_VERSION
    }
}

/// A request from a client. The service answers with a [`Response`] carrying
/// the same `id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct Request {
    /// Chosen by the client and echoed in the response.
    pub id: u32,
    /// What is being asked.
    pub body: RequestBody,
}

/// What a client can ask for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "method",
    content = "params",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub enum RequestBody {
    /// Become the owner. Accepted from any local user while no owner exists,
    /// and from the owner afterwards; refused for everyone else.
    Claim,
    /// Report the current connection state.
    Status,
    /// Open the tunnel with a session cookie obtained by logging in.
    Connect(ConnectParams),
    /// Close the tunnel and remove its routes and DNS.
    Disconnect,
    /// Read the service's log from a place in it.
    Logs(LogsParams),
    /// Turn [`Event::Log`] on or off for this connection.
    WatchLogs(WatchLogsParams),
    /// Describe the service and its state, for someone helping the user.
    Diagnostics,
    /// Add a line to the service's log. Only the command-line client's own
    /// login sends this; the bridge refuses it from the app.
    AddLog(AddLogParams),
    /// Apply these routes to the live tunnel in place of the ones it has:
    /// add the new, remove the dropped, and verify both. Only the
    /// command-line client sends this, with the routes it has just saved in
    /// the user's settings; the bridge refuses it from the app.
    ///
    /// - **Success:** the answer is `accepted`, and the outcome comes as the
    ///   usual state event: `connected` with the new [`TunnelInfo`](crate::state::TunnelInfo).
    /// - **Refusal:** the same checks as `connect`, [`RouteSet::check`] with
    ///   the policy's allow-list and then the local-network rule against the
    ///   network captured at connect, give `route_refused`; so does a change
    ///   that adds DNS domains to a connection that has none when the DNS
    ///   servers the gateway assigned cannot be used. Nothing is changed and
    ///   the connection is kept as it was.
    /// - **No change:** subnets and domains that are, as sets, the ones the
    ///   tunnel carries (in any order, duplicates counted once) are
    ///   answered at once with `status`, the connection as it is, which
    ///   already carries them; nothing is changed, logged or reported.
    /// - **Failure while applying or verifying:** everything is torn down
    ///   and the state is `failed`. The tunnel never goes on with the old
    ///   routes, nor with a mix of old and new.
    /// - **Timing:** `busy` while connecting, disconnecting or applying
    ///   another update; `not_connected` when there is no tunnel. These
    ///   come before the no-change answer: a request that would change
    ///   nothing is still `busy` while something else is in progress.
    UpdateRoutes(RouteSet),
    /// Switch the live tunnel between split and full, in place, without
    /// reconnecting. Only the command-line client sends this, with the mode
    /// it has just saved in the user's settings; the bridge refuses it from
    /// the app.
    ///
    /// Its answers follow `update_routes` exactly:
    ///
    /// - **Success:** `accepted`, then the usual state event: `connected`
    ///   with a [`TunnelInfo`](crate::state::TunnelInfo) in the new mode.
    /// - **Refusal:** `route_refused`, with a message saying why, when full
    ///   mode cannot be had safely here: the policy forbids it, the gateway
    ///   assigned no usable DNS server, another program already routes all
    ///   traffic or resolves all names, the router is not on the local
    ///   network, IPv6 could leave by another network, or this operating
    ///   system cannot do it, which includes reporting IPv6 changes. Nothing
    ///   is changed and the connection is kept as it was. A refusal for the
    ///   policy or the operating system comes before `not_connected` and
    ///   `busy`; the others need the connection.
    /// - **No change:** the mode the tunnel already has is answered at once
    ///   with `status`, the connection as it is.
    /// - **Failure while applying or verifying:** everything is torn down
    ///   and the state is `failed`, as for `update_routes`.
    /// - **Timing:** `busy` and `not_connected` as for `update_routes`.
    SetTunnel(SetTunnelParams),
}

/// The mode to switch the live tunnel to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct SetTunnelParams {
    /// Split or full.
    pub mode: TunnelMode,
}

/// Where to read the log from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct LogsParams {
    /// The last line already read, or `None` to read from the oldest line
    /// the service still has.
    pub after: Option<LogCursor>,
}

/// Whether this connection wants [`Event::Log`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct WatchLogsParams {
    /// `true` to be sent new lines as they come, `false` to stop.
    pub on: bool,
}

/// A line for the service to keep.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct AddLogParams {
    /// How serious the line is.
    pub level: LogLevel,
    /// The line. It must be a [`LogText`]: the service answers one that is
    /// too long, or is not one plain line, with `bad_request`, and keeps
    /// nothing of it. It is a plain string here so that such a request can
    /// be answered and not merely fail to be read.
    pub text: String,
}

/// What the service needs to open a tunnel.
///
/// The gateway's name and its certificate pins are deliberately absent: the
/// service takes those from its own policy file and from nowhere else. The
/// one thing a client does supply is which of the gateway's addresses issued
/// the cookie, and that is an untrusted hint; see
/// [`ConnectParams::gateway_addr`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct ConnectParams {
    /// The session cookie the gateway issued at login.
    pub cookie: Secret,
    /// Which of the gateway's addresses issued the cookie. A gateway behind a
    /// load balancer has several, and the cookie is only good at this one.
    ///
    /// This comes from an unprivileged client, so the service treats it as a
    /// hint about where to connect and nothing more: it refuses addresses that
    /// cannot be a gateway (see [`is_plausible_gateway_addr`]), and whatever
    /// answers there must still present a key that matches a pin in the
    /// service's own policy before anything is sent to it.
    #[cfg_attr(test, ts(type = "string"))]
    pub gateway_addr: Ipv4Addr,
    /// The subnets and DNS domains to send through the tunnel.
    pub routes: RouteSet,
    /// Split or full. Left out, it is split, as before there was a choice.
    /// Full is refused, as for [`RequestBody::SetTunnel`], when it cannot
    /// be had safely here. A refusal for the policy or the operating system
    /// is the answer to the request, with nothing done. The others are a
    /// `failed` state with `route_refused`: for the network, before the
    /// gateway is contacted; for the tunnel, and for a gateway that
    /// assigned no DNS server, once the tunnel is open and before anything
    /// is applied. A DNS server that cannot be used is `engine_failed`, as
    /// in split mode.
    #[serde(default)]
    pub tunnel: TunnelMode,
}

/// Whether an address could be a VPN gateway at all.
///
/// The service calls this on [`ConnectParams::gateway_addr`] before it opens
/// any connection. It refuses the same reserved ranges that routes may not
/// touch ("this network", loopback, link-local, multicast, and the reserved
/// block that includes broadcast), so a client cannot aim the privileged
/// service at the machine's loopback or at a whole network segment.
///
/// It does not make an address trusted: the certificate pin does that. And it
/// cannot know this machine's own addresses, so the service must also refuse
/// its own interface addresses and the tunnel's address, and must add the
/// route to the gateway only after the pin has matched.
pub fn is_plausible_gateway_addr(addr: Ipv4Addr) -> bool {
    Ipv4Net::new(addr, 32).is_ok_and(|host| !host.is_reserved())
}

/// Whether a session cookie can be sent to a gateway as it is: not empty,
/// and every byte one that RFC 6265 allows in a cookie value
/// (`cookie-octet`: visible ASCII but for `"`, `,`, `;` and `\`).
///
/// The service calls this on [`ConnectParams::cookie`] before it opens any
/// connection, and every tunnel engine calls it too. The cookie comes from
/// an unprivileged program and goes into the `Cookie:` header that the
/// privileged service sends: a `;` would add cookies of the client's
/// choosing, and a CR or LF would add header lines. A gateway issues
/// nothing else, base64 padding (`=`) included, which is allowed.
pub fn is_plausible_cookie(cookie: &Secret) -> bool {
    let cookie = cookie.expose().as_bytes();
    !cookie.is_empty() && cookie.iter().all(|byte| is_cookie_octet(*byte))
}

/// RFC 6265's `cookie-octet`.
fn is_cookie_octet(byte: u8) -> bool {
    matches!(byte, 0x21 | 0x23..=0x2B | 0x2D..=0x3A | 0x3C..=0x5B | 0x5D..=0x7E)
}

/// Anything the service sends after the handshake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub enum ServerMessage {
    /// The answer to one request.
    Response(Response),
    /// Something that happened without being asked for.
    Event(Event),
}

/// The answer to the [`Request`] with the same `id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct Response {
    /// The `id` of the request being answered.
    pub id: u32,
    /// Whether it worked.
    pub outcome: Outcome,
}

/// Success or failure of a request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", content = "value", rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub enum Outcome {
    /// The request was carried out or accepted.
    Ok(ResponseBody),
    /// The request was refused or failed.
    Error(ErrorInfo),
}

/// What a successful request returns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub enum ResponseBody {
    /// The caller is now, or already was, the owner.
    Claimed,
    /// The current connection state.
    Status(ConnState),
    /// The request was accepted. Progress follows as [`Event`]s.
    Accepted,
    /// Lines of the service's log.
    Logs(LogPage),
    /// The service and its state. Boxed only because it is much the
    /// largest answer; on the wire it is the value itself.
    Diagnostics(Box<Diagnostics>),
}

/// Something the service reports without being asked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub enum Event {
    /// The connection state changed.
    StateChanged(ConnState),
    /// A switch of tunnel mode (`set_tunnel`) was applied, failed its
    /// checks, and was undone: the connection is up in the mode it had,
    /// which the [`Event::StateChanged`] sent next reports. Says why, for the
    /// client that asked, as a refusal would. A switch whose undoing failed
    /// or could not be checked closes the connection instead, and only the
    /// state says so.
    SwitchUndone(ErrorInfo),
    /// The service logged a line. Sent only to a connection that asked with
    /// `watch_logs`, and dropped when that connection is slow.
    Log(LogLine),
}

/// The longest text of one log line, in bytes.
pub const MAX_LOG_TEXT_BYTES: usize = 512;

/// About how much of a line a [`LogPage`] may fill, once encoded. It leaves
/// room for the rest of the response, so that a page can never pass
/// [`MAX_LINE_BYTES`].
pub const LOG_PAGE_BYTES: usize = 48 * 1024;

/// How many lines one connection may add with `add_log`.
pub const MAX_ADDED_LOG_LINES: usize = 20;

/// How many added lines the service keeps. They are kept apart from the
/// service's own lines, which they can therefore never push out.
pub const KEPT_ADDED_LOG_LINES: usize = 100;

/// How serious a log line is. There is no level for protocol detail: such
/// lines are never kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub enum LogLevel {
    /// Something failed.
    Error,
    /// Something is wrong but was dealt with.
    Warn,
    /// What happened, in the ordinary course.
    Info,
}

/// Who wrote a log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub enum LogSource {
    /// The service itself.
    Service,
    /// The VPN engine inside the service.
    Engine,
    /// The command-line client's login, handed over with `add_log`.
    Login,
}

/// The text of one log line: not empty, one line, at most
/// [`MAX_LOG_TEXT_BYTES`], and with no character that could mislead whoever
/// reads it (see [`misleads`]).
///
/// It cannot be made, and cannot be decoded, any other way. That it holds no
/// secret is not something a type can check: the service sees to that
/// before it makes one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, type = "string"))]
pub struct LogText(String);

/// Why a text is not a [`LogText`]. It does not repeat the text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotLogText;

impl fmt::Display for NotLogText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("not one plain line of a length that can be kept")
    }
}

impl std::error::Error for NotLogText {}

impl LogText {
    /// Stands where a line was that could not be kept.
    pub const LEFT_OUT: &'static str = "(a line that could not be kept was left out)";

    /// `text` as a log line's text, if it is one.
    pub fn new(text: &str) -> Result<Self, NotLogText> {
        let plain = !text.is_empty() && !text.chars().any(misleads);
        match plain && text.len() <= MAX_LOG_TEXT_BYTES {
            true => Ok(Self(text.to_string())),
            false => Err(NotLogText),
        }
    }

    /// `text` with every misleading character removed, if what is left is a
    /// log line's text. Nothing is cut to fit: a line that is still too
    /// long is not one, since half a line can read as something else.
    pub fn cleaned(text: &str) -> Result<Self, NotLogText> {
        let kept: String = text.chars().filter(|c| !misleads(*c)).collect();
        Self::new(&kept)
    }

    /// The marker that stands where a line could not be kept.
    pub fn left_out() -> Self {
        Self(Self::LEFT_OUT.to_string())
    }

    /// The text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for LogText {
    type Error = NotLogText;

    fn try_from(text: String) -> Result<Self, NotLogText> {
        Self::new(&text)
    }
}

impl From<LogText> for String {
    fn from(text: LogText) -> Self {
        text.0
    }
}

/// One line of the service's log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct LogLine {
    /// Its number within this run of the service, from 1. Numbers are given
    /// out without gaps; a page may skip those of lines no longer held.
    #[cfg_attr(test, ts(type = "number"))]
    pub seq: u64,
    /// When the service took the line, by its own clock: milliseconds since
    /// the start of 1970 (UTC). Clocks get set, so order is by `seq`.
    #[cfg_attr(test, ts(type = "number"))]
    pub at_unix_ms: u64,
    /// How serious it is.
    pub level: LogLevel,
    /// Who wrote it.
    pub source: LogSource,
    /// What it says.
    pub text: LogText,
}

/// A place in the service's log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct LogCursor {
    /// Which run of the service the number belongs to.
    #[cfg_attr(test, ts(type = "number"))]
    pub run: u64,
    /// The number of a line in that run.
    #[cfg_attr(test, ts(type = "number"))]
    pub seq: u64,
}

/// Some lines of the service's log, oldest first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct LogPage {
    /// This run of the service.
    #[cfg_attr(test, ts(type = "number"))]
    pub run: u64,
    /// The lines, oldest first. Empty when there are none after the cursor.
    pub lines: Vec<LogLine>,
    /// Where to read on from: with `run`, the cursor for the next request.
    /// The `seq` of the last line here, or the cursor that was used when
    /// there is none: 0 if none was given or it was from another run.
    #[cfg_attr(test, ts(type = "number"))]
    pub next: u64,
    /// Whether a line of this run with a `seq` greater than the cursor
    /// that was used existed and is no longer held. A cursor from another
    /// run does not make this true by itself; `run` shows that.
    pub dropped: bool,
}

impl LogPage {
    /// A page of the lines after `after` in this `run`: as many of `lines`,
    /// which must be in order, as fit in [`LOG_PAGE_BYTES`] once encoded.
    /// `after` is the cursor that was used: 0 when the client gave none or
    /// gave one from another run. `dropped` is for the service to say; see
    /// [`LogPage::dropped`].
    pub fn after(
        run: u64,
        after: u64,
        dropped: bool,
        lines: impl IntoIterator<Item = LogLine>,
    ) -> Self {
        let mut room = LOG_PAGE_BYTES;
        let fits = |line: &LogLine| {
            // What the line really takes on the wire, and the comma after it.
            let size = serde_json::to_string(line).map_or(usize::MAX, |text| text.len() + 1);
            let fit = size <= room;
            room = room.saturating_sub(size);
            fit
        };
        let lines: Vec<LogLine> = lines.into_iter().take_while(fits).collect();
        let next = lines.last().map_or(after, |last| last.seq);
        Self {
            run,
            lines,
            next,
            dropped,
        }
    }
}

/// Where the connection stands, without what a [`ConnState`] carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub enum StateKind {
    /// See [`ConnState::Disconnected`].
    Disconnected,
    /// See [`ConnState::Connecting`].
    Connecting,
    /// See [`ConnState::Connected`].
    Connected,
    /// See [`ConnState::Disconnecting`].
    Disconnecting,
    /// See [`ConnState::LoginNeeded`].
    LoginNeeded,
    /// See [`ConnState::Failed`].
    Failed,
}

impl From<&ConnState> for StateKind {
    fn from(state: &ConnState) -> Self {
        match state {
            ConnState::Disconnected => Self::Disconnected,
            ConnState::Connecting => Self::Connecting,
            ConnState::Connected { .. } => Self::Connected,
            ConnState::Disconnecting => Self::Disconnecting,
            ConnState::LoginNeeded => Self::LoginNeeded,
            ConnState::Failed { .. } => Self::Failed,
        }
    }
}

/// A failure of a connection, as [`Diagnostics`] reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct LastError {
    /// What went wrong, for a program to act on.
    pub code: ErrorCode,
    /// What went wrong, for a person to read: cleaned by the service as a
    /// log line is, and checked like one when it is read.
    pub message: LogText,
}

/// The service and its state, for someone helping the user. It names no
/// path and no user.
///
/// Nothing in it grows with what is connected: the tunnel's subnets and
/// domains are counted, not listed, and every text has a limit. So it
/// always fits in one line, whatever the state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct Diagnostics {
    /// The service's product version.
    pub service_version: String,
    /// The service's [`PROTOCOL_VERSION`].
    pub protocol_version: u32,
    /// The kind of operating system: `windows`, `macos` or `linux`.
    pub os: String,
    /// The kind of processor the service was built for, such as `x86_64`.
    pub arch: String,
    /// The operating system's version, when the service can tell. One
    /// plain line, like a log line's text.
    pub os_version: Option<LogText>,
    /// How long the service has been running, in seconds.
    #[cfg_attr(test, ts(type = "number"))]
    pub uptime_s: u64,
    /// Where the connection stands. `status` gives the whole state.
    pub state: StateKind,
    /// How many subnets are routed through the tunnel; 0 with no tunnel.
    pub subnets: u32,
    /// How many DNS domains are resolved through it; 0 with no tunnel.
    pub dns_domains: u32,
    /// The last failure of a connection, if there has been one in this run.
    pub last_error: Option<LastError>,
    /// Whether the service's policy file could be read and is valid.
    pub policy_readable: bool,
    /// How many certificate pins the policy holds.
    pub pins: u32,
    /// The gateway the policy names, when the policy could be read.
    pub gateway: Option<String>,
    /// Whether an owner has claimed the service.
    pub owner_claimed: bool,
}

/// Why a request failed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct ErrorInfo {
    /// For the client to act on.
    pub code: ErrorCode,
    /// For the user to read. Never contains a secret.
    pub message: String,
}

/// What the user is told when the gateway presents a key that matches none
/// of the pins, at login or when the tunnel opens. Nothing was sent to it.
/// The usual cause is that the gateway's certificate was replaced (UBC's
/// current one expires on 2027-04-22), and the fix is a release of UBC VPN
/// whose policy pins the new key. The other usual cause is a network that
/// intercepts connections, such as a hotel's sign-in page, and the fix is
/// another network. It never offers a way past the pin. It is fixed text,
/// and holds none of the words that make the log hide the rest of a line.
pub const CERTIFICATE_CHANGED: &str = "The VPN server's certificate has changed, so UBC VPN \
    did not send it anything. Update UBC VPN to the latest version, then connect again. If \
    UBC VPN is already up to date, the network you are on may be intercepting the \
    connection: try another network.";

/// The kinds of failure a client can act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub enum ErrorCode {
    /// The caller is not the owner.
    NotOwner,
    /// No owner exists yet, and the request was not `claim`.
    NotClaimed,
    /// The client and the service speak different protocol versions.
    ProtocolMismatch,
    /// The message could not be understood.
    BadRequest,
    /// The service refused one of the chosen routes or DNS domains.
    RouteRefused,
    /// The gateway's certificate matched none of the policy's pins.
    PinMismatch,
    /// The session is no longer valid. The user must log in again.
    LoginNeeded,
    /// The gateway could not be reached over the network.
    GatewayUnreachable,
    /// The VPN engine could not open or keep the tunnel.
    EngineFailed,
    /// Routes or DNS could not be confirmed, so everything was removed.
    VerificationFailed,
    /// Another connect or disconnect is still in progress.
    Busy,
    /// The request needs a connected tunnel, and there is none.
    NotConnected,
    /// The service's policy file is missing or unusable.
    PolicyInvalid,
    /// Something unexpected went wrong inside the service.
    Internal,
}

/// Why a line could not be written or read.
///
/// It deliberately does not keep `serde_json`'s own error. That error's text
/// can quote the input, and the input may hold a cookie or a password, so only
/// the kind of problem and its position survive. Both `Display` and `Debug` are
/// therefore safe to log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// The line is longer than [`MAX_LINE_BYTES`].
    TooLong,
    /// The line is not the expected JSON.
    Invalid {
        /// What kind of problem it was.
        kind: InvalidKind,
        /// The column where parsing stopped, counted from 1.
        column: usize,
    },
}

/// What was wrong with a line that is not the expected JSON.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidKind {
    /// Not JSON at all, or cut short.
    Syntax,
    /// Valid JSON of the wrong shape: a wrong type, an unknown field or method,
    /// or a value that failed validation.
    Shape,
}

impl From<serde_json::Error> for FrameError {
    fn from(e: serde_json::Error) -> Self {
        let kind = match e.classify() {
            serde_json::error::Category::Data => InvalidKind::Shape,
            _ => InvalidKind::Syntax,
        };
        Self::Invalid {
            kind,
            column: e.column(),
        }
    }
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong => write!(f, "line is longer than {MAX_LINE_BYTES} bytes"),
            Self::Invalid {
                kind: InvalidKind::Syntax,
                column,
            } => write!(f, "message is not valid JSON at column {column}"),
            Self::Invalid {
                kind: InvalidKind::Shape,
                column,
            } => write!(f, "message has an unexpected shape at column {column}"),
        }
    }
}

impl std::error::Error for FrameError {}

/// Turns a message into one line, newline included.
pub fn encode<T: Serialize>(message: &T) -> Result<String, FrameError> {
    let mut line = serde_json::to_string(message)?;
    line.push('\n');
    if line.len() > MAX_LINE_BYTES {
        return Err(FrameError::TooLong);
    }
    Ok(line)
}

/// Reads a message from one line, with or without its newline.
///
/// The length is checked before any parsing, so an oversized line costs
/// nothing to refuse.
pub fn decode<T: DeserializeOwned>(line: &str) -> Result<T, FrameError> {
    if line.len() > MAX_LINE_BYTES {
        return Err(FrameError::TooLong);
    }
    Ok(serde_json::from_str(line.trim_end_matches(['\r', '\n']))?)
}

/// Reads only the protocol version from a client's first line.
///
/// Unlike [`decode`] of a [`Hello`], this ignores every other field, so the
/// service can tell a newer or older client "please update" even when it
/// cannot read the rest of that client's `Hello`.
pub fn peek_protocol_version(line: &str) -> Result<u32, FrameError> {
    #[derive(Deserialize)]
    struct VersionOnly {
        protocol_version: u32,
    }
    Ok(decode::<VersionOnly>(line)?.protocol_version)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::Ipv4Net;

    // When the gateway's certificate is replaced, every connect fails until
    // the user updates. The sentence says so, and reaches the log whole.
    #[test]
    fn a_changed_certificate_tells_the_user_to_update() {
        assert!(CERTIFICATE_CHANGED.contains("certificate has changed"));
        assert!(CERTIFICATE_CHANGED.contains("Update UBC VPN"));
        // The other usual cause: a network that intercepts connections.
        assert!(CERTIFICATE_CHANGED.contains("already up to date"));
        assert!(CERTIFICATE_CHANGED.contains("try another network"));
        // Security rule: it never offers a way past the pin.
        let lower = CERTIFICATE_CHANGED.to_lowercase();
        for offer in ["accept", "trust", "anyway", "continue", "ignore", "proceed"] {
            assert!(!lower.contains(offer), "{offer}");
        }
        assert_eq!(
            crate::redact::redact_line(CERTIFICATE_CHANGED),
            CERTIFICATE_CHANGED
        );
    }

    fn connect() -> Request {
        Request {
            id: 7,
            body: RequestBody::Connect(ConnectParams {
                cookie: Secret::new("s3cr3t-cookie"),
                gateway_addr: Ipv4Addr::new(192, 0, 2, 1),
                routes: RouteSet {
                    subnets: vec!["198.19.0.0/16".parse::<Ipv4Net>().unwrap()],
                    dns_domains: vec!["dept.ubc.ca".to_string()],
                },
                tunnel: TunnelMode::Split,
            }),
        }
    }

    #[test]
    fn request_wire_format_is_stable() {
        // If the snapshot below has to change, so does this number: an older
        // peer could no longer read the message.
        assert_eq!(PROTOCOL_VERSION, 6);
        let line = encode(&connect()).unwrap();
        assert_eq!(
            line,
            concat!(
                r#"{"id":7,"body":{"method":"connect","params":{"cookie":"s3cr3t-cookie","gateway_addr":"192.0.2.1","#,
                r#""routes":{"subnets":["198.19.0.0/16"],"dns_domains":["dept.ubc.ca"]},"tunnel":"split"}}}"#,
                "\n"
            )
        );
        assert_eq!(decode::<Request>(&line).unwrap(), connect());
    }

    // Version 5: a connect says split or full, and left out it is split, as
    // before there was a choice. Only those two words are taken.
    #[test]
    fn a_connect_says_its_tunnel_mode() {
        let without = concat!(
            r#"{"id":7,"body":{"method":"connect","params":{"cookie":"s3cr3t-cookie","gateway_addr":"192.0.2.1","#,
            r#""routes":{"subnets":["198.19.0.0/16"],"dns_domains":["dept.ubc.ca"]}}}}"#
        );
        assert_eq!(decode::<Request>(without).unwrap(), connect());
        let full = without.replace(r#"]}}}}"#, r#"]},"tunnel":"full"}}}"#);
        let Request {
            body: RequestBody::Connect(params),
            ..
        } = decode::<Request>(&full).unwrap()
        else {
            panic!("{full}")
        };
        assert_eq!(params.tunnel, TunnelMode::Full);
        let other = without.replace(r#"]}}}}"#, r#"]},"tunnel":"everything"}}}"#);
        assert!(decode::<Request>(&other).is_err());
    }

    // Version 5: the live tunnel can be switched between split and full,
    // with nothing else in the request.
    #[test]
    fn set_tunnel_has_a_stable_wire_format() {
        let switch = Request {
            id: 11,
            body: RequestBody::SetTunnel(SetTunnelParams {
                mode: TunnelMode::Full,
            }),
        };
        let line = encode(&switch).unwrap();
        assert_eq!(
            line,
            "{\"id\":11,\"body\":{\"method\":\"set_tunnel\",\"params\":{\"mode\":\"full\"}}}\n"
        );
        assert_eq!(decode::<Request>(&line).unwrap(), switch);
        let smuggled = [
            r#"{"id":11,"body":{"method":"set_tunnel","params":{"mode":"full","subnets":["0.0.0.0/1"]}}}"#,
            r#"{"id":11,"body":{"method":"set_tunnel","params":{}}}"#,
            r#"{"id":11,"body":{"method":"set_tunnel"}}"#,
        ];
        for line in smuggled {
            assert!(decode::<Request>(line).is_err(), "{line}");
        }
    }

    // The mode of a live tunnel is in every `connected` state, for the app to
    // show, and is always there.
    #[test]
    fn a_connected_state_says_its_mode() {
        let state = ConnState::Connected {
            tunnel: crate::state::TunnelInfo {
                interface: "tun0".to_string(),
                address: "10.255.0.2".to_string(),
                subnets: vec![],
                dns_domains: vec![],
                mode: TunnelMode::Full,
            },
        };
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(
            json,
            r#"{"state":"connected","tunnel":{"interface":"tun0","address":"10.255.0.2","subnets":[],"dns_domains":[],"mode":"full"}}"#
        );
        assert_eq!(serde_json::from_str::<ConnState>(&json).unwrap(), state);
        let without = json.replace(r#","mode":"full""#, "");
        assert!(serde_json::from_str::<ConnState>(&without).is_err());
    }

    // A peer that speaks version 4 knows nothing of `set_tunnel` or of a
    // tunnel's mode. It is told to update in the handshake.
    #[test]
    fn a_version_4_peer_is_told_to_update() {
        let older = r#"{"protocol_version":4,"client":"cli","client_version":"0.1.0"}"#;
        assert_eq!(peek_protocol_version(older), Ok(4));
        let reply = HelloReply {
            protocol_version: 4,
            service_version: "0.1.0".to_string(),
            owner_claimed: true,
        };
        assert!(!reply.is_compatible());
    }

    #[test]
    fn unit_requests_have_no_params() {
        let line = encode(&Request {
            id: 1,
            body: RequestBody::Status,
        })
        .unwrap();
        assert_eq!(line, "{\"id\":1,\"body\":{\"method\":\"status\"}}\n");
    }

    #[test]
    fn server_messages_round_trip() {
        let messages = [
            ServerMessage::Response(Response {
                id: 1,
                outcome: Outcome::Ok(ResponseBody::Status(ConnState::Disconnected)),
            }),
            ServerMessage::Response(Response {
                id: 2,
                outcome: Outcome::Error(ErrorInfo {
                    code: ErrorCode::NotOwner,
                    message: "only the owner may do this".to_string(),
                }),
            }),
            ServerMessage::Event(Event::StateChanged(ConnState::Connecting)),
        ];
        for message in messages {
            let line = encode(&message).unwrap();
            assert_eq!(decode::<ServerMessage>(&line).unwrap(), message);
        }
        let undone = ServerMessage::Event(Event::SwitchUndone(ErrorInfo {
            code: ErrorCode::VerificationFailed,
            message: "Kept split tunnel.".to_string(),
        }));
        let line = encode(&undone).unwrap();
        let expected = r#"{"type":"event","data":{"kind":"switch_undone","value":{"code":"verification_failed","message":"Kept split tunnel."}}}"#;
        assert_eq!(line.trim_end(), expected);
        assert_eq!(decode::<ServerMessage>(&line).unwrap(), undone);
    }

    // Security rule: the service accepts exactly the expected fields. A request
    // must not be able to smuggle in a gateway name or a pin.
    #[test]
    fn requests_with_unknown_fields_are_refused() {
        let smuggled = [
            r#"{"id":1,"body":{"method":"status"},"gateway":"evil.example"}"#,
            r#"{"id":1,"body":{"method":"connect","params":{"cookie":"c","gateway_addr":"192.0.2.1","routes":{"subnets":[]},"gateway":"evil.example"}}}"#,
            r#"{"id":1,"body":{"method":"connect","params":{"cookie":"c","gateway_addr":"192.0.2.1","routes":{"subnets":[],"pins":[]}}}}"#,
            r#"{"protocol_version":1,"client":"app","client_version":"0.1.0","owner":"me"}"#,
        ];
        assert!(decode::<Request>(smuggled[0]).is_err());
        assert!(decode::<Request>(smuggled[1]).is_err());
        assert!(decode::<Request>(smuggled[2]).is_err());
        assert!(decode::<Hello>(smuggled[3]).is_err());

        // Beside the method, where a `deny_unknown_fields` on the outer struct
        // alone would not reach.
        let beside_method = [
            r#"{"id":1,"body":{"method":"status","gateway":"evil.example"}}"#,
            r#"{"id":1,"body":{"method":"connect","params":{"cookie":"c","gateway_addr":"192.0.2.1","routes":{"subnets":[]}},"pins":["x"]}}"#,
        ];
        for line in beside_method {
            assert!(decode::<Request>(line).is_err(), "{line} must be refused");
        }
    }

    // Version 4: the routes of a live tunnel can be changed, and a request
    // that needs a tunnel is refused with its own code when there is none.
    #[test]
    fn update_routes_has_a_stable_wire_format() {
        let update = Request {
            id: 9,
            body: RequestBody::UpdateRoutes(RouteSet {
                subnets: vec!["10.255.0.0/16".parse().unwrap()],
                dns_domains: vec!["dept.example.test".to_string()],
            }),
        };
        let line = encode(&update).unwrap();
        assert_eq!(
            line,
            concat!(
                r#"{"id":9,"body":{"method":"update_routes","params":"#,
                r#"{"subnets":["10.255.0.0/16"],"dns_domains":["dept.example.test"]}}}"#,
                "\n"
            )
        );
        assert_eq!(decode::<Request>(&line).unwrap(), update);
        // As strict as a connect's routes: nothing may be smuggled in.
        let smuggled = r#"{"id":9,"body":{"method":"update_routes","params":{"subnets":[],"gateway":"evil.example"}}}"#;
        assert!(decode::<Request>(smuggled).is_err());

        let refused = Outcome::Error(ErrorInfo {
            code: ErrorCode::NotConnected,
            message: "made up".to_string(),
        });
        let json = serde_json::to_string(&refused).unwrap();
        assert!(json.contains(r#""code":"not_connected""#), "{json}");
    }

    // A peer that speaks version 3 knows nothing of `update_routes`. It is
    // told to update in the handshake.
    #[test]
    fn a_version_3_peer_is_told_to_update() {
        let older = r#"{"protocol_version":3,"client":"app","client_version":"0.1.0"}"#;
        assert_eq!(peek_protocol_version(older), Ok(3));
        let reply = HelloReply {
            protocol_version: 3,
            service_version: "0.1.0".to_string(),
            owner_claimed: true,
        };
        assert!(!reply.is_compatible());
    }

    #[test]
    fn unknown_methods_are_refused() {
        assert!(decode::<Request>(r#"{"id":1,"body":{"method":"set_gateway"}}"#).is_err());
    }

    // Security rule: an oversized line is refused before it is parsed.
    #[test]
    fn oversized_lines_are_refused() {
        let huge = format!(r#"{{"id":1,"pad":"{}"}}"#, "x".repeat(MAX_LINE_BYTES));
        assert!(matches!(decode::<Request>(&huge), Err(FrameError::TooLong)));

        let big_cookie = Request {
            id: 1,
            body: RequestBody::Connect(ConnectParams {
                cookie: Secret::new("x".repeat(MAX_LINE_BYTES)),
                gateway_addr: Ipv4Addr::new(192, 0, 2, 1),
                routes: RouteSet::default(),
                tunnel: TunnelMode::Split,
            }),
        };
        assert!(matches!(encode(&big_cookie), Err(FrameError::TooLong)));
    }

    // Security rule: a cookie holds only what RFC 6265 allows in a cookie
    // value. Each byte that could split the `Cookie:` header, end it, or add
    // a cookie is refused; what gateways issue, base64 padding included, is
    // not.
    #[test]
    fn a_cookie_holds_only_cookie_octets() {
        let plausible = |text: &str| is_plausible_cookie(&Secret::new(text));
        for good in [
            "Zq7-made-up-0123456789",
            "bWFkZS11cC1jb29raWU==",
            "webvpn=bWFkZS11cC1jb29raWU=",
            "1A2B3C@1234@ABCD@0123456789ABCDEF",
            "!#$%&'()*+-./:<>?[]^_`{|}~",
        ] {
            assert!(plausible(good), "{good:?}");
        }
        let base = "made-up-cookie";
        for bad in [
            ";", "\r", "\n", " ", "\"", ",", "\\", "é", "\0", "\t", "\u{7f}",
        ] {
            for cookie in [
                format!("{bad}{base}"),
                format!("{base}{bad}x"),
                format!("{base}{bad}"),
            ] {
                assert!(!plausible(&cookie), "{cookie:?}");
            }
        }
        assert!(!plausible(""));
        // Every byte outside the set, one at a time.
        let allowed = (0u8..=127).filter(|byte| plausible(&char::from(*byte).to_string()));
        let expected = (0x21u8..=0x7e).filter(|byte| !b"\",;\\".contains(byte));
        assert!(allowed.eq(expected));
    }

    // Security rule: neither a request's debug output nor a decode error may
    // reveal the cookie.
    #[test]
    fn the_cookie_never_reaches_debug_output_or_errors() {
        assert!(!format!("{:?}", connect()).contains("s3cr3t-cookie"));

        // In each of these the secret sits where another type is expected,
        // which is exactly when serde_json quotes the offending value in its
        // own error message.
        let broken = [
            r#"{"id":"s3cr3t-cookie","body":{"method":"status"}}"#,
            r#"{"id":1,"body":{"method":"connect","params":{"cookie":"x","gateway_addr":"192.0.2.1","routes":"s3cr3t-cookie"}}}"#,
            r#"{"id":1,"body":{"method":"s3cr3t-cookie"}}"#,
            r#"{"id":1,"body":{"method":"status"},"s3cr3t-cookie":1}"#,
        ];
        for line in broken {
            let error = decode::<Request>(line).unwrap_err();
            assert!(
                matches!(
                    error,
                    FrameError::Invalid {
                        kind: InvalidKind::Shape,
                        ..
                    }
                ),
                "{line} should be a shape error, got {error:?}"
            );
            for shown in [format!("{error}"), format!("{error:?}")] {
                assert!(!shown.contains("s3cr3t"), "{shown} reveals the input");
            }
        }
    }

    #[test]
    fn syntax_and_shape_errors_are_told_apart() {
        assert!(matches!(
            decode::<Request>("{not json"),
            Err(FrameError::Invalid {
                kind: InvalidKind::Syntax,
                ..
            })
        ));
        assert!(matches!(
            decode::<Request>(r#"{"id":1}"#),
            Err(FrameError::Invalid {
                kind: InvalidKind::Shape,
                ..
            })
        ));
    }

    // A client from another version must still get a "please update" answer,
    // so its version is readable even when the rest of its hello is not.
    #[test]
    fn the_version_is_readable_from_a_hello_this_version_cannot_parse() {
        let future =
            r#"{"protocol_version":2,"client":"tray","client_version":"9.0.0","new":true}"#;
        assert!(decode::<Hello>(future).is_err());
        assert_eq!(peek_protocol_version(future).unwrap(), 2);
        assert!(peek_protocol_version(r#"{"client":"app"}"#).is_err());
    }

    // Security rule: the service must not be aimed at itself, at a network
    // segment, or at a non-address. Weakening the check, or removing any
    // range from the reserved list in routes.rs, makes
    // this test fail.
    #[test]
    fn implausible_gateway_addresses_are_refused() {
        for bad in [
            "0.0.0.0",
            "0.1.2.3",
            "127.0.0.1",
            "169.254.1.1",
            "224.0.0.1",
            "239.255.255.255",
            "240.0.0.1",
            "255.255.255.255",
        ] {
            let addr: Ipv4Addr = bad.parse().unwrap();
            assert!(!is_plausible_gateway_addr(addr), "{bad} must be refused");
        }
        for good in [
            "198.19.1.1",
            "10.0.0.1",
            "192.168.1.1",
            "1.1.1.1",
            "223.255.255.254",
        ] {
            let addr: Ipv4Addr = good.parse().unwrap();
            assert!(is_plausible_gateway_addr(addr), "{good} must be accepted");
        }
    }

    #[test]
    fn a_connect_request_needs_a_well_formed_gateway_address() {
        let without = r#"{"id":1,"body":{"method":"connect","params":{"cookie":"c","routes":{"subnets":[]}}}}"#;
        assert!(decode::<Request>(without).is_err());
        for bad in ["myvpn.ubc.ca", "::1", "1.2.3", "1.2.3.4:443", ""] {
            let line = format!(
                r#"{{"id":1,"body":{{"method":"connect","params":{{"cookie":"c","gateway_addr":"{bad}","routes":{{"subnets":[]}}}}}}}}"#
            );
            assert!(decode::<Request>(&line).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn hello_reply_reports_compatibility() {
        let reply = |v| HelloReply {
            protocol_version: v,
            service_version: "0.1.0".to_string(),
            owner_claimed: true,
        };
        assert!(reply(PROTOCOL_VERSION).is_compatible());
        assert!(!reply(PROTOCOL_VERSION + 1).is_compatible());
    }

    fn line(seq: u64, text: &str) -> LogLine {
        LogLine {
            seq,
            at_unix_ms: 1_800_000_000_000 + seq,
            level: LogLevel::Info,
            source: LogSource::Engine,
            text: LogText::new(text).unwrap(),
        }
    }

    // The app is written against these lines. Changing one is changing the
    // protocol.
    #[test]
    fn the_log_messages_have_a_stable_wire_format() {
        let request = |body| encode(&Request { id: 1, body }).unwrap();
        let after = Some(LogCursor { run: 7, seq: 41 });
        let add = AddLogParams {
            level: LogLevel::Error,
            text: "Login failed.".to_string(),
        };
        let requests = [
            (
                RequestBody::Logs(LogsParams { after }),
                r#"{"id":1,"body":{"method":"logs","params":{"after":{"run":7,"seq":41}}}}"#,
            ),
            (
                RequestBody::Logs(LogsParams { after: None }),
                r#"{"id":1,"body":{"method":"logs","params":{"after":null}}}"#,
            ),
            (
                RequestBody::WatchLogs(WatchLogsParams { on: true }),
                r#"{"id":1,"body":{"method":"watch_logs","params":{"on":true}}}"#,
            ),
            (
                RequestBody::Diagnostics,
                r#"{"id":1,"body":{"method":"diagnostics"}}"#,
            ),
            (
                RequestBody::AddLog(add),
                r#"{"id":1,"body":{"method":"add_log","params":{"level":"error","text":"Login failed."}}}"#,
            ),
        ];
        for (body, wire) in requests {
            assert_eq!(request(body.clone()), format!("{wire}\n"));
            assert_eq!(decode::<Request>(wire).unwrap().body, body);
        }
        // `after` may be left out, which reads from the oldest line.
        let bare: Request = decode(r#"{"id":1,"body":{"method":"logs","params":{}}}"#).unwrap();
        assert_eq!(bare.body, RequestBody::Logs(LogsParams { after: None }));

        let logged = r#"{"seq":42,"at_unix_ms":1800000000042,"level":"info","source":"engine","text":"CSTP connected"}"#;
        let event = ServerMessage::Event(Event::Log(line(42, "CSTP connected")));
        let wire = format!(r#"{{"type":"event","data":{{"kind":"log","value":{logged}}}}}"#);
        assert_eq!(encode(&event).unwrap(), format!("{wire}\n"));
        assert_eq!(decode::<ServerMessage>(&wire).unwrap(), event);

        let page = LogPage::after(7, 41, true, [line(42, "CSTP connected")]);
        let wire = format!(
            r#"{{"kind":"logs","value":{{"run":7,"lines":[{logged}],"next":42,"dropped":true}}}}"#
        );
        assert_eq!(
            encode(&ResponseBody::Logs(page.clone())).unwrap(),
            format!("{wire}\n")
        );
        assert_eq!(
            decode::<ResponseBody>(&wire).unwrap(),
            ResponseBody::Logs(page)
        );
        for (level, source) in [("error", "service"), ("warn", "login")] {
            let other = logged.replace("info", level).replace("engine", source);
            assert!(decode::<LogLine>(&other).is_ok(), "{other}");
        }
    }

    #[test]
    fn diagnostics_have_a_stable_wire_format() {
        let diagnostics = Diagnostics {
            service_version: "0.1.0".to_string(),
            protocol_version: 3,
            os: "linux".to_string(),
            arch: "x86_64".to_string(),
            os_version: None,
            uptime_s: 90,
            state: StateKind::Connected,
            subnets: 2,
            dns_domains: 1,
            last_error: Some(LastError {
                code: ErrorCode::GatewayUnreachable,
                message: LogText::new("The gateway could not be reached.").unwrap(),
            }),
            policy_readable: true,
            pins: 2,
            gateway: Some("vpn.example.test".to_string()),
            owner_claimed: true,
        };
        let wire = concat!(
            r#"{"kind":"diagnostics","value":{"service_version":"0.1.0","protocol_version":3,"#,
            r#""os":"linux","arch":"x86_64","os_version":null,"uptime_s":90,"#,
            r#""state":"connected","subnets":2,"dns_domains":1,"#,
            r#""last_error":{"code":"gateway_unreachable","message":"The gateway could not be reached."},"#,
            r#""policy_readable":true,"pins":2,"gateway":"vpn.example.test","owner_claimed":true}}"#,
        );
        let body = ResponseBody::Diagnostics(Box::new(diagnostics.clone()));
        assert_eq!(encode(&body).unwrap(), format!("{wire}\n"));
        assert_eq!(decode::<ResponseBody>(wire).unwrap(), body);

        // Security rule: the message of the last failure is checked like a
        // log line when it is read, as is the system's version.
        for odd in ["two\\nlines", "escape\\u001b[2J", ""] {
            let message = wire.replace("The gateway could not be reached.", odd);
            assert!(decode::<ResponseBody>(&message).is_err(), "{odd}");
            let version = wire.replace(r#""os_version":null"#, &format!(r#""os_version":"{odd}""#));
            assert!(decode::<ResponseBody>(&version).is_err(), "{odd}");
        }

        // The largest there can be: the worst text wherever there is text
        // with a limit, the largest numbers, and the longest name a gateway
        // can have. The largest state a connect can carry (256 subnets and
        // as many domains as fit in a request) adds nothing to it, because
        // those are counted, not listed.
        let worst = LogText::new(&"\"".repeat(MAX_LOG_TEXT_BYTES)).unwrap();
        let largest = Diagnostics {
            os_version: Some(worst.clone()),
            uptime_s: u64::MAX,
            state: StateKind::Disconnecting,
            subnets: u32::MAX,
            dns_domains: u32::MAX,
            last_error: Some(LastError {
                code: ErrorCode::VerificationFailed,
                message: worst,
            }),
            pins: u32::MAX,
            gateway: Some("x".repeat(253)),
            ..diagnostics
        };
        let line = encode(&ResponseBody::Diagnostics(Box::new(largest))).unwrap();
        assert!(line.len() < 4096, "{}", line.len());
    }

    // What `diagnostics` says of each state.
    #[test]
    fn every_state_has_its_kind() {
        let tunnel = crate::state::TunnelInfo {
            interface: "fake0".to_string(),
            address: "10.255.0.2".to_string(),
            subnets: Vec::new(),
            dns_domains: Vec::new(),
            mode: TunnelMode::Split,
        };
        let (code, message) = (ErrorCode::Internal, String::new());
        let kinds = [
            (ConnState::Disconnected, "disconnected"),
            (ConnState::Connecting, "connecting"),
            (ConnState::Connected { tunnel }, "connected"),
            (ConnState::Disconnecting, "disconnecting"),
            (ConnState::LoginNeeded, "login_needed"),
            (ConnState::Failed { code, message }, "failed"),
        ];
        for (state, kind) in kinds {
            let said = serde_json::to_string(&StateKind::from(&state)).unwrap();
            assert_eq!(said, format!("{kind:?}"));
            // The same word as the state itself uses.
            let whole = serde_json::to_string(&state).unwrap();
            assert!(whole.contains(&format!(r#""state":{said}"#)), "{whole}");
        }
    }

    // Security rule: a log line is one plain line of bounded length, however
    // it comes to be: made here, or read off the wire from a peer.
    #[test]
    fn a_log_text_is_one_plain_line_or_it_is_nothing() {
        // The number is part of the contract: the app sizes its rows by it.
        assert_eq!(MAX_LOG_TEXT_BYTES, 512);
        let longest = "x".repeat(MAX_LOG_TEXT_BYTES);
        assert_eq!(LogText::new(&longest).unwrap().as_str(), longest);
        // Counted in bytes, not characters.
        let wide = "é".repeat(MAX_LOG_TEXT_BYTES / 2);
        assert!(LogText::new(&wide).is_ok());
        let not_lines = [
            String::new(),
            format!("{longest}x"),
            format!("{wide}é"),
            "two\nlines".to_string(),
            "carriage\rreturn".to_string(),
            "escape\u{1b}[2J".to_string(),
            "tab\there".to_string(),
            "reordered\u{202e}txet".to_string(),
            "hid\u{200b}den".to_string(),
            // Not control characters, but each breaks a line.
            "two\u{2028}lines".to_string(),
            "two\u{2029}paragraphs".to_string(),
            "tagged\u{e0041}".to_string(),
        ];
        for text in &not_lines {
            assert_eq!(LogText::new(text), Err(NotLogText), "{text:?}");
            // The same text off the wire is refused in a line. A request to
            // add it can be read, so that the service can answer it.
            let quoted = serde_json::to_string(text).unwrap();
            let shape = Err(InvalidKind::Shape);
            let kind = |found: Result<(), FrameError>| match found {
                Err(FrameError::Invalid { kind, .. }) => Err(kind),
                other => Ok(other),
            };
            assert_eq!(
                kind(decode::<LogText>(&quoted).map(drop)),
                shape,
                "{text:?}"
            );
            let logged = format!(
                r#"{{"seq":1,"at_unix_ms":1,"level":"info","source":"engine","text":{quoted}}}"#
            );
            assert_eq!(
                kind(decode::<LogLine>(&logged).map(drop)),
                shape,
                "{text:?}"
            );
            let add = format!(
                r#"{{"id":1,"body":{{"method":"add_log","params":{{"level":"info","text":{quoted}}}}}}}"#
            );
            let Ok(Request { body, .. }) = decode::<Request>(&add) else {
                panic!("{text:?} must be readable, to be answered");
            };
            let RequestBody::AddLog(params) = body else {
                panic!("not an add_log: {body:?}");
            };
            assert_eq!(LogText::new(&params.text), Err(NotLogText));
        }
        // The error does not repeat the text.
        assert!(!NotLogText.to_string().contains("escape"));

        // Cleaning removes what misleads and keeps the rest, and still does
        // not cut: a line too long to keep is not kept in part.
        let cleaned = LogText::cleaned("es\u{1b}[2Jcape\u{202e} and a\ttab").unwrap();
        assert_eq!(cleaned.as_str(), "es[2Jcape and atab");
        assert_eq!(
            LogText::cleaned(&format!("{longest}\u{1b}"))
                .unwrap()
                .as_str(),
            longest
        );
        assert_eq!(LogText::cleaned(&format!("{longest}x")), Err(NotLogText));
        assert_eq!(LogText::cleaned("\u{1b}\n"), Err(NotLogText));
        // The marker for a line that was left out is itself a line.
        assert_eq!(LogText::new(LogText::LEFT_OUT), Ok(LogText::left_out()));
    }

    // A page of the log is one response and so one line. However long the
    // lines are, and however many there are, the page stops in time.
    #[test]
    fn a_page_of_the_log_always_fits_in_a_line() {
        // The worst a line can be on the wire: every byte doubles.
        let worst = "\"".repeat(MAX_LOG_TEXT_BYTES);
        let all: Vec<LogLine> = (1..=600).map(|seq| line(seq, &worst)).collect();
        let (mut after, mut read, mut pages) = (0, Vec::new(), 0);
        loop {
            let rest = all.iter().filter(|line| line.seq > after).cloned();
            let page = LogPage::after(7, after, false, rest);
            let response = ServerMessage::Response(Response {
                id: u32::MAX,
                outcome: Outcome::Ok(ResponseBody::Logs(page.clone())),
            });
            let wire = encode(&response).expect("a page fits in a line");
            assert!(wire.len() <= LOG_PAGE_BYTES + 256, "{}", wire.len());
            if page.lines.is_empty() {
                // An empty page leaves the cursor where it was.
                assert_eq!(page.next, after);
                break;
            }
            // Nothing is skipped and nothing comes twice.
            assert_eq!(page.lines[0].seq, after + 1);
            assert_eq!(page.next, page.lines.last().unwrap().seq);
            after = page.next;
            read.extend(page.lines);
            pages += 1;
        }
        assert_eq!(read, all);
        // Full pages: about 48 KiB of lines that take about 1.1 KiB each.
        assert!((13..=16).contains(&pages), "{pages} pages");
        // Short lines go many to a page, by the same rule.
        let short = (1..=600).map(|seq| line(seq, "ok"));
        let page = LogPage::after(7, 0, false, short);
        assert!(page.lines.len() > 400, "{}", page.lines.len());
        assert!(encode(&ResponseBody::Logs(page)).unwrap().len() <= LOG_PAGE_BYTES + 256);
    }

    // The app reads these as JavaScript numbers. The contract says they stay
    // below 2^53; a `bigint` here would break the app's arithmetic on them.
    #[test]
    fn the_log_numbers_are_plain_numbers_for_the_app() {
        use ts_rs::TS;
        let how = ts_rs::Config::default();
        let fields = [
            (LogLine::decl(&how), "seq"),
            (LogLine::decl(&how), "at_unix_ms"),
            (LogCursor::decl(&how), "run"),
            (LogCursor::decl(&how), "seq"),
            (LogPage::decl(&how), "run"),
            (LogPage::decl(&how), "next"),
            (Diagnostics::decl(&how), "uptime_s"),
        ];
        for (declared, field) in fields {
            let wanted = format!("{field}: number,");
            let found = declared.lines().any(|line| line.starts_with(&wanted));
            assert!(found, "{field} in {declared}");
        }
        // The largest value promised is carried without loss.
        let most = (1u64 << 53) - 1;
        let text = encode(&LogCursor {
            run: most,
            seq: most,
        })
        .unwrap();
        assert_eq!(
            text.trim_end(),
            r#"{"run":9007199254740991,"seq":9007199254740991}"#
        );
    }

    // The new requests refuse what they do not know, like the old ones.
    #[test]
    fn the_log_requests_refuse_unknown_fields() {
        for odd in [
            r#"{"id":1,"body":{"method":"logs","params":{"after":null,"all":true}}}"#,
            r#"{"id":1,"body":{"method":"logs","params":{"after":{"run":1,"seq":2,"x":3}}}}"#,
            r#"{"id":1,"body":{"method":"logs","params":{"after":{"seq":2}}}}"#,
            r#"{"id":1,"body":{"method":"watch_logs","params":{"on":true,"level":"debug"}}}"#,
            r#"{"id":1,"body":{"method":"watch_logs","params":{}}}"#,
            r#"{"id":1,"body":{"method":"add_log","params":{"level":"debug","text":"x"}}}"#,
            r#"{"id":1,"body":{"method":"add_log","params":{"level":"info","text":"x","source":"service"}}}"#,
            r#"{"id":1,"body":{"method":"add_log","params":{"level":"info"}}}"#,
            r#"{"id":1,"body":{"method":"diagnostics","params":{}}}"#,
        ] {
            assert!(decode::<Request>(odd).is_err(), "{odd}");
        }
        // A level for protocol detail does not exist, so no line can have it.
        assert!(decode::<LogLevel>(r#""debug""#).is_err());
    }

    // A peer that speaks version 2 knows none of this. It is told to update
    // in the handshake, before either side sends what the other cannot read.
    #[test]
    fn a_version_2_peer_is_told_to_update() {
        let older = r#"{"protocol_version":2,"client":"app","client_version":"0.1.0"}"#;
        assert_eq!(peek_protocol_version(older), Ok(2));
        assert_ne!(peek_protocol_version(older), Ok(PROTOCOL_VERSION));
        let reply = HelloReply {
            protocol_version: 2,
            service_version: "0.1.0".to_string(),
            owner_claimed: true,
        };
        assert!(!reply.is_compatible());
    }
}
