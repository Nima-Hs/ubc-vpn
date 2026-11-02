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

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::redact::Secret;
use crate::routes::{Ipv4Net, RouteSet};
use crate::state::{ConnState, TunnelMode};

mod frame;
mod log;

pub use frame::{FrameError, InvalidKind, decode, encode, peek_protocol_version};
pub use log::{
    KEPT_ADDED_LOG_LINES, LOG_PAGE_BYTES, LogCursor, LogLevel, LogLine, LogPage, LogSource,
    LogText, MAX_ADDED_LOG_LINES, MAX_LOG_TEXT_BYTES, NotLogText,
};

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

#[cfg(test)]
mod tests;
