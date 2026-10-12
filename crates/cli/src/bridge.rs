//! `ubc-vpn bridge`: carries messages between the app, on standard input and
//! output, and the service, on the channel. The reference for its behaviour
//! is the module documentation of `ubc_vpn_core::bridge`.
//!
//! The app cannot open the channel safely itself, so this is the only way it
//! reaches the service. Two rules matter most: a `connect` request is never
//! forwarded, because the app must not hold a session cookie; and standard
//! output carries nothing but [`BridgeLine`]s.
//!
//! The bridge keeps nothing. It uses the client's handshake but not its
//! queue of kept events: every message from the service is written out the
//! moment it arrives, whether or not a request is waiting for an answer, so
//! nothing accumulates however long the app runs.

use std::collections::VecDeque;
use std::io::{BufRead, Read, Write};
use std::sync::Arc;
use std::sync::mpsc::{self, Sender};
use std::thread;
use std::time::Instant;

use ubc_vpn_core::bridge::{BridgeLine, bridge_allows};
use ubc_vpn_core::protocol::{
    ClientKind, ErrorCode, ErrorInfo, MAX_LINE_BYTES, Outcome, Request, Response, ServerMessage,
    decode, encode,
};
use ubc_vpn_core::redact::redact_line;
use ubc_vpn_platform::{Connection, Error, Platform};

use crate::client::{ClientError, Limits, hello};

/// What reaches the bridge's one loop, from either side.
enum Arrival {
    /// A request the app wrote, or `Err` for a line that is not one.
    App(Result<Request, ()>),
    /// The app closed standard input.
    AppGone,
    Service(ServerMessage),
    ServiceGone,
}

/// Why there is no channel: the one line to write, and the reason for
/// standard error.
type NoChannel = Box<(BridgeLine, String)>;

/// Runs the bridge until either side goes away and returns the exit status:
/// 0 when the app closed standard input, 1 in every other case.
///
/// The bridge lives as long as the app, so it waits without limit while
/// nothing is asked: the service says nothing for hours when nothing
/// changes. But each request it forwards must be answered within
/// [`Limits::answer`]. A service that takes requests and does not answer
/// them is reported as unavailable, so the app can start again.
pub fn run(
    platform: &dyn Fn() -> ubc_vpn_platform::Result<Platform>,
    input: impl BufRead + Send + 'static,
    limits: Limits,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    let (conn, ready) = match open(platform, limits) {
        Ok(opened) => opened,
        Err(failed) => {
            let (last, why) = *failed;
            // Diagnostics go to standard error only, and redacted.
            let _ = writeln!(err, "ubc-vpn bridge: {}", redact_line(&why));
            write(out, &last);
            return 1;
        }
    };
    if !write(out, &ready) {
        return 1;
    }
    // Only now is standard input read: nothing the app wrote early is acted
    // on before it has been told the channel is ready.
    let (arrivals, inbox) = mpsc::channel();
    let (from_app, from_service) = (arrivals.clone(), arrivals);
    thread::spawn(move || read_app(input, &from_app));
    let service = conn.clone();
    thread::spawn(move || read_service(&service, &from_service));

    // The requests sent on and not yet answered, oldest first, each with
    // the time its answer is due.
    let mut unanswered: VecDeque<(u32, Instant)> = VecDeque::new();
    let status = loop {
        let arrival = match unanswered.front() {
            None => inbox.recv().ok(),
            Some((_, due)) => {
                let left = due.saturating_duration_since(Instant::now());
                match inbox.recv_timeout(left) {
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        let late = "the service did not answer a request in time";
                        let _ = writeln!(err, "ubc-vpn bridge: {late}");
                        Some(Arrival::ServiceGone)
                    }
                    arrival => arrival.ok(),
                }
            }
        };
        match arrival.unwrap_or(Arrival::ServiceGone) {
            Arrival::AppGone => break 0,
            Arrival::App(Err(())) => {
                write(out, &BridgeLine::BadLine);
                break 1;
            }
            Arrival::App(Ok(request)) => {
                if bridge_allows(&request.body) {
                    unanswered.push_back((request.id, Instant::now() + limits.answer));
                }
                if !forward(&conn, request, out) {
                    break 1;
                }
            }
            Arrival::Service(message) => {
                if let ServerMessage::Response(response) = &message {
                    unanswered.retain(|(id, _)| *id != response.id);
                }
                if !write(out, &BridgeLine::Server { message }) {
                    break 1;
                }
            }
            Arrival::ServiceGone => {
                write(out, &BridgeLine::ServiceUnavailable);
                break 1;
            }
        }
    };
    conn.close();
    status
}

/// Opens the channel and does the handshake as the app. On failure returns
/// the one line to write and, for standard error, the reason.
fn open(
    platform: &dyn Fn() -> ubc_vpn_platform::Result<Platform>,
    limits: Limits,
) -> Result<(Arc<Connection>, BridgeLine), NoChannel> {
    let unavailable = |why: Error| Box::new((BridgeLine::ServiceUnavailable, why.to_string()));
    let platform = platform().map_err(unavailable)?;
    // The transport refuses a listener that is not the service before
    // anything is sent, and there is then no connection to send on.
    let connected = platform.transport.connect(&platform.paths.channel_name);
    let conn = connected.map_err(|why| match why {
        Error::PermissionDenied => Box::new((BridgeLine::NotOwner, why.to_string())),
        Error::NotTheService => Box::new((BridgeLine::UntrustedService, why.to_string())),
        why => unavailable(why),
    })?;
    let reply = hello(&conn, ClientKind::App, limits).map_err(|why| match why {
        ClientError::Mismatch(service_version) => {
            let service_version = service_version.unwrap_or_else(|| "unknown".to_string());
            let why = format!("the service is version {service_version}");
            Box::new((BridgeLine::UpdateNeeded { service_version }, why))
        }
        // A reply that cannot be read counts as no service.
        why => Box::new((BridgeLine::ServiceUnavailable, format!("{why:?}"))),
    })?;
    // The app's connection is idle for as long as nothing changes.
    conn.set_read_timeout(None).map_err(unavailable)?;
    let ready = BridgeLine::Ready {
        service_version: reply.service_version,
        owner_claimed: reply.owner_claimed,
    };
    Ok((Arc::new(conn), ready))
}

/// Writes one line and reports whether the app took it.
fn write(out: &mut dyn Write, line: &BridgeLine) -> bool {
    let written = encode(line).is_ok_and(|text| out.write_all(text.as_bytes()).is_ok());
    written && out.flush().is_ok()
}

/// Sends an allowed request on to the service exactly as it was decoded. A
/// `connect` is answered here and never reaches the service. Returns whether
/// the bridge can carry on.
fn forward(conn: &Connection, request: Request, out: &mut dyn Write) -> bool {
    if bridge_allows(&request.body) {
        // If this fails the connection is closed, and the service's reader
        // reports that it has gone.
        let _ = encode(&request).map(|line| conn.write_line(line.trim_end()));
        return true;
    }
    let refusal = ErrorInfo {
        code: ErrorCode::BadRequest,
        message: "The app cannot send this request.".to_string(),
    };
    let message = ServerMessage::Response(Response {
        id: request.id,
        outcome: Outcome::Error(refusal),
    });
    write(out, &BridgeLine::Server { message })
}

/// Reads the app's lines until standard input closes or a line is bad. No
/// more than the line limit is ever taken in for one line, and a bad line is
/// dropped here: it is never echoed or logged.
fn read_app(mut input: impl BufRead, to: &Sender<Arrival>) {
    loop {
        let mut line = Vec::new();
        let limit = MAX_LINE_BYTES as u64 + 1;
        let read = input.by_ref().take(limit).read_until(b'\n', &mut line);
        let arrival = match read {
            Ok(0) | Err(_) => Arrival::AppGone,
            Ok(_) => {
                let text = String::from_utf8(line).map_err(drop);
                Arrival::App(text.and_then(|text| decode::<Request>(&text).map_err(drop)))
            }
        };
        let last = !matches!(arrival, Arrival::App(Ok(_)));
        if to.send(arrival).is_err() || last {
            return;
        }
    }
}

/// Reads the service's messages until the channel closes or sends something
/// that is not a message.
fn read_service(conn: &Connection, to: &Sender<Arrival>) {
    loop {
        let line = conn.read_line().ok().flatten();
        let message = line.and_then(|line| decode::<ServerMessage>(&line).ok());
        let gone = message.is_none();
        let arrival = message.map_or(Arrival::ServiceGone, Arrival::Service);
        if to.send(arrival).is_err() || gone {
            return;
        }
    }
}

#[cfg(test)]
#[path = "bridge_tests.rs"]
mod tests;
