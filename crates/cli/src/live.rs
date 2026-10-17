//! Applying a saved change to the user's live connection: the routes, for
//! `settings set-routes`, and the tunnel mode, for `settings set-tunnel`.
//!
//! What is sent is what was just saved, and nothing else: a live tunnel only
//! ever carries routes and a mode from the user's settings, as a connect
//! does. This only reads and asks: it makes nobody the owner. Whatever
//! happens, the change stays saved and is used at the next connect.

use std::time::Instant;

use ubc_vpn_core::protocol::{
    ClientKind, ErrorCode, Event, RequestBody, ResponseBody, SetTunnelParams,
};
use ubc_vpn_core::routes::RouteSet;
use ubc_vpn_core::settings_cli::LiveRoutes;
use ubc_vpn_core::state::{ConnState, TunnelInfo, TunnelMode};
use ubc_vpn_platform::Platform;

use crate::clean;
use crate::client::{Client, ClientError, Limits};

/// The most of a message from the service that is passed on, in
/// characters. The reply must fit in one line whatever the service says.
const MAX_MESSAGE_CHARS: usize = 300;

/// Asks the service to apply `routes` to the live connection, and waits for
/// what came of it.
pub(crate) fn apply(platform: &Platform, routes: &RouteSet, limits: Limits) -> LiveRoutes {
    let request = RequestBody::UpdateRoutes(routes.clone());
    let done = |tunnel: &TunnelInfo| routes.is_carried_by(&tunnel.subnets, &tunnel.dns_domains);
    let unsaid = "The service did not say whether the routes were applied.";
    change(platform, request, &done, unsaid, limits)
}

/// Asks the service to switch the live connection to `mode`, and waits for
/// what came of it.
pub(crate) fn switch(platform: &Platform, mode: TunnelMode, limits: Limits) -> LiveRoutes {
    let request = RequestBody::SetTunnel(SetTunnelParams { mode });
    let done = |tunnel: &TunnelInfo| tunnel.mode == mode;
    let unsaid = "The service did not say whether the tunnel mode was changed.";
    change(platform, request, &done, unsaid, limits)
}

/// Sends `request`, and waits for a connection of which `done` holds, or
/// for its end.
fn change(
    platform: &Platform,
    request: RequestBody,
    done: &dyn Fn(&TunnelInfo) -> bool,
    unsaid: &str,
    limits: Limits,
) -> LiveRoutes {
    let mut client = match Client::reach(platform, ClientKind::Cli, limits) {
        Ok(client) => client,
        // No service, so no connection to change.
        Err(_) => return LiveRoutes::NextConnect,
    };
    match client.request(request) {
        Ok(ResponseBody::Accepted) => outcome(&mut client, done, unsaid),
        // The connection has it already: nothing was changed.
        Ok(ResponseBody::Status(ConnState::Connected { tunnel })) if done(&tunnel) => {
            LiveRoutes::Applied
        }
        Ok(_) => unknown("The service gave an answer of the wrong kind."),
        Err(ClientError::Refused(refusal)) => match refusal.code {
            // Not connected, not this user's, or nobody's yet.
            ErrorCode::NotConnected | ErrorCode::NotOwner | ErrorCode::NotClaimed => {
                LiveRoutes::NextConnect
            }
            code => LiveRoutes::Refused {
                code,
                message: tidy(&refusal.message),
            },
        },
        Err(_) => unknown("The service could not be asked to change the connection."),
    }
}

/// Waits for the state the change ends in. The service reports the
/// connection again with the change when it is applied, or the end of the
/// connection when it could not be. A state reported before, without the
/// change, is passed over.
fn outcome(client: &mut Client, done: &dyn Fn(&TunnelInfo) -> bool, unsaid: &str) -> LiveRoutes {
    let deadline = Instant::now() + client.limits().outcome;
    loop {
        let event = match client.next_event(Some(deadline)) {
            Ok(event) => event,
            Err(_) => return unknown(unsaid),
        };
        let Event::StateChanged(state) = event else {
            continue;
        };
        match state {
            ConnState::Connected { tunnel } if done(&tunnel) => return LiveRoutes::Applied,
            ConnState::Connected { .. } | ConnState::Connecting | ConnState::Disconnecting => {}
            ConnState::Failed { code, message } => {
                return LiveRoutes::Failed {
                    code,
                    message: tidy(&message),
                };
            }
            // Ended meanwhile, by the user or the gateway.
            ConnState::Disconnected | ConnState::LoginNeeded => return LiveRoutes::NextConnect,
        }
    }
}

fn unknown(message: &str) -> LiveRoutes {
    LiveRoutes::Unknown {
        message: message.to_string(),
    }
}

/// A message from the service, safe to print and short enough to pass on.
fn tidy(message: &str) -> String {
    clean(message).chars().take(MAX_MESSAGE_CHARS).collect()
}
