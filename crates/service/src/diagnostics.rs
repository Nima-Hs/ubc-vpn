//! What the service tells its owner about itself: enough for someone
//! helping the user, with no path and no user name in it.

use std::time::Instant;

use ubc_vpn_core::VERSION;
use ubc_vpn_core::policy::Policy;
use ubc_vpn_core::protocol::{Diagnostics, LastError, PROTOCOL_VERSION, StateKind};
use ubc_vpn_core::settings_cli::misleads;
use ubc_vpn_core::state::ConnState;

use crate::Logs;
use crate::hub::Hub;

/// What is known from start-up on.
pub(crate) struct About {
    started: Instant,
    /// The gateway the policy names and how many pins it holds, when the
    /// policy could be used.
    policy: Option<(String, u32)>,
}

/// A count as it is reported.
fn count(many: usize) -> u32 {
    u32::try_from(many).unwrap_or(u32::MAX)
}

/// The most of a name that is reported, in bytes. The longest host name
/// there can be is 253.
const MAX_NAME_BYTES: usize = 255;

/// A name as it is reported: with nothing that misleads, and cut to a
/// length that keeps the whole report small. The names are the service's
/// own and its policy's, and a valid one passes unchanged; this holds the
/// size even if one is not what it should be.
fn name(text: &str) -> String {
    let mut room = MAX_NAME_BYTES;
    let fits = |c: &char| {
        let fit = c.len_utf8() <= room;
        room = room.saturating_sub(c.len_utf8());
        fit
    };
    let seen = text.chars().filter(|c| !misleads(*c));
    seen.take_while(fits).collect()
}

/// What is remembered of `state` if it is a failure. The message can quote
/// the engine or the OS, so it is cleaned as a log line is, and at once:
/// the secrets held when a connection fails are the ones its message could
/// show, and they are not held for long afterwards.
pub(crate) fn failure(state: &ConnState, logs: &Logs) -> Option<LastError> {
    let ConnState::Failed { code, message } = state else {
        return None;
    };
    let (code, message) = (*code, logs.shown(message));
    Some(LastError { code, message })
}

impl About {
    pub(crate) fn new(policy: &Result<Policy, String>) -> Self {
        let policy = policy.as_ref().ok();
        Self {
            started: Instant::now(),
            policy: policy.map(|policy| (policy.gateway.clone(), count(policy.pins.len()))),
        }
    }

    /// The service and its state, as they are now.
    pub(crate) fn report(&self, hub: &Hub) -> Diagnostics {
        let state = hub.state();
        // What the tunnel carries is counted, not listed, so that this
        // always fits in one line.
        let (subnets, dns_domains) = match &state {
            ConnState::Connected { tunnel } => (tunnel.subnets.len(), tunnel.dns_domains.len()),
            _ => (0, 0),
        };
        Diagnostics {
            service_version: name(VERSION),
            protocol_version: PROTOCOL_VERSION,
            os: name(std::env::consts::OS),
            arch: name(std::env::consts::ARCH),
            // The standard library cannot tell it.
            os_version: None,
            uptime_s: self.started.elapsed().as_secs(),
            state: StateKind::from(&state),
            subnets: count(subnets),
            dns_domains: count(dns_domains),
            last_error: hub.last_error(),
            policy_readable: self.policy.is_some(),
            pins: self.policy.as_ref().map_or(0, |(_, pins)| *pins),
            gateway: self.policy.as_ref().map(|(gateway, _)| name(gateway)),
            owner_claimed: hub.owner().is_some(),
        }
    }
}

#[cfg(test)]
mod tests {
    use ubc_vpn_core::protocol::{ErrorCode, ResponseBody, encode};

    use super::*;

    // The report fits in one line whatever it is made from: a name that is
    // far too long, which a valid policy cannot hold, is cut, and the
    // longest failure message there could be is kept as a line or not kept.
    #[test]
    fn the_report_is_small_whatever_it_is_made_from() {
        let policy = Policy {
            gateway: format!("vpn.\u{1b}{}", "é".repeat(40_000)),
            pins: Vec::new(),
            allowed_routes: None,
        };
        let about = About::new(&Ok(policy));
        let hub = Hub::new(None);
        let (code, message) = (ErrorCode::EngineFailed, "\"".repeat(70_000));
        let state = ConnState::Failed { code, message };
        let failure = failure(&state, &Logs::default());
        hub.publish(state, failure);
        let report = about.report(&hub);
        let gateway = report.gateway.clone().unwrap();
        assert!(gateway.starts_with("vpn.é") && gateway.len() <= MAX_NAME_BYTES);
        // Cut between characters, as near the limit as that allows.
        assert!(gateway.len() >= MAX_NAME_BYTES - 1, "{}", gateway.len());
        let line = encode(&ResponseBody::Diagnostics(Box::new(report))).unwrap();
        assert!(line.len() < 4096, "{}", line.len());

        assert_eq!(name("0.1.0"), "0.1.0");
        assert_eq!(name("vpn.example.test"), "vpn.example.test");
    }

    // Security rule: the message of a failure is cleaned as a log line
    // would be, with a secret the service holds removed from it, and when
    // the failure happens: by the time it is read the secret is no longer
    // held, and the message must not show it then either.
    #[test]
    fn the_last_failure_loses_what_a_log_line_would() {
        let about = About::new(&Err("no policy".to_string()));
        let (hub, logs) = (Hub::new(None), Logs::default());
        let held = logs.hold(&ubc_vpn_core::redact::Secret::new("Zq7-made-up-0123456789"));
        let code = ErrorCode::EngineFailed;
        let message = "The engine\u{1b} said Zq7-made-up-0123456789.".to_string();
        let state = ConnState::Failed { code, message };
        let failure = failure(&state, &logs);
        hub.publish(state, failure);
        drop(held);
        // A state that is no failure leaves the last one remembered.
        assert_eq!(super::failure(&ConnState::Disconnected, &logs), None);
        hub.publish(ConnState::Disconnected, None);
        let last = about.report(&hub).last_error.unwrap();
        assert_eq!(last.code, code);
        assert_eq!(last.message.as_str(), "The engine said [redacted].");
    }
}
