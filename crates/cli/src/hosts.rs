//! `ubc-vpn diagnostics --host <name>`: whether a host's traffic goes
//! through the VPN.
//!
//! The name is resolved as any program on this computer would resolve it,
//! so while connected a name under one of the tunnel's DNS domains is
//! looked up through the tunnel. Each address is then checked against the
//! saved routes and, while connected, against the routes the service
//! applied, by [`ubc_vpn_core::coverage`].
//!
//! Like `diagnostics`, it only reads: it makes nobody the owner. When the
//! service cannot say whether it is connected, the saved routes are still
//! checked, and the reason is given on standard error.

use std::io::Write;
use std::net::{IpAddr, ToSocketAddrs};

use ubc_vpn_core::coverage::{HostCoverage, Live, TunnelKnown, check_host};
use ubc_vpn_core::protocol::{ClientKind, ErrorCode, RequestBody, ResponseBody, encode};
use ubc_vpn_core::settings::Settings;
use ubc_vpn_core::state::{ConnState, TunnelInfo};
use ubc_vpn_platform::Platform;

use crate::client::{Client, ClientError, Limits};
use crate::{FAILED, USAGE, clean, explain, say, settings};

/// The longest host name DNS allows, without a final dot.
const MAX_NAME: usize = 253;

/// What the command was asked.
#[derive(Debug, PartialEq, Eq)]
pub struct Args<'a> {
    pub host: &'a str,
    pub json: bool,
}

impl<'a> Args<'a> {
    /// The arguments after `diagnostics`, in either order:
    /// `--host <name> [--json]` or `--json --host <name>`.
    pub fn parse(args: &[&'a str]) -> Option<Self> {
        match *args {
            ["--host", host] => Some(Self { host, json: false }),
            ["--host", host, "--json"] | ["--json", "--host", host] => {
                Some(Self { host, json: true })
            }
            _ => None,
        }
    }
}

/// Resolves a name to its addresses.
pub type Resolve<'a> = &'a dyn Fn(&str) -> std::io::Result<Vec<IpAddr>>;

/// Resolves `host` with the system's resolver, the way other programs on
/// this computer do, so the split-DNS rules the service set are followed.
pub fn system(host: &str) -> std::io::Result<Vec<IpAddr>> {
    let mut found: Vec<IpAddr> = Vec::new();
    for address in (host, 0).to_socket_addrs()? {
        if !found.contains(&address.ip()) {
            found.push(address.ip());
        }
    }
    Ok(found)
}

/// `host` in lower case, if it is an IP address or a plain host name:
/// letters, digits, hyphens and underscores in labels of 1 to 63 that do
/// not start or end with a hyphen, joined by dots, perhaps with one final
/// dot. Anything else is refused before it is looked up or printed.
pub fn plain_host(host: &str) -> Option<String> {
    if host.parse::<IpAddr>().is_ok() {
        return Some(host.to_string());
    }
    let name = host.strip_suffix('.').unwrap_or(host);
    let label_ok = |label: &str| {
        (1..=63).contains(&label.len())
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    };
    let fits = !name.is_empty() && name.len() <= MAX_NAME;
    (fits && name.split('.').all(label_ok)).then(|| host.to_ascii_lowercase())
}

/// Runs `diagnostics --host` and returns the exit status: 0 when the check
/// was made, whatever it found.
pub fn check(
    args: &Args,
    platform: &dyn Fn() -> ubc_vpn_platform::Result<Platform>,
    resolve: Resolve,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    let Some(host) = plain_host(args.host) else {
        let message = "ubc-vpn: That is not a host name or an IP address.";
        return say(err, message, USAGE);
    };
    let Ok(platform) = platform() else {
        let message = "ubc-vpn: This system has no place for UBC VPN's settings.";
        return say(err, message, FAILED);
    };
    let saved = match saved(&platform) {
        Ok(saved) => saved,
        Err(why) => return say(err, &format!("ubc-vpn: {why}"), FAILED),
    };
    let addresses = match resolve(&host) {
        Ok(addresses) if !addresses.is_empty() => addresses,
        _ => {
            let message = format!("ubc-vpn: {host} could not be resolved to an address.");
            return say(err, &message, FAILED);
        }
    };
    let (state, why) = live(&platform);
    if let Some(why) = why {
        let _ = writeln!(
            err,
            "ubc-vpn: Whether the VPN is connected is not known: {why}"
        );
    }
    let live = match &state {
        Some(Some(tunnel)) => Live::Connected(tunnel),
        Some(None) => Live::NotConnected,
        None => Live::Unknown,
    };
    let report = check_host(&host, &addresses, &saved.routes, live);
    let text = match args.json {
        true => encode(&report).map(|line| clean(line.trim_end())),
        false => Ok(describe(&report)),
    };
    match text {
        Ok(text) => say(out, &text, 0),
        Err(_) => say(err, "ubc-vpn: The report could not be written.", FAILED),
    }
}

/// The user's settings, or the defaults when none are saved.
fn saved(platform: &Platform) -> Result<Settings, String> {
    let dir = &platform.paths.settings_dir;
    let unreadable = |_| {
        crate::private_fs::folder_problem(dir)
            .unwrap_or_else(|| "The settings file cannot be read.".to_string())
    };
    match settings::stored(dir).map_err(unreadable)? {
        Some(text) => settings::understood(&text).map_err(unreadable),
        None => Ok(Settings::default()),
    }
}

/// The live tunnel: `Some(Some(_))` connected, `Some(None)` not connected,
/// or `None` and why when the service cannot say. Nobody is made the owner.
fn live(platform: &Platform) -> (Option<Option<TunnelInfo>>, Option<String>) {
    let asked = Client::reach(platform, ClientKind::Cli, Limits::default())
        .and_then(|mut client| client.request(RequestBody::Status));
    match asked {
        Ok(ResponseBody::Status(ConnState::Connected { tunnel })) => (Some(Some(tunnel)), None),
        Ok(ResponseBody::Status(_)) => (Some(None), None),
        Ok(other) => (None, Some(clean(&format!("unexpected answer: {other:?}")))),
        // Without a service, or before anyone has used it, there is no
        // tunnel.
        Err(ClientError::NotInstalled | ClientError::NotRunning) => (Some(None), None),
        Err(ClientError::Refused(refusal)) if refusal.code == ErrorCode::NotClaimed => {
            (Some(None), None)
        }
        Err(error) => (None, Some(explain(&error).1)),
    }
}

/// The report in words.
fn describe(report: &HostCoverage) -> String {
    let mut lines = vec![format!("Host: {}", report.host)];
    lines.push(match &report.saved_dns_domain {
        Some(domain) => format!(
            "DNS: under the saved domain {}, looked up through the tunnel while connected",
            clean(domain)
        ),
        None => "DNS: under no saved domain, looked up as usual".to_string(),
    });
    let connected = report.tunnel == TunnelKnown::Connected;
    lines.push(
        match report.tunnel {
            TunnelKnown::Connected => "Tunnel: connected",
            TunnelKnown::NotConnected => "Tunnel: not connected",
            TunnelKnown::Unknown => "Tunnel: not known",
        }
        .to_string(),
    );
    if report.tunnel == TunnelKnown::NotConnected && report.saved_dns_domain.is_some() {
        lines.push(
            "  Not connected, so the name was looked up without the tunnel's DNS. \
             Connected, it may resolve to other addresses."
                .to_string(),
        );
    }
    for address in &report.addresses {
        let saved = match (address.saved_network, address.address) {
            (Some(network), _) => format!("covered by the saved network {network}"),
            (None, IpAddr::V6(_)) => "not covered: the routes hold IPv4 networks only".to_string(),
            (None, IpAddr::V4(_)) => "not covered by any saved network".to_string(),
        };
        let now = match (connected, address.tunnel_route) {
            (false, _) => String::new(),
            (true, Some(route)) => format!("; goes through the tunnel by {route}"),
            (true, None) => "; does not go through the tunnel".to_string(),
        };
        lines.push(format!("{}: {saved}{now}", address.address));
    }
    lines.push(verdict(report));
    lines.join("\n")
}

/// The last line: what it means, and what to do about it.
fn verdict(report: &HostCoverage) -> String {
    let outside: Vec<String> = report
        .addresses
        .iter()
        .filter(|a| a.saved_network.is_none())
        .map(|a| a.address.to_string())
        .collect();
    if !outside.is_empty() {
        return format!(
            "Covered: no. Traffic to {} goes over the usual network, not the VPN. To send \
             it through the VPN, add a network that holds it to the routes in the app.",
            outside.join(", ")
        );
    }
    let missing = report.tunnel == TunnelKnown::Connected
        && report.addresses.iter().any(|a| a.tunnel_route.is_none());
    match missing {
        true => "Covered: yes, by the saved routes, but the tunnel was set up with other \
                 routes. Disconnect and connect again to use the saved ones."
            .to_string(),
        false => "Covered: yes.".to_string(),
    }
}

#[cfg(test)]
#[path = "hosts_tests.rs"]
mod tests;
