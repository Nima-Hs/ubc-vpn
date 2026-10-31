//! What `ubc-vpn settings` reads and writes in `--json` mode.
//!
//! The app never opens `settings.json` or the policy file itself. It runs the
//! command-line client, so the rules for routes exist in one place, here, and
//! the service applies the same ones at connect time.
//!
//! - `ubc-vpn settings get --json` writes one [`SettingsView`] line.
//! - `ubc-vpn settings check-routes --json` reads one [`RouteInput`] line on
//!   standard input and writes one [`RoutesReply`] line. It changes nothing.
//! - `ubc-vpn settings set-routes --json` does the same, and when the reply
//!   is [`RoutesReply::Ok`] it has replaced the `routes` field of
//!   `settings.json` and nothing else in the file (see [`replace_routes`]).
//!
//! - `ubc-vpn settings reset --json` is the way out when `settings.json`
//!   cannot be read: it moves the file aside and starts afresh, and writes
//!   one [`ResetReply`] line. It does nothing to a file that can be read
//!   unless it is spelled `settings reset --force --json`. It never
//!   replaces or removes a file it moved aside earlier: when it has nowhere
//!   left to move one to, it changes nothing and fails with
//!   [`SettingsFailureCode::Unwritable`].
//!
//! - `ubc-vpn settings set-tunnel --json` reads one [`TunnelInput`] line and
//!   writes one [`TunnelReply`] line. It saves `global.tunnel` under the
//!   settings lock, changing nothing else, unless the mode is full and the
//!   policy forbids it: then it answers [`TunnelReply::Forbidden`] and saves
//!   nothing. With a policy that cannot be read nothing forbids it here.
//!   Once saved, it asks the service to switch a live connection to the
//!   mode, as `set-routes` does for routes, and says what came of that in
//!   `live`. Both answers exit with status 0. `ubc-vpn connect` sends the
//!   saved mode.
//!
//! The username is not set through these commands. `ubc-vpn connect` saves
//! the one the user typed once a login with it has succeeded, and removes a
//! saved one that the gateway refused (see [`replace_username`]).
//!
//! Saved routes are used by the next connection. When the user's VPN is up,
//! `set-routes` also asks the service to apply them to it, and says in the
//! reply's `live` field what came of that (see [`LiveRoutes`]). Saving never
//! fails because of it.
//!
//! # The cases
//!
//! - **Output.** Each command writes exactly one line on standard output and
//!   nothing else there. It exits with status 0 when that line is a
//!   [`SettingsView`] or a [`RoutesReply`], including
//!   [`RoutesReply::Invalid`], and with status 1 when it is a
//!   [`SettingsFailure`].
//! - **Input.** One line of at most
//!   [`MAX_LINE_BYTES`](crate::protocol::MAX_LINE_BYTES). A missing, longer
//!   or undecodable line is [`SettingsFailureCode::BadInput`].
//! - **Routes too long to report.** Routes whose reply, or the view `get`
//!   would then print, would not fit in one line are
//!   [`SettingsFailureCode::BadInput`], and nothing is saved. `set-routes`
//!   may refuse for this reason where `check-routes` accepted, because only
//!   it knows the rest of the file.
//! - **No `settings.json`.** `get` answers with the default settings.
//!   `set-routes` creates the file, and its folder if needed.
//! - **A `settings.json` that cannot be read or understood.** `get` and
//!   `set-routes` fail with [`SettingsFailureCode::Unreadable`] and leave it
//!   alone. `check-routes` does not read the file, so it cannot fail this
//!   way.
//! - **A policy that is missing or invalid.** No command fails for this.
//!   `get` says so in [`SettingsView::policy_readable`]. `check-routes` and
//!   `set-routes` then check everything but the allow-list. The service
//!   refuses to connect without a valid policy, so nothing is tunnelled on
//!   the strength of that weaker check.
//! - **Saving fails.** [`SettingsFailureCode::Unwritable`]; the old file is
//!   unchanged, because the new one is written beside it and renamed.

use serde::{Deserialize, Serialize};

use crate::policy::Policy;
use crate::protocol::ErrorCode;
use crate::routes::{Ipv4Net, MAX_ROUTES, MIN_PREFIX_LEN, RouteSet, is_valid_domain};
use crate::settings::Settings;
use crate::state::TunnelMode;

/// The longest entry [`check_input`] will look at. Anything longer is reported
/// as a problem without being examined.
pub const MAX_ENTRY_BYTES: usize = 253;

/// The answer to `settings get`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct SettingsView {
    /// The user's settings as stored.
    pub settings: Settings,
    /// Whether the policy file could be read and is valid. When it is not,
    /// the app cannot connect, and `allowed_routes` says nothing.
    pub policy_readable: bool,
    /// When the policy limits routes, the only networks they may fall inside.
    /// `None` means the policy sets no limit, or was not readable.
    #[cfg_attr(test, ts(type = "Array<string> | null"))]
    pub allowed_routes: Option<Vec<Ipv4Net>>,
    /// The widest subnet a route may be, as a prefix length.
    pub min_prefix_len: u8,
    /// The most subnets, and the most DNS domains, a user may list.
    #[cfg_attr(test, ts(type = "number"))]
    pub max_routes: usize,
}

impl SettingsView {
    /// A view of `settings` under a policy, or under none when the policy
    /// could not be read.
    pub fn new(settings: Settings, policy: Option<&Policy>) -> Self {
        Self {
            settings,
            policy_readable: policy.is_some(),
            allowed_routes: policy.and_then(|p| p.allowed_routes.clone()),
            min_prefix_len: MIN_PREFIX_LEN,
            max_routes: MAX_ROUTES,
        }
    }
}

/// Routes as the user typed them, not yet checked.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct RouteInput {
    /// Subnets such as `198.19.0.0/16`.
    pub subnets: Vec<String>,
    /// DNS domains such as `dept.ubc.ca`.
    pub dns_domains: Vec<String>,
}

/// The answer to `check-routes` and `set-routes`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub enum RoutesReply {
    /// Every entry is acceptable. For `set-routes`, they are now saved.
    Ok {
        /// The routes in the form they are stored and sent to the service.
        routes: RouteSet,
        /// For `set-routes` only: what became of the live connection.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[cfg_attr(test, ts(optional))]
        live: Option<LiveRoutes>,
    },
    /// At least one entry is not acceptable. Nothing was saved.
    Invalid {
        /// Every problem found, in the order of the input.
        problems: Vec<RouteProblem>,
    },
}

/// The input of `settings set-tunnel`: split or full, for every profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct TunnelInput {
    /// The mode to save, and to switch a live connection to.
    pub mode: TunnelMode,
}

/// The answer to `settings set-tunnel`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub enum TunnelReply {
    /// The mode is saved.
    Ok {
        /// The mode now saved.
        tunnel: TunnelMode,
        /// What became of the live connection, as for `set-routes`: it was
        /// switched, it is used at the next connect, or the service refused
        /// or failed to switch it.
        live: LiveRoutes,
    },
    /// The policy forbids full mode. Nothing was saved.
    Forbidden,
}

/// What saving routes did to the user's live connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub enum LiveRoutes {
    /// The VPN is connected, and now carries the saved routes: they were
    /// applied and verified.
    Applied,
    /// The VPN is not connected, or not this user's to change: the routes
    /// are used at the next connect.
    NextConnect,
    /// The service refused to change the connection. It keeps the routes
    /// it had; the saved ones are used at the next connect. A switch of
    /// tunnel mode that was applied, failed its checks and was undone is
    /// one too: the connection stays up in the mode it had.
    Refused {
        /// Why, for the client to act on.
        code: ErrorCode,
        /// Why, for the user to read.
        message: String,
    },
    /// Applying them failed, so the connection was closed and everything
    /// it had applied removed.
    Failed {
        /// Why, for the client to act on.
        code: ErrorCode,
        /// Why, for the user to read.
        message: String,
    },
    /// What became of the connection is not known: the service did not say
    /// in time.
    Unknown {
        /// Why, for the user to read.
        message: String,
    },
}

/// The answer to `settings reset`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub enum ResetReply {
    /// The settings are now the defaults.
    Reset {
        /// The name, inside the settings folder, of the file the old
        /// settings were moved to.
        kept: String,
        /// Whether every password this product saved was removed from the
        /// OS keyring. When `false` the keyring could not be used for it,
        /// and saved passwords may still be there.
        passwords_forgotten: bool,
    },
    /// Nothing was changed. Either there is no settings file, or it can be
    /// read and the command was not told to reset it all the same.
    NotNeeded,
}

/// One thing wrong with a [`RouteInput`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct RouteProblem {
    /// What is wrong.
    pub code: RouteProblemCode,
    /// Which list the entry is in. `None` for a problem with the whole input.
    pub list: Option<RouteList>,
    /// The entry's position in that list, counting from zero.
    #[cfg_attr(test, ts(type = "number | null"))]
    pub index: Option<usize>,
}

/// The two lists in a [`RouteInput`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub enum RouteList {
    /// [`RouteInput::subnets`].
    Subnets,
    /// [`RouteInput::dns_domains`].
    DnsDomains,
}

/// Why an entry, or the whole input, is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub enum RouteProblemCode {
    /// No subnets were given, so there is nothing to tunnel.
    NoSubnets,
    /// There are more subnets or more DNS domains than allowed.
    TooMany,
    /// The entry is not a network in `address/length` form with no host bits
    /// set.
    BadSubnet,
    /// The subnet is wider than allowed.
    TooWide,
    /// The subnet touches a loopback, link-local, multicast or reserved range.
    Reserved,
    /// The policy limits routes and the subnet is outside them.
    NotAllowed,
    /// The entry is not a plain lower-case host name.
    BadDomain,
}

/// Why a `settings` command could not do its work.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct SettingsFailure {
    /// What went wrong.
    pub error: SettingsFailureCode,
}

/// The ways a `settings` command can fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub enum SettingsFailureCode {
    /// The input line was missing, too long or not a [`RouteInput`].
    BadInput,
    /// `settings.json` exists but could not be read or understood. It is left
    /// as it is.
    Unreadable,
    /// The new settings could not be saved. The old file is unchanged.
    Unwritable,
}

/// Checks routes the user typed, reporting every problem, not just the first.
///
/// An entry is checked exactly as typed: surrounding spaces and upper-case
/// letters in a domain are problems, so what is stored is what was shown.
/// The rules are those of [`RouteSet::check`]; anything this accepts, that
/// accepts under the same allow-list.
pub fn check_input(
    input: &RouteInput,
    allow_list: Option<&[Ipv4Net]>,
) -> Result<RouteSet, Vec<RouteProblem>> {
    let whole = |code| RouteProblem {
        code,
        list: None,
        index: None,
    };
    let mut problems = Vec::new();
    if input.subnets.is_empty() {
        problems.push(whole(RouteProblemCode::NoSubnets));
    }
    if input.subnets.len() > MAX_ROUTES || input.dns_domains.len() > MAX_ROUTES {
        // Looking at each of an unbounded number of entries would let one
        // input line cost as much as the caller likes.
        problems.push(whole(RouteProblemCode::TooMany));
        return Err(problems);
    }

    let mut subnets = Vec::with_capacity(input.subnets.len());
    for (index, entry) in input.subnets.iter().enumerate() {
        match check_subnet(entry, allow_list) {
            Ok(net) => subnets.push(net),
            Err(code) => problems.push(RouteProblem {
                code,
                list: Some(RouteList::Subnets),
                index: Some(index),
            }),
        }
    }
    for (index, entry) in input.dns_domains.iter().enumerate() {
        if entry.len() > MAX_ENTRY_BYTES || !is_valid_domain(entry) {
            problems.push(RouteProblem {
                code: RouteProblemCode::BadDomain,
                list: Some(RouteList::DnsDomains),
                index: Some(index),
            });
        }
    }
    if !problems.is_empty() {
        return Err(problems);
    }
    Ok(RouteSet {
        subnets,
        dns_domains: input.dns_domains.clone(),
    })
}

/// The new text of `settings.json` with its routes replaced.
///
/// `current` is the file's text, or `None` when there is no file yet. Only
/// the `routes` field changes. Every other field is kept exactly, including
/// ones this version does not know, so saving routes with an older version
/// does not delete what a newer one stored.
///
/// Fails with [`SettingsFailureCode::Unreadable`] when `current` is not
/// settings this version can load.
pub fn replace_routes(
    current: Option<&str>,
    routes: &RouteSet,
) -> Result<String, SettingsFailureCode> {
    let routes = serde_json::to_value(routes).map_err(|_| SettingsFailureCode::Unreadable)?;
    replace_field(current, "routes", Some(routes))
}

/// Whether `c` can make text read as something other than what it is: a
/// control character, which can do anything to a terminal, or a character
/// that is not seen and hides or reorders the text around it.
///
/// This is the one rule for text that is shown to the user but was not
/// written by this program. The command-line client removes these
/// characters from whatever it prints, and a username that holds one is
/// not saved.
///
/// The zero-width joiner and non-joiner (U+200C, U+200D) are not among
/// them: they are ordinary in Persian, Arabic and Indic text and in emoji,
/// and neither reorder nor hide anything.
///
/// The line and paragraph separators (U+2028, U+2029) are among them: they
/// are not control characters, but they break a line wherever white space
/// is kept, so one line could be made to look like two. So are the tag
/// characters (U+E0000 to U+E007F), which are not seen at all.
pub fn misleads(c: char) -> bool {
    let unseen = matches!(c, '\u{061c}' | '\u{200b}' | '\u{200e}' | '\u{200f}')
        || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{2069}' | '\u{feff}')
        || matches!(c, '\u{e0000}'..='\u{e007f}');
    let breaks = matches!(c, '\u{2028}' | '\u{2029}');
    c.is_control() || unseen || breaks
}

/// The longest username that is saved, in bytes.
pub const MAX_USERNAME_BYTES: usize = 256;

/// The new text of `settings.json` with its username replaced, or removed
/// when `username` is `None`.
///
/// `current` is the file's text, or `None` when there is no file yet. Only
/// the `username` field changes; every other field is kept exactly, as
/// [`replace_routes`] keeps them.
///
/// Fails with [`SettingsFailureCode::Unreadable`] when `current` is not
/// settings this version can load, and with
/// [`SettingsFailureCode::BadInput`] for a username that is empty or only
/// spaces, longer than [`MAX_USERNAME_BYTES`], or holds a character that
/// [`misleads`]. None is a name a person would type, and the last kind could
/// be shown as a name it is not.
pub fn replace_username(
    current: Option<&str>,
    username: Option<&str>,
) -> Result<String, SettingsFailureCode> {
    if username.is_some_and(|name| !usable_username(name)) {
        return Err(SettingsFailureCode::BadInput);
    }
    replace_field(current, "username", username.map(serde_json::Value::from))
}

/// Whether `name` is a username that may be saved: not empty or only
/// spaces, no longer than [`MAX_USERNAME_BYTES`], and with no character
/// that [`misleads`]. None is a name a person would type, and the last kind
/// could be shown as a name it is not.
pub fn usable_username(name: &str) -> bool {
    !name.trim().is_empty() && name.len() <= MAX_USERNAME_BYTES && !name.chars().any(misleads)
}

/// The text of a settings file with one field set to `value`, or removed.
fn replace_field(
    current: Option<&str>,
    field: &str,
    value: Option<serde_json::Value>,
) -> Result<String, SettingsFailureCode> {
    let unreadable = |_| SettingsFailureCode::Unreadable;
    let text = current.unwrap_or("{}");
    // Loading it as settings first refuses anything `get` would refuse.
    serde_json::from_str::<Settings>(text).map_err(unreadable)?;
    let mut file: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(text).map_err(unreadable)?;
    match value {
        Some(value) => file.insert(field.to_string(), value),
        None => file.remove(field),
    };
    let mut text = serde_json::to_string_pretty(&file).map_err(unreadable)?;
    text.push('\n');
    Ok(text)
}

fn check_subnet(entry: &str, allow_list: Option<&[Ipv4Net]>) -> Result<Ipv4Net, RouteProblemCode> {
    if entry.len() > MAX_ENTRY_BYTES {
        return Err(RouteProblemCode::BadSubnet);
    }
    let net: Ipv4Net = entry.parse().map_err(|_| RouteProblemCode::BadSubnet)?;
    if net.prefix_len() < MIN_PREFIX_LEN {
        return Err(RouteProblemCode::TooWide);
    }
    if net.is_reserved() {
        return Err(RouteProblemCode::Reserved);
    }
    if let Some(allowed) = allow_list
        && !allowed.iter().any(|a| a.contains(&net))
    {
        return Err(RouteProblemCode::NotAllowed);
    }
    Ok(net)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{decode, encode};

    fn input(subnets: &[&str], dns_domains: &[&str]) -> RouteInput {
        let owned = |list: &[&str]| list.iter().map(|s| s.to_string()).collect();
        RouteInput {
            subnets: owned(subnets),
            dns_domains: owned(dns_domains),
        }
    }

    fn at(code: RouteProblemCode, list: RouteList, index: usize) -> RouteProblem {
        RouteProblem {
            code,
            list: Some(list),
            index: Some(index),
        }
    }

    fn whole(code: RouteProblemCode) -> RouteProblem {
        RouteProblem {
            code,
            list: None,
            index: None,
        }
    }

    #[test]
    fn good_input_becomes_the_routes_it_spells() {
        let routes = check_input(&input(&["198.19.0.0/16"], &["dept.ubc.ca"]), None).unwrap();
        assert_eq!(routes.subnets, ["198.19.0.0/16".parse().unwrap()]);
        assert_eq!(routes.dns_domains, ["dept.ubc.ca"]);
    }

    #[test]
    fn every_problem_is_reported_with_its_place() {
        use RouteList::{DnsDomains, Subnets};
        use RouteProblemCode::{BadDomain, BadSubnet, NotAllowed, Reserved, TooWide};
        let allowed: Vec<Ipv4Net> = vec!["198.19.0.0/16".parse().unwrap()];
        let typed = input(
            &[
                "198.19.5.0/24",
                "not a subnet",
                "198.19.5.1/24",
                " 198.19.0.0/16",
                "0.0.0.0/0",
                "10.0.0.0/7",
                "127.0.0.0/8",
                "10.19.0.0/16",
            ],
            &["dept.ubc.ca", "DEPT.ubc.ca", "*.ubc.ca", "ubc"],
        );
        assert_eq!(
            check_input(&typed, Some(&allowed)),
            Err(vec![
                at(BadSubnet, Subnets, 1),
                at(BadSubnet, Subnets, 2),
                at(BadSubnet, Subnets, 3),
                at(TooWide, Subnets, 4),
                at(TooWide, Subnets, 5),
                at(Reserved, Subnets, 6),
                at(NotAllowed, Subnets, 7),
                at(BadDomain, DnsDomains, 1),
                at(BadDomain, DnsDomains, 2),
                at(BadDomain, DnsDomains, 3),
            ])
        );
    }

    #[test]
    fn nothing_to_tunnel_is_a_problem_with_the_whole_input() {
        assert_eq!(
            check_input(&input(&[], &["dept.ubc.ca"]), None),
            Err(vec![whole(RouteProblemCode::NoSubnets)])
        );
    }

    #[test]
    fn too_many_entries_are_refused_without_being_examined() {
        let subnet = "10.19.0.0/16".to_string();
        let mut typed = RouteInput {
            subnets: vec![subnet.clone(); MAX_ROUTES],
            dns_domains: Vec::new(),
        };
        assert!(check_input(&typed, None).is_ok());
        typed.subnets.push("not a subnet".to_string());
        assert_eq!(
            check_input(&typed, None),
            Err(vec![whole(RouteProblemCode::TooMany)])
        );

        let domains = RouteInput {
            subnets: vec![subnet],
            dns_domains: vec!["dept.ubc.ca".to_string(); MAX_ROUTES + 1],
        };
        assert_eq!(
            check_input(&domains, None),
            Err(vec![whole(RouteProblemCode::TooMany)])
        );
    }

    #[test]
    fn an_over_long_entry_is_refused() {
        let long = format!("{}.ca", "a".repeat(MAX_ENTRY_BYTES));
        assert_eq!(
            check_input(&input(&["10.19.0.0/16"], &[&long]), None),
            Err(vec![at(
                RouteProblemCode::BadDomain,
                RouteList::DnsDomains,
                0
            )])
        );
        assert_eq!(
            check_input(&input(&[&long], &[]), None),
            Err(vec![at(RouteProblemCode::BadSubnet, RouteList::Subnets, 0)])
        );
    }

    // Security rule: the editor must never save routes the service would
    // refuse, or accept what it refuses. Whatever this check accepts, the
    // service's own check accepts under the same allow-list, and each entry
    // the service's rule refuses is refused here.
    #[test]
    fn agrees_with_the_rule_the_service_applies() {
        let allowed: Vec<Ipv4Net> = vec!["198.19.0.0/16".parse().unwrap()];
        let cases: [(&[&str], &[&str]); 8] = [
            (&["198.19.0.0/16"], &["dept.ubc.ca"]),
            (&["198.19.9.0/24", "198.19.0.0/16"], &[]),
            (&[], &[]),
            (&["0.0.0.0/0"], &[]),
            (&["10.0.0.0/7"], &[]),
            (&["224.0.0.0/8"], &[]),
            (&["10.19.0.0/16"], &[]),
            (&["198.19.0.0/16"], &["ubc"]),
        ];
        for (subnets, domains) in cases {
            for allow_list in [None, Some(allowed.as_slice())] {
                let typed = input(subnets, domains);
                let strict = RouteSet {
                    subnets: subnets.iter().map(|s| s.parse().unwrap()).collect(),
                    dns_domains: typed.dns_domains.clone(),
                };
                let here = check_input(&typed, allow_list);
                assert_eq!(
                    here.is_ok(),
                    strict.check(allow_list).is_ok(),
                    "{subnets:?} {domains:?} under {allow_list:?}"
                );
                if let Ok(routes) = here {
                    assert_eq!(routes, strict);
                }
            }
        }
    }

    #[test]
    fn reset_replies_have_a_stable_wire_format() {
        let kept = || "settings.json.damaged-1".to_string();
        let lines = [
            (
                ResetReply::Reset {
                    kept: kept(),
                    passwords_forgotten: true,
                },
                "{\"type\":\"reset\",\"kept\":\"settings.json.damaged-1\",\"passwords_forgotten\":true}\n",
            ),
            (
                ResetReply::Reset {
                    kept: kept(),
                    passwords_forgotten: false,
                },
                "{\"type\":\"reset\",\"kept\":\"settings.json.damaged-1\",\"passwords_forgotten\":false}\n",
            ),
            (ResetReply::NotNeeded, "{\"type\":\"not_needed\"}\n"),
        ];
        // A reply always says where the old file went, and whether saved
        // passwords may be left.
        let no_kept = "{\"type\":\"reset\",\"kept\":null,\"passwords_forgotten\":true}";
        assert!(decode::<ResetReply>(no_kept).is_err());
        let no_word = "{\"type\":\"reset\",\"kept\":\"settings.json.damaged-1\"}";
        assert!(decode::<ResetReply>(no_word).is_err());
        assert!(decode::<ResetReply>("{\"type\":\"reset\"}").is_err());
        for (reply, line) in lines {
            assert_eq!(encode(&reply).unwrap(), line);
            assert_eq!(decode::<ResetReply>(line).unwrap(), reply);
        }
    }

    #[test]
    fn tunnel_lines_have_a_stable_wire_format() {
        let input: TunnelInput = decode(r#"{"mode":"full"}"#).unwrap();
        assert_eq!(input.mode, TunnelMode::Full);
        for wrong in [
            r#"{"mode":"all"}"#,
            r#"{}"#,
            r#"{"mode":"full","subnets":[]}"#,
        ] {
            assert!(decode::<TunnelInput>(wrong).is_err(), "{wrong}");
        }
        let ok = TunnelReply::Ok {
            tunnel: TunnelMode::Full,
            live: LiveRoutes::Applied,
        };
        let line = encode(&ok).unwrap();
        assert_eq!(
            line,
            "{\"type\":\"ok\",\"tunnel\":\"full\",\"live\":{\"result\":\"applied\"}}\n"
        );
        assert_eq!(decode::<TunnelReply>(&line).unwrap(), ok);
        let forbidden = encode(&TunnelReply::Forbidden).unwrap();
        assert_eq!(forbidden, "{\"type\":\"forbidden\"}\n");
    }

    #[test]
    fn replies_have_a_stable_wire_format() {
        let ok = RoutesReply::Ok {
            routes: check_input(&input(&["10.19.0.0/16"], &[]), None).unwrap(),
            live: None,
        };
        assert_eq!(
            encode(&ok).unwrap(),
            "{\"type\":\"ok\",\"routes\":{\"subnets\":[\"10.19.0.0/16\"],\"dns_domains\":[]}}\n"
        );
        // What saving did to the live connection, when it was saved.
        let applied = RoutesReply::Ok {
            routes: check_input(&input(&["10.19.0.0/16"], &[]), None).unwrap(),
            live: Some(LiveRoutes::Applied),
        };
        let text = encode(&applied).unwrap();
        assert!(
            text.ends_with(",\"live\":{\"result\":\"applied\"}}\n"),
            "{text}"
        );
        assert_eq!(decode::<RoutesReply>(&text).unwrap(), applied);
        let refused = LiveRoutes::Refused {
            code: crate::protocol::ErrorCode::RouteRefused,
            message: "made up".to_string(),
        };
        assert_eq!(
            serde_json::to_string(&refused).unwrap(),
            r#"{"result":"refused","code":"route_refused","message":"made up"}"#
        );
        let later = serde_json::to_string(&LiveRoutes::NextConnect).unwrap();
        assert_eq!(later, r#"{"result":"next_connect"}"#);
        let invalid = RoutesReply::Invalid {
            problems: vec![
                whole(RouteProblemCode::NoSubnets),
                at(RouteProblemCode::BadDomain, RouteList::DnsDomains, 2),
            ],
        };
        let text = encode(&invalid).unwrap();
        assert_eq!(
            text,
            "{\"type\":\"invalid\",\"problems\":[\
             {\"code\":\"no_subnets\",\"list\":null,\"index\":null},\
             {\"code\":\"bad_domain\",\"list\":\"dns_domains\",\"index\":2}]}\n"
        );
        assert_eq!(decode::<RoutesReply>(&text).unwrap(), invalid);
        assert_eq!(
            encode(&SettingsFailure {
                error: SettingsFailureCode::Unwritable
            })
            .unwrap(),
            "{\"error\":\"unwritable\"}\n"
        );
    }

    #[test]
    fn the_view_carries_the_limits_the_editor_shows() {
        let view = SettingsView::new(Settings::default(), None);
        assert_eq!(
            encode(&view).unwrap(),
            "{\"settings\":{\"username\":null,\"routes\":{\"subnets\":[],\"dns_domains\":[]},\
             \"save_password\":false},\"policy_readable\":false,\"allowed_routes\":null,\
             \"min_prefix_len\":8,\"max_routes\":256}\n"
        );
    }

    // The app must be able to tell "the policy sets no limit" from "there is
    // no usable policy".
    #[test]
    fn the_view_tells_no_limit_from_no_policy() {
        let policy = |allowed_routes| Policy {
            gateway: "vpn.example.test".to_string(),
            pins: Vec::new(),
            allowed_routes,
            full_tunnel: Default::default(),
        };
        let limit = vec!["198.19.0.0/16".parse().unwrap()];

        let none = SettingsView::new(Settings::default(), None);
        assert!(!none.policy_readable);
        assert_eq!(none.allowed_routes, None);

        let open = policy(None);
        let open = SettingsView::new(Settings::default(), Some(&open));
        assert!(open.policy_readable);
        assert_eq!(open.allowed_routes, None);

        let limited = policy(Some(limit.clone()));
        let limited = SettingsView::new(Settings::default(), Some(&limited));
        assert!(limited.policy_readable);
        assert_eq!(limited.allowed_routes, Some(limit));
    }

    fn routes(subnet: &str) -> RouteSet {
        check_input(&input(&[subnet], &["dept.ubc.ca"]), None).unwrap()
    }

    // Settings files are shared between versions. Saving routes with this
    // version must not delete what another version stored.
    #[test]
    fn saving_routes_changes_nothing_else_in_the_file() {
        let before = r#"{"username":"jdoe","routes":{"subnets":["10.19.0.0/16"],"old":1},
            "save_password":true,"theme":"dark","future":{"a":[1,2]}}"#;
        let after = replace_routes(Some(before), &routes("198.19.0.0/16")).unwrap();

        let saved: Settings = serde_json::from_str(&after).unwrap();
        assert_eq!(saved.username.as_deref(), Some("jdoe"));
        assert!(saved.save_password);
        assert_eq!(saved.routes, routes("198.19.0.0/16"));

        let mut expected: serde_json::Value = serde_json::from_str(before).unwrap();
        expected["routes"] = serde_json::json!({
            "subnets": ["198.19.0.0/16"],
            "dns_domains": ["dept.ubc.ca"],
        });
        let got: serde_json::Value = serde_json::from_str(&after).unwrap();
        assert_eq!(got, expected);
        assert!(after.ends_with('\n'));
    }

    #[test]
    fn saving_routes_with_no_file_makes_one() {
        let after = replace_routes(None, &routes("198.19.0.0/16")).unwrap();
        let saved: Settings = serde_json::from_str(&after).unwrap();
        assert_eq!(
            saved,
            Settings {
                routes: routes("198.19.0.0/16"),
                ..Settings::default()
            }
        );
    }

    // A file this version cannot load is left for the user to look at, not
    // overwritten with something that happens to parse.
    #[test]
    fn a_file_that_does_not_load_is_not_rewritten() {
        let unreadable = Err(SettingsFailureCode::Unreadable);
        for bad in [
            "",
            "not json",
            "[]",
            "null",
            r#"{"routes":{"subnets":["10.0.0.1/8"]}}"#,
            r#"{"save_password":"yes"}"#,
            r#"{"username":"jdoe""#,
        ] {
            assert_eq!(
                replace_routes(Some(bad), &routes("10.19.0.0/16")),
                unreadable,
                "{bad:?}"
            );
        }
    }

    // Saving or forgetting the username changes that one field and nothing
    // else, whatever else another version stored.
    #[test]
    fn saving_the_username_changes_nothing_else_in_the_file() {
        let before = r#"{"username":"jdoe","routes":{"subnets":["10.19.0.0/16"],"old":1},
            "save_password":true,"theme":"dark","future":{"a":[1,2]}}"#;
        let mut expected: serde_json::Value = serde_json::from_str(before).unwrap();
        let value = |text: &str| serde_json::from_str::<serde_json::Value>(text).unwrap();

        let renamed = replace_username(Some(before), Some("asmith")).unwrap();
        expected["username"] = serde_json::json!("asmith");
        assert_eq!(value(&renamed), expected);
        assert!(renamed.ends_with('\n'));

        let forgotten = replace_username(Some(before), None).unwrap();
        expected.as_object_mut().unwrap().remove("username");
        assert_eq!(value(&forgotten), expected);
        let loaded: Settings = serde_json::from_str(&forgotten).unwrap();
        assert_eq!(loaded.username, None);

        // With no file there is one afterwards, or still nothing to forget.
        let made = replace_username(None, Some("jdoe")).unwrap();
        assert_eq!(value(&made), serde_json::json!({"username": "jdoe"}));
        assert_eq!(replace_username(None, None).unwrap(), "{}\n");
    }

    #[test]
    fn a_file_that_does_not_load_keeps_its_username() {
        let unreadable = Err(SettingsFailureCode::Unreadable);
        for bad in ["", "not json", "[]", r#"{"save_password":"yes"}"#] {
            assert_eq!(
                replace_username(Some(bad), Some("jdoe")),
                unreadable,
                "{bad:?}"
            );
            assert_eq!(replace_username(Some(bad), None), unreadable, "{bad:?}");
        }
    }

    // A name nobody would type is not kept, so that it cannot make the file
    // too long to show or put control characters in it.
    #[test]
    fn only_a_plausible_username_is_saved() {
        let longest = "u".repeat(MAX_USERNAME_BYTES);
        assert!(replace_username(None, Some(&longest)).is_ok());
        let too_long = format!("{longest}u");
        let odd_names = [
            "",
            " ",
            " \u{3000}\u{a0} ",
            &too_long,
            "j\ndoe",
            "jdoe\u{1b}[2J",
            "j\u{0}doe",
            // Shown, this one reads "jdoe" followed by something else.
            "jdoe\u{202e}nimda",
            "j\u{200b}doe",
            "\u{feff}jdoe",
            "jdoe\u{2066}",
            "jdoe\u{2028}admin",
            "jdoe\u{2029}admin",
            "jdoe\u{e0061}",
        ];
        for odd in odd_names {
            let refused = replace_username(Some("{}"), Some(odd));
            assert_eq!(refused, Err(SettingsFailureCode::BadInput), "{odd:?}");
        }
        let plain_names = [
            "jdoe@example.test",
            "Zoë Müller",
            " jdoe",
            // A joiner inside a Persian name is part of how it is written.
            "می\u{200c}خواهم",
        ];
        for plain in plain_names {
            assert!(replace_username(None, Some(plain)).is_ok(), "{plain:?}");
        }
    }

    // One rule says which characters mislead, for what is printed and for
    // what is saved. This holds it to the list.
    #[test]
    fn the_characters_that_mislead_are_these() {
        let misleading = "\u{0}\u{1b}\u{7f}\u{85}\u{061c}\u{200b}\u{200e}\u{200f}\u{202a}\u{202e}\u{2060}\u{2069}\u{feff}\u{2028}\u{2029}\u{e0000}\u{e0041}\u{e007f}";
        for c in misleading.chars() {
            assert!(misleads(c), "{c:?}");
        }
        let ordinary =
            "a Zé\u{200c}\u{200d}\u{2027}\u{202f}\u{206a}\u{fefe}\u{1f512}\u{dffff}\u{e0080}";
        for c in ordinary.chars() {
            assert!(!misleads(c), "{c:?}");
        }
    }

    // The input comes from the app. An unknown field means the app and the
    // client disagree about the format, which must not pass silently.
    #[test]
    fn input_with_an_unknown_field_is_refused() {
        assert!(decode::<RouteInput>("{\"subnets\":[],\"dns_domains\":[]}").is_ok());
        assert!(decode::<RouteInput>("{\"subnets\":[],\"dns_domains\":[],\"x\":1}").is_err());
        assert!(decode::<RouteInput>("{\"subnets\":[]}").is_err());
    }
}
