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
//! Saved routes are used by the next connection. A connection that is already
//! up keeps the routes it started with.
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
use crate::routes::{Ipv4Net, MAX_ROUTES, MIN_PREFIX_LEN, RouteSet, is_valid_domain};
use crate::settings::Settings;

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
    /// Subnets such as `142.103.0.0/16`.
    pub subnets: Vec<String>,
    /// DNS domains such as `ece.ubc.ca`.
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
    },
    /// At least one entry is not acceptable. Nothing was saved.
    Invalid {
        /// Every problem found, in the order of the input.
        problems: Vec<RouteProblem>,
    },
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
    let unreadable = |_| SettingsFailureCode::Unreadable;
    let text = current.unwrap_or("{}");
    // Loading it as settings first refuses anything `get` would refuse.
    serde_json::from_str::<Settings>(text).map_err(unreadable)?;
    let mut file: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(text).map_err(unreadable)?;
    let routes = serde_json::to_value(routes).map_err(unreadable)?;
    file.insert("routes".to_string(), routes);
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
        let routes = check_input(&input(&["142.103.0.0/16"], &["ece.ubc.ca"]), None).unwrap();
        assert_eq!(routes.subnets, ["142.103.0.0/16".parse().unwrap()]);
        assert_eq!(routes.dns_domains, ["ece.ubc.ca"]);
    }

    #[test]
    fn every_problem_is_reported_with_its_place() {
        use RouteList::{DnsDomains, Subnets};
        use RouteProblemCode::{BadDomain, BadSubnet, NotAllowed, Reserved, TooWide};
        let allowed: Vec<Ipv4Net> = vec!["142.103.0.0/16".parse().unwrap()];
        let typed = input(
            &[
                "142.103.5.0/24",
                "not a subnet",
                "142.103.5.1/24",
                " 142.103.0.0/16",
                "0.0.0.0/0",
                "10.0.0.0/7",
                "127.0.0.0/8",
                "10.19.0.0/16",
            ],
            &["ece.ubc.ca", "ECE.ubc.ca", "*.ubc.ca", "ubc"],
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
            check_input(&input(&[], &["ece.ubc.ca"]), None),
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
            dns_domains: vec!["ece.ubc.ca".to_string(); MAX_ROUTES + 1],
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
        let allowed: Vec<Ipv4Net> = vec!["142.103.0.0/16".parse().unwrap()];
        let cases: [(&[&str], &[&str]); 8] = [
            (&["142.103.0.0/16"], &["ece.ubc.ca"]),
            (&["142.103.9.0/24", "142.103.0.0/16"], &[]),
            (&[], &[]),
            (&["0.0.0.0/0"], &[]),
            (&["10.0.0.0/7"], &[]),
            (&["224.0.0.0/8"], &[]),
            (&["10.19.0.0/16"], &[]),
            (&["142.103.0.0/16"], &["ubc"]),
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
    fn replies_have_a_stable_wire_format() {
        let ok = RoutesReply::Ok {
            routes: check_input(&input(&["10.19.0.0/16"], &[]), None).unwrap(),
        };
        assert_eq!(
            encode(&ok).unwrap(),
            "{\"type\":\"ok\",\"routes\":{\"subnets\":[\"10.19.0.0/16\"],\"dns_domains\":[]}}\n"
        );
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
        };
        let limit = vec!["142.103.0.0/16".parse().unwrap()];

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
        check_input(&input(&[subnet], &["ece.ubc.ca"]), None).unwrap()
    }

    // Settings files are shared between versions. Saving routes with this
    // version must not delete what another version stored.
    #[test]
    fn saving_routes_changes_nothing_else_in_the_file() {
        let before = r#"{"username":"jdoe","routes":{"subnets":["10.19.0.0/16"],"old":1},
            "save_password":true,"theme":"dark","future":{"a":[1,2]}}"#;
        let after = replace_routes(Some(before), &routes("142.103.0.0/16")).unwrap();

        let saved: Settings = serde_json::from_str(&after).unwrap();
        assert_eq!(saved.username.as_deref(), Some("jdoe"));
        assert!(saved.save_password);
        assert_eq!(saved.routes, routes("142.103.0.0/16"));

        let mut expected: serde_json::Value = serde_json::from_str(before).unwrap();
        expected["routes"] = serde_json::json!({
            "subnets": ["142.103.0.0/16"],
            "dns_domains": ["ece.ubc.ca"],
        });
        let got: serde_json::Value = serde_json::from_str(&after).unwrap();
        assert_eq!(got, expected);
        assert!(after.ends_with('\n'));
    }

    #[test]
    fn saving_routes_with_no_file_makes_one() {
        let after = replace_routes(None, &routes("142.103.0.0/16")).unwrap();
        let saved: Settings = serde_json::from_str(&after).unwrap();
        assert_eq!(
            saved,
            Settings {
                routes: routes("142.103.0.0/16"),
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

    // The input comes from the app. An unknown field means the app and the
    // client disagree about the format, which must not pass silently.
    #[test]
    fn input_with_an_unknown_field_is_refused() {
        assert!(decode::<RouteInput>("{\"subnets\":[],\"dns_domains\":[]}").is_ok());
        assert!(decode::<RouteInput>("{\"subnets\":[],\"dns_domains\":[],\"x\":1}").is_err());
        assert!(decode::<RouteInput>("{\"subnets\":[]}").is_err());
    }
}
