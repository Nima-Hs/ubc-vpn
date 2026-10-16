//! The user's settings, stored in `settings.json` in their config folder.
//!
//! The app and the command-line client both read and write settings through
//! this type, so they always agree.

use serde::{Deserialize, Deserializer, Serialize};

use crate::routes::{Ipv4Net, RouteSet};

/// The contents of `settings.json`. Every field has a default, so a missing or
/// older file still loads.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct Settings {
    /// The CWL username, remembered so the user is not asked each time.
    pub username: Option<String>,
    /// The subnets and DNS domains to send through the tunnel.
    #[serde(deserialize_with = "lenient_routes")]
    pub routes: RouteSet,
    /// Whether to keep the password in the OS keyring. The password itself is
    /// never stored here.
    pub save_password: bool,
}

/// Reads the routes the way a settings file needs: missing and unknown fields
/// are fine, so files from older and newer versions both load. On the channel
/// the same type is strict. An invalid subnet is still an error, because
/// silently dropping a route the user chose would be worse than refusing.
pub(crate) fn lenient_routes<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<RouteSet, D::Error> {
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Lenient {
        subnets: Vec<Ipv4Net>,
        dns_domains: Vec<String>,
    }
    let Lenient {
        subnets,
        dns_domains,
    } = Lenient::deserialize(deserializer)?;
    Ok(RouteSet {
        subnets,
        dns_domains,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_file_gives_defaults() {
        assert_eq!(
            serde_json::from_str::<Settings>("{}").unwrap(),
            Settings::default()
        );
    }

    #[test]
    fn settings_round_trip() {
        let json = r#"{"username":"jdoe","routes":{"subnets":["142.103.0.0/16"],"dns_domains":["ece.ubc.ca"]},"save_password":true}"#;
        let settings: Settings = serde_json::from_str(json).unwrap();
        assert_eq!(settings.username.as_deref(), Some("jdoe"));
        assert!(settings.save_password);
        assert_eq!(serde_json::to_string(&settings).unwrap(), json);
    }

    // Unlike channel requests, settings tolerate unknown fields, so a file
    // written by a newer version still loads in an older one.
    #[test]
    fn unknown_fields_are_ignored() {
        let settings: Settings = serde_json::from_str(r#"{"theme":"dark"}"#).unwrap();
        assert_eq!(settings, Settings::default());
    }

    // The same tolerance holds inside `routes`, where the channel is strict.
    #[test]
    fn routes_tolerate_unknown_and_missing_fields() {
        let newer: Settings =
            serde_json::from_str(r#"{"routes":{"subnets":["10.19.0.0/16"],"future":1}}"#).unwrap();
        assert_eq!(newer.routes.subnets.len(), 1);

        let partial: Settings =
            serde_json::from_str(r#"{"routes":{"dns_domains":["ece.ubc.ca"]}}"#).unwrap();
        assert!(partial.routes.subnets.is_empty());
        assert_eq!(partial.routes.dns_domains, ["ece.ubc.ca"]);
    }

    #[test]
    fn an_invalid_subnet_is_an_error_not_a_silent_drop() {
        assert!(
            serde_json::from_str::<Settings>(r#"{"routes":{"subnets":["10.0.0.1/8"]}}"#).is_err()
        );
    }
}
