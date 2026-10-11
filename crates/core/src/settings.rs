//! The user's settings, stored in `settings.json` in their config folder.
//!
//! The app and the command-line client both read and write settings through
//! this type, so they always agree.

use serde::{Deserialize, Serialize};

use crate::routes::RouteSet;

/// The contents of `settings.json`. Every field has a default, so a missing or
/// older file still loads.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct Settings {
    /// The CWL username, remembered so the user is not asked each time.
    pub username: Option<String>,
    /// The subnets and DNS domains to send through the tunnel.
    pub routes: RouteSet,
    /// Whether to keep the password in the OS keyring. The password itself is
    /// never stored here.
    pub save_password: bool,
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
}
