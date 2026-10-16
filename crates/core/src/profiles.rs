//! Settings version 2: profiles, and the settings they share.
//!
//! A profile is a named way to connect: a username, whether its password is
//! saved in the OS keyring, and the routes and DNS domains to send through
//! the tunnel. The gateway is the policy's, the same for every profile. What
//! the profiles share is in [`GlobalSettings`]: how UBC VPN starts when the
//! user signs in, whether it connects by itself, and which profile is used.
//!
//! ```json
//! { "version": 2,
//!   "global": { "start": "off", "auto_connect": false, "active_profile": "<id>" },
//!   "profiles": [ { "id": "<id>", "name": "UBC VPN", "username": null,
//!                   "routes": { "subnets": [], "dns_domains": [] },
//!                   "save_password": false } ] }
//! ```
//!
//! - **Ids, not names, are the keys.** A [`ProfileId`] is 32 lowercase hex
//!   digits and never changes; a rename changes only the name. The saved
//!   password is kept in the keyring under the id.
//! - **Version 1 is read as one profile.** A file without a `version` holds
//!   one user's `username`, `routes` and `save_password`. It is read as the
//!   profile [`FIRST_PROFILE_NAME`], with the id [`ProfileId::first`], made
//!   active; its routes are kept exactly. Reading writes nothing: the file
//!   becomes version 2 the first time it is saved, and the id is the same
//!   every time it is read until then.
//! - **Anything else is unreadable.** A newer version, or a version 2 file
//!   that breaks a rule here, is [`SettingsFailureCode::Unreadable`]: the
//!   way out is `settings reset`, as for any file that cannot be read.
//! - **Fields this version does not know are kept,** at the top, in
//!   `global` and in each profile, so a file saved by a newer version keeps
//!   what that version stored.
//!
//! The rules for changing them are the methods of [`Profiles`]; the
//! command-line client reads the file, calls one, and saves the result. The
//! lines the app exchanges with it are at the end of this module.

use std::collections::HashSet;

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};

use crate::routes::{Ipv4Net, RouteSet};
use crate::settings::{Settings, lenient_routes};
use crate::settings_cli::{RouteInput, SettingsFailureCode, misleads, usable_username};

/// The version of the settings file this module writes.
pub const SETTINGS_VERSION: u32 = 2;

/// The most profiles a user may have.
pub const MAX_PROFILES: usize = 32;

/// The longest profile name, in characters.
pub const MAX_NAME_CHARS: usize = 64;

/// The name of the profile that settings from before profiles become, and of
/// the one a user starts with.
pub const FIRST_PROFILE_NAME: &str = "UBC VPN";

/// A profile's id: 32 lowercase hex digits, made when the profile is made
/// and never changed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, type = "string"))]
pub struct ProfileId(String);

/// The length of a [`ProfileId`], in hex digits.
const ID_DIGITS: usize = 32;

impl ProfileId {
    /// The id of the first profile: the one a user starts with and the one
    /// settings from before profiles become. Fixed, so that it is the same
    /// every time such a file is read.
    pub fn first() -> Self {
        Self(format!("{:0>ID_DIGITS$}", 1))
    }

    /// An id from 16 random bytes.
    pub fn from_random(bytes: [u8; 16]) -> Self {
        Self(bytes.iter().map(|b| format!("{b:02x}")).collect())
    }

    /// The id as text, as it is stored and shown.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ProfileId {
    type Error = &'static str;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        let hex = |b: u8| b.is_ascii_digit() || (b'a'..=b'f').contains(&b);
        match text.len() == ID_DIGITS && text.bytes().all(hex) {
            true => Ok(Self(text)),
            false => Err("a profile id is 32 lowercase hex digits"),
        }
    }
}

impl From<ProfileId> for String {
    fn from(id: ProfileId) -> Self {
        id.0
    }
}

impl std::str::FromStr for ProfileId {
    type Err = &'static str;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::try_from(text.to_string())
    }
}

/// How UBC VPN starts when the user signs in. The app registers itself to
/// match; the settings only hold the choice.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub enum StartMode {
    /// It does not start by itself.
    #[default]
    Off,
    /// It starts and opens its window.
    Window,
    /// It starts in the tray, with no window.
    Tray,
}

/// What every profile shares.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct GlobalSettings {
    /// How UBC VPN starts when the user signs in.
    #[serde(default)]
    pub start: StartMode,
    /// Whether it connects with the active profile once it has started.
    #[serde(default)]
    pub auto_connect: bool,
    /// The profile `connect` uses unless told otherwise.
    pub active_profile: ProfileId,
    /// Fields this version does not know, kept as they are.
    #[serde(flatten)]
    #[cfg_attr(test, ts(skip))]
    pub other: Map<String, Value>,
}

/// One way to connect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct Profile {
    /// Never changes.
    pub id: ProfileId,
    /// What the user calls it. See [`check_name`].
    pub name: String,
    /// The username that answers the gateway's question, when saved.
    #[serde(default)]
    pub username: Option<String>,
    /// The subnets and DNS domains to send through the tunnel. Kept as
    /// saved: the service checks them again at connect.
    #[serde(default, deserialize_with = "lenient_routes")]
    pub routes: RouteSet,
    /// Whether this profile's password is kept in the OS keyring. The
    /// password itself is never in this file.
    #[serde(default)]
    pub save_password: bool,
    /// Fields this version does not know, kept as they are.
    #[serde(flatten)]
    #[cfg_attr(test, ts(skip))]
    pub other: Map<String, Value>,
}

/// The settings file, version 2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct Profiles {
    /// Always [`SETTINGS_VERSION`].
    pub version: u32,
    /// What the profiles share.
    pub global: GlobalSettings,
    /// At least one, at most [`MAX_PROFILES`], in the order the user made
    /// them.
    pub profiles: Vec<Profile>,
    /// Fields this version does not know, kept as they are.
    #[serde(flatten)]
    #[cfg_attr(test, ts(skip))]
    pub other: Map<String, Value>,
}

/// Why a change to the profiles was refused. Nothing was changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub enum ProfileFailureCode {
    /// No profile has that id.
    UnknownProfile,
    /// The name is empty, too long, or holds a character that could mislead.
    BadName,
    /// Another profile has that name, in any case.
    NameTaken,
    /// There are [`MAX_PROFILES`] already.
    TooManyProfiles,
    /// The last profile cannot be deleted.
    LastProfile,
    /// The username is not one that is saved: see
    /// [`usable_username`].
    BadUsername,
}

/// A profile name made fit to store: trimmed, 1 to [`MAX_NAME_CHARS`]
/// characters, and with no character that [`misleads`].
pub fn check_name(name: &str) -> Result<String, ProfileFailureCode> {
    let name = name.trim();
    let length = name.chars().count();
    match (1..=MAX_NAME_CHARS).contains(&length) && !name.chars().any(misleads) {
        true => Ok(name.to_string()),
        false => Err(ProfileFailureCode::BadName),
    }
}

/// What a change means for the profile's saved password.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum Password {
    /// It may be kept.
    Keep,
    /// It must be deleted from the keyring: the profile is gone, it no
    /// longer saves its password, or its username changed.
    Forget,
}

impl Profiles {
    /// The settings of a user who has saved none: one empty profile.
    pub fn fresh() -> Self {
        Self::from_v1(Settings::default(), Map::new())
    }

    /// Settings from before profiles, as one active profile. `other` are
    /// the file's other fields, kept.
    fn from_v1(v1: Settings, other: Map<String, Value>) -> Self {
        let id = ProfileId::first();
        let profile = Profile {
            id: id.clone(),
            name: FIRST_PROFILE_NAME.to_string(),
            username: v1.username,
            routes: v1.routes,
            save_password: v1.save_password,
            other: Map::new(),
        };
        Self {
            version: SETTINGS_VERSION,
            global: GlobalSettings {
                start: StartMode::Off,
                auto_connect: false,
                active_profile: id,
                other: Map::new(),
            },
            profiles: vec![profile],
            other,
        }
    }

    /// Reads a settings file's text, or `None` when there is no file. A
    /// file from before profiles is read as one profile; see the module
    /// documentation.
    pub fn read(text: Option<&str>) -> Result<Self, SettingsFailureCode> {
        let unreadable = |_| SettingsFailureCode::Unreadable;
        let Some(text) = text else {
            return Ok(Self::fresh());
        };
        let Value::Object(mut file) = serde_json::from_str(text).map_err(unreadable)? else {
            return Err(SettingsFailureCode::Unreadable);
        };
        match file.get("version").map(Value::as_u64) {
            // Before profiles there was no version.
            None | Some(Some(1)) => {
                let v1: Settings =
                    serde_json::from_value(Value::Object(file.clone())).map_err(unreadable)?;
                for moved in ["version", "username", "routes", "save_password"] {
                    file.remove(moved);
                }
                Ok(Self::from_v1(v1, file))
            }
            Some(Some(2)) => {
                let read: Self = serde_json::from_value(Value::Object(file)).map_err(unreadable)?;
                read.check().map_err(|_| SettingsFailureCode::Unreadable)?;
                Ok(read)
            }
            // A newer version, or not a number: not this version's to read.
            Some(_) => Err(SettingsFailureCode::Unreadable),
        }
    }

    /// The text to save, as version 2.
    pub fn to_text(&self) -> String {
        let mut text = serde_json::to_string_pretty(self).unwrap_or_default();
        text.push('\n');
        text
    }

    /// Checks every rule of the module documentation.
    pub fn check(&self) -> Result<(), ProfileFailureCode> {
        if self.version != SETTINGS_VERSION {
            return Err(ProfileFailureCode::UnknownProfile);
        }
        if self.profiles.is_empty() {
            return Err(ProfileFailureCode::LastProfile);
        }
        if self.profiles.len() > MAX_PROFILES {
            return Err(ProfileFailureCode::TooManyProfiles);
        }
        let mut ids = HashSet::new();
        let mut names = HashSet::new();
        for profile in &self.profiles {
            if !ids.insert(&profile.id) {
                return Err(ProfileFailureCode::UnknownProfile);
            }
            if check_name(&profile.name).as_deref() != Ok(profile.name.as_str()) {
                return Err(ProfileFailureCode::BadName);
            }
            if !names.insert(profile.name.to_lowercase()) {
                return Err(ProfileFailureCode::NameTaken);
            }
            if profile
                .username
                .as_deref()
                .is_some_and(|u| !usable_username(u))
            {
                return Err(ProfileFailureCode::BadUsername);
            }
        }
        match ids.contains(&self.global.active_profile) {
            true => Ok(()),
            false => Err(ProfileFailureCode::UnknownProfile),
        }
    }

    /// The profile with `id`.
    pub fn profile(&self, id: &ProfileId) -> Result<&Profile, ProfileFailureCode> {
        let found = self.profiles.iter().find(|p| p.id == *id);
        found.ok_or(ProfileFailureCode::UnknownProfile)
    }

    fn profile_mut(&mut self, id: &ProfileId) -> Result<&mut Profile, ProfileFailureCode> {
        let found = self.profiles.iter_mut().find(|p| p.id == *id);
        found.ok_or(ProfileFailureCode::UnknownProfile)
    }

    /// The profile `connect` uses.
    pub fn active(&self) -> &Profile {
        self.profile(&self.global.active_profile)
            .unwrap_or(&self.profiles[0])
    }

    /// Applies `change` to a copy and keeps it only if every rule still
    /// holds, so a refused change changes nothing.
    fn change<T>(
        &mut self,
        change: impl FnOnce(&mut Self) -> Result<T, ProfileFailureCode>,
    ) -> Result<T, ProfileFailureCode> {
        let mut changed = self.clone();
        let result = change(&mut changed)?;
        changed.check()?;
        *self = changed;
        Ok(result)
    }

    /// Makes a profile with a new `id`, which the caller makes at random.
    /// It is not made active.
    pub fn create(
        &mut self,
        id: ProfileId,
        name: &str,
        username: Option<&str>,
        routes: RouteSet,
        save_password: bool,
    ) -> Result<(), ProfileFailureCode> {
        let name = check_name(name)?;
        if username.is_some_and(|u| !usable_username(u)) {
            return Err(ProfileFailureCode::BadUsername);
        }
        if self.profiles.len() >= MAX_PROFILES {
            return Err(ProfileFailureCode::TooManyProfiles);
        }
        self.change(|all| {
            all.profiles.push(Profile {
                id,
                name,
                username: username.map(str::to_string),
                routes,
                save_password,
                other: Map::new(),
            });
            Ok(())
        })
    }

    /// Renames a profile. Its id, and so its saved password, stay.
    pub fn rename(&mut self, id: &ProfileId, name: &str) -> Result<(), ProfileFailureCode> {
        let name = check_name(name)?;
        self.change(|all| {
            all.profile_mut(id)?.name = name;
            Ok(())
        })
    }

    /// Changes a profile's username, when `username` is given (`Some(None)`
    /// removes it), and whether it saves its password. The saved password
    /// is to be forgotten when the username changes or saving is turned
    /// off: it was the old user's, or the user no longer wants it kept.
    pub fn update(
        &mut self,
        id: &ProfileId,
        username: Option<Option<&str>>,
        save_password: Option<bool>,
    ) -> Result<Password, ProfileFailureCode> {
        if let Some(Some(name)) = username
            && !usable_username(name)
        {
            return Err(ProfileFailureCode::BadUsername);
        }
        self.change(|all| {
            let profile = all.profile_mut(id)?;
            let mut forget = false;
            if let Some(username) = username {
                forget |= profile.username.as_deref() != username;
                profile.username = username.map(str::to_string);
            }
            if let Some(save) = save_password {
                forget |= profile.save_password && !save;
                profile.save_password = save;
            }
            Ok(if forget {
                Password::Forget
            } else {
                Password::Keep
            })
        })
    }

    /// Deletes a profile, whose saved password is to be forgotten. The last
    /// one cannot be. When the active one is deleted, the first that is
    /// left becomes active.
    pub fn delete(&mut self, id: &ProfileId) -> Result<Password, ProfileFailureCode> {
        self.profile(id)?;
        if self.profiles.len() == 1 {
            return Err(ProfileFailureCode::LastProfile);
        }
        self.change(|all| {
            all.profiles.retain(|p| p.id != *id);
            if all.global.active_profile == *id {
                all.global.active_profile = all.profiles[0].id.clone();
            }
            Ok(Password::Forget)
        })
    }

    /// Makes a profile the one `connect` uses.
    pub fn switch(&mut self, id: &ProfileId) -> Result<(), ProfileFailureCode> {
        self.change(|all| {
            all.profile(id)?;
            all.global.active_profile = id.clone();
            Ok(())
        })
    }

    /// Replaces a profile's routes with ones already checked.
    pub fn set_routes(
        &mut self,
        id: &ProfileId,
        routes: RouteSet,
    ) -> Result<(), ProfileFailureCode> {
        self.change(|all| {
            all.profile_mut(id)?.routes = routes;
            Ok(())
        })
    }

    /// Sets how UBC VPN starts and whether it connects by itself.
    pub fn set_startup(&mut self, start: StartMode, auto_connect: bool) {
        self.global.start = start;
        self.global.auto_connect = auto_connect;
    }

    /// The active profile as the settings were before profiles, for the
    /// commands and the app that do not know profiles yet.
    pub fn v1_view(&self) -> Settings {
        let active = self.active();
        Settings {
            username: active.username.clone(),
            routes: active.routes.clone(),
            save_password: active.save_password,
        }
    }
}

// The lines the app exchanges with the command-line client about profiles.
// Each command reads one line and writes one line, as `settings` does.

/// Whether the OS keyring can be used to save passwords.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub enum Keyring {
    /// It can: a profile that saves its password keeps it there.
    Available,
    /// It cannot: passwords are asked for each time.
    Unavailable,
}

/// The answer to `profiles list`, and to every change of the profiles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct ProfilesView {
    /// What the profiles share.
    pub global: GlobalSettings,
    /// Every profile, with whether its password is saved.
    pub profiles: Vec<ProfileView>,
    /// Whether passwords can be saved at all.
    pub keyring: Keyring,
    /// Whether the policy file could be read and is valid.
    pub policy_readable: bool,
    /// When the policy limits routes, the only networks they may fall inside.
    #[cfg_attr(test, ts(type = "Array<string> | null"))]
    pub allowed_routes: Option<Vec<Ipv4Net>>,
}

/// A profile as the app sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct ProfileView {
    /// The profile as stored.
    #[serde(flatten)]
    pub profile: Profile,
    /// Whether a password for it is in the keyring now. Only whether: the
    /// password itself is never read for this.
    pub password_saved: bool,
}

/// The input of `profiles create`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct NewProfile {
    /// What the user calls it.
    pub name: String,
    /// Its username, if known.
    #[serde(default)]
    pub username: Option<String>,
    /// Its routes as typed, checked as `settings check-routes` checks them.
    #[serde(default)]
    pub routes: Option<RouteInput>,
    /// Whether it saves its password.
    #[serde(default)]
    pub save_password: bool,
}

/// The input of `profiles rename`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct RenameProfile {
    /// Which profile.
    pub id: ProfileId,
    /// Its new name.
    pub name: String,
}

/// The input of `profiles update`. A field that is left out is not changed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct UpdateProfile {
    /// Which profile.
    pub id: ProfileId,
    /// Its new username, or `null` to remove it. Changing it forgets the
    /// saved password.
    #[serde(default, deserialize_with = "present")]
    #[cfg_attr(test, ts(optional, type = "string | null"))]
    pub username: Option<Option<String>>,
    /// Whether it saves its password. Turning it off forgets the saved one.
    #[serde(default)]
    #[cfg_attr(test, ts(optional))]
    pub save_password: Option<bool>,
}

/// Tells a field given as `null` from one left out: `Some(None)` and `None`.
fn present<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<Option<String>>, D::Error> {
    Option::<String>::deserialize(deserializer).map(Some)
}

/// The input of `profiles delete` and `profiles switch`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct ProfileRef {
    /// Which profile.
    pub id: ProfileId,
}

/// The input of `password forget`: a profile, or the active one.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct MaybeProfile {
    /// Which profile; the active one when left out.
    #[serde(default)]
    pub id: Option<ProfileId>,
}

/// The input of `profile set-routes`: routes as typed, for a profile or the
/// active one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct ProfileRoutes {
    /// Which profile; the active one when left out.
    #[serde(default)]
    pub id: Option<ProfileId>,
    /// Subnets such as `142.103.0.0/16`.
    pub subnets: Vec<String>,
    /// DNS domains such as `ece.ubc.ca`.
    pub dns_domains: Vec<String>,
}

/// The input of `settings set-startup`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct Startup {
    /// How UBC VPN starts when the user signs in.
    pub start: StartMode,
    /// Whether it connects once it has started.
    pub auto_connect: bool,
}

/// The answer to a change of the profiles that was refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct ProfileFailure {
    /// Why. Nothing was changed.
    pub error: ProfileFailureCode,
}

#[cfg(test)]
#[path = "profiles_tests.rs"]
mod tests;
