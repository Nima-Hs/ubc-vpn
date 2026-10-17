//! The profiles commands, for the app: `profiles list`, `create`, `rename`,
//! `update`, `delete` and `switch`; `profile set-routes`; `password forget`;
//! `settings set-startup`; and `settings set-tunnel`. Each is spelled with
//! `--json`, reads at most one line on standard input, and writes one line.
//! The rules are in `ubc_vpn_core::profiles`; this file reads the file,
//! calls one, and saves the result.
//!
//! - **Every change is made under the settings lock,** from the read to the
//!   save, and so is every change to a saved password that goes with it:
//!   two processes of this program never change the settings, or the
//!   keyring's index, at once.
//! - **A saved password is forgotten** when its profile is deleted, when the
//!   profile stops saving it, when its username changes, when the user asks
//!   (`password forget`), and when reading cleared its username. A rename
//!   keeps it: the id does not change.
//! - **Whether a password is saved** comes from the keyring's index; no
//!   password is read for it. A keyring that cannot be used is said to be
//!   one, and the profiles are shown all the same.
//! - **Nothing is saved that cannot be shown:** a change whose answer would
//!   not fit in one line is refused, with the file as it was.
//! - **Full mode the policy forbids is never saved:** `settings set-tunnel`
//!   answers [`TunnelReply::Forbidden`] under the lock, with the file as it
//!   was.
//! - **This claims nothing.** Only `profile set-routes` and `settings
//!   set-tunnel` talk to the service, as `settings set-routes` does: the
//!   one for the active profile, the other to switch the live connection
//!   to the mode just saved.

use std::io::{BufRead, Write};

use ubc_vpn_core::policy::{FullTunnel, Policy};
use ubc_vpn_core::profiles::{
    Keyring, MaybeProfile, NewProfile, Password, ProfileFailure, ProfileFailureCode, ProfileRef,
    ProfileRoutes, ProfileView, Profiles, ProfilesView, RenameProfile, Startup, UpdateProfile,
};
use ubc_vpn_core::protocol::{decode, encode};
use ubc_vpn_core::routes::RouteSet;
use ubc_vpn_core::settings_cli::{
    LiveRoutes, RouteInput, RoutesReply, SettingsFailure, SettingsFailureCode, TunnelInput,
    TunnelReply, check_input,
};
use ubc_vpn_core::state::TunnelMode;
use ubc_vpn_platform::Platform;

use crate::settings::{Found, line, new_id, policy, read_profiles, write_profiles};
use crate::settings_lock::change;
use crate::{keys, live};

/// The commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// `profiles list --json`
    List,
    /// `profiles create --json`
    Create,
    /// `profiles rename --json`
    Rename,
    /// `profiles update --json`
    Update,
    /// `profiles delete --json`
    Delete,
    /// `profiles switch --json`
    Switch,
    /// `profile set-routes --json`
    SetRoutes,
    /// `password forget --json`
    ForgetPassword,
    /// `settings set-startup --json`
    SetStartup,
    /// `settings set-tunnel --json`
    SetTunnel,
}

impl Command {
    /// Reads the whole command line, or `None` when it is none of these.
    pub fn parse(args: &[&str]) -> Option<Self> {
        Some(match args {
            ["profiles", "list", "--json"] => Self::List,
            ["profiles", "create", "--json"] => Self::Create,
            ["profiles", "rename", "--json"] => Self::Rename,
            ["profiles", "update", "--json"] => Self::Update,
            ["profiles", "delete", "--json"] => Self::Delete,
            ["profiles", "switch", "--json"] => Self::Switch,
            ["profile", "set-routes", "--json"] => Self::SetRoutes,
            ["password", "forget", "--json"] => Self::ForgetPassword,
            ["settings", "set-startup", "--json"] => Self::SetStartup,
            ["settings", "set-tunnel", "--json"] => Self::SetTunnel,
            _ => return None,
        })
    }
}

/// What a command answers: one line, and whether it is a failure.
enum Answer {
    /// The profiles as they now are.
    Profiles(Box<ProfilesView>),
    /// For `profile set-routes`: as `settings set-routes` answers.
    Routes(RoutesReply),
    /// For `settings set-tunnel`.
    Tunnel(TunnelReply),
    /// A change the rules refused. Nothing was changed.
    Refused(ProfileFailureCode),
}

/// Runs one command: writes exactly one line on `out` and returns the exit
/// status, 0 unless that line is a failure.
pub fn run(
    command: Command,
    platform: &dyn Fn() -> ubc_vpn_platform::Result<Platform>,
    input: &mut dyn BufRead,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    let platform = platform().ok();
    let answered = platform
        .as_ref()
        .ok_or(SettingsFailureCode::Unreadable)
        .and_then(|platform| answer(command, platform, input, err));
    let (line, failed) = match answered {
        Ok(Answer::Profiles(view)) => (encode(&*view), false),
        Ok(Answer::Routes(reply)) => (encode(&reply), false),
        Ok(Answer::Tunnel(reply)) => (encode(&reply), false),
        Ok(Answer::Refused(error)) => (encode(&ProfileFailure { error }), true),
        Err(error) => (encode(&SettingsFailure { error }), true),
    };
    let written = out.write_all(line.unwrap_or_default().as_bytes());
    let unsaid = written.and_then(|()| out.flush()).is_err();
    u8::from(failed || unsaid)
}

fn answer(
    command: Command,
    platform: &Platform,
    stdin: &mut dyn BufRead,
    err: &mut dyn Write,
) -> Result<Answer, SettingsFailureCode> {
    let paths = &platform.paths;
    let policy = policy(&paths.policy_dir);
    let dir = paths.settings_dir.as_path();
    if command == Command::List {
        let found = read_profiles(dir)?;
        tell_cleaned(&found, err);
        return view(&found.profiles, policy.as_ref()).map(Answer::Profiles);
    }
    // What the change asks for is read before anything is locked.
    let change_asked = asked(command, stdin)?;
    let (answer, live) = {
        let _changing = change(dir)?;
        let found = read_profiles(dir)?;
        tell_cleaned(&found, err);
        let Found {
            mut profiles,
            cleaned_passwords: mut forget,
            ..
        } = found;
        let made = apply(change_asked, &mut profiles, &mut forget, policy.as_ref());
        let (answer, live) = match made {
            Ok(Made::Routes(routes, active)) => {
                // Shown as `settings get` and `profiles list` show them.
                let reply = RoutesReply::Ok {
                    routes: routes.clone(),
                    live: None,
                };
                encode(&reply).map_err(|_| SettingsFailureCode::BadInput)?;
                (Answer::Routes(reply), active.then_some(routes))
            }
            Ok(Made::Profiles) => (
                Answer::Profiles(Box::new(fits(&profiles, policy.as_ref())?)),
                None,
            ),
            // Shown as the reply will be once the service has answered.
            Ok(Made::Tunnel(tunnel)) => (
                Answer::Tunnel(TunnelReply::Ok {
                    tunnel,
                    live: LiveRoutes::NextConnect,
                }),
                None,
            ),
            Ok(Made::Invalid(reply)) => return Ok(Answer::Routes(reply)),
            Ok(Made::Forbidden) => return Ok(Answer::Tunnel(TunnelReply::Forbidden)),
            Err(code) => return Ok(Answer::Refused(code)),
        };
        // Nothing is saved that cannot be shown.
        view(&profiles, policy.as_ref())?;
        write_profiles(dir, &profiles, &forget)?;
        let answer = match answer {
            // What the keyring holds now that the change is made.
            Answer::Profiles(_) => Answer::Profiles(view(&profiles, policy.as_ref())?),
            other => other,
        };
        (answer, live)
    };
    // Routes saved for the active profile, and a tunnel mode, go to the
    // live connection too, once the lock on the settings is let go: the
    // service may take a moment.
    let limits = crate::client::Limits::default();
    match (answer, live) {
        (Answer::Routes(RoutesReply::Ok { routes, .. }), Some(_)) => {
            let live = live::apply(platform, &routes, limits);
            let reply = RoutesReply::Ok {
                routes,
                live: Some(live),
            };
            Ok(Answer::Routes(reply))
        }
        (Answer::Tunnel(TunnelReply::Ok { tunnel, .. }), _) => {
            let live = live::switch(platform, tunnel, limits);
            Ok(Answer::Tunnel(TunnelReply::Ok { tunnel, live }))
        }
        (answer, _) => Ok(answer),
    }
}

/// What a change command asks for, read from its input.
enum Asked {
    Create(NewProfile),
    Rename(RenameProfile),
    Update(UpdateProfile),
    Delete(ProfileRef),
    Switch(ProfileRef),
    Routes(ProfileRoutes),
    Forget(MaybeProfile),
    Startup(Startup),
    Tunnel(TunnelInput),
}

fn asked(command: Command, stdin: &mut dyn BufRead) -> Result<Asked, SettingsFailureCode> {
    let bad = |_| SettingsFailureCode::BadInput;
    if command == Command::List {
        return Err(SettingsFailureCode::BadInput);
    }
    let text = line(stdin)?;
    Ok(match command {
        Command::List => return Err(SettingsFailureCode::BadInput),
        Command::Create => Asked::Create(decode(&text).map_err(bad)?),
        Command::Rename => Asked::Rename(decode(&text).map_err(bad)?),
        Command::Update => Asked::Update(decode(&text).map_err(bad)?),
        Command::Delete => Asked::Delete(decode(&text).map_err(bad)?),
        Command::Switch => Asked::Switch(decode(&text).map_err(bad)?),
        Command::SetRoutes => Asked::Routes(decode(&text).map_err(bad)?),
        Command::ForgetPassword => Asked::Forget(decode(&text).map_err(bad)?),
        Command::SetStartup => Asked::Startup(decode(&text).map_err(bad)?),
        Command::SetTunnel => Asked::Tunnel(decode(&text).map_err(bad)?),
    })
}

/// What a change made.
enum Made {
    /// The profiles changed.
    Profiles,
    /// A profile's routes were set; `true` when it is the active one.
    Routes(RouteSet, bool),
    /// The routes typed have problems: nothing was changed.
    Invalid(RoutesReply),
    /// The tunnel mode was set to this.
    Tunnel(TunnelMode),
    /// The policy forbids the mode asked for: nothing was changed.
    Forbidden,
}

/// Makes the change asked for to `profiles`, adding to `forget` the
/// profiles whose saved passwords must go.
fn apply(
    asked: Asked,
    profiles: &mut Profiles,
    forget: &mut Vec<ubc_vpn_core::profiles::ProfileId>,
    policy: Option<&Policy>,
) -> Result<Made, ProfileFailureCode> {
    let allowed = policy.and_then(|p| p.allowed_routes.as_deref());
    let forgets =
        |password: Password, id: &ubc_vpn_core::profiles::ProfileId, forget: &mut Vec<_>| {
            if password == Password::Forget {
                forget.push(id.clone());
            }
        };
    match asked {
        Asked::Create(new) => {
            let routes = match new.routes {
                None => RouteSet::default(),
                Some(typed) => match checked(&typed, allowed) {
                    Ok(routes) => routes,
                    Err(reply) => return Ok(Made::Invalid(reply)),
                },
            };
            // An id that is taken, which random ones almost never are, is
            // made again.
            let mut tries = 0;
            loop {
                let made = profiles.create(
                    new_id(),
                    &new.name,
                    new.username.as_deref(),
                    routes.clone(),
                    new.save_password,
                );
                match made {
                    Err(ProfileFailureCode::IdTaken) if tries < 3 => tries += 1,
                    other => return other.map(|()| Made::Profiles),
                }
            }
        }
        Asked::Rename(rename) => profiles
            .rename(&rename.id, &rename.name)
            .map(|()| Made::Profiles),
        Asked::Update(update) => {
            let username = update.username.as_ref().map(|name| name.as_deref());
            let was_saving = profiles.profile(&update.id).map(|p| p.save_password);
            let password = profiles.update(&update.id, username, update.save_password)?;
            forgets(password, &update.id, forget);
            // Turned on: whatever the keyring still holds for the profile
            // goes first. A password refused while the keyring would not
            // let it go was set aside by turning saving off, and is still
            // there; it must not be sent once saving is back on. If it
            // cannot go, saving stays off.
            if was_saving == Ok(false) && update.save_password == Some(true) {
                let cleared = keys::keyring().forget(update.id.as_str());
                cleared.map_err(|_| ProfileFailureCode::KeyringNotCleared)?;
            }
            Ok(Made::Profiles)
        }
        Asked::Delete(which) => {
            let password = profiles.delete(&which.id)?;
            forgets(password, &which.id, forget);
            Ok(Made::Profiles)
        }
        Asked::Switch(which) => profiles.switch(&which.id).map(|()| Made::Profiles),
        Asked::Routes(typed) => {
            let id = typed
                .id
                .unwrap_or_else(|| profiles.global.active_profile.clone());
            let input = RouteInput {
                subnets: typed.subnets,
                dns_domains: typed.dns_domains,
            };
            let routes = match checked(&input, allowed) {
                Ok(routes) => routes,
                Err(reply) => return Ok(Made::Invalid(reply)),
            };
            profiles.set_routes(&id, routes.clone())?;
            let active = id == profiles.global.active_profile;
            Ok(Made::Routes(routes, active))
        }
        Asked::Forget(which) => {
            let id = which
                .id
                .unwrap_or_else(|| profiles.global.active_profile.clone());
            profiles.profile(&id)?;
            forget.push(id);
            Ok(Made::Profiles)
        }
        Asked::Startup(startup) => {
            profiles.set_startup(startup.start, startup.auto_connect);
            Ok(Made::Profiles)
        }
        // Without a policy that can be read nothing forbids it here; the
        // service refuses to connect at all then.
        Asked::Tunnel(TunnelInput { mode }) => {
            let forbidden = policy.is_some_and(|p| p.full_tunnel == FullTunnel::Forbidden);
            if mode == TunnelMode::Full && forbidden {
                return Ok(Made::Forbidden);
            }
            profiles.set_tunnel(mode);
            Ok(Made::Tunnel(mode))
        }
    }
}

/// Routes as typed, checked as `settings check-routes` checks them.
fn checked(
    typed: &RouteInput,
    allowed: Option<&[ubc_vpn_core::routes::Ipv4Net]>,
) -> Result<RouteSet, RoutesReply> {
    check_input(typed, allowed).map_err(|problems| RoutesReply::Invalid { problems })
}

/// The profiles as the app sees them, with whether each has a password
/// saved, as the keyring's index says. A keyring that cannot be used is
/// said to be so, and shows none saved.
fn view(
    profiles: &Profiles,
    policy: Option<&Policy>,
) -> Result<Box<ProfilesView>, SettingsFailureCode> {
    let (keyring, saved) = match keys::keyring().saved() {
        Ok(saved) => (Keyring::Available, saved),
        Err(_) => (Keyring::Unavailable, Vec::new()),
    };
    let view = ProfilesView {
        global: profiles.global.clone(),
        profiles: profiles
            .profiles
            .iter()
            .map(|profile| ProfileView {
                password_saved: saved.iter().any(|a| a == profile.id.as_str()),
                profile: profile.clone(),
            })
            .collect(),
        keyring,
        policy_readable: policy.is_some(),
        allowed_routes: policy.and_then(|p| p.allowed_routes.clone()),
        full_tunnel: policy.map(|p| p.full_tunnel).unwrap_or_default(),
    };
    Ok(Box::new(view))
}

/// The view of `profiles`, if it fits in one line; otherwise the change is
/// refused.
fn fits(profiles: &Profiles, policy: Option<&Policy>) -> Result<ProfilesView, SettingsFailureCode> {
    let view = view(profiles, policy)?;
    encode(&*view).map_err(|_| SettingsFailureCode::BadInput)?;
    Ok(*view)
}

/// Tells the user, on standard error, that a name or a username could not
/// be kept as it was and was changed. Once saved, the file holds what it
/// was changed to, and this is not said again.
fn tell_cleaned(found: &Found, err: &mut dyn Write) {
    if found.cleaned {
        let _ = writeln!(
            err,
            "ubc-vpn: A profile name or username in the settings could not be kept as it \
             was, so it was changed. Check your profiles."
        );
    }
}
