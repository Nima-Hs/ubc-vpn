//! `settings set-tunnel`, and the mode `connect` sends, against the real
//! service on the fakes. Tests marked "Security rule" must fail if the rule
//! they name is removed. Every value is made up.

use ubc_vpn_core::protocol::{ClientKind, ErrorCode, decode};
use ubc_vpn_core::settings_cli::{LiveRoutes, SettingsFailure, SettingsFailureCode, TunnelReply};
use ubc_vpn_core::state::{ConnState, TunnelMode};

use crate::client::{Client, Limits};
use crate::connect_tests::{CODE, PASSWORD, ROUTES, Scene, Typist, settings_text};
use crate::profiles::{Command, run};

const FULL: &str = r#"{"mode":"full"}"#;
const SPLIT: &str = r#"{"mode":"split"}"#;

/// Runs `settings set-tunnel --json` with `typed` on standard input, and
/// returns its exit status and line.
fn set_tunnel(scene: &Scene, typed: &str) -> (u8, String) {
    let platform = || Ok(scene.rig.fake.platform(&scene.rig.root));
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let status = run(
        Command::SetTunnel,
        &platform,
        &mut typed.as_bytes(),
        &mut out,
        &mut err,
    );
    (status, String::from_utf8(out).unwrap())
}

/// The reply of a `set-tunnel` that worked.
fn reply(scene: &Scene, typed: &str) -> TunnelReply {
    let (status, out) = set_tunnel(scene, typed);
    assert_eq!(status, 0, "{out}");
    decode(out.trim_end()).unwrap()
}

/// The mode saved in the settings file.
fn saved_mode(scene: &Scene) -> serde_json::Value {
    let saved: serde_json::Value = serde_json::from_str(&settings_text(scene)).unwrap();
    saved["global"]["tunnel"].clone()
}

/// The mode of the connection the service reports, if connected.
fn live_mode(scene: &Scene) -> Option<TunnelMode> {
    match decode::<ConnState>(scene.state().trim_end()).unwrap() {
        ConnState::Connected { tunnel } => Some(tunnel.mode),
        _ => None,
    }
}

fn connect(scene: &Scene) {
    let mut typist = Typist::typing(&[Some(PASSWORD), Some(CODE)]);
    let (status, _, err) = scene.connect(&mut typist);
    assert_eq!(status, 0, "{err}");
}

// The issue's case: the mode is saved for every profile, and a connected
// VPN is switched to it without reconnecting, both ways.
#[test]
fn a_mode_saved_while_connected_is_applied_to_it() {
    let scene = Scene::usual();
    connect(&scene);
    let full = reply(&scene, FULL);
    let applied = TunnelReply::Ok {
        tunnel: TunnelMode::Full,
        live: LiveRoutes::Applied,
    };
    assert_eq!(full, applied);
    assert_eq!(saved_mode(&scene), "full");
    assert_eq!(live_mode(&scene), Some(TunnelMode::Full));
    assert!(scene.rig.fake.applied().full_tunnel.is_some());

    let split = reply(&scene, SPLIT);
    let applied = TunnelReply::Ok {
        tunnel: TunnelMode::Split,
        live: LiveRoutes::Applied,
    };
    assert_eq!(split, applied);
    assert_eq!(saved_mode(&scene), "split");
    assert_eq!(live_mode(&scene), Some(TunnelMode::Split));
    assert!(scene.rig.fake.applied().full_tunnel.is_none());
}

// `connect` sends the saved mode: once full is saved, the next connection
// is in full mode.
#[test]
fn connect_sends_the_saved_mode() {
    let scene = Scene::usual();
    let saved = reply(&scene, FULL);
    let next = TunnelReply::Ok {
        tunnel: TunnelMode::Full,
        live: LiveRoutes::NextConnect,
    };
    assert_eq!(saved, next);
    connect(&scene);
    assert_eq!(live_mode(&scene), Some(TunnelMode::Full));
}

// Not connected, the mode is saved for the next connect, and saving it
// makes nobody the owner.
#[test]
fn a_mode_saved_while_not_connected_is_for_the_next_connect() {
    let scene = Scene::usual();
    let saved = reply(&scene, FULL);
    assert!(
        matches!(
            saved,
            TunnelReply::Ok {
                live: LiveRoutes::NextConnect,
                ..
            }
        ),
        "{saved:?}"
    );
    // Security rule: saving the mode makes nobody the owner.
    let platform = scene.rig.fake.platform(&scene.rig.root);
    let client = Client::reach(&platform, ClientKind::Cli, Limits::default()).unwrap();
    assert!(
        !client.owner_claimed(),
        "saving the mode claimed the service"
    );
}

// Security rule: full mode the policy forbids is never saved: the reply
// says so, the file is as it was, and the service is not asked. Split may
// still be saved.
#[test]
fn full_mode_the_policy_forbids_is_not_saved() {
    let settings = format!(r#"{{"username":"alice",{ROUTES}}}"#);
    let scene = Scene::new(Some(&settings), r#","full_tunnel":"forbidden""#);
    connect(&scene);
    let (before, calls) = (settings_text(&scene), scene.rig.fake.calls());
    assert_eq!(reply(&scene, FULL), TunnelReply::Forbidden);
    assert_eq!(settings_text(&scene), before, "something was saved");
    assert_eq!(scene.rig.fake.calls(), calls, "the service was asked");
    assert_eq!(live_mode(&scene), Some(TunnelMode::Split));
    let split = reply(&scene, SPLIT);
    assert!(matches!(split, TunnelReply::Ok { .. }), "{split:?}");
    assert_eq!(saved_mode(&scene), "split");
}

// A mode the service refuses for this network stays saved, the connection
// keeps the mode it has, and the reply says why.
#[test]
fn a_mode_the_service_refuses_leaves_the_connection_as_it_was() {
    let scene = Scene::usual();
    connect(&scene);
    scene.rig.fake.set_foreign_catch_all(true);
    let refused = reply(&scene, FULL);
    let TunnelReply::Ok {
        tunnel: TunnelMode::Full,
        live: LiveRoutes::Refused { code, message },
    } = refused
    else {
        panic!("not refused: {refused:?}");
    };
    assert_eq!(code, ErrorCode::RouteRefused);
    assert!(message.contains("already resolves all names"), "{message}");
    assert_eq!(saved_mode(&scene), "full");
    assert_eq!(live_mode(&scene), Some(TunnelMode::Split));
}

// Input that is not a mode is refused, and nothing is saved.
#[test]
fn input_that_is_not_a_mode_is_refused() {
    let scene = Scene::usual();
    let before = settings_text(&scene);
    for typed in [r#"{"mode":"all"}"#, r#"{"mode":"Full"}"#, "", r#"{}"#] {
        let (status, out) = set_tunnel(&scene, typed);
        assert_eq!(status, 1, "{typed}: {out}");
        let failure: SettingsFailure = decode(out.trim_end()).unwrap();
        assert_eq!(failure.error, SettingsFailureCode::BadInput, "{typed}");
    }
    assert_eq!(settings_text(&scene), before, "something was saved");
}
