//! `settings set-tunnel`, and the mode `connect` sends, against the real
//! service on the fakes. Tests marked "Security rule" must fail if the rule
//! they name is removed. Every value is made up.

use std::cell::RefCell;
use std::path::Path;
use std::rc::Rc;
use std::time::Duration;

use ubc_vpn_core::policy::FullTunnel;
use ubc_vpn_core::profiles::{ProfileId, Profiles, ProfilesView, StartMode};
use ubc_vpn_core::protocol::{
    ClientKind, ErrorCode, Event, Outcome, Request, RequestBody, Response, ResponseBody,
    ServerMessage, SetTunnelParams, decode,
};
use ubc_vpn_core::settings_cli::{LiveRoutes, SettingsFailure, SettingsFailureCode, TunnelReply};
use ubc_vpn_core::state::{ConnState, TunnelInfo, TunnelMode};

use crate::client::{Client, Limits};
use crate::connect::Ended;
use crate::connect_tests::{CODE, PASSWORD, ROUTES, Scene, Typist, brief, settings_text};
use crate::interrupt::Progress;
use crate::profiles::{Command, run};
use crate::settings::DURING_A_SAVE;
use crate::settings_lock::change_within;
use crate::tests::{Rig, greet, scripted, tell};

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

/// How many switches of mode the service was asked for, admitted or
/// refused: each is one line in its log. A switch to the mode in effect is
/// answered without a line, so the tests that count ask for the other one.
fn switches_asked(scene: &Scene) -> usize {
    let (status, out, err) = scene.rig.run(&["logs"]);
    assert_eq!(status, 0, "{err}");
    out.lines()
        .filter(|line| {
            ["tunnel mode change admitted", "tunnel mode change refused"]
                .iter()
                .any(|said| line.contains(said))
        })
        .count()
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
    // Each switch the service was asked for is counted.
    assert_eq!(switches_asked(&scene), 2);
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
    let before = settings_text(&scene);
    assert_eq!(reply(&scene, FULL), TunnelReply::Forbidden);
    assert_eq!(settings_text(&scene), before, "something was saved");
    assert_eq!(switches_asked(&scene), 0, "the service was asked");
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

/// Runs `look` with the settings folder in the middle of every save this
/// thread makes while `run` runs.
fn during_a_save<T>(look: impl Fn(&Path) + 'static, run: impl FnOnce() -> T) -> T {
    DURING_A_SAVE.with(|during| *during.borrow_mut() = Some(Box::new(look)));
    let ran = run();
    DURING_A_SAVE.with(|during| *during.borrow_mut() = None);
    ran
}

// Security rule: the mode is saved under the settings lock, from the read
// to the save, so it cannot undo a change made at the same time.
#[test]
fn the_mode_is_saved_under_the_settings_lock() {
    let scene = Scene::usual();
    let found = Rc::new(RefCell::new(Vec::new()));
    let looked = found.clone();
    let look = move |dir: &Path| {
        let tried = change_within(dir, Duration::from_millis(100));
        looked
            .borrow_mut()
            .push(tried.map(|changing| changing.unlocked()));
    };
    during_a_save(look, || reply(&scene, FULL));
    let held = Err(SettingsFailureCode::Unwritable);
    assert_eq!(*found.borrow(), [held], "the lock was not held");
    assert_eq!(saved_mode(&scene), "full");
}

// Security rule: the live connection is switched only once the mode is
// saved. A save that fails is a failure, and the service is not asked.
#[test]
fn a_mode_that_could_not_be_saved_is_not_applied() {
    let scene = Scene::usual();
    connect(&scene);
    let calls = scene.rig.fake.calls();
    // In the middle of the save, a folder takes the file's name, so the
    // new file cannot be put in its place.
    let block = |dir: &Path| {
        let file = dir.join("settings.json");
        std::fs::remove_file(&file).unwrap();
        std::fs::create_dir(&file).unwrap();
        std::fs::write(file.join("in-the-way"), "").unwrap();
    };
    let (status, out) = during_a_save(block, || set_tunnel(&scene, FULL));
    assert_eq!(status, 1, "{out}");
    let failure: SettingsFailure = decode(out.trim_end()).unwrap();
    assert_eq!(failure.error, SettingsFailureCode::Unwritable);
    assert_eq!(scene.rig.fake.calls(), calls, "the service was asked");
    assert_eq!(switches_asked(&scene), 0, "a switch was asked for");
    assert_eq!(live_mode(&scene), Some(TunnelMode::Split));
}

/// Settings with the usual first profile, active, and a second one, `Lab`,
/// with the same username and routes, and a start-up setting that is not
/// the default.
fn with_a_lab() -> (String, ProfileId) {
    let first = format!(r#"{{"username":"alice",{ROUTES}}}"#);
    let mut profiles = Profiles::read(Some(&first)).unwrap().profiles;
    let lab = ProfileId::from_random([0x2b; 16]);
    let routes = profiles.active().routes.clone();
    profiles
        .create(lab.clone(), "Lab", Some("alice"), routes, false)
        .unwrap();
    profiles.set_startup(StartMode::Tray, true);
    (profiles.to_text(), lab)
}

// `connect --profile` sends the saved mode too: it is one setting for
// every profile, not the active one's.
#[test]
fn connect_with_a_profile_sends_the_saved_mode() {
    let (settings, lab) = with_a_lab();
    let scene = Scene::new(Some(&settings), "");
    reply(&scene, FULL);
    let mut typist = Typist::typing(&[Some(PASSWORD), Some(CODE)]);
    let (ended, _, err) = scene.connect_as(Some(&lab), &mut typist, &Progress::default());
    assert_eq!(ended, Ended::Status(0), "{err}");
    assert_eq!(live_mode(&scene), Some(TunnelMode::Full));
}

// `set-tunnel` changes `global.tunnel` and nothing else in the file: not
// the profiles, their routes, which one is active, or any other global
// setting.
#[test]
fn only_the_mode_is_changed_in_the_file() {
    let (settings, _) = with_a_lab();
    let scene = Scene::new(Some(&settings), "");
    let read = |scene: &Scene| -> serde_json::Value {
        serde_json::from_str(&settings_text(scene)).unwrap()
    };
    let mut before = read(&scene);
    for (typed, mode) in [(FULL, "full"), (SPLIT, "split")] {
        reply(&scene, typed);
        let mut after = read(&scene);
        assert_eq!(after["global"]["tunnel"], mode);
        // The mode aside, the file is as it was.
        for file in [&mut before, &mut after] {
            file["global"].as_object_mut().unwrap().remove("tunnel");
        }
        assert_eq!(after, before, "something else changed");
        before = read(&scene);
    }
}

/// Runs `switch` to `mode` against a stand-in for the service, which
/// greets, answers the request with `answer`, then sends `events`.
fn switch_answered(
    mode: TunnelMode,
    answer: ResponseBody,
    events: Vec<ConnState>,
) -> (LiveRoutes, Option<RequestBody>) {
    let rig = Rig::new();
    let (asked, heard) = std::sync::mpsc::channel();
    let service = scripted(&rig, move |conn| {
        greet(conn);
        let request: Request = decode(&conn.read_line().unwrap().unwrap()).unwrap();
        let response = Response {
            id: request.id,
            outcome: Outcome::Ok(answer),
        };
        asked.send(request.body).unwrap();
        tell(conn, &ServerMessage::Response(response));
        for state in events {
            tell(conn, &ServerMessage::Event(Event::StateChanged(state)));
        }
        // Stays until the client has hung up.
        while conn.read_line().is_ok_and(|line| line.is_some()) {}
    });
    let platform = rig.fake.platform(&rig.root);
    let live = crate::live::switch(&platform, mode, brief());
    drop(platform);
    service.join().unwrap();
    (live, heard.try_recv().ok())
}

/// A connection in `mode`, as the service reports it.
fn in_mode(mode: TunnelMode) -> ConnState {
    ConnState::Connected {
        tunnel: TunnelInfo {
            interface: "fake0".to_string(),
            address: "10.255.0.2".to_string(),
            subnets: vec!["10.255.0.0/24".parse().unwrap()],
            dns_domains: vec!["dept.example.test".to_string()],
            mode,
        },
    }
}

// A connection still in the old mode, reported before the switch ended, is
// not the switch's outcome: it is passed over, and what comes next is.
#[test]
fn a_state_in_the_old_mode_is_not_the_outcome() {
    let failed = ConnState::Failed {
        code: ErrorCode::VerificationFailed,
        message: "Full tunnel could not be checked.".to_string(),
    };
    let events = vec![in_mode(TunnelMode::Split), failed];
    let (live, asked) = switch_answered(TunnelMode::Full, ResponseBody::Accepted, events);
    let set = SetTunnelParams {
        mode: TunnelMode::Full,
    };
    assert_eq!(asked, Some(RequestBody::SetTunnel(set)));
    assert!(matches!(live, LiveRoutes::Failed { .. }), "{live:?}");
    // Answered at once with the connection in the old mode: not applied.
    let old = ResponseBody::Status(in_mode(TunnelMode::Split));
    let (live, _) = switch_answered(TunnelMode::Full, old, Vec::new());
    assert!(matches!(live, LiveRoutes::Unknown { .. }), "{live:?}");
    // In the new mode: there was nothing to do.
    let new = ResponseBody::Status(in_mode(TunnelMode::Full));
    let (live, _) = switch_answered(TunnelMode::Full, new, Vec::new());
    assert_eq!(live, LiveRoutes::Applied);
}

// An answer of the wrong kind says nothing of the connection, so it is
// never taken for a change that was applied.
#[test]
fn an_answer_of_the_wrong_kind_is_not_applied() {
    for answer in [
        ResponseBody::Status(ConnState::Disconnected),
        ResponseBody::Claimed,
    ] {
        let (live, _) = switch_answered(TunnelMode::Full, answer.clone(), Vec::new());
        assert!(
            matches!(live, LiveRoutes::Unknown { .. }),
            "{answer:?}: {live:?}"
        );
    }
}

/// The answer to `profiles list`.
fn listed(scene: &Scene) -> ProfilesView {
    let platform = || Ok(scene.rig.fake.platform(&scene.rig.root));
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let status = run(
        Command::List,
        &platform,
        &mut "".as_bytes(),
        &mut out,
        &mut err,
    );
    let out = String::from_utf8(out).unwrap();
    assert_eq!(status, 0, "{out}");
    decode(out.trim_end()).unwrap()
}

// The profiles view says whether the policy lets full mode be chosen, so
// the app can say so before anyone chooses it. Without a word in the
// policy, it may be.
#[test]
fn the_profiles_view_says_whether_the_policy_allows_full_mode() {
    let settings = format!(r#"{{"username":"alice",{ROUTES}}}"#);
    let forbidden = Scene::new(Some(&settings), r#","full_tunnel":"forbidden""#);
    assert_eq!(listed(&forbidden).full_tunnel, FullTunnel::Forbidden);
    let allowed = Scene::new(Some(&settings), r#","full_tunnel":"allowed""#);
    assert_eq!(listed(&allowed).full_tunnel, FullTunnel::Allowed);
    let unsaid = Scene::new(Some(&settings), "");
    assert_eq!(listed(&unsaid).full_tunnel, FullTunnel::Allowed);
}
