//! The Duo method at connect: the username the gateway is sent, the
//! passcode, texted codes, and `--duo`. Usernames and codes are made up.

use ubc_vpn_core::duo::DuoMethod;
use ubc_vpn_core::login::PromptKind;
use ubc_vpn_core::redact::Secret;
use ubc_vpn_engine::fake::{FakeEngine, Script};

use crate::FAILED;
use crate::connect::{BAD_CODE, Ended, LOGIN_REFUSED, PASSCODE, TEXTED};
use crate::interrupt::Progress;
use crate::test_support::{
    CODE, PASSWORD, ROUTES, Scene, Typist, gateway_script, saved, settings_text,
};

/// A passcode, and a code from a text message. Neither holds a word the
/// log takes for a secret, nor is in any other value here.
const PASSCODE_TYPED: &str = "135790";
const TEXTED_CODE: &str = "8642097";

/// The pretend gateway taking `username`, the password and the one-time
/// code, as the usual scene's does.
fn gateway(username: &str) -> Script {
    let mut script = gateway_script();
    script.form[0].1 = Secret::new(username);
    let mut code = script.form[1].clone();
    (code.0.kind, code.1) = (PromptKind::Code, Secret::new(CODE));
    script.form.push(code);
    script
}

/// A scene whose saved username is `username`, which reading splits as it
/// splits any from before the method was a setting, and whose gateway
/// takes `wanted`.
fn scene(username: &str, wanted: &str) -> Scene {
    let mut scene = Scene::new(
        Some(&format!(r#"{{"username":"{username}",{ROUTES}}}"#)),
        "",
    );
    scene.gateway = FakeEngine::new(gateway(wanted));
    scene
}

/// The usernames the gateway was sent, in order.
fn sent_usernames(scene: &Scene) -> Vec<String> {
    let answers = scene.gateway.answers();
    let names = answers
        .iter()
        .filter(|(kind, _)| *kind == PromptKind::Username);
    names.map(|(_, name)| name.expose().to_string()).collect()
}

fn connect(scene: &Scene, duo: Option<DuoMethod>, typist: &mut Typist) -> (u8, String, String) {
    let (ended, out, err) = scene.connect_with(None, duo, typist, &Progress::default());
    match ended {
        Ended::Status(code) => (code, out, err),
        other => panic!("the connect was stopped: {other:?}"),
    }
}

// The saved method is what a connect uses: the one an automatic connect at
// start-up, or a reconnect that logs in again, runs as well, since each is
// this same command with no `--duo`. Ignoring it sends the wrong suffix and
// fails here.
#[test]
fn the_saved_method_is_put_on_the_username() {
    for (saved_as, sent) in [
        ("alice", "alice@app"),
        ("alice@app", "alice@app"),
        ("alice@call", "alice@call"),
        ("alice@phone", "alice@call"),
        ("alice.dept@call", "alice.dept@call"),
        ("alice@other", "alice@other"),
    ] {
        let scene = scene(saved_as, sent);
        let mut typist = Typist::typing(&[Some(PASSWORD), Some(CODE)]);
        let (code, _, err) = connect(&scene, None, &mut typist);
        assert_eq!(code, 0, "{saved_as}: {err}");
        assert_eq!(sent_usernames(&scene), [sent], "{saved_as}");
        assert_eq!(typist.asked, [PromptKind::Password, PromptKind::Code]);
    }
}

// A typed username gets the method too, and is kept without it; one typed
// with its own `@` is sent as typed.
#[test]
fn a_typed_username_gets_the_method_and_is_kept_without_it() {
    let first = ubc_vpn_core::profiles::ProfileId::first();
    let file = format!(
        r#"{{"version":2,"global":{{"active_profile":"{first}"}},
        "profiles":[{{"id":"{first}","name":"UBC VPN","duo_method":"call",{ROUTES}}}]}}"#,
        first = first.as_str()
    );
    let mut scene = Scene::new(Some(&file), "");
    scene.gateway = FakeEngine::new(gateway("alice@call"));
    let mut typist = Typist::typing(&[Some("alice"), Some(PASSWORD), Some(CODE)]);
    let (code, _, err) = connect(&scene, None, &mut typist);
    assert_eq!(code, 0, "{err}");
    assert_eq!(sent_usernames(&scene), ["alice@call"]);
    assert_eq!(saved(&scene)["username"], "alice");
    assert!(settings_text(&scene).contains(r#""duo_method": "call""#));
}

// `--duo` is for one connect: it is sent, and nothing is saved.
#[test]
fn duo_overrides_the_method_for_one_connect_and_saves_nothing() {
    let scene = scene("alice@app", "alice@call");
    let before = settings_text(&scene);
    let mut typist = Typist::typing(&[Some(PASSWORD), Some(CODE)]);
    let (code, _, err) = connect(&scene, Some(DuoMethod::Call), &mut typist);
    assert_eq!(code, 0, "{err}");
    assert_eq!(sent_usernames(&scene), ["alice@call"]);
    assert_eq!(settings_text(&scene), before);
}

// Security rule: a passcode is asked for at each connect, before the
// username is sent, and checked; it goes to the gateway in the username and
// nowhere else: not the settings, not what is printed, not the service's
// log. The careless library here echoes every answer in error lines and
// registers none.
#[test]
fn a_passcode_is_asked_for_sent_and_never_kept_or_shown() {
    let wanted = format!("alice@{PASSCODE_TYPED}");
    let mut scene = scene("alice@111111", &wanted);
    let mut script = gateway(&wanted);
    script.leaks = true;
    scene.gateway = FakeEngine::new(script);
    // Not a passcode, then one with the space Duo Mobile shows.
    let mut typist = Typist::typing(&[Some("12345"), Some("135 790"), Some(PASSWORD), Some(CODE)]);
    let (code, out, err) = connect(&scene, None, &mut typist);
    assert_eq!(code, 0, "{err}");
    let asked = [
        PromptKind::Code,
        PromptKind::Code,
        PromptKind::Password,
        PromptKind::Code,
    ];
    assert_eq!(typist.asked, asked);
    assert_eq!(sent_usernames(&scene), [wanted.as_str()]);
    let logs = scene.service.as_ref().unwrap().login_lines().join("\n");
    let listed = scene.rig.run(&["logs", "--json"]).1;
    let file = settings_text(&scene);
    assert!(file.contains(r#""duo_method": "passcode""#), "{file}");
    for shown in [&out, &err, &logs, &listed, &file] {
        for secret in [PASSCODE_TYPED, "111111", PASSWORD] {
            assert!(!shown.contains(secret), "{secret} in {shown}");
        }
    }
    // The echoed answers did arrive, blanked.
    assert!(err.contains("ubc-vpn: > [redacted]"), "{err}");
}

#[test]
fn a_passcode_that_is_never_one_stops_the_login_unsent() {
    let scene = scene("alice@123456", "alice@135790");
    let mut typist = Typist::typing(&[Some("1"), Some("abcdef"), Some("1234567")]);
    let (code, _, err) = connect(&scene, None, &mut typist);
    assert_eq!(code, FAILED, "{err}");
    assert!(err.contains(BAD_CODE), "{err}");
    assert_eq!(typist.asked, [PromptKind::Code; 3]);
    assert!(!scene.gateway_was_asked());
    // Giving up at the question is a cancel, as at any other.
    let mut leaving = Typist::typing(&[None]);
    let (code, _, err) = connect(&scene, None, &mut leaving);
    assert_eq!(code, crate::connect::CANCELLED, "{err}");
    assert!(!scene.gateway_was_asked());
}

// The words of the questions this program asks itself.
#[test]
fn the_code_questions_say_what_to_enter() {
    assert!(PASSCODE.message.contains("6-digit"));
    assert!(TEXTED.label.contains("text message"));
    assert!(TEXTED.message.contains("text message"));
}

// With texted codes, the gateway refuses the login sent with `@sms` and
// texts the codes. The user is asked for one once, and the login is made
// again with it and the same password; nothing else is asked again. The
// code is kept out of everything shown, like a passcode.
#[test]
fn texted_codes_are_asked_for_after_the_refusal_and_sent() {
    let wanted = format!("alice@{TEXTED_CODE}");
    let scene = scene("alice@sms", &wanted);
    let mut typist = Typist::typing(&[Some(PASSWORD), Some(CODE), Some(TEXTED_CODE), Some(CODE)]);
    let (code, out, err) = connect(&scene, None, &mut typist);
    assert_eq!(code, 0, "{err}");
    assert_eq!(sent_usernames(&scene), ["alice@sms", wanted.as_str()]);
    // The password was typed once, and sent again with the code.
    let asked = [
        PromptKind::Password,
        PromptKind::Code,
        PromptKind::Code,
        PromptKind::Code,
    ];
    assert_eq!(typist.asked, asked);
    let logs = scene.service.as_ref().unwrap().login_lines().join("\n");
    for shown in [&out, &err, &logs, &settings_text(&scene)] {
        assert!(!shown.contains(TEXTED_CODE), "{shown}");
    }
}

// Only once: a second refusal is a refused login, as any other.
#[test]
fn texted_codes_are_tried_once() {
    let scene = scene("alice@sms", "alice@0000000");
    let mut typist = Typist::typing(&[Some(PASSWORD), Some(CODE), Some(TEXTED_CODE), Some(CODE)]);
    let (code, _, err) = connect(&scene, None, &mut typist);
    assert_eq!(code, LOGIN_REFUSED, "{err}");
    let usernames = sent_usernames(&scene);
    assert_eq!(usernames.last().map(String::as_str), Some("alice@8642097"));
    assert_eq!(usernames.iter().filter(|n| n.ends_with("@sms")).count(), 1);
}

// A gateway that takes `@sms` at once is never asked again.
#[test]
fn a_gateway_that_takes_sms_at_once_is_not_asked_again() {
    let scene = scene("alice@sms", "alice@sms");
    let mut typist = Typist::typing(&[Some(PASSWORD), Some(CODE)]);
    let (code, _, err) = connect(&scene, None, &mut typist);
    assert_eq!(code, 0, "{err}");
    assert_eq!(sent_usernames(&scene), ["alice@sms"]);
}

// Security rule: a passcode stored in a username by an older version is
// taken out of the file by the next connect, which never sends it.
#[test]
fn a_stored_passcode_leaves_the_file_at_the_next_connect() {
    let scene = scene("alice@246802", "alice@135790");
    assert!(settings_text(&scene).contains("246802"));
    let mut typist = Typist::typing(&[Some(PASSCODE_TYPED), Some(PASSWORD), Some(CODE)]);
    let (code, _, err) = connect(&scene, None, &mut typist);
    assert_eq!(code, 0, "{err}");
    assert!(!settings_text(&scene).contains("246802"));
    assert!(!sent_usernames(&scene).concat().contains("246802"));
}
