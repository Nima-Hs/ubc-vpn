//! Saved passwords in a connect: against the real service on the fakes, a
//! pretend gateway, and the fake keyring of each test's thread. Usernames
//! and passwords are made up; no test here can reach the user's keyring
//! (see `keys.rs`).

use ubc_vpn_core::login::PromptKind;
use ubc_vpn_core::profiles::{ProfileId, Profiles};
use ubc_vpn_core::redact::Secret;
use ubc_vpn_engine::fake::{FakeEngine, Script};
use ubc_vpn_platform::secrets::{FakeSecrets, Saved};

use crate::connect::{Ended, LOGIN_REFUSED};
use crate::connect_tests::{
    CODE, PASSWORD, ROUTES, Scene, Typist, pin, returning, saved, settings_text,
};
use crate::interrupt::Progress;
use crate::passwords::{NO_KEYRING, NOT_SAVED};
use crate::{FAILED, keys};

/// A password nobody types, left in the keyring from before.
const STALE: &str = "made-up-stale-pass-0001";

fn keyring() -> FakeSecrets {
    keys::test::fake()
}

/// A returning user whose profile saves its password.
fn saving() -> Scene {
    returning(&format!(
        r#"{{"username":"alice","save_password":true,{ROUTES}}}"#
    ))
}

/// The same, with a gateway that asks for no one-time code.
fn saving_without_a_code() -> Scene {
    let mut scene = saving();
    scene.gateway = FakeEngine::new(Script::new(pin()));
    scene
}

fn put(id: &ProfileId, username: &str, password: &str, in_doubt: bool) {
    let saved = Saved {
        username: username.to_string(),
        password: Secret::new(password),
        in_doubt,
    };
    keyring().secrets().save(id.as_str(), &saved).unwrap();
}

/// What is saved for the first profile: username, password, in doubt.
fn entry() -> Option<(String, String, bool)> {
    let saved = keyring().secrets().load(ProfileId::first().as_str());
    let saved = saved.unwrap()?;
    let password = saved.password.expose().to_string();
    Some((saved.username, password, saved.in_doubt))
}

/// Every password the gateway was sent, in order.
fn passwords_sent(scene: &Scene) -> Vec<String> {
    let answers = scene.gateway.answers();
    let passwords = answers
        .iter()
        .filter(|(kind, _)| *kind == PromptKind::Password);
    passwords.map(|(_, p)| p.expose().to_string()).collect()
}

fn disconnect(scene: &Scene) {
    assert_eq!(scene.rig.run(&["disconnect"]).0, 0);
}

// A typed password is saved once the login worked and the service accepted
// the connect, and the next connect sends it: only the code is asked.
#[test]
fn a_password_that_worked_is_saved_and_sent_next_time() {
    let scene = saving();
    let mut typist = Typist::typing(&[Some(PASSWORD), Some(CODE)]);
    let (code, _, err) = scene.connect(&mut typist);
    assert_eq!((code, err.as_str()), (0, ""));
    let expected = ("alice".to_string(), PASSWORD.to_string(), false);
    assert_eq!(entry(), Some(expected));
    assert!(!settings_text(&scene).contains(PASSWORD));
    disconnect(&scene);

    let mut typist = Typist::typing(&[Some(CODE)]);
    let (code, _, err) = scene.connect(&mut typist);
    assert_eq!((code, err.as_str()), (0, ""));
    assert_eq!(typist.asked, [PromptKind::Code]);
    assert_eq!(passwords_sent(&scene), [PASSWORD, PASSWORD]);
}

// A username typed in the same connect is saved first, and the password
// with it.
#[test]
fn a_typed_username_and_password_are_saved_together() {
    let scene = returning(&format!(r#"{{"save_password":true,{ROUTES}}}"#));
    let mut typist = Typist::typing(&[Some("alice"), Some(PASSWORD), Some(CODE)]);
    assert_eq!(scene.connect(&mut typist).0, 0);
    assert_eq!(saved(&scene)["username"], "alice");
    let expected = ("alice".to_string(), PASSWORD.to_string(), false);
    assert_eq!(entry(), Some(expected));
}

// A profile that does not save its password never reaches the keyring: it
// is not read, nothing is saved, and an unusable one is not mentioned.
#[test]
fn a_profile_that_saves_no_password_leaves_the_keyring_alone() {
    let scene = returning(&format!(r#"{{"username":"alice",{ROUTES}}}"#));
    put(&ProfileId::first(), "alice", STALE, false);
    let mut typist = Typist::typing(&[Some(PASSWORD), Some(CODE)]);
    assert_eq!(scene.connect(&mut typist).0, 0);
    assert_eq!(typist.asked, [PromptKind::Password, PromptKind::Code]);
    assert_eq!(passwords_sent(&scene), [PASSWORD]);
    let left = ("alice".to_string(), STALE.to_string(), false);
    assert_eq!(entry(), Some(left), "the keyring was changed");
    disconnect(&scene);

    keyring().set_unusable(true);
    let mut typist = Typist::typing(&[Some(PASSWORD), Some(CODE)]);
    let (code, _, err) = scene.connect(&mut typist);
    keyring().set_unusable(false);
    assert_eq!((code, err.as_str()), (0, ""));
}

// Nothing is saved from a login that was refused or given up, or from a
// connect the service did not accept.
#[test]
fn nothing_is_saved_from_a_connect_that_did_not_start() {
    let attempts: [&[Option<&str>]; 2] = [&[Some("wrong-pass-0000"), Some(CODE)], &[None]];
    for typed in attempts {
        let scene = saving();
        let mut typist = Typist::typing(typed);
        assert_ne!(scene.connect(&mut typist).0, 0);
        assert_eq!(entry(), None, "{typed:?}");
    }
    // The login is good, and the service refuses the connect: the policy it
    // read when it started does not allow routes the policy file now does.
    let narrow = r#","allowed_routes":["142.103.0.0/16"]"#;
    let settings = format!(r#"{{"username":"alice","save_password":true,{ROUTES}}}"#);
    let scene = Scene::new(Some(&settings), narrow);
    let open = format!(
        r#"{{"gateway":"vpn.example.test","pins":["{}"]}}"#,
        pin().as_str()
    );
    std::fs::write(scene.rig.root.join("policy/policy.json"), open).unwrap();
    let mut typist = Typist::typing(&[Some(PASSWORD), Some(CODE)]);
    let (code, _, err) = scene.connect(&mut typist);
    assert_eq!(code, FAILED, "{err}");
    assert!(scene.gateway_was_asked(), "the login was made");
    assert_eq!(entry(), None);
}

// Security rule: a saved password is sent only for the username it was
// saved for, without regard to case. One left under the first profile's
// fixed id for another username is never sent, and is forgotten; the
// typed password that works then takes its place.
#[test]
fn a_password_saved_for_another_username_is_never_sent() {
    let scene = saving();
    put(&ProfileId::first(), "mallory", STALE, false);
    let mut typist = Typist::typing(&[Some(PASSWORD), Some(CODE)]);
    let (code, _, err) = scene.connect(&mut typist);
    assert_eq!((code, err.as_str()), (0, ""));
    assert_eq!(typist.asked, [PromptKind::Password, PromptKind::Code]);
    assert_eq!(passwords_sent(&scene), [PASSWORD]);
    let expected = ("alice".to_string(), PASSWORD.to_string(), false);
    assert_eq!(entry(), Some(expected));
    disconnect(&scene);

    // Saved for the same username in other letters: it is the same user.
    put(&ProfileId::first(), "ALICE", PASSWORD, false);
    let mut typist = Typist::typing(&[Some(CODE)]);
    assert_eq!(scene.connect(&mut typist).0, 0);
    assert_eq!(typist.asked, [PromptKind::Code]);
}

// Security rule: with no username saved there is no username a password
// can be bound to, so none is sent, and a leftover one is forgotten before
// anything is asked.
#[test]
fn a_profile_without_a_username_sends_no_saved_password() {
    let scene = returning(&format!(r#"{{"save_password":true,{ROUTES}}}"#));
    put(&ProfileId::first(), "alice", STALE, false);
    let mut typist = Typist::typing(&[None]);
    assert_eq!(scene.connect(&mut typist).0, crate::connect::CANCELLED);
    assert_eq!(entry(), None);
    assert!(passwords_sent(&scene).is_empty());
}

// Security rule: a saved password the gateway refused, with no code
// entered, can only have been the wrong answer. It is forgotten at once and
// never sent again: the next connect asks for it.
#[test]
fn a_refused_saved_password_with_no_code_entered_is_forgotten() {
    let scene = saving_without_a_code();
    put(&ProfileId::first(), "alice", STALE, false);
    let mut typist = Typist::default();
    let (code, _, err) = scene.connect(&mut typist);
    assert_eq!(code, LOGIN_REFUSED, "{err}");
    assert!(typist.asked.is_empty(), "the saved answers were used");
    assert_eq!(passwords_sent(&scene), [STALE]);
    assert_eq!(entry(), None);

    let mut typist = Typist::typing(&[Some(PASSWORD)]);
    assert_eq!(scene.connect(&mut typist).0, 0);
    assert_eq!(typist.asked, [PromptKind::Password]);
    assert_eq!(passwords_sent(&scene), [STALE, PASSWORD]);
    let expected = ("alice".to_string(), PASSWORD.to_string(), false);
    assert_eq!(entry(), Some(expected));
}

// Security rule: a saved password refused with a code entered may have been
// right, so it is kept, marked in doubt, and not sent again: the next
// connect asks. A typed password refused again leaves it in doubt; one that
// works replaces it.
#[test]
fn a_refused_saved_password_with_a_code_entered_is_kept_in_doubt() {
    let scene = saving();
    put(&ProfileId::first(), "alice", PASSWORD, false);
    // The password was right, the code was not.
    let mut typist = Typist::typing(&[Some("000000")]);
    assert_eq!(scene.connect(&mut typist).0, LOGIN_REFUSED);
    let doubted = ("alice".to_string(), PASSWORD.to_string(), true);
    assert_eq!(entry(), Some(doubted.clone()));

    let mut typist = Typist::typing(&[Some("wrong-pass-0000"), Some(CODE)]);
    assert_eq!(scene.connect(&mut typist).0, LOGIN_REFUSED);
    assert_eq!(typist.asked, [PromptKind::Password, PromptKind::Code]);
    assert_eq!(
        entry(),
        Some(doubted),
        "a refused typed password settled it"
    );

    let mut typist = Typist::typing(&[Some(PASSWORD), Some(CODE)]);
    assert_eq!(scene.connect(&mut typist).0, 0);
    assert_eq!(typist.asked, [PromptKind::Password, PromptKind::Code]);
    // The saved one was sent once, then never again.
    assert_eq!(
        passwords_sent(&scene),
        [PASSWORD, "wrong-pass-0000", PASSWORD]
    );
    let settled = ("alice".to_string(), PASSWORD.to_string(), false);
    assert_eq!(entry(), Some(settled));
}

// Security rule: should the keyring not forget a refused password, it is
// marked in doubt instead, so it is not sent again either way.
#[test]
fn a_refused_password_the_keyring_will_not_forget_is_put_in_doubt() {
    let scene = saving_without_a_code();
    put(&ProfileId::first(), "alice", STALE, false);
    // Deleting the entry fails; writing it does not.
    let account = ProfileId::first();
    keyring().fail_deletes_of(account.as_str(), true);
    let refused = scene.connect(&mut Typist::default()).0;
    keyring().fail_deletes_of(account.as_str(), false);
    assert_eq!(refused, LOGIN_REFUSED);
    let doubted = ("alice".to_string(), STALE.to_string(), true);
    assert_eq!(entry(), Some(doubted));
    let mut typist = Typist::typing(&[None]);
    assert_eq!(scene.connect(&mut typist).0, crate::connect::CANCELLED);
    assert_eq!(typist.asked, [PromptKind::Password]);
    assert_eq!(passwords_sent(&scene), [STALE], "it was sent again");
}

// A username the gateway refuses as a username is forgotten, and the
// password saved for it with it.
#[test]
fn a_username_to_check_takes_its_saved_password_with_it() {
    let mut scene = saving();
    put(&ProfileId::first(), "alice", PASSWORD, false);
    let mut script = Script::new(pin());
    script.form.truncate(1);
    script.form[0].1 = Secret::new("alice.ece@app");
    scene.gateway = FakeEngine::new(script);
    assert_eq!(scene.connect(&mut Typist::default()).0, LOGIN_REFUSED);
    assert!(saved(&scene).get("username").is_none());
    assert_eq!(entry(), None);
}

// A keyring that cannot be used is said to be one, the password is asked
// for, and the connect works; nothing more is said about it.
#[test]
fn an_unusable_keyring_is_said_and_the_password_asked() {
    let scene = saving();
    keyring().set_unusable(true);
    let mut typist = Typist::typing(&[Some(PASSWORD), Some(CODE)]);
    let (code, _, err) = scene.connect(&mut typist);
    keyring().set_unusable(false);
    assert_eq!(code, 0, "{err}");
    assert_eq!(err, format!("ubc-vpn: {NO_KEYRING}\n"));
    assert_eq!(typist.asked, [PromptKind::Password, PromptKind::Code]);
    assert_eq!(entry(), None);
}

// A password that worked and cannot be saved does not fail the connect:
// the user is told.
#[test]
fn a_password_that_cannot_be_saved_does_not_fail_the_connect() {
    let scene = saving();
    let fake = keyring();
    fake.fail_writes_to(ProfileId::first().as_str(), true);
    let mut typist = Typist::typing(&[Some(PASSWORD), Some(CODE)]);
    let (code, _, err) = scene.connect(&mut typist);
    fake.fail_writes_to(ProfileId::first().as_str(), false);
    assert_eq!(code, 0, "{err}");
    assert_eq!(err, format!("ubc-vpn: {NOT_SAVED}\n"));
}

// Security rule: what is saved after a connect is judged by the settings
// as they are then, under the lock, not as the connect found them: a
// profile that stopped saving its password, changed its username or is
// gone has nothing saved.
#[test]
fn a_password_is_saved_only_as_the_settings_still_ask() {
    let scene = saving();
    let dir = scene.rig.root.join("settings");
    let first = ProfileId::first();
    let keep = |username: &str| {
        let mut err = Vec::new();
        let password = Secret::new(PASSWORD);
        crate::passwords::keep(&dir, &first, username, &password, &mut err);
        assert!(err.is_empty());
    };
    keep("bob");
    assert_eq!(entry(), None, "saved for another username");
    keep("ALICE");
    let expected = ("alice".to_string(), PASSWORD.to_string(), false);
    assert_eq!(
        entry(),
        Some(expected),
        "saved under the profile's own name"
    );
    keyring().secrets().forget(first.as_str()).unwrap();

    let not_saving = format!(r#"{{"username":"alice",{ROUTES}}}"#);
    std::fs::write(dir.join("settings.json"), not_saving).unwrap();
    keep("alice");
    assert_eq!(entry(), None, "saved for a profile that saves none");

    let mut err = Vec::new();
    let gone = ProfileId::from_random([0x3c; 16]);
    crate::passwords::keep(&dir, &gone, "alice", &Secret::new(PASSWORD), &mut err);
    assert_eq!(keyring().entries(), [], "saved for a profile that is gone");
}

// A refusal settles only the password that was sent: one another connect
// saved since is left as it is.
#[test]
fn a_refusal_settles_only_the_password_it_sent() {
    let scene = saving();
    let dir = scene.rig.root.join("settings");
    let first = ProfileId::first();
    put(&first, "alice", PASSWORD, false);
    let sent = Secret::new(STALE);
    for code_entered in [false, true] {
        crate::passwords::refused(&dir, &first, &sent, code_entered).unwrap();
        let kept = ("alice".to_string(), PASSWORD.to_string(), false);
        assert_eq!(entry(), Some(kept), "code entered: {code_entered}");
    }
}

/// Settings with the first profile, as `settings`, and a second one, `Lab`,
/// with username `alice` and the same routes, which saves its password.
fn with_a_lab(first: &str) -> (String, ProfileId) {
    let mut profiles = Profiles::read(Some(first)).unwrap().profiles;
    let lab = ProfileId::from_random([0x1a; 16]);
    let routes = profiles.active().routes.clone();
    profiles
        .create(lab.clone(), "Lab", Some("alice"), routes, true)
        .unwrap();
    (profiles.to_text(), lab)
}

// `connect --profile` connects with that profile: its username, its
// routes and its saved password, whichever profile is active. An id no
// profile has is refused before anything is asked.
#[test]
fn a_connect_with_a_profile_uses_that_profiles_password() {
    let (settings, lab) = with_a_lab(&format!("{{{ROUTES}}}"));
    let scene = returning(&settings);
    put(&lab, "alice", PASSWORD, false);
    let mut typist = Typist::typing(&[Some(CODE)]);
    let (ended, _, err) = scene.connect_as(Some(&lab), &mut typist, &Progress::default());
    assert_eq!(ended, Ended::Status(0), "{err}");
    assert_eq!(typist.asked, [PromptKind::Code]);
    assert_eq!(passwords_sent(&scene), [PASSWORD]);
    disconnect(&scene);

    // The active profile has no username and saves nothing.
    let mut typist = Typist::typing(&[None]);
    scene.connect(&mut typist);
    assert_eq!(typist.asked, [PromptKind::Username]);

    let nobody = ProfileId::from_random([0x2b; 16]);
    let mut typist = Typist::default();
    let (ended, _, err) = scene.connect_as(Some(&nobody), &mut typist, &Progress::default());
    assert_eq!(ended, Ended::Status(FAILED));
    assert!(err.contains("No profile has that id"), "{err}");
    assert!(typist.asked.is_empty());
}

// `connect` takes `--profile <id>` and `--json`, each once, in either
// order. Anything else, an id that cannot be one included, is wrong usage.
#[test]
fn connect_takes_a_profile_and_json_in_either_order() {
    use crate::{Connecting, connect_args};
    let id = "1a".repeat(16);
    let lab = Some(id.parse::<ProfileId>().unwrap());
    let read = |args: &[&str]| connect_args(args);
    let plain = |profile: Option<ProfileId>, json| Some(Connecting { profile, json });
    assert_eq!(read(&["connect"]), plain(None, false));
    assert_eq!(read(&["connect", "--json"]), plain(None, true));
    assert_eq!(
        read(&["connect", "--profile", &id]),
        plain(lab.clone(), false)
    );
    let both = plain(lab, true);
    assert_eq!(read(&["connect", "--profile", &id, "--json"]), both);
    assert_eq!(read(&["connect", "--json", "--profile", &id]), both);
    for wrong in [
        &["connect", "--profile"][..],
        &["connect", "--profile", "lab"],
        &["connect", "--json", "--json"],
        &["connect", "--profile", &id, "--profile", &id],
        &["connect", "now"],
        &["status"],
    ] {
        assert_eq!(read(wrong), None, "{wrong:?}");
    }
}
