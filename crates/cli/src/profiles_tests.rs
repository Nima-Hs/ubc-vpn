//! The profiles commands, against folders made for each test and the fake
//! keyring of each test's thread. Names, usernames and passwords are made
//! up; no test here can reach the user's keyring (see `keys.rs`).

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use ubc_vpn_core::profiles::{
    FIRST_PROFILE_NAME, Keyring, ProfileFailure, ProfileFailureCode, ProfileId, Profiles,
    ProfilesView, StartMode,
};
use ubc_vpn_core::protocol::decode;
use ubc_vpn_core::redact::Secret;
use ubc_vpn_core::settings_cli::{LiveRoutes, ResetReply, RoutesReply, SettingsView};
use ubc_vpn_platform::fake::Fake;
use ubc_vpn_platform::secrets::{FakeSecrets, Saved};

use crate::keys;
use crate::profiles::{Command, run};

/// One user's machine: a policy, a settings folder, and the fake keyring.
struct Machine {
    root: PathBuf,
    said: std::cell::RefCell<String>,
}

impl Machine {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let unique = (std::process::id(), NEXT.fetch_add(1, Ordering::SeqCst));
        let root = std::env::temp_dir().join(format!("ubc-vpn-profiles-test-{unique:?}"));
        // A process ID comes round again, and with it this name: whatever
        // an earlier run left here goes first, or its settings would be
        // read as this test's.
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("policy")).unwrap();
        let pin = format!("pin-sha256:{}=", "A".repeat(43));
        let policy = format!(r#"{{"gateway":"vpn.example.test","pins":["{pin}"]}}"#);
        std::fs::write(root.join("policy/policy.json"), policy).unwrap();
        // Every test starts with an empty keyring.
        for (account, _) in keys::test::fake().entries() {
            keys::test::fake().secrets().forget(&account).unwrap();
        }
        let said = Default::default();
        Self { root, said }
    }

    fn settings_file(&self) -> PathBuf {
        self.root.join("settings/settings.json")
    }

    fn write_settings(&self, text: &str) {
        crate::tests::settings_folder(&self.root.join("settings"));
        std::fs::write(self.settings_file(), text).unwrap();
    }

    fn stored(&self) -> Profiles {
        let text = std::fs::read_to_string(self.settings_file()).unwrap();
        Profiles::read(Some(&text)).unwrap().profiles
    }

    /// Runs a command; returns the exit status and the one line it wrote.
    fn run(&self, command: Command, input: &str) -> (u8, String) {
        let platform = || Ok(Fake::new().platform(&self.root));
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let status = run(
            command,
            &platform,
            &mut input.as_bytes(),
            &mut out,
            &mut err,
        );
        *self.said.borrow_mut() = String::from_utf8(err).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.ends_with('\n') && out.lines().count() == 1, "{out:?}");
        (status, out)
    }

    fn list(&self) -> ProfilesView {
        let (status, line) = self.run(Command::List, "");
        assert_eq!(status, 0, "{line}");
        decode(&line).unwrap()
    }

    fn changed(&self, command: Command, input: &str) -> ProfilesView {
        let (status, line) = self.run(command, input);
        assert_eq!(status, 0, "{line}");
        decode(&line).unwrap()
    }

    fn refused(&self, command: Command, input: &str) -> ProfileFailureCode {
        let (status, line) = self.run(command, input);
        assert_eq!(status, 1, "{line}");
        decode::<ProfileFailure>(&line).unwrap().error
    }

    /// Runs `settings reset --json`, which must reset; returns whether the
    /// saved passwords were forgotten and where the old file went.
    fn reset(&self) -> (bool, String) {
        let platform = || Ok(Fake::new().platform(&self.root));
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let status = crate::settings::run(
            crate::settings::Command::Reset { force: false },
            &platform,
            &mut "".as_bytes(),
            &mut out,
            &mut err,
        );
        let line = String::from_utf8(out).unwrap();
        assert_eq!(status, 0, "{line}");
        match decode::<ResetReply>(&line).unwrap() {
            ResetReply::Reset {
                kept,
                passwords_forgotten,
            } => (passwords_forgotten, kept),
            ResetReply::NotNeeded => panic!("{line}"),
        }
    }

    /// Makes a profile and returns its id.
    fn create(&self, name: &str, username: &str) -> ProfileId {
        let input = format!(r#"{{"name":"{name}","username":"{username}","save_password":true}}"#);
        let view = self.changed(Command::Create, &input);
        let made = view
            .profiles
            .iter()
            .find(|p| p.profile.name == name)
            .unwrap();
        made.profile.id.clone()
    }
}

impl Drop for Machine {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn keyring() -> FakeSecrets {
    keys::test::fake()
}

/// Saves a made-up password for `id`, as a connect would.
fn save_password(id: &ProfileId, username: &str) {
    let saved = Saved {
        username: username.to_string(),
        password: Secret::new("made-up-pass-0001"),
        in_doubt: false,
    };
    keyring().secrets().save(id.as_str(), &saved).unwrap();
}

fn has_password(id: &ProfileId) -> bool {
    keyring().secrets().load(id.as_str()).unwrap().is_some()
}

#[test]
fn a_new_user_has_one_profile_and_nothing_saved() {
    let machine = Machine::new();
    let view = machine.list();
    assert_eq!(view.profiles.len(), 1);
    assert_eq!(view.profiles[0].profile.name, FIRST_PROFILE_NAME);
    assert!(!view.profiles[0].password_saved);
    assert_eq!(view.keyring, Keyring::Available);
    assert!(view.policy_readable);
    // Listing writes nothing.
    assert!(!machine.settings_file().exists());
}

#[test]
fn profiles_are_made_renamed_switched_and_shown() {
    let machine = Machine::new();
    let lab = machine.create("Lab", "user.lab@app");
    let view = machine.list();
    assert_eq!(view.profiles.len(), 2);
    assert_eq!(view.global.active_profile, ProfileId::first());
    assert_ne!(lab, ProfileId::first());
    machine.changed(Command::Switch, &format!(r#"{{"id":"{}"}}"#, lab.as_str()));
    machine.changed(
        Command::Rename,
        &format!(r#"{{"id":"{}","name":"Robotics"}}"#, lab.as_str()),
    );
    let stored = machine.stored();
    assert_eq!(stored.active().name, "Robotics");
    assert_eq!(stored.active().id, lab);
    // The file is version 2 now.
    let text = std::fs::read_to_string(machine.settings_file()).unwrap();
    assert!(text.contains("\"version\": 2"), "{text}");
    let startup = machine.changed(
        Command::SetStartup,
        r#"{"start":"tray","auto_connect":true}"#,
    );
    assert_eq!(
        (startup.global.start, startup.global.auto_connect),
        (StartMode::Tray, true)
    );
}

// A change the rules refuse says why, exits with status 1 and changes
// nothing; input that is not the command's is bad input.
#[test]
fn a_refused_change_changes_nothing() {
    let machine = Machine::new();
    let lab = machine.create("Lab", "user.lab@app");
    let before = std::fs::read_to_string(machine.settings_file()).unwrap();
    let refusals = [
        (
            Command::Create,
            r#"{"name":"lab"}"#.to_string(),
            ProfileFailureCode::NameTaken,
        ),
        (
            Command::Create,
            r#"{"name":"  "}"#.to_string(),
            ProfileFailureCode::BadName,
        ),
        (
            Command::Create,
            r#"{"name":"Home","username":"a\u001b[2Jb"}"#.to_string(),
            ProfileFailureCode::BadUsername,
        ),
        (
            Command::Rename,
            format!(r#"{{"id":"{}","name":"UBC VPN"}}"#, lab.as_str()),
            ProfileFailureCode::NameTaken,
        ),
        (
            Command::Switch,
            format!(r#"{{"id":"{}"}}"#, "9".repeat(32)),
            ProfileFailureCode::UnknownProfile,
        ),
        (
            Command::ForgetPassword,
            format!(r#"{{"id":"{}"}}"#, "9".repeat(32)),
            ProfileFailureCode::UnknownProfile,
        ),
    ];
    for (command, input, code) in refusals {
        assert_eq!(machine.refused(command, &input), code, "{input}");
    }
    let now = std::fs::read_to_string(machine.settings_file()).unwrap();
    assert_eq!(now, before);
    // Not the command's input, and something smuggled in: bad input.
    for input in ["", "not json", r#"{"name":"Lab 2","password":"made-up"}"#] {
        let (status, line) = machine.run(Command::Create, input);
        assert_eq!(
            (status, line.as_str()),
            (1, "{\"error\":\"bad_input\"}\n"),
            "{input}"
        );
    }
}

// Security rule: a password is never taken in through a profiles command,
// so none can end up in the settings file. Every change command's own
// input with a password added is bad input, and changes neither the file
// nor the keyring.
#[test]
fn no_change_command_takes_a_password() {
    let machine = Machine::new();
    let lab = machine.create("Lab", "user.lab@app");
    save_password(&lab, "user.lab@app");
    let id = format!(r#""id":"{}""#, lab.as_str());
    // In an order in which each, without the password, is taken.
    let inputs = [
        (
            Command::Create,
            r#""name":"Home","username":"user@app""#.to_string(),
        ),
        (Command::Rename, format!(r#"{id},"name":"Lab 2""#)),
        (
            Command::SetRoutes,
            format!(r#"{id},"subnets":["10.255.0.0/16"],"dns_domains":[]"#),
        ),
        (
            Command::SetStartup,
            r#""start":"tray","auto_connect":true"#.to_string(),
        ),
        (Command::Switch, id.clone()),
        (Command::Update, format!(r#"{id},"save_password":false"#)),
        (Command::ForgetPassword, id.clone()),
        (Command::Delete, id.clone()),
    ];
    for (command, fields) in inputs {
        // A saved password each time, which a change taken would forget.
        save_password(&lab, "user.lab@app");
        let before = std::fs::read_to_string(machine.settings_file()).unwrap();
        let saved = keyring().entries();
        let input = format!(r#"{{{fields},"password":"made-up-pass-0002"}}"#);
        let (status, line) = machine.run(command, &input);
        assert_eq!(
            (status, line.as_str()),
            (1, "{\"error\":\"bad_input\"}\n"),
            "{input}"
        );
        let now = std::fs::read_to_string(machine.settings_file()).unwrap();
        assert_eq!(now, before, "{input} changed the file");
        assert!(!now.contains("made-up-pass"), "{input}");
        assert_eq!(keyring().entries(), saved, "{input} changed the keyring");
        // The same input without the password is the command's own.
        let (status, line) = machine.run(command, &format!("{{{fields}}}"));
        assert_eq!(status, 0, "{fields}: {line}");
    }
}

// Security rule: a profile's saved password is forgotten when it is
// deleted, when it stops saving it, when its username changes, and when
// the user asks; a rename keeps it, since the id stays.
#[test]
fn saved_passwords_go_when_their_profile_says_so() {
    let machine = Machine::new();
    let lab = machine.create("Lab", "user.lab@app");
    let id = || format!(r#""id":"{}""#, lab.as_str());

    save_password(&lab, "user.lab@app");
    machine.changed(Command::Rename, &format!("{{{},\"name\":\"Lab 2\"}}", id()));
    assert!(has_password(&lab), "a rename forgot it");
    let view = machine.list();
    assert!(
        view.profiles
            .iter()
            .any(|p| p.profile.id == lab && p.password_saved)
    );
    // Updating nothing that matters keeps it.
    machine.changed(
        Command::Update,
        &format!("{{{},\"save_password\":true}}", id()),
    );
    assert!(has_password(&lab));

    machine.changed(
        Command::Update,
        &format!("{{{},\"username\":\"other@app\"}}", id()),
    );
    assert!(!has_password(&lab), "a new username kept it");

    save_password(&lab, "other@app");
    machine.changed(
        Command::Update,
        &format!("{{{},\"save_password\":false}}", id()),
    );
    assert!(!has_password(&lab), "saving turned off kept it");

    save_password(&lab, "other@app");
    let view = machine.changed(Command::ForgetPassword, &format!("{{{}}}", id()));
    assert!(!has_password(&lab), "forget kept it");
    assert!(view.profiles.iter().all(|p| !p.password_saved));

    save_password(&lab, "other@app");
    machine.changed(Command::Delete, &format!("{{{}}}", id()));
    assert!(!has_password(&lab), "a delete kept it");
    assert_eq!(keyring().entries(), [], "something was left in the keyring");
}

// `password forget` with no id forgets the active profile's.
#[test]
fn forgetting_without_an_id_forgets_the_active_profiles() {
    let machine = Machine::new();
    let first = ProfileId::first();
    machine.changed(
        Command::SetStartup,
        r#"{"start":"off","auto_connect":false}"#,
    );
    save_password(&first, "user@app");
    machine.changed(Command::ForgetPassword, "{}");
    assert!(!has_password(&first));
}

// Security rule: a reset forgets every password this product saved, those
// of profiles the settings no longer name included, and starts with a
// fresh profile whose id is not the fixed one.
#[test]
fn a_reset_forgets_every_saved_password() {
    let machine = Machine::new();
    let lab = machine.create("Lab", "user.lab@app");
    save_password(&lab, "user.lab@app");
    save_password(&ProfileId::first(), "user@app");
    // Left by settings that are gone.
    save_password(&ProfileId::from_random([7; 16]), "gone@app");
    machine.write_settings("not settings at all");
    assert_eq!(
        machine.reset(),
        (true, "settings.json.damaged-1".to_string())
    );
    assert_eq!(keyring().entries(), [], "a saved password was kept");
    let fresh = machine.stored();
    assert_eq!(fresh.profiles.len(), 1);
    assert_ne!(fresh.active().id, ProfileId::first());
}

// A reset whose keyring will not let a saved password go still resets the
// settings, and says the password may be left, for the user to remove.
#[test]
fn a_reset_says_when_saved_passwords_could_not_be_forgotten() {
    let machine = Machine::new();
    let lab = machine.create("Lab", "user.lab@app");
    save_password(&lab, "user.lab@app");
    keyring().fail_writes_to(lab.as_str(), true);
    machine.write_settings("not settings at all");
    let said = machine.reset();
    keyring().fail_writes_to(lab.as_str(), false);
    assert_eq!(said, (false, "settings.json.damaged-1".to_string()));
    assert!(has_password(&lab));
    assert_ne!(machine.stored().active().id, ProfileId::first());

    // With no keyring at all, it cannot be said that none is left either.
    save_password(&lab, "user.lab@app");
    machine.write_settings("not settings at all");
    keyring().set_unusable(true);
    let said = machine.reset();
    keyring().set_unusable(false);
    assert_eq!(said, (false, "settings.json.damaged-2".to_string()));
}

// Settings from before profiles keep their routes when first saved, and
// `settings get` still shows the active profile as it did.
#[test]
fn version_1_settings_are_kept_when_saved_as_version_2() {
    let machine = Machine::new();
    machine.write_settings(
        r#"{"username":"user.dept@app","routes":{"subnets":["10.255.0.0/16"],"dns_domains":["dept.example.test"]}}"#,
    );
    machine.create("Lab", "user.lab@app");
    let stored = machine.stored();
    let first = stored.profile(&ProfileId::first()).unwrap();
    assert_eq!(first.username.as_deref(), Some("user.dept@app"));
    assert_eq!(first.routes.subnets[0].to_string(), "10.255.0.0/16");
    let platform = || Ok(Fake::new().platform(&machine.root));
    let (mut out, mut err) = (Vec::new(), Vec::new());
    crate::settings::run(
        crate::settings::Command::Get,
        &platform,
        &mut "".as_bytes(),
        &mut out,
        &mut err,
    );
    let view: SettingsView = decode(&String::from_utf8(out).unwrap()).unwrap();
    assert_eq!(view.settings.username.as_deref(), Some("user.dept@app"));
}

// Security rule: a username today's rules refuse is cleared when read,
// said once on standard error, and its saved password forgotten at the
// next save, whichever command saves.
#[test]
fn a_cleaned_username_loses_its_saved_password() {
    let through_profiles = |machine: &Machine| {
        machine.changed(
            Command::SetStartup,
            r#"{"start":"window","auto_connect":false}"#,
        );
    };
    let through_settings = |machine: &Machine| {
        let platform = || Ok(Fake::new().platform(&machine.root));
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let status = crate::settings::run(
            crate::settings::Command::SetRoutes,
            &platform,
            &mut r#"{"subnets":["10.255.0.0/16"],"dns_domains":[]}"#.as_bytes(),
            &mut out,
            &mut err,
        );
        let line = String::from_utf8(out).unwrap();
        assert_eq!(status, 0, "{line}");
        assert!(
            matches!(decode(&line).unwrap(), RoutesReply::Ok { .. }),
            "{line}"
        );
    };
    let saves = [
        (
            "settings set-startup",
            &through_profiles as &dyn Fn(&Machine),
        ),
        ("settings set-routes", &through_settings),
    ];
    for (name, saving) in saves {
        let machine = Machine::new();
        machine.write_settings(r#"{"username":"user.dept@app\nsudo","save_password":true}"#);
        save_password(&ProfileId::first(), "user.dept@app");
        machine.list();
        assert!(
            machine.said.borrow().contains("could not be kept"),
            "{}",
            machine.said.borrow()
        );
        assert!(
            has_password(&ProfileId::first()),
            "a list changed the keyring"
        );
        saving(&machine);
        assert!(!has_password(&ProfileId::first()), "{name} kept it");
        assert_eq!(machine.stored().active().username, None, "{name}");
        machine.list();
        assert_eq!(*machine.said.borrow(), "", "said again once saved");
    }
}

// Security rule: a connect that saves a username the user typed, other
// than the profile's, forgets the password saved for the old one; saving
// the same username keeps it.
#[test]
fn a_new_username_from_a_connect_forgets_the_old_ones_password() {
    let machine = Machine::new();
    let dir = machine.root.join("settings");
    crate::tests::settings_folder(&dir);
    crate::settings::remember_username(&dir, None, &ProfileId::first(), Some("user@app")).unwrap();
    save_password(&ProfileId::first(), "user@app");
    crate::settings::remember_username(&dir, None, &ProfileId::first(), Some("user@app")).unwrap();
    assert!(
        has_password(&ProfileId::first()),
        "the same username forgot it"
    );
    crate::settings::remember_username(&dir, None, &ProfileId::first(), Some("other@app")).unwrap();
    assert!(!has_password(&ProfileId::first()), "a new username kept it");
}

// Routes set for a profile that is not active are saved and offered to no
// connection; for the active one they are, as `settings set-routes` does.
#[test]
fn routes_go_live_only_for_the_active_profile() {
    let machine = Machine::new();
    let lab = machine.create("Lab", "user.lab@app");
    let typed = |id: &str| format!(r#"{{{id}"subnets":["10.255.0.0/16"],"dns_domains":[]}}"#);
    let (status, line) = machine.run(
        Command::SetRoutes,
        &typed(&format!(r#""id":"{}","#, lab.as_str())),
    );
    assert_eq!(status, 0, "{line}");
    let RoutesReply::Ok { live, .. } = decode(&line).unwrap() else {
        panic!("{line}")
    };
    assert_eq!(live, None);
    assert_eq!(
        machine.stored().profile(&lab).unwrap().routes.subnets.len(),
        1
    );
    let (_, line) = machine.run(Command::SetRoutes, &typed(""));
    let RoutesReply::Ok { live, .. } = decode(&line).unwrap() else {
        panic!("{line}")
    };
    // No service here, so nothing is connected.
    assert_eq!(live, Some(LiveRoutes::NextConnect));
    // Routes with a problem are said, and nothing is saved.
    let (status, line) = machine.run(
        Command::SetRoutes,
        r#"{"subnets":["10.0.0.0/7"],"dns_domains":[]}"#,
    );
    assert_eq!(status, 0);
    assert!(
        matches!(decode(&line).unwrap(), RoutesReply::Invalid { .. }),
        "{line}"
    );
}

// A keyring that cannot be used is said to be one; the profiles still work.
#[test]
fn an_unusable_keyring_is_said_and_the_rest_works() {
    let machine = Machine::new();
    keyring().set_unusable(true);
    let view = machine.list();
    keyring().set_unusable(false);
    assert_eq!(view.keyring, Keyring::Unavailable);
    keyring().set_unusable(true);
    let lab = machine.create("Lab", "user.lab@app");
    keyring().set_unusable(false);
    assert!(machine.stored().profile(&lab).is_ok());
}

// Each command is reached from the command line the app runs, spelled
// exactly so, and does there what it does when called directly: here, with
// nothing typed, the same answer. Any other spelling is not it.
#[test]
fn every_command_line_reaches_its_command() {
    let spellings = [
        (&["profiles", "list", "--json"][..], Command::List),
        (&["profiles", "create", "--json"], Command::Create),
        (&["profiles", "rename", "--json"], Command::Rename),
        (&["profiles", "update", "--json"], Command::Update),
        (&["profiles", "delete", "--json"], Command::Delete),
        (&["profiles", "switch", "--json"], Command::Switch),
        (&["profile", "set-routes", "--json"], Command::SetRoutes),
        (&["password", "forget", "--json"], Command::ForgetPassword),
        (&["settings", "set-startup", "--json"], Command::SetStartup),
        (&["settings", "set-tunnel", "--json"], Command::SetTunnel),
    ];
    for (args, command) in spellings {
        assert_eq!(Command::parse(args), Some(command), "{args:?}");
        let machine = Machine::new();
        let direct = machine.run(command, "");
        let platform = || Ok(Fake::new().platform(&machine.root));
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let typed = crate::run_typed(args, &platform, &mut "".as_bytes(), &mut out, &mut err);
        let line = String::from_utf8(out).unwrap();
        assert_eq!(typed.map(|status| (status, line)), Some(direct), "{args:?}");
        // Without `--json`, or with more after it, it is none of them.
        assert_eq!(Command::parse(&args[..2]), None, "{args:?}");
        let more = [args, &["x"]].concat();
        assert_eq!(Command::parse(&more), None, "{args:?}");
    }
}
