//! The `settings` commands, against folders made for each test. The cases
//! are those listed in `ubc_vpn_core::settings_cli`.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use ubc_vpn_core::protocol::{MAX_LINE_BYTES, decode};
use ubc_vpn_core::settings_cli::{
    ResetReply, RouteProblemCode, RoutesReply, SettingsFailure, SettingsFailureCode, SettingsView,
};
use ubc_vpn_platform::Error;
use ubc_vpn_platform::fake::Fake;

use crate::settings::{
    Command, kept_notice, nowhere_to_keep, partial_name, place, remember_username, reset_with, run,
    sweep, write_partial,
};

const GOOD: &str =
    r#"{"subnets":["10.19.0.0/16","142.103.0.0/16"],"dns_domains":["ece.example.test"]}"#;

/// One user's machine: a policy folder and a settings folder, both empty.
struct Machine {
    root: PathBuf,
    /// What the last command wrote on standard error.
    said: std::cell::RefCell<String>,
}

impl Machine {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let unique = (std::process::id(), NEXT.fetch_add(1, Ordering::SeqCst));
        let root = std::env::temp_dir().join(format!("ubc-vpn-settings-test-{unique:?}"));
        std::fs::create_dir_all(&root).unwrap();
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

    fn write_policy(&self, text: &str) {
        std::fs::create_dir_all(self.root.join("policy")).unwrap();
        std::fs::write(self.root.join("policy/policy.json"), text).unwrap();
    }

    /// A valid policy, with `extra` fields appended.
    fn policy(&self, extra: &str) {
        let pin = format!("pin-sha256:{}=", "A".repeat(43));
        let text = format!(r#"{{"gateway":"vpn.example.test","pins":["{pin}"]{extra}}}"#);
        self.write_policy(&text);
    }

    /// Runs a command with `input` on standard input. Returns the exit
    /// status and what was written, which must be exactly one line.
    fn run(&self, command: Command, input: &str) -> (u8, String) {
        let platform = || Ok(Fake::new().platform(&self.root));
        let mut out = Vec::new();
        let mut err = Vec::new();
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

    fn view(&self) -> SettingsView {
        let (status, line) = self.run(Command::Get, "");
        assert_eq!(status, 0, "{line}");
        decode(&line).unwrap()
    }

    fn routes(&self, command: Command, input: &str) -> RoutesReply {
        let (status, line) = self.run(command, input);
        assert_eq!(status, 0, "{line}");
        decode(&line).unwrap()
    }

    /// Runs a command that must fail, and returns why.
    fn fails(&self, command: Command, input: &str) -> SettingsFailureCode {
        let (status, line) = self.run(command, input);
        assert_eq!(status, 1, "{line}");
        decode::<SettingsFailure>(&line).unwrap().error
    }
}

impl Drop for Machine {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn problems(reply: RoutesReply) -> Vec<RouteProblemCode> {
    match reply {
        RoutesReply::Invalid { problems } => problems.iter().map(|p| p.code).collect(),
        RoutesReply::Ok { .. } => panic!("the routes were accepted"),
    }
}

#[test]
fn only_the_three_spellings_are_commands() {
    assert_eq!(Command::parse(&["get", "--json"]), Some(Command::Get));
    let check = Command::parse(&["check-routes", "--json"]);
    assert_eq!(check, Some(Command::CheckRoutes));
    let set = Command::parse(&["set-routes", "--json"]);
    assert_eq!(set, Some(Command::SetRoutes));
    let reset = |force| Some(Command::Reset { force });
    assert_eq!(Command::parse(&["reset", "--json"]), reset(false));
    assert_eq!(Command::parse(&["reset", "--force", "--json"]), reset(true));
    for wrong in [
        &[][..],
        &["get"],
        &["get", "--json", "x"],
        &["set", "--json"],
        &["reset"],
        &["reset", "--force"],
        &["reset", "--json", "--force"],
        &["reset", "-f", "--json"],
    ] {
        assert_eq!(Command::parse(wrong), None, "{wrong:?}");
    }
}

// No settings file: `get` answers with the defaults, and `set-routes` makes
// the file and its folder.
#[test]
fn with_no_settings_file_get_gives_defaults_and_set_creates_it() {
    let machine = Machine::new();
    machine.policy("");
    let view = machine.view();
    assert_eq!(view.settings, Default::default());
    assert!(view.policy_readable);
    assert_eq!((view.min_prefix_len, view.max_routes), (8, 256));

    let saved = machine.routes(Command::SetRoutes, GOOD);
    let RoutesReply::Ok { routes } = saved else {
        panic!("{saved:?}");
    };
    assert_eq!(machine.view().settings.routes, routes);
    assert_eq!(routes.dns_domains, ["ece.example.test"]);
    assert!(!machine.root.join("settings/settings.json.tmp").exists());
}

// Saving routes changes the routes and nothing else in the file, including
// what this version does not know about. Checking them changes nothing.
#[test]
fn set_routes_replaces_the_routes_and_keeps_everything_else() {
    let machine = Machine::new();
    let before = r#"{"username":"jdoe","save_password":true,"theme":"dark","routes":{"subnets":["10.1.0.0/16"]}}"#;
    machine.write_settings(before);
    let checked = machine.routes(Command::CheckRoutes, GOOD);
    assert!(matches!(checked, RoutesReply::Ok { .. }));
    let untouched = std::fs::read_to_string(machine.settings_file()).unwrap();
    assert_eq!(untouched, before, "checking saves nothing");

    assert!(matches!(
        machine.routes(Command::SetRoutes, GOOD),
        RoutesReply::Ok { .. }
    ));
    let after: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(machine.settings_file()).unwrap()).unwrap();
    let expected = serde_json::json!({
        "username": "jdoe",
        "save_password": true,
        "theme": "dark",
        "routes": serde_json::from_str::<serde_json::Value>(GOOD).unwrap(),
    });
    assert_eq!(after, expected);
}

// Routes that do not pass are reported, with success as the exit status, and
// nothing is saved.
#[test]
fn routes_that_do_not_pass_are_reported_and_not_saved() {
    let machine = Machine::new();
    let before = r#"{"routes":{"subnets":["10.1.0.0/16"]}}"#;
    machine.write_settings(before);
    let typed = r#"{"subnets":["0.0.0.0/0","127.0.0.0/8","nonsense"],"dns_domains":["UPPER.example.test"]}"#;
    use RouteProblemCode::{BadDomain, BadSubnet, Reserved, TooWide};
    for command in [Command::CheckRoutes, Command::SetRoutes] {
        let found = problems(machine.routes(command, typed));
        assert_eq!(found, [TooWide, Reserved, BadSubnet, BadDomain]);
    }
    assert_eq!(
        std::fs::read_to_string(machine.settings_file()).unwrap(),
        before
    );
}

// The input is one line, no longer than the limit, and exactly a set of
// routes. Anything else is refused before any file is looked at.
#[test]
fn a_missing_long_or_undecodable_line_is_bad_input() {
    let machine = Machine::new();
    // Even an unreadable settings file is not what is reported.
    machine.write_settings("not json");
    let long = format!(
        r#"{{"subnets":["10.19.0.0/16"],"dns_domains":["{}"]}}"#,
        "a".repeat(MAX_LINE_BYTES)
    );
    let unknown_field =
        r#"{"subnets":["10.19.0.0/16"],"dns_domains":[],"gateway":"evil.example.test"}"#;
    let wrong = ["", "\n", "not json", "[]", unknown_field, &long, "\u{0}"];
    for command in [Command::CheckRoutes, Command::SetRoutes] {
        for input in wrong {
            let why = machine.fails(command, input);
            let shown = &input[..input.len().min(40)];
            assert_eq!(why, SettingsFailureCode::BadInput, "{command:?} {shown:?}");
        }
    }
    assert_eq!(
        std::fs::read_to_string(machine.settings_file()).unwrap(),
        "not json"
    );
}

// A settings file that is there but cannot be read or understood is left
// alone, and neither shown as defaults nor written over. A file that is not
// a JSON object counts, whatever the settings type would make of it.
#[test]
fn an_unreadable_settings_file_is_refused_and_left_alone() {
    let unreadable = [
        "",
        "not json",
        "[]",
        "null",
        "\"text\"",
        "7",
        r#"{"routes":{"subnets":["10.0.0.1/8"]}}"#,
    ];
    for text in unreadable {
        let machine = Machine::new();
        machine.write_settings(text);
        for command in [Command::Get, Command::SetRoutes] {
            let why = machine.fails(command, GOOD);
            assert_eq!(why, SettingsFailureCode::Unreadable, "{command:?} {text:?}");
        }
        assert_eq!(
            std::fs::read_to_string(machine.settings_file()).unwrap(),
            text
        );
        // Checking routes does not read the file, so it cannot fail this way.
        assert!(matches!(
            machine.routes(Command::CheckRoutes, GOOD),
            RoutesReply::Ok { .. }
        ));
    }
    // Something is there that is not a file at all.
    let machine = Machine::new();
    std::fs::create_dir_all(machine.settings_file()).unwrap();
    for command in [Command::Get, Command::SetRoutes] {
        assert_eq!(
            machine.fails(command, GOOD),
            SettingsFailureCode::Unreadable
        );
    }
}

// A missing or invalid policy fails nothing. `get` says it could not be
// read, and routes are then checked against everything but the allow-list.
#[test]
fn the_policy_limits_routes_only_when_it_can_be_read() {
    let machine = Machine::new();
    machine.policy(r#","allowed_routes":["142.103.0.0/16"]"#);
    let view = machine.view();
    assert!(view.policy_readable);
    assert_eq!(
        view.allowed_routes,
        Some(vec!["142.103.0.0/16".parse().unwrap()])
    );
    for command in [Command::CheckRoutes, Command::SetRoutes] {
        let found = problems(machine.routes(command, GOOD));
        assert_eq!(
            found,
            [RouteProblemCode::NotAllowed],
            "10.19.0.0/16 is outside"
        );
    }
    assert!(!machine.settings_file().exists());

    // No pins, not JSON, and no file at all.
    let no_pins = r#"{"gateway":"vpn.example.test","pins":[],"allowed_routes":["142.103.0.0/16"]}"#;
    for invalid in [Some(no_pins), Some("{"), None] {
        let machine = Machine::new();
        if let Some(text) = invalid {
            machine.write_policy(text);
        }
        let view = machine.view();
        assert!(!view.policy_readable, "{invalid:?}");
        assert_eq!(view.allowed_routes, None);
        assert!(matches!(
            machine.routes(Command::SetRoutes, GOOD),
            RoutesReply::Ok { .. }
        ));
    }
}

/// The partial files in the machine's settings folder.
fn partials(machine: &Machine) -> Vec<String> {
    let entries = std::fs::read_dir(machine.root.join("settings")).unwrap();
    let names = entries.map(|entry| entry.unwrap().file_name().into_string().unwrap());
    names.filter(|name| name.ends_with(".tmp")).collect()
}

// When saving fails the old file is exactly as it was, and nothing is left
// beside it.
#[test]
fn a_failed_save_leaves_the_old_file_unchanged() {
    let machine = Machine::new();
    let before = r#"{"username":"jdoe"}"#;
    machine.write_settings(before);
    let dir = machine.root.join("settings");
    // Every name the save tries is taken, by a file that is another's.
    std::fs::write(dir.join("taken"), "theirs").unwrap();
    let mut tried = 0;
    let mut taken = || {
        tried += 1;
        assert!(tried < 100, "the save never gives up");
        "taken".to_string()
    };
    let failed = write_partial(&dir, "new", &mut taken).unwrap_err();
    assert_eq!(failed.kind(), std::io::ErrorKind::AlreadyExists);
    assert!(
        (2..10).contains(&tried),
        "tried {tried} names, then gave up"
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("taken")).unwrap(),
        "theirs"
    );
    let untouched = std::fs::read_to_string(machine.settings_file()).unwrap();
    assert_eq!(untouched, before);
    // A partial file that cannot be put in place does not stay.
    let partial = write_partial(&dir, "new", &mut || "mine.tmp".to_string()).unwrap();
    std::fs::remove_file(machine.settings_file()).unwrap();
    std::fs::create_dir_all(machine.settings_file().join("in the way")).unwrap();
    assert!(place(&partial, &dir).is_err());
    assert!(partials(&machine).is_empty());
}

// A folder at the name a save would use is in the way like any file, and
// the save uses another name.
#[test]
fn a_folder_at_the_partial_files_name_is_passed_over() {
    let machine = Machine::new();
    machine.write_settings("{}");
    let dir = machine.root.join("settings");
    std::fs::create_dir(dir.join("first.tmp")).unwrap();
    let mut names = ["first.tmp", "second.tmp"].into_iter();
    let mut name = || names.next().unwrap().to_string();
    let partial = write_partial(&dir, "new", &mut name).unwrap();
    assert_eq!(partial, dir.join("second.tmp"));
    assert!(dir.join("first.tmp").is_dir());
}

// A partial file dated in the future is not old, whatever the clock did,
// and is left alone.
#[test]
fn a_partial_file_from_the_future_is_not_swept() {
    let machine = Machine::new();
    machine.write_settings("{}");
    let dir = machine.root.join("settings");
    let later = dir.join("settings.json.1-2-0000abcd.tmp");
    std::fs::write(&later, "theirs").unwrap();
    let ahead = std::time::SystemTime::now() + std::time::Duration::from_secs(2 * 3600);
    let file = std::fs::File::options().write(true).open(&later).unwrap();
    file.set_modified(ahead).unwrap();
    drop(file);
    assert!(matches!(
        machine.routes(Command::SetRoutes, GOOD),
        RoutesReply::Ok { .. }
    ));
    sweep(&dir, std::time::Duration::ZERO);
    assert_eq!(std::fs::read_to_string(&later).unwrap(), "theirs");
}

// An old partial file that cannot be removed is left, and the save goes on
// as if it were not there.
#[test]
fn a_partial_file_that_cannot_be_removed_is_no_obstacle() {
    let machine = Machine::new();
    machine.write_settings("{}");
    let dir = machine.root.join("settings");
    let stuck = dir.join("settings.json.tmp");
    std::fs::write(&stuck, "half a file").unwrap();
    let long_ago = std::time::SystemTime::now() - std::time::Duration::from_secs(2 * 3600);
    let file = std::fs::File::options().write(true).open(&stuck).unwrap();
    file.set_modified(long_ago).unwrap();
    drop(file);
    // How a file is made impossible to remove differs. On Windows a file
    // that someone holds open without sharing its removal cannot be
    // removed, and the save still has its folder.
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // Shared for reading and writing, and not for deleting.
        let (read, write) = (1, 2);
        let mut held = std::fs::File::options();
        let held = held.read(true).share_mode(read | write).open(&stuck);
        let held = held.unwrap();
        let saved = machine.routes(Command::SetRoutes, GOOD);
        let left = stuck.exists();
        drop(held);
        assert!(matches!(saved, RoutesReply::Ok { .. }));
        assert!(left, "the file that could not be removed is still there");
    }
    // Elsewhere nothing in a read-only folder can be removed, and nothing
    // saved there either, so only the sweep is run. Root can remove it all
    // the same; then there is nothing to see.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |mode| std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode));
        mode(0o500).unwrap();
        let root = std::fs::write(dir.join("probe"), "").is_ok();
        sweep(&dir, std::time::Duration::ZERO);
        let left = stuck.exists();
        mode(0o700).unwrap();
        assert!(
            left || root,
            "the file that could not be removed is still there"
        );
    }
}

// Two saves at once each write a file of their own, so neither can put the
// other's half-written file in place, and both succeed.
#[test]
fn two_saves_at_once_do_not_touch_each_others_files() {
    let machine = Machine::new();
    machine.write_settings("{}");
    let dir = machine.root.join("settings");
    let first = write_partial(&dir, "first", &mut partial_name).unwrap();
    let second = write_partial(&dir, "second", &mut partial_name).unwrap();
    assert_ne!(first, second);
    assert_eq!(std::fs::read_to_string(&first).unwrap(), "first");
    place(&second, &dir).unwrap();
    place(&first, &dir).unwrap();
    assert_eq!(
        std::fs::read_to_string(machine.settings_file()).unwrap(),
        "first"
    );
    assert!(partials(&machine).is_empty());

    // Through the command: a save in progress beside it is no obstacle and
    // is left alone, and the command leaves nothing of its own behind.
    let theirs = write_partial(&dir, "theirs", &mut partial_name).unwrap();
    machine.write_settings("{}");
    assert!(matches!(
        machine.routes(Command::SetRoutes, GOOD),
        RoutesReply::Ok { .. }
    ));
    assert_eq!(std::fs::read_to_string(&theirs).unwrap(), "theirs");
    assert_eq!(partials(&machine).len(), 1);
}

// What a save that was cut short left behind does not stay for ever: the
// next save removes it once it is old. The name an older version used
// counts too. Nothing else is removed: not a file with another name, not a
// link, not a folder, and not a partial file that is still fresh.
#[test]
fn only_old_partial_files_are_swept_away() {
    let machine = Machine::new();
    machine.write_settings("{}");
    let dir = machine.root.join("settings");
    let long_ago = std::time::SystemTime::now() - std::time::Duration::from_secs(2 * 3600);
    let aged = |name: &str| {
        std::fs::write(dir.join(name), "half a file").unwrap();
        let file = std::fs::File::options().write(true).open(dir.join(name));
        file.unwrap().set_modified(long_ago).unwrap();
    };
    let ours = partial_name();
    for swept in ["settings.json.tmp", "settings.json.1-2-0000abcd.tmp", &ours] {
        aged(swept);
    }
    let mut kept = vec![
        "notes.tmp",
        "settings.json.backup.tmp",
        "settings.json.1-2-0000abcd.tmp.tmp",
        "settings.json.1-2-abcd.tmp",
        "settings.json.1-x-0000abcd.tmp",
        "settings.json.1-2-0000abcd-4.tmp",
        "xsettings.json.tmp",
    ];
    for name in &kept {
        aged(name);
    }
    // A folder with a partial file's name, as old as the rest.
    std::fs::create_dir(dir.join("settings.json.3-4-0000abcd.tmp")).unwrap();
    kept.push("settings.json.3-4-0000abcd.tmp");
    // A link with one, to a file that is old too. Where links cannot be
    // made the rest of the test still runs.
    let target = machine.root.join("someone-elses-file");
    std::fs::write(&target, "precious").unwrap();
    let file = std::fs::File::options().write(true).open(&target).unwrap();
    file.set_modified(long_ago).unwrap();
    drop(file);
    if link_to_file(&target, &dir.join("settings.json.5-6-0000abcd.tmp")).is_ok() {
        kept.push("settings.json.5-6-0000abcd.tmp");
    }
    // Fresh: it may be a save in progress.
    std::fs::write(dir.join("settings.json.7-8-0000abcd.tmp"), "theirs").unwrap();
    kept.push("settings.json.7-8-0000abcd.tmp");

    assert!(matches!(
        machine.routes(Command::SetRoutes, GOOD),
        RoutesReply::Ok { .. }
    ));
    let (mut left, mut kept) = (partials(&machine), kept);
    left.sort();
    kept.sort();
    assert_eq!(left, kept);

    // A link cannot be given an old date here, so the same again with
    // everything counted as old: the link and the folder are still not
    // removed, and what the link points at is untouched.
    std::thread::sleep(std::time::Duration::from_millis(50));
    sweep(&dir, std::time::Duration::ZERO);
    let (mut left, fresh) = (partials(&machine), "settings.json.7-8-0000abcd.tmp");
    left.sort();
    kept.retain(|name| *name != fresh);
    assert_eq!(left, kept);
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "precious");
}

// A save that fails after the file was read is reported as unwritable, and
// the old file is as it was. The folder is made read-only for the save.
#[cfg(unix)]
#[test]
fn a_folder_that_cannot_be_written_to_is_unwritable() {
    use std::os::unix::fs::PermissionsExt;

    let machine = Machine::new();
    let before = r#"{"username":"jdoe"}"#;
    machine.write_settings(before);
    let dir = machine.root.join("settings");
    let mode = |mode| std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode));
    mode(0o500).unwrap();
    if std::fs::write(dir.join("probe"), "").is_ok() {
        // Root writes where it likes. Said past the capture, so a log shows it.
        mode(0o700).unwrap();
        let skipped = "SKIPPED a_folder_that_cannot_be_written_to_is_unwritable: run as root\n";
        std::io::Write::write_all(&mut std::io::stderr(), skipped.as_bytes()).unwrap();
        return;
    }
    let why = machine.fails(Command::SetRoutes, GOOD);
    mode(0o700).unwrap();
    assert_eq!(why, SettingsFailureCode::Unwritable);
    let untouched = std::fs::read_to_string(machine.settings_file()).unwrap();
    assert_eq!(untouched, before);
    assert!(partials(&machine).is_empty());
}

// A system with nowhere to keep files has no settings to show or to save,
// but routes can still be checked.
#[test]
fn without_a_platform_only_checking_works() {
    let machine = Machine::new();
    let nowhere = || Err(Error::Unsupported);
    let status = |command: Command| {
        let mut out = Vec::new();
        let status = run(
            command,
            &nowhere,
            &mut GOOD.as_bytes(),
            &mut out,
            &mut Vec::new(),
        );
        (status, String::from_utf8(out).unwrap())
    };
    assert_eq!(
        status(Command::Get),
        (1, "{\"error\":\"unreadable\"}\n".to_string())
    );
    assert_eq!(
        status(Command::SetRoutes),
        (1, "{\"error\":\"unwritable\"}\n".to_string())
    );
    assert_eq!(status(Command::CheckRoutes).0, 0);
    let reset = Command::Reset { force: true };
    assert_eq!(
        status(reset),
        (1, "{\"error\":\"unwritable\"}\n".to_string())
    );
    drop(machine);
}

// Security rule: the settings file is the user's alone. It is created
// readable and writable by the user and nobody else, whatever it was before.
#[cfg(unix)]
#[test]
fn the_saved_file_is_private_to_the_user() {
    use std::os::unix::fs::PermissionsExt;

    let machine = Machine::new();
    machine.write_settings("{}");
    let open_to_all = std::fs::Permissions::from_mode(0o666);
    std::fs::set_permissions(machine.settings_file(), open_to_all).unwrap();
    assert!(matches!(
        machine.routes(Command::SetRoutes, GOOD),
        RoutesReply::Ok { .. }
    ));
    let mode = std::fs::metadata(machine.settings_file())
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}

/// Makes `link` a symbolic link to the file `target`, where the OS and the
/// user's rights allow it.
fn link_to_file(target: &std::path::Path, link: &std::path::Path) -> std::io::Result<()> {
    #[cfg(unix)]
    return std::os::unix::fs::symlink(target, link);
    #[cfg(windows)]
    return std::os::windows::fs::symlink_file(target, link);
}

// Security rule: the settings are never written through a link. A link at
// the name a save would use is left alone, what it points at is untouched,
// and the save uses another name.
#[test]
fn settings_are_never_written_through_a_link() {
    let machine = Machine::new();
    machine.write_settings("{}");
    let dir = machine.root.join("settings");
    let target = machine.root.join("someone-elses-file");
    std::fs::write(&target, "precious").unwrap();
    if let Err(error) = link_to_file(&target, &dir.join("first.tmp")) {
        // Windows lets only an admin, or anyone in Developer Mode, make one.
        // Written past the test harness's capture, so that a CI log shows
        // whether this test ran or not.
        let skipped = format!("SKIPPED settings_are_never_written_through_a_link: {error}\n");
        std::io::Write::write_all(&mut std::io::stderr(), skipped.as_bytes()).unwrap();
        return;
    }
    let mut names = ["first.tmp", "second.tmp"].into_iter();
    let mut name = || names.next().unwrap().to_string();
    let partial = write_partial(&dir, "new", &mut name).unwrap();
    assert_eq!(partial, dir.join("second.tmp"));
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "precious");
    place(&partial, &dir).unwrap();
    let saved = std::fs::symlink_metadata(machine.settings_file()).unwrap();
    assert!(saved.is_file());
}

// An endless line on standard input cannot fill memory: reading stops just
// past the limit and the input is refused.
#[test]
fn no_more_than_the_limit_is_read_from_standard_input() {
    struct Endless(usize);
    impl std::io::Read for Endless {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = buf.len().min(10 * MAX_LINE_BYTES - self.0);
            buf[..n].fill(b'x');
            self.0 += n;
            Ok(n)
        }
    }
    let machine = Machine::new();
    let platform = || Ok(Fake::new().platform(&machine.root));
    let mut input = std::io::BufReader::new(Endless(0));
    let mut out = Vec::new();
    let status = run(
        Command::CheckRoutes,
        &platform,
        &mut input,
        &mut out,
        &mut Vec::new(),
    );
    assert_eq!(status, 1);
    assert_eq!(out, b"{\"error\":\"bad_input\"}\n");
    let taken = input.get_ref().0;
    assert!(taken <= 2 * MAX_LINE_BYTES, "{taken} bytes were read");
}

/// A set of routes whose input line, newline included, is `bytes` long:
/// one subnet and 256 domains, the last ones shortened to fit.
fn routes_filling(bytes: usize) -> String {
    // A valid name exactly `len` bytes long: labels of at most 63, then
    // `.test`.
    let domain = |len: usize| {
        let (whole, rest) = ((len - 5) / 63, (len - 5) % 63);
        let mut labels = vec!["a".repeat(62); whole];
        match rest {
            0 => labels[0].push('a'),
            rest => labels.push("b".repeat(rest)),
        }
        labels.join(".") + ".test"
    };
    let line = |lengths: &[usize]| {
        let domains: Vec<String> = lengths
            .iter()
            .map(|len| format!("\"{}\"", domain(*len)))
            .collect();
        format!(
            r#"{{"subnets":["10.19.0.0/16"],"dns_domains":[{}]}}"#,
            domains.join(",")
        )
    };
    let mut lengths = vec![253; 256];
    let mut spare = line(&lengths).len() + 1 - bytes;
    for len in lengths.iter_mut().rev() {
        let cut = spare.min(*len - 20);
        (*len, spare) = (*len - cut, spare - cut);
    }
    let made = line(&lengths);
    assert_eq!(made.len() + 1, bytes);
    made
}

// Security rule: a save is never reported as a failure, and nothing that
// `set-routes` accepts can leave `get` unable to answer. Routes that fit
// in the input line but whose reply or settings would not fit in a line are
// refused as bad input, with the file untouched.
#[test]
fn routes_too_long_to_report_are_refused_before_anything_is_saved() {
    // A field this version does not know, so that the settings are otherwise
    // the defaults and both commands judge the same length.
    let before = r#"{"theme":"dark"}"#;
    // From an input of exactly the limit downwards, to the first that fits.
    let sizes = (0..40).map(|step| MAX_LINE_BYTES - step * 16);
    let mut refused = 0;
    for size in sizes {
        let machine = Machine::new();
        machine.write_settings(before);
        let typed = routes_filling(size);
        let (status, line) = machine.run(Command::SetRoutes, &typed);
        let (check_status, check_line) = machine.run(Command::CheckRoutes, &typed);
        assert_eq!(
            (check_status, &check_line),
            (status, &line),
            "{size}: the two agree"
        );
        // Whatever was answered, the settings can still be shown.
        let view = machine.view();
        if status == 1 {
            assert_eq!(line, "{\"error\":\"bad_input\"}\n", "{size}");
            let untouched = std::fs::read_to_string(machine.settings_file()).unwrap();
            assert_eq!(untouched, before, "{size}: nothing was saved");
            refused += 1;
            continue;
        }
        assert_eq!(view.settings.routes.dns_domains.len(), 256, "{size}: saved");
        assert!(refused > 0, "an input of exactly the limit must not fit");
        return;
    }
    panic!("no size was accepted");
}

// Security rule: `set-routes` reckons with the settings that are stored,
// not with defaults. With a long username already in the file, routes that
// `check-routes` accepts can be too long to show beside it; saving them
// would leave `get` unable to answer, so they are refused and nothing is
// saved.
#[test]
fn set_routes_reckons_with_what_is_already_stored() {
    let machine = Machine::new();
    let before = format!(r#"{{"username":"{}"}}"#, "u".repeat(1000));
    machine.write_settings(&before);
    // The longest routes `check-routes` accepts: they fit, but only just.
    let sizes = (0..40).map(|step| MAX_LINE_BYTES - step * 16);
    let fitting = sizes.map(routes_filling).find(|typed| {
        let (status, _) = machine.run(Command::CheckRoutes, typed);
        status == 0
    });
    let typed = fitting.expect("some size is accepted");
    assert!(matches!(
        machine.routes(Command::CheckRoutes, &typed),
        RoutesReply::Ok { .. }
    ));

    let why = machine.fails(Command::SetRoutes, &typed);
    assert_eq!(why, SettingsFailureCode::BadInput);
    let untouched = std::fs::read_to_string(machine.settings_file()).unwrap();
    assert_eq!(untouched, before, "nothing was saved");
    assert_eq!(
        machine.view().settings.username.map(|name| name.len()),
        Some(1000)
    );

    // A file already too long for `get` to show is unreadable to both.
    let huge = format!(r#"{{"username":"{}"}}"#, "u".repeat(MAX_LINE_BYTES));
    machine.write_settings(&huge);
    for command in [Command::Get, Command::SetRoutes] {
        assert_eq!(
            machine.fails(command, GOOD),
            SettingsFailureCode::Unreadable
        );
    }
    assert_eq!(
        std::fs::read_to_string(machine.settings_file()).unwrap(),
        huge
    );
}

// A file that is too long to show because of its own routes is repaired by
// saving shorter ones. One that is too long for another reason is not: it
// stays unreadable, and is left as it is.
#[test]
fn routes_that_are_too_long_can_be_replaced_by_shorter_ones() {
    let machine = Machine::new();
    let long = format!(
        r#"{{"username":"jdoe","routes":{}}}"#,
        routes_filling(MAX_LINE_BYTES)
    );
    machine.write_settings(&long);
    assert_eq!(
        machine.fails(Command::Get, ""),
        SettingsFailureCode::Unreadable
    );
    assert!(matches!(
        machine.routes(Command::SetRoutes, GOOD),
        RoutesReply::Ok { .. }
    ));
    let view = machine.view();
    assert_eq!(view.settings.username.as_deref(), Some("jdoe"));
    assert_eq!(view.settings.routes.dns_domains.len(), 1);

    let long = format!(r#"{{"username":"{}"}}"#, "u".repeat(MAX_LINE_BYTES));
    machine.write_settings(&long);
    let why = machine.fails(Command::SetRoutes, GOOD);
    assert_eq!(why, SettingsFailureCode::Unreadable);
    assert_eq!(
        std::fs::read_to_string(machine.settings_file()).unwrap(),
        long
    );
}

// Security rule: nothing a connect saves can leave `get` unable to answer.
// Beside routes that only just fit, a username that would not is not saved.
#[test]
fn a_username_that_would_not_fit_beside_the_routes_is_not_saved() {
    let machine = Machine::new();
    let dir = machine.root.join("settings");
    // The longest routes `get` can still show.
    let sizes = (0..40).map(|step| MAX_LINE_BYTES - step * 16);
    let fitting = sizes.map(routes_filling).find(|routes| {
        machine.write_settings(&format!(r#"{{"routes":{routes}}}"#));
        machine.run(Command::Get, "").0 == 0
    });
    assert!(fitting.is_some(), "some size can be shown");
    let before = std::fs::read_to_string(machine.settings_file()).unwrap();
    let long = "u".repeat(200);
    let refused = remember_username(&dir, None, Some(&long));
    assert_eq!(refused, Err(SettingsFailureCode::BadInput));
    let untouched = std::fs::read_to_string(machine.settings_file()).unwrap();
    assert_eq!(untouched, before);
    assert_eq!(machine.run(Command::Get, "").0, 0);
    // Forgetting never makes a file longer, so it always goes through.
    assert_eq!(remember_username(&dir, None, None), Ok(()));
}

// Security rule: the settings folder is the user's alone. One this program
// makes is made that way, whatever the umask.
#[cfg(unix)]
#[test]
fn the_settings_folder_is_made_for_the_user_alone() {
    use std::os::unix::fs::PermissionsExt;

    let machine = Machine::new();
    let dir = machine.root.join("settings");
    assert!(!dir.exists());
    assert!(matches!(
        machine.routes(Command::SetRoutes, GOOD),
        RoutesReply::Ok { .. }
    ));
    let mode = std::fs::metadata(&dir).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o700);
}

// Security rule: a settings folder that others can write to is not used,
// to read or to save, and the user is told why. Whoever can write there can
// replace the settings, and with them the routes of the next connect.
#[cfg(unix)]
#[test]
fn a_settings_folder_others_can_write_to_is_refused() {
    use std::os::unix::fs::PermissionsExt;

    let machine = Machine::new();
    let before = r#"{"username":"jdoe"}"#;
    machine.write_settings(before);
    let dir = machine.root.join("settings");
    let mode = |mode| std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode));
    for open in [0o720, 0o702, 0o777] {
        mode(open).unwrap();
        for command in [Command::Get, Command::SetRoutes] {
            let why = machine.fails(command, GOOD);
            assert_eq!(why, SettingsFailureCode::Unreadable, "{open:o}");
            let said = machine.said.borrow().clone();
            assert!(said.contains("can be changed by other users"), "{said}");
            let fix = format!("To stop them, run: chmod go-w '{}'\n", dir.display());
            assert!(said.ends_with(&fix), "{said}");
        }
        // Checking routes reads no file, and has nothing to say about it.
        assert_eq!(machine.run(Command::CheckRoutes, GOOD).0, 0);
        assert_eq!(*machine.said.borrow(), "");
    }
    let untouched = std::fs::read_to_string(machine.settings_file()).unwrap();
    assert_eq!(untouched, before);

    // Others may read it; that is not the rule.
    mode(0o755).unwrap();
    assert_eq!(machine.view().settings.username.as_deref(), Some("jdoe"));
    assert!(matches!(
        machine.routes(Command::SetRoutes, GOOD),
        RoutesReply::Ok { .. }
    ));
    assert_eq!(*machine.said.borrow(), "");
}

// Security rule: a settings folder that is a link is judged by where it
// leads, since that is the folder that is used: a link to a folder others
// can write to is refused, and a link to the user's own is not.
#[cfg(unix)]
#[test]
fn a_settings_folder_that_is_a_link_is_judged_by_where_it_leads() {
    use std::os::unix::fs::PermissionsExt;

    let machine = Machine::new();
    let real = machine.root.join("elsewhere");
    crate::tests::settings_folder(&real);
    std::fs::write(real.join("settings.json"), r#"{"username":"jdoe"}"#).unwrap();
    std::os::unix::fs::symlink(&real, machine.root.join("settings")).unwrap();
    assert_eq!(machine.view().settings.username.as_deref(), Some("jdoe"));
    assert!(matches!(
        machine.routes(Command::SetRoutes, GOOD),
        RoutesReply::Ok { .. }
    ));

    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o770)).unwrap();
    for command in [Command::Get, Command::SetRoutes] {
        let why = machine.fails(command, GOOD);
        assert_eq!(why, SettingsFailureCode::Unreadable);
        assert!(machine.said.borrow().contains("chmod go-w"));
    }
}

// The command the user is given can be pasted into a shell whatever the
// folder is called.
#[cfg(unix)]
#[test]
fn the_fix_is_quoted_for_a_shell() {
    use std::os::unix::fs::PermissionsExt;

    let root = std::env::temp_dir().join(format!("ubc-vpn it's $HOME {}", std::process::id()));
    let dir = root.join("settings");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o770)).unwrap();
    let said = crate::settings::folder_problem(&dir);
    std::fs::remove_dir_all(&root).unwrap();
    let quoted = dir.display().to_string().replace('\'', r"'\''");
    let fix = format!("To stop them, run: chmod go-w '{quoted}'");
    assert!(said.is_some_and(|said| said.ends_with(&fix)));
    assert!(fix.contains(r"it'\''s $HOME"), "{fix}");
}

const RESET: Command = Command::Reset { force: false };
const RESET_ALL: Command = Command::Reset { force: true };

impl Machine {
    fn reset(&self, command: Command) -> ResetReply {
        let (status, line) = self.run(command, "");
        assert_eq!(status, 0, "{line}");
        decode(&line).unwrap()
    }

    fn kept(&self, n: usize) -> PathBuf {
        let name = format!("settings/settings.json.damaged-{n}");
        self.root.join(name)
    }
}

fn was_reset(n: usize) -> ResetReply {
    let kept = format!("settings.json.damaged-{n}");
    ResetReply::Reset { kept }
}

// A settings file that cannot be read is the user's dead end without this:
// `reset` puts it aside, whole, and the settings are the defaults again.
#[test]
fn a_damaged_file_is_put_aside_and_the_settings_start_afresh() {
    let too_long = format!(r#"{{"routes":{}}}"#, routes_filling(MAX_LINE_BYTES));
    let damaged: [&[u8]; 5] = [
        b"not json",
        b"[]",
        br#"{"save_password":"yes"}"#,
        b"\xff\xfe not text",
        too_long.as_bytes(),
    ];
    for bytes in damaged {
        let machine = Machine::new();
        machine.write_settings("");
        std::fs::write(machine.settings_file(), bytes).unwrap();
        assert_eq!(
            machine.fails(Command::Get, ""),
            SettingsFailureCode::Unreadable
        );

        assert_eq!(machine.reset(RESET), was_reset(1));
        assert_eq!(std::fs::read(machine.kept(1)).unwrap(), bytes);
        assert_eq!(machine.view().settings, Default::default());
        let fresh = std::fs::read_to_string(machine.settings_file()).unwrap();
        assert_eq!(fresh, "{}\n");
        // And they can be used again.
        assert!(matches!(
            machine.routes(Command::SetRoutes, GOOD),
            RoutesReply::Ok { .. }
        ));
    }
}

// Security rule: `reset` cannot be used to wipe good settings by accident,
// or by a part of the app that should not be able to. A file that can be
// read is left exactly as it is, unless the command says otherwise; and
// even then the old file is kept.
#[test]
fn settings_that_can_be_read_are_not_reset_unless_told_to() {
    let machine = Machine::new();
    let good = r#"{"username":"jdoe","theme":"dark"}"#;
    machine.write_settings(good);
    assert_eq!(machine.reset(RESET), ResetReply::NotNeeded);
    assert_eq!(
        std::fs::read_to_string(machine.settings_file()).unwrap(),
        good
    );
    assert!(!machine.kept(1).exists());

    assert_eq!(machine.reset(RESET_ALL), was_reset(1));
    assert_eq!(std::fs::read_to_string(machine.kept(1)).unwrap(), good);
    assert_eq!(machine.view().settings.username, None);

    // With no file there is nothing to reset and nothing is made.
    let machine = Machine::new();
    for command in [RESET, RESET_ALL] {
        assert_eq!(machine.reset(command), ResetReply::NotNeeded);
    }
    assert!(!machine.root.join("settings").exists());
}

// Security rule: a reset never destroys settings, however often it is
// asked. Old files go to the lowest free name and are never replaced: with
// every name taken a reset changes nothing, fails, and says what to do.
// So the good settings a forced reset put aside are still there, byte for
// byte, after any number of further resets.
#[test]
fn no_number_of_resets_replaces_a_kept_file() {
    let machine = Machine::new();
    let good = r#"{"username":"jdoe","theme":"dark"}"#;
    machine.write_settings(good);
    let kept = |n: usize| std::fs::read_to_string(machine.kept(n)).unwrap();
    assert_eq!(machine.reset(RESET_ALL), was_reset(1));
    assert_eq!(machine.reset(RESET_ALL), was_reset(2));
    machine.write_settings("damaged, the third time");
    // With a name still free, a reset that failed would have another cause,
    // and the sentence about the kept files would be the wrong one.
    assert_eq!(nowhere_to_keep(&machine.root.join("settings")), None);
    assert_eq!(machine.reset(RESET), was_reset(3));
    assert_eq!(*machine.said.borrow(), "");
    assert!(nowhere_to_keep(&machine.root.join("settings")).is_some());

    // Every name is taken. Forced or not, damaged or not: nothing changes.
    for (command, now) in [(RESET_ALL, "{}\n"), (RESET, "damaged, the fourth time")] {
        std::fs::write(machine.settings_file(), now).unwrap();
        for _ in 0..3 {
            assert_eq!(machine.fails(command, ""), SettingsFailureCode::Unwritable);
            let said = machine.said.borrow().clone();
            assert!(said.starts_with("ubc-vpn: Nothing was reset."), "{said}");
            assert!(said.contains("settings.json.damaged-1 to settings.json.damaged-3"));
            assert!(said.ends_with("then reset again.\n"), "{said}");
        }
        assert_eq!(
            std::fs::read_to_string(machine.settings_file()).unwrap(),
            now
        );
        let all = [kept(1), kept(2), kept(3)];
        assert_eq!(all, [good, "{}\n", "damaged, the third time"]);
        assert!(!machine.kept(4).exists(), "three are kept, and no more");
    }

    // A name the user freed is used again, and the others are left alone.
    std::fs::remove_file(machine.kept(2)).unwrap();
    assert_eq!(machine.reset(RESET), was_reset(2));
    assert_eq!(*machine.said.borrow(), "");
    assert_eq!(
        (kept(1), kept(2)),
        (good.to_string(), "damaged, the fourth time".to_string())
    );

    // A folder at a name takes it like any file. And the sweep of old
    // partial files, which the save below runs, removes none of these.
    std::fs::remove_file(machine.kept(2)).unwrap();
    std::fs::create_dir(machine.kept(2)).unwrap();
    let long_ago = std::time::SystemTime::now() - std::time::Duration::from_secs(48 * 3600);
    for n in [1, 3] {
        let file = std::fs::File::options().write(true).open(machine.kept(n));
        file.unwrap().set_modified(long_ago).unwrap();
    }
    assert!(matches!(
        machine.routes(Command::SetRoutes, GOOD),
        RoutesReply::Ok { .. }
    ));
    assert_eq!(
        machine.fails(RESET_ALL, ""),
        SettingsFailureCode::Unwritable
    );
    assert_eq!(
        (kept(1), kept(3)),
        (good.to_string(), "damaged, the third time".to_string())
    );
    assert!(machine.kept(2).is_dir());

    // The sentence about the kept files is for a reset that could not
    // write. With every name still taken, a save that fails says nothing of
    // them, and neither does a reset that did not fail.
    let dir = machine.root.join("settings");
    assert!(kept_notice(RESET_ALL, true, &dir).is_some());
    assert_eq!(kept_notice(Command::SetRoutes, true, &dir), None);
    assert_eq!(kept_notice(RESET, false, &dir), None);
}

// A reset that could not move the old file, or could not write the new
// one, is a failure and is never reported as a reset.
#[test]
fn a_reset_that_fails_part_way_is_a_failure() {
    let machine = Machine::new();
    machine.write_settings("not json");
    let dir = machine.root.join("settings");
    let denied = || std::io::Error::from(std::io::ErrorKind::PermissionDenied);
    let unwritable = Err(SettingsFailureCode::Unwritable);

    // The move fails: nothing has changed, and no new file is written.
    let stuck = |_: &std::path::Path| Err(denied());
    let never = |_: &std::path::Path| panic!("nothing is written after a failed move");
    assert_eq!(reset_with(&dir, None, false, &stuck, &never), unwritable);
    let untouched = std::fs::read_to_string(machine.settings_file()).unwrap();
    assert_eq!(untouched, "not json");
    assert!(!machine.kept(1).exists());

    // The move works and the write fails: the old file is aside, whole.
    let aside = |dir: &std::path::Path| {
        std::fs::rename(
            dir.join("settings.json"),
            dir.join("settings.json.damaged-1"),
        )?;
        Ok("settings.json.damaged-1".to_string())
    };
    let full = |_: &std::path::Path| Err(denied());
    assert_eq!(reset_with(&dir, None, false, &aside, &full), unwritable);
    assert_eq!(
        std::fs::read_to_string(machine.kept(1)).unwrap(),
        "not json"
    );
    // With no settings file the settings read as the defaults.
    assert_eq!(machine.view().settings, Default::default());
}

// The file that is put aside is the same file, with the access it had.
#[cfg(unix)]
#[test]
fn a_kept_file_keeps_its_mode() {
    use std::os::unix::fs::PermissionsExt;

    let machine = Machine::new();
    machine.write_settings("not json");
    let mode = std::fs::Permissions::from_mode(0o640);
    std::fs::set_permissions(machine.settings_file(), mode).unwrap();
    assert_eq!(machine.reset(RESET), was_reset(1));
    let kept = std::fs::metadata(machine.kept(1))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(kept & 0o777, 0o640);
    let fresh = std::fs::metadata(machine.settings_file()).unwrap();
    assert_eq!(fresh.permissions().mode() & 0o777, 0o600);
}

// Security rule: a link where the settings file should be is moved aside
// as a link. What it points at is neither read as damaged nor written.
#[test]
fn a_link_in_place_of_the_settings_is_moved_and_not_followed() {
    let machine = Machine::new();
    machine.write_settings("");
    std::fs::remove_file(machine.settings_file()).unwrap();
    let target = machine.root.join("someone-elses-file");
    std::fs::write(&target, "precious, and not settings").unwrap();
    if let Err(error) = link_to_file(&target, &machine.settings_file()) {
        let skipped = format!("SKIPPED a_link_in_place_of_the_settings_is_moved: {error}\n");
        std::io::Write::write_all(&mut std::io::stderr(), skipped.as_bytes()).unwrap();
        return;
    }
    assert_eq!(machine.reset(RESET), was_reset(1));
    assert_eq!(
        std::fs::read_to_string(&target).unwrap(),
        "precious, and not settings"
    );
    assert!(
        std::fs::symlink_metadata(machine.kept(1))
            .unwrap()
            .is_symlink()
    );
    let fresh = std::fs::symlink_metadata(machine.settings_file()).unwrap();
    assert!(fresh.is_file());

    // A link that leads nowhere is still something in the settings' place.
    std::fs::remove_file(machine.settings_file()).unwrap();
    let nowhere = machine.root.join("not-there");
    link_to_file(&nowhere, &machine.settings_file()).unwrap();
    assert_eq!(machine.reset(RESET), was_reset(2));
    let moved = std::fs::symlink_metadata(machine.kept(2)).unwrap();
    assert!(moved.is_symlink() && !nowhere.exists());
    let fresh = std::fs::symlink_metadata(machine.settings_file()).unwrap();
    assert!(fresh.is_file());

    // That link now sits at a kept name, leading nowhere. It still takes
    // the name: the next reset goes to the one after it.
    std::fs::write(machine.settings_file(), "not json").unwrap();
    assert_eq!(machine.reset(RESET), was_reset(3));
    let still = std::fs::symlink_metadata(machine.kept(2)).unwrap();
    assert!(still.is_symlink() && !nowhere.exists());
}

// Security rule: the folder rule holds for `reset` too. In a folder others
// can write to nothing is moved and nothing is written, and the user is
// told why.
#[cfg(unix)]
#[test]
fn reset_does_nothing_in_a_folder_others_can_write_to() {
    use std::os::unix::fs::PermissionsExt;

    let machine = Machine::new();
    machine.write_settings("not json");
    let dir = machine.root.join("settings");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o770)).unwrap();
    for command in [RESET, RESET_ALL] {
        assert_eq!(machine.fails(command, ""), SettingsFailureCode::Unreadable);
        assert!(machine.said.borrow().contains("chmod go-w"));
    }
    let untouched = std::fs::read_to_string(machine.settings_file()).unwrap();
    assert_eq!(untouched, "not json");
    assert!(!machine.kept(1).exists());
}
