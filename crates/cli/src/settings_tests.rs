//! The `settings` commands, against folders made for each test. The cases
//! are those listed in `ubc_vpn_core::settings_cli`.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use ubc_vpn_core::protocol::{MAX_LINE_BYTES, decode};
use ubc_vpn_core::settings_cli::{
    RouteProblemCode, RoutesReply, SettingsFailure, SettingsFailureCode, SettingsView,
};
use ubc_vpn_platform::Error;
use ubc_vpn_platform::fake::Fake;

use crate::settings::{Command, run};

const GOOD: &str =
    r#"{"subnets":["10.19.0.0/16","142.103.0.0/16"],"dns_domains":["ece.example.test"]}"#;

/// One user's machine: a policy folder and a settings folder, both empty.
struct Machine {
    root: PathBuf,
}

impl Machine {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let unique = (std::process::id(), NEXT.fetch_add(1, Ordering::SeqCst));
        let root = std::env::temp_dir().join(format!("ubc-vpn-settings-test-{unique:?}"));
        std::fs::create_dir_all(&root).unwrap();
        Self { root }
    }

    fn settings_file(&self) -> PathBuf {
        self.root.join("settings/settings.json")
    }

    fn write_settings(&self, text: &str) {
        std::fs::create_dir_all(self.root.join("settings")).unwrap();
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
        let status = run(command, &platform, &mut input.as_bytes(), &mut out);
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
    for wrong in [
        &[][..],
        &["get"],
        &["get", "--json", "x"],
        &["set", "--json"],
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

// When saving fails the old file is exactly as it was.
#[test]
fn a_failed_save_leaves_the_old_file_unchanged() {
    let machine = Machine::new();
    let before = r#"{"username":"jdoe"}"#;
    machine.write_settings(before);
    // The new file is written beside the old one. A folder in its place
    // cannot be removed as a file, so the save cannot begin.
    let partial = machine.root.join("settings/settings.json.tmp");
    std::fs::create_dir_all(&partial).unwrap();
    let why = machine.fails(Command::SetRoutes, GOOD);
    assert_eq!(why, SettingsFailureCode::Unwritable);
    assert_eq!(
        std::fs::read_to_string(machine.settings_file()).unwrap(),
        before
    );

    // A partial file a crash left behind is no obstacle and does not stay.
    std::fs::remove_dir(&partial).unwrap();
    std::fs::write(&partial, "half a file").unwrap();
    assert!(matches!(
        machine.routes(Command::SetRoutes, GOOD),
        RoutesReply::Ok { .. }
    ));
    assert!(!partial.exists());
    assert_eq!(machine.view().settings.username.as_deref(), Some("jdoe"));
}

// A system with nowhere to keep files has no settings to show or to save,
// but routes can still be checked.
#[test]
fn without_a_platform_only_checking_works() {
    let machine = Machine::new();
    let nowhere = || Err(Error::Unsupported);
    let status = |command: Command| {
        let mut out = Vec::new();
        let status = run(command, &nowhere, &mut GOOD.as_bytes(), &mut out);
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
// the partial file's name is replaced, and what it pointed at is untouched.
#[test]
fn settings_are_never_written_through_a_link() {
    let machine = Machine::new();
    machine.write_settings("{}");
    let target = machine.root.join("someone-elses-file");
    std::fs::write(&target, "precious").unwrap();
    let partial = machine.root.join("settings/settings.json.tmp");
    if let Err(error) = link_to_file(&target, &partial) {
        // Windows lets only an admin, or anyone in Developer Mode, make one.
        eprintln!("SKIPPED settings_are_never_written_through_a_link: no link ({error})");
        return;
    }
    assert!(matches!(
        machine.routes(Command::SetRoutes, GOOD),
        RoutesReply::Ok { .. }
    ));
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "precious");
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
    let status = run(Command::CheckRoutes, &platform, &mut input, &mut out);
    assert_eq!(status, 1);
    assert_eq!(out, b"{\"error\":\"bad_input\"}\n");
    let taken = input.get_ref().0;
    assert!(taken <= 2 * MAX_LINE_BYTES, "{taken} bytes were read");
}
