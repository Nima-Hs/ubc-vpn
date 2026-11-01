//! `connect` and `disconnect`, against the real service on the fakes, with a
//! pretend gateway to log in to and a stand-in for the person at the terminal.

use std::collections::VecDeque;

use ubc_vpn_core::login::PromptKind;
use ubc_vpn_core::policy::Policy;
use ubc_vpn_core::redact::Secret;
use ubc_vpn_core::state::ConnState;
use ubc_vpn_engine::fake::{FakeEngine, Script};
use ubc_vpn_engine::{LoginEngine, Prompt};
use ubc_vpn_platform::Error;
use ubc_vpn_platform::fake::Op;
use ubc_vpn_service::Service;

use crate::client::Limits;
use crate::connect::{
    Ask, BUSY, CANCELLED, CHECK_USERNAME, Ended, LOGIN_REFUSED, connect, disconnect,
};
use crate::interrupt::Progress;
use crate::tests::Rig;
use crate::{FAILED, NOT_RUNNING};

pub(crate) const PASSWORD: &str = "correct-horse-battery";
pub(crate) const CODE: &str = "246810";
pub(crate) const COOKIE: &str = "Zq7-made-up-0123456789";
pub(crate) const ROUTES: &str =
    r#""routes":{"subnets":["10.255.0.0/24"],"dns_domains":["dept.example.test"]}"#;

/// The person at the terminal: answers in order, and keeps what was asked.
#[derive(Default)]
pub(crate) struct Typist {
    answers: VecDeque<Option<&'static str>>,
    pub(crate) asked: Vec<PromptKind>,
    unusable: Option<String>,
    /// Whether a `None` answer is Ctrl-C rather than giving up.
    interrupted: bool,
}

impl Typist {
    pub(crate) fn typing(answers: &[Option<&'static str>]) -> Self {
        Self {
            answers: answers.iter().copied().collect(),
            ..Self::default()
        }
    }
}

impl Ask for Typist {
    fn unusable(&self) -> Option<String> {
        self.unusable.clone()
    }

    fn ask(&mut self, prompt: &Prompt) -> Option<Secret> {
        self.asked.push(prompt.kind);
        self.answers.pop_front().flatten().map(Secret::new)
    }

    fn interrupted(&self) -> bool {
        self.interrupted
    }
}

/// A machine with a policy, saved settings, a running service, and a pretend
/// gateway that asks for a username, a password and a one-time code.
pub(crate) struct Scene {
    pub(crate) rig: Rig,
    pub(crate) gateway: FakeEngine,
    pub(crate) service: Option<Service>,
}

/// A short wait for the outcome, so that a connect whose outcome never
/// comes fails its test soon and does not hang it.
pub(crate) fn brief() -> Limits {
    Limits {
        outcome: std::time::Duration::from_secs(5),
        ..Limits::default()
    }
}

pub(crate) fn pin() -> ubc_vpn_core::policy::Pin {
    format!("pin-sha256:{}=", "A".repeat(43))
        .try_into()
        .unwrap()
}

impl Scene {
    /// With `settings` as the text of the settings file, and `policy_extra`
    /// appended to the fields of a valid policy.
    pub(crate) fn new(settings: Option<&str>, policy_extra: &str) -> Self {
        let rig = Rig::new();
        let policy = format!(
            r#"{{"gateway":"vpn.example.test","pins":["{}"]{policy_extra}}}"#,
            pin().as_str()
        );
        std::fs::create_dir_all(rig.root.join("policy")).unwrap();
        std::fs::write(rig.root.join("policy/policy.json"), policy).unwrap();
        if let Some(text) = settings {
            crate::tests::settings_folder(&rig.root.join("settings"));
            std::fs::write(rig.root.join("settings/settings.json"), text).unwrap();
        }
        let mut script = Script::new(pin());
        let mut code = script.form[1].clone();
        (code.0.kind, code.1) = (PromptKind::Code, Secret::new(CODE));
        script.form.push(code);
        let service = Some(rig.service());
        Self {
            rig,
            gateway: FakeEngine::new(script),
            service,
        }
    }

    /// The usual one: a saved username and routes the policy allows.
    pub(crate) fn usual() -> Self {
        Self::new(Some(&format!(r#"{{"username":"alice",{ROUTES}}}"#)), "")
    }

    /// Runs `connect` with `typist` at the terminal.
    pub(crate) fn connect(&self, typist: &mut dyn Ask) -> (u8, String, String) {
        let (ended, out, err) = self.connect_watched(typist, &Progress::default());
        match ended {
            Ended::Status(code) => (code, out, err),
            other => panic!("the connect was stopped: {other:?}"),
        }
    }

    /// The same, for a connect that may be stopped part-way.
    pub(crate) fn connect_watched(
        &self,
        typist: &mut dyn Ask,
        progress: &Progress,
    ) -> (Ended, String, String) {
        self.connect_as(None, typist, progress)
    }

    /// `connect --profile <profile>`, or with the active profile for `None`.
    pub(crate) fn connect_as(
        &self,
        profile: Option<&ubc_vpn_core::profiles::ProfileId>,
        typist: &mut dyn Ask,
        progress: &Progress,
    ) -> (Ended, String, String) {
        let platform = || Ok(self.rig.fake.platform(&self.rig.root));
        let engines = |_: &Policy| Ok(Box::new(self.gateway.clone()) as Box<dyn LoginEngine>);
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let limits = brief();
        let ended = connect(
            &platform, profile, &engines, typist, progress, limits, &mut out, &mut err,
        );
        let text = |bytes| String::from_utf8(bytes).unwrap();
        (ended, text(out), text(err))
    }

    pub(crate) fn state(&self) -> String {
        self.rig.run(&["status", "--json"]).1
    }

    /// Whether the gateway was sent anything, which is what costs the user
    /// an MFA request.
    pub(crate) fn gateway_was_asked(&self) -> bool {
        !self.gateway.answers().is_empty()
    }
}

#[test]
fn connect_logs_in_asks_only_what_it_must_and_connects() {
    let scene = Scene::usual();
    let mut typist = Typist::typing(&[Some(PASSWORD), Some(CODE)]);
    let (code, out, err) = scene.connect(&mut typist);
    assert_eq!((code, err.as_str()), (0, ""), "{out}");
    assert_eq!(
        out,
        "Connected (fake0 as 10.255.0.2)\n  \
         Tunnel: split (only the chosen UBC subnets and domains)\n  \
         Subnets: 10.255.0.0/24\n  DNS domains: dept.example.test\n"
    );
    // The saved username answered for itself; the rest was asked once each.
    assert_eq!(typist.asked, [PromptKind::Password, PromptKind::Code]);
    assert!(scene.state().contains(r#""state":"connected""#));

    // Connected already: nothing is asked, and nothing is sent.
    let mut again = Typist::typing(&[Some(PASSWORD), Some(CODE)]);
    let (code, out, err) = scene.connect(&mut again);
    assert_eq!((code, out.as_str()), (BUSY, ""));
    assert!(err.contains("disconnect` first"), "{err}");
    assert!(again.asked.is_empty());

    let (code, out, err) = scene.rig.run(&["disconnect"]);
    assert_eq!(
        (code, out.as_str(), err.as_str()),
        (0, "Disconnected\n", "")
    );
    assert!(scene.state().contains(r#""state":"disconnected""#));
}

// Security rule: the password, the code and the cookie are never printed.
#[test]
fn no_secret_is_ever_printed() {
    let scene = Scene::new(Some(&format!("{{{ROUTES}}}")), "");
    let mut typist = Typist::typing(&[Some("alice"), Some(PASSWORD), Some(CODE)]);
    let (code, out, err) = scene.connect(&mut typist);
    assert_eq!(code, 0, "{err}");
    // With no username saved, that is asked too.
    let asked = [PromptKind::Username, PromptKind::Password, PromptKind::Code];
    assert_eq!(typist.asked, asked);
    let shown = [out, err, scene.state(), scene.rig.run(&["disconnect"]).1].concat();
    for secret in [PASSWORD, CODE, COOKIE] {
        assert!(!shown.contains(secret), "{secret} was printed");
    }
}

// Security rule: the same holds when the library is careless. This gateway
// writes every answer and the cookie in error lines, which connect prints,
// and registers none of them: only connect's own care keeps them out.
#[test]
fn a_library_that_leaks_secrets_has_them_removed() {
    let mut scene = Scene::new(Some(&format!("{{{ROUTES}}}")), "");
    let mut script = Script::new(pin());
    script.leaks = true;
    scene.gateway = FakeEngine::new(script);
    let mut typist = Typist::typing(&[Some("alice"), Some(PASSWORD)]);
    let (code, out, err) = scene.connect(&mut typist);
    assert_eq!(code, 0, "{err}");
    // The lines did arrive: two answers and the cookie, each blanked.
    assert_eq!(err.matches("ubc-vpn: > [redacted]\n").count(), 2, "{err}");
    assert_eq!(err.matches("ubc-vpn: < [redacted]\n").count(), 1, "{err}");
    let shown = [out, err, scene.state()].concat();
    for secret in ["alice", PASSWORD, COOKIE] {
        assert!(!shown.contains(secret), "{secret} was printed");
    }
}

// Security rule: what an engine logs can be text a gateway sent, some of it
// before its certificate was judged, and connect prints it in the user's
// terminal. No control character gets there. The careless gateway echoes the
// username, which is too short for the log sink to hide.
#[test]
fn engine_lines_are_printed_without_control_characters() {
    const ESCAPE: &str = "\u{1b}[2";
    let mut scene = Scene::new(Some(&format!("{{{ROUTES}}}")), "");
    let mut script = Script::new(pin());
    (script.leaks, script.form[0].1) = (true, Secret::new(ESCAPE));
    scene.gateway = FakeEngine::new(script);
    let mut typist = Typist::typing(&[Some(ESCAPE), Some(PASSWORD)]);
    let (code, _, err) = scene.connect(&mut typist);
    assert_eq!(code, 0, "{err:?}");
    assert!(err.contains("ubc-vpn: > [2\n"), "{err:?}");
    assert!(!err.chars().any(|c| c.is_control() && c != '\n'), "{err:?}");

    // The same for a reason that quotes the settings file. The route error
    // itself writes the domain with its control characters escaped, and
    // this fails if that ever stops being so.
    let quoted = r#"{"routes":{"subnets":["10.255.0.0/24"],"dns_domains":["a\u001b[2J.test"]}}"#;
    let scene = Scene::new(Some(quoted), "");
    let (code, _, err) = scene.connect(&mut Typist::default());
    assert_eq!(code, FAILED);
    assert!(
        err.contains("saved routes cannot be used") && err.contains("[2J"),
        "{err:?}"
    );
    assert!(!err.chars().any(|c| c.is_control() && c != '\n'), "{err:?}");
}

// A connection that failed, or whose session has ended, is over. Connecting
// again is not "busy".
#[test]
fn a_failed_or_ended_connection_can_be_connected_again() {
    let mut scene = Scene::usual();
    scene.service = None;
    // One gateway for both sides, so that a new login brings the session
    // back after the service logged it off.
    scene.service = Some(scene.rig.service_on(scene.gateway.clone()));
    let connect = |scene: &Scene| {
        let mut typist = Typist::typing(&[Some(PASSWORD), Some(CODE)]);
        let (code, _, err) = scene.connect(&mut typist);
        (code, err)
    };
    let denied = Some(Error::PermissionDenied);
    scene.rig.fake.set_failure(Op::AddTunnelRoutes, denied);
    assert_eq!(connect(&scene).0, FAILED);
    assert!(scene.state().contains(r#""state":"failed""#));
    scene.rig.fake.set_failure(Op::AddTunnelRoutes, None);
    assert_eq!(connect(&scene), (0, String::new()));

    scene.gateway.expire_session();
    let patience = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !scene.state().contains(r#""state":"login_needed""#) {
        assert!(std::time::Instant::now() < patience, "{}", scene.state());
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert_eq!(connect(&scene), (0, String::new()));
}

// Security rule: a connect that cannot succeed asks nothing and sends the
// gateway nothing, so it costs the user no MFA request.
#[test]
fn a_doomed_connect_asks_nothing_and_sends_nothing() {
    let usual = format!(r#"{{"username":"alice",{ROUTES}}}"#);
    let narrow = r#","allowed_routes":["198.19.0.0/16"]"#;
    let doomed: [(Option<&str>, &str, &str); 5] = [
        (None, "", "saved routes cannot be used: no subnets"),
        (Some("{}"), "", "saved routes cannot be used: no subnets"),
        (Some("not json"), "", "settings file cannot be read"),
        (Some(&usual), narrow, "outside the allowed routes"),
        (
            Some(&usual),
            r#","pins":[]"#,
            "policy file is missing or not valid",
        ),
    ];
    let attempt = |scene: &Scene, typist: &mut Typist, why: &str, status: u8| {
        let (code, out, err) = scene.connect(typist);
        assert_eq!((code, out.as_str()), (status, ""), "{why}: {err}");
        assert!(err.contains(why), "{err}");
        assert!(
            typist.asked.is_empty() && !scene.gateway_was_asked(),
            "{why}"
        );
    };
    for (settings, policy_extra, why) in doomed {
        let scene = Scene::new(settings, policy_extra);
        attempt(&scene, &mut Typist::typing(&[Some(PASSWORD)]), why, FAILED);
    }

    // No way to ask, no engine, and no service.
    let scene = Scene::usual();
    let mut mute = Typist {
        unusable: Some("run this in a terminal".to_string()),
        ..Typist::default()
    };
    attempt(&scene, &mut mute, "run this in a terminal", FAILED);

    let no_engine = |scene: &Scene| {
        let platform = || Ok(scene.rig.fake.platform(&scene.rig.root));
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let mut typist = Typist::typing(&[Some(PASSWORD)]);
        let none = |_: &Policy| Err("The VPN library could not be loaded.".to_string());
        let unwatched = Progress::default();
        let limits = brief();
        let ended = connect(
            &platform,
            None,
            &none,
            &mut typist,
            &unwatched,
            limits,
            &mut out,
            &mut err,
        );
        assert_eq!((ended, out.is_empty()), (Ended::Status(FAILED), true));
        let err = String::from_utf8(err).unwrap();
        // The reason there is no engine is what the user is told.
        assert!(
            err.contains("The VPN library could not be loaded."),
            "{err}"
        );
        assert!(typist.asked.is_empty());
    };
    no_engine(&scene);

    let mut scene = Scene::usual();
    scene.service = None;
    // A build with no engine says so before it looks for the service, so it
    // claims nothing on the way to failing.
    no_engine(&scene);
    let mut typist = Typist::typing(&[Some(PASSWORD)]);
    attempt(
        &scene,
        &mut typist,
        "service is installed but not running",
        NOT_RUNNING,
    );
}

// Security rule: a refused login stops at once. Nothing is asked twice and
// nothing is sent to the service.
#[test]
fn a_refused_or_abandoned_login_connects_nothing() {
    let scene = Scene::usual();
    let mut wrong = Typist::typing(&[Some("wrong-password-0000"), Some(CODE), Some(PASSWORD)]);
    let (code, out, err) = scene.connect(&mut wrong);
    assert_eq!((code, out.as_str()), (LOGIN_REFUSED, ""));
    assert!(
        err.contains("rejected the username, password or code"),
        "{err}"
    );
    assert!(!err.contains("wrong-password-0000"));
    assert_eq!(
        wrong.asked,
        [PromptKind::Password, PromptKind::Code],
        "asked once"
    );
    assert!(scene.state().contains(r#""state":"disconnected""#));

    // The user gives up at the code.
    let mut leaving = Typist::typing(&[Some(PASSWORD), None]);
    let (code, out, err) = scene.connect(&mut leaving);
    assert_eq!((code, out.as_str()), (CANCELLED, ""));
    assert!(err.contains("cancelled"), "{err}");
    assert!(scene.state().contains(r#""state":"disconnected""#));
}

// What the service makes of the connect is the command's own result.
#[test]
fn a_connect_the_service_cannot_complete_is_a_failure() {
    let scene = Scene::usual();
    let denied = Some(Error::PermissionDenied);
    scene.rig.fake.set_failure(Op::AddTunnelRoutes, denied);
    let mut typist = Typist::typing(&[Some(PASSWORD), Some(CODE)]);
    let (code, out, err) = scene.connect(&mut typist);
    assert_eq!((code, out.as_str()), (FAILED, ""));
    assert!(
        err.contains("Failed: The tunnel routes could not be added"),
        "{err}"
    );
}

#[test]
fn disconnect_reports_what_happened() {
    let scene = Scene::usual();
    // Nothing is connected: it still ends disconnected, and says so.
    let (code, out, _) = scene.rig.run(&["disconnect"]);
    assert_eq!((code, out.as_str()), (0, "Disconnected\n"));

    let mut gone = Scene::usual();
    gone.service = None;
    let (code, out, err) = gone.rig.run(&["disconnect"]);
    assert_eq!((code, out.as_str()), (NOT_RUNNING, ""));
    assert!(
        err.contains("service is installed but not running"),
        "{err}"
    );

    // The function behind the command, for a platform that is missing.
    let nowhere = || Err(Error::Unsupported);
    let (mut out, mut err) = (Vec::new(), Vec::new());
    assert_eq!(disconnect(&nowhere, brief(), &mut out, &mut err), FAILED);
    assert!(out.is_empty());
}

// The state the user is left in must be the truth.
#[test]
fn the_saved_state_names_are_what_status_shows() {
    let scene = Scene::usual();
    let state: ConnState = serde_json::from_str(&scene.state()).unwrap();
    assert_eq!(state, ConnState::Disconnected);
}

// What the gateway's side says goes to the user: why the login failed, and
// the engine's own lines about it.
#[test]
fn a_gateway_that_is_wrong_or_away_is_explained() {
    let scene = Scene::usual();
    scene.gateway.set_reachable(false);
    let mut typist = Typist::typing(&[Some(PASSWORD), Some(CODE)]);
    let (code, out, err) = scene.connect(&mut typist);
    assert_eq!((code, out.as_str()), (FAILED, ""));
    assert!(
        err.contains("ubc-vpn: The gateway could not be reached."),
        "{err}"
    );
    assert!(
        err.contains("ubc-vpn: Failed to connect to the gateway"),
        "{err}"
    );
    assert!(
        typist.asked.is_empty(),
        "nothing is asked of a gateway that is away"
    );

    // A gateway whose key the policy does not pin is sent nothing.
    let mut scene = Scene::usual();
    let other = format!("pin-sha256:{}=", "B".repeat(43));
    scene.gateway = FakeEngine::new(Script::new(other.try_into().unwrap()));
    let mut typist = Typist::typing(&[Some(PASSWORD), Some(CODE)]);
    let (code, _, err) = scene.connect(&mut typist);
    assert_eq!(code, FAILED);
    // The user is told what to do: the certificate changed, so update.
    assert!(
        err.contains(ubc_vpn_core::protocol::CERTIFICATE_CHANGED),
        "{err}"
    );
    assert!(typist.asked.is_empty() && !scene.gateway_was_asked());
}

// Dev mode: the service's pretend gateway and the client's are two that
// share nothing, as in two processes. Connecting, disconnecting and
// connecting again must work, which it does only because the service's is
// the dev-mode kind.
#[test]
fn in_dev_mode_a_second_connect_works_after_a_disconnect() {
    let mut scene = Scene::usual();
    scene.service = None;
    scene.service = Some(
        scene
            .rig
            .service_on(FakeEngine::for_dev_mode(Script::new(pin()))),
    );
    for round in 1..=2 {
        let mut typist = Typist::typing(&[Some(PASSWORD), Some(CODE)]);
        let (code, out, err) = scene.connect(&mut typist);
        assert_eq!(code, 0, "round {round}: {err}");
        assert!(out.starts_with("Connected (fake0"), "round {round}: {out}");
        let (code, out, _) = scene.rig.run(&["disconnect"]);
        assert_eq!((code, out.as_str()), (0, "Disconnected\n"), "round {round}");
    }

    // With the ordinary kind the second connect is refused: the session
    // was logged off, and nothing in this process can bring it back.
    let scene = Scene::usual();
    let mut typist = Typist::typing(&[Some(PASSWORD), Some(CODE)]);
    assert_eq!(scene.connect(&mut typist).0, 0);
    assert_eq!(scene.rig.run(&["disconnect"]).0, 0);
    let mut typist = Typist::typing(&[Some(PASSWORD), Some(CODE)]);
    assert_eq!(scene.connect(&mut typist).0, LOGIN_REFUSED);
}

// A disconnect waits for what the service makes of it, and a teardown that
// left something behind is a failure, not "Disconnected".
#[test]
fn a_disconnect_that_leaves_something_behind_is_a_failure() {
    let scene = Scene::usual();
    let mut typist = Typist::typing(&[Some(PASSWORD), Some(CODE)]);
    assert_eq!(scene.connect(&mut typist).0, 0);
    let denied = Some(Error::PermissionDenied);
    scene.rig.fake.set_failure(Op::RemoveAllRoutes, denied);
    let (code, out, err) = scene.rig.run(&["disconnect"]);
    assert_eq!((code, out.as_str()), (FAILED, ""));
    assert!(err.contains("could not be removed"), "{err}");
}

// A service that accepts a request and then never says how it ended does
// not hang the command: the wait for the outcome has an end.
#[test]
fn the_wait_for_the_outcome_has_an_end() {
    use ubc_vpn_core::protocol::{Outcome, Request, Response, ResponseBody, ServerMessage, decode};

    let rig = Rig::new();
    let service = crate::tests::scripted(&rig, |conn| {
        crate::tests::greet(conn);
        let asked: Request = decode(&conn.read_line().unwrap().unwrap()).unwrap();
        let outcome = Outcome::Ok(ResponseBody::Accepted);
        let id = asked.id;
        crate::tests::tell(conn, &ServerMessage::Response(Response { id, outcome }));
        // Accepted, and then nothing, until the client goes or patience ends.
        drop(conn.read_line());
    });
    let platform = || Ok(rig.fake.platform(&rig.root));
    let limits = Limits {
        outcome: std::time::Duration::from_millis(600),
        ..Limits::default()
    };
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let started = std::time::Instant::now();
    let code = disconnect(&platform, limits, &mut out, &mut err);
    let waited = started.elapsed();
    service.join().unwrap();
    assert_eq!((code, out.is_empty()), (FAILED, true));
    let err = String::from_utf8(err).unwrap();
    assert!(err.contains("did not answer in time"), "{err}");
    assert!(waited < std::time::Duration::from_secs(3), "{waited:?}");
}

// Security rule: the login's lines are handed over after the connect
// request, never before it. By then the service holds the cookie, so its
// own removal covers these lines as well as the client's does.
#[test]
fn the_logins_lines_follow_the_connect_request() {
    use std::sync::{Arc, Mutex};
    use ubc_vpn_core::protocol::{
        Event, Outcome, Request, RequestBody, Response, ResponseBody, ServerMessage, decode,
    };

    let mut scene = Scene::new(Some(&format!("{{{ROUTES}}}")), "");
    let mut script = Script::new(pin());
    script.leaks = true;
    scene.gateway = FakeEngine::new(script);
    scene.service = None;
    let asked = Arc::new(Mutex::new(Vec::new()));
    let seen = asked.clone();
    let service = crate::tests::scripted(&scene.rig, move |conn| {
        crate::tests::greet(conn);
        while let Ok(Some(line)) = conn.read_line() {
            let Request { id, body } = decode(&line).unwrap();
            let (name, answer, then) = match body {
                RequestBody::Status => {
                    let idle = ResponseBody::Status(ConnState::Disconnected);
                    ("status", idle, None)
                }
                // Accepted, and it ends at once, so the client is done soon.
                RequestBody::Connect(_) => {
                    let ends = [ConnState::Connecting, ConnState::LoginNeeded];
                    ("connect", ResponseBody::Accepted, Some(ends))
                }
                RequestBody::AddLog(_) => ("add_log", ResponseBody::Accepted, None),
                _ => ("another", ResponseBody::Accepted, None),
            };
            seen.lock().unwrap().push(name);
            let outcome = Outcome::Ok(answer);
            crate::tests::tell(conn, &ServerMessage::Response(Response { id, outcome }));
            for state in then.into_iter().flatten() {
                crate::tests::tell(conn, &ServerMessage::Event(Event::StateChanged(state)));
            }
        }
    });
    let mut typist = Typist::typing(&[Some("alice"), Some(PASSWORD)]);
    let (code, _, err) = scene.connect(&mut typist);
    service.join().unwrap();
    assert_eq!(code, LOGIN_REFUSED, "{err}");
    // Two lines of progress, two answers and the cookie, each in a line of
    // its own, then how the login ended.
    let order = [
        "status", "connect", "add_log", "add_log", "add_log", "add_log", "add_log", "add_log",
    ];
    assert_eq!(*asked.lock().unwrap(), order);
}

/// A scene whose service takes a new login after a log-off, with these
/// settings saved.
pub(crate) fn returning(settings: &str) -> Scene {
    let mut scene = Scene::new(Some(settings), "");
    scene.service = None;
    scene.service = Some(
        scene
            .rig
            .service_on(FakeEngine::for_dev_mode(Script::new(pin()))),
    );
    scene
}

/// The settings file, byte for byte.
pub(crate) fn settings_text(scene: &Scene) -> String {
    std::fs::read_to_string(scene.rig.root.join("settings/settings.json")).unwrap()
}

pub(crate) fn saved(scene: &Scene) -> serde_json::Value {
    crate::tests::as_v1(&settings_text(scene))
}

// A username the user typed is kept once a connect made with it has been
// accepted, and is not asked for again. Nothing else in the file changes.
#[test]
fn the_username_is_remembered_after_a_connect_that_was_accepted() {
    let scene = returning(&format!(r#"{{"theme":"dark",{ROUTES}}}"#));
    let before = saved(&scene);
    let mut typist = Typist::typing(&[Some("alice"), Some(PASSWORD), Some(CODE)]);
    let (code, _, err) = scene.connect(&mut typist);
    assert_eq!((code, err.as_str()), (0, ""));
    let mut expected = before;
    expected["username"] = serde_json::json!("alice");
    assert_eq!(saved(&scene), expected);

    assert_eq!(scene.rig.run(&["disconnect"]).0, 0);
    let mut typist = Typist::typing(&[Some(PASSWORD), Some(CODE)]);
    assert_eq!(scene.connect(&mut typist).0, 0);
    assert_eq!(typist.asked, [PromptKind::Password, PromptKind::Code]);
    assert_eq!(saved(&scene), expected);
}

// Nothing is remembered from a login that failed or was given up, or from
// a connect the service did not accept.
#[test]
fn no_username_is_kept_from_a_connect_that_did_not_start() {
    let attempts: [&[Option<&str>]; 3] = [
        &[Some("alice"), Some("wrong-password-0000"), Some(CODE)],
        &[Some("alice"), None],
        &[None],
    ];
    for typed in attempts {
        let scene = returning(&format!("{{{ROUTES}}}"));
        // The file as it was written, which is not how this program would
        // write it: a save of any kind would show.
        let before = settings_text(&scene);
        let mut typist = Typist::typing(typed);
        assert_ne!(scene.connect(&mut typist).0, 0);
        assert_eq!(settings_text(&scene), before, "{typed:?}");
        let beside = std::fs::read_dir(scene.rig.root.join("settings")).unwrap();
        assert_eq!(beside.count(), 1, "nothing was written beside it");
    }
    // The login is good, and the service refuses the connect: the policy it
    // read when it started does not allow routes the policy file now does.
    let narrow = r#","allowed_routes":["198.19.0.0/16"]"#;
    let scene = Scene::new(Some(&format!("{{{ROUTES}}}")), narrow);
    let before = saved(&scene);
    let open = format!(
        r#"{{"gateway":"vpn.example.test","pins":["{}"]}}"#,
        pin().as_str()
    );
    std::fs::write(scene.rig.root.join("policy/policy.json"), open).unwrap();
    let mut typist = Typist::typing(&[Some("alice"), Some(PASSWORD), Some(CODE)]);
    let (code, _, err) = scene.connect(&mut typist);
    assert_eq!(code, FAILED, "{err}");
    assert!(scene.gateway_was_asked(), "the login was made");
    assert_eq!(saved(&scene), before);
}

// A refused password keeps the saved username: the gateway does not say
// which answer it refused, and the user can change the username in the
// app. The next connect asks only for the password and the code. (A
// username refused as one is forgotten: see
// `a_refused_username_is_to_be_checked_and_is_forgotten`.)
#[test]
fn a_refused_password_keeps_the_saved_username() {
    let scene = returning(&format!(
        r#"{{"username":"alice","theme":"dark",{ROUTES}}}"#
    ));
    let before = settings_text(&scene);
    let mut typist = Typist::typing(&[Some("wrong-password-0000"), Some(CODE)]);
    assert_eq!(scene.connect(&mut typist).0, LOGIN_REFUSED);
    assert_eq!(settings_text(&scene), before);

    let mut typist = Typist::typing(&[Some(PASSWORD), Some(CODE)]);
    assert_eq!(scene.connect(&mut typist).0, 0);
    assert_eq!(typist.asked, [PromptKind::Password, PromptKind::Code]);
    assert_eq!(saved(&scene)["username"], "alice");

    // Any other failure leaves a saved username where it is.
    assert_eq!(scene.rig.run(&["disconnect"]).0, 0);
    scene.gateway.set_reachable(false);
    assert_eq!(scene.connect(&mut Typist::default()).0, FAILED);
    let mut leaving = Typist::typing(&[None]);
    scene.gateway.set_reachable(true);
    assert_eq!(scene.connect(&mut leaving).0, CANCELLED);
    assert_eq!(saved(&scene)["username"], "alice");
}

// A name nobody would type as a username is not kept, and the connect is
// none the worse for it.
#[test]
fn an_odd_username_is_used_but_not_kept() {
    let odd = "u".repeat(300);
    let mut scene = returning(&format!("{{{ROUTES}}}"));
    let before = saved(&scene);
    let mut script = Script::new(pin());
    script.form[0].1 = Secret::new(odd.as_str());
    scene.gateway = FakeEngine::new(script);
    let typed: &'static str = Box::leak(odd.into_boxed_str());
    let mut typist = Typist::typing(&[Some(typed), Some(PASSWORD)]);
    let (code, _, err) = scene.connect(&mut typist);
    assert_eq!((code, err.as_str()), (0, ""));
    assert_eq!(saved(&scene), before);
}

// A username that cannot be saved does not undo a connect that worked. The
// user is told, and is asked again next time.
#[cfg(unix)]
#[test]
fn a_username_that_cannot_be_saved_does_not_fail_the_connect() {
    use std::os::unix::fs::PermissionsExt;

    let scene = returning(&format!("{{{ROUTES}}}"));
    let before = saved(&scene);
    let dir = scene.rig.root.join("settings");
    let mode = |mode| std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode));
    mode(0o500).unwrap();
    let root = std::fs::write(dir.join("probe"), "").is_ok();
    let mut typist = Typist::typing(&[Some("alice"), Some(PASSWORD), Some(CODE)]);
    let (code, _, err) = scene.connect(&mut typist);
    mode(0o700).unwrap();
    assert_eq!(code, 0, "{err}");
    if root {
        // Root writes where it likes, so the save went through and there is
        // nothing to see. Said past the capture, so a log shows it.
        let skipped = "SKIPPED a_username_that_cannot_be_saved_does_not_fail_the_connect: \
                       run as root, so only the exit status was checked\n";
        std::io::Write::write_all(&mut std::io::stderr(), skipped.as_bytes()).unwrap();
    }
    if !root {
        assert_eq!(
            err,
            "ubc-vpn: The username could not be saved in the settings.\n"
        );
        assert_eq!(saved(&scene), before);
    }
}

// Security rule: a connect takes its routes from the settings, so it does
// not read them from a folder others can write to. It asks nothing, sends
// nothing, and says what to do about it.
#[cfg(unix)]
#[test]
fn a_connect_does_not_read_settings_others_can_change() {
    use std::os::unix::fs::PermissionsExt;

    let scene = Scene::usual();
    let dir = scene.rig.root.join("settings");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o770)).unwrap();
    let mut typist = Typist::typing(&[Some(PASSWORD), Some(CODE)]);
    let (code, out, err) = scene.connect(&mut typist);
    assert_eq!((code, out.as_str()), (FAILED, ""));
    assert!(err.contains("can be changed by other users"), "{err}");
    assert!(err.contains("To stop them, run: chmod go-w '"), "{err}");
    assert!(typist.asked.is_empty() && !scene.gateway_was_asked());
}

// Security rule: a name that could be shown as another name is not kept.
// The connect is none the worse for it, and the name is asked for again.
#[test]
fn a_username_that_could_mislead_is_used_but_not_kept() {
    for odd in ["alice\u{202e}ecila", "al\u{200b}ice", "   "] {
        let mut scene = returning(&format!("{{{ROUTES}}}"));
        let before = settings_text(&scene);
        let mut script = Script::new(pin());
        script.form[0].1 = Secret::new(odd);
        scene.gateway = FakeEngine::new(script);
        let mut typist = Typist::typing(&[Some(odd), Some(PASSWORD)]);
        let (code, _, err) = scene.connect(&mut typist);
        assert_eq!((code, err.as_str()), (0, ""), "{odd:?}");
        assert_eq!(settings_text(&scene), before, "{odd:?}");
    }
}

// Why a login failed is in the service's log afterwards, where the app can
// show it: the same line as was printed, with the progress before it, which
// was not printed.
#[test]
fn what_a_failed_login_wrote_is_handed_to_the_service() {
    let scene = Scene::usual();
    scene.gateway.set_reachable(false);
    let (code, _, err) = scene.connect(&mut Typist::default());
    assert_eq!(code, FAILED, "{err}");
    assert!(
        err.contains("ubc-vpn: Failed to connect to the gateway\n"),
        "{err}"
    );
    let logs = scene.service.as_ref().unwrap().login_lines();
    let outcome = "login failed: gateway_unreachable";
    let progress = "Connecting to vpn.example.test";
    assert_eq!(
        logs,
        [progress, "Failed to connect to the gateway", outcome]
    );
    assert!(!err.contains(progress), "{err}");
    // A login that failed in any way but a refusal, or a username to check,
    // keeps the saved username.
    assert_eq!(saved(&scene)["username"], "alice");
}

// A gateway that asks for the username again before any password refused
// the username: the user is told to check its form, with the form UBC's
// gateway expects, and the saved username, which was the one refused, is
// forgotten. All names are made up.
#[test]
fn a_refused_username_is_to_be_checked_and_is_forgotten() {
    let mut scene = Scene::usual();
    let mut script = Script::new(pin());
    script.form.truncate(1);
    script.form[0].1 = Secret::new("alice.dept@app");
    scene.gateway = FakeEngine::new(script);
    let (code, _, err) = scene.connect(&mut Typist::default());
    assert_eq!(code, LOGIN_REFUSED, "{err}");
    assert!(err.contains(CHECK_USERNAME), "{err}");
    assert!(CHECK_USERNAME.contains("CWL.dept@method"));
    assert!(
        saved(&scene).get("username").is_none(),
        "{}",
        settings_text(&scene)
    );
    let logs = scene.service.as_ref().unwrap().login_lines();
    assert_eq!(
        logs.last().map(String::as_str),
        Some("login failed: refused by the gateway, check the name's form")
    );
}

// How a login ended is in the log whether or not the library printed
// anything: a success, and a wrong password.
#[test]
fn every_finished_login_says_how_it_ended() {
    let scene = Scene::usual();
    let mut typist = Typist::typing(&[Some(PASSWORD), Some(CODE)]);
    assert_eq!(scene.connect(&mut typist).0, 0);
    assert_eq!(scene.rig.run(&["disconnect"]).0, 0);
    let mut wrong = Typist::typing(&[Some("wrong-password-0000"), Some(CODE), Some(PASSWORD)]);
    assert_eq!(scene.connect(&mut wrong).0, LOGIN_REFUSED);
    let logs = scene.service.as_ref().unwrap().login_lines();
    let progress = "Connecting to vpn.example.test";
    assert_eq!(
        logs,
        [
            progress,
            "Login succeeded",
            "login succeeded",
            progress,
            "login failed: refused by the gateway"
        ]
    );
}

// A user who gave up is told only that, since nothing went wrong: the lines
// the login printed are not handed over. The careless gateway writes a line
// for the username before the password is asked for, so there is a line
// that could have been.
#[test]
fn a_login_the_user_gave_up_hands_over_only_that() {
    let mut scene = Scene::new(Some(&format!("{{{ROUTES}}}")), "");
    let mut script = Script::new(pin());
    script.leaks = true;
    scene.gateway = FakeEngine::new(script);
    let mut typist = Typist::typing(&[Some("alice"), None]);
    let (code, _, err) = scene.connect(&mut typist);
    assert_eq!(code, CANCELLED, "{err}");
    assert!(err.contains("ubc-vpn: > [redacted]\n"), "{err}");
    let logs = scene.service.as_ref().unwrap().login_lines();
    assert_eq!(logs, ["login failed: cancelled"]);
}

// Ctrl-C at a question ends the program at once: nothing is handed over.
#[test]
fn a_login_left_with_ctrl_c_hands_over_nothing() {
    let scene = Scene::usual();
    let mut typist = Typist::typing(&[None]);
    typist.interrupted = true;
    let (ended, _, _) = scene.connect_watched(&mut typist, &Progress::default());
    assert_eq!(ended, Ended::Interrupted);
    let logs = scene.service.as_ref().unwrap().login_lines();
    assert_eq!(logs, [""; 0], "a line was handed over");
}

// No more is handed over than one connection may add: the last lines, which
// are the nearest to how it ended. A blank line is passed over, and a line
// too long to keep is not cut: the marker goes in its place.
#[test]
fn only_the_last_lines_are_handed_over_and_none_is_cut() {
    use ubc_vpn_core::protocol::{ClientKind, LogText, MAX_ADDED_LOG_LINES};

    let scene = Scene::usual();
    let platform = scene.rig.fake.platform(&scene.rig.root);
    let (transport, name) = (&*platform.transport, &platform.paths.channel_name);
    let mut client =
        crate::client::Client::connect_within(transport, name, ClientKind::Cli, brief()).unwrap();
    client.claim_if_unowned().unwrap();
    let error = ubc_vpn_core::protocol::LogLevel::Error;
    let mut said: Vec<_> = (0..MAX_ADDED_LOG_LINES + 3)
        .map(|n| (error, format!("line {n}")))
        .collect();
    said.extend([(error, "  ".to_string()), (error, "x".repeat(600))]);
    let outcome = (
        ubc_vpn_core::protocol::LogLevel::Info,
        "made-up outcome".to_string(),
    );
    crate::connect::hand_over(&mut client, &said, outcome);
    let logs = scene.service.as_ref().unwrap().login_lines();
    // The outcome last, and room left for it.
    assert_eq!(logs.len(), MAX_ADDED_LOG_LINES);
    assert_eq!(logs[0], "line 5");
    assert_eq!(logs[MAX_ADDED_LOG_LINES - 3], "line 22");
    assert_eq!(logs[MAX_ADDED_LOG_LINES - 2], LogText::LEFT_OUT);
    assert_eq!(logs[MAX_ADDED_LOG_LINES - 1], "made-up outcome");
}
