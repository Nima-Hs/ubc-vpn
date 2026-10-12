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
use crate::connect::{Ask, BUSY, CANCELLED, LOGIN_REFUSED, connect, disconnect};
use crate::tests::Rig;
use crate::{FAILED, NOT_RUNNING};

const PASSWORD: &str = "correct-horse-battery";
const CODE: &str = "246810";
const COOKIE: &str = "Zq7-made-up-0123456789";
const ROUTES: &str = r#""routes":{"subnets":["10.255.0.0/24"],"dns_domains":["ece.example.test"]}"#;

/// The person at the terminal: answers in order, and keeps what was asked.
#[derive(Default)]
struct Typist {
    answers: VecDeque<Option<&'static str>>,
    asked: Vec<PromptKind>,
    unusable: Option<String>,
}

impl Typist {
    fn typing(answers: &[Option<&'static str>]) -> Self {
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
}

/// A machine with a policy, saved settings, a running service, and a pretend
/// gateway that asks for a username, a password and a one-time code.
struct Scene {
    rig: Rig,
    gateway: FakeEngine,
    service: Option<Service>,
}

/// A short wait for the outcome, so that a connect whose outcome never
/// comes fails its test soon and does not hang it.
fn brief() -> Limits {
    Limits {
        outcome: std::time::Duration::from_secs(5),
        ..Limits::default()
    }
}

fn pin() -> ubc_vpn_core::policy::Pin {
    format!("pin-sha256:{}=", "A".repeat(43))
        .try_into()
        .unwrap()
}

impl Scene {
    /// With `settings` as the text of the settings file, and `policy_extra`
    /// appended to the fields of a valid policy.
    fn new(settings: Option<&str>, policy_extra: &str) -> Self {
        let rig = Rig::new();
        let policy = format!(
            r#"{{"gateway":"vpn.example.test","pins":["{}"]{policy_extra}}}"#,
            pin().as_str()
        );
        std::fs::create_dir_all(rig.root.join("policy")).unwrap();
        std::fs::write(rig.root.join("policy/policy.json"), policy).unwrap();
        if let Some(text) = settings {
            std::fs::create_dir_all(rig.root.join("settings")).unwrap();
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
    fn usual() -> Self {
        Self::new(Some(&format!(r#"{{"username":"alice",{ROUTES}}}"#)), "")
    }

    /// Runs `connect` with `typist` at the terminal.
    fn connect(&self, typist: &mut Typist) -> (u8, String, String) {
        let platform = || Ok(self.rig.fake.platform(&self.rig.root));
        let engines = |_: &Policy| Some(Box::new(self.gateway.clone()) as Box<dyn LoginEngine>);
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = connect(&platform, &engines, typist, brief(), &mut out, &mut err);
        let text = |bytes| String::from_utf8(bytes).unwrap();
        (code, text(out), text(err))
    }

    fn state(&self) -> String {
        self.rig.run(&["status", "--json"]).1
    }

    /// Whether the gateway was sent anything, which is what costs the user
    /// an MFA request.
    fn gateway_was_asked(&self) -> bool {
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
        "Connected (fake0 as 10.255.0.2)\n  Subnets: 10.255.0.0/24\n  \
         DNS domains: ece.example.test\n"
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

// Security rule: a connect that cannot succeed asks nothing and sends the
// gateway nothing, so it costs the user no MFA request.
#[test]
fn a_doomed_connect_asks_nothing_and_sends_nothing() {
    let usual = format!(r#"{{"username":"alice",{ROUTES}}}"#);
    let narrow = r#","allowed_routes":["142.103.0.0/16"]"#;
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

    let platform = || Ok(scene.rig.fake.platform(&scene.rig.root));
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let mut typist = Typist::typing(&[Some(PASSWORD)]);
    let none = |_: &Policy| None;
    let code = connect(&platform, &none, &mut typist, brief(), &mut out, &mut err);
    assert_eq!((code, out.is_empty()), (FAILED, true));
    assert!(
        String::from_utf8(err)
            .unwrap()
            .contains("no VPN engine yet")
    );
    assert!(typist.asked.is_empty());

    let mut scene = Scene::usual();
    scene.service = None;
    let mut typist = Typist::typing(&[Some(PASSWORD)]);
    attempt(&scene, &mut typist, "service is not running", NOT_RUNNING);
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
    assert!(err.contains("service is not running"), "{err}");

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
    assert!(err.contains("ubc-vpn: The gateway could not be reached."), "{err}");
    assert!(err.contains("ubc-vpn: Failed to connect to the gateway"), "{err}");
    assert!(typist.asked.is_empty(), "nothing is asked of a gateway that is away");

    // A gateway whose key the policy does not pin is sent nothing.
    let mut scene = Scene::usual();
    let other = format!("pin-sha256:{}=", "B".repeat(43));
    scene.gateway = FakeEngine::new(Script::new(other.try_into().unwrap()));
    let mut typist = Typist::typing(&[Some(PASSWORD), Some(CODE)]);
    let (code, _, err) = scene.connect(&mut typist);
    assert_eq!(code, FAILED);
    assert!(err.contains("certificate is not the expected one"), "{err}");
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
    scene.service = Some(scene.rig.service_on(FakeEngine::for_dev_mode(Script::new(pin()))));
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
