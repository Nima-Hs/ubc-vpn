//! What the client's tests share: a fake machine running the real service, a
//! pretend service, and a scene with a pretend gateway to log in to and a
//! stand-in for the person at the terminal. Every value is made up.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ubc_vpn_core::login::PromptKind;
use ubc_vpn_core::policy::Policy;
use ubc_vpn_core::protocol::{ClientKind, HelloReply, PROTOCOL_VERSION, ServerMessage, encode};
use ubc_vpn_core::redact::Secret;
use ubc_vpn_engine::fake::{FakeEngine, Script};
use ubc_vpn_engine::{LoginEngine, Prompt};
use ubc_vpn_platform::fake::{Fake, paths};
use ubc_vpn_platform::{Connection, Transport};
use ubc_vpn_service::{Service, Timeouts};

use crate::client::{Client, Limits};
use crate::connect::{Ask, Ended, connect};
use crate::interrupt::Progress;
use crate::run;

/// A fake machine with the files of one service in a folder of its own.
pub(crate) struct Rig {
    pub(crate) fake: Fake,
    pub(crate) root: PathBuf,
}

impl Rig {
    pub(crate) fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let unique = (std::process::id(), NEXT.fetch_add(1, Ordering::SeqCst));
        let root = std::env::temp_dir().join(format!("ubc-vpn-cli-test-{unique:?}"));
        // Left by an earlier run whose process ID this one was given.
        let _ = std::fs::remove_dir_all(&root);
        let fake = Fake::new();
        Self { fake, root }
    }

    pub(crate) fn service(&self) -> Service {
        let key = format!("pin-sha256:{}=", "A".repeat(43));
        self.service_on(FakeEngine::new(Script::new(key.try_into().unwrap())))
    }

    /// A service whose tunnels are opened by `engine`.
    pub(crate) fn service_on(&self, engine: FakeEngine) -> Service {
        let platform = self.fake.platform(&self.root);
        let state = ubc_vpn_platform::StateDir::unchecked(&platform.paths.state_dir).unwrap();
        Service::start(platform, state, Arc::new(engine), Timeouts::default()).unwrap()
    }

    /// Runs the command line as the fake's own user, `fake-user`.
    pub(crate) fn run(&self, args: &[&str]) -> (u8, String, String) {
        let platform = || Ok(self.fake.platform(&self.root));
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = run(args, &platform, &mut out, &mut err);
        let text = |bytes| String::from_utf8(bytes).unwrap();
        (code, text(out), text(err))
    }

    /// Makes another user the owner.
    pub(crate) fn claim_as_someone_else(&self) {
        let other = "someone-else".parse().unwrap();
        let name = paths(&self.root).channel_name;
        let conn = self.fake.connect_as(&name, &other).unwrap();
        let mut client = Client::over(conn, ClientKind::App, Limits::default()).unwrap();
        client.claim_if_unowned().unwrap();
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Makes a settings folder as this program would: on Unix for the user
/// alone, whatever the umask of whoever runs the tests.
pub(crate) fn settings_folder(dir: &std::path::Path) {
    std::fs::create_dir_all(dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
}

/// A settings file's text as the settings were before profiles: the active
/// profile's username (when it has one), routes and `save_password` (when
/// set), beside the file's other top-level fields. So a test of what a
/// command keeps and changes reads the same whichever version wrote it.
pub(crate) fn as_v1(text: &str) -> serde_json::Value {
    let profiles = ubc_vpn_core::profiles::Profiles::read(Some(text))
        .expect("readable settings")
        .profiles;
    let active = profiles.v1_view();
    let mut v1 = profiles.other.clone();
    if let Some(name) = active.username {
        v1.insert("username".to_string(), name.into());
    }
    let routes = serde_json::to_value(&active.routes).unwrap();
    v1.insert("routes".to_string(), routes);
    if active.save_password {
        v1.insert("save_password".to_string(), true.into());
    }
    serde_json::Value::Object(v1)
}

/// How long a pretend service keeps going when the client does not hang up.
/// A client that has lost its deadline then fails its test late, and does
/// not hang it.
pub(crate) const PATIENCE: Duration = Duration::from_secs(5);

/// Stands in for the service on `rig`'s channel: accepts one connection and
/// hands it to `script`. Its own reads give up after [`PATIENCE`].
pub(crate) fn scripted(
    rig: &Rig,
    script: impl FnOnce(&Connection) + Send + 'static,
) -> std::thread::JoinHandle<()> {
    let listener = rig.fake.listen(&paths(&rig.root).channel_name).unwrap();
    std::thread::spawn(move || {
        let (conn, _) = listener.accept().unwrap();
        conn.set_read_timeout(Some(PATIENCE)).unwrap();
        script(&conn);
    })
}

/// Reads the hello and answers it as an owned service of this version.
pub(crate) fn greet(conn: &Connection) {
    conn.read_line().unwrap();
    let reply = HelloReply {
        protocol_version: PROTOCOL_VERSION,
        service_version: "0.1.0".to_string(),
        owner_claimed: true,
    };
    conn.write_line(encode(&reply).unwrap().trim_end()).unwrap();
}

/// Sends one message from the pretend service. False once the client is gone.
pub(crate) fn tell(conn: &Connection, message: &ServerMessage) -> bool {
    conn.write_line(encode(message).unwrap().trim_end()).is_ok()
}

pub(crate) const PASSWORD: &str = "correct-horse-battery";
pub(crate) const CODE: &str = "246810";
pub(crate) const COOKIE: &str = "Zq7-made-up-0123456789";
pub(crate) const ROUTES: &str =
    r#""routes":{"subnets":["10.255.0.0/24"],"dns_domains":["dept.example.test"]}"#;

/// The person at the terminal: answers in order, and keeps what was asked.
#[derive(Default)]
pub(crate) struct Typist {
    pub(crate) answers: VecDeque<Option<&'static str>>,
    pub(crate) asked: Vec<PromptKind>,
    pub(crate) unusable: Option<String>,
    /// Whether a `None` answer is Ctrl-C rather than giving up.
    pub(crate) interrupted: bool,
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
            settings_folder(&rig.root.join("settings"));
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
    as_v1(&settings_text(scene))
}
