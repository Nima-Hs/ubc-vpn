//! `connect --json`, with a stand-in for the app on a thread of its own, on
//! the other end of two pipes.

use std::io::{BufRead, BufReader, Lines, PipeReader, PipeWriter, Write};
use std::time::{Duration, Instant};

use ubc_vpn_core::login::{CliMessage, LoginErrorCode};
use ubc_vpn_core::policy::Policy;
use ubc_vpn_core::protocol::{ErrorCode, ErrorInfo, MAX_LINE_BYTES, decode};
use ubc_vpn_core::redact::Secret;
use ubc_vpn_engine::fake::{FakeEngine, Script};
use ubc_vpn_engine::{Cancel, Gateway, LogSink, LoginEngine, LoginError, Prompts, Session};

use crate::client::ClientError;
use crate::connect::{BUSY, CANCELLED, LOGIN_REFUSED, stop};
use crate::connect_json::connect;
use crate::connect_tests::{CODE, COOKIE, PASSWORD, ROUTES, Scene, Typist, brief, pin};
use crate::{FAILED, NOT_OWNER, NOT_RUNNING};

/// What the command writes, line by line, as the app reads it.
type FromCli = Lines<BufReader<PipeReader>>;

/// Runs `connect --json` in `scene`, logging in through `engine`, with `app`
/// playing the app. `app` is given the command's output and its input, and
/// what it returns is handed back with the exit status and standard error.
///
/// Every `app` here ends by itself, and when it does its end of the input
/// closes, which stops the command: so a test fails where it could hang.
fn drive_through<T: Send + 'static>(
    scene: &Scene,
    engine: &dyn Fn() -> Box<dyn LoginEngine>,
    app: impl FnOnce(FromCli, PipeWriter) -> T + Send + 'static,
) -> (u8, T, String) {
    let (from_cli, mut out) = std::io::pipe().unwrap();
    let (input, to_cli) = std::io::pipe().unwrap();
    let playing = std::thread::spawn(move || app(BufReader::new(from_cli).lines(), to_cli));
    let platform = || Ok(scene.rig.fake.platform(&scene.rig.root));
    let engines = |_: &Policy| Some(engine());
    let mut err = Vec::new();
    let input = BufReader::new(input);
    let code = connect(&platform, &engines, input, brief(), &mut out, &mut err);
    drop(out);
    let played = playing.join().unwrap();
    (code, played, String::from_utf8(err).unwrap())
}

fn drive<T: Send + 'static>(
    scene: &Scene,
    app: impl FnOnce(FromCli, PipeWriter) -> T + Send + 'static,
) -> (u8, T, String) {
    drive_through(scene, &|| Box::new(scene.gateway.clone()), app)
}

fn answer(to_cli: &mut PipeWriter, id: u32, value: &str) {
    writeln!(to_cli, r#"{{"type":"answer","id":{id},"value":"{value}"}}"#).unwrap();
}

/// An app that answers each question with the next of `answers`, cancels
/// when it has none left, and returns every line it was sent.
fn answering(answers: &'static [&'static str]) -> impl FnOnce(FromCli, PipeWriter) -> Vec<String> {
    move |lines, mut to_cli| {
        let mut answers = answers.iter();
        let mut seen = Vec::new();
        for line in lines {
            let line = line.unwrap();
            if let Ok(CliMessage::Prompt { id, .. }) = decode(&line) {
                match answers.next() {
                    Some(value) => answer(&mut to_cli, id, value),
                    None => writeln!(to_cli, r#"{{"type":"cancel"}}"#).unwrap(),
                }
            }
            seen.push(line);
        }
        seen
    }
}

fn error_line(code: &str, message: &str) -> String {
    format!(r#"{{"type":"error","code":"{code}","message":"{message}"}}"#)
}

fn wait_until(what: &str, done: impl Fn() -> bool) {
    let patience = Instant::now() + Duration::from_secs(5);
    while !done() {
        assert!(Instant::now() < patience, "waited too long for {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

const CANCELLED_LINE: &str = "Login was cancelled.";

/// Runs `connect --json` while the login waits on the gateway with every
/// question answered. `act` is the app's next move; it gives its end of the
/// input back to keep it open, or drops it. Returns the exit status and the
/// lines the command wrote after that.
fn while_the_login_waits(
    act: impl FnOnce(PipeWriter) -> Option<PipeWriter> + Send + 'static,
) -> (u8, Vec<String>, Scene) {
    let scene = Scene::usual();
    scene.gateway.hold();
    let gateway = scene.gateway.clone();
    let (code, rest, _) = drive(&scene, move |mut lines, mut to_cli| {
        for (id, value) in [(1, PASSWORD), (2, CODE)] {
            lines.next().unwrap().unwrap();
            answer(&mut to_cli, id, value);
        }
        wait_until("the answers to arrive", || gateway.answers().len() == 2);
        let kept_open = act(to_cli);
        // A login that this did not stop would wait for ever. It is let go
        // after a while, and would then succeed and fail the test.
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(2));
            gateway.release();
        });
        let rest: Vec<String> = lines.map(Result::unwrap).collect();
        drop(kept_open);
        rest
    });
    (code, rest, scene)
}

#[test]
fn the_app_is_asked_and_told_done_once_the_service_accepts() {
    let mut scene = Scene::usual();
    // The service's own gateway is slow to open the tunnel.
    let slow = FakeEngine::new(Script::new(pin()));
    slow.hold();
    scene.service = None;
    scene.service = Some(scene.rig.service_on(slow.clone()));
    let let_go = slow.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(2));
        let_go.release();
    });

    let (code, lines, err) = drive(&scene, answering(&[PASSWORD, CODE]));
    assert_eq!((code, err.as_str()), (0, ""));
    assert_eq!(
        lines,
        [
            r#"{"type":"prompt","id":1,"kind":"password","label":"Password"}"#,
            r#"{"type":"prompt","id":2,"kind":"code","label":"Password"}"#,
            r#"{"type":"done"}"#,
        ]
    );
    // "done" means accepted: the command has ended and the service is still
    // connecting. It carries on from there.
    assert!(scene.state().contains(r#""state":"connecting""#));
    slow.release();
    wait_until("the connection", || {
        scene.state().contains(r#""state":"connected""#)
    });
    // Security rule: no answer and no cookie in anything the app is sent.
    let shown = [lines.concat(), scene.state()].concat();
    for secret in [PASSWORD, CODE, COOKIE] {
        assert!(!shown.contains(secret), "{secret} was shown");
    }
}

// Security rule: a cancel stops a login that is waiting on the gateway, not
// only one that is waiting for an answer, and nothing is then connected. So
// does the app going away.
#[test]
fn a_cancel_or_a_closed_input_stops_a_login_that_is_waiting() {
    let cancel = |mut to_cli: PipeWriter| {
        writeln!(to_cli, r#"{{"type":"cancel"}}"#).unwrap();
        Some(to_cli)
    };
    let close = |_| None;
    for (code, last, scene) in [while_the_login_waits(cancel), while_the_login_waits(close)] {
        assert_eq!(code, CANCELLED);
        assert_eq!(last, [error_line("cancelled", CANCELLED_LINE)]);
        assert!(scene.state().contains(r#""state":"disconnected""#));
    }
}

// Answers nobody asked for are not kept without end: an app that sends
// them is given up on.
#[test]
fn answers_to_no_question_are_not_piled_up() {
    let (code, last, _) = while_the_login_waits(|mut to_cli| {
        for _ in 0..20 {
            // The command stops reading part-way through these.
            let _ = writeln!(to_cli, r#"{{"type":"answer","id":3,"value":"made-up"}}"#);
        }
        Some(to_cli)
    });
    assert_eq!(code, CANCELLED);
    assert_eq!(last, [error_line("cancelled", CANCELLED_LINE)]);
}

/// A login that takes no notice of a cancel until it is too late, and may
/// then still ask a question.
struct TooLate {
    asks: bool,
}

impl LoginEngine for TooLate {
    fn login(
        &self,
        _: &Gateway,
        prompts: &mut Prompts<'_>,
        cancel: &Cancel,
        _: &LogSink,
    ) -> Result<Session, LoginError> {
        wait_until("the cancel", || cancel.is_cancelled());
        if self.asks {
            let script = Script::new(pin());
            prompts.ask(&script.form[1].0)?;
        }
        Ok(Session {
            cookie: Secret::new(COOKIE),
            gateway_addr: [192, 0, 2, 1].into(),
        })
    }
}

// Security rule: a session that arrives after the user gave up is thrown
// away, not handed to the service. And nothing is asked of a user who gave
// up.
#[test]
fn nothing_is_asked_or_used_after_a_cancel() {
    for asks in [false, true] {
        let scene = Scene::usual();
        let engine = || Box::new(TooLate { asks }) as Box<dyn LoginEngine>;
        let (code, lines, _) = drive_through(&scene, &engine, |lines, to_cli| {
            drop(to_cli);
            lines.map(Result::unwrap).collect::<Vec<_>>()
        });
        assert_eq!(code, CANCELLED, "asks: {asks}");
        assert_eq!(lines, [error_line("cancelled", CANCELLED_LINE)]);
        assert!(scene.state().contains(r#""state":"disconnected""#));
    }
}

// Each way of failing has the code the app acts on, and the exit status the
// terminal command gives for it. A connect that could not succeed asks the
// app nothing.
#[test]
fn every_failure_has_its_code() {
    let usual = format!(r#"{{"username":"alice",{ROUTES}}}"#);
    let fails = |scene: &Scene, answers, code: &str, status: u8, said: &str| {
        let (exit, lines, _) = drive(scene, answering(answers));
        let last = lines.last().unwrap();
        let start = format!(r#"{{"type":"error","code":"{code}","message":""#);
        assert!(last.starts_with(&start) && last.contains(said), "{last}");
        assert_eq!(exit, status, "{last}");
        lines.len() - 1
    };

    let before_asking: [(Option<&str>, &str, &str, &str); 3] = [
        (None, "", "route_refused", "saved routes cannot be used"),
        (
            Some("not json"),
            "",
            "internal",
            "settings file cannot be read",
        ),
        (Some(&usual), r#","pins":[]"#, "internal", "policy file is"),
    ];
    for (settings, policy_extra, code, said) in before_asking {
        let scene = Scene::new(settings, policy_extra);
        assert_eq!(fails(&scene, &[], code, FAILED, said), 0);
        assert!(!scene.gateway_was_asked());
    }

    let mut scene = Scene::usual();
    scene.service = None;
    let said = "service is not running";
    assert_eq!(
        fails(&scene, &[], "service_unavailable", NOT_RUNNING, said),
        0
    );

    let scene = Scene::usual();
    scene.rig.claim_as_someone_else();
    assert_eq!(
        fails(&scene, &[], "not_owner", NOT_OWNER, "not the owner"),
        0
    );

    let scene = Scene::usual();
    let mut typist = Typist::typing(&[Some(PASSWORD), Some(CODE)]);
    assert_eq!(scene.connect(&mut typist).0, 0);
    assert_eq!(fails(&scene, &[], "busy", BUSY, "disconnect` first"), 0);

    // The gateway's side. Only a wrong answer comes after questions.
    let scene = Scene::usual();
    let wrong: &[&str] = &["wrong-password-0000", CODE, PASSWORD];
    let asked = fails(&scene, wrong, "wrong_password", LOGIN_REFUSED, "rejected");
    assert_eq!(asked, 2, "nothing is asked twice");

    let scene = Scene::usual();
    scene.gateway.set_reachable(false);
    let said = "could not be reached";
    assert_eq!(fails(&scene, &[], "gateway_unreachable", FAILED, said), 0);

    let mut scene = Scene::usual();
    let other = format!("pin-sha256:{}=", "B".repeat(43));
    scene.gateway = FakeEngine::new(Script::new(other.try_into().unwrap()));
    assert_eq!(fails(&scene, &[], "pin_mismatch", FAILED, "certificate"), 0);
}

// What the service can answer, as the app is told it.
#[test]
fn the_services_answers_have_their_codes() {
    let refused = |code| {
        let message = "made up".to_string();
        ClientError::Refused(ErrorInfo { code, message })
    };
    let cases = [
        (refused(ErrorCode::Busy), LoginErrorCode::Busy),
        (refused(ErrorCode::NotOwner), LoginErrorCode::NotOwner),
        (
            refused(ErrorCode::RouteRefused),
            LoginErrorCode::RouteRefused,
        ),
        (refused(ErrorCode::Internal), LoginErrorCode::Internal),
        (ClientError::NotOwner, LoginErrorCode::NotOwner),
        // Not there, not the same version, not the service, or gone.
        (ClientError::NotRunning, LoginErrorCode::ServiceUnavailable),
        (
            ClientError::Mismatch(None),
            LoginErrorCode::ServiceUnavailable,
        ),
        (
            ClientError::NotTheService,
            LoginErrorCode::ServiceUnavailable,
        ),
        (
            ClientError::Lost("made up".to_string()),
            LoginErrorCode::ServiceUnavailable,
        ),
    ];
    for (error, code) in cases {
        let named = format!("{error:?}");
        assert_eq!(stop(error).code, code, "{named}");
    }
}

// Security rule: an app that does not follow the conversation is given up
// on, the login with it, and what it sent is never repeated back.
#[test]
fn an_app_that_makes_no_sense_ends_the_login() {
    const NONSENSE: &str = "hunter2-made-up-not-json";
    let said = "The app sent something that is not an answer to the question asked.";
    let answer_to =
        |id: u32, value: &str| format!(r#"{{"type":"answer","id":{id},"value":"{value}"}}"#);
    let replies = [
        // The answer to another question.
        answer_to(7, PASSWORD),
        NONSENSE.to_string(),
        r#"{"type":"answer","id":1,"value":"correct-horse-battery","more":1}"#.to_string(),
        // A line one byte longer than a message may be.
        answer_to(1, &"x".repeat(MAX_LINE_BYTES - answer_to(1, "").len())),
    ];
    for reply in replies {
        let scene = Scene::usual();
        let (code, lines, err) = drive(&scene, move |mut lines, mut to_cli| {
            let question = lines.next().unwrap().unwrap();
            // The command may stop reading part-way through a long line.
            let _ = writeln!(to_cli, "{reply}");
            // Its end of the input closes here, so that a command which
            // went on to another question would be stopped.
            drop(to_cli);
            let mut seen = vec![question];
            seen.extend(lines.map(Result::unwrap));
            seen
        });
        assert_eq!(code, FAILED);
        assert_eq!(lines.len(), 2, "one question, then the end: {lines:?}");
        assert_eq!(lines[1], error_line("internal", said));
        assert!(scene.state().contains(r#""state":"disconnected""#));
        assert!(!lines.concat().contains(NONSENSE) && !err.contains(NONSENSE));
    }

    // The same while the login waits on the gateway and nothing is asked.
    let (code, lines, scene) = while_the_login_waits(|mut to_cli| {
        writeln!(to_cli, "{NONSENSE}").unwrap();
        Some(to_cli)
    });
    assert_eq!((code, lines), (FAILED, vec![error_line("internal", said)]));
    assert!(scene.state().contains(r#""state":"disconnected""#));
}

// Security rule: the gateway words the questions, and its wording reaches
// the app without control characters.
#[test]
fn a_question_reaches_the_app_without_control_characters() {
    let mut scene = Scene::usual();
    let mut script = Script::new(pin());
    script.form[1].0.label = "Pass\u{1b}[2J\u{202e}word".to_string();
    scene.gateway = FakeEngine::new(script);
    let (code, lines, _) = drive(&scene, answering(&[PASSWORD]));
    assert_eq!(code, 0);
    let asked = r#"{"type":"prompt","id":1,"kind":"password","label":"Pass[2Jword"}"#;
    assert_eq!(lines[0], asked);
}
