//! `connect` with a terminal whose two ways of reading a line are stand-ins.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::Cursor;
use std::rc::Rc;

use ubc_vpn_core::login::PromptKind;
use ubc_vpn_core::redact::Secret;
use ubc_vpn_engine::Prompt;
use ubc_vpn_platform::Error;
use ubc_vpn_platform::terminal::MAX_HIDDEN_LINE_BYTES;

use crate::FAILED;
use crate::connect::{Ask, CANCELLED};
use crate::terminal::{ReadLine, Terminal, read_shown};
use crate::test_support::{CODE, PASSWORD, ROUTES, Scene};

/// What was typed, or how the read failed.
type Typed = Result<&'static str, Error>;

/// Every question asked, with whether the answer was hidden.
type Asked = Rc<RefCell<Vec<(bool, String)>>>;

/// A terminal at which `typed` is typed, in order.
fn terminal(interactive: bool, typed: &[Typed]) -> (Terminal, Asked) {
    let asked = Asked::default();
    let typed: Rc<RefCell<VecDeque<Typed>>> =
        Rc::new(RefCell::new(typed.iter().cloned().collect()));
    let reader = |hidden: bool| -> ReadLine {
        let (asked, typed) = (asked.clone(), typed.clone());
        Box::new(move |question: &str| {
            asked.borrow_mut().push((hidden, question.to_string()));
            let next = typed.borrow_mut().pop_front().expect("asked too much");
            next.map(Secret::new)
        })
    };
    let terminal = Terminal::with(interactive, reader(false), reader(true));
    (terminal, asked)
}

// Security rule: the password and the code are read with nothing shown.
// Only the username is typed in the open.
#[test]
fn only_the_username_is_shown_as_it_is_typed() {
    let scene = Scene::new(Some(&format!("{{{ROUTES}}}")), "");
    let (mut at, asked) = terminal(true, &[Ok("alice"), Ok(PASSWORD), Ok(CODE)]);
    let (code, out, err) = scene.connect(&mut at);
    assert_eq!((code, err.as_str()), (0, ""), "{out}");
    let (shown, hidden) = (false, true);
    assert_eq!(
        *asked.borrow(),
        [
            (shown, "Username: ".to_string()),
            (hidden, "Password: ".to_string()),
            (hidden, "Password: ".to_string()),
        ]
    );
}

// Security rule: without a terminal nothing is asked and nothing is sent,
// so no password is ever read from a pipe or a file.
#[test]
fn outside_a_terminal_nothing_is_asked() {
    let scene = Scene::usual();
    let (mut at, asked) = terminal(false, &[Ok(PASSWORD), Ok(CODE)]);
    let (code, out, err) = scene.connect(&mut at);
    assert_eq!((code, out.as_str()), (FAILED, ""));
    assert!(
        err.contains("Run it in a terminal, or use the app."),
        "{err}"
    );
    assert!(asked.borrow().is_empty() && !scene.gateway_was_asked());
    // The service was left alone: nobody owns it, so another user can
    // still claim it.
    scene.rig.claim_as_someone_else();
}

// Giving up at a question is a cancel. Any other failed read stops the
// login with its reason, and the question is not asked again.
#[test]
fn a_read_that_fails_stops_the_login_once() {
    let unreadable = Error::Failed("made up".to_string());
    let not_text = read_shown("", &mut Cursor::new(b"\xff\xfe\n"), &mut Vec::new());
    let cases = [
        (not_text.unwrap_err(), FAILED, "That username is not text"),
        (Error::Closed, CANCELLED, "Login was cancelled."),
        (Error::NotATerminal, FAILED, "Run it in a terminal"),
        (Error::LineTooLong, FAILED, "That answer is too long"),
        (unreadable, FAILED, "The terminal could not be read"),
    ];
    for (error, status, said) in cases {
        let scene = Scene::usual();
        let (mut at, asked) = terminal(true, &[Err(error.clone()), Ok(PASSWORD), Ok(CODE)]);
        let (code, out, err) = scene.connect(&mut at);
        assert_eq!((code, out.as_str()), (status, ""), "{error:?}: {err}");
        assert!(err.contains(said), "{error:?}: {err}");
        assert_eq!(asked.borrow().len(), 1, "{error:?}");
        assert!(scene.state().contains(r#""state":"disconnected""#));
    }
}

// Security rule: the gateway words the questions, and its wording reaches
// the terminal without control characters.
#[test]
fn a_question_is_written_without_control_characters() {
    let (mut at, asked) = terminal(true, &[Ok(CODE), Ok("alice")]);
    let mut prompt = Prompt {
        kind: PromptKind::Code,
        label: "Co\u{1b}[2Jde".to_string(),
        message: Some("Try\u{1b}[1A again\u{202e}.".to_string()),
    };
    assert!(at.ask(&prompt).is_some());
    (prompt.kind, prompt.message) = (PromptKind::Username, None);
    assert!(at.ask(&prompt).is_some());
    let questions = [
        (true, "Try[1A again.\nCo[2Jde: ".to_string()),
        (false, "Co[2Jde: ".to_string()),
    ];
    assert_eq!(*asked.borrow(), questions);

    // And never longer than the app would show, cut between characters.
    let (mut at, asked) = terminal(true, &[Ok(CODE)]);
    let wide = "\u{1f512}";
    prompt.label = format!("{}{wide}", "l".repeat(199));
    prompt.message = Some("m".repeat(70_000));
    assert!(at.ask(&prompt).is_some());
    let question = format!("{}\n{}: ", "m".repeat(1000), "l".repeat(199));
    assert_eq!(*asked.borrow(), [(false, question)]);
}

// Security rule: a question of a kind this program does not know may have
// a secret for its answer, so that answer is not shown either.
#[test]
fn any_other_question_is_answered_unseen() {
    let (mut at, asked) = terminal(true, &[Ok("made-up-answer")]);
    let prompt = Prompt {
        kind: PromptKind::Text,
        label: "Security question".to_string(),
        message: None,
    };
    assert!(at.ask(&prompt).is_some());
    let hidden = true;
    assert_eq!(
        *asked.borrow(),
        [(hidden, "Security question: ".to_string())]
    );
}

#[test]
fn a_shown_line_is_read_whole_or_not_at_all() {
    let read = |typed: &[u8]| {
        let mut echo = Vec::new();
        let read = read_shown("Username: ", &mut Cursor::new(typed), &mut echo);
        assert_eq!(echo, b"Username: ");
        read.map(|secret| secret.expose().to_string())
    };
    assert_eq!(read(b"alice\nmore\n"), Ok("alice".to_string()));
    assert_eq!(read(b"alice\r\n"), Ok("alice".to_string()));
    assert_eq!(read(b"alice"), Ok("alice".to_string()));
    assert_eq!(read(b"\n"), Ok(String::new()));
    // The end of the input is the user giving up.
    assert_eq!(read(b""), Err(Error::Closed));
    let longest = "a".repeat(MAX_HIDDEN_LINE_BYTES);
    assert_eq!(
        read(format!("{longest}\r\n").as_bytes()),
        Ok(longest.clone())
    );
    assert_eq!(
        read(format!("{longest}a\n").as_bytes()),
        Err(Error::LineTooLong)
    );
    assert_eq!(
        read(format!("{longest}{longest}").as_bytes()),
        Err(Error::LineTooLong)
    );
    assert!(matches!(read(b"\xff\xfe\n"), Err(Error::Failed(_))));
}
