//! Real interrupts sent to a real `ubc-vpn connect` in a terminal of its
//! own, against a real dev-mode service: at the username, at the password,
//! at the one-time code, and while the connect request is with the service.
//!
//! After each, the program has ended with the status that is usual for an
//! interrupt, the terminal shows what is typed again, nothing that was typed
//! unseen has appeared, and the service is not left connecting.
//!
//! Linux and macOS only: a test can give a child a terminal of its own
//! there and nowhere else. It runs when `UBC_VPN_SYSTEM_SERVICE` names a
//! service built with the `dev-mode` feature, and says `RAN: interrupts`
//! when it has, as the system test does.
//!
//! How each case is arranged:
//!
//! - `connect` is started by a small shell script that stays in the
//!   terminal after it. So the terminal outlives `connect`, and the test can
//!   ask whether it echoes, see the exit status the shell prints, and type
//!   one more line to see it shown.
//! - Ctrl-C is typed into the terminal, which is what sends the interrupt.
//!   At a hidden question the terminal hands it over as a key; one case
//!   there sends the signal from outside as well.
//! - The dev-mode service connects in a few milliseconds, which leaves no
//!   time to interrupt. To have a connect request with the service and not
//!   yet answered, the service is paused with `SIGSTOP` once the last
//!   question is on the screen, and resumed after the interrupt.
#![cfg(all(feature = "dev-mode", unix))]

mod support;

use std::path::Path;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use support::{CODE, Home, PASSWORD, ROUTES, Running, SERVICE, USERNAME, within};
use ubc_vpn_platform::interrupt::send_interrupt;
use ubc_vpn_platform::terminal::testing::{Screen, spawn_in_terminal};

const SOON: Duration = Duration::from_secs(15);
const CTRL_C: &str = "\x03";
/// Typed at a hidden question and never entered. It must not be seen.
const BLIND: &str = "typed-blind-and-never-shown";
/// The shell prints this after `connect` has ended with the status for an
/// interrupt.
const INTERRUPTED: &str = "EXIT:130";

/// `connect` in a terminal of its own, under a shell that outlives it. The
/// shell is ended when the test lets go of this, however the test ends.
struct Session {
    shell: Child,
    screen: Screen,
}

impl Session {
    fn start(home: &Home) -> Self {
        // The trap keeps the shell alive through the interrupt; a trap is
        // not handed on to `connect`, which starts with the usual handling.
        let script = r#"trap : INT; "$0" --dev connect; echo "EXIT:$?"; read line"#;
        let mut command = Command::new("sh");
        command.args(["-c", script, env!("CARGO_BIN_EXE_ubc-vpn")]);
        command.envs(home.variables.iter().cloned());
        let (shell, screen) = spawn_in_terminal(&mut command).expect("a terminal");
        Self { shell, screen }
    }

    fn sees(&mut self, text: &str) -> String {
        self.screen.expect(text, SOON).unwrap()
    }

    fn types(&mut self, text: &str) {
        self.screen.type_text(text).unwrap();
    }

    /// Waits until the terminal has stopped showing what is typed, as it
    /// does for a hidden question.
    fn hides_typing(&self) {
        within("the terminal to stop echoing", || {
            (!self.screen.echoes().unwrap()).then_some(())
        });
    }

    /// The process `connect` itself, which the shell started.
    fn connect_id(&self) -> u32 {
        let parent = self.shell.id().to_string();
        within("connect to be running", || {
            let found = Command::new("pgrep").args(["-P", &parent]).output();
            let found = String::from_utf8(found.expect("pgrep runs").stdout).ok()?;
            found.lines().next()?.trim().parse().ok()
        })
    }

    /// What must hold after an interrupt, whatever point it came at. Ends
    /// the shell and returns everything the screen showed.
    fn ended_by_the_interrupt(mut self) -> String {
        self.sees(INTERRUPTED);
        // The terminal is as a person expects it: what is typed is shown.
        assert!(self.screen.echoes().unwrap(), "echo is still off");
        self.types("seen-after\r");
        let shown = self.sees("seen-after");
        let ended = within("the shell to end", || self.shell.try_wait().unwrap());
        assert!(ended.success(), "{ended:?}");
        for unseen in [BLIND, PASSWORD, CODE] {
            assert!(
                !shown.contains(unseen),
                "{unseen} is on the screen:\n{shown}"
            );
        }
        shown
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.shell.kill();
        let _ = self.shell.wait();
    }
}

/// A paused process, resumed when the test lets go of it, however it ends.
struct Paused(u32);

fn signal(name: &str, process: u32) {
    let sent = Command::new("kill")
        .args([name, &process.to_string()])
        .status();
    assert!(sent.expect("kill runs").success(), "kill {name} {process}");
}

impl Paused {
    fn pause(process: u32) -> Self {
        signal("-STOP", process);
        Self(process)
    }
}

impl Drop for Paused {
    fn drop(&mut self) {
        let _ = Command::new("kill")
            .args(["-CONT", &self.0.to_string()])
            .status();
    }
}

#[test]
fn an_interrupt_leaves_the_terminal_and_the_service_as_they_should_be() {
    let Some(service) = std::env::var_os(SERVICE) else {
        eprintln!("SKIPPED: interrupts: {SERVICE} does not name a dev-mode service");
        return;
    };
    let home = Home::new();
    let state = |state: &str| format!(r#""state":"{state}""#);
    let disconnected = (0, "Disconnected".to_string());
    let service = Running::start(home.command(Path::new(&service), &[]), &home.said);
    let first = within("the service to listen", || {
        let (status, out) = home.run(&["status"], "");
        (status != 3).then_some((status, out))
    });
    assert_eq!(first, disconnected);
    assert_eq!(home.run(&["settings", "set-routes", "--json"], ROUTES).0, 0);
    // What the service does is watched through a bridge, as the app would.
    let mut bridge = home.client(&["bridge"]);
    bridge.until(r#""type":"ready""#);

    // At the username: the terminal turns Ctrl-C into the interrupt.
    let mut session = Session::start(&home);
    session.sees("Username: ");
    session.types(CTRL_C);
    session.ended_by_the_interrupt();
    assert_eq!(home.run(&["status"], ""), disconnected);

    // At the password, which is hidden: Ctrl-C arrives as a key.
    let mut session = Session::start(&home);
    session.sees("Username: ");
    session.types(&format!("{USERNAME}\r"));
    session.sees("Password: ");
    session.hides_typing();
    session.types(BLIND);
    session.types(CTRL_C);
    session.ended_by_the_interrupt();

    // At the password again, with the interrupt sent from outside: what
    // `kill` or a closing window would do. The program is not in the
    // terminal's hands then, and still has to put the terminal back.
    let mut session = Session::start(&home);
    session.sees("Username: ");
    session.types(&format!("{USERNAME}\r"));
    session.sees("Password: ");
    session.hides_typing();
    session.types(BLIND);
    send_interrupt(session.connect_id()).unwrap();
    session.ended_by_the_interrupt();

    // At the one-time code, with the password already given.
    let mut session = Session::start(&home);
    session.sees("Username: ");
    session.types(&format!("{USERNAME}\r"));
    session.sees("Password: ");
    session.types(&format!("{PASSWORD}\r"));
    session.sees("One-time code: ");
    session.hides_typing();
    session.types(CTRL_C);
    session.ended_by_the_interrupt();

    // At the one-time code, with the code entered and Ctrl-C typed in the
    // same instant, so that it is waiting as a key when Enter is read. The
    // user changed their mind in time: it interrupts, and the code that
    // was entered is used for nothing.
    let mut session = Session::start(&home);
    session.sees("Username: ");
    session.types(&format!("{USERNAME}\r"));
    session.sees("Password: ");
    session.types(&format!("{PASSWORD}\r"));
    session.sees("One-time code: ");
    session.hides_typing();
    session.types(&format!("{CODE}\r{CTRL_C}"));
    session.ended_by_the_interrupt();
    // Nothing reached the service in any of these.
    assert_eq!(home.run(&["status"], ""), disconnected);

    // While the connect request is with the service. The service is paused
    // once the last question is asked, so the request waits unanswered.
    let answers_all = |session: &mut Session| {
        session.sees("Username: ");
        session.types(&format!("{USERNAME}\r"));
        session.sees("Password: ");
        session.types(&format!("{PASSWORD}\r"));
        session.sees("One-time code: ");
    };
    let mut session = Session::start(&home);
    answers_all(&mut session);
    let paused = Paused::pause(service.child.id());
    session.types(&format!("{CODE}\r"));
    // Time for the login to finish and the request to go. Nothing shows
    // when it has; the bridge below fails the test if this was too short.
    std::thread::sleep(Duration::from_secs(1));
    session.types(CTRL_C);
    // The program is now telling the service to disconnect, and waiting to
    // be heard. The service wakes and hears both.
    std::thread::sleep(Duration::from_millis(300));
    drop(paused);
    session.ended_by_the_interrupt();
    // The request had gone: the service began to connect. And it was
    // undone: the service is not left connected with nobody watching.
    bridge.until(&state("connecting"));
    within("the service to be disconnected again", || {
        (home.run(&["status"], "") == disconnected).then_some(())
    });

    // The same, and a second Ctrl-C while the first is still being seen to:
    // the program ends at once, without waiting to be heard.
    let mut session = Session::start(&home);
    answers_all(&mut session);
    let paused = Paused::pause(service.child.id());
    session.types(&format!("{CODE}\r"));
    std::thread::sleep(Duration::from_secs(1));
    let first = Instant::now();
    session.types(CTRL_C);
    std::thread::sleep(Duration::from_millis(300));
    session.types(CTRL_C);
    session.sees(INTERRUPTED);
    let took = first.elapsed();
    // Well inside the three seconds the first would have waited.
    assert!(took < Duration::from_millis(2500), "it waited {took:?}");
    session.ended_by_the_interrupt();
    drop(paused);
    // The program was gone before the service woke, so it never told the
    // service to disconnect. The service admits the connect, finds it
    // cannot answer the one who asked, and undoes the connect itself
    // (#163): it is not left connected with nobody watching.
    bridge.until(&state("connecting"));
    within(
        "the service to undo the connect of a client that went",
        || {
            let (_, logged) = home.run(&["logs"], "");
            logged
                .contains("went before hearing the answer")
                .then_some(())
        },
    );
    within("the service to be disconnected after that", || {
        (home.run(&["status"], "") == disconnected).then_some(())
    });
    // `disconnect` still answers as the help says, with nothing to undo.
    assert_eq!(home.run(&["disconnect"], ""), disconnected);

    let (status, _) = bridge.end();
    assert_eq!(status, 0);
    drop(service);
    // No password or code in anything the programs wrote outside a terminal.
    let said = home.said.lock().unwrap().clone();
    for secret in [PASSWORD, CODE, BLIND] {
        assert!(!said.contains(secret), "{secret} was written:\n{said}");
    }
    println!("RAN: interrupts");
}
