//! The Windows half of `interrupt`: a console control handler, which
//! Windows runs on a thread of its own for each event.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::Duration;

use windows_sys::Win32::System::Console::{CTRL_BREAK_EVENT, CTRL_C_EVENT, SetConsoleCtrlHandler};
use windows_sys::core::BOOL;

use super::security::{last_error, os_error};
use crate::interrupt::Stop;
use crate::{Error, Result, lock, terminal};

static WATCHING: AtomicBool = AtomicBool::new(false);
static REQUESTS: Mutex<Option<Sender<Stop>>> = Mutex::new(None);

/// How long the handler holds on when the console closes, at log-off and at
/// shutdown. Windows ends the program the moment the handler returns, and
/// after about five seconds anyway.
const LAST_MOMENTS: Duration = Duration::from_secs(10);

/// What Windows gives a program it ends for a console event.
const STATUS_CONTROL_C_EXIT: u32 = 0xC000_013A;

pub(crate) fn exit_status(_stop: Stop) -> i32 {
    STATUS_CONTROL_C_EXIT as i32
}

pub(crate) fn watch() -> Result<Receiver<Stop>> {
    if WATCHING.swap(true, Ordering::SeqCst) {
        return Err(Error::AlreadyExists);
    }
    let (requests, receiver) = mpsc::channel();
    *lock(&REQUESTS) = Some(requests);
    // SAFETY: `on_event` is a function of the type a handler must have and
    // lives as long as the program.
    if unsafe { SetConsoleCtrlHandler(Some(on_event), 1) } == 0 {
        return Err(os_error(last_error()));
    }
    Ok(receiver)
}

/// The handler. Returning true tells Windows the event was dealt with, so
/// that it does not end the program for it.
unsafe extern "system" fn on_event(event: u32) -> BOOL {
    handle(event);
    1
}

fn handle(event: u32) {
    let stop = match event {
        CTRL_C_EVENT => Stop::Interrupt,
        _ => Stop::Terminate,
    };
    // Security rule: the terminal is put back before anyone hears of the
    // request, so that no exit, however quick, leaves it silent.
    terminal::restore_after_signal();
    let requests = lock(&REQUESTS).clone();
    // Nobody is listening any more: the request is carried out here, or
    // nothing could stop the program.
    if !requests.is_some_and(|requests| requests.send(stop).is_ok()) {
        std::process::exit(exit_status(stop));
    }
    // For anything but Ctrl-C and Ctrl-Break, Windows ends the program as
    // soon as this returns. The caller needs the time to exit by itself.
    if !matches!(event, CTRL_C_EVENT | CTRL_BREAK_EVENT) {
        thread::sleep(LAST_MOMENTS);
    }
}

#[cfg(feature = "fake")]
pub(crate) fn send_interrupt(child: u32) -> Result<()> {
    use windows_sys::Win32::System::Console::GenerateConsoleCtrlEvent;

    // SAFETY: a plain call. The event goes to the processes of the group
    // with this ID that share the caller's console.
    match unsafe { GenerateConsoleCtrlEvent(CTRL_C_EVENT, child) } {
        0 => Err(os_error(last_error())),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader};
    use std::os::windows::process::CommandExt;
    use std::process::{Child, Command, Stdio};
    use std::sync::mpsc::RecvTimeoutError;
    use std::time::Instant;

    use windows_sys::Win32::System::Console::{
        CTRL_CLOSE_EVENT, ENABLE_ECHO_INPUT, GenerateConsoleCtrlEvent, GetConsoleMode,
    };
    use windows_sys::Win32::System::Threading::{
        CREATE_NEW_CONSOLE, CREATE_NO_WINDOW, DETACHED_PROCESS,
    };

    use super::*;
    use crate::interrupt::{exit_status, watch};
    use crate::os::terminal::console;
    use crate::terminal::read_hidden_line;

    const CHILD: &str = "UBC_VPN_INTERRUPT_CHILD";
    const WAIT: Duration = Duration::from_secs(20);

    /// A child process running `child` below as `kind`, and what it prints.
    struct Program {
        child: Child,
        lines: Receiver<String>,
    }

    impl Program {
        fn start(kind: &str, flags: u32) -> Self {
            let mut child = Command::new(std::env::current_exe().expect("this program"));
            let (_, tests) = module_path!().split_once("::").expect("a module path");
            let name = format!("{tests}::child");
            child.args(["--exact", name.as_str(), "--nocapture", "--test-threads=1"]);
            child
                .env(CHILD, kind)
                .stdout(Stdio::piped())
                .creation_flags(flags);
            let mut child = child.spawn().expect("start the child");
            let printed = BufReader::new(child.stdout.take().expect("its output"));
            let (found, lines) = mpsc::channel();
            thread::spawn(move || {
                for line in printed.lines().map_while(std::io::Result::ok) {
                    let _ = found.send(line);
                }
            });
            Self { child, lines }
        }

        /// The next line the child itself says, past what the test harness
        /// in it prints.
        fn says(&self) -> String {
            loop {
                match self.lines.recv_timeout(WAIT) {
                    Ok(line) => match line.split_once("SAYS ") {
                        Some((_, said)) => return said.to_string(),
                        None => continue,
                    },
                    Err(RecvTimeoutError::Timeout) => panic!("the child said nothing"),
                    Err(RecvTimeoutError::Disconnected) => return "(it ended)".to_string(),
                }
            }
        }

        fn ended(mut self) -> i32 {
            let status = self.child.wait().expect("wait for the child");
            status.code().expect("an exit status")
        }
    }

    impl Drop for Program {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    /// Whether the tests may make consoles: only under CI, where the window
    /// a new console opens is nobody's.
    fn consoles(test: &str) -> bool {
        let ci = std::env::var_os("GITHUB_ACTIONS").is_some();
        match ci {
            true => println!("RAN: {test}"),
            false => println!("SKIPPED: {test} (it would open a window; CI runs it)"),
        }
        ci
    }

    // Real console events, in a console of the child's own: each is
    // delivered, a second too, none ends the program, and the terminal is
    // put back before the first is heard of.
    #[test]
    fn console_events_are_delivered_and_no_longer_end_the_program() {
        if !consoles("interrupt") {
            return;
        }
        let program = Program::start("console", CREATE_NEW_CONSOLE);
        assert_eq!(program.says(), "GOT Interrupt restored=true");
        assert_eq!(program.says(), "GOT Interrupt");
        assert_eq!(program.says(), "GOT Terminate");
        assert_eq!(program.ended(), 7, "it exits when it chooses to");
    }

    // A program that no longer listens must not become one Ctrl-C does
    // nothing to.
    #[test]
    fn a_request_nobody_listens_for_ends_the_program() {
        if !consoles("interrupt unheard") {
            return;
        }
        let program = Program::start("dropped", CREATE_NEW_CONSOLE);
        assert_eq!(program.ended(), exit_status(Stop::Interrupt));
        assert_eq!(exit_status(Stop::Terminate) as u32, 0xC000_013A);
    }

    // What tests of other crates use: a real Ctrl-C from this process to a
    // child in a group of its own on the same console.
    #[cfg(feature = "fake")]
    #[test]
    fn a_real_ctrl_c_can_be_sent_to_a_child() {
        if !consoles("interrupt sent") {
            return;
        }
        let program = Program::start(
            "group",
            windows_sys::Win32::System::Threading::CREATE_NEW_PROCESS_GROUP,
        );
        assert_eq!(program.says(), "READY");
        crate::interrupt::send_interrupt(program.child.id()).expect("send");
        assert_eq!(program.says(), "GOT Interrupt");
    }

    // When the console closes, Windows ends the program the moment the
    // handler returns. So it must not return while the caller tidies up.
    #[test]
    fn the_handler_holds_on_when_the_console_closes() {
        let program = Program::start("close", CREATE_NO_WINDOW);
        assert_eq!(program.says(), "GOT Terminate held=true");
    }

    // A program with no console at all, as one started by a service is.
    #[test]
    fn without_a_console_watching_says_what_it_can_do() {
        let program = Program::start("none", DETACHED_PROCESS);
        assert_eq!(program.says(), "WATCH None");
    }

    // Not a test of its own: the tests above run it in a new process.
    #[test]
    fn child() {
        let Some(kind) = std::env::var_os(CHILD) else {
            return;
        };
        if kind == "none" {
            println!("SAYS WATCH {:?}", watch().err());
            return;
        }
        // A new process group starts with Ctrl-C turned off.
        // SAFETY: a plain call; no handler and "do not ignore".
        unsafe { SetConsoleCtrlHandler(None, 0) };
        let stops = watch().expect("watch");
        assert_eq!(watch().err(), Some(Error::AlreadyExists), "watched twice");
        let event = |event| {
            // SAFETY: a plain call. Group zero is every process on this
            // console, and this console is the child's alone.
            let made = unsafe { GenerateConsoleCtrlEvent(event, 0) };
            assert_ne!(made, 0, "make the event");
        };
        match kind.to_str().expect("a kind") {
            "dropped" => {
                drop(stops);
                event(CTRL_C_EVENT);
                thread::sleep(WAIT);
            }
            "group" => {
                println!("SAYS READY");
                println!(
                    "SAYS GOT {:?}",
                    stops.recv_timeout(WAIT).expect("a request")
                );
            }
            "close" => {
                let handler = thread::spawn(|| handle(CTRL_CLOSE_EVENT));
                let stop = stops.recv_timeout(WAIT).expect("a request");
                thread::sleep(Duration::from_millis(1500));
                println!("SAYS GOT {stop:?} held={}", !handler.is_finished());
            }
            _ => {
                // A hidden question is open when the first event comes.
                let input = console("CONIN$").expect("the console");
                let mode = || {
                    let mut mode = 0;
                    // SAFETY: `mode` is a live integer and the handle open.
                    assert_ne!(unsafe { GetConsoleMode(input.0, &mut mode) }, 0);
                    mode
                };
                let before = mode();
                thread::spawn(|| read_hidden_line("Password: "));
                let started = Instant::now();
                while mode() & ENABLE_ECHO_INPUT != 0 && started.elapsed() < WAIT {
                    thread::sleep(Duration::from_millis(10));
                }
                assert_ne!(mode(), before, "the question changed nothing");
                event(CTRL_C_EVENT);
                let stop = stops.recv_timeout(WAIT).expect("a request");
                println!("SAYS GOT {stop:?} restored={}", mode() == before);
                event(CTRL_C_EVENT);
                println!("SAYS GOT {:?}", stops.recv_timeout(WAIT).expect("a second"));
                event(CTRL_BREAK_EVENT);
                println!("SAYS GOT {:?}", stops.recv_timeout(WAIT).expect("a third"));
                std::process::exit(7);
            }
        }
    }
}
