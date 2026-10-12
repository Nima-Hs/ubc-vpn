//! The Linux and macOS half of `interrupt`: signals, a pipe and a thread.

use std::io::{self, Read};
use std::os::fd::{BorrowedFd, IntoRawFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;

use libc::{SIGHUP, SIGINT, SIGTERM, c_int};

use crate::interrupt::Stop;
use crate::{Error, Result, terminal};

static WATCHING: AtomicBool = AtomicBool::new(false);
/// The end of the pipe the handler writes to. Never closed, so the handler
/// can use it at any moment.
static PIPE: AtomicI32 = AtomicI32::new(-1);
/// The process that watches. A child made by `fork` is not it.
static WATCHER: AtomicI32 = AtomicI32::new(0);

pub(crate) fn exit_status(stop: Stop) -> i32 {
    match stop {
        Stop::Interrupt => 128 + SIGINT,
        Stop::Terminate => 128 + SIGTERM,
    }
}

pub(crate) fn watch() -> Result<Receiver<Stop>> {
    if WATCHING.swap(true, Ordering::SeqCst) {
        return Err(Error::AlreadyExists);
    }
    let (pipe, handlers_end) = UnixStream::pair()?;
    // The handler must never wait: a full pipe drops the byte instead.
    handlers_end.set_nonblocking(true)?;
    PIPE.store(handlers_end.into_raw_fd(), Ordering::SeqCst);
    WATCHER.store(std::process::id() as i32, Ordering::SeqCst);
    let (requests, receiver) = mpsc::channel();
    let forwarder = thread::Builder::new().name("stop requests".to_string());
    forwarder.spawn(move || forward(pipe, &requests))?;
    for signal in [SIGINT, SIGTERM, SIGHUP] {
        handle(signal)?;
    }
    Ok(receiver)
}

/// Sends on what the handler wrote, one request for each byte.
fn forward(mut pipe: UnixStream, requests: &Sender<Stop>) {
    loop {
        let mut signal = [0];
        match pipe.read(&mut signal) {
            Ok(0) => return,
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return,
        }
        let stop = match c_int::from(signal[0]) {
            SIGINT => Stop::Interrupt,
            _ => Stop::Terminate,
        };
        // Nobody is listening any more: the request is carried out here, or
        // nothing could stop the program.
        if requests.send(stop).is_err() {
            std::process::exit(exit_status(stop));
        }
    }
}

/// Has `signal` call `on_signal`, unless the program was started with it
/// ignored.
fn handle(signal: c_int) -> io::Result<()> {
    // SAFETY: a zeroed `sigaction` is a valid value of that plain C struct,
    // every pointer passed is to one that lives across the call or is null
    // where the call allows it, and `on_signal` is a function of the type a
    // handler without `SA_SIGINFO` must have, which lives as long as the
    // program.
    unsafe {
        let mut old: libc::sigaction = std::mem::zeroed();
        if libc::sigaction(signal, std::ptr::null(), &mut old) != 0 {
            return Err(io::Error::last_os_error());
        }
        if old.sa_sigaction == libc::SIG_IGN {
            return Ok(());
        }
        let mut new: libc::sigaction = std::mem::zeroed();
        new.sa_sigaction = on_signal as extern "C" fn(c_int) as usize;
        // What the signal interrupted goes on afterwards, as far as it can.
        new.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&mut new.sa_mask);
        if libc::sigaction(signal, &new, std::ptr::null_mut()) != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Where this thread's `errno` is.
fn errno() -> *mut c_int {
    // SAFETY: the call has no conditions and returns a valid pointer that
    // is this thread's own.
    #[cfg(target_os = "macos")]
    return unsafe { libc::__error() };
    // SAFETY: as above.
    #[cfg(not(target_os = "macos"))]
    return unsafe { libc::__errno_location() };
}

/// The signal handler. It may run at any moment on any thread, so it makes
/// only calls that are safe then: the terminal's (see
/// `terminal::restore_after_signal`) and one `write`. It takes no lock and
/// does not allocate.
extern "C" fn on_signal(signal: c_int) {
    // SAFETY: `errno` returns a valid pointer of this thread's own. What the
    // handler interrupted may be about to read the value.
    let before = unsafe { *errno() };
    // A child this program has made, in the moment before it becomes
    // another program, still has this handler and the pipe. The signal was
    // sent to the child, not to this program: no request comes of it, and
    // the child ends as it would have with no handler at all.
    // SAFETY: the call is safe in a signal handler and has no conditions.
    let me = unsafe { libc::getpid() };
    if me != WATCHER.load(Ordering::SeqCst) {
        // SAFETY: both calls are safe in a signal handler and have no other
        // conditions. The signal raised is held back until this handler
        // returns, and then meets its default action.
        unsafe {
            libc::signal(signal, libc::SIG_DFL);
            libc::raise(signal);
        }
        return;
    }
    // Security rule: the terminal is put back before anyone hears of the
    // request, so that no exit, however quick, leaves it silent.
    terminal::restore_after_signal();
    let pipe = PIPE.load(Ordering::SeqCst);
    if pipe >= 0 {
        // SAFETY: the descriptor was open when it was stored and is never
        // closed.
        let pipe = unsafe { BorrowedFd::borrow_raw(pipe) };
        let _ = rustix::io::write(pipe, &[signal as u8]);
    }
    // SAFETY: as for the read above.
    unsafe { *errno() = before };
}

#[cfg(feature = "fake")]
pub(crate) fn send_interrupt(child: u32) -> Result<()> {
    use rustix::process::{Pid, Signal, kill_process};

    let child = i32::try_from(child).ok().and_then(Pid::from_raw);
    let child = child.ok_or_else(|| Error::Failed("not a process ID".to_string()))?;
    Ok(kill_process(child, Signal::INT).map_err(io::Error::from)?)
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader};
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use std::process::{Child, Command, Stdio};
    use std::sync::mpsc::RecvTimeoutError;
    use std::time::Duration;

    use rustix::fs::{Mode, OFlags, open};
    use rustix::process::{ioctl_tiocsctty, setsid};
    use rustix::pty::ptsname;
    use rustix::termios::{LocalModes, tcgetattr};

    use super::*;
    use crate::interrupt::{exit_status, watch};
    use crate::terminal::read_hidden_line;
    use crate::unix::terminal::tests::{pty, read_from};

    const CHILD: &str = "UBC_VPN_INTERRUPT_CHILD";
    const TERMINAL: &str = "UBC_VPN_INTERRUPT_TERMINAL";
    const WAIT: Duration = Duration::from_secs(20);

    /// A child process running `child` below as `kind`, and what it prints.
    struct Program {
        child: Child,
        lines: Receiver<String>,
    }

    impl Program {
        fn start(kind: &str, adjust: impl FnOnce(&mut Command)) -> Self {
            let mut child = Command::new(std::env::current_exe().expect("this program"));
            let (_, tests) = module_path!().split_once("::").expect("a module path");
            let name = format!("{tests}::child");
            child.args(["--exact", name.as_str(), "--nocapture", "--test-threads=1"]);
            child.env(CHILD, kind).stdout(Stdio::piped());
            adjust(&mut child);
            let mut child = child.spawn().expect("start the child");
            let printed = BufReader::new(child.stdout.take().expect("its output"));
            let (found, lines) = mpsc::channel();
            thread::spawn(move || {
                for line in printed.lines().map_while(io::Result::ok) {
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

        fn signal(&self, signal: c_int) {
            // SAFETY: the call has no memory-safety conditions, and the
            // child has not been waited for, so the ID is still its own.
            let sent = unsafe { libc::kill(self.child.id() as i32, signal) };
            assert_eq!(sent, 0, "send signal {signal}");
        }

        /// How it ended: its exit status, or minus the signal that killed it.
        fn ended(mut self) -> i32 {
            let status = self.child.wait().expect("wait for the child");
            status
                .code()
                .or(status.signal().map(|signal| -signal))
                .expect("an end")
        }
    }

    impl Drop for Program {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    // Each kind of request is delivered, a second and a third too, and none
    // of them ends the program: it ends itself, with the status it is given.
    #[test]
    fn requests_are_delivered_and_no_longer_end_the_program() {
        let program = Program::start("watch", |_| {});
        assert_eq!(program.says(), "READY");
        for (signal, stop) in [
            (SIGINT, "Interrupt"),
            (SIGINT, "Interrupt"),
            (SIGHUP, "Terminate"),
        ] {
            program.signal(signal);
            assert_eq!(program.says(), format!("GOT {stop}"));
        }
        // The helper tests of other crates use, which needs no unsafe code.
        #[cfg(feature = "fake")]
        crate::interrupt::send_interrupt(program.child.id()).expect("send");
        #[cfg(not(feature = "fake"))]
        program.signal(SIGINT);
        assert_eq!(program.says(), "GOT Interrupt");
        program.signal(SIGTERM);
        assert_eq!(program.says(), "GOT Terminate");
        assert_eq!(program.ended(), 143, "the status it exits with");
        assert_eq!(
            (exit_status(Stop::Interrupt), exit_status(Stop::Terminate)),
            (130, 143)
        );
    }

    // A program that no longer listens must not become one Ctrl-C does
    // nothing to.
    #[test]
    fn a_request_nobody_listens_for_ends_the_program() {
        let program = Program::start("dropped", |_| {});
        assert_eq!(program.says(), "READY");
        program.signal(SIGINT);
        assert_eq!(program.ended(), 130);
    }

    // A child the program makes still has the handler in the moment before
    // it becomes another program. A signal sent to it then is the child's
    // own: it ends the child, and the program hears of no request.
    #[test]
    fn a_signal_to_a_forked_child_is_not_a_request() {
        let program = Program::start("fork", |_| {});
        let forked = program.says();
        let forked = forked.strip_prefix("FORKED ").expect("its ID");
        let forked: i32 = forked.parse().expect("a number");
        // SAFETY: the call has no memory-safety conditions, and the ID is
        // of a process the child has not waited for yet.
        assert_eq!(unsafe { libc::kill(forked, SIGINT) }, 0, "send");
        assert_eq!(program.says(), format!("FORK ENDED by={SIGINT} requests=0"));
    }

    // A program started with a signal ignored, as under `nohup`, keeps
    // ignoring it.
    #[test]
    fn a_signal_ignored_at_the_start_stays_ignored() {
        let program = Program::start("watch", |child| {
            // SAFETY: the closure runs in the child between fork and exec
            // and makes one call that is safe there.
            unsafe {
                child.pre_exec(|| {
                    libc::signal(SIGINT, libc::SIG_IGN);
                    Ok(())
                });
            }
        });
        assert_eq!(program.says(), "READY");
        program.signal(SIGINT);
        program.signal(SIGHUP);
        assert_eq!(
            program.says(),
            "GOT Terminate",
            "the ignored one came first"
        );
    }

    // Security rule: the terminal is put back before the request is
    // delivered. The child has a terminal of its own and a hidden question
    // open in it, through the real `/dev/tty`.
    #[test]
    fn the_terminal_is_put_back_before_a_request_is_delivered() {
        let pty = pty();
        let before = pty.mode();
        let name = ptsname(&pty.ours, Vec::new()).expect("its name");
        let name = name.to_str().expect("UTF-8").to_string();
        let program = Program::start("terminal", |child| {
            child.env(TERMINAL, &name);
        });
        assert_eq!(
            read_from(&pty.ours, Some("Password: "), 20_000),
            "Password: "
        );
        assert_ne!(pty.mode(), before, "the question changed nothing");
        program.signal(SIGTERM);
        assert_eq!(program.says(), "GOT Terminate restored=true");
        // The child looked at the mode itself when the request reached it.
        // Looking again from here after it has ended is not possible on
        // macOS, which takes a terminal away when its session's first
        // process ends.
        assert_eq!(program.ended(), 143);
    }

    // Not a test of its own: the tests above run it in a new process.
    #[test]
    fn child() {
        let Some(kind) = std::env::var_os(CHILD) else {
            return;
        };
        let terminal = std::env::var_os(TERMINAL).map(|name| {
            // A session of its own, with the test's pty as its terminal.
            setsid().expect("a new session");
            let flags = OFlags::RDWR | OFlags::NOCTTY | OFlags::CLOEXEC;
            let terminal = open(name, flags, Mode::empty()).expect("open the terminal");
            ioctl_tiocsctty(&terminal).expect("make it this process's terminal");
            terminal
        });
        let stops = watch().expect("watch");
        assert_eq!(watch().err(), Some(Error::AlreadyExists), "watched twice");
        if let Some(terminal) = terminal {
            // A hidden question is open when the request comes.
            thread::spawn(|| read_hidden_line("Password: "));
            let stop = stops.recv().expect("a request");
            let shown = LocalModes::ECHO | LocalModes::ICANON | LocalModes::ISIG;
            let now = tcgetattr(&terminal).expect("its mode").local_modes;
            println!("SAYS GOT {stop:?} restored={}", now.contains(shown));
            std::process::exit(exit_status(stop));
        }
        if kind == "fork" {
            // SAFETY: the child of the fork only waits, with a call that is
            // safe after a fork in a program with threads.
            let forked = unsafe { libc::fork() };
            assert!(forked >= 0, "fork");
            if forked == 0 {
                loop {
                    // SAFETY: as above.
                    unsafe { libc::pause() };
                }
            }
            println!("SAYS FORKED {forked}");
            let mut status = 0;
            // SAFETY: `status` is a live integer, and the ID is a child's
            // that has not been waited for.
            unsafe { libc::waitpid(forked, &mut status, 0) };
            let by = match libc::WIFSIGNALED(status) {
                true => libc::WTERMSIG(status),
                false => 0,
            };
            thread::sleep(Duration::from_millis(300));
            println!(
                "SAYS FORK ENDED by={by} requests={}",
                stops.try_iter().count()
            );
            return;
        }
        if kind == "dropped" {
            drop(stops);
            println!("SAYS READY");
            thread::sleep(Duration::from_secs(60));
            return;
        }
        println!("SAYS READY");
        for (count, stop) in stops.iter().enumerate() {
            println!("SAYS GOT {stop:?}");
            if stop == Stop::Terminate && count >= 4 {
                std::process::exit(exit_status(stop));
            }
        }
    }
}
