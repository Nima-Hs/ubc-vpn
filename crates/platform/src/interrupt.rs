//! Learning that the program has been asked to stop.
//!
//! A program that holds the terminal in an odd mode, or a connection it
//! should close properly, cannot afford to be ended where it stands by
//! Ctrl-C. [`watch`] turns such requests into values on a channel, and from
//! then on they no longer end the program: it has to exit by itself, with
//! [`exit_status`].
//!
//! - **The terminal is put back first.** Before a request is delivered, the
//!   terminal is put back as [`crate::terminal::restore_after_signal`] does.
//!   On Linux and macOS that happens inside the signal handler itself, not
//!   on the thread that forwards the request: the handler runs at once,
//!   whatever the program's threads are doing, and the function was written
//!   to be safe there. The handler does nothing else but write one byte to a
//!   pipe (and keep `errno` as it was); a thread reads the pipe and sends.
//! - **Every request is delivered**, a second and a third too. A caller that
//!   is already stopping should take a second one to mean "now": give up the
//!   tidying and exit at once with [`exit_status`]. A user who presses Ctrl-C
//!   twice is not asking twice for the same thing.
//! - **A request nobody is listening for ends the program.** If the receiver
//!   has been dropped, the program exits with [`exit_status`] when a request
//!   comes, so that it cannot become a program Ctrl-C does nothing to.
//! - **What was ignored stays ignored** on Linux and macOS: a signal the
//!   program was started with set to be ignored, as `nohup` does for a
//!   hang-up, is left alone.
//! - **Windows gives little time.** When the console closes, or at log-off or
//!   shutdown, Windows ends the program as soon as the handler returns, and
//!   after a few seconds whatever happens. So for those the handler does not
//!   return for a few seconds: the caller has that long to exit. Ctrl-C and
//!   Ctrl-Break have no such limit.
//!
//! Without the `fake` feature there is no way here to send a request:
//!
#![cfg_attr(not(feature = "fake"), doc = "```compile_fail")]
#![cfg_attr(feature = "fake", doc = "```no_run")]
//! use ubc_vpn_platform::interrupt::send_interrupt;
//! ```
//!
//! This much is always there:
//!
//! ```no_run
//! use ubc_vpn_platform::interrupt::{exit_status, watch};
//! ```

use std::sync::mpsc::Receiver;

use crate::Result;
#[cfg(windows)]
use crate::os::interrupt as os;
#[cfg(unix)]
use crate::unix::interrupt as os;

/// What asked the program to stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stop {
    /// Ctrl-C: `SIGINT` on Linux and macOS, `CTRL_C_EVENT` on Windows.
    Interrupt,
    /// `SIGTERM` or `SIGHUP` on Linux and macOS; Ctrl-Break, the console
    /// closing, log-off or shutdown on Windows.
    Terminate,
}

/// Starts watching and returns where requests arrive. From then on such a
/// request no longer ends the program by itself: the caller must exit.
/// Before a request is delivered the terminal is put back as
/// [`crate::terminal::restore_after_signal`] does.
///
/// Once per process: a second call fails with [`crate::Error::AlreadyExists`].
/// Keep the receiver for as long as the program runs: see the module's notes
/// on a second request and on a dropped receiver.
pub fn watch() -> Result<Receiver<Stop>> {
    os::watch()
}

/// The exit status a program ended by `stop` conventionally has: 130 and 143
/// on Linux and macOS, as for a program killed by `SIGINT` and by `SIGTERM`;
/// `0xC000013A` on Windows for both, which is what Windows itself gives a
/// program it ends for any of these.
pub fn exit_status(stop: Stop) -> i32 {
    os::exit_status(stop)
}

/// For tests only: a variable a test sets for a child process on Windows, so
/// that [`watch`] in the child turns Ctrl-C back on. Windows turns it off
/// for a program started in a process group of its own, which is how a test
/// has to start one to send it Ctrl-C and nobody else. Without the `fake`
/// feature the variable does nothing.
#[cfg(feature = "fake")]
pub const ACCEPT_CTRL_C: &str = "UBC_VPN_FAKE_ACCEPT_CTRL_C";

/// For tests only: sends a real Ctrl-C to the child process with this ID.
///
/// On Linux and macOS it is `SIGINT`. On Windows it is `CTRL_C_EVENT`, which
/// reaches the child only if the test started it in a process group of its
/// own (`CREATE_NEW_PROCESS_GROUP`), on the test's own console, with
/// [`ACCEPT_CTRL_C`] set, and the child calls [`watch`]. Under CI a test has
/// a console; a program with none cannot send the event.
#[cfg(feature = "fake")]
pub fn send_interrupt(child: u32) -> Result<()> {
    os::send_interrupt(child)
}
