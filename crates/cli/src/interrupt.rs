//! What `connect` does when the user presses Ctrl-C, or the program is told
//! to end some other way.
//!
//! The platform turns such a request into a value on a channel, with the
//! terminal already put back as it was. What is left to decide is how much
//! tidying there is to do, and that depends on how far the connect has got:
//!
//! - **Before the connect request has gone to the service** there is nothing
//!   to tidy: nothing was sent, so the program ends at once. That is also
//!   the only safe thing at a question whose answer is hidden: the terminal
//!   shows what is typed again from the moment of the request, so the
//!   question must not stay open.
//! - **After it has gone** the service would carry on connecting with nobody
//!   watching, so it is told to disconnect first, and then the program ends.
//! - **A second request** means "now": the program ends at once, whatever
//!   it was in the middle of.
//!
//! Either way the program ends with the status that is usual for a program
//! stopped that way, and prints nothing.

use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex, PoisonError};

use ubc_vpn_platform::interrupt::Stop;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// Checking, asking, logging in. Nothing has gone to the service.
    #[default]
    Before,
    /// The connect request has gone, or is about to.
    Sent,
    /// A request to stop has come.
    Stopping,
}

/// How far a connect has got. The connect and whoever handles a request to
/// stop share one.
#[derive(Debug, Default, Clone)]
pub struct Progress(Arc<Mutex<Stage>>);

impl Progress {
    fn stage(&self) -> std::sync::MutexGuard<'_, Stage> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The connect request is about to go to the service. From here on a
    /// request to stop has something to undo.
    pub fn sending(&self) {
        let mut stage = self.stage();
        if *stage == Stage::Before {
            *stage = Stage::Sent;
        }
    }

    /// Whether a request to stop has come. A connect that sees this says
    /// nothing more: the one handling the request ends the program.
    pub fn stopping(&self) -> bool {
        *self.stage() == Stage::Stopping
    }

    /// Takes note of a request to stop, and returns whether the service has
    /// to be told to disconnect before the program ends. That is so for the
    /// first request after the connect request has gone, and for no other.
    pub fn stop(&self) -> bool {
        std::mem::replace(&mut *self.stage(), Stage::Stopping) == Stage::Sent
    }
}

/// Handles requests to stop for as long as they come. `undo` tells the
/// service to disconnect; `exit` ends the program with the status for the
/// request it is given. Neither is called before a request comes.
///
/// `undo` runs on a thread of its own, so that a second request is heard
/// while it runs and can end the program without waiting for it.
pub fn serve(
    requests: Receiver<Stop>,
    progress: &Progress,
    undo: impl FnOnce() + Send + 'static,
    exit: impl Fn(Stop) + Send + Sync + 'static,
) {
    let exit = Arc::new(exit);
    let mut undo = Some(undo);
    for stop in requests {
        match undo.take().filter(|_| progress.stop()) {
            Some(undo) => {
                let exit = exit.clone();
                std::thread::spawn(move || {
                    undo();
                    exit(stop);
                });
            }
            None => exit(stop),
        }
    }
}
