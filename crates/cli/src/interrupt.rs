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
//!   The disconnect goes on a connection of its own, and the service serves
//!   connections independently, so it is sent only once the service has
//!   answered the connect request (or [`SETTLE`] has passed). Sent sooner,
//!   it could be served first, find nothing to stop, and let the connect
//!   through.
//! - **Once the connect has its outcome** and is telling the user, there is
//!   again nothing to undo. A Ctrl-C in that last instant ends the program
//!   and leaves the VPN as the user was just told it is.
//! - **A second request** means "now": the program ends at once, whatever
//!   it was in the middle of.
//!
//! The connect and the handler of requests run on different threads, so
//! each of these is decided in one step, under one lock: a request either
//! comes before the connect request is marked as going, and then it is
//! never sent; or after, and then it is undone.
//!
//! Either way the program ends with the status that is usual for a program
//! stopped that way, and says nothing more. What the login had already
//! printed by then, such as an error line from the gateway's side, stays.

use std::sync::mpsc::Receiver;
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::Duration;

use ubc_vpn_platform::interrupt::Stop;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// Checking, asking, logging in. Nothing has gone to the service.
    #[default]
    Before,
    /// The connect request has gone, or is about to.
    Sent,
    /// The connect has its outcome and is reporting it.
    Finished,
    /// A request to stop has come.
    Stopping,
}

/// How far a connect has got. The connect and whoever handles a request to
/// stop share one.
#[derive(Debug, Default, Clone)]
pub struct Progress(Arc<Shared>);

#[derive(Debug, Default)]
struct Shared {
    stage: Mutex<Stage>,
    /// Whether the connect request has been answered, or has failed.
    settled: Mutex<bool>,
    settling: Condvar,
}

impl Progress {
    fn stage(&self) -> std::sync::MutexGuard<'_, Stage> {
        self.0.stage.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The connect request is about to go to the service. Returns whether
    /// it may: not when a request to stop has already come, for that
    /// request found nothing to undo and nobody will undo this. From here
    /// on a request to stop has something to undo.
    pub fn sending(&self) -> bool {
        let mut stage = self.stage();
        if *stage == Stage::Before {
            *stage = Stage::Sent;
        }
        *stage == Stage::Sent
    }

    /// The connect has its outcome and is about to tell the user. Returns
    /// whether it may: not when a request to stop has come, for then the
    /// one handling it ends the program and nothing more is said. From here
    /// on a request to stop has nothing to undo: the user is being told how
    /// it ended, and a Ctrl-C now must not change that behind their back.
    pub fn finish(&self) -> bool {
        let mut stage = self.stage();
        if *stage != Stage::Stopping {
            *stage = Stage::Finished;
        }
        *stage == Stage::Finished
    }

    /// Takes note of a request to stop, and returns whether the service has
    /// to be told to disconnect before the program ends. That is so for the
    /// first request while the connect request is out and its outcome is
    /// not yet known, and for no other.
    pub fn stop(&self) -> bool {
        std::mem::replace(&mut *self.stage(), Stage::Stopping) == Stage::Sent
    }

    /// The connect request has its answer from the service, or failed to
    /// get one, or was never sent. An undo waits for this before it tells
    /// the service to disconnect.
    pub fn settled(&self) {
        *self
            .0
            .settled
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = true;
        self.0.settling.notify_all();
    }

    /// Whether [`Progress::settled`] was called.
    #[cfg(test)]
    pub fn is_settled(&self) -> bool {
        *self
            .0
            .settled
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Waits until [`Progress::settled`], or `limit` at most.
    fn wait_settled(&self, limit: Duration) {
        let settled = self
            .0
            .settled
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let waiting = |settled: &mut bool| !*settled;
        let waited = self.0.settling.wait_timeout_while(settled, limit, waiting);
        drop(waited.unwrap_or_else(PoisonError::into_inner));
    }
}

/// What a connect tells, and asks, whoever may stop it, at the steps where
/// that matters.
pub trait Steps {
    /// The connect request is about to go. It goes only if this says so.
    fn sending(&self) -> bool;
    /// The service has answered the connect request.
    fn answered(&self);
    /// Whether the user has stopped the command.
    fn stopped(&self) -> bool;
}

impl Steps for Progress {
    fn sending(&self) -> bool {
        Progress::sending(self)
    }

    fn answered(&self) {
        self.settled();
    }

    fn stopped(&self) -> bool {
        *self.stage() == Stage::Stopping
    }
}

/// For a connect nobody can stop from here, such as `connect --json`,
/// which the app stops through its own channel.
pub struct Unwatched;

impl Steps for Unwatched {
    fn sending(&self) -> bool {
        true
    }

    fn answered(&self) {}

    fn stopped(&self) -> bool {
        false
    }
}

/// How long an undo waits for the service to answer the connect request
/// before it sends the disconnect all the same. Past it the service may not
/// have the request yet, so the disconnect could find nothing to stop; that
/// is the most that can be done for a service that does not answer.
pub const SETTLE: Duration = Duration::from_secs(3);

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
                let (exit, progress) = (exit.clone(), progress.clone());
                std::thread::spawn(move || {
                    // The disconnect goes on a connection of its own, and the
                    // service serves connections independently. Sent before
                    // the connect is answered, it could be served first,
                    // find nothing to stop, and let the connect through.
                    progress.wait_settled(SETTLE);
                    undo();
                    exit(stop);
                });
            }
            None => exit(stop),
        }
    }
}
