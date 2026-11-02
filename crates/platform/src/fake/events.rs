//! The fake's network events: it delivers only what a test injects.

use std::sync::mpsc;

use super::{Fake, Op};
use crate::{NetworkEvents, PhysicalNetwork, Result, Subscription};

impl NetworkEvents for Fake {
    fn reports_ipv6_changes(&self) -> bool {
        self.state().reports_ipv6
    }

    /// Delivers only what [`Fake::send_event`] injects, whatever is watched.
    fn subscribe(&self, _watching: &PhysicalNetwork) -> Result<Subscription> {
        let (mut state, outcome) = self.start(Op::Subscribe);
        outcome?;
        let (sender, receiver) = mpsc::channel();
        state.next_subscriber += 1;
        let id = state.next_subscriber;
        state.subscribers.insert(id, sender);
        let ends = Unsubscribe {
            fake: self.clone(),
            id,
        };
        Ok(Subscription::new(receiver, ends))
    }
}

/// Removes one subscriber from the fake when dropped.
struct Unsubscribe {
    fake: Fake,
    id: u64,
}

impl Drop for Unsubscribe {
    fn drop(&mut self) {
        self.fake.state().subscribers.remove(&self.id);
    }
}
