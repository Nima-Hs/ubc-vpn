//! The fake's network events: what a test injects, and the changes
//! somebody else makes through [`Foreign`](crate::suite::Foreign).

use std::sync::mpsc;

use super::{Fake, Op};
use crate::{NetworkEvents, PhysicalNetwork, Result, Subscription};

impl NetworkEvents for Fake {
    fn reports_ipv6_changes(&self) -> bool {
        self.state().reports_ipv6
    }

    /// Delivers what [`Fake::send_event`] injects, and, as an OS would, the
    /// changes made as somebody else through `Foreign`. Nothing
    /// the product does sends one.
    fn subscribe(&self, watching: &PhysicalNetwork) -> Result<Subscription> {
        let (mut state, outcome) = self.start(Op::Subscribe);
        outcome?;
        let (sender, receiver) = mpsc::channel();
        state.next_subscriber += 1;
        let id = state.next_subscriber;
        let watched = watching.interface().to_string();
        state.subscribers.insert(id, (watched, sender));
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
