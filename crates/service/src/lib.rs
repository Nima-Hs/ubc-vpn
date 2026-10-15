//! The service's logic, as a library. The binary is a thin wrapper round
//! [`Service::start`], and the tests drive the same code through the platform
//! fake.
//!
//! One file per job: `args` (the command line), `policy` (the policy file),
//! `owner` (the state file), `logs` (the log), `hub` (who is connected and
//! what they are told), `queue` (what waits to be written to one of them),
//! `server` (the channel), `diagnostics` (what the service says about
//! itself), `session` (the connection state machine), `connect`, `verify`
//! and `teardown` (its three steps).

use std::sync::{Mutex, MutexGuard, PoisonError};

pub mod args;
mod connect;
mod diagnostics;
mod hub;
mod logs;
mod owner;
pub mod policy;
mod queue;
mod server;
mod session;
mod teardown;
mod verify;
mod words;

pub use logs::{CAPACITY as LOG_CAPACITY, LINGER, Logs, NOT_LOGGED, REQUEST_LINES};
pub use server::{MAX_CONNECTIONS, MAX_PER_STRANGER, MAX_STRANGERS, Service, Timeouts};
pub use verify::DNS_UNCONFIRMED;

/// Locks a mutex, carrying on after another thread panicked while holding it.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
