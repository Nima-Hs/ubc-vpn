//! The service's logic, as a library. The binary is a thin wrapper round
//! [`Service::start`], and the tests drive the same code through the platform
//! fake.
//!
//! One file per job: `args` (the command line), `policy` (the policy file),
//! `owner` (the state file), `logs` (the log buffer), `hub` (who is connected
//! and what they are told), `server` (the channel), `session` (the connection
//! state machine), `connect`, `verify` and `teardown` (its three steps).

use std::sync::{Mutex, MutexGuard, PoisonError};

pub mod args;
mod connect;
mod hub;
mod logs;
mod owner;
pub mod policy;
mod server;
mod session;
mod teardown;
mod verify;

pub use logs::Logs;
pub use server::{MAX_CONNECTIONS, MAX_PER_STRANGER, MAX_STRANGERS, Service, Timeouts};

/// Locks a mutex, carrying on after another thread panicked while holding it.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
