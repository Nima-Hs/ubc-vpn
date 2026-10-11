//! The VPN engine: a wrapper around `libopenconnect`.
//!
//! The rest of the workspace talks to an engine interface, with a fake for
//! tests. The real library sits behind a feature that is off by default, so
//! ordinary builds and tests need no native library.
