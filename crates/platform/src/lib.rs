//! The OS seam.
//!
//! Everything that differs between Windows, macOS and Linux lives here, behind
//! one set of interfaces with a real implementation per OS and a fake for
//! tests. No other crate contains OS-specific code.
