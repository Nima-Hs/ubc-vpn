//! The C shim on its own, called the way the library calls it, with a
//! `Lines` as `privdata` the way `Handle::new` passes one. No native library
//! is loaded.
//!
//! The `Engine` workflow runs these in a release build too: the wipe is
//! something an optimising compiler removes if the shim lets it.

#![cfg(all(feature = "libopenconnect", feature = "fake"))]

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use ubc_vpn_engine::ffi::{LineState, Lines};

unsafe extern "C" {
    /// `shim.c`'s entry point, which the engine hands to the library.
    fn ubc_vpn_progress(privdata: *mut c_void, level: c_int, fmt: *const c_char, ...);
}

/// The size of the shim's buffer, NUL included.
const BUFFER: usize = 4096;

/// Formats `text` through the shim with the format `fmt`, and returns the
/// one line that arrived: its length and how it was marked.
fn through(fmt: &CStr, text: *const c_void) -> (usize, LineState) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let into = Arc::clone(&seen);
    let lines: Lines = Box::new(move |_, line: &CStr, state| {
        into.lock().unwrap().push((line.to_bytes().len(), state));
    });
    let privdata = Box::into_raw(Box::new(lines));
    // SAFETY: `privdata` is a live `Lines`, which is what the shim's
    // callback expects; `fmt` takes one pointer argument and gets `text`,
    // which the caller keeps valid for it; `privdata` is freed once.
    unsafe {
        ubc_vpn_progress(privdata.cast(), 1, fmt.as_ptr(), text);
        drop(Box::from_raw(privdata));
    }
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1, "one call is one line");
    seen[0]
}

/// Leaves a pattern with no NUL in it where the shim's buffer will be, so
/// that a buffer the shim did not write shows.
#[inline(never)]
fn prime_the_stack() {
    let mut block = [b'S'; 16 * 1024];
    std::hint::black_box(&mut block);
}

fn of_length(length: usize) -> (usize, LineState) {
    let text = CString::new("x".repeat(length)).unwrap();
    through(c"%s", text.as_ptr().cast())
}

// Security rule: a line never overruns the buffer. The longest that fits is
// whole; anything longer is cut to that length and marked cut, so that an
// engine can treat it as holding part of a secret.
#[test]
fn a_long_line_is_cut_to_the_buffer_and_marked() {
    assert_eq!(of_length(10), (10, LineState::Whole));
    assert_eq!(of_length(BUFFER - 1), (BUFFER - 1, LineState::Whole));
    assert_eq!(of_length(BUFFER), (BUFFER - 1, LineState::Cut));
    assert_eq!(of_length(10_000), (BUFFER - 1, LineState::Cut));
    assert_eq!(of_length(1_000_000), (BUFFER - 1, LineState::Cut));
}

// Security rule: a line that could not be formatted is marked as such. A
// wide string that cannot be converted makes the formatting fail.
#[test]
fn a_line_that_cannot_be_formatted_is_marked() {
    #[cfg(windows)]
    let wide: [u16; 3] = [0xD800, 0x41, 0];
    #[cfg(not(windows))]
    let wide: [u32; 3] = [0x7fff_ffff, 0x41, 0];
    // Nothing was formatted, so the line is empty, whatever was there before.
    prime_the_stack();
    let (length, state) = through(c"%ls", wide.as_ptr().cast());
    assert_eq!((length, state), (0, LineState::Failed));
    let (length, state) = through(c"before %ls after", wide.as_ptr().cast());
    assert!(
        length < BUFFER && state == LineState::Failed,
        "{length} {state:?}"
    );
}

/// Where the shim's buffer was during the last call.
static WHERE: AtomicUsize = AtomicUsize::new(0);

// Security rule: the shim wipes its buffer before it returns, so a line with
// the session cookie in it does not stay on the stack.
#[test]
fn the_buffer_is_wiped_before_the_shim_returns() {
    let lines: Lines = Box::new(move |_, line: &CStr, _| {
        WHERE.store(line.as_ptr() as usize, Ordering::SeqCst);
    });
    let privdata = Box::into_raw(Box::new(lines));
    let secret = c"webvpn=NOT-A-REAL-COOKIE-0123456789";
    let mut left = [0xffu8; 44];
    // SAFETY: the call is as in `through`. What follows reads the shim's
    // buffer after the shim has returned: memory below this function's
    // frame, on this thread's own stack, which stays mapped. Nothing is
    // called in between, so nothing has reused it; `read_volatile` keeps the
    // compiler from assuming what a dead frame holds.
    unsafe {
        ubc_vpn_progress(privdata.cast(), 2, c"Cookie: %s".as_ptr(), secret.as_ptr());
        let at = WHERE.load(Ordering::Relaxed) as *const u8;
        for (index, byte) in left.iter_mut().enumerate() {
            *byte = std::ptr::read_volatile(at.add(index));
        }
        drop(Box::from_raw(privdata));
    }
    assert_ne!(WHERE.load(Ordering::SeqCst), 0, "the callback did not run");
    let text = String::from_utf8_lossy(&left);
    assert_eq!(left, [0u8; 44], "left in the buffer: {text:?}");
}
