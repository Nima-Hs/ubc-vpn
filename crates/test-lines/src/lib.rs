//! Writes the lines CI reads from a test's output, whole.
//!
//! A test that is skipped passes, so each one that must run says `RAN: <name>`,
//! and the workflow requires that as a whole line of the log
//! (`.github/ran/check.sh`). With `--nocapture`, tests share standard output
//! with the test harness, which writes `test <name> ... ` and then, as a
//! separate write, its result. A plain `println!` from another test can land
//! between the two: `test <name> ... RAN: <other>`. The test ran and the check
//! says it did not, and it must keep saying so: a line that only contains a
//! name proves nothing.
//!
//! So [`whole_line!`] ends whatever is on the line first. Other processes and
//! standard error can share the same pipe, and Rust's lock on standard output
//! does not hold them back, so the line goes out in one write: a write that
//! small to a pipe is not split.

/// Writes a line of its own, in one write. Takes what `format!` takes.
///
/// A test that is not run with `--nocapture` keeps it to itself, as with
/// `println!`. Use this for any line a workflow looks for.
#[macro_export]
macro_rules! whole_line {
    ($($line:tt)*) => {
        $crate::say(&::std::format!($($line)*))
    };
}

/// What [`whole_line!`] calls.
pub fn say(line: &str) {
    // Formatted first: `print!` makes a write for each piece of its format
    // up to a line end, so "\n{line}\n" would write the first line end alone.
    let whole = format!("\n{line}\n");
    print!("{whole}");
}
