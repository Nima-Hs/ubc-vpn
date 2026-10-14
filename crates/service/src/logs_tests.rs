//! The log's rules, one test each. All values are made up.

use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ubc_vpn_core::protocol::MAX_LOG_TEXT_BYTES;

use super::*;

const COOKIE: &str = "Zq7-made-up-0123456789";
const MARKER: &str = LogText::LEFT_OUT;

/// Every line kept, as text.
fn texts(logs: &Logs) -> Vec<String> {
    logs.lines()
}

fn info() -> ubc_vpn_engine::LogLevel {
    ubc_vpn_engine::LogLevel::Info
}

// Security rule: the cookie is registered with the engine's sink, so a line
// that carries it with no marker word still never reaches the log.
#[test]
fn the_cookie_never_reaches_the_log_from_the_engine() {
    let logs = Logs::default();
    let sink = logs.sink(&Secret::new(COOKIE));
    sink.log(ubc_vpn_engine::LogLevel::Error, &format!("> {COOKIE} <"));
    assert_eq!(texts(&logs), ["> [redacted] <"]);
    let line = &logs.page(None).lines[0];
    assert_eq!(
        (line.level, line.source),
        (LogLevel::Error, LogSource::Engine)
    );
}

// Security rule: a line of protocol detail is never kept, in any build. The
// engine's sink is not asked for such lines, and one that came anyway has no
// level to be kept at.
#[test]
fn a_line_of_protocol_detail_is_never_kept() {
    assert_eq!(kept(ubc_vpn_engine::LogLevel::Debug), None);
    assert_eq!(kept(info()), Some(LogLevel::Info));
    let logs = Logs::default();
    let sink = logs.sink(&Secret::new(COOKIE));
    sink.log(ubc_vpn_engine::LogLevel::Debug, "detail");
    sink.log(info(), "progress");
    assert_eq!(texts(&logs), ["progress"]);
}

// Security rule: every line goes through the same cleaning, the service's
// own and a client's included: each secret held at the time is removed
// exactly, and so is everything after a word that marks a secret.
#[test]
fn every_line_loses_each_secret_held_and_what_follows_a_marker() {
    let logs = Logs::default();
    let cookie = logs.hold(&Secret::new(COOKIE));
    let other = logs.hold(&Secret::new("second-made-up-value"));
    logs.error(&format!("failed near {COOKIE} and second-made-up-value."));
    logs.warn("the gateway said token=made-up-elsewhere");
    let added = LogText::new(&format!("< {COOKIE}")).unwrap();
    logs.add(LogLevel::Error, &added);
    let expected = [
        "failed near [redacted] and [redacted].",
        "the gateway said [redacted]",
        "< [redacted]",
    ];
    assert_eq!(texts(&logs), expected);
    let shown = logs.shown(&format!("no {COOKIE}"));
    assert_eq!(shown.as_str(), "no [redacted]");

    // A hold ends when it is dropped, and only that one.
    drop(cookie);
    logs.error(&format!("{COOKIE} second-made-up-value"));
    assert_eq!(texts(&logs)[3], format!("{COOKIE} [redacted]"));
    drop(other);
    assert!(lock(&logs.0.inner).hidden.is_empty(), "a secret was kept");
}

// Security rule: a secret cannot be hidden from the removal by characters
// that are themselves removed, in the line or in the secret.
#[test]
fn a_secret_split_by_unseen_characters_is_still_removed() {
    let logs = Logs::default();
    let _cookie = logs.hold(&Secret::new(COOKIE));
    let (start, end) = COOKIE.split_at(5);
    logs.error(&format!("> {start}\u{200b}{end}\u{1b}[0m <"));
    let _odd = logs.hold(&Secret::new("made\u{7}up\u{202e}odd"));
    logs.error("> madeupodd <");
    assert_eq!(texts(&logs), ["> [redacted][0m <", "> [redacted] <"]);
}

// Security rule: a line is kept whole or not at all. One that is too long
// is not cut, because the cut could fall inside a secret and leave half of
// it; the marker stands in its place.
#[test]
fn a_line_that_cannot_be_kept_whole_leaves_only_the_marker() {
    let logs = Logs::default();
    let _cookie = logs.hold(&Secret::new(COOKIE));
    // The cookie straddles the limit: a cut there would keep its start.
    let long = format!("{}{COOKIE}", "x".repeat(MAX_LOG_TEXT_BYTES - 10));
    logs.error(&long);
    // Removal can make a line longer than may be kept.
    let _short = logs.hold(&Secret::new("abcd"));
    logs.error(&"abcd".repeat(MAX_LOG_TEXT_BYTES / 4));
    // Nothing is left of a line of unseen characters.
    logs.error("\u{1b}\u{200b}");
    assert_eq!(texts(&logs), [MARKER, MARKER, MARKER]);
    // A blank line is no line.
    logs.error("  ");
    logs.error("");
    assert_eq!(texts(&logs).len(), 3);
    // The longest line there may be is kept as it is.
    let most = "y".repeat(MAX_LOG_TEXT_BYTES);
    logs.error(&most);
    assert_eq!(texts(&logs)[3], most);
}

// Security rule: lines that clients add are kept apart, so no client can
// push a line of the service's own out of the log.
#[test]
fn added_lines_never_push_out_the_services_own() {
    let logs = Logs::default();
    logs.error("the service's own");
    let text = LogText::new("added").unwrap();
    for _ in 0..KEPT_ADDED_LOG_LINES + 50 {
        logs.add(LogLevel::Info, &text);
    }
    let kept = texts(&logs);
    assert_eq!(kept[0], "the service's own");
    assert_eq!(kept.len(), 1 + KEPT_ADDED_LOG_LINES);
    let line = &logs.page(None).lines[1];
    assert_eq!((line.source, line.seq), (LogSource::Login, 52));
}

#[test]
fn the_services_own_lines_are_bounded_too() {
    let logs = Logs::default();
    (0..CAPACITY + 10).for_each(|n| logs.warn(&n.to_string()));
    let lines = texts(&logs);
    assert_eq!(lines.len(), CAPACITY);
    assert_eq!(lines[0], "10");
}

fn seqs(page: &LogPage) -> Vec<u64> {
    page.lines.iter().map(|line| line.seq).collect()
}

// The contract: lines are numbered from 1; a page holds those after the
// cursor, from both kinds, in order; `next` is the last one, or the cursor
// when there is none.
#[test]
fn a_page_holds_the_lines_after_the_cursor_in_order() {
    let logs = Logs::default();
    let run = logs.0.run;
    let at = |seq| Some(LogCursor { run, seq });
    let empty = logs.page(None);
    assert_eq!((empty.run, empty.next, empty.dropped), (run, 0, false));
    logs.error("one");
    logs.add(LogLevel::Info, &LogText::new("two").unwrap());
    logs.warn("three");
    let all = logs.page(None);
    assert_eq!(
        (seqs(&all), all.next, all.dropped),
        (vec![1, 2, 3], 3, false)
    );
    let rest = logs.page(at(1));
    assert_eq!((seqs(&rest), rest.next), (vec![2, 3], 3));
    let none = logs.page(at(3));
    assert_eq!((seqs(&none), none.next, none.dropped), (vec![], 3, false));
    // Times are the service's clock, in milliseconds: this century.
    assert!(all.lines[0].at_unix_ms > 1_600_000_000_000);
}

// The contract: a place in another run is no place in this one. The page
// starts from the oldest line held, `next` is 0 when there is none, and
// `dropped` is not true for that alone: the reader sees the run changed.
#[test]
fn a_cursor_from_another_run_reads_from_the_start() {
    let logs = Logs::default();
    let other = Some(LogCursor {
        run: logs.0.run + 1,
        seq: 2,
    });
    let empty = logs.page(other);
    assert_eq!((empty.next, empty.dropped), (0, false));
    (0..3).for_each(|_| logs.error("line"));
    let page = logs.page(other);
    assert_eq!(
        (seqs(&page), page.next, page.dropped),
        (vec![1, 2, 3], 3, false)
    );
    // Another run of the service has another number.
    assert_ne!(Logs::default().0.run, logs.0.run);
}

// The contract: `dropped` says exactly that a line of this run after the
// cursor that was used is no longer held, whichever kind of line it was.
#[test]
fn dropped_means_a_line_after_the_cursor_is_gone() {
    let logs = Logs::default();
    let run = logs.0.run;
    let dropped = |seq| logs.page(Some(LogCursor { run, seq })).dropped;
    let text = LogText::new("added").unwrap();
    // Lines 1 to 101 are added ones, so line 1 is lost.
    (0..=KEPT_ADDED_LOG_LINES).for_each(|_| logs.add(LogLevel::Info, &text));
    let first = logs.page(None);
    assert!(first.dropped, "a first read after a loss must say so");
    assert_eq!(first.lines[0].seq, 2);
    assert!(dropped(0));
    assert!(!dropped(1), "nothing after line 1 is gone");
    // A cursor from another run is read as none, so it sees the loss too.
    let other = LogCursor {
        run: run + 1,
        seq: 50,
    };
    assert!(logs.page(Some(other)).dropped);

    // The service's own lines: lines 102 to 602, so line 102 is lost.
    (0..=CAPACITY).for_each(|_| logs.warn("own"));
    assert!(dropped(101));
    assert!(!dropped(102));
    // Line 3 is still held, but line 102 after it is not.
    assert!(dropped(3));
}

// Lines are told in the order of their numbers, each once.
#[test]
fn each_line_is_told_as_it_is_kept() {
    let logs = Logs::default();
    logs.error("before anyone listened");
    let (told, heard) = mpsc::channel();
    logs.tell(move |line| {
        told.send((line.seq, line.text.as_str().to_string()))
            .unwrap()
    });
    logs.error("first");
    logs.sink(&Secret::new(COOKIE)).log(info(), "second");
    let heard: Vec<_> = heard.try_iter().collect();
    let expected = [(2, "first".to_string()), (3, "second".to_string())];
    assert_eq!(heard, expected);
}

/// A log whose clock stands still until the test moves it on.
fn with_a_clock() -> (Logs, impl Fn(Duration)) {
    let now = Arc::new(Mutex::new(Instant::now()));
    let read = now.clone();
    let logs = Logs::with(move || *read.lock().unwrap(), LINGER);
    (logs, move |by| *now.lock().unwrap() += by)
}

fn holds(logs: &Logs) -> usize {
    logs.held()
}

// Security rule: when everything for a connection has been torn down its
// cookie is still held for the cleaning of the log, for a short time and no
// longer. A client's lines about a connect that failed arrive just then.
#[test]
fn a_cookie_lingers_for_the_cleaning_and_is_then_wiped() {
    // How long is part of the rule: long enough for a client's lines to
    // arrive after a connect failed, and no longer.
    assert_eq!(LINGER, Duration::from_secs(30));
    let said = LogText::new(&format!("the client says {COOKIE}")).unwrap();
    let (logs, pass) = with_a_clock();
    logs.hold(&Secret::new(COOKIE)).linger();
    pass(Duration::from_secs(1));
    logs.add(LogLevel::Error, &said);
    let tick = Duration::from_millis(1);
    pass(LINGER - Duration::from_secs(1) - tick);
    logs.add(LogLevel::Error, &said);
    // Just before its time is up it is still there, and that is how long.
    assert_eq!((logs.wipe(), holds(&logs)), (Some(tick), 1));
    pass(tick);
    assert_eq!((logs.wipe(), holds(&logs)), (None, 0), "it was not wiped");
    logs.add(LogLevel::Error, &said);
    let cleaned = "the client says [redacted]";
    assert_eq!(texts(&logs), [cleaned, cleaned, said.as_str()]);

    // It is wiped when its time is up even if nobody asks: the next line
    // kept does it.
    let (logs, pass) = with_a_clock();
    logs.hold(&Secret::new(COOKIE)).linger();
    pass(LINGER);
    logs.error("something else");
    assert_eq!(holds(&logs), 0, "it was not wiped");

    // A hold that is simply dropped does not linger.
    drop(logs.hold(&Secret::new(COOKIE)));
    assert_eq!((logs.wipe(), holds(&logs)), (None, 0));
}

// Security rule: a cookie that lingers is wiped as soon as the next connect
// is admitted, which is when the next one is held.
#[test]
fn the_next_secret_held_wipes_one_that_lingered() {
    let (logs, _pass) = with_a_clock();
    logs.hold(&Secret::new(COOKIE)).linger();
    let _next = logs.hold(&Secret::new("another-made-up-value"));
    assert_eq!(holds(&logs), 1);
    logs.error(&format!("{COOKIE} another-made-up-value"));
    assert_eq!(texts(&logs), [format!("{COOKIE} [redacted]")]);
}

// Security rule: nothing that can happen again and again can push the
// earlier lines out of the log. A line about such a thing that repeats the
// last one about it is passed over while that one is still in the log.
#[test]
fn a_line_that_only_repeats_is_not_kept_again() {
    let logs = Logs::default();
    logs.error("what happened first");
    for _ in 0..2 * CAPACITY {
        logs.error_about("accepting", "accepting failed: denied");
        logs.warn_about("a step", "a step failed: denied");
    }
    let once = [
        "what happened first",
        "accepting failed: denied",
        "a step failed: denied",
    ];
    assert_eq!(texts(&logs), once);
    // News about the same thing is kept, and then that is the last line.
    logs.error_about("accepting", "accepting failed: no memory");
    logs.error_about("accepting", "accepting failed: no memory");
    logs.error_about("accepting", "accepting failed: denied");
    let lines = texts(&logs);
    assert_eq!(lines.len(), 5);
    assert_eq!(
        lines[3..],
        ["accepting failed: no memory", "accepting failed: denied"]
    );
    assert_eq!(logs.page(None).lines[2].level, LogLevel::Warn);
}

// The other half of that rule: the log is never left without a line about
// a fault that is still happening. A teardown step fails; other lines push
// that line out; the step fails again the same way, and it is written
// again, once.
#[test]
fn a_repeat_is_written_again_once_its_line_has_been_pushed_out() {
    let logs = Logs::default();
    let step = "clearing split DNS";
    let failed = "teardown: clearing split DNS failed: permission denied";
    let about_it = |logs: &Logs| texts(logs).iter().filter(|line| *line == failed).count();
    logs.error_about(step, failed);
    // One line short of pushing it out: it is still there, so a repeat is
    // passed over.
    (1..CAPACITY).for_each(|n| logs.error(&format!("another line {n}")));
    logs.error_about(step, failed);
    assert_eq!((about_it(&logs), texts(&logs)[0].as_str()), (1, failed));
    // One more line and it is gone.
    logs.error("the line that pushes it out");
    assert_eq!(about_it(&logs), 0);
    logs.error_about(step, failed);
    logs.error_about(step, failed);
    assert_eq!(about_it(&logs), 1, "written again, and once");
    assert_eq!(texts(&logs).last().map(String::as_str), Some(failed));
}

// Security rule: the lines a client causes by asking have a budget, so that
// no client can push the earlier lines out by asking again and again. Past
// it one line says so; once the window has passed they are kept again.
#[test]
fn lines_caused_by_requests_have_a_budget() {
    let (logs, pass) = with_a_clock();
    logs.error("the line before");
    for n in 0..REQUEST_LINES + 40 {
        logs.about_requests(LogLevel::Info, &format!("asked {n}"));
    }
    let kept = texts(&logs);
    assert_eq!(kept.len(), 1 + REQUEST_LINES + 1);
    assert_eq!(kept[0], "the line before");
    assert_eq!(kept[REQUEST_LINES], format!("asked {}", REQUEST_LINES - 1));
    assert_eq!(kept.last().map(String::as_str), Some(NOT_LOGGED));
    // Other lines are not held back by it.
    logs.error("a line of the service's own");
    assert_eq!(texts(&logs).len(), kept.len() + 1);

    // Just before the window has passed, still nothing; then it begins
    // again, with a whole budget.
    pass(REQUEST_WINDOW - Duration::from_millis(1));
    logs.about_requests(LogLevel::Info, "too soon");
    pass(Duration::from_millis(1));
    for n in 0..REQUEST_LINES {
        logs.about_requests(LogLevel::Info, &format!("later {n}"));
    }
    let now = texts(&logs);
    assert!(!now.iter().any(|line| line == "too soon"));
    let later = now.iter().filter(|line| line.starts_with("later ")).count();
    assert_eq!(later, REQUEST_LINES);
    assert_eq!(now.iter().filter(|line| *line == NOT_LOGGED).count(), 1);
}
