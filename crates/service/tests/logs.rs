//! The log and the diagnostics, as the owner reads them over the channel.
//! Tests marked "Security rule" must fail if the rule they name is removed.
//! Every value is made up.

mod harness;

use harness::*;
use ubc_vpn_core::protocol::{
    AddLogParams, Diagnostics, KEPT_ADDED_LOG_LINES, LogLevel, LogPage, LogSource,
    MAX_ADDED_LOG_LINES, MAX_LINE_BYTES, MAX_LOG_TEXT_BYTES, StateKind, WatchLogsParams,
};

const ACCEPTED: Result<ResponseBody, ErrorCode> = Ok(ResponseBody::Accepted);
const REFUSED: Result<ResponseBody, ErrorCode> = Err(ErrorCode::BadRequest);

fn add(text: &str) -> RequestBody {
    let (level, text) = (LogLevel::Error, text.to_string());
    RequestBody::AddLog(AddLogParams { level, text })
}

fn watch(on: bool) -> RequestBody {
    RequestBody::WatchLogs(WatchLogsParams { on })
}

fn page(peer: &mut Peer, after: Option<LogCursor>) -> LogPage {
    match peer.ask(RequestBody::Logs(LogsParams { after })) {
        Ok(ResponseBody::Logs(page)) => page,
        other => panic!("expected a page of the log, got {other:?}"),
    }
}

fn diagnostics(peer: &mut Peer) -> Diagnostics {
    match peer.ask(RequestBody::Diagnostics) {
        Ok(ResponseBody::Diagnostics(report)) => *report,
        other => panic!("expected diagnostics, got {other:?}"),
    }
}

fn texts(lines: &[LogLine]) -> Vec<&str> {
    lines.iter().map(|line| line.text.as_str()).collect()
}

/// Connects and waits until the tunnel is up.
fn connected(peer: &mut Peer) {
    let state = peer.connect_ends(good());
    assert!(matches!(state, ConnState::Connected { .. }), "{state:?}");
}

// The owner reads what was logged, and a connection that asks is sent each
// new line once, in order, until it asks no more. One that did not ask is
// sent none.
#[test]
fn the_owner_reads_the_log_and_is_sent_new_lines_when_it_asks() {
    let rig = rig();
    let mut alice = rig.owner();
    let mut other = rig.owner_again();
    assert_eq!(alice.ask(watch(true)), ACCEPTED);
    connected(&mut alice);

    // The engine's lines came as events, numbered as they are in the log.
    let first = alice.log();
    assert_eq!(first.source, LogSource::Engine);
    let second = alice.log();
    assert_eq!(second.seq, first.seq + 1);
    assert_eq!(
        texts(&[first.clone(), second]),
        ["> [redacted]", "CSTP connected"]
    );
    let read = alice.whole_log();
    assert_eq!(read[0], first);
    assert_eq!(texts(&read), ["> [redacted]", "CSTP connected"]);

    // A line from elsewhere reaches the one that watches, and only it.
    assert_eq!(other.ask(add("Login failed.")), ACCEPTED);
    let added = alice.log();
    assert_eq!((added.seq, added.text.as_str()), (3, "Login failed."));
    assert_eq!(
        (added.level, added.source),
        (LogLevel::Error, LogSource::Login)
    );
    assert_eq!(other.state(), ConnState::Connecting);
    assert!(matches!(other.state(), ConnState::Connected { .. }));
    assert!(
        other.is_quiet(),
        "a connection that did not ask was sent a line"
    );

    assert_eq!(alice.ask(watch(false)), ACCEPTED);
    assert_eq!(other.ask(add("Another line.")), ACCEPTED);
    assert!(
        alice.is_quiet(),
        "a line came after the watch was turned off"
    );
    assert_eq!(alice.whole_log().len(), 4);
}

// Security rule: the cookie reaches no line of the log, however it is read:
// in a page, in an event, or in the diagnostics. The engine here writes it
// in a line that is kept, with no word to mark it, before hiding it; and a
// client hands over a line that holds it while the service still does.
#[test]
fn the_cookie_is_in_nothing_the_owner_can_read() {
    let rig = rig();
    let mut alice = rig.owner();
    assert_eq!(alice.ask(watch(true)), ACCEPTED);
    connected(&mut alice);
    assert_eq!(
        alice.ask(add(&format!("the client says {COOKIE}"))),
        ACCEPTED
    );
    assert_eq!(alice.ask(add("password=made-up-elsewhere")), ACCEPTED);
    let read = alice.whole_log();
    let expected = [
        "> [redacted]",
        "CSTP connected",
        "the client says [redacted]",
        "[redacted]",
    ];
    assert_eq!(texts(&read), expected);
    diagnostics(&mut alice);
    (0..4).for_each(|_| drop(alice.log()));
    for line in &alice.lines {
        assert!(!line.contains(COOKIE), "the cookie was sent: {line}");
        assert!(!line.contains("made-up-elsewhere"), "{line}");
    }
}

// Security rule: one connection may add only so many lines, and a text that
// is not one plain line of a length that can be kept is refused whole. Both
// are answered and neither closes the connection.
#[test]
fn a_client_may_add_only_so_much_and_only_plain_lines() {
    let rig = rig();
    let mut alice = rig.owner();
    let not_lines = [
        "x".repeat(MAX_LOG_TEXT_BYTES + 1),
        "two\nlines".to_string(),
        "escape\u{1b}[2J".to_string(),
        "two\u{2028}lines".to_string(),
        String::new(),
    ];
    for text in &not_lines {
        assert_eq!(alice.ask(add(text)), REFUSED, "{text:?}");
    }
    assert!(
        alice.whole_log().is_empty(),
        "something of a refused line was kept"
    );

    // The refused ones did not count.
    for n in 0..MAX_ADDED_LOG_LINES {
        assert_eq!(alice.ask(add(&format!("line {n}"))), ACCEPTED);
    }
    assert_eq!(alice.ask(add("one too many")), REFUSED);
    assert_eq!(alice.whole_log().len(), MAX_ADDED_LOG_LINES);
    // The limit is the connection's: the next one has its own.
    let mut again = rig.owner_again();
    assert_eq!(again.ask(add("from another connection")), ACCEPTED);
    assert_eq!(
        alice.ask(RequestBody::Status),
        Ok(ResponseBody::Status(ConnState::Disconnected))
    );
}

// Security rule: nothing of an `add_log` request is written anywhere before
// its text has been checked and has had secrets removed. A request that is
// refused, or cannot be read at all, leaves no trace of what it held.
#[test]
fn nothing_of_a_line_that_is_not_kept_is_logged() {
    const VALUE: &str = "made-up-value-9f3";
    let rig = rig();
    let mut alice = rig.owner();
    let long = format!("{}{VALUE}", "x".repeat(MAX_LOG_TEXT_BYTES));
    for text in [format!("{VALUE}\nsecond line"), long] {
        assert_eq!(alice.ask(add(&text)), REFUSED);
    }
    // A level there is none of: the request cannot be read, so it gets no
    // answer and the connection ends.
    let unreadable = format!(
        r#"{{"id":9,"body":{{"method":"add_log","params":{{"level":"loud","text":"{VALUE}"}}}}}}"#
    );
    alice.conn.write_line(&unreadable).unwrap();
    assert!(alice.is_closed(), "no answer to what is not a request");

    let mut again = rig.owner_again();
    let read = again.whole_log();
    // That a request could not be read is noted, and nothing of it.
    assert_eq!(
        texts(&read),
        [
            "a request from the owner could not be understood; later ones are not noted while this line is in the log"
        ]
    );
    let sent = [alice.lines, again.lines, rig.logs()].concat();
    assert!(!sent.join("\n").contains(VALUE), "{sent:?}");
}

// The contract, over the channel: the log is read in pages that each fit in
// a line, `dropped` says that a line after the cursor is gone, and a cursor
// from another run of the service reads from the start.
#[test]
fn the_log_is_read_in_pages_and_says_what_it_lost() {
    let mut rig = rig();
    let mut alice = rig.owner();
    let before = page(&mut alice, None);
    assert_eq!(
        (before.lines.len(), before.next, before.dropped),
        (0, 0, false)
    );

    // The longest lines there may be, with the worst text for size, from as
    // many connections as it takes to lose some.
    let worst = "\"".repeat(MAX_LOG_TEXT_BYTES);
    let sent = KEPT_ADDED_LOG_LINES + MAX_ADDED_LOG_LINES;
    for _ in 0..sent / MAX_ADDED_LOG_LINES {
        let mut peer = rig.owner_again();
        for _ in 0..MAX_ADDED_LOG_LINES {
            assert_eq!(peer.ask(add(&worst)), ACCEPTED);
        }
    }
    let first = page(&mut alice, None);
    assert!(first.dropped, "a first read after a loss must say so");
    let lost = (sent - KEPT_ADDED_LOG_LINES) as u64;
    assert_eq!(first.lines[0].seq, lost + 1);
    assert!(
        first.lines.len() < KEPT_ADDED_LOG_LINES,
        "it cannot all fit"
    );

    let read = alice.whole_log();
    let seqs: Vec<u64> = read.iter().map(|line| line.seq).collect();
    let kept: Vec<u64> = (lost + 1..=sent as u64).collect();
    assert_eq!(seqs, kept, "every line once, in order");
    for line in &alice.lines {
        assert!(line.len() < MAX_LINE_BYTES, "{} bytes", line.len());
    }
    let run = first.run;
    let at = |seq| Some(LogCursor { run, seq });
    assert!(page(&mut alice, at(lost - 1)).dropped);
    assert!(!page(&mut alice, at(lost)).dropped);
    let end = page(&mut alice, at(sent as u64));
    assert_eq!(
        (end.lines.len(), end.next, end.dropped),
        (0, sent as u64, false)
    );

    // Another run: its lines start at 1 again, and the old place means
    // nothing in it.
    rig.stop();
    rig.start().unwrap();
    let mut alice = rig.owner_again();
    assert_eq!(alice.ask(add("in the new run")), ACCEPTED);
    let old = page(&mut alice, at(sent as u64));
    assert_ne!(old.run, run);
    assert_eq!(
        (texts(&old.lines), old.next, old.dropped),
        (vec!["in the new run"], 1, false)
    );
}

// What the service says about itself: enough to help, and nothing that
// names a path or a user.
#[test]
fn diagnostics_describe_the_service_and_name_no_path_or_user() {
    let rig = rig();
    let mut alice = rig.owner();
    let idle = diagnostics(&mut alice);
    assert_eq!(idle.service_version, ubc_vpn_core::VERSION);
    assert_eq!(
        idle.protocol_version,
        ubc_vpn_core::protocol::PROTOCOL_VERSION
    );
    assert_eq!(
        (idle.os.as_str(), idle.arch.as_str()),
        (std::env::consts::OS, std::env::consts::ARCH)
    );
    assert_eq!(
        (idle.state, idle.subnets, idle.dns_domains),
        (StateKind::Disconnected, 0, 0)
    );
    assert_eq!((idle.policy_readable, idle.pins), (true, 1));
    assert_eq!(idle.gateway.as_deref(), Some("vpn.example.test"));
    assert!(idle.owner_claimed && idle.last_error.is_none());
    assert!(idle.uptime_s < 60);

    connected(&mut alice);
    let up = diagnostics(&mut alice);
    assert_eq!(
        (up.state, up.subnets, up.dns_domains),
        (StateKind::Connected, 2, 1)
    );

    // A failure is remembered after the state has moved on.
    assert_eq!(alice.ask(RequestBody::Disconnect), ACCEPTED);
    assert_eq!(alice.state(), ConnState::Disconnecting);
    assert_eq!(alice.state(), ConnState::Disconnected);
    rig.engine.set_reachable(false);
    let failed = alice.connect_ends(good());
    assert!(matches!(failed, ConnState::Failed { .. }), "{failed:?}");
    rig.engine.set_reachable(true);
    assert_eq!(alice.connect_ends(good()), ConnState::LoginNeeded);
    let after = diagnostics(&mut alice);
    assert_eq!(after.state, StateKind::LoginNeeded);
    let last = after.last_error.expect("the failure is remembered");
    assert_eq!(last.code, ErrorCode::GatewayUnreachable);

    let root = rig.root.to_string_lossy().replace('\\', "\\\\");
    for line in &alice.lines {
        assert!(!line.contains(&root) && !line.contains("alice"), "{line}");
    }
}

// Security rule: a client hands over what its login wrote just after a
// connect has failed, so the service still removes that connect's cookie
// from a line then, though the tunnel is gone. It stops as soon as the next
// connect is admitted: by then it knows only the next one's.
#[test]
fn a_line_added_just_after_a_connect_failed_still_loses_its_cookie() {
    let rig = rig();
    let mut alice = rig.owner();
    rig.engine.set_reachable(false);
    let failed = alice.connect_ends(good());
    assert!(matches!(failed, ConnState::Failed { .. }), "{failed:?}");
    let line = format!("the client says {COOKIE}");
    assert_eq!(alice.ask(add(&line)), ACCEPTED);

    let other = "another-made-up-cookie-000";
    let subnets = ["10.255.0.0/24", "192.0.2.0/24"];
    let next = connect(other, GATEWAY, &subnets, &[]);
    let failed = alice.connect_ends(next);
    assert!(matches!(failed, ConnState::Failed { .. }), "{failed:?}");
    assert_eq!(alice.ask(add(&format!("{line} and {other}"))), ACCEPTED);
    let read = alice.whole_log();
    let added = |line: &&LogLine| line.source == LogSource::Login;
    let added: Vec<&str> = read.iter().filter(added).map(|l| l.text.as_str()).collect();
    let now = format!("{line} and [redacted]");
    assert_eq!(added, ["the client says [redacted]", now.as_str()]);
}

// Security rule: nothing a client can do again and again pushes the earlier
// lines out of the log. Here the log holds one line of the service's own.
// More requests that cannot be read than the log has room for come from the
// owner, one to a connection; then the owner asks for a disconnect, which
// fails the same way each time, more often than the log has room for.
#[test]
fn no_number_of_requests_pushes_the_earlier_lines_out() {
    let mut rig = Rig::stopped(None);
    rig.start().unwrap();
    let mut alice = rig.owner();
    for _ in 0..ubc_vpn_service::LOG_CAPACITY + 20 {
        let mut noisy = rig.owner_again();
        noisy.conn.write_line("this is not a request").unwrap();
        assert!(noisy.is_closed());
    }
    let denied = Some(Error::PermissionDenied);
    rig.fake.set_failure(Op::ClearSplitDns, denied);
    for _ in 0..ubc_vpn_service::LOG_CAPACITY / 2 + 20 {
        assert_eq!(alice.ask(RequestBody::Disconnect), ACCEPTED);
        assert_eq!(alice.state(), ConnState::Disconnecting);
        assert!(matches!(alice.state(), ConnState::Failed { .. }));
    }
    let read = alice.whole_log();
    let lines = texts(&read);
    assert!(lines[0].contains("policy file"), "the first line is gone");
    assert_eq!(lines.len(), 3, "{lines:?}");
    assert!(lines[1].contains("from the owner could not be understood"));
    assert!(lines[2].contains("clearing split DNS failed"));
    assert!(!page(&mut alice, None).dropped);
}

// With no policy the service still answers, and says so.
#[test]
fn diagnostics_say_when_there_is_no_policy() {
    let mut rig = Rig::stopped(None);
    rig.start().unwrap();
    let mut alice = rig.owner();
    let report = diagnostics(&mut alice);
    assert_eq!(
        (report.policy_readable, report.pins, report.gateway),
        (false, 0, None)
    );
    // Why is in the log, as an error of the service's own.
    let read = alice.whole_log();
    assert_eq!(
        (read[0].seq, read[0].level, read[0].source),
        (1, LogLevel::Error, LogSource::Service)
    );
    assert!(read[0].text.as_str().contains("policy file"));
}
