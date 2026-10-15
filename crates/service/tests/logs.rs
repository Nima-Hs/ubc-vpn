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

/// The lines that are not the service's own: the engine's and the ones
/// clients added.
fn others(lines: Vec<LogLine>) -> Vec<LogLine> {
    let other = |line: &LogLine| line.source != LogSource::Service;
    lines.into_iter().filter(other).collect()
}

/// The next log event that is not one of the service's own lines.
fn next_other(peer: &mut Peer) -> LogLine {
    loop {
        let line = peer.log();
        if line.source != LogSource::Service {
            return line;
        }
    }
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
    let first = next_other(&mut alice);
    assert_eq!(first.source, LogSource::Engine);
    let second = next_other(&mut alice);
    assert_eq!(second.seq, first.seq + 1);
    assert_eq!(
        texts(&[first.clone(), second.clone()]),
        ["> [redacted]", "CSTP connected"]
    );
    let read = others(alice.whole_log());
    assert_eq!(read[0], first);
    assert_eq!(texts(&read), ["> [redacted]", "CSTP connected"]);

    // A line from elsewhere reaches the one that watches, and only it.
    assert_eq!(other.ask(add("Login failed.")), ACCEPTED);
    let added = next_other(&mut alice);
    assert!(added.seq > second.seq);
    assert_eq!(added.text.as_str(), "Login failed.");
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
    assert_eq!(others(alice.whole_log()).len(), 4);
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
    let read = others(alice.whole_log());
    let expected = [
        "> [redacted]",
        "CSTP connected",
        "the client says [redacted]",
        "[redacted]",
    ];
    assert_eq!(texts(&read), expected);
    diagnostics(&mut alice);
    (0..4).for_each(|_| drop(next_other(&mut alice)));
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
        others(alice.whole_log()).is_empty(),
        "something of a refused line was kept"
    );

    // The refused ones did not count.
    for n in 0..MAX_ADDED_LOG_LINES {
        assert_eq!(alice.ask(add(&format!("line {n}"))), ACCEPTED);
    }
    assert_eq!(alice.ask(add("one too many")), REFUSED);
    assert_eq!(others(alice.whole_log()).len(), MAX_ADDED_LOG_LINES);
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
        texts(&read).last().copied(),
        Some(
            "a request from the owner could not be understood; later ones are not noted while this line is in the log"
        )
    );
    assert!(others(read).is_empty(), "a refused line was kept");
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
    // The service's own lines about starting, and about the owner.
    let before = page(&mut alice, None);
    let own = before.lines.len() as u64;
    assert_eq!((before.next, before.dropped), (own, false));

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
    let lost = own + (sent - KEPT_ADDED_LOG_LINES) as u64;
    let last = own + sent as u64;
    assert_eq!(first.lines[own as usize].seq, lost + 1);
    assert!(
        first.lines.len() < KEPT_ADDED_LOG_LINES,
        "it cannot all fit"
    );

    let read = alice.whole_log();
    let seqs: Vec<u64> = read.iter().map(|line| line.seq).collect();
    let kept: Vec<u64> = (1..=own).chain(lost + 1..=last).collect();
    assert_eq!(seqs, kept, "every line once, in order");
    for line in &alice.lines {
        assert!(line.len() < MAX_LINE_BYTES, "{} bytes", line.len());
    }
    let run = first.run;
    let at = |seq| Some(LogCursor { run, seq });
    assert!(page(&mut alice, at(lost - 1)).dropped);
    assert!(!page(&mut alice, at(lost)).dropped);
    let end = page(&mut alice, at(last));
    assert_eq!((end.lines.len(), end.next, end.dropped), (0, last, false));

    // Another run: its lines start at 1 again, and the old place means
    // nothing in it.
    rig.stop();
    rig.start().unwrap();
    let mut alice = rig.owner_again();
    assert_eq!(alice.ask(add("in the new run")), ACCEPTED);
    let old = page(&mut alice, at(last));
    assert_ne!(old.run, run);
    assert_eq!(old.lines[0].seq, 1);
    assert!(old.lines[0].text.as_str().starts_with("service started"));
    let lines = texts(&old.lines);
    assert_eq!(lines.last(), Some(&"in the new run"));
    assert_eq!((old.next, old.dropped), (lines.len() as u64, false));
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
    assert!(
        lines[0].starts_with("service started"),
        "the first line is gone"
    );
    assert!(lines[1].contains("policy file"), "the second line is gone");
    let count = |what: &str| lines.iter().filter(|line| line.contains(what)).count();
    assert_eq!(count("from the owner could not be understood"), 1);
    assert_eq!(count("clearing split DNS failed"), 1);
    // A disconnect of nothing writes no line of its own, and the same
    // failure again and again, with nothing between, is said once.
    assert_eq!(count("failed: internal:"), 1);
    assert_eq!(count(ubc_vpn_service::NOT_LOGGED), 0);
    assert!(!page(&mut alice, None).dropped);
}

// Security rule: the budget for lines that requests cause can never hide
// what came of a connect. Once a client has spent it on connects that are
// refused (as the app's renderer could on purpose), the next `connected`
// and the next failure are still written.
#[test]
fn a_spent_budget_hides_no_connection_or_failure() {
    use ubc_vpn_service::{NOT_LOGGED, REQUEST_LINES};
    let rig = rig();
    let mut alice = rig.owner();
    for _ in 0..REQUEST_LINES + 5 {
        let elsewhere = connect(COOKIE, [0, 0, 0, 0], &["10.255.0.0/24"], &[]);
        assert_eq!(alice.ask(elsewhere), Err(ErrorCode::BadRequest));
    }
    connected(&mut alice);
    assert_eq!(alice.ask(RequestBody::Disconnect), ACCEPTED);
    assert_eq!(alice.state(), ConnState::Disconnecting);
    assert_eq!(alice.state(), ConnState::Disconnected);
    rig.engine.set_reachable(false);
    let failed = alice.connect_ends(good());
    assert!(matches!(failed, ConnState::Failed { .. }), "{failed:?}");

    let lines = own_lines(&mut alice);
    let after = lines.iter().position(|line| line == NOT_LOGGED);
    let after = &lines[after.expect("the budget was spent") + 1..];
    let said = |what: &str| after.iter().any(|line| line.starts_with(what));
    assert!(said("connected"), "{after:?}");
    assert!(said("routes and DNS applied"), "{after:?}");
    assert!(
        said("everything applied for the connection was removed"),
        "{after:?}"
    );
    assert!(said("disconnected"), "{after:?}");
    assert!(said("failed: gateway_unreachable"), "{after:?}");
    // And the requests themselves are not: the budget is spent.
    assert!(!said("connect admitted"), "{after:?}");
}

// Each connect that was admitted has its outcome in the log, even when it
// ends the same way as the one before: a user who retries while something
// is wrong is exactly who the log is for.
#[test]
fn every_admitted_connect_has_its_outcome_written() {
    let rig = rig();
    let mut alice = rig.owner();
    rig.engine.set_reachable(false);
    for _ in 0..2 {
        let failed = alice.connect_ends(good());
        assert!(matches!(failed, ConnState::Failed { .. }), "{failed:?}");
    }
    let lines = own_lines(&mut alice);
    let ends = |line: &&String| line.starts_with("connect admitted") || line.starts_with("failed:");
    let kinds: Vec<_> = lines.iter().filter(ends).map(|line| &line[..8]).collect();
    assert_eq!(
        kinds,
        ["connect ", "failed: ", "connect ", "failed: "],
        "{lines:?}"
    );
}

// The same for a connect stopped by a disconnect before it was up, in a
// service whose last state line was already `disconnected`.
#[test]
fn a_cancelled_connect_has_its_outcome_written() {
    let rig = rig();
    let mut alice = rig.owner();
    connected(&mut alice);
    assert_eq!(alice.ask(RequestBody::Disconnect), ACCEPTED);
    assert_eq!(alice.state(), ConnState::Disconnecting);
    assert_eq!(alice.state(), ConnState::Disconnected);
    rig.engine.hold();
    assert_eq!(alice.ask(good()), ACCEPTED);
    rig.engine.wait_until_blocked();
    assert_eq!(alice.ask(RequestBody::Disconnect), ACCEPTED);
    let heard = [alice.state(), alice.state(), alice.state()];
    assert_eq!(heard[2], ConnState::Disconnected, "{heard:?}");
    rig.engine.release();

    let lines = own_lines(&mut alice);
    let last = lines
        .iter()
        .rposition(|line| line.starts_with("connect admitted"));
    let after = &lines[last.expect("a connect was admitted") + 1..];
    assert!(after.iter().any(|line| line == "disconnected"), "{lines:?}");
}

// The first line says which kind of run this is.
#[test]
fn the_first_line_says_installed() {
    let rig = rig();
    let mut alice = rig.owner();
    let lines = own_lines(&mut alice);
    assert!(lines[0].ends_with(", installed"), "{lines:?}");
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
    assert!(read[0].text.as_str().starts_with("service started"));
    assert_eq!(
        (read[1].seq, read[1].level, read[1].source),
        (2, LogLevel::Error, LogSource::Service)
    );
    assert!(read[1].text.as_str().contains("policy file"));
}

/// The service's own lines, as text.
fn own_lines(peer: &mut Peer) -> Vec<String> {
    let own = |line: &LogLine| line.source == LogSource::Service;
    let lines = peer.whole_log().into_iter().filter(own);
    lines.map(|line| line.text.as_str().to_string()).collect()
}

// Security rule: a connect that is admitted but stops before the gateway is
// contacted costs the client nothing, so asking for it again and again must
// not fill the log. Here each one asks for the home network the machine is
// on, which is refused once the network has been looked at: the same
// failure every time. The service's first lines are still there after more
// such connects than the log holds.
#[test]
fn connects_that_never_reach_the_gateway_do_not_fill_the_log() {
    let rig = rig();
    let mut alice = rig.owner();
    for round in 0..ubc_vpn_service::LOG_CAPACITY + 20 {
        let home = connect(COOKIE, GATEWAY, &["192.168.0.0/24"], &[]);
        let state = alice.connect_ends(home);
        let refused =
            matches!(&state, ConnState::Failed { code, .. } if *code == ErrorCode::RouteRefused);
        assert!(refused, "{round}: {state:?}");
    }
    assert!(rig.spy.opens().is_empty(), "the gateway was contacted");
    let lines = own_lines(&mut alice);
    assert!(lines[0].starts_with("service started"), "{lines:?}");
    assert!(lines[1].starts_with("policy read"), "{lines:?}");
    // The failure itself is in the log, once.
    let failures = lines
        .iter()
        .filter(|line| line.starts_with("failed: route_refused"));
    assert_eq!(failures.count(), 1, "{lines:?}");
}

// Security rule: the same for a connect followed at once by a disconnect,
// which stops it before the gateway is contacted. Here the connect is held
// while it looks at the network, so the disconnect always comes first. The
// service's first lines are still there after more such rounds than the log
// holds, and `disconnected` is said at most once: it started so.
#[test]
fn connect_then_disconnect_again_and_again_does_not_fill_the_log() {
    let rig = rig();
    let mut alice = rig.owner();
    for round in 0..ubc_vpn_service::LOG_CAPACITY + 20 {
        rig.os.hold_at(Op::CapturePhysical);
        assert_eq!(alice.ask(good()), Ok(ResponseBody::Accepted), "{round}");
        rig.os.wait_until_held();
        assert_eq!(
            alice.ask(RequestBody::Disconnect),
            Ok(ResponseBody::Accepted)
        );
        rig.os.release();
        let heard = [alice.state(), alice.state(), alice.state()];
        let expected = [
            ConnState::Connecting,
            ConnState::Disconnecting,
            ConnState::Disconnected,
        ];
        assert_eq!(heard, expected, "{round}");
    }
    let lines = own_lines(&mut alice);
    assert!(lines[0].starts_with("service started"), "{lines:?}");
    assert!(lines[1].starts_with("policy read"), "{lines:?}");
    let disconnected = lines.iter().filter(|line| *line == "disconnected");
    assert!(disconnected.count() <= 1, "{lines:?}");
}

// What someone helping the user reads after an ordinary session, a connect
// refused for its routes, and a disconnect when nothing was connected: a
// line for each thing that happened, in order, and none that only repeats.
#[test]
fn an_ordinary_session_is_in_the_log() {
    let allowed = r#","allowed_routes":["10.255.0.0/24","192.0.2.0/24"]"#;
    let mut rig = Rig::stopped(policy('A', allowed));
    rig.start().unwrap();
    let mut alice = rig.owner();
    // Claiming again changes nothing, and is not news.
    assert_eq!(alice.ask(RequestBody::Claim), Ok(ResponseBody::Claimed));
    connected(&mut alice);
    assert_eq!(alice.ask(RequestBody::Disconnect), ACCEPTED);
    assert_eq!(alice.state(), ConnState::Disconnecting);
    assert_eq!(alice.state(), ConnState::Disconnected);
    let elsewhere = connect(COOKIE, GATEWAY, &["10.1.0.0/24"], &[]);
    assert_eq!(alice.ask(elsewhere), Err(ErrorCode::RouteRefused));
    assert_eq!(alice.ask(RequestBody::Disconnect), ACCEPTED);
    assert_eq!(alice.state(), ConnState::Disconnecting);
    assert_eq!(alice.state(), ConnState::Disconnected);

    let started = format!(
        "service started: version {}, protocol 3, installed",
        ubc_vpn_core::VERSION
    );
    let expected = [
        started.as_str(),
        "policy read: gateway vpn.example.test, 1 pin",
        "an owner was recorded",
        "connect admitted (2 subnets and 1 DNS domain)",
        "routes and DNS applied and checked: 2 subnet routes, 1 DNS server route, \
         split DNS for 1 domain",
        "connected",
        // The harness says it is the app; the service cannot tell.
        "disconnect requested by a client that said it was the app",
        "everything applied for the connection was removed",
        "disconnected",
        "connect refused: route_refused",
    ];
    assert_eq!(own_lines(&mut alice), expected);
    // An owner already stored is not recorded again by a restart.
    rig.stop();
    rig.start().unwrap();
    let mut again = rig.owner_again();
    assert_eq!(again.ask(RequestBody::Claim), Ok(ResponseBody::Claimed));
    let lines = own_lines(&mut again);
    assert_eq!(lines.len(), 2, "{lines:?}");
}

// Security rule: no line the service writes names the user or a path under
// the folder its files are in, which stands for a home folder here. The
// session above, a failure, and a refusal, all searched for both.
#[test]
fn no_line_names_the_user_or_a_path() {
    let rig = rig();
    let mut alice = rig.owner();
    connected(&mut alice);
    assert_eq!(alice.ask(RequestBody::Disconnect), ACCEPTED);
    assert_eq!(alice.state(), ConnState::Disconnecting);
    assert_eq!(alice.state(), ConnState::Disconnected);
    rig.engine.set_reachable(false);
    let failed = alice.connect_ends(good());
    assert!(matches!(failed, ConnState::Failed { .. }), "{failed:?}");
    rig.fake
        .set_failure(Op::ClearSplitDns, Some(Error::PermissionDenied));
    assert_eq!(alice.ask(RequestBody::Disconnect), ACCEPTED);
    assert_eq!(alice.state(), ConnState::Disconnecting);
    alice.state();
    // Someone else, whom the channel refuses.
    assert!(rig.raw("mallory").is_err());

    let lines = alice.whole_log();
    assert!(lines.len() > 8, "{:?}", texts(&lines));
    let root = rig.root.to_string_lossy().to_string();
    let parent = rig.root.parent().unwrap().to_string_lossy().to_string();
    for line in texts(&lines) {
        for name in ["alice", "mallory", root.as_str(), parent.as_str()] {
            assert!(!line.contains(name), "{name} in {line}");
        }
    }
}
