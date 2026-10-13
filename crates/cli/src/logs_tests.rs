//! `logs` and `diagnostics`, against the real service on the fakes and, for
//! what a real service would never send, against a stand-in.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ubc_vpn_core::protocol::{
    AddLogParams, LogLevel, LogSource, Outcome, Request, Response, ServerMessage, StateKind, decode,
};
use ubc_vpn_platform::fake::paths;

use super::*;
use crate::client::Limits;
use crate::connect_tests::{CODE, PASSWORD, Scene, Typist};
use crate::tests::{Rig, greet, scripted, tell};
use crate::{NOT_OWNER, NOT_RUNNING, USAGE};
use ubc_vpn_core::VERSION;

/// A scene whose service has logged a connect.
fn connected() -> Scene {
    let scene = Scene::usual();
    let mut typist = Typist::typing(&[Some(PASSWORD), Some(CODE)]);
    let (status, _, err) = scene.connect(&mut typist);
    assert_eq!(status, 0, "{err}");
    scene
}

/// Adds a line to the service's log, as a client's login would.
fn add(rig: &Rig, text: &str) {
    let platform = rig.fake.platform(&rig.root);
    let name = &platform.paths.channel_name;
    let mut client = Client::connect(&*platform.transport, name, ClientKind::Cli).unwrap();
    let (level, text) = (LogLevel::Error, text.to_string());
    let added = client.request(RequestBody::AddLog(AddLogParams { level, text }));
    assert_eq!(added.ok(), Some(ResponseBody::Accepted));
}

#[test]
fn logs_prints_each_line_with_its_time_level_and_source() {
    let scene = connected();
    add(&scene.rig, "Login failed.");
    let (status, out, err) = scene.rig.run(&["logs"]);
    assert_eq!((status, err.as_str()), (0, ""));
    let lines: Vec<&str> = out.lines().collect();
    let ends = [
        "  info   engine   CSTP connected",
        "  error  login    Login failed.",
    ];
    assert_eq!(lines.len(), ends.len(), "{out}");
    for (line, end) in lines.iter().zip(ends) {
        let (when, rest) = line.split_at(20);
        assert_eq!(rest, end, "{line}");
        // A date and a time of day in UTC, this century.
        assert!(when.starts_with("20") && when.ends_with('Z'), "{line}");
        assert_eq!((&when[4..5], &when[10..11], &when[13..14]), ("-", " ", ":"));
    }

    // With --json, the same lines in the protocol's own shape.
    let (status, out, err) = scene.rig.run(&["logs", "--json"]);
    assert_eq!((status, err.as_str()), (0, ""));
    let lines: Vec<LogLine> = out.lines().map(|line| decode(line).unwrap()).collect();
    let seen = |line: &LogLine| (line.seq, line.source, line.text.as_str().to_string());
    let expected = [
        (1, LogSource::Engine, "CSTP connected".to_string()),
        (2, LogSource::Login, "Login failed.".to_string()),
    ];
    assert_eq!(lines.iter().map(seen).collect::<Vec<_>>(), expected);
}

#[test]
fn a_long_log_is_read_to_its_end_and_a_loss_is_said() {
    let scene = connected();
    let worst = "\"".repeat(512);
    // More than the service keeps of such lines, and more than one answer
    // can hold.
    for _ in 0..6 {
        let platform = scene.rig.fake.platform(&scene.rig.root);
        let name = &platform.paths.channel_name;
        let mut client = Client::connect(&*platform.transport, name, ClientKind::Cli).unwrap();
        for _ in 0..20 {
            let (level, text) = (LogLevel::Error, worst.clone());
            let added = client.request(RequestBody::AddLog(AddLogParams { level, text }));
            assert_eq!(added.ok(), Some(ResponseBody::Accepted));
        }
    }
    let (status, out, err) = scene.rig.run(&["logs", "--json"]);
    assert_eq!(status, 0, "{err}");
    let seqs: Vec<u64> = out
        .lines()
        .map(|line| decode::<LogLine>(line).unwrap().seq)
        .collect();
    // The engine's line, then the hundred added lines that are still kept.
    let kept: Vec<u64> = std::iter::once(1).chain(22..=121).collect();
    assert_eq!(seqs, kept);
    assert_eq!(
        err.matches("no longer kept by the service").count(),
        1,
        "{err}"
    );
}

// Reading is not using: neither command makes anyone the owner, and
// neither answers anyone but the owner.
#[test]
fn neither_command_claims_the_service_or_answers_a_stranger() {
    let rig = Rig::new();
    for command in ["logs", "diagnostics"] {
        let (status, out, err) = rig.run(&[command]);
        assert_eq!((status, out.as_str()), (NOT_RUNNING, ""), "{err}");
    }
    let _service = rig.service();
    for args in [&["logs"][..], &["logs", "--json"], &["diagnostics"]] {
        let (status, out, err) = rig.run(args);
        assert_eq!((status, out.as_str()), (FAILED, ""));
        assert!(err.contains("Nobody has used UBC VPN"), "{err}");
    }
    // Nobody was made the owner by that: someone else still can be.
    rig.claim_as_someone_else();
    for args in [
        &["logs"][..],
        &["logs", "--follow"],
        &["diagnostics", "--json"],
    ] {
        let (status, out, err) = rig.run(args);
        assert_eq!((status, out.as_str()), (NOT_OWNER, ""), "{err}");
    }
}

#[test]
fn only_these_options_are_taken() {
    let both = Options {
        json: true,
        follow: true,
    };
    assert_eq!(Options::parse(&["--follow", "--json"]), Some(both));
    assert_eq!(
        Options::parse(&[]).map(|o| (o.json, o.follow)),
        Some((false, false))
    );
    let rig = Rig::new();
    let odd = [
        &["logs", "--all"][..],
        &["logs", "--json", "--json"],
        &["logs", "follow"],
        &["diagnostics", "--follow"],
        &["diagnostics", "--json", "x"],
    ];
    for args in odd {
        let (status, out, err) = rig.run(args);
        assert_eq!((status, out.as_str()), (USAGE, ""), "{args:?}");
        assert!(err.starts_with("Usage:"), "{args:?}");
    }
}

#[test]
fn diagnostics_says_what_the_service_is_and_how_it_stands() {
    let scene = connected();
    let (status, out, err) = scene.rig.run(&["diagnostics"]);
    assert_eq!((status, err.as_str()), (0, ""));
    let lines: Vec<&str> = out.lines().collect();
    let service = format!("Service: {VERSION} (protocol 3), running for 0 h 0 min");
    let system = format!(
        "System: {} on {}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    let expected = [
        service.as_str(),
        system.as_str(),
        "State: connected, 1 subnet and 1 DNS domain",
        "Last failure: none",
        "Policy: gateway vpn.example.test, 1 pin",
        "Owner: claimed",
    ];
    assert_eq!(lines, expected);

    // With --json, one line in the protocol's own shape.
    let (status, out, _) = scene.rig.run(&["diagnostics", "--json"]);
    assert_eq!((status, out.lines().count()), (0, 1));
    let report: Diagnostics = decode(out.trim_end()).unwrap();
    assert_eq!((report.state, report.pins), (StateKind::Connected, 1));

    // A connect that the service could not finish: the failure is said
    // with its code, and nothing is counted as carried.
    let scene = Scene::usual();
    let denied = Some(ubc_vpn_platform::Error::PermissionDenied);
    let routes = ubc_vpn_platform::fake::Op::AddTunnelRoutes;
    scene.rig.fake.set_failure(routes, denied);
    let mut typist = Typist::typing(&[Some(PASSWORD), Some(CODE)]);
    assert_eq!(scene.connect(&mut typist).0, FAILED);
    let (_, out, _) = scene.rig.run(&["diagnostics"]);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines[2], "State: failed");
    let failure = "Last failure: The tunnel routes could not be added: ";
    assert!(lines[3].starts_with(failure), "{out}");
    assert!(lines[3].ends_with(" (internal)"), "{out}");

    // Before anyone has used it, to its owner-to-be it says so.
    let report = Diagnostics {
        owner_claimed: false,
        policy_readable: false,
        gateway: None,
        ..report
    };
    let said = summary(&report);
    assert!(
        said.contains("Policy: missing or not valid\nOwner: nobody yet"),
        "{said}"
    );
}

/// A stand-in for the service that answers one request with `answer`.
fn answering(rig: &Rig, answer: ResponseBody) -> std::thread::JoinHandle<()> {
    scripted(rig, move |conn| {
        greet(conn);
        let asked: Request = decode(&conn.read_line().unwrap().unwrap()).unwrap();
        let outcome = Outcome::Ok(answer);
        let id = asked.id;
        tell(conn, &ServerMessage::Response(Response { id, outcome }));
    })
}

// Security rule: what the service says is printed without a character that
// could do something to the terminal or make a line read as another. The
// real service sends none; a program in its place might.
#[test]
fn nothing_the_service_says_reaches_the_terminal_unclean() {
    let scene = connected();
    let (_, json, _) = scene.rig.run(&["diagnostics", "--json"]);
    let mut report: Diagnostics = decode(json.trim_end()).unwrap();
    drop(scene);
    let odd = "\u{1b}[2Jvpn\u{202e}.example\u{2028}.test";
    (report.gateway, report.os) = (Some(odd.to_string()), odd.to_string());
    report.service_version = odd.to_string();
    report.arch = odd.to_string();
    let rig = Rig::new();
    let service = answering(&rig, ResponseBody::Diagnostics(Box::new(report.clone())));
    let (status, out, err) = rig.run(&["diagnostics"]);
    service.join().unwrap();
    assert_eq!((status, err.as_str()), (0, ""));
    assert!(out.contains("gateway [2Jvpn.example.test,"), "{out:?}");
    let unclean = |c: char| c != '\n' && ubc_vpn_core::settings_cli::misleads(c);
    assert!(!out.chars().any(unclean), "{out:?}");

    // The same with --json: JSON writes a control character as an escape,
    // but not the unseen ones, so those are removed there too. And a name
    // far longer than the service would send is cut, in both forms.
    report.gateway = Some(format!("{odd}{}", "é".repeat(30_000)));
    for args in [&["diagnostics"][..], &["diagnostics", "--json"]] {
        let rig = Rig::new();
        let service = answering(&rig, ResponseBody::Diagnostics(Box::new(report.clone())));
        let (status, out, err) = rig.run(args);
        service.join().unwrap();
        assert_eq!((status, err.as_str()), (0, ""));
        assert!(!out.chars().any(unclean), "{args:?}");
        assert!(out.len() < 1500, "{args:?}: {} bytes", out.len());
        assert!(out.contains("vpn.example.testééé"), "{args:?}");
    }
    let rig = Rig::new();
    let service = answering(&rig, ResponseBody::Diagnostics(Box::new(report)));
    let (_, out, _) = rig.run(&["diagnostics", "--json"]);
    service.join().unwrap();
    let printed: Diagnostics = decode(out.trim_end()).unwrap();
    let gateway = printed.gateway.unwrap();
    assert!((254..=255).contains(&gateway.len()), "{}", gateway.len());
    assert_eq!(printed.os, "[2Jvpn.example.test");

    // A line of the log that is not one plain line is not a line at all:
    // nothing of it is printed.
    let rig = Rig::new();
    let service = scripted(&rig, |conn| {
        greet(conn);
        let asked: Request = decode(&conn.read_line().unwrap().unwrap()).unwrap();
        let line =
            r#"{"seq":1,"at_unix_ms":1,"level":"info","source":"engine","text":"a\u001b[2Jb"}"#;
        let page = format!(r#"{{"run":1,"lines":[{line}],"next":1,"dropped":false}}"#);
        let response = format!(
            r#"{{"id":{},"outcome":{{"status":"ok","body":{{"kind":"logs","value":{page}}}}}}}"#,
            asked.id
        );
        let _ = conn.write_line(&response);
    });
    let (status, out, err) = rig.run(&["logs"]);
    service.join().unwrap();
    assert_eq!((status, out.as_str()), (FAILED, ""), "{err}");
    assert!(!(out + &err).chars().any(unclean));
}

/// Standard output that a test can read while a command still writes.
#[derive(Clone, Default)]
struct Shared(Arc<Mutex<Vec<u8>>>);

impl Shared {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

impl Write for Shared {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Waits, up to ten seconds, for something that should happen soon.
fn until(what: &str, happened: impl Fn() -> bool) {
    let started = Instant::now();
    while !happened() {
        assert!(started.elapsed() < Duration::from_secs(10), "{what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

// With --follow the lines there are come first, then each new one as the
// service writes it, once; and it ends when the service does.
#[test]
fn follow_prints_new_lines_as_they_come_until_the_service_goes() {
    let mut scene = connected();
    let (out, err) = (Shared::default(), Shared::default());
    let (fake, root) = (scene.rig.fake.clone(), scene.rig.root.clone());
    let (mut to_out, mut to_err) = (out.clone(), err.clone());
    let following = std::thread::spawn(move || {
        let platform = || Ok(fake.platform(&root));
        let options = Options {
            json: false,
            follow: true,
        };
        logs(options, &platform, &mut to_out, &mut to_err)
    });
    until("the lines there were", || {
        out.text().contains("CSTP connected")
    });
    for n in 1..=3 {
        add(&scene.rig, &format!("made-up line {n}"));
    }
    until("the new lines", || out.text().contains("made-up line 3"));
    let text = out.text();
    let ends: Vec<&str> = text.lines().map(|line| &line[20..]).collect();
    let expected = [
        "  info   engine   CSTP connected",
        "  error  login    made-up line 1",
        "  error  login    made-up line 2",
        "  error  login    made-up line 3",
    ];
    assert_eq!(ends, expected);

    scene.service = None;
    until("the end", || following.is_finished());
    assert_eq!(following.join().unwrap(), FAILED);
    assert!(
        err.text().contains("Lost contact with the service"),
        "{}",
        err.text()
    );
}

/// Standard output that nobody reads any more.
struct Gone;

impl Write for Gone {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::ErrorKind::BrokenPipe.into())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// The service may drop a log event for a client that is slow. The gap shows
// in the numbers, and the lines are fetched: none is missed and none is
// printed twice. A stand-in plays the service, to make the gap.
#[test]
fn follow_fetches_the_lines_whose_events_were_dropped() {
    use ubc_vpn_core::protocol::{LogPage, LogText};

    let line = |seq: u64| LogLine {
        seq,
        at_unix_ms: 1_800_000_000_000,
        level: LogLevel::Info,
        source: LogSource::Service,
        text: LogText::new(&format!("line {seq}")).unwrap(),
    };
    let rig = Rig::new();
    let service = scripted(&rig, move |conn| {
        greet(conn);
        let answer = |body: ResponseBody| {
            let asked: Request = decode(&conn.read_line().unwrap().unwrap()).unwrap();
            let (id, outcome) = (asked.id, Outcome::Ok(body));
            tell(conn, &ServerMessage::Response(Response { id, outcome }));
            asked.body
        };
        let event = |seq| {
            tell(conn, &ServerMessage::Event(Event::Log(line(seq))));
        };
        answer(ResponseBody::Accepted);
        answer(ResponseBody::Logs(LogPage::after(7, 0, false, [line(1)])));
        answer(ResponseBody::Logs(LogPage::after(7, 1, false, [])));
        // An event that repeats what was read, the next line, and then one
        // from further on: lines 3 and 4 had their events dropped.
        [1, 2, 5].into_iter().for_each(event);
        let asked = answer(ResponseBody::Logs(LogPage::after(
            7,
            2,
            false,
            [line(3), line(4), line(5)],
        )));
        let after = Some(LogCursor { run: 7, seq: 2 });
        assert_eq!(asked, RequestBody::Logs(LogsParams { after }));
        answer(ResponseBody::Logs(LogPage::after(7, 5, false, [])));
        event(6);
        // Until the client has taken it all in; then the stand-in goes.
        std::thread::sleep(Duration::from_millis(300));
    });
    let (status, out, err) = rig.run(&["logs", "--follow"]);
    service.join().unwrap();
    assert_eq!(status, FAILED, "{err}");
    let printed: Vec<&str> = out.lines().map(|line| &line[20..]).collect();
    let expected: Vec<String> = (1..=6)
        .map(|seq| format!("  info   service  line {seq}"))
        .collect();
    assert_eq!(printed, expected);
}

/// A line of a stand-in's log.
fn numbered(seq: u64) -> LogLine {
    LogLine {
        seq,
        at_unix_ms: 1_800_000_000_000,
        level: LogLevel::Info,
        source: LogSource::Service,
        text: ubc_vpn_core::protocol::LogText::new(&format!("line {seq}")).unwrap(),
    }
}

/// Reads one request as a stand-in for the service.
fn asked(conn: &ubc_vpn_platform::Connection) -> Option<Request> {
    let line = conn.read_line().ok().flatten()?;
    Some(decode(&line).unwrap())
}

/// Answers `request` with `body`.
fn reply(conn: &ubc_vpn_platform::Connection, request: &Request, body: ResponseBody) {
    let (id, outcome) = (request.id, Outcome::Ok(body));
    tell(conn, &ServerMessage::Response(Response { id, outcome }));
}

/// The lines after the place `request` names, of a log that holds lines 1
/// to `have` in run 7: what the real service would answer.
fn page_of(request: &Request, have: u64) -> ubc_vpn_core::protocol::LogPage {
    let RequestBody::Logs(LogsParams { after }) = &request.body else {
        panic!("not a request for the log: {request:?}");
    };
    let after = after.map_or(0, |place| place.seq);
    ubc_vpn_core::protocol::LogPage::after(7, after, false, (after + 1..=have).map(numbered))
}

// Under load the service drops events for a client it has many waiting for,
// and that is just when many more are on their way. Those that arrive while
// the missing lines are fetched are not kept, so no number of them is too
// many: the lines they told of are read by their numbers afterwards. Every
// line is printed once, in order.
#[test]
fn follow_survives_any_number_of_events_during_a_fetch() {
    for burst in [70, 200] {
        let rig = Rig::new();
        let service = scripted(&rig, move |conn| {
            greet(conn);
            let event = |seq| {
                tell(conn, &ServerMessage::Event(Event::Log(numbered(seq))));
            };
            let serve = |have: u64| {
                let request = asked(conn).expect("a request");
                let page = page_of(&request, have);
                let empty = page.lines.is_empty();
                reply(conn, &request, ResponseBody::Logs(page));
                empty
            };
            reply(conn, &asked(conn).unwrap(), ResponseBody::Accepted);
            assert!(!serve(1) && serve(1));
            // Line 2 as it is written, then line 5: two events were dropped.
            [2, 5].into_iter().for_each(event);
            // The fetch is asked for; before it is answered, the events
            // of many more lines are already on their way.
            let request = asked(conn).expect("the fetch");
            (6..=5 + burst).for_each(event);
            reply(conn, &request, ResponseBody::Logs(page_of(&request, 5)));
            // The rest is read by its numbers, until two readings in a row
            // found nothing more.
            let mut empty = 0;
            while empty < 2 {
                empty += u8::from(serve(5 + burst));
            }
            event(6 + burst);
            // Until the client has taken it all in; then the stand-in goes.
            std::thread::sleep(Duration::from_millis(300));
        });
        let (status, out, err) = rig.run(&["logs", "--follow"]);
        service.join().unwrap();
        assert_eq!(status, FAILED, "{burst}: {err}");
        assert!(err.contains("Lost contact"), "{burst}: {err}");
        let printed: Vec<&str> = out.lines().map(|line| &line[20..]).collect();
        let expected: Vec<String> = (1..=6 + burst)
            .map(|seq| format!("  info   service  line {seq}"))
            .collect();
        assert_eq!(printed, expected, "{burst}");
    }
}

/// Runs `logs` with `args` against a stand-in that answers request number
/// `n` for the log with `page(n)`, for as long as it is asked. Returns what
/// the command did and how many requests it made.
fn against_pages(
    args: &[&str],
    page: impl Fn(usize) -> ubc_vpn_core::protocol::LogPage + Send + 'static,
) -> ((u8, String, String), usize) {
    let rig = Rig::new();
    let (counted, count) = std::sync::mpsc::channel();
    let service = scripted(&rig, move |conn| {
        greet(conn);
        let mut answered = 0;
        while let Some(request) = asked(conn) {
            reply(conn, &request, ResponseBody::Logs(page(answered)));
            answered += 1;
            // Not for ever, whatever the command does: a reading without
            // end fails its test and does not hang it.
            if answered == 1000 {
                break;
            }
        }
        counted.send(answered).unwrap();
    });
    let ran = rig.run(args);
    service.join().unwrap();
    (ran, count.recv().unwrap())
}

// Security rule: nothing that answers in the service's place can make
// `logs` print without end, print a line twice, or print lines out of
// order. `ubc-vpn logs > file` must not be able to fill a disk.
#[test]
fn a_log_that_does_not_behave_is_given_up_not_printed_for_ever() {
    use ubc_vpn_core::protocol::LogPage;
    let ends =
        |out: &str| -> Vec<String> { out.lines().map(|line| line[20..].to_string()).collect() };
    let lines = |seqs: &[u64]| -> Vec<String> {
        let line = |seq: &u64| format!("  info   service  line {seq}");
        seqs.iter().map(line).collect()
    };
    let lost = "no longer kept by the service";

    // The same page again and again, each time saying lines were lost.
    let same = |_| LogPage::after(7, 0, true, [numbered(1), numbered(2)]);
    let ((status, out, err), asked) = against_pages(&["logs"], same);
    assert_eq!((status, ends(&out)), (FAILED, lines(&[1, 2])));
    assert_eq!(asked, 2, "it went on asking");
    assert_eq!(err.matches(lost).count(), 1, "{err}");
    assert!(
        err.contains("could not be read: its lines were not in order"),
        "{err}"
    );

    // Numbers that go backwards, between pages and inside one. A page
    // with one line out of place is not printed at all.
    let backwards = |n| match n {
        0 => LogPage::after(7, 0, false, [numbered(5), numbered(6)]),
        _ => LogPage::after(7, 6, false, [numbered(3), numbered(4)]),
    };
    let ((status, out, _), asked) = against_pages(&["logs"], backwards);
    assert_eq!((status, ends(&out), asked), (FAILED, lines(&[5, 6]), 2));
    let muddled = |_| LogPage::after(7, 0, false, [numbered(2), numbered(1)]);
    let ((status, out, _), asked) = against_pages(&["logs", "--json"], muddled);
    assert_eq!((status, out.as_str(), asked), (FAILED, "", 1));

    // A run that changes from page to page.
    let flapping = |n: usize| {
        let seq = n as u64 + 1;
        LogPage::after(7 + seq % 2, seq - 1, false, [numbered(seq)])
    };
    let ((status, out, err), asked) = against_pages(&["logs"], flapping);
    assert_eq!((status, ends(&out), asked), (FAILED, lines(&[1]), 2));
    assert!(err.contains("the service started again part-way"), "{err}");

    // Lines that are in order and never end: one command reads only so
    // many pages.
    let endless = |n: usize| LogPage::after(7, n as u64, false, [numbered(n as u64 + 1)]);
    let ((status, out, err), asked) = against_pages(&["logs"], endless);
    assert_eq!((status, asked), (FAILED, MAX_PAGES));
    assert_eq!(out.lines().count(), MAX_PAGES);
    assert!(err.contains("it did not come to an end"), "{err}");
}

/// Standard output on a disk that is full.
struct Full;

impl Write for Full {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::ErrorKind::StorageFull.into())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// Only a pipe whose reader has gone is passed over in silence. Output that
// cannot be written for another reason is a failure, and is said.
#[test]
fn output_that_cannot_be_written_is_a_failure() {
    let scene = connected();
    let platform = || Ok(scene.rig.fake.platform(&scene.rig.root));
    let options = Options {
        json: false,
        follow: false,
    };
    let mut err = Vec::new();
    assert_eq!(logs(options, &platform, &mut Full, &mut err), FAILED);
    let err = String::from_utf8(err).unwrap();
    assert!(err.contains("The output could not be written"), "{err}");
    let mut err = Vec::new();
    assert_eq!(diagnostics(true, &platform, &mut Full, &mut err), FAILED);
    assert!(!err.is_empty());
    assert_eq!(diagnostics(false, &platform, &mut Gone, &mut Vec::new()), 0);
}

// `ubc-vpn logs --follow | head` ends quietly when `head` has had enough.
#[test]
fn a_reader_that_has_gone_ends_the_command_without_complaint() {
    let scene = connected();
    let platform = || Ok(scene.rig.fake.platform(&scene.rig.root));
    let mut err = Vec::new();
    let options = Options {
        json: true,
        follow: true,
    };
    let limits = Limits::default();
    let started = Instant::now();
    assert_eq!(logs(options, &platform, &mut Gone, &mut err), 0);
    assert!(started.elapsed() < limits.answer, "it went on waiting");
    assert_eq!(String::from_utf8(err).unwrap(), "");
    let _ = paths(&scene.rig.root);
}

#[test]
fn a_time_is_shown_as_a_date_and_a_time_of_day_in_utc() {
    assert_eq!(time(0), "1970-01-01 00:00:00Z");
    assert_eq!(time(999), "1970-01-01 00:00:00Z");
    assert_eq!(time(1_800_000_000_000), "2027-01-15 08:00:00Z");
    // The last second of a leap day, and the first of the next day.
    assert_eq!(time(1_709_251_199_000), "2024-02-29 23:59:59Z");
    assert_eq!(time(1_709_251_200_000), "2024-03-01 00:00:00Z");
    assert_eq!(time(4_102_444_799_999), "2099-12-31 23:59:59Z");
}
