//! The channel: the handshake, who is served, and start-up. Tests marked
//! "Security rule" must fail if the rule they name is removed.

mod harness;

use std::time::{Duration, Instant};

use harness::*;
use ubc_vpn_core::protocol::{
    AddLogParams, HelloReply, LogLevel, LogsParams, PROTOCOL_VERSION, WatchLogsParams, decode,
};
use ubc_vpn_platform::fake::Applied;
use ubc_vpn_platform::{Dns, Routes, SplitDns, Transport};
use ubc_vpn_service::{MAX_CONNECTIONS, MAX_PER_STRANGER, MAX_STRANGERS};

const DISCONNECTED: Result<ResponseBody, ErrorCode> =
    Ok(ResponseBody::Status(ConnState::Disconnected));

/// A running service whose limit for strangers is `stranger`, and which the
/// OS cannot narrow to its owner, so that strangers still get through and
/// the service's own checks are what is tested.
fn open_to_all(stranger: Duration) -> Rig {
    let mut rig = Rig::stopped(policy('A', ""));
    rig.timeouts.stranger = stranger;
    let broken = Some(Error::Unsupported);
    rig.fake.set_failure(Op::RestrictTo, broken);
    rig.start().unwrap();
    rig
}

const NEVER: Duration = Duration::from_secs(120);

// Security rule: until someone claims the service it carries out nothing but
// `claim`, and tells nobody its state.
#[test]
fn nothing_but_claim_is_served_before_a_claim() {
    let rig = rig();
    let mut alice = rig.peer("alice");
    assert!(!alice.hello.owner_claimed);
    for body in [RequestBody::Status, RequestBody::Disconnect, good()] {
        assert_eq!(alice.ask(body), Err(ErrorCode::NotClaimed));
    }
    assert!(alice.is_quiet(), "no state is sent before the claim");

    assert_eq!(alice.ask(RequestBody::Claim), Ok(ResponseBody::Claimed));
    assert_eq!(alice.state(), ConnState::Disconnected);
    assert_eq!(alice.ask(RequestBody::Status), DISCONNECTED);
    assert_eq!(alice.ask(RequestBody::Claim), Ok(ResponseBody::Claimed));
}

// Security rule: once there is an owner, the service compares every caller
// with it. Anyone else is refused and disconnected, whatever they ask, and a
// claim by anyone else makes no new owner.
#[test]
fn a_non_owner_is_refused_and_disconnected() {
    // No time limit comes to the rescue: only the owner check closes these.
    let rig = open_to_all(NEVER);
    let mut early = rig.peer("mallory");
    // An answered request shows the service has finished taking this
    // connection in. One still between its hello and that point when the
    // claim happens is not closed by the claim; it is a stranger's
    // connection like any made later, refused at its first request.
    let before = early.ask(RequestBody::Status);
    assert_eq!(before, Err(ErrorCode::NotClaimed));
    let mut alice = rig.owner();
    let closed = early.is_closed();
    assert!(closed, "the claim closes a stranger's connection");

    let requests = [
        RequestBody::Claim,
        RequestBody::Status,
        RequestBody::Disconnect,
        good(),
        RequestBody::Logs(LogsParams { after: None }),
        RequestBody::WatchLogs(WatchLogsParams { on: true }),
        RequestBody::Diagnostics,
        RequestBody::AddLog(AddLogParams {
            level: LogLevel::Info,
            text: "made up".to_string(),
        }),
    ];
    for (n, body) in requests.into_iter().enumerate() {
        let mut stranger = rig.peer(&format!("stranger-{n}"));
        assert!(stranger.hello.owner_claimed);
        assert_eq!(stranger.ask(body), Err(ErrorCode::NotOwner));
        assert!(stranger.is_closed());
        assert_eq!(stranger.lines.len(), 1, "told nothing but the refusal");
    }
    assert_eq!(alice.ask(RequestBody::Claim), Ok(ResponseBody::Claimed));
    assert_eq!(alice.ask(RequestBody::Status), DISCONNECTED);
    // None of the strangers' requests did anything: nothing was added to
    // the log, which the owner can read.
    let Ok(ResponseBody::Logs(page)) = alice.ask(RequestBody::Logs(LogsParams { after: None }))
    else {
        panic!("the owner may read the log");
    };
    let made_up = |line: &LogLine| line.text.as_str() == "made up";
    assert!(!page.lines.iter().any(made_up), "a stranger added a line");
    let stored = std::fs::read_to_string(rig.state_dir().join("state.json")).unwrap();
    assert_eq!(stored, r#"{"owner":"alice"}"#);
}

// Security rule: a claim narrows the channel, so the OS itself refuses other
// users before any of this code runs.
#[test]
fn a_claim_narrows_the_channel_to_the_owner() {
    let rig = rig();
    assert!(rig.raw("mallory").is_ok());
    let _alice = rig.owner();
    assert_eq!(rig.raw("mallory").err(), Some(Error::PermissionDenied));
    assert!(rig.raw("alice").is_ok());
}

// When the OS cannot narrow the channel at a claim, the service says so
// once, keeps checking every request itself, and tries again later.
#[test]
fn a_narrowing_that_failed_is_tried_again() {
    let rig = open_to_all(NEVER);
    let mut alice = rig.owner();
    for n in 0..3 {
        let mut stranger = rig.peer(&format!("stranger-{n}"));
        assert_eq!(stranger.ask(RequestBody::Status), Err(ErrorCode::NotOwner));
    }
    let complaints = |rig: &Rig| {
        let about = |line: &String| line.contains("could not be narrowed");
        rig.logs().into_iter().filter(about).count()
    };
    assert_eq!(complaints(&rig), 1, "said once, not at every connection");

    // A refused claim narrows nothing: least of all to the one refused.
    let mut late = rig.peer("stranger-late");
    rig.fake.set_failure(Op::RestrictTo, None);
    assert_eq!(late.ask(RequestBody::Claim), Err(ErrorCode::NotOwner));
    // The next connection the service accepts makes it try again.
    assert_eq!(rig.peer("alice").state(), ConnState::Disconnected);
    assert_eq!(rig.raw("mallory").err(), Some(Error::PermissionDenied));
    assert_eq!(alice.ask(RequestBody::Status), DISCONNECTED);
    assert_eq!(complaints(&rig), 1);
}

// Security rule: the owner is stored, so a restart neither forgets it nor
// lets a second user claim the service.
#[test]
fn the_owner_survives_a_restart_and_nobody_else_can_claim() {
    let mut rig = rig();
    drop(rig.owner());
    rig.stop();
    rig.start().unwrap();
    let refused = rig.raw("mallory").err();
    assert_eq!(refused, Some(Error::PermissionDenied), "narrowed at once");
    let mut alice = rig.peer("alice");
    assert!(alice.hello.owner_claimed);
    let first = alice.state();
    assert_eq!(first, ConnState::Disconnected, "the owner hears the state");
    assert_eq!(alice.ask(RequestBody::Claim), Ok(ResponseBody::Claimed));
}

// Security rule: the owner is read and written only through the state
// folder the service was given, which is what checks who may change it. A
// file at the plain path, which a standard user could have made, is neither
// read nor written.
#[test]
fn the_owner_is_kept_only_in_the_state_folder_the_service_was_given() {
    let mut rig = Rig::stopped(policy('A', ""));
    let plain = rig.fake.platform(&rig.root).paths.state_dir;
    assert_ne!(plain, rig.state_dir());
    std::fs::create_dir_all(&plain).unwrap();
    std::fs::write(plain.join("state.json"), r#"{"owner":"mallory"}"#).unwrap();
    rig.start().unwrap();
    assert!(
        !rig.peer("mallory").hello.owner_claimed,
        "the plain file was read"
    );
    let _alice = rig.owner();
    let stored = std::fs::read_to_string(rig.state_dir().join("state.json")).unwrap();
    assert_eq!(stored, r#"{"owner":"alice"}"#);
    let untouched = std::fs::read_to_string(plain.join("state.json")).unwrap();
    assert_eq!(
        untouched, r#"{"owner":"mallory"}"#,
        "the plain file was written"
    );
}

/// The service's channel name, held by another program, as any local user
/// can while it is free: during an update, say, or a restart.
fn squat(rig: &Rig) -> Box<dyn ubc_vpn_platform::Listener> {
    let name = rig.platform().paths.channel_name;
    rig.fake.listen(&name).expect("the name is free")
}

// Security rule: someone who takes the service's channel name while it is
// free cannot keep the service down. It waits for the name, a while, and
// comes up once the name is free; it says once that someone else held it.
#[test]
fn a_channel_name_someone_else_holds_is_waited_for() {
    let mut rig = Rig::stopped(policy('A', ""));
    rig.timeouts.claim = Duration::from_secs(10);
    let squatter = squat(&rig);
    let releases = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        squatter.close();
    });
    let started = Instant::now();
    rig.start()
        .expect("the service comes up once the name is free");
    assert!(
        started.elapsed() >= Duration::from_millis(250),
        "it did not wait"
    );
    releases.join().unwrap();
    let mut alice = rig.owner();
    assert_eq!(alice.ask(RequestBody::Status), DISCONNECTED);
    let held = |line: &String| line.contains("held by another program");
    assert_eq!(rig.logs().iter().filter(|line| held(line)).count(), 1);
}

// Security rule: past the limit the service stops, cleanly and with a
// reason. It never uses or connects to a channel it did not make: the one
// holding the name is left as it was.
#[test]
fn a_channel_name_held_past_the_limit_stops_the_service() {
    let mut rig = Rig::stopped(policy('A', ""));
    rig.timeouts.claim = Duration::from_millis(300);
    let _squatter = squat(&rig);
    let (fake, name) = (rig.fake.clone(), rig.platform().paths.channel_name);
    // On a thread of its own, so that a start that never gives up fails
    // this test instead of hanging it.
    let started = Instant::now();
    let (ended, start) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = ended.send(rig.start());
        drop(rig);
    });
    let started_up = start.recv_timeout(Duration::from_secs(5));
    let refused = started_up.expect("it waited past its limit").unwrap_err();
    assert!(refused.contains("held by another program"), "{refused}");
    assert!(
        started.elapsed() >= Duration::from_millis(250),
        "it did not wait"
    );
    // The other program's channel still has the name.
    assert_eq!(fake.listen(&name).err(), Some(Error::AlreadyExists));
}

// Security rule: with an owner on record, a service that cannot have the OS
// keep the channel to that owner does not serve at all.
#[test]
fn a_stored_owner_the_channel_cannot_be_kept_to_stops_the_service() {
    let mut rig = rig();
    drop(rig.owner());
    rig.stop();
    let broken = Some(Error::PermissionDenied);
    rig.fake.set_failure(Op::RestrictTo, broken);
    assert!(rig.start().unwrap_err().contains("kept to the owner"));
    assert_eq!(rig.raw("alice").err(), Some(Error::NotFound));
    assert_eq!(rig.raw("mallory").err(), Some(Error::NotFound));
}

// Security rule: a state file that cannot be read or understood is never
// taken as "nobody owns the service", which would let any local user claim.
#[test]
fn a_damaged_or_unreadable_state_file_stops_the_service() {
    let mut rig = Rig::stopped(policy('A', ""));
    let file = rig.state_dir().join("state.json");
    std::fs::create_dir_all(rig.state_dir()).unwrap();
    for damaged in ["", "{}", r#"{"owner":"two words"}"#] {
        std::fs::write(&file, damaged).unwrap();
        assert!(rig.start().unwrap_err().contains("damaged"), "{damaged:?}");
        assert_eq!(rig.raw("mallory").err(), Some(Error::NotFound));
    }
    // Something is there, and it cannot be read as a file.
    std::fs::remove_file(&file).unwrap();
    std::fs::create_dir(&file).unwrap();
    assert!(rig.start().unwrap_err().contains("cannot be read"));
    assert_eq!(rig.raw("mallory").err(), Some(Error::NotFound));
}

// Security rule: an owner exists only once it is stored. If it cannot be
// stored the claim fails and nobody owns the service, in memory either.
#[test]
fn a_claim_that_cannot_be_stored_makes_no_owner() {
    let rig = rig();
    let partial = rig.state_dir().join(".state.json.new");
    // Not a file, so it is not written through or replaced.
    std::fs::create_dir_all(&partial).unwrap();
    let mut alice = rig.peer("alice");
    assert_eq!(alice.ask(RequestBody::Claim), Err(ErrorCode::Internal));
    assert_eq!(alice.ask(RequestBody::Status), Err(ErrorCode::NotClaimed));
    assert!(!rig.peer("bob").hello.owner_claimed);
    assert!(!rig.state_dir().join("state.json").exists());

    // A partial file left by a crash is no obstacle, and does not survive.
    std::fs::remove_dir(&partial).unwrap();
    std::fs::write(&partial, "left behind").unwrap();
    assert_eq!(alice.ask(RequestBody::Claim), Ok(ResponseBody::Claimed));
    assert!(!partial.exists());
    let stored = std::fs::read_to_string(rig.state_dir().join("state.json")).unwrap();
    assert_eq!(stored, r#"{"owner":"alice"}"#);
}

// A client from another version, or one that sends nonsense, is always told
// the service's version before it is disconnected.
#[test]
fn a_mismatched_or_unreadable_hello_is_answered_before_the_close() {
    let rig = rig();
    let v = PROTOCOL_VERSION;
    let proper =
        |v: u32| format!(r#"{{"protocol_version":{v},"client":"cli","client_version":"0.1.0"}}"#);
    let hellos = [
        // Well formed, and from another version.
        proper(v + 1),
        proper(v - 1),
        // This version, and not a hello this version knows.
        format!(r#"{{"protocol_version":{v},"client":"cli","client_version":"0","owner":"me"}}"#),
        format!(r#"{{"protocol_version":{v},"client":"tray","client_version":"0"}}"#),
        "not json".to_string(),
    ];
    for hello in hellos {
        let conn = rig.raw("alice").unwrap();
        conn.write_line(&hello).unwrap();
        let reply: HelloReply = decode(&conn.read_line().unwrap().unwrap()).unwrap();
        assert_eq!(reply.protocol_version, PROTOCOL_VERSION);
        // Whatever it asks next goes unanswered: the connection is closed.
        let _ = conn.write_line(r#"{"id":1,"body":{"method":"claim"}}"#);
        let after = conn.read_line();
        let closed = matches!(after, Ok(None) | Err(Error::Closed));
        assert!(closed, "{hello} was served: {after:?}");
    }
    assert!(
        !rig.peer("alice").hello.owner_claimed,
        "nothing was claimed"
    );
}

// Security rule: a client that says nothing is dropped after the limit and
// delays nobody else in the meantime. The owner is not such a client.
#[test]
fn a_silent_client_is_dropped_and_stalls_nobody() {
    // With a limit far longer than the test, alice is served while the
    // silent client is still being waited for.
    let patient = open_to_all(NEVER);
    let _silent = patient.raw("mallory").unwrap();
    assert_eq!(patient.owner().ask(RequestBody::Status), DISCONNECTED);

    let strict = open_to_all(Duration::from_secs(1));
    let (silent, mut slow) = (strict.raw("mallory").unwrap(), strict.peer("mallory"));
    let answered = silent.read_line().unwrap().is_some();
    assert!(answered, "a client with no hello is answered all the same");
    assert_eq!(silent.read_line(), Ok(None), "then dropped");
    // Nobody owns the service yet, so only the limit can have closed this.
    assert!(slow.is_closed(), "a stranger who never asks is dropped");

    // The same once there is an owner, for a stranger and for the owner's
    // own hello. But the owner's app is idle for hours between requests.
    let mut alice = strict.owner();
    let (mut stranger, late) = (strict.peer("trudy"), strict.raw("alice").unwrap());
    assert!(stranger.is_closed(), "a silent stranger is dropped");
    assert!(late.read_line().unwrap().is_some());
    assert_eq!(late.read_line(), Ok(None), "no hello, even from the owner");
    std::thread::sleep(Duration::from_millis(1500));
    assert_eq!(alice.ask(RequestBody::Status), DISCONNECTED);
}

// Fail closed: without a usable policy there is no gateway to trust, so
// every connect is refused. Status still works.
#[test]
fn without_a_valid_policy_every_connect_is_refused() {
    let no_pins = r#"{"gateway":"vpn.example.test","pins":[]}"#.to_string();
    for policy in [None, Some("{".to_string()), Some(no_pins)] {
        let mut rig = Rig::stopped(policy);
        rig.start().unwrap();
        let mut alice = rig.owner();
        assert_eq!(alice.ask(good()), Err(ErrorCode::PolicyInvalid));
        assert_eq!(alice.ask(RequestBody::Status), DISCONNECTED);
        // Just after the line that says the service started.
        assert!(rig.logs()[1].contains("policy file"));
    }
}

// Whatever a crashed run left applied is removed before anyone can connect:
// here the channel never opens at all, and the cleanup has still happened.
#[test]
fn start_up_cleans_up_before_it_listens() {
    let mut rig = Rig::stopped(policy('A', ""));
    let gateway = [192, 0, 2, 1].into();
    let physical = rig.fake.capture_physical(gateway).unwrap();
    let subnets = ["10.255.0.0/24".parse().unwrap()];
    let dns = SplitDns {
        resolvers: vec![[10, 255, 0, 53].into()],
        domains: vec!["ece.example.test".to_string()],
    };
    rig.fake.add_gateway_route(gateway, &physical).unwrap();
    rig.fake.add_tunnel_routes("old0", &subnets).unwrap();
    rig.fake.set_split_dns("old0", &dns).unwrap();

    let broken = Some(Error::PermissionDenied);
    rig.fake.set_failure(Op::Listen, broken);
    assert!(rig.start().is_err());
    assert_eq!(rig.fake.applied(), Applied::default());
    let cleanup = [Op::RemoveAllRoutes, Op::ClearSplitDns];
    assert_eq!(rig.fake.calls()[4..], cleanup);
}

/// Connects as `name` until the service answers a hello, for a place that
/// is given back a moment after its connection closes.
fn gets_a_place(rig: &Rig, name: &str) -> bool {
    (0..200).any(|_| {
        std::thread::sleep(Duration::from_millis(10));
        let conn = rig.raw(name).unwrap();
        // A refused connection may already be closed.
        let _ = conn.write_line("{}");
        conn.read_line().ok().flatten().is_some()
    })
}

// Security rule: strangers can hold only so many connections, and fewer
// than the service serves in all, so they cannot use up its threads and
// keep the owner out. A place is given back when its connection ends.
#[test]
fn strangers_cannot_crowd_out_the_owner() {
    let rig = open_to_all(NEVER);
    let mut alice = rig.owner();
    // The owner was a stranger when she connected, and holds one place.
    let strangers = (1..MAX_STRANGERS).map(|n| rig.peer(&format!("stranger-{n}")));
    let mut held: Vec<_> = strangers.collect();
    let refused = rig.raw("one-too-many").unwrap();
    assert_eq!(refused.read_line(), Ok(None), "closed without a word");

    let owners = (MAX_STRANGERS..MAX_CONNECTIONS).map(|_| rig.peer("alice"));
    let mut more: Vec<_> = owners.collect();
    assert_eq!(more[0].ask(RequestBody::Status), DISCONNECTED);
    let full = rig.raw("alice").unwrap();
    assert_eq!(full.read_line(), Ok(None), "the total is limited too");

    drop((held.pop(), more.pop()));
    assert!(
        gets_a_place(&rig, "newcomer"),
        "a stranger's place came back"
    );
    assert!(gets_a_place(&rig, "alice"), "and so did the owner's");
    assert_eq!(alice.ask(RequestBody::Status), DISCONNECTED);
}

// Security rule: one user cannot hold all the strangers' places, and so
// cannot keep the first real user from claiming an unclaimed service.
#[test]
fn one_stranger_cannot_hold_every_strangers_place() {
    let rig = open_to_all(NEVER);
    let greedy = (0..MAX_PER_STRANGER).map(|_| rig.peer("mallory"));
    let mut held: Vec<_> = greedy.collect();
    for _ in 0..MAX_STRANGERS {
        let refused = rig.raw("mallory").unwrap();
        assert_eq!(refused.read_line(), Ok(None), "closed without a word");
    }
    // Still held, and still no obstacle to anyone else.
    assert_eq!(held[0].ask(RequestBody::Status), Err(ErrorCode::NotClaimed));
    let mut alice = rig.owner();
    assert_eq!(alice.ask(RequestBody::Status), DISCONNECTED);
    drop(held.pop());
    assert!(gets_a_place(&rig, "mallory"), "her own place came back");
}

// Security rule: nothing a client sends is written to the log, where a
// session cookie would outlive the request. And a stranger cannot fill the
// log with complaints about what they send.
#[test]
fn nothing_from_a_request_reaches_the_log() {
    let rig = rig();
    let unreadable = format!(r#"{{"id":2,"body":{{"method":"connect","cookie":"{COOKIE}"}}}}"#);
    for n in 0..3 {
        let mut stranger = rig.peer(&format!("stranger-{n}"));
        stranger.conn.write_line(&unreadable).unwrap();
        assert!(stranger.is_closed(), "no answer to what is not a request");
    }
    let mut alice = rig.owner();
    assert_eq!(alice.ask(good()), Ok(ResponseBody::Accepted));
    alice.conn.write_line(&unreadable).unwrap();
    // After the events of the connect that was accepted.
    assert!((0..5).any(|_| alice.is_closed()));

    let logs = rig.logs();
    let about = |who: &str| {
        let told = |line: &&String| line.contains(who) && line.contains("not be understood");
        logs.iter().filter(told).count()
    };
    assert_eq!(about("not the owner"), 1, "counted, not logged each time");
    assert_eq!(about("from the owner"), 1);
    assert!(!logs.join("\n").contains(COOKIE), "{logs:?}");
}

/// Makes `link` a symbolic link to the file `target`, where the OS and the
/// user's rights allow it.
fn link_to_file(target: &std::path::Path, link: &std::path::Path) -> std::io::Result<()> {
    #[cfg(unix)]
    return std::os::unix::fs::symlink(target, link);
    #[cfg(windows)]
    return std::os::windows::fs::symlink_file(target, link);
}

// Security rule: the state file is never written through a link. A link at
// the partial file's name is replaced, and what it pointed at is untouched.
#[test]
fn the_owner_is_never_written_through_a_link() {
    let rig = rig();
    let state = rig.state_dir();
    std::fs::create_dir_all(&state).unwrap();
    let target = rig.root.join("someone-elses-file");
    std::fs::write(&target, "precious").unwrap();
    if let Err(error) = link_to_file(&target, &state.join(".state.json.new")) {
        // Windows lets only an admin, or anyone in Developer Mode, make one.
        eprintln!("SKIPPED the_owner_is_never_written_through_a_link: no link ({error})");
        return;
    }
    let _alice = rig.owner();
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "precious");
    let stored = state.join("state.json");
    assert!(std::fs::symlink_metadata(&stored).unwrap().is_file());
    let owner = std::fs::read_to_string(stored).unwrap();
    assert_eq!(owner, r#"{"owner":"alice"}"#);
}

/// A checked state folder, as dev mode opens it, at the rig's state folder,
/// and a way to let everyone change it, as a standard user could have.
#[cfg(all(windows, feature = "dev-mode"))]
mod checked {
    use super::*;
    use ubc_vpn_platform::Mode;

    pub fn open(rig: &Rig) -> StateDir {
        let paths = ubc_vpn_platform::Paths {
            state_dir: rig.state_dir(),
            ..rig.platform().paths
        };
        StateDir::open(Mode::Dev, &paths).expect("a fresh dev-mode state folder")
    }

    /// Grants Everyone modify on the folder and what it holds.
    pub fn open_to_everyone(rig: &Rig) {
        let granted = std::process::Command::new("icacls")
            .arg(rig.state_dir())
            .args(["/grant", "*S-1-1-0:(OI)(CI)(M)"])
            .output()
            .expect("icacls runs");
        assert!(granted.status.success(), "{granted:?}");
    }
}

// Security rule: the owner is read through the state folder's checks, not
// around them. A folder anyone may change stops the service, even when it
// holds a well-formed owner.
#[cfg(all(windows, feature = "dev-mode"))]
#[test]
fn a_state_folder_others_may_change_is_not_read() {
    let mut rig = Rig::stopped(policy('A', ""));
    let state = checked::open(&rig);
    state.write("state.json", br#"{"owner":"alice"}"#).unwrap();
    rig.start_with(state.clone())
        .expect("a safe folder is used");
    rig.stop();
    checked::open_to_everyone(&rig);
    let refused = rig.start_with(state).unwrap_err();
    assert!(refused.contains("not safe to use"), "{refused}");
    assert!(!refused.contains(".."), "{refused}");
    assert_eq!(rig.raw("alice").err(), Some(Error::NotFound));
}

// Security rule: the owner is written through the same checks. A claim made
// after the folder was opened to others is refused, and nobody owns the
// service.
#[cfg(all(windows, feature = "dev-mode"))]
#[test]
fn a_state_folder_others_may_change_is_not_written() {
    let mut rig = Rig::stopped(policy('A', ""));
    let state = checked::open(&rig);
    rig.start_with(state).expect("a safe folder is used");
    checked::open_to_everyone(&rig);
    let mut alice = rig.peer("alice");
    assert_eq!(alice.ask(RequestBody::Claim), Err(ErrorCode::Internal));
    assert_eq!(alice.ask(RequestBody::Status), Err(ErrorCode::NotClaimed));
    assert!(!rig.state_dir().join("state.json").exists());
}
