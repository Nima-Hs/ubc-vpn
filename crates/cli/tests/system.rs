//! The real programs together: `ubc-vpn-service --dev` as a child process,
//! and `ubc-vpn --dev` run against it over the real channel. No fake
//! transport and nothing scripted; only routing, DNS and the gateway are
//! pretend, as dev mode makes them.
//!
//! It runs only when `UBC_VPN_SYSTEM_SERVICE` names a service built with the
//! `dev-mode` feature, and says `RAN: system` when it has. The workflow that
//! sets the variable also checks for that line, so a skip cannot pass there.
//!
//! What keeps this apart from a real UBC VPN on the same machine:
//!
//! - Both programs run with `--dev`, whose files and channel are never the
//!   installed product's.
//! - Every child gets a home of its own under one temporary folder, removed
//!   at the end. On Linux `XDG_CONFIG_HOME` holds dev mode's files and
//!   `XDG_RUNTIME_DIR` its socket; on macOS `HOME` and `TMPDIR` do; on
//!   Windows `USERPROFILE` holds the files.
//! - On Windows the dev channel is a pipe named after the user, not after
//!   the profile, so it is shared with any other dev-mode service this user
//!   runs. The test checks first that none is running, with a bridge, which
//!   claims nothing, and fails if one is.
//!
//! Not covered here: a second user of the computer, who must be refused.
//! That needs an account this test cannot make without admin rights; the
//! elevated tests of the platform crate cover it.
#![cfg(feature = "dev-mode")]

mod support;

use std::path::Path;

use support::{CODE, COOKIE, Home, PASSWORD, ROUTES, Running, SERVICE, USERNAME, within};

#[test]
fn the_service_and_the_client_work_together() {
    let Some(service) = std::env::var_os(SERVICE) else {
        eprintln!("SKIPPED: system: {SERVICE} does not name a dev-mode service");
        return;
    };
    let home = Home::new();
    let state = |state: &str| format!(r#""state":"{state}""#);
    let connected = "Connected (fake0 as 10.255.0.2)\n  Subnets: 10.255.0.0/24\n  \
                     DNS domains: ece.example.test";

    // Nothing is running yet. On Windows this also shows that no other
    // dev-mode service of this user holds the channel. A bridge asks, since
    // it claims nothing: a developer's own service is left as it was.
    let (status, line) = home.run(&["bridge"], "");
    let nobody = (1, r#"{"type":"service_unavailable"}"#.to_string());
    assert_eq!((status, line), nobody, "a service is running already");
    assert_eq!(home.run(&["status"], "").0, 3);

    let start = || Running::start(home.command(Path::new(&service), &[]), &home.said);
    let running = start();
    // The first status that finds the service also makes this user its owner.
    let first = within("the service to listen", || {
        let (status, out) = home.run(&["status"], "");
        (status != 3).then_some((status, out))
    });
    assert_eq!(first, (0, "Disconnected".to_string()));

    // Settings: nothing saved yet, then a small set of routes.
    let (status, shown) = home.run(&["settings", "get", "--json"], "");
    assert!(status == 0 && shown.contains(r#""subnets":[]"#), "{shown}");
    let (status, checked) = home.run(&["settings", "check-routes", "--json"], ROUTES);
    assert!(
        status == 0 && checked.contains("10.255.0.0/24"),
        "{checked}"
    );
    let (status, saved) = home.run(&["settings", "set-routes", "--json"], ROUTES);
    assert_eq!((status, &saved), (0, &checked));
    let (status, shown) = home.run(&["settings", "get", "--json"], "");
    assert!(status == 0 && shown.contains("ece.example.test"), "{shown}");
    // Settings that can be read are not reset by asking.
    let (status, kept) = home.run(&["settings", "reset", "--json"], "");
    assert_eq!((status, kept.as_str()), (0, r#"{"type":"not_needed"}"#));
    let (status, refused) = home.run(&["settings", "set-routes", "--json"], "not json");
    assert_eq!((status, refused.as_str()), (1, r#"{"error":"bad_input"}"#));

    // The bridge, held open as the app holds it.
    let mut bridge = home.client(&["bridge"]);
    let ready = bridge.until(r#""type":"ready""#);
    assert!(ready.contains(r#""owner_claimed":true"#), "{ready}");
    bridge.say(r#"{"id":1,"body":{"method":"status"}}"#);
    let answered = bridge.until(r#""id":1"#);
    assert!(answered.contains(&state("disconnected")), "{answered}");

    // Connect and disconnect, twice: the pretend gateway takes a new login
    // after a log-off. The username is asked for the first time only: once
    // a connect made with it was accepted, it is remembered.
    let everything = [Some(USERNAME), Some(PASSWORD), Some(CODE)];
    for round in 1..=2 {
        let replies = &everything[round - 1..];
        let (status, last) = home.connect(replies);
        assert_eq!(
            (status, last.as_str()),
            (0, r#"{"type":"done"}"#),
            "{round}"
        );
        bridge.until(&state("connecting"));
        bridge.until(&state("connected"));
        assert_eq!(home.run(&["status"], ""), (0, connected.to_string()));
        // What the service logged and what it says of itself, read from a
        // terminal's side. Each connect leaves the engine's line.
        let (status, log) = home.run(&["logs"], "");
        let opened = log.matches("  info   engine   CSTP connected").count();
        assert_eq!((status, opened), (0, round), "{log}");
        let (status, about) = home.run(&["diagnostics"], "");
        let carrying = "State: connected, 1 subnet and 1 DNS domain";
        assert!(status == 0 && about.contains(carrying), "{about}");
        // Connected already: busy, and nothing is asked.
        let (status, last) = home.connect(&[]);
        assert!(status == 7 && last.contains(r#""code":"busy""#), "{last}");

        let (status, out) = home.run(&["disconnect"], "");
        assert_eq!((status, out.as_str()), (0, "Disconnected"), "{round}");
        bridge.until(&state("disconnecting"));
        bridge.until(&state("disconnected"));
    }

    let (_, shown) = home.run(&["settings", "get", "--json"], "");
    assert!(shown.contains(r#""username":"alice""#), "{shown}");

    // A cancel at the password, and a wrong password: nothing is connected.
    let (status, last) = home.connect(&[None]);
    assert!(
        status == 9 && last.contains(r#""code":"cancelled""#),
        "{last}"
    );
    let wrong = [Some("wrong-password-0000"), Some(CODE)];
    let (status, last) = home.connect(&wrong);
    assert!(
        status == 8 && last.contains(r#""code":"wrong_password""#),
        "{last}"
    );
    // The gateway refused a login made with the saved username, so it is
    // forgotten, and the next connect, further down, is asked for it again.
    let (_, shown) = home.run(&["settings", "get", "--json"], "");
    assert!(shown.contains(r#""username":null"#), "{shown}");
    assert_eq!(home.run(&["status"], ""), (0, "Disconnected".to_string()));
    // In a terminal's place there is a pipe here, so the plain connect asks
    // nothing and says why.
    assert_eq!(home.run(&["connect"], "").0, 1);

    // The app quits: the bridge ends quietly, having passed on nothing else.
    let (status, rest) = bridge.end();
    assert_eq!((status, rest), (0, Vec::new()));

    // A second service cannot take the place of the one that is running.
    let (status, _) = start().end();
    assert_ne!(status, 0, "a second service started");
    assert_eq!(home.run(&["status"], ""), (0, "Disconnected".to_string()));

    // The service is killed while connected, with a bridge open. The bridge
    // says so and ends, and the client finds no service.
    // The log is being followed too: it shows the connect as it happens,
    // and ends when the service does.
    let mut bridge = home.client(&["bridge"]);
    bridge.until(r#""type":"ready""#);
    let mut log = home.client(&["logs", "--follow", "--json"]);
    let opened = r#""text":"CSTP connected""#;
    // The two connects from before are there to begin with.
    let earlier = [log.until(opened), log.until(opened)];
    let (status, _) = home.connect(&[Some(USERNAME), Some(PASSWORD), Some(CODE)]);
    assert_eq!(status, 0);
    bridge.until(&state("connected"));
    let new = log.until(opened);
    assert!(!earlier.contains(&new), "the new line is another line");
    drop(running);
    bridge.until(r#"{"type":"service_unavailable"}"#);
    assert_eq!(bridge.end(), (1, Vec::new()));
    assert_eq!(log.end().0, 1, "following ends when the service goes");
    assert_eq!(home.run(&["status"], "").0, 3);

    // Started again, it listens where the killed one did, still belongs to
    // this user, and holds no connection. The bridge claims nothing, so
    // what it is told about the owner is what the service remembered.
    let _running = start();
    let ready = within("the service to listen again", || {
        let mut bridge = home.client(&["bridge"]);
        let first = bridge.until(r#""type":"#);
        first.contains("ready").then_some(first)
    });
    assert!(ready.contains(r#""owner_claimed":true"#), "{ready}");
    assert_eq!(home.run(&["status"], ""), (0, "Disconnected".to_string()));

    // Security rule: no password, code or cookie in anything any of the
    // programs wrote, on standard output or standard error.
    // What the last programs wrote may still be on its way here.
    let said = within("everything that was written", || {
        let said = home.said.lock().unwrap().clone();
        let all = said.contains("is running") && said.contains("Run it in a terminal");
        all.then_some(said)
    });
    for secret in [PASSWORD, CODE, COOKIE, "wrong-password-0000"] {
        assert!(!said.contains(secret), "{secret} was written:\n{said}");
    }
    println!("RAN: system");
}
