//! A real `ubc-vpn-service --dev` stopped as launchd and systemd stop the
//! installed service: with `SIGTERM`. It must remove everything it applied
//! before it exits, while connected and while connecting, and a second
//! signal during that must not cut it short.
//!
//! What the service did is read from what it writes to standard error when
//! it has stopped in dev mode: the lines it logged from the request to stop
//! on, and whether anything is left on its fake routing and DNS.
//!
//! Linux and macOS only: Windows stops a service through its service
//! manager, which `ubc-vpn-service`'s own tests cover. It runs when
//! `UBC_VPN_SYSTEM_SERVICE` names a service built with the `dev-mode`
//! feature, and says `RAN: service stop` when it has, as the system test
//! does. Everything it starts has a home of its own under one temporary
//! folder (see `support::Home`), so no installed service is reached.
#![cfg(all(feature = "dev-mode", unix))]

mod support;

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use support::{CODE, Home, PASSWORD, ROUTES, Running, SERVICE, USERNAME, within};

/// What the service writes once its teardown at shutdown has removed what
/// a connection applied.
const REMOVED: &str = "logged at the end: everything applied for the connection was removed";
const NOTHING_LEFT: &str = "dev mode: no routes or DNS are left applied";
const STOPPED: &str = " has stopped";

fn signal(name: &str, process: u32) {
    let sent = Command::new("kill")
        .args([name, &process.to_string()])
        .status();
    assert!(sent.expect("kill runs").success(), "kill {name} {process}");
}

/// A paused process, resumed when the test lets go of it, however it ends.
struct Paused(u32);

impl Paused {
    fn pause(process: u32) -> Self {
        signal("-STOP", process);
        Self(process)
    }
}

impl Drop for Paused {
    fn drop(&mut self) {
        let _ = Command::new("kill")
            .args(["-CONT", &self.0.to_string()])
            .status();
    }
}

/// Starts the service and waits until it answers.
fn start(home: &Home, service: &Path) -> Running {
    let running = Running::start(home.command(service, &[]), &home.said);
    let first = within("the service to listen", || {
        let (status, out) = home.run(&["status"], "");
        (status != 3).then_some((status, out))
    });
    assert_eq!(first, (0, "Disconnected".to_string()));
    running
}

/// Waits for the service to end by itself and returns its exit status. One
/// ended by a signal has none, which fails the test.
fn ends(service: &mut Running) -> i32 {
    let ended = within("the service to end", || service.child.try_wait().unwrap());
    ended
        .code()
        .unwrap_or_else(|| panic!("ended by a signal: {ended:?}"))
}

/// What everything wrote, once the service's last line has arrived.
fn said_by_the_end(home: &Home) -> String {
    within("the service's last line", || {
        let said = home.said.lock().unwrap().clone();
        said.contains(STOPPED).then_some(said)
    })
}

/// Where `text` is in `said`, which must have it.
fn at(said: &str, text: &str) -> usize {
    said.find(text)
        .unwrap_or_else(|| panic!("no {text:?} in:\n{said}"))
}

#[test]
fn sigterm_removes_everything_before_the_service_exits() {
    let Some(service) = std::env::var_os(SERVICE) else {
        eprintln!("SKIPPED: service stop: {SERVICE} does not name a dev-mode service");
        return;
    };
    // A connect saves a username, and a release build keeps it in the OS
    // keyring. CI's machines are thrown away; nobody else's may be touched.
    if !cfg!(debug_assertions) && std::env::var_os("CI").is_none() {
        eprintln!("SKIPPED: service stop: a release build would use the OS keyring; CI only");
        return;
    }
    let service = Path::new(&service);

    // Connected. The service is paused while both signals are sent, so the
    // second is certain to come while the first is being seen to.
    let home = Home::new();
    let mut running = start(&home, service);
    assert_eq!(home.run(&["settings", "set-routes", "--json"], ROUTES).0, 0);
    let (status, last) = home.connect(&[Some(USERNAME), Some(PASSWORD), Some(CODE)]);
    assert_eq!((status, last.as_str()), (0, r#"{"type":"done"}"#));
    let (status, shown) = home.run(&["status"], "");
    let first = shown.lines().next().unwrap_or("");
    assert_eq!((status, first), (0, "Connected (fake0 as 10.255.0.2)"));
    let paused = Paused::pause(running.child.id());
    signal("-TERM", running.child.id());
    signal("-INT", running.child.id());
    drop(paused);
    assert_eq!(ends(&mut running), 0, "{}", home.said.lock().unwrap());
    let said = said_by_the_end(&home);
    let asked = at(&said, "logged at the end: asked to stop (");
    let removed = at(&said, REMOVED);
    let nothing = at(&said, NOTHING_LEFT);
    assert!(
        asked < removed && removed < nothing,
        "out of order:\n{said}"
    );
    assert!(nothing < at(&said, STOPPED), "{said}");
    assert_eq!(home.run(&["status"], "").0, 3, "the service is gone");
    drop(home);

    // While connecting. The service is paused once the last question is
    // asked, so the connect request waits for it, and SIGTERM is sent
    // before it is resumed: it wakes to both at once. The dev-mode connect
    // takes a few milliseconds, so how far it gets first varies; however
    // far that is, nothing is left.
    let home = Home::new();
    let mut running = start(&home, service);
    assert_eq!(home.run(&["settings", "set-routes", "--json"], ROUTES).0, 0);
    let mut bridge = home.client(&["bridge"]);
    bridge.until(r#""type":"ready""#);
    let mut client = home.client(&["connect", "--json"]);
    for (id, answer) in [(1, USERNAME), (2, PASSWORD)] {
        client.until(&format!(r#"{{"type":"prompt","id":{id},"#));
        client.say(&format!(
            r#"{{"type":"answer","id":{id},"value":"{answer}"}}"#
        ));
    }
    client.until(r#"{"type":"prompt","id":3,"#);
    let paused = Paused::pause(running.child.id());
    client.say(&format!(r#"{{"type":"answer","id":3,"value":"{CODE}"}}"#));
    // Time for the login to finish and the request to go.
    std::thread::sleep(Duration::from_secs(1));
    signal("-TERM", running.child.id());
    drop(paused);
    assert_eq!(ends(&mut running), 0, "{}", home.said.lock().unwrap());
    let said = said_by_the_end(&home);
    let asked = at(&said, "logged at the end: asked to stop (terminate)");
    assert!(asked < at(&said, NOTHING_LEFT), "{said}");
    // If anything was applied, it was removed after the request to stop.
    let applied = "logged at the end: routes and DNS applied";
    if said.contains(applied) {
        assert!(at(&said, applied) < at(&said, REMOVED), "{said}");
    }
    // The app hears that the service went, and the connect ends too.
    bridge.until(r#"{"type":"service_unavailable"}"#);
    client.end();
    drop(home);
    println!("RAN: service stop");
}
