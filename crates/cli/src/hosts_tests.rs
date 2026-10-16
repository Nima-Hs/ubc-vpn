//! `diagnostics --host`, against the real service on the fakes, with
//! made-up hosts resolved by a stand-in for the system's resolver.

use std::cell::RefCell;
use std::net::IpAddr;

use ubc_vpn_core::coverage::{HostCoverage, TunnelKnown};
use ubc_vpn_core::protocol::decode;

use crate::connect_tests::{CODE, PASSWORD, ROUTES, Scene, Typist};
use crate::hosts::{Args, check, plain_host};
use crate::tests::Rig;
use crate::{FAILED, NOT_OWNER, USAGE};

/// The saved routes are `10.255.0.0/24` and the DNS domain
/// `dept.example.test` (see `connect_tests.rs`). These hosts are made up.
const OUTSIDE: &str = "ssh.elsewhere.example";
const INSIDE: &str = "build.dept.example.test";

/// What the stand-in resolver answers, and what it was asked.
struct Names {
    asked: RefCell<Vec<String>>,
}

impl Names {
    fn new() -> Self {
        Self {
            asked: RefCell::new(Vec::new()),
        }
    }

    fn resolve(&self, host: &str) -> std::io::Result<Vec<IpAddr>> {
        self.asked.borrow_mut().push(host.to_string());
        let found: &[&str] = match host {
            OUTSIDE => &["192.0.2.25"],
            INSIDE => &["10.255.0.7"],
            "mixed.example.test" => &["10.255.0.8", "198.51.100.4", "2001:db8::4"],
            "empty.example.test" => &[],
            _ => return Err(std::io::ErrorKind::NotFound.into()),
        };
        Ok(found.iter().map(|ip| ip.parse().unwrap()).collect())
    }
}

/// Runs `diagnostics` with `args` after it, resolving with `names`.
fn run_with(rig: &Rig, names: &Names, args: &[&str]) -> (u8, String, String) {
    let platform = || Ok(rig.fake.platform(&rig.root));
    let resolve = |host: &str| names.resolve(host);
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let args = Args::parse(args).expect("arguments the command takes");
    let code = check(&args, &platform, &resolve, &mut out, &mut err);
    let text = |bytes| String::from_utf8(bytes).unwrap();
    (code, text(out), text(err))
}

fn connected() -> Scene {
    let scene = Scene::usual();
    let mut typist = Typist::typing(&[Some(PASSWORD), Some(CODE)]);
    let (status, _, err) = scene.connect(&mut typist);
    assert_eq!(status, 0, "{err}");
    scene
}

// The issue's case: a server outside the saved routes is reported as not
// covered, and as not going through the connected tunnel.
#[test]
fn a_host_outside_the_routes_is_reported_as_not_covered() {
    let (scene, names) = (connected(), Names::new());
    let (status, out, err) = run_with(&scene.rig, &names, &["--host", OUTSIDE]);
    assert_eq!((status, err.as_str()), (0, ""));
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(
        lines,
        [
            "Host: ssh.elsewhere.example",
            "DNS: under no saved domain, looked up as usual",
            "Tunnel: connected",
            "192.0.2.25: not covered by any saved network; does not go through the tunnel",
            "Covered: no. Traffic to 192.0.2.25 goes over the usual network, not the VPN. \
             To send it through the VPN, add a network that holds it to the routes in the app.",
        ]
    );

    let (status, out, _) = run_with(&scene.rig, &names, &["--host", OUTSIDE, "--json"]);
    assert_eq!((status, out.lines().count()), (0, 1));
    let report: HostCoverage = decode(out.trim_end()).unwrap();
    assert!(!report.covered);
    assert_eq!(report.tunnel, TunnelKnown::Connected);
    assert_eq!(report.addresses[0].saved_network, None);
    assert_eq!(report.addresses[0].tunnel_route, None);
}

#[test]
fn a_host_inside_the_routes_is_covered_and_goes_through_the_tunnel() {
    let (scene, names) = (connected(), Names::new());
    let (status, out, err) = run_with(&scene.rig, &names, &["--json", "--host", INSIDE]);
    assert_eq!((status, err.as_str()), (0, ""));
    let report: HostCoverage = decode(out.trim_end()).unwrap();
    assert!(report.covered);
    assert_eq!(
        report.saved_dns_domain.as_deref(),
        Some("dept.example.test")
    );
    assert_eq!(
        report.tunnel_dns_domain.as_deref(),
        Some("dept.example.test")
    );
    let network = Some("10.255.0.0/24".parse().unwrap());
    assert_eq!(report.addresses[0].saved_network, network);
    assert_eq!(report.addresses[0].tunnel_route, network);

    let (_, out, _) = run_with(&scene.rig, &names, &["--host", INSIDE]);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(
        lines[1],
        "DNS: under the saved domain dept.example.test, looked up through the tunnel while connected"
    );
    assert_eq!(
        lines[3],
        "10.255.0.7: covered by the saved network 10.255.0.0/24; \
         goes through the tunnel by 10.255.0.0/24"
    );
    assert_eq!(lines[4], "Covered: yes.");
}

// Every address is said, and the host is covered only if all of them are.
#[test]
fn each_address_is_said_and_one_outside_is_enough() {
    let (scene, names) = (connected(), Names::new());
    let (_, out, _) = run_with(&scene.rig, &names, &["--host", "mixed.example.test"]);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(
        &lines[3..6],
        [
            "10.255.0.8: covered by the saved network 10.255.0.0/24; \
             goes through the tunnel by 10.255.0.0/24",
            "198.51.100.4: not covered by any saved network; does not go through the tunnel",
            "2001:db8::4: not covered: the routes hold IPv4 networks only; \
             does not go through the tunnel",
        ]
    );
    assert!(
        lines[6].starts_with("Covered: no. Traffic to 198.51.100.4, 2001:db8::4 goes"),
        "{out}"
    );
}

// Not connected, the saved routes are still checked, and a name under a
// saved domain is said to have been looked up without the tunnel's DNS.
#[test]
fn not_connected_the_saved_routes_are_still_checked() {
    let (scene, names) = (Scene::usual(), Names::new());
    let (status, out, err) = run_with(&scene.rig, &names, &["--host", INSIDE]);
    assert_eq!((status, err.as_str()), (0, ""));
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines[2], "Tunnel: not connected");
    assert!(lines[3].contains("without the tunnel's DNS"), "{out}");
    assert_eq!(
        lines[4],
        "10.255.0.7: covered by the saved network 10.255.0.0/24"
    );
    assert_eq!(lines[5], "Covered: yes.");

    // Nor is anyone made the owner by it: someone else still can be.
    scene.rig.claim_as_someone_else();

    // Without a service there is no tunnel either.
    let rig = Rig::new();
    let (status, out, _) = run_with(&rig, &names, &["--host", OUTSIDE, "--json"]);
    assert_eq!(status, 0);
    let report: HostCoverage = decode(out.trim_end()).unwrap();
    assert_eq!(report.tunnel, TunnelKnown::NotConnected);
    assert!(!report.covered);
}

// To someone who is not the owner the service does not say; the saved
// routes are checked all the same, and why the tunnel is unknown is said.
#[test]
fn a_tunnel_the_service_will_not_tell_of_is_unknown() {
    let (scene, names) = (Scene::usual(), Names::new());
    scene.rig.claim_as_someone_else();
    let (status, out, err) = run_with(&scene.rig, &names, &["--host", INSIDE]);
    assert_eq!(status, 0);
    assert!(out.contains("Tunnel: not known"), "{out}");
    assert!(out.contains("Covered: yes."), "{out}");
    assert!(
        err.starts_with(
            "ubc-vpn: Whether the VPN is connected is not known: You are not the owner"
        ),
        "{err}"
    );
    // The same failure on its own is still the owner's exit status.
    assert_eq!(scene.rig.run(&["status"]).0, NOT_OWNER);
}

// A saved route added after the connect covers the host, but the tunnel was
// set up without it: that is said, with what to do.
#[test]
fn routes_saved_after_the_connect_are_told_apart() {
    let (scene, names) = (connected(), Names::new());
    let wider = ROUTES.replace(
        r#"["10.255.0.0/24"]"#,
        r#"["10.255.0.0/24","192.0.2.0/24"]"#,
    );
    let settings = format!(r#"{{"username":"alice",{wider}}}"#);
    std::fs::write(scene.rig.root.join("settings/settings.json"), settings).unwrap();
    let (_, out, _) = run_with(&scene.rig, &names, &["--host", OUTSIDE]);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(
        lines[3],
        "192.0.2.25: covered by the saved network 192.0.2.0/24; does not go through the tunnel"
    );
    assert!(lines[4].contains("Disconnect and connect again"), "{out}");
}

// A name that is not a plain host name is refused before it is looked up.
#[test]
fn only_a_plain_host_name_or_an_address_is_looked_up() {
    let (rig, names) = (Rig::new(), Names::new());
    let odd = [
        "",
        ".",
        "a..b",
        "-x.example",
        "has space.example",
        "esc\u{1b}[2J.example",
        "café.example",
        "a/b",
    ];
    for host in odd {
        let (status, out, err) = run_with(&rig, &names, &["--host", host]);
        assert_eq!((status, out.as_str()), (USAGE, ""), "{host:?}");
        // What was given is never printed back: it could hold anything.
        let control = err.trim_end_matches('\n').chars().any(char::is_control);
        assert!(!control, "a control character on stderr: {err:?}");
        if host.len() > 1 {
            assert!(!err.contains(host), "the name given was printed: {err:?}");
        }
        assert_eq!(err, "ubc-vpn: That is not a host name or an IP address.\n");
    }
    let long = format!("{}.example", "a".repeat(64));
    assert_eq!(run_with(&rig, &names, &["--host", &long]).0, USAGE);
    assert!(names.asked.borrow().is_empty(), "{:?}", names.asked);

    assert_eq!(
        plain_host("SSH.Example.Test."),
        Some("ssh.example.test.".to_string())
    );
    assert_eq!(plain_host("192.0.2.1"), Some("192.0.2.1".to_string()));
    assert_eq!(plain_host("2001:db8::1"), Some("2001:db8::1".to_string()));
    assert_eq!(
        plain_host("_srv.example.test"),
        Some("_srv.example.test".to_string())
    );
}

#[test]
fn a_name_that_does_not_resolve_is_a_failure() {
    let (scene, names) = (Scene::usual(), Names::new());
    for host in ["nowhere.example.test", "empty.example.test"] {
        let (status, out, err) = run_with(&scene.rig, &names, &["--host", host]);
        assert_eq!((status, out.as_str()), (FAILED, ""));
        assert_eq!(
            err,
            format!("ubc-vpn: {host} could not be resolved to an address.\n")
        );
    }
}

#[test]
fn unreadable_settings_are_a_failure() {
    let (scene, names) = (Scene::new(Some("[1]"), ""), Names::new());
    let (status, out, err) = run_with(&scene.rig, &names, &["--host", OUTSIDE]);
    assert_eq!((status, out.as_str()), (FAILED, ""));
    assert!(err.contains("settings file cannot be read"), "{err}");
}

#[test]
fn only_these_arguments_are_taken() {
    let host = |json| {
        Some(Args {
            host: "h.example",
            json,
        })
    };
    assert_eq!(Args::parse(&["--host", "h.example"]), host(false));
    assert_eq!(Args::parse(&["--host", "h.example", "--json"]), host(true));
    assert_eq!(Args::parse(&["--json", "--host", "h.example"]), host(true));
    let rig = Rig::new();
    let odd = [
        &["diagnostics", "--host"][..],
        &["diagnostics", "--host", "a.example", "b.example"],
        &["diagnostics", "--host", "a.example", "--follow"],
        &["diagnostics", "--json", "--host"],
        &["diagnostics", "--host", "--json", "a.example"],
        &["diagnostics", "a.example"],
    ];
    for args in odd {
        let (status, out, err) = rig.run(args);
        assert_eq!((status, out.as_str()), (USAGE, ""), "{args:?}");
        assert!(err.starts_with("Usage:"), "{args:?}");
    }
}

// The system's resolver gives an address back as itself, without asking
// any server.
#[test]
fn the_system_resolver_takes_an_address_as_it_is() {
    let found = crate::hosts::system("192.0.2.1").unwrap();
    assert_eq!(found, [IpAddr::from([192, 0, 2, 1])]);
}
