//! Tests of the routing table on Linux.
//!
//! Most need root and a tunnel device, which each opens itself, so they run
//! on GitHub's runners in CI and never on a developer's machine by
//! accident: without root they say `SKIPPED, needs root`, and fail instead
//! when `UBC_VPN_REQUIRE_ROOT` is set, as it is in CI. One that passes as
//! root says `RAN AS ROOT: <name>`, which CI looks for.
//!
//! Each runs in a process of its own. Other tests in this crate switch the
//! whole process to another user for a moment, which would take away the
//! rights these need in the middle of one. They refuse to start while any
//! route carries the product's mark, as a running VPN's would: they remove
//! every such route when they end.

use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::{Mutex, Once, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use ubc_vpn_core::routes::Ipv4Net;

use super::routes::netlink::{
    self, AF_INET, AF_INET6, AF_UNSPEC, Address, IFF_RUNNING, IFF_UP, Link, RT_SCOPE_LINK,
    RT_TABLE_MAIN, RTN_UNICAST, Route,
};
use super::routes::{LinuxRoutes, Present, is_ours, local_network_holding, present, verdict};
use crate::suite::{self, Foreign};
use crate::{Error, LINUX_ROUTE_PROTOCOL, Routes, Verified};

/// Names the one test a process started by [`as_root`] runs.
const CHILD: &str = "UBC_VPN_ROUTES_TEST";
/// The folder of the process the crash test kills.
const CRASH: &str = "UBC_VPN_ROUTES_CRASH";
/// One root test at a time: they share the routing table and the test
/// addresses.
static TURN: Mutex<()> = Mutex::new(());
/// How long one test's process may take before it ends itself.
const DEADLINE: Duration = Duration::from_secs(120);
/// Every destination the tests route, with or without the mark. Nothing
/// else is ever touched.
const TEST_RANGES: [&str; 4] = [
    "192.0.2.0/24",
    "198.51.100.0/24",
    "198.18.0.0/15",
    "203.0.113.0/24",
];
/// The same for IPv6: the documentation range.
const TEST_RANGE_V6: &str = "2001:db8::/32";

/// Writes one whole line in one call, so nothing another thread prints can
/// land inside it: CI looks for these lines.
fn say(line: &str) {
    let line = format!("\n{line}\n");
    std::io::stderr().write_all(line.as_bytes()).expect("say");
}

fn net(text: &str) -> Ipv4Net {
    text.parse().expect("a network")
}

/// The routes that carry the product's mark, in every table.
fn marked() -> Vec<Route> {
    let table = netlink::routes(AF_UNSPEC).expect("the routing table");
    table.into_iter().filter(is_ours).collect()
}

/// Removes every route of the product's, and every route to a test
/// destination, however a test ends.
struct Cleanup;

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = LinuxRoutes.remove_all();
        for range in TEST_RANGES {
            let _ = ip(&["-4", "route", "flush", "root", range, "table", "main"]);
        }
        let _ = ip(&[
            "-6",
            "route",
            "flush",
            "root",
            TEST_RANGE_V6,
            "table",
            "main",
        ]);
    }
}

/// Ends the process, saying so, if a test is stuck: a stuck system call
/// cannot be interrupted any other way.
fn watchdog() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        thread::spawn(|| {
            thread::sleep(DEADLINE);
            say("HUNG: a routing test did not finish");
            drop(Cleanup);
            std::process::exit(101);
        });
    });
}

/// The path libtest knows the test function `test` in this file by.
fn test_path(test: &str) -> String {
    let module = module_path!();
    let local = module.split_once("::").map_or(module, |(_, rest)| rest);
    format!("{local}::{test}")
}

/// Runs `body` as root, in a process of its own that runs the test function
/// `test` alone, and says `RAN AS ROOT: {name}` when it passed.
fn as_root(name: &str, test: &str, body: impl FnOnce()) {
    if std::env::var(CHILD).as_deref() == Ok(test) {
        watchdog();
        let live = marked();
        assert!(
            live.is_empty(),
            "routes of a running UBC VPN are here, and these tests would remove them: {live:?}"
        );
        let _cleanup = Cleanup;
        body();
        return;
    }
    // The real user: another test may have switched the effective one.
    if rustix::process::getuid().as_raw() != 0 {
        let required = std::env::var_os("UBC_VPN_REQUIRE_ROOT").is_some();
        assert!(!required, "{name} needs root");
        say(&format!("SKIPPED, needs root: {name}"));
        return;
    }
    let _turn = TURN.lock().unwrap_or_else(PoisonError::into_inner);
    let status = Command::new(std::env::current_exe().expect("this program"))
        .args([
            "--exact",
            &test_path(test),
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, test)
        // Root again, should another test have switched the effective user
        // for a moment just as this one started.
        .uid(0)
        .status()
        .expect("start the test's own process");
    assert!(
        status.success(),
        "{name} failed in its own process: {status}"
    );
    say(&format!("RAN AS ROOT: {name}"));
}

/// Runs the system's `ip`, as somebody other than the product.
fn ip(args: &[&str]) -> Output {
    Command::new("ip").args(args).output().expect("run ip")
}

fn ip_ok(args: &[&str]) {
    let done = ip(args);
    let stderr = String::from_utf8_lossy(&done.stderr);
    assert!(done.status.success(), "ip {args:?}: {stderr}");
}

/// The router the default route on `interface` uses, if any.
fn router(interface: &str) -> Option<String> {
    let done = ip(&["-4", "route", "show", "default", "dev", interface]);
    let text = String::from_utf8_lossy(&done.stdout).into_owned();
    let line = text.lines().next()?.to_string();
    let mut words = line.split_whitespace();
    words.find(|word| *word == "via")?;
    words.next().map(str::to_string)
}

/// Changes routes and addresses as somebody other than the product: with
/// the system's own tool, without the product's mark.
struct Outsider;

impl Outsider {
    fn route(verb: &str, interface: &str, net: Ipv4Net, metric: Option<u32>) -> Output {
        let net = net.to_string();
        let mut args = vec!["-4", "route", verb, net.as_str(), "dev", interface];
        let hop = router(interface);
        if let Some(hop) = &hop {
            args.extend(["via", hop.as_str()]);
        }
        let metric = metric.map(|m| m.to_string());
        if let Some(metric) = &metric {
            args.extend(["metric", metric.as_str()]);
        }
        ip(&args)
    }

    /// Adds a route to `net` through `interface` at `metric`.
    fn add_route_at(interface: &str, net: Ipv4Net, metric: u32) {
        let done = Self::route("add", interface, net, Some(metric));
        let stderr = String::from_utf8_lossy(&done.stderr);
        assert!(done.status.success(), "add {net} on {interface}: {stderr}");
    }
}

impl Foreign for Outsider {
    fn add_route(&self, interface: &str, net: Ipv4Net) {
        let done = Self::route("add", interface, net, None);
        let stderr = String::from_utf8_lossy(&done.stderr);
        assert!(done.status.success(), "add {net} on {interface}: {stderr}");
    }

    fn remove_route(&self, interface: &str, net: Ipv4Net) {
        let done = Self::route("del", interface, net, None);
        let stderr = String::from_utf8_lossy(&done.stderr);
        let gone = stderr.contains("No such process");
        assert!(
            done.status.success() || gone,
            "remove {net} on {interface}: {stderr}"
        );
    }

    fn add_address(&self, interface: &str, address: Ipv4Addr) {
        ip_ok(&[
            "-4",
            "addr",
            "add",
            &format!("{address}/24"),
            "dev",
            interface,
        ]);
    }

    fn addresses(&self, interface: &str) -> Vec<Ipv4Addr> {
        let done = ip(&["-4", "-o", "addr", "show", "dev", interface]);
        assert!(done.status.success(), "list the addresses of {interface}");
        let text = String::from_utf8_lossy(&done.stdout).into_owned();
        let mut found = Vec::new();
        for line in text.lines() {
            let mut words = line.split_whitespace();
            if words.any(|word| word == "inet") {
                let with_len = words.next().expect("an address after inet");
                let addr = with_len.split('/').next().expect("an address");
                found.push(addr.parse().expect("an IPv4 address"));
            }
        }
        found
    }

    fn add_route_v6(&self, interface: &str, dest: Ipv6Addr, prefix_len: u8) {
        ip_ok(&[
            "-6",
            "route",
            "add",
            &format!("{dest}/{prefix_len}"),
            "dev",
            interface,
        ]);
    }

    fn remove_route_v6(&self, interface: &str, dest: Ipv6Addr, prefix_len: u8) {
        ip_ok(&[
            "-6",
            "route",
            "del",
            &format!("{dest}/{prefix_len}"),
            "dev",
            interface,
        ]);
    }

    fn add_address_v6(&self, interface: &str, address: Ipv6Addr) {
        let address = format!("{address}/64");
        ip_ok(&["-6", "addr", "add", &address, "dev", interface, "nodad"]);
    }

    fn remove_address_v6(&self, interface: &str, address: Ipv6Addr) {
        ip_ok(&[
            "-6",
            "addr",
            "del",
            &format!("{address}/64"),
            "dev",
            interface,
        ]);
    }

    fn set_link(&self, interface: &str, up: bool) {
        let state = if up { "up" } else { "down" };
        ip_ok(&["link", "set", "dev", interface, state]);
    }

    fn bind_ipv6(&self, interface: &str, on: bool) {
        let path = format!("/proc/sys/net/ipv6/conf/{interface}/disable_ipv6");
        std::fs::write(path, if on { "0" } else { "1" }).expect("turn IPv6 on or off");
    }
}

/// `TUNSETIFF`, `_IOW('T', 202, int)`.
const TUNSETIFF: u64 = 0x4004_54ca;
/// `TUNSETCARRIER`, `_IOW('T', 226, int)`.
const TUNSETCARRIER: u64 = 0x4004_54e2;
const IFF_TUN: u16 = 0x0001;
const IFF_NO_PI: u16 = 0x1000;

/// A tunnel device the test opened, as the engine would. It goes when this
/// is dropped, and its routes and addresses with it.
struct Tun {
    fd: OwnedFd,
    name: String,
}

impl Tun {
    fn open(name: &str) -> Self {
        let flags = rustix::fs::OFlags::RDWR | rustix::fs::OFlags::CLOEXEC;
        let fd = rustix::fs::open("/dev/net/tun", flags, rustix::fs::Mode::empty())
            .expect("open /dev/net/tun");
        // `struct ifreq`: the name, then the flags, in 40 bytes.
        let mut request = [0u8; 40];
        assert!(name.len() < 16, "a name too long for a device");
        request[..name.len()].copy_from_slice(name.as_bytes());
        request[16..18].copy_from_slice(&(IFF_TUN | IFF_NO_PI).to_ne_bytes());
        // SAFETY: `request` is a live, writable `struct ifreq` of the size
        // the call reads and writes, and `fd` is open.
        let status = unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETIFF as _, request.as_mut_ptr()) };
        assert_eq!(
            status,
            0,
            "create {name}: {}",
            std::io::Error::last_os_error()
        );
        Self {
            fd,
            name: name.to_string(),
        }
    }

    /// Says whether the device's link works, as a cable plugged in or out.
    fn set_carrier(&self, on: bool) {
        let mut value = libc::c_int::from(on);
        // SAFETY: `value` is a live `int`, which is what the call reads, and
        // the descriptor is open.
        let status =
            unsafe { libc::ioctl(self.fd.as_raw_fd(), TUNSETCARRIER as _, &raw mut value) };
        assert_eq!(
            status,
            0,
            "set the carrier: {}",
            std::io::Error::last_os_error()
        );
    }

    fn link(&self) -> Option<Link> {
        let links = netlink::links().expect("the links");
        links.into_iter().find(|link| link.name == self.name)
    }

    fn index(&self) -> u32 {
        self.link().expect("the device").index
    }
}

/// Waits up to five seconds for `done`.
fn wait_for(done: impl Fn() -> bool) -> bool {
    let started = Instant::now();
    while !done() && started.elapsed() < Duration::from_secs(5) {
        thread::sleep(Duration::from_millis(100));
    }
    done()
}

/// The physical interface: the one the way to a documentation address
/// takes before any test route exists.
fn wire() -> String {
    let physical = LinuxRoutes.capture_physical(Ipv4Addr::new(192, 0, 2, 1));
    physical.expect("capture").interface().to_string()
}

// The shared rules, on a tunnel device like the one the engine opens.
#[test]
fn passes_the_shared_route_suite_on_a_tun_device() {
    as_root(
        "routes",
        "passes_the_shared_route_suite_on_a_tun_device",
        || {
            let tun = Tun::open("uvt-suite0");
            let routes = LinuxRoutes;
            say("STEP: check_configure_tunnel");
            suite::check_configure_tunnel(&routes, &Outsider, &tun.name);
            say("STEP: check_routes");
            suite::check_routes(&routes, &tun.name);
            say("STEP: check_route_ownership");
            let restarted = || Box::new(LinuxRoutes) as Box<dyn Routes>;
            suite::check_route_ownership(&routes, &restarted, &Outsider, &tun.name);
        },
    );
}

// A change of routes on a live connection (#194), on the real routing
// table. Linux split DNS is not written yet (X2), so the fake's DNS stands
// in for that half until it is.
#[test]
fn passes_the_shared_live_route_change_check() {
    let test = "passes_the_shared_live_route_change_check";
    as_root("live route change", test, || {
        let tun = Tun::open("uvt-live0");
        let routes = LinuxRoutes;
        routes
            .configure_tunnel(&tun.name, Ipv4Addr::new(198, 18, 0, 4), 1300)
            .expect("configure");
        let dns = crate::fake::Fake::new();
        suite::check_live_route_change(&routes, &dns, &tun.name, &|name| dns.resolvers_for(name));
    });
}

// The mark is the whole rule, for IPv6 as for IPv4: start-up removes an
// IPv6 route that carries it, as full mode's blocking halves will, and
// leaves somebody else's.
#[test]
fn remove_all_removes_a_marked_ipv6_route() {
    as_root(
        "marked ipv6",
        "remove_all_removes_a_marked_ipv6_route",
        || {
            let tun = Tun::open("uvt-mark6-0");
            let routes = LinuxRoutes;
            routes
                .configure_tunnel(&tun.name, Ipv4Addr::new(198, 18, 0, 6), 1300)
                .expect("configure");
            let (ours, theirs) = ("2001:db8:5::/48", "2001:db8:6::/48");
            let protocol = LINUX_ROUTE_PROTOCOL.to_string();
            ip_ok(&[
                "-6", "route", "add", ours, "dev", &tun.name, "proto", &protocol,
            ]);
            Outsider.add_route_v6(
                &tun.name,
                Ipv6Addr::new(0x2001, 0xdb8, 6, 0, 0, 0, 0, 0),
                48,
            );
            let present = |dest: &str| {
                let net: Ipv6Addr = dest.split('/').next().unwrap().parse().unwrap();
                let table = netlink::routes(AF_INET6).expect("the IPv6 table");
                table
                    .iter()
                    .any(|r| r.dst == IpAddr::V6(net) && r.dst_len == 48)
            };
            assert!(
                present(ours) && present(theirs),
                "the routes were not added"
            );
            let marked_v6 = marked().iter().filter(|r| r.family == AF_INET6).count();
            assert_eq!(marked_v6, 1, "the IPv6 route does not carry the mark");

            routes.remove_all().expect("remove all");
            assert!(!present(ours), "remove_all left a marked IPv6 route");
            assert!(
                present(theirs),
                "remove_all took somebody else's IPv6 route"
            );
        },
    );
}

// Linux keeps routes to one destination with different metrics side by
// side. Ours would join somebody else's at another metric, and win or lose
// by it; the add must refuse instead and change nothing.
#[test]
fn a_route_beside_one_with_another_metric_is_refused() {
    as_root(
        "metric",
        "a_route_beside_one_with_another_metric_is_refused",
        || {
            let tun = Tun::open("uvt-metric0");
            let routes = LinuxRoutes;
            let gateway = Ipv4Addr::new(192, 0, 2, 1);
            let physical = routes.capture_physical(gateway).expect("capture");
            let wire = physical.interface().to_string();
            routes
                .configure_tunnel(&tun.name, Ipv4Addr::new(198, 18, 0, 3), 1300)
                .expect("configure");

            let theirs = net("198.18.0.0/24");
            Outsider::add_route_at(&wire, theirs, 77);
            let refused = routes.add_tunnel_routes(&tun.name, &[theirs]);
            assert_eq!(refused, Err(Error::AlreadyExists), "joined their route");
            let kept = routes.uses_interface(Ipv4Addr::new(198, 18, 0, 9), &wire);
            assert_eq!(kept, Verified::Yes, "their route lost to ours");

            // The same for the gateway's own route.
            Outsider::add_route_at(&tun.name, net("192.0.2.1/32"), 55);
            let refused = routes.add_gateway_route(gateway, &physical);
            assert_eq!(
                refused,
                Err(Error::AlreadyExists),
                "joined their gateway route"
            );
            assert_eq!(marked(), [], "a route of ours was added");
        },
    );
}

// Issue #146: the kernel answers ARP for the tunnel's address on every
// interface, so a tunnel address inside a network the machine is on would
// draw a neighbour's traffic. It is refused before anything changes, also
// on an interface that is down, which may come up.
#[test]
fn refuses_a_tunnel_address_inside_a_network_the_machine_is_on() {
    let test = "refuses_a_tunnel_address_inside_a_network_the_machine_is_on";
    as_root("on-link address", test, || {
        let tun = Tun::open("uvt-146-0");
        let other = Tun::open("uvt-146-1");
        let routes = LinuxRoutes;
        let address = |c, d| Ipv4Addr::new(198, 18, c, d);
        Outsider.add_address(&other.name, address(5, 1));
        Outsider.add_address(&tun.name, address(7, 99));
        let mtu = || {
            let path = format!("/sys/class/net/{}/mtu", tun.name);
            std::fs::read_to_string(path)
                .expect("the packet size")
                .trim()
                .to_string()
        };
        assert_eq!(mtu(), "1500", "a new device's packet size");

        for (inside, what) in [(address(5, 7), "a neighbour's"), (address(5, 1), "its own")] {
            let refused = routes.configure_tunnel(&tun.name, inside, 1300);
            assert_eq!(refused, Err(Error::InvalidInput), "{what} address");
            let left = Outsider.addresses(&tun.name);
            assert_eq!(left, [address(7, 99)], "a refusal changed the tunnel");
            assert_eq!(mtu(), "1500", "a refusal changed the packet size");
        }
        let down = tun.link().expect("the tunnel");
        assert_eq!(down.flags & IFF_UP, 0, "a refusal brought the tunnel up");

        // Outside every such network: accepted. The tunnel's own earlier
        // address, in another network, does not count against it.
        routes
            .configure_tunnel(&tun.name, address(7, 5), 1300)
            .expect("an address outside the machine's networks");
        assert_eq!(Outsider.addresses(&tun.name), [address(7, 5)]);
        drop(other);
    });
}

// Decision G16: the tunnel keeps IPv6, with no address of its own, after
// every configure, also when a small packet size stops IPv6 on it and a
// larger one starts it afresh.
#[test]
fn the_tunnel_has_no_ipv6_address_after_each_configure() {
    as_root(
        "ipv6",
        "the_tunnel_has_no_ipv6_address_after_each_configure",
        || {
            let tun = Tun::open("uvt-ipv6-0");
            let routes = LinuxRoutes;
            let ipv6 = || {
                let all = netlink::addresses(AF_INET6).expect("the IPv6 addresses");
                let index = tun.index();
                all.into_iter().filter(|a| a.index == index).count()
            };
            // Every IPv6 address the kernel adds or removes, as it happens, so
            // one that comes and goes within a configure is seen too.
            let mut monitor = Command::new("stdbuf")
                .args(["-oL", "ip", "-6", "-o", "monitor", "address"])
                .stdout(Stdio::piped())
                .spawn()
                .expect("start ip monitor");
            let output = monitor.stdout.take().expect("the monitor's output");
            let lines = thread::spawn(move || {
                let reader = std::io::BufReader::new(output);
                std::io::BufRead::lines(reader)
                    .map_while(Result::ok)
                    .collect::<Vec<_>>()
            });
            thread::sleep(Duration::from_secs(1));
            // Up at 1300, then down to 1000, which stops IPv6 on it, then up
            // to 1400 while the device is up, which starts IPv6 afresh.
            for (n, mtu) in [(2, 1300), (3, 1000), (3, 1400), (3, 1400)] {
                routes
                    .configure_tunnel(&tun.name, Ipv4Addr::new(198, 18, 0, n), mtu)
                    .expect("configure");
                // Give the kernel a moment to add one, if it were going to.
                thread::sleep(Duration::from_secs(1));
                assert_eq!(ipv6(), 0, "an IPv6 address after configuring .{n} at {mtu}");
            }
            // The monitor sees an address that is added: this one.
            let control = Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 1);
            Outsider.add_address_v6(&tun.name, control);
            thread::sleep(Duration::from_secs(1));
            let _ = monitor.kill();
            let _ = monitor.wait();
            let lines = lines.join().expect("the monitor's lines");
            let on_tunnel: Vec<_> = lines.iter().filter(|l| l.contains(&tun.name)).collect();
            say(&format!("IPV6 seen on the tunnel: {on_tunnel:?}"));
            let seen_control = on_tunnel.iter().any(|l| l.contains("2001:db8:1::1"));
            assert!(seen_control, "the monitor saw nothing: {lines:?}");
            let others: Vec<_> = on_tunnel
                .iter()
                .filter(|l| !l.contains("2001:db8:1::1"))
                .collect();
            assert_eq!(
                others,
                Vec::<&&String>::new(),
                "an IPv6 address came and went"
            );
            let mode = format!("/proc/sys/net/ipv6/conf/{}/addr_gen_mode", tun.name);
            if let Ok(mode) = std::fs::read_to_string(mode) {
                assert_eq!(mode.trim(), "1", "the kernel would give it an address");
            }
        },
    );
}

// Security rule: only a tunnel device is configured or routed through as
// one, never the physical network.
#[test]
fn refuses_to_treat_the_physical_interface_as_the_tunnel() {
    let test = "refuses_to_treat_the_physical_interface_as_the_tunnel";
    as_root("physical", test, || {
        let routes = LinuxRoutes;
        let wire = wire();
        let configured = routes.configure_tunnel(&wire, Ipv4Addr::new(198, 51, 100, 7), 1300);
        assert!(
            matches!(configured, Err(Error::Failed(_))),
            "{configured:?}"
        );
        let routed = routes.add_tunnel_routes(&wire, &[net("198.51.100.0/24")]);
        assert!(matches!(routed, Err(Error::Failed(_))), "{routed:?}");
        assert_eq!(marked(), [], "a route of ours was added");
    });
}

// Security rule: a route on an interface that is down carries nothing, so
// it is never the way to its destination. The kernel keeps a route on a
// device whose link is gone, and still picks it; it drops a route on a
// device taken down.
#[test]
fn a_route_on_a_down_interface_never_counts() {
    as_root(
        "down interface",
        "a_route_on_a_down_interface_never_counts",
        || {
            let tun = Tun::open("uvt-down0");
            let routes = LinuxRoutes;
            routes
                .configure_tunnel(&tun.name, Ipv4Addr::new(198, 18, 0, 8), 1400)
                .expect("configure");
            let theirs = net("198.51.100.0/24");
            let dest = Ipv4Addr::new(198, 51, 100, 9);
            let index = tun.index();
            let in_table = || {
                let table = netlink::routes(AF_INET).expect("the table");
                table.iter().any(|route| {
                    route.dst == IpAddr::V4(theirs.addr())
                        && route.dst_len == 24
                        && route.oif == Some(index)
                })
            };
            let answer = || routes.uses_interface(dest, &tun.name);
            let running = || tun.link().is_some_and(|link| link.flags & IFF_RUNNING != 0);

            Outsider.add_route(&tun.name, theirs);
            assert!(running(), "the device's link does not work");
            assert_eq!(answer(), Verified::Yes, "the route did not count while up");

            tun.set_carrier(false);
            assert!(wait_for(|| !running()), "the link still works");
            let kept = in_table();
            let without_link = answer();
            say(&format!(
                "DOWN no carrier: in the table {kept}, answer {without_link:?}"
            ));
            assert!(kept, "the kernel dropped the route with the link");
            assert_eq!(without_link, Verified::No, "a route with no link counted");

            tun.set_carrier(true);
            assert!(wait_for(running), "the link did not come back");
            assert_eq!(answer(), Verified::Yes, "the route did not count again");

            ip_ok(&["link", "set", "dev", &tun.name, "down"]);
            let taken_down = answer();
            say(&format!(
                "DOWN taken down: in the table {}, answer {taken_down:?}",
                in_table()
            ));
            assert_eq!(
                taken_down,
                Verified::No,
                "a route on a device taken down counted"
            );
        },
    );
}

/// The part of `a_killed_service_leaves_what_start_up_removes` that is
/// killed. It does nothing unless that test started it.
#[test]
fn crash_child() {
    let Some(dir) = std::env::var_os(CRASH).map(PathBuf::from) else {
        return;
    };
    // Ends this process too if it is stuck, so it never outlives the test.
    watchdog();
    let tun = Tun::open("uvt-crash0");
    let routes = LinuxRoutes;
    let gateway = Ipv4Addr::new(192, 0, 2, 1);
    let physical = routes.capture_physical(gateway).expect("capture");
    routes
        .configure_tunnel(&tun.name, Ipv4Addr::new(198, 18, 0, 2), 1300)
        .expect("configure");
    routes
        .add_gateway_route(gateway, &physical)
        .expect("add the gateway route");
    routes
        .add_tunnel_routes(&tun.name, &[net("198.18.0.0/24")])
        .expect("add the tunnel route");
    // Written whole, then moved into place, so it is never read half done.
    std::fs::write(dir.join("ready.new"), physical.interface()).expect("write");
    std::fs::rename(dir.join("ready.new"), dir.join("ready")).expect("rename");
    std::mem::forget(tun);
    loop {
        thread::park();
    }
}

// A service killed mid-connection leaves its gateway route behind: the
// tunnel's routes go with the device, which goes with the process. The next
// start removes the product's routes, found by their mark with no journal,
// and nothing else.
#[test]
fn a_killed_service_leaves_what_start_up_removes() {
    as_root(
        "crash",
        "a_killed_service_leaves_what_start_up_removes",
        || {
            let dir = std::env::temp_dir().join(format!("uvt-crash-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir(&dir).expect("make the folder");
            let wire = wire();
            let theirs = net("203.0.113.0/24");
            Outsider.add_route(&wire, theirs);

            let mut child = Command::new(std::env::current_exe().expect("this program"))
                .args([
                    "--exact",
                    &test_path("crash_child"),
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(CRASH, &dir)
                .env_remove(CHILD)
                .stdout(Stdio::null())
                .spawn()
                .expect("start the child");
            let started = Instant::now();
            let ready = loop {
                if let Ok(wire) = std::fs::read_to_string(dir.join("ready")) {
                    break Some(wire);
                }
                if started.elapsed() > DEADLINE / 2 {
                    break None;
                }
                thread::sleep(Duration::from_millis(100));
            };
            let before = marked();
            child.kill().expect("kill the child");
            child.wait().expect("wait for the child");
            let _ = std::fs::remove_dir_all(&dir);
            assert_eq!(
                ready.as_deref(),
                Some(wire.as_str()),
                "the child did not get ready"
            );
            say(&format!("CRASH ours while it ran: {before:?}"));
            assert_eq!(before.len(), 2, "the child's routes are not both there");

            let device_gone = || {
                let links = netlink::links().expect("the links");
                !links.iter().any(|link| link.name == "uvt-crash0")
            };
            assert!(
                wait_for(device_gone),
                "the killed process's device is still there"
            );
            let left = marked();
            say(&format!("CRASH ours after the kill: {left:?}"));
            let gateway = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
            let survived = left
                .iter()
                .any(|route| route.dst == gateway && route.dst_len == 32);
            assert!(survived, "the gateway route went with the process");

            LinuxRoutes
                .remove_all()
                .expect("remove all at the next start");
            assert_eq!(marked(), [], "start-up left a route of ours");
            let kept = LinuxRoutes.uses_interface(Ipv4Addr::new(203, 0, 113, 9), &wire);
            assert_eq!(
                kept,
                Verified::Yes,
                "start-up removed somebody else's route"
            );
            Outsider.remove_route(&wire, theirs);
        },
    );
}

// Out of range is refused before the device is even looked for, so it
// needs no root and changes nothing.
#[test]
fn a_packet_size_out_of_range_is_refused_first() {
    for mtu in [0, 575, 1501, u16::MAX] {
        let refused = LinuxRoutes.configure_tunnel("uvt-none0", Ipv4Addr::new(198, 18, 0, 1), mtu);
        assert_eq!(refused, Err(Error::InvalidInput), "{mtu}");
    }
}

// Full mode is not written yet on Linux: it says so.
#[test]
fn full_mode_routes_are_not_implemented_yet() {
    let unsupported = Some(Error::Unsupported);
    assert_eq!(LinuxRoutes.add_full_tunnel("uvt-none0").err(), unsupported);
    assert_eq!(LinuxRoutes.full_tunnel_ipv6("uvt-none0").err(), unsupported);
    assert_eq!(
        LinuxRoutes.remove_full_tunnel("uvt-none0").err(),
        unsupported
    );
    assert_eq!(
        LinuxRoutes.foreign_full_tunnel("uvt-none0").err(),
        unsupported
    );
}

fn route(dst: [u8; 4], len: u8, oif: Option<u32>, gateway: Option<[u8; 4]>) -> Route {
    Route {
        family: AF_INET,
        dst: IpAddr::V4(Ipv4Addr::from(dst)),
        dst_len: len,
        tos: 0,
        table: RT_TABLE_MAIN,
        protocol: 3,
        scope: RT_SCOPE_LINK,
        kind: RTN_UNICAST,
        flags: 0,
        oif,
        gateway: gateway.map(|g| IpAddr::V4(Ipv4Addr::from(g))),
        priority: None,
        multipath: false,
        via: false,
    }
}

fn link(index: u32, flags: u32) -> Link {
    Link {
        index,
        name: format!("if{index}"),
        flags,
        kind: None,
        mtu: None,
    }
}

// Security rule: `uses_interface` fails closed. A question the kernel
// could not answer, or an answer that could not be read, is `Unknown`,
// never `No`; only the kernel's own "no route" is `No`.
#[test]
fn a_failed_question_is_unknown_never_no() {
    let links = [link(2, IFF_UP | IFF_RUNNING), link(3, IFF_UP | IFF_RUNNING)];
    let errno = |code| Err(std::io::Error::from_raw_os_error(code));
    for code in [
        libc::EIO,
        libc::EPERM,
        libc::ENOBUFS,
        libc::EAGAIN,
        libc::EINVAL,
    ] {
        assert_eq!(
            verdict(errno(code), 2, &links),
            Verified::Unknown,
            "errno {code}"
        );
    }
    let unreadable = std::io::Error::new(std::io::ErrorKind::InvalidData, "cut short");
    assert_eq!(verdict(Err(unreadable), 2, &links), Verified::Unknown);
    let no_interface = route([198, 51, 100, 9], 32, None, None);
    assert_eq!(verdict(Ok(no_interface), 2, &links), Verified::Unknown);
    for code in [libc::ENETUNREACH, libc::EHOSTUNREACH] {
        assert_eq!(
            verdict(errno(code), 2, &links),
            Verified::No,
            "errno {code}"
        );
    }
    let through = |oif| Ok(route([198, 51, 100, 9], 32, Some(oif), None));
    assert_eq!(verdict(through(2), 2, &links), Verified::Yes);
    assert_eq!(verdict(through(3), 2, &links), Verified::No);
}

// The same rule as the root test, without the kernel: a route through an
// interface that is down, or whose link does not work, never counts.
#[test]
fn a_route_through_an_interface_that_does_not_run_is_no() {
    let through = || Ok(route([198, 51, 100, 9], 32, Some(2), None));
    for flags in [0, IFF_UP, IFF_RUNNING] {
        let links = [link(2, flags)];
        assert_eq!(
            verdict(through(), 2, &links),
            Verified::No,
            "flags {flags:#x}"
        );
    }
    assert_eq!(
        verdict(through(), 2, &[]),
        Verified::No,
        "an unknown interface"
    );
    let mut local = route([198, 51, 100, 9], 32, Some(2), None);
    local.kind = 2;
    let links = [link(2, IFF_UP | IFF_RUNNING)];
    assert_eq!(verdict(Ok(local), 2, &links), Verified::No, "a local route");
}

fn address(index: u32, addr: [u8; 4], prefix_len: u8) -> Address {
    Address {
        family: AF_INET,
        prefix_len,
        flags: 0,
        index,
        local: IpAddr::V4(Ipv4Addr::from(addr)),
        address: None,
    }
}

// How Linux's address flags and interface state map onto the networks the
// machine is on: a preferred or deprecated address on an interface that is
// up and running counts; a tentative or duplicate one, or any on an
// interface that is down or has no link, does not.
#[test]
fn only_a_usable_address_on_a_running_link_puts_the_machine_on_a_network() {
    use super::routes::netlink::{IFA_F_DADFAILED, IFA_F_DEPRECATED, IFA_F_TENTATIVE};
    let running = IFF_UP | IFF_RUNNING;
    let links = [
        link(2, running),
        link(3, IFF_UP),
        link(4, 0),
        link(5, running),
    ];
    let flagged = |index, addr, flags| Address {
        flags,
        ..address(index, addr, 24)
    };
    let rows = [
        flagged(2, [10, 200, 0, 10], 0),
        flagged(2, [10, 201, 0, 10], IFA_F_DEPRECATED),
        flagged(2, [10, 202, 0, 10], IFA_F_TENTATIVE),
        flagged(2, [10, 203, 0, 10], IFA_F_DADFAILED),
        flagged(3, [10, 204, 0, 10], 0),
        flagged(4, [10, 205, 0, 10], 0),
        // An interface the list of links does not have.
        flagged(9, [10, 206, 0, 10], 0),
        Address {
            family: AF_INET6,
            local: "2001:db8::1".parse().unwrap(),
            ..address(5, [0; 4], 64)
        },
    ];
    let usable = rows
        .iter()
        .filter_map(|row| super::routes::address_row(row, &links));
    let networks = crate::on_link::usable_networks(usable);
    assert_eq!(networks, [net("10.200.0.0/24"), net("10.201.0.0/24")]);
}

// Issue #146, the rule alone: the networks of every other interface's
// addresses count, used or not; the tunnel's own do not, nor IPv6 ones.
#[test]
fn the_146_rule_finds_the_network_that_holds_the_address() {
    let tunnel = 9;
    let rows = [
        address(2, [10, 200, 0, 10], 24),
        address(3, [203, 0, 113, 5], 32),
        address(tunnel, [198, 51, 100, 99], 24),
        Address {
            family: AF_INET6,
            local: "2001:db8::1".parse().unwrap(),
            ..address(4, [0; 4], 64)
        },
    ];
    let holding = |addr: [u8; 4]| local_network_holding(Ipv4Addr::from(addr), tunnel, &rows);
    assert_eq!(holding([10, 200, 0, 77]), Some(net("10.200.0.0/24")));
    assert_eq!(holding([10, 200, 0, 10]), Some(net("10.200.0.0/24")));
    assert_eq!(holding([203, 0, 113, 5]), Some(net("203.0.113.5/32")));
    assert_eq!(holding([203, 0, 113, 6]), None);
    assert_eq!(holding([198, 51, 100, 7]), None, "the tunnel's own counted");
    assert_eq!(holding([10, 201, 0, 1]), None);
}

// A route is identical only with the same destination, interface and next
// hop, whatever its metric or protocol; any other route to the destination
// in the main table is somebody else's way there.
#[test]
fn only_the_same_interface_and_next_hop_is_identical() {
    let dest = net("192.0.2.0/24");
    let hop = Some(Ipv4Addr::new(198, 51, 100, 1));
    let same = route([192, 0, 2, 0], 24, Some(2), Some([198, 51, 100, 1]));
    assert_eq!(present(&[], dest, 2, hop), Present::None);
    assert_eq!(
        present(std::slice::from_ref(&same), dest, 2, hop),
        Present::Identical
    );
    let metric = Route {
        priority: Some(77),
        protocol: LINUX_ROUTE_PROTOCOL,
        ..same.clone()
    };
    assert_eq!(present(&[metric], dest, 2, hop), Present::Identical);
    let other_interface = route([192, 0, 2, 0], 24, Some(3), Some([198, 51, 100, 1]));
    let both = [same.clone(), other_interface.clone()];
    assert_eq!(present(&both, dest, 2, hop), Present::Elsewhere);
    let direct = route([192, 0, 2, 0], 24, Some(2), None);
    assert_eq!(present(&[direct], dest, 2, hop), Present::Elsewhere);
    let multipath = Route {
        multipath: true,
        ..same.clone()
    };
    assert_eq!(present(&[multipath], dest, 2, hop), Present::Elsewhere);
    // Other tables, other destinations and other prefixes do not count.
    let elsewhere = [
        Route {
            table: 100,
            ..other_interface.clone()
        },
        route([192, 0, 2, 0], 25, Some(3), None),
        route([192, 0, 3, 0], 24, Some(3), None),
    ];
    assert_eq!(present(&elsewhere, dest, 2, hop), Present::None);
}

// Only the product's mark makes a route its own, so start-up never takes
// anybody else's.
#[test]
fn only_a_route_with_the_mark_is_ours() {
    let mut route = route([192, 0, 2, 0], 24, Some(2), None);
    for protocol in [2, 3, 4, 16, 186, 0xb4] {
        route.protocol = protocol;
        assert!(!is_ours(&route), "protocol {protocol}");
    }
    route.protocol = 0xb5;
    assert!(is_ours(&route));
}
