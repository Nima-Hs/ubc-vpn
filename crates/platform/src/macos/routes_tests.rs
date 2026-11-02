//! Tests of the routing table on macOS.
//!
//! The first ones read made-up tables and need nothing. The rest change the
//! real table and need root and a `utun` device, which each opens itself.
//! Each of those runs in a process of its own, started by the test: the
//! channel's tests switch the whole process to another user for a moment,
//! and nothing may change a route then. Without root they say `SKIPPED,
//! needs root`, unless `UBC_VPN_REQUIRE_ROOT` is set, as it is in CI, which
//! makes that a failure. When they ran, they say `RAN AS ROOT: <name>`, and
//! CI requires the names in `.github/ran/platform-unix/macos/routes.txt`.
//!
//! They use only addresses reserved for documentation and benchmarking, and
//! remove every route to those however they end.

use std::io::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ubc_vpn_core::routes::Ipv4Net;

use super::route_socket::{self, Change, IOC_IN, IOC_INOUT, Interface, Route, V4Address, ioc};
use super::routes::{
    BEFORE_ADD, MacRoutes, OURS, Present, boot, counts, is_utun_name, present, through, tunnel,
    winners,
};
use crate::fake::Fake;
use crate::journal::{Boot, Journal, Prefix, Row, Store};
use crate::suite::{self, Foreign};
use crate::{Error, Mode, Platform, Routes, Verified, lock};

fn net(text: &str) -> Ipv4Net {
    text.parse().expect("a network")
}

fn ip(text: &str) -> Ipv4Addr {
    text.parse().expect("an address")
}

// ---------------------------------------------------------------------------
// Made-up tables: these need nothing.

/// One message of a dump of the table, as the kernel writes it: a header,
/// then each socket address padded to four bytes.
fn dumped(flags: libc::c_int, index: u16, addresses: &[(libc::c_int, Vec<u8>)]) -> Vec<u8> {
    let mut body = Vec::new();
    let mut addrs = 0;
    for (bit, address) in addresses {
        addrs |= bit;
        body.extend_from_slice(address);
        let padded = if address.is_empty() {
            4
        } else {
            address.len().div_ceil(4) * 4
        };
        body.resize(body.len() + padded - address.len(), 0);
    }
    // SAFETY: plain data, for which all zeroes is valid.
    let mut header: libc::rt_msghdr = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::rt_msghdr>();
    header.rtm_msglen = (size + body.len()) as u16;
    header.rtm_version = libc::RTM_VERSION as u8;
    header.rtm_type = libc::RTM_GET as u8;
    header.rtm_index = index;
    header.rtm_flags = flags;
    header.rtm_addrs = addrs;
    // SAFETY: the slice covers exactly the header, which outlives it.
    let header = unsafe { std::slice::from_raw_parts((&raw const header).cast::<u8>(), size) };
    [header, &body].concat()
}

/// A whole `sockaddr_in`.
fn inet(addr: &str) -> Vec<u8> {
    let mut bytes = vec![16, libc::AF_INET as u8, 0, 0];
    bytes.extend_from_slice(&ip(addr).octets());
    bytes.resize(16, 0);
    bytes
}

/// A netmask cut short, as dumps have them: `length` bytes of a
/// `sockaddr_in` holding `mask`.
fn short_mask(mask: &str, length: usize) -> Vec<u8> {
    let mut bytes = inet(mask);
    bytes.truncate(length);
    if let Some(first) = bytes.first_mut() {
        *first = length as u8;
    }
    bytes
}

/// A link-level address naming interface `index`.
fn link(index: u16) -> Vec<u8> {
    let mut bytes = vec![20, libc::AF_LINK as u8];
    bytes.extend_from_slice(&index.to_ne_bytes());
    bytes.resize(20, 0);
    bytes
}

const DST: libc::c_int = libc::RTA_DST;
const GATEWAY: libc::c_int = libc::RTA_GATEWAY;
const NETMASK: libc::c_int = libc::RTA_NETMASK;
const UG: libc::c_int = libc::RTF_UP | libc::RTF_GATEWAY;

// The default route's netmask is all zeroes, so the kernel writes none of
// its bytes; another is cut after its last byte that is not zero.
#[test]
fn reads_a_dump_of_the_table_with_short_netmasks() {
    let dump = [
        dumped(
            UG,
            4,
            &[
                (DST, inet("0.0.0.0")),
                (GATEWAY, inet("192.0.2.1")),
                (NETMASK, short_mask("0.0.0.0", 0)),
            ],
        ),
        dumped(
            libc::RTF_UP,
            4,
            &[
                (DST, inet("192.0.2.0")),
                (GATEWAY, link(4)),
                (NETMASK, short_mask("255.255.255.0", 7)),
            ],
        ),
        dumped(
            libc::RTF_UP | libc::RTF_HOST | libc::RTF_WASCLONED,
            9,
            &[(DST, inet("198.51.100.7")), (GATEWAY, link(9))],
        ),
    ]
    .concat();
    let routes = route_socket::parse_table(&dump).expect("a table");
    let want = [
        Route {
            dest: net("0.0.0.0/0"),
            index: 4,
            router: Some(ip("192.0.2.1")),
            flags: UG,
        },
        Route {
            dest: net("192.0.2.0/24"),
            index: 4,
            router: None,
            flags: libc::RTF_UP,
        },
        Route {
            dest: net("198.51.100.7/32"),
            index: 9,
            router: None,
            flags: libc::RTF_UP | libc::RTF_HOST | libc::RTF_WASCLONED,
        },
    ];
    assert_eq!(routes, want);
}

// A table that cannot be read whole is not read at all: a route left out
// could be the one that decides, so a check must answer `Unknown`.
#[test]
fn refuses_a_dump_it_cannot_read() {
    let good = dumped(
        libc::RTF_UP,
        4,
        &[
            (DST, inet("192.0.2.0")),
            (GATEWAY, link(4)),
            (NETMASK, short_mask("255.255.255.0", 7)),
        ],
    );
    let mut wrong_version = good.clone();
    wrong_version[2] = 4;
    let gapped_mask = dumped(
        libc::RTF_UP,
        4,
        &[
            (DST, inet("192.0.2.0")),
            (GATEWAY, link(4)),
            (NETMASK, short_mask("255.0.255.0", 7)),
        ],
    );
    let router_not_ipv4 = dumped(UG, 4, &[(DST, inet("192.0.2.0")), (GATEWAY, link(4))]);
    let no_destination = dumped(libc::RTF_UP, 4, &[(GATEWAY, link(4))]);
    let bad = [
        good[..good.len() - 1].to_vec(),
        good[..3].to_vec(),
        wrong_version,
        gapped_mask,
        router_not_ipv4,
        no_destination,
    ];
    for (n, dump) in bad.iter().enumerate() {
        let read = route_socket::parse_table(&[good.as_slice(), dump].concat());
        assert!(matches!(read, Err(Error::Failed(_))), "case {n}: {read:?}");
    }
    assert_eq!(route_socket::parse_table(&[]), Ok(vec![]));
}

// What this code asks the kernel for reads back as the route it meant.
#[test]
fn a_route_message_holds_the_route_it_was_made_for() {
    let cases = [
        (net("192.0.2.0/24"), 7, None),
        (net("192.0.2.1/32"), 4, Some(ip("198.51.100.1"))),
        (net("0.0.0.0/1"), 7, None),
    ];
    for (dest, index, router) in cases {
        let message = route_socket::message(Change::Add, dest, index, router, OURS);
        let read = route_socket::parse_table(&message).expect("a message");
        let [route] = read.as_slice() else {
            panic!("{read:?}")
        };
        assert_eq!(
            (route.dest, route.index, route.router),
            (dest, index, router)
        );
        let host = if dest.prefix_len() == 32 {
            libc::RTF_HOST
        } else {
            0
        };
        let wanted = libc::RTF_UP | libc::RTF_STATIC | OURS | host;
        assert_eq!(route.flags & wanted, wanted, "{dest}");
        assert_eq!(route.flags & libc::RTF_IFSCOPE, 0, "{dest} is scoped");
    }
}

// Each message asks for exactly the socket addresses its route needs: a
// netmask only for a network, and the interface besides the router only
// when adding a route through one.
#[test]
fn a_route_message_names_only_what_its_route_needs() {
    let cases = [
        (
            Change::Add,
            net("192.0.2.1/32"),
            Some(ip("198.51.100.1")),
            DST | GATEWAY | libc::RTA_IFP,
        ),
        (
            Change::Delete,
            net("192.0.2.1/32"),
            Some(ip("198.51.100.1")),
            DST | GATEWAY,
        ),
        (
            Change::Add,
            net("192.0.2.0/24"),
            None,
            DST | GATEWAY | NETMASK,
        ),
        (
            Change::Delete,
            net("192.0.2.0/24"),
            None,
            DST | GATEWAY | NETMASK,
        ),
        (Change::Add, net("192.0.2.9/32"), None, DST | GATEWAY),
    ];
    for (change, dest, router, addrs) in cases {
        let message = route_socket::message(change, dest, 7, router, 0);
        // SAFETY: a message starts with a whole header; copied out.
        let header: libc::rt_msghdr = unsafe { std::ptr::read_unaligned(message.as_ptr().cast()) };
        assert_eq!(header.rtm_addrs, addrs, "{change:?} {dest}");
        assert_eq!(usize::from(header.rtm_msglen), message.len());
        let kind = match change {
            Change::Add => libc::RTM_ADD,
            Change::Delete => libc::RTM_DELETE,
        };
        assert_eq!(libc::c_int::from(header.rtm_type), kind);
        assert_eq!(header.rtm_flags & OURS, 0, "marked unasked");
    }
}

// A refusal from the kernel is told apart by its reason.
#[test]
fn reads_the_kernels_reasons() {
    let reason = |errno| route_socket::os_error("call", std::io::Error::from_raw_os_error(errno));
    assert_eq!(reason(libc::EEXIST), Error::AlreadyExists);
    for errno in [libc::ESRCH, libc::ENXIO, libc::ENODEV, libc::EADDRNOTAVAIL] {
        assert_eq!(reason(errno), Error::NotFound, "{errno}");
    }
    for errno in [libc::EPERM, libc::EACCES] {
        assert_eq!(reason(errno), Error::PermissionDenied, "{errno}");
    }
    let Error::Failed(message) = reason(libc::EINVAL) else {
        panic!("EINVAL is a failure");
    };
    assert!(message.starts_with("call: "), "{message}");
}

// The ioctl numbers are those of the system's headers.
#[test]
fn the_ioctl_numbers_are_the_systems() {
    let ifreq = std::mem::size_of::<libc::ifreq>();
    assert_eq!(ioc(IOC_INOUT, b'i', 33, ifreq), libc::SIOCGIFADDR);
    let info = std::mem::size_of::<libc::ctl_info>();
    assert_eq!(ioc(IOC_INOUT, b'N', 3, info), libc::CTLIOCGINFO);
    assert_eq!(route_socket::SIOCSIFFLAGS, 0x8020_6910);
    assert_eq!(route_socket::SIOCGIFFLAGS, 0xc020_6911);
    assert_eq!(route_socket::SIOCDIFADDR, 0x8020_6919);
    assert_eq!(route_socket::SIOCAIFADDR, 0x8040_691a);
    assert_eq!(route_socket::SIOCSIFMTU, 0x8020_6934);
    let in6 = std::mem::size_of::<libc::in6_ifreq>();
    assert_eq!(route_socket::SIOCDIFADDR_IN6, ioc(IOC_IN, b'i', 25, in6));
}

// A later version must find an earlier one's routes, so the mark never
// changes. It is never the kernel's own expiry mark, `RTF_PROTO3`, which the
// kernel clears on use and deletes routes by.
#[test]
fn the_route_mark_never_changes() {
    assert_eq!(OURS, 0x8000);
    assert_ne!(OURS, libc::RTF_PROTO3);
}

fn interface(name: &str, index: u16, flags: libc::c_int) -> Interface {
    Interface {
        name: name.to_string(),
        index,
        flags,
        ..Interface::default()
    }
}

const UP: libc::c_int = libc::IFF_UP | libc::IFF_RUNNING;

fn route(dest: &str, index: u16, router: Option<&str>, flags: libc::c_int) -> Route {
    Route {
        dest: net(dest),
        index,
        router: router.map(ip),
        flags: libc::RTF_UP | flags,
    }
}

fn interfaces() -> Vec<Interface> {
    vec![
        interface("en0", 4, UP | libc::IFF_BROADCAST),
        interface("utun5", 9, UP | libc::IFF_POINTOPOINT),
        interface("en1", 5, libc::IFF_BROADCAST),
    ]
}

// Scoped routes, cloned routes and neighbour entries do not decide where
// traffic goes; the longest prefix of the rest does. A route out of an
// interface that is down never counts.
#[test]
fn only_routes_that_count_decide_and_the_longest_prefix_wins() {
    let gateway = libc::RTF_GATEWAY;
    let table = [
        route("0.0.0.0/0", 4, Some("192.0.2.1"), gateway),
        route("0.0.0.0/0", 9, None, libc::RTF_IFSCOPE),
        route("198.51.100.0/24", 9, None, 0),
        // A cloned host route left from before the tunnel's route.
        route(
            "198.51.100.9/32",
            4,
            Some("192.0.2.1"),
            gateway | libc::RTF_WASCLONED,
        ),
        // A neighbour on the local network.
        route(
            "198.51.100.10/32",
            4,
            None,
            libc::RTF_LLINFO | libc::RTF_HOST,
        ),
        route("203.0.113.0/24", 9, None, libc::RTF_IFSCOPE),
        // Out of an interface that is down.
        route("198.18.0.0/24", 5, None, 0),
    ];
    let interfaces = interfaces();
    let via = |dest: &str| {
        let winners = winners(&table, &interfaces, ip(dest));
        winners.iter().map(|r| r.index).collect::<Vec<_>>()
    };
    assert_eq!(via("198.51.100.9"), [9], "a cloned route decided");
    assert_eq!(via("198.51.100.10"), [9], "a neighbour entry decided");
    assert_eq!(via("203.0.113.9"), [4], "a scoped route decided");
    assert_eq!(
        via("198.18.0.9"),
        [4],
        "a route on a down interface decided"
    );
    assert_eq!(via("192.0.2.77"), [4]);
    let read = || Ok((table.to_vec(), interfaces.clone()));
    assert_eq!(through(read(), ip("198.51.100.9"), "utun5"), Verified::Yes);
    assert_eq!(through(read(), ip("198.51.100.9"), "en0"), Verified::No);
    assert_eq!(through(read(), ip("198.18.0.9"), "en1"), Verified::No);
    assert_eq!(through(read(), ip("198.18.0.9"), "en0"), Verified::Yes);
    // A route that is not up does not count either.
    let mut down = table.to_vec();
    down[2].flags &= !libc::RTF_UP;
    let read_down = Ok((down, interfaces.clone()));
    assert_eq!(
        through(read_down, ip("198.51.100.9"), "utun5"),
        Verified::No
    );
}

// The check fails closed: a table or a list of interfaces that cannot be
// read is `Unknown`, never `No`. So are two winners that disagree. A route
// out of an interface that is not listed is not out of one that is up.
#[test]
fn the_check_is_unknown_when_it_cannot_tell() {
    let dest = ip("198.51.100.9");
    let failed = Error::Failed("the routing table cannot be read".to_string());
    assert_eq!(through(Err(failed), dest, "utun5"), Verified::Unknown);
    assert_eq!(
        through(Err(Error::PermissionDenied), dest, "en0"),
        Verified::Unknown
    );
    let tunnelled = vec![route("198.51.100.0/24", 9, None, 0)];
    let found = through(Ok((tunnelled.clone(), interfaces())), dest, "utun5");
    assert_eq!(found, Verified::Yes);
    let unlisted = interfaces().into_iter().filter(|i| i.index != 9).collect();
    let gone = through(Ok((tunnelled, unlisted)), dest, "utun5");
    assert_eq!(
        gone,
        Verified::No,
        "a route out of no listed interface counted"
    );
    let tie = vec![
        route("198.51.100.0/24", 9, None, 0),
        route("198.51.100.0/24", 4, None, 0),
    ];
    let disagree = through(Ok((tie, interfaces())), dest, "utun5");
    assert_eq!(disagree, Verified::Unknown);
    assert_eq!(
        through(Ok((vec![], interfaces())), dest, "utun5"),
        Verified::No
    );
}

// A name the kernel never gave a tunnel, or a device that is not
// point-to-point, is never configured or routed through as the tunnel.
#[test]
fn only_a_utun_device_is_the_tunnel() {
    for name in ["utun0", "utun12"] {
        assert!(is_utun_name(name), "{name}");
    }
    for name in ["utun", "en0", "utunx", "utun1 ", "xutun1", "utun-1"] {
        assert!(!is_utun_name(name), "{name}");
    }
    let interfaces = interfaces();
    assert_eq!(tunnel(&interfaces, "utun5").map(|i| i.index), Ok(9));
    assert!(matches!(tunnel(&interfaces, "en0"), Err(Error::Failed(_))));
    assert_eq!(tunnel(&interfaces, "utun6").err(), Some(Error::NotFound));
    let not_p2p = [interface("utun5", 9, UP)];
    assert!(matches!(tunnel(&not_p2p, "utun5"), Err(Error::Failed(_))));
}

fn row(dest: &str, index: u16, hop: Option<&str>, interface: &str) -> Row {
    Row {
        dest: dest.parse().expect("a prefix"),
        luid: u64::from(index),
        next_hop: IpAddr::V4(hop.map_or(Ipv4Addr::UNSPECIFIED, ip)),
        interface: interface.to_string(),
    }
}

// Before an add: an identical route (the same destination, interface and
// next hop) is told from one elsewhere, and from nothing, and the mark says
// whether it is ours. Cloned and scoped routes are not in the way.
#[test]
fn tells_what_is_there_before_an_add() {
    let ours = row("192.0.2.1/32", 4, Some("198.51.100.1"), "en0");
    let tunnel = row("192.0.2.0/24", 9, None, "utun5");
    let marked = libc::RTF_GATEWAY | libc::RTF_HOST | OURS;
    let identical = route("192.0.2.1/32", 4, Some("198.51.100.1"), marked);
    let unmarked = route("192.0.2.1/32", 4, Some("198.51.100.1"), libc::RTF_GATEWAY);
    let other_hop = route("192.0.2.1/32", 4, Some("198.51.100.2"), libc::RTF_GATEWAY);
    let other_link = route("192.0.2.1/32", 9, None, 0);
    let cloned = route(
        "192.0.2.1/32",
        4,
        None,
        libc::RTF_WASCLONED | libc::RTF_LLINFO,
    );
    let scoped = route("192.0.2.0/24", 4, None, libc::RTF_IFSCOPE);
    assert_eq!(present(&[], &ours), Present::None);
    assert_eq!(
        present(&[identical], &ours),
        Present::Identical { ours: true }
    );
    assert_eq!(
        present(&[unmarked], &ours),
        Present::Identical { ours: false }
    );
    assert_eq!(present(&[other_hop], &ours), Present::Elsewhere);
    assert_eq!(
        present(std::slice::from_ref(&other_link), &ours),
        Present::Elsewhere
    );
    assert_eq!(present(&[cloned], &ours), Present::None);
    assert_eq!(present(&[scoped], &tunnel), Present::None);
    let link_route = route("192.0.2.0/24", 9, None, OURS);
    assert_eq!(
        present(&[link_route], &tunnel),
        Present::Identical { ours: true }
    );
    assert!(counts(&other_link));
}

// The route journal drops rows from another boot, so the boot must be read,
// stay the same while the machine runs, and agree with the clock.
#[test]
fn the_boot_is_read_from_the_kernel() {
    let first = boot().expect("the boot");
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    assert!(first.started > 0 && first.uptime > 0, "{first:?}");
    // The time since start is counted from the start, not from some other
    // moment: the two add up to the clock, give or take the clock's drift.
    let gap = (first.started + first.uptime).abs_diff(now.as_secs());
    assert!(gap <= 60, "{first:?} at {now:?}");
    thread::sleep(Duration::from_millis(1100));
    let later = boot().expect("the boot");
    assert!(later.uptime > first.uptime, "{first:?} then {later:?}");
    assert!(first.same_as(&later), "{first:?} then {later:?}");
}

// The platform is built with these routes; full mode is the next part, and
// says so (its own tests are in full_tunnel_tests.rs).
#[test]
fn the_platform_uses_these_routes() {
    let modes = [
        Mode::Installed,
        #[cfg(feature = "dev-mode")]
        Mode::Dev,
    ];
    for mode in modes {
        let routes = Platform::native(mode).expect("a platform").routes;
        assert_eq!(
            routes.add_full_tunnel("utun9").err(),
            Some(Error::Unsupported)
        );
        // A device that does not exist is not configured.
        let configured = routes.configure_tunnel("utun999", ip("198.51.100.7"), 1300);
        assert!(
            matches!(configured, Err(Error::NotFound | Error::PermissionDenied)),
            "{configured:?}"
        );
        assert_eq!(
            routes.configure_tunnel("utun999", ip("198.51.100.7"), 575),
            Err(Error::InvalidInput)
        );
    }
}

// ---------------------------------------------------------------------------
// The real table: these need root.

/// The test this process was started to run alone, if any.
const CHILD: &str = "UBC_VPN_ROUTES_CHILD";
/// Tells `crash_child` where its journal is, and that it is wanted.
const CRASH: &str = "UBC_VPN_CRASH_CHILD";

/// How long one routing test's process may take.
const DEADLINE: Duration = Duration::from_secs(150);

/// Every destination the routing tests use. Nothing else is ever touched.
const TEST_RANGES: [&str; 4] = [
    "192.0.2.0/24",
    "198.51.100.0/24",
    "198.18.0.0/24",
    "203.0.113.0/24",
];

/// Writes one whole line in one call, so that nothing another thread prints
/// can land inside it: CI looks for these lines.
fn say(line: &str) {
    let line = format!("\n{line}\n");
    std::io::stderr().write_all(line.as_bytes()).expect("say");
}

/// One routing test's process at a time: they share addresses and the
/// machine's one table.
static TURN: Mutex<()> = Mutex::new(());

/// Runs `body` as the test named `test` in a process of its own, as root,
/// and says `RAN AS ROOT: <ran>` when it passed. In that process, which
/// runs nothing else, it runs `body` itself.
fn alone_as_root(test: &str, ran: &str, body: impl FnOnce()) {
    match std::env::var(CHILD) {
        Ok(child) if child == test => {
            regain_root();
            watchdog();
            body();
            return;
        }
        // Started for another test.
        Ok(_) => return,
        Err(_) => {}
    }
    // The real user, which the channel's tests leave alone when they become
    // somebody else for a moment.
    // SAFETY: no preconditions.
    if unsafe { libc::getuid() } != 0 {
        let required = std::env::var_os("UBC_VPN_REQUIRE_ROOT").is_some();
        assert!(!required, "{ran} needs root");
        say(&format!("SKIPPED, needs root: {ran}"));
        return;
    }
    let _turn = lock(&TURN);
    let status = Command::new(std::env::current_exe().expect("this program"))
        .args([
            "--exact",
            &format!("os::routes_tests::{test}"),
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, test)
        .status()
        .expect("start the test's own process");
    assert!(status.success(), "{ran}: its process failed: {status}");
    say(&format!("RAN AS ROOT: {ran}"));
}

/// Becomes root again, if this process started while a channel test was
/// somebody else: it inherited that user as its effective one, but its real
/// user is root.
fn regain_root() {
    // SAFETY: no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        // SAFETY: no preconditions.
        let status = unsafe { libc::seteuid(0) };
        assert_eq!(status, 0, "could not become root again");
    }
}

/// Ends this process, saying where, if a test is stuck, having removed the
/// tests' routes first.
fn watchdog() {
    thread::spawn(|| {
        thread::sleep(DEADLINE);
        say("HUNG: a routing test is stuck");
        scrub(&[]);
        std::process::exit(101);
    });
}

/// Removes every route to a test destination, through any interface, and
/// every route the journals in `dirs` name.
fn scrub(dirs: &[PathBuf]) {
    for dir in dirs {
        let _ = MacRoutes::unchecked(dir).remove_all();
    }
    let ranges = TEST_RANGES.map(net);
    for route in route_socket::table().unwrap_or_default() {
        let ours = ranges.iter().any(|range| range.contains(&route.dest));
        if ours && counts(&route) {
            let _ = route_socket::change(Change::Delete, route.dest, route.index, route.router, 0);
        }
    }
}

/// Removes, when dropped, what a test may have left.
struct Cleanup(Vec<PathBuf>);

impl Drop for Cleanup {
    fn drop(&mut self) {
        scrub(&self.0);
        for dir in &self.0 {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

/// A journal folder of the test's own.
fn state_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ubc-vpn-routes-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn journal_rows(dir: &Path) -> Vec<Row> {
    let mut journal = Journal::new(Store::Unchecked(dir.to_path_buf()));
    journal
        .rows(boot().expect("the boot"))
        .expect("the journal")
}

/// A `utun` device, which lasts as long as this value: the kernel removes
/// it, and every route through it, when its control socket closes.
struct Utun {
    _control: OwnedFd,
    name: String,
}

/// Opens a `utun` device, as the VPN engine does: a kernel control socket
/// connected to `com.apple.net.utun_control`.
fn utun() -> Utun {
    // SAFETY: no pointers are passed.
    let socket = unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
    assert!(socket >= 0, "socket: {}", std::io::Error::last_os_error());
    // SAFETY: just opened, and owned by nothing else.
    let control = unsafe { OwnedFd::from_raw_fd(socket) };
    // SAFETY: plain data, for which all zeroes is valid.
    let mut info: libc::ctl_info = unsafe { std::mem::zeroed() };
    for (to, from) in info.ctl_name.iter_mut().zip(b"com.apple.net.utun_control") {
        *to = *from as libc::c_char;
    }
    // SAFETY: `info` is a live `ctl_info` for the call to fill.
    let found = unsafe { libc::ioctl(control.as_raw_fd(), libc::CTLIOCGINFO, &mut info) };
    assert_eq!(found, 0, "CTLIOCGINFO: {}", std::io::Error::last_os_error());
    let address = libc::sockaddr_ctl {
        sc_len: std::mem::size_of::<libc::sockaddr_ctl>() as u8,
        sc_family: libc::AF_SYSTEM as u8,
        ss_sysaddr: libc::AF_SYS_CONTROL as u16,
        sc_id: info.ctl_id,
        // Any free unit.
        sc_unit: 0,
        sc_reserved: [0; 5],
    };
    // SAFETY: the address is live and its length is passed.
    let connected = unsafe {
        libc::connect(
            control.as_raw_fd(),
            (&raw const address).cast(),
            std::mem::size_of::<libc::sockaddr_ctl>() as libc::socklen_t,
        )
    };
    assert_eq!(connected, 0, "connect: {}", std::io::Error::last_os_error());
    let mut name = [0u8; libc::IFNAMSIZ];
    let mut size = name.len() as libc::socklen_t;
    // SAFETY: `name` is a live buffer of `size` bytes for the call to fill.
    let asked = unsafe {
        libc::getsockopt(
            control.as_raw_fd(),
            libc::SYSPROTO_CONTROL,
            libc::UTUN_OPT_IFNAME,
            name.as_mut_ptr().cast(),
            &mut size,
        )
    };
    assert_eq!(
        asked,
        0,
        "UTUN_OPT_IFNAME: {}",
        std::io::Error::last_os_error()
    );
    let name = std::ffi::CStr::from_bytes_until_nul(&name).expect("a name");
    let name = name.to_str().expect("a name").to_string();
    say(&format!("UTUN: {name}"));
    Utun {
        _control: control,
        name,
    }
}

fn find(name: &str) -> Option<Interface> {
    let interfaces = route_socket::interfaces().expect("the interfaces");
    interfaces.into_iter().find(|i| i.name == name)
}

fn index_of(name: &str) -> u16 {
    find(name).expect("the interface").index
}

/// The router the interface's default route uses, if it has one.
fn router_of(name: &str) -> Option<Ipv4Addr> {
    let index = index_of(name);
    let table = route_socket::table().expect("the table");
    let default = table
        .into_iter()
        .find(|r| counts(r) && r.dest.prefix_len() == 0 && r.index == index && r.router.is_some());
    default.and_then(|r| r.router)
}

/// The routes to `dest` that count, as (interface index, router, marked).
fn routes_to(dest: Ipv4Net) -> Vec<(u16, Option<Ipv4Addr>, bool)> {
    let table = route_socket::table().expect("the table");
    let found = table.into_iter().filter(|r| counts(r) && r.dest == dest);
    found
        .map(|r| (r.index, r.router, r.flags & OURS != 0))
        .collect()
}

/// Changes routes and addresses as somebody other than the product: with
/// the same calls, but unmarked and recorded nowhere.
struct Outsider;

impl Foreign for Outsider {
    fn add_route(&self, interface: &str, net: Ipv4Net) {
        let index = index_of(interface);
        let added = route_socket::change(Change::Add, net, index, router_of(interface), 0);
        added.expect("add a route");
    }

    fn remove_route(&self, interface: &str, net: Ipv4Net) {
        let index = index_of(interface);
        let removed = route_socket::change(Change::Delete, net, index, router_of(interface), 0);
        assert!(
            matches!(removed, Ok(()) | Err(Error::NotFound)),
            "{removed:?}"
        );
    }

    fn add_address(&self, interface: &str, address: Ipv4Addr) {
        let added = route_socket::add_address(interface, address, 24, Some(address));
        added.expect("add an address");
    }

    fn addresses(&self, interface: &str) -> Vec<Ipv4Addr> {
        let found = find(interface).expect("the interface");
        found.v4.iter().map(|a| a.addr).collect()
    }

    // The rest, for full mode's and events' checks, go through the
    // system's own tools. Nothing here uses them until those parts exist.

    fn add_route_v6(&self, interface: &str, dest: Ipv6Addr, prefix_len: u8) {
        let net = format!("{dest}/{prefix_len}");
        system(
            "/sbin/route",
            &["-q", "-n", "add", "-inet6", &net, "-interface", interface],
        );
    }

    fn remove_route_v6(&self, interface: &str, dest: Ipv6Addr, prefix_len: u8) {
        let net = format!("{dest}/{prefix_len}");
        let args = [
            "-q",
            "-n",
            "delete",
            "-inet6",
            &net,
            "-interface",
            interface,
        ];
        system("/sbin/route", &args);
    }

    fn add_address_v6(&self, interface: &str, address: Ipv6Addr) {
        let address = address.to_string();
        let args = [interface, "inet6", &address, "prefixlen", "64", "alias"];
        system("/sbin/ifconfig", &args);
    }

    fn remove_address_v6(&self, interface: &str, address: Ipv6Addr) {
        let address = address.to_string();
        system("/sbin/ifconfig", &[interface, "inet6", &address, "-alias"]);
    }

    fn set_link(&self, interface: &str, up: bool) {
        route_socket::set_up(interface, up).expect("set the link");
    }

    fn bind_ipv6(&self, interface: &str, on: bool) {
        let setting = if on { "-ifdisabled" } else { "ifdisabled" };
        system("/sbin/ifconfig", &[interface, "inet6", setting]);
    }
}

/// Runs one of the system's tools, which must succeed.
fn system(program: &str, args: &[&str]) {
    let status = Command::new(program).args(args).status().expect(program);
    assert!(status.success(), "{program} {args:?}: {status}");
}

#[test]
fn passes_the_shared_route_suite_on_a_utun() {
    alone_as_root(
        "passes_the_shared_route_suite_on_a_utun",
        "routes suite",
        || {
            let device = utun();
            let dir = state_dir("suite");
            let _cleanup = Cleanup(vec![dir.clone()]);
            let routes = MacRoutes::unchecked(&dir);
            say("STEP: check_configure_tunnel");
            suite::check_configure_tunnel(&routes, &Outsider, &device.name);
            say("STEP: check_routes");
            suite::check_routes(&routes, &device.name);
            say("STEP: check_route_ownership");
            let restarted = || Box::new(MacRoutes::unchecked(&dir)) as Box<dyn Routes>;
            suite::check_route_ownership(&routes, &restarted, &Outsider, &device.name);
        },
    );
}

// A change of routes on a live connection (#194). Split DNS on macOS is its
// own part, not written yet, so the DNS half of the check runs against the
// fake's resolver; the routes are real.
#[test]
fn passes_the_shared_live_route_change_check_on_a_utun() {
    alone_as_root(
        "passes_the_shared_live_route_change_check_on_a_utun",
        "routes live change",
        || {
            let device = utun();
            let dir = state_dir("live");
            let _cleanup = Cleanup(vec![dir.clone()]);
            let routes = MacRoutes::unchecked(&dir);
            routes
                .configure_tunnel(&device.name, ip("198.18.0.9"), 1300)
                .expect("configure");
            let dns = Fake::new();
            let resolvers_for = |name: &str| dns.resolvers_for(name);
            suite::check_live_route_change(&routes, &dns, &device.name, &resolvers_for);
        },
    );
}

// The device gets one address, a single host: the address with itself as
// the other end and a mask of all ones. Also the packet size, the up flag,
// and no IPv6 address, after each configure and a moment later.
#[test]
fn the_tunnel_is_a_single_host_with_no_ipv6() {
    alone_as_root(
        "the_tunnel_is_a_single_host_with_no_ipv6",
        "routes tunnel",
        || {
            let device = utun();
            let routes = MacRoutes::unchecked(&state_dir("tunnel"));
            // With IPv6 addresses, as a reused device could have, so taking
            // them off is seen.
            let v6 = "2001:db8::5";
            let added = Command::new("/sbin/ifconfig")
                .args([device.name.as_str(), "inet6", v6, "prefixlen", "128"])
                .status()
                .expect("ifconfig");
            assert!(added.success(), "ifconfig: {added}");
            let before = find(&device.name).expect("the device").v6_addresses();
            say(&format!("IPV6 before: {before:?}"));
            assert!(
                before.contains(&v6.parse().expect("an address")),
                "{before:?}"
            );
            for (n, mtu) in [(2, 1300), (3, 1400), (3, 1400)] {
                let address = Ipv4Addr::new(198, 18, 0, n);
                // Down, so bringing it up is seen, also with the same address.
                route_socket::set_up(&device.name, false).expect("take the device down");
                assert!(!find(&device.name).expect("the device").is_up(), "still up");
                routes
                    .configure_tunnel(&device.name, address, mtu)
                    .expect("configure");
                thread::sleep(Duration::from_secs(2));
                let found = find(&device.name).expect("the device");
                let single = V4Address {
                    addr: address,
                    prefix_len: 32,
                    peer: Some(address),
                };
                assert_eq!(found.v4, [single], "after configuring .{n}");
                let v6 = found.v6_addresses();
                assert!(v6.is_empty(), "IPv6 after configuring .{n}: {v6:?}");
                assert_eq!(found.mtu, u32::from(mtu));
                assert!(found.is_up(), "not up: {:#x}", found.flags);
            }
        },
    );
}

/// The part of `a_killed_service_leaves_what_start_up_removes` that is
/// killed. It does nothing unless that test started it.
#[test]
fn crash_child() {
    let Some(dir) = std::env::var_os(CRASH) else {
        return;
    };
    regain_root();
    watchdog();
    let dir = PathBuf::from(dir);
    let device = utun();
    let routes = MacRoutes::unchecked(&dir);
    let gateway = ip("192.0.2.1");
    let physical = routes.capture_physical(gateway).expect("capture");
    routes
        .configure_tunnel(&device.name, ip("198.18.0.2"), 1300)
        .expect("configure");
    routes
        .add_gateway_route(gateway, &physical)
        .expect("the gateway route");
    routes
        .add_tunnel_routes(&device.name, &[net("198.18.0.0/24")])
        .expect("the tunnel route");
    let names = format!("{}\n{}\n", physical.interface(), device.name);
    std::fs::write(dir.join("names"), names).expect("write the names");
    // The last add stops between its row and its route, says it is there,
    // and waits to be killed.
    BEFORE_ADD.with(|hook| {
        hook.set(Some(|| {
            let dir = PathBuf::from(std::env::var_os(CRASH).expect("the folder"));
            // Written whole, then moved into place, so it is never read
            // half done.
            std::fs::write(dir.join("ready.new"), "").expect("write ready");
            std::fs::rename(dir.join("ready.new"), dir.join("ready")).expect("ready");
            loop {
                thread::park();
            }
        }));
    });
    let second = ip("203.0.113.1");
    let _ = routes.add_gateway_route(second, &physical);
    unreachable!("the add was to stop");
}

// What a service killed mid-connection leaves behind, and that the next
// start removes the product's routes and nothing else. It is killed while
// adding a route: that route's row is in the journal already, and the route
// was never added.
#[test]
fn a_killed_service_leaves_what_start_up_removes() {
    alone_as_root(
        "a_killed_service_leaves_what_start_up_removes",
        "routes crash",
        || {
            let dir = state_dir("crash");
            let _cleanup = Cleanup(vec![dir.clone()]);
            std::fs::create_dir_all(&dir).expect("the folder");
            let mut child = Command::new(std::env::current_exe().expect("this program"))
                .args([
                    "--exact",
                    "os::routes_tests::crash_child",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(CRASH, &dir)
                .spawn()
                .expect("start the child");
            let started = Instant::now();
            while !dir.join("ready").exists() {
                if started.elapsed() > DEADLINE / 2 || child.try_wait().ok().flatten().is_some() {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("the child did not get ready");
                }
                thread::sleep(Duration::from_millis(100));
            }
            child.kill().expect("kill the child");
            child.wait().expect("wait for the child");

            let names = std::fs::read_to_string(dir.join("names")).expect("the names");
            let [wire, tunnel] = [0, 1].map(|n| names.lines().nth(n).expect("a name").to_string());
            let journal = std::fs::read_to_string(dir.join("routes.journal")).unwrap_or_default();
            say(&format!("JOURNAL\n{journal}"));
            let dests: Vec<String> = journal_rows(&dir)
                .iter()
                .map(|r| r.dest.to_string())
                .collect();
            assert_eq!(
                dests,
                ["192.0.2.1/32", "198.18.0.0/24", "203.0.113.1/32"],
                "the journal does not name every route the child added or was adding"
            );
            let wire_index = index_of(&wire);
            let gateway_route = routes_to(net("192.0.2.1/32"));
            assert_eq!(
                gateway_route,
                [(wire_index, router_of(&wire), true)],
                "the gateway route did not survive the child, marked"
            );
            assert_eq!(
                routes_to(net("203.0.113.1/32")),
                [],
                "the stopped add went in"
            );
            // The device goes with the process that held it, and its route
            // with it; give the kernel a moment.
            let gone = Instant::now();
            while find(&tunnel).is_some() && gone.elapsed() < Duration::from_secs(10) {
                thread::sleep(Duration::from_millis(100));
            }
            assert!(find(&tunnel).is_none(), "the child's device is still there");
            assert_eq!(routes_to(net("198.18.0.0/24")), []);

            MacRoutes::unchecked(&dir)
                .remove_all()
                .expect("remove all at the next start");
            assert_eq!(journal_rows(&dir), [], "rows left");
            assert_eq!(
                routes_to(net("192.0.2.1/32")),
                [],
                "the gateway route stayed"
            );
        },
    );
}

// A crash between writing a row and adding its route leaves a row with no
// route: the next start drops it without harm. If somebody else adds the
// identical route in the meantime, it carries no mark, so it stays.
#[test]
fn a_row_whose_route_was_never_added_is_dropped() {
    alone_as_root(
        "a_row_whose_route_was_never_added_is_dropped",
        "routes orphan row",
        || {
            let dir = state_dir("orphan");
            let _cleanup = Cleanup(vec![dir.clone()]);
            let routes = MacRoutes::unchecked(&dir);
            let gateway = ip("192.0.2.1");
            let physical = routes.capture_physical(gateway).expect("capture");
            let wire = physical.interface().to_string();
            let row = Row {
                dest: Prefix::V4(net("192.0.2.1/32")),
                luid: u64::from(index_of(&wire)),
                next_hop: IpAddr::V4(router_of(&wire).unwrap_or(Ipv4Addr::UNSPECIFIED)),
                interface: wire.clone(),
            };
            let write = |rows: &[Row]| {
                let mut journal = Journal::new(Store::Unchecked(dir.clone()));
                journal
                    .write(boot().expect("the boot"), rows)
                    .expect("write");
            };
            write(std::slice::from_ref(&row));
            MacRoutes::unchecked(&dir)
                .remove_all()
                .expect("remove all at the next start");
            assert_eq!(journal_rows(&dir), []);

            write(std::slice::from_ref(&row));
            Outsider.add_route(&wire, net("192.0.2.1/32"));
            let theirs = routes_to(net("192.0.2.1/32"));
            assert_eq!(theirs.len(), 1, "the harness added nothing: {theirs:?}");
            MacRoutes::unchecked(&dir)
                .remove_all()
                .expect("remove all at the next start");
            assert_eq!(journal_rows(&dir), []);
            assert_eq!(
                routes_to(net("192.0.2.1/32")),
                theirs,
                "removed somebody else's route that a row named"
            );
            Outsider.remove_route(&wire, net("192.0.2.1/32"));
        },
    );
}

// Routes do not outlive a restart, so a journal from another boot is
// dropped and nothing is removed for it, even a route that matches a row.
#[test]
fn rows_from_another_boot_remove_nothing() {
    alone_as_root(
        "rows_from_another_boot_remove_nothing",
        "routes other boot",
        || {
            let device = utun();
            let dir = state_dir("boot");
            let _cleanup = Cleanup(vec![dir.clone()]);
            let routes = MacRoutes::unchecked(&dir);
            routes
                .configure_tunnel(&device.name, ip("198.18.0.3"), 1300)
                .expect("configure");
            let theirs = net("198.51.100.0/24");
            routes
                .add_tunnel_routes(&device.name, &[theirs])
                .expect("add");
            let rows = journal_rows(&dir);
            assert_eq!(rows.len(), 1, "{rows:?}");
            let now = boot().expect("the boot");
            let earlier = Boot {
                started: now.started - 7_200,
                uptime: now.uptime,
            };
            let mut journal = Journal::new(Store::Unchecked(dir.clone()));
            journal.write(earlier, &rows).expect("write");
            MacRoutes::unchecked(&dir).remove_all().expect("remove all");
            let kept = routes.uses_interface(ip("198.51.100.9"), &device.name);
            assert_eq!(
                kept,
                Verified::Yes,
                "a row from another boot removed a route"
            );
            assert_eq!(journal_rows(&dir), []);
            Outsider.remove_route(&device.name, theirs);
        },
    );
}

// A route is written to the journal before it is added, so a crash
// between the two leaves a row and never a route that nothing names.
#[test]
fn the_row_is_written_before_the_route_is_added() {
    alone_as_root(
        "the_row_is_written_before_the_route_is_added",
        "routes journal first",
        || {
            let dir = state_dir("first");
            let _cleanup = Cleanup(vec![dir.clone()]);
            let routes = MacRoutes::unchecked(&dir);
            let gateway = ip("198.18.0.1");
            let physical = routes.capture_physical(gateway).expect("capture");
            BEFORE_ADD
                .with(|hook| hook.set(Some(|| panic!("a crash between the row and the route"))));
            let added = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                routes.add_gateway_route(gateway, &physical)
            }));
            BEFORE_ADD.with(|hook| hook.set(None));
            assert!(added.is_err(), "the add did not stop where it was told to");
            let dests: Vec<String> = journal_rows(&dir)
                .iter()
                .map(|r| r.dest.to_string())
                .collect();
            assert_eq!(dests, ["198.18.0.1/32"]);
            assert_eq!(routes_to(net("198.18.0.1/32")), [], "the route went in");
        },
    );
}

// An add over a route that is there already never writes a row for it,
// even for a moment: the table is read first. Whether that route is
// identical or elsewhere, a crash then could leave a row naming somebody
// else's route.
#[test]
fn an_add_over_a_route_already_there_writes_no_row() {
    alone_as_root(
        "an_add_over_a_route_already_there_writes_no_row",
        "routes no row for theirs",
        || {
            let device = utun();
            let dir = state_dir("theirs");
            let _cleanup = Cleanup(vec![dir.clone()]);
            let routes = MacRoutes::unchecked(&dir);
            routes
                .configure_tunnel(&device.name, ip("198.18.0.5"), 1300)
                .expect("configure");
            let physical = routes.capture_physical(ip("192.0.2.1")).expect("capture");
            let wire = physical.interface().to_string();
            let (identical, elsewhere) = (net("198.51.100.0/24"), net("203.0.113.0/24"));
            Outsider.add_route(&device.name, identical);
            Outsider.add_route(&wire, elsewhere);
            BEFORE_ADD.with(|hook| {
                hook.set(Some(|| {
                    panic!("a row was written for a route already there")
                }))
            });
            let over_identical = routes.add_tunnel_routes(&device.name, &[identical]);
            let over_elsewhere = routes.add_tunnel_routes(&device.name, &[elsewhere]);
            BEFORE_ADD.with(|hook| hook.set(None));
            assert_eq!(over_identical, Ok(()));
            assert_eq!(over_elsewhere, Err(Error::AlreadyExists));
            assert_eq!(journal_rows(&dir), []);
            Outsider.remove_route(&device.name, identical);
            Outsider.remove_route(&wire, elsewhere);
        },
    );
}

/// The route somebody else adds while an add is between its row and its
/// route: the destination, the interface's index and the router.
static RACE: Mutex<Option<(Ipv4Net, u16, Option<Ipv4Addr>)>> = Mutex::new(None);

// Somebody else adds a route to the same destination after the table was
// read and the row written, before the route went in. The kernel refuses
// ours; the row is withdrawn, and their route is not ours. An identical one
// counts as added; one elsewhere is `AlreadyExists`.
#[test]
fn an_add_that_loses_a_race_withdraws_its_row() {
    alone_as_root(
        "an_add_that_loses_a_race_withdraws_its_row",
        "routes race",
        || {
            let device = utun();
            let dir = state_dir("race");
            let _cleanup = Cleanup(vec![dir.clone()]);
            let routes = MacRoutes::unchecked(&dir);
            routes
                .configure_tunnel(&device.name, ip("198.18.0.7"), 1300)
                .expect("configure");
            let physical = routes.capture_physical(ip("192.0.2.1")).expect("capture");
            let wire = physical.interface().to_string();
            let (tunnel_index, wire_index) = (index_of(&device.name), index_of(&wire));
            let (identical, elsewhere) = (net("198.51.100.0/24"), net("203.0.113.0/24"));
            BEFORE_ADD.with(|hook| {
                hook.set(Some(|| {
                    let (net, index, router) = lock(&RACE).expect("a race to run");
                    let added = route_socket::change(Change::Add, net, index, router, 0);
                    added.expect("somebody else's route");
                }));
            });
            *lock(&RACE) = Some((identical, tunnel_index, None));
            let over_identical = routes.add_tunnel_routes(&device.name, &[identical]);
            *lock(&RACE) = Some((elsewhere, wire_index, router_of(&wire)));
            let over_elsewhere = routes.add_tunnel_routes(&device.name, &[elsewhere]);
            BEFORE_ADD.with(|hook| hook.set(None));
            assert_eq!(over_identical, Ok(()));
            assert_eq!(over_elsewhere, Err(Error::AlreadyExists));
            assert_eq!(journal_rows(&dir), [], "a row stayed for a route that lost");
            let theirs = [
                (identical, tunnel_index, None),
                (elsewhere, wire_index, router_of(&wire)),
            ];
            for (net, index, router) in theirs {
                assert_eq!(routes_to(net), [(index, router, false)], "{net}");
            }
            routes.remove_all().expect("remove all");
            for (net, index, router) in theirs {
                assert_eq!(
                    routes_to(net),
                    [(index, router, false)],
                    "{net} was removed"
                );
            }
            Outsider.remove_route(&device.name, identical);
            Outsider.remove_route(&wire, elsewhere);
        },
    );
}

// Removing some routes removes those and leaves the rest of ours: another
// gateway's route through the same router, and another of the tunnel's.
#[test]
fn removing_some_routes_leaves_the_others() {
    alone_as_root(
        "removing_some_routes_leaves_the_others",
        "routes remove some",
        || {
            let device = utun();
            let dir = state_dir("some");
            let _cleanup = Cleanup(vec![dir.clone()]);
            let routes = MacRoutes::unchecked(&dir);
            routes
                .configure_tunnel(&device.name, ip("198.18.0.6"), 1300)
                .expect("configure");
            let (first, second) = (ip("192.0.2.1"), ip("203.0.113.1"));
            let physical = routes.capture_physical(first).expect("capture");
            let (a, b) = (net("198.51.100.0/25"), net("198.51.100.128/25"));
            routes
                .add_gateway_route(first, &physical)
                .expect("a gateway route");
            routes
                .add_gateway_route(second, &physical)
                .expect("another");
            routes
                .add_tunnel_routes(&device.name, &[a, b])
                .expect("tunnel routes");
            let there = || {
                [
                    "192.0.2.1/32",
                    "203.0.113.1/32",
                    "198.51.100.0/25",
                    "198.51.100.128/25",
                ]
                .map(|dest| !routes_to(net(dest)).is_empty())
            };
            assert_eq!(there(), [true; 4]);
            routes
                .remove_tunnel_routes(&device.name, &[a])
                .expect("remove one tunnel route");
            assert_eq!(there(), [true, true, false, true]);
            routes
                .remove_gateway_route(first, &physical)
                .expect("remove one gateway route");
            assert_eq!(there(), [false, true, false, true]);
            let left: Vec<String> = journal_rows(&dir)
                .iter()
                .map(|r| r.dest.to_string())
                .collect();
            assert_eq!(left, ["203.0.113.1/32", "198.51.100.128/25"]);
            routes.remove_all().expect("remove all");
            assert_eq!(there(), [false; 4]);
        },
    );
}

// Security rule: a route out of an interface that is down carries nothing,
// so it is never the way to its destination. The route counts while the
// device is up, and is still in the table once it is down.
#[test]
fn a_route_on_a_down_interface_never_counts() {
    alone_as_root(
        "a_route_on_a_down_interface_never_counts",
        "routes down interface",
        || {
            let device = utun();
            let dir = state_dir("down");
            let _cleanup = Cleanup(vec![dir.clone()]);
            let routes = MacRoutes::unchecked(&dir);
            routes
                .configure_tunnel(&device.name, ip("198.18.0.8"), 1400)
                .expect("configure");
            let net = net("198.51.100.0/24");
            let dest = ip("198.51.100.9");
            Outsider.add_route(&device.name, net);
            assert_eq!(
                routes.uses_interface(dest, &device.name),
                Verified::Yes,
                "while up"
            );

            route_socket::set_up(&device.name, false).expect("take the device down");
            let started = Instant::now();
            while find(&device.name).is_some_and(|i| i.is_up())
                && started.elapsed() < Duration::from_secs(10)
            {
                thread::sleep(Duration::from_millis(100));
            }
            assert!(!find(&device.name).expect("the device").is_up(), "still up");
            // Should the kernel drop the route as the device goes down, it is
            // added again, on the device that is down.
            if routes_to(net).is_empty() {
                Outsider.add_route(&device.name, net);
            }
            let index = index_of(&device.name);
            assert_eq!(
                routes_to(net).iter().map(|r| r.0).collect::<Vec<_>>(),
                [index]
            );
            let answer = routes.uses_interface(dest, &device.name);
            assert_eq!(
                answer,
                Verified::No,
                "a route on a device that is down counted"
            );
            Outsider.remove_route(&device.name, net);
        },
    );
}

// Security rule: only a tunnel device is configured or routed through as
// one, never the physical network.
#[test]
fn refuses_to_treat_the_physical_interface_as_the_tunnel() {
    alone_as_root(
        "refuses_to_treat_the_physical_interface_as_the_tunnel",
        "routes physical",
        || {
            let dir = state_dir("physical");
            let _cleanup = Cleanup(vec![dir.clone()]);
            let routes = MacRoutes::unchecked(&dir);
            let physical = routes.capture_physical(ip("192.0.2.1")).expect("capture");
            let wire = physical.interface();
            // Only a point-to-point interface has another end.
            let addresses = find(wire).expect("the physical interface").v4;
            assert!(
                !addresses.is_empty(),
                "the physical interface has no address"
            );
            assert!(addresses.iter().all(|a| a.peer.is_none()), "{addresses:?}");
            let configured = routes.configure_tunnel(wire, ip("198.51.100.7"), 1300);
            assert!(
                matches!(configured, Err(Error::Failed(_))),
                "{configured:?}"
            );
            let routed = routes.add_tunnel_routes(wire, &[net("198.51.100.0/24")]);
            assert!(matches!(routed, Err(Error::Failed(_))), "{routed:?}");
            assert_eq!(journal_rows(&dir), []);
        },
    );
}

// The mark stays on a route that traffic uses. The kernel clears its own
// expiry mark, `RTF_PROTO3`, from a route the first time it is looked up,
// which would leave the route unremovable; this one stays, and the route is
// removed.
#[test]
fn the_mark_survives_the_route_being_used() {
    alone_as_root(
        "the_mark_survives_the_route_being_used",
        "routes mark survives use",
        || {
            let device = utun();
            let dir = state_dir("mark");
            let _cleanup = Cleanup(vec![dir.clone()]);
            let routes = MacRoutes::unchecked(&dir);
            routes
                .configure_tunnel(&device.name, ip("198.18.0.4"), 1300)
                .expect("configure");
            let net = net("198.51.100.0/24");
            routes.add_tunnel_routes(&device.name, &[net]).expect("add");
            // Connecting looks the route up and holds it, as traffic does.
            let socket = UdpSocket::bind("0.0.0.0:0").expect("a socket");
            socket.connect("198.51.100.9:9").expect("connect");
            let _ = socket.send(b"x");
            thread::sleep(Duration::from_millis(500));
            let index = index_of(&device.name);
            assert_eq!(
                routes_to(net),
                [(index, None, true)],
                "the mark went with use"
            );
            drop(socket);
            routes.remove_all().expect("remove all");
            assert_eq!(routes_to(net), [], "the route used was not removed");
        },
    );
}
