//! Tests of network change notifications on Linux.
//!
//! The comparison and the worker are tested here on made-up lists. The rest
//! runs on the real kernel, as root, in a process of its own like the
//! routing tests (see `routes_tests`): veth pairs the test makes play the
//! physical network and another network, and a tunnel device it opens plays
//! the tunnel, so nothing on the runner's own network changes. A link the
//! test did not make is never changed: the harness refuses one.

use std::cell::RefCell;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Command;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use rustix::event::{EventfdFlags, eventfd};
use ubc_vpn_core::routes::Ipv4Net;

use super::dns_tests::PREFIX;
use super::events::{
    self, GROUPS, LinuxEvents, Listener, Physical, Source, State, Wake, Watcher, changes,
    differs_from_capture, state, watch,
};
use super::netlink::{
    self, AF_INET, AF_INET6, Address, IFF_RUNNING, IFF_UP, Link, RT_SCOPE_LINK, RT_TABLE_MAIN,
    RTM_F_CLONED, RTN_UNICAST, Route,
};
use super::routes::LinuxRoutes;
use super::routes_tests::{Outsider, Tun, as_root_in, ip_ok, say};
use crate::suite::{self, Foreign};
use crate::{
    Ipv6Block, LINUX_ROUTE_PROTOCOL, Mode, NetworkEvent, NetworkEvents, PhysicalNetwork, Platform,
    Result, Routes, Subscription, Verified,
};

const PHYSICAL: NetworkEvent = NetworkEvent::PhysicalChanged;
const IPV6: NetworkEvent = NetworkEvent::Ipv6Changed;

fn link(index: u32, name: &str, flags: u32) -> Link {
    Link {
        index,
        name: name.to_string(),
        flags,
        kind: None,
        mtu: None,
    }
}

fn address(index: u32, addr: IpAddr, prefix_len: u8) -> Address {
    let family = if addr.is_ipv4() { AF_INET } else { AF_INET6 };
    Address {
        family,
        prefix_len,
        flags: 0,
        index,
        local: addr,
        address: None,
    }
}

fn route(dst: IpAddr, dst_len: u8, oif: Option<u32>, protocol: u8) -> Route {
    let family = if dst.is_ipv4() { AF_INET } else { AF_INET6 };
    Route {
        family,
        dst,
        dst_len,
        tos: 0,
        table: RT_TABLE_MAIN,
        protocol,
        scope: RT_SCOPE_LINK,
        kind: RTN_UNICAST,
        flags: 0,
        oif,
        gateway: None,
        priority: None,
        multipath: false,
        via: false,
    }
}

fn ip(text: &str) -> IpAddr {
    text.parse().expect("an address")
}

/// The interfaces of the made-up lists: loopback, the watched one, another
/// and the tunnel.
const LO: u32 = 1;
const WIRE: u32 = 2;
const OTHER: u32 = 3;
const TUNNEL: u32 = 4;
/// A route protocol of somebody else's: the kernel's own.
const KERNEL: u8 = 2;

fn links() -> Vec<Link> {
    let running = IFF_UP | IFF_RUNNING;
    vec![
        link(LO, "lo", running),
        link(WIRE, "wire0", running),
        link(OTHER, "other0", running),
        link(TUNNEL, "uvt-tun0", running),
    ]
}

/// A network as a machine on one has it.
fn usual() -> (Vec<Address>, Vec<Route>) {
    let addresses = vec![
        address(LO, ip("127.0.0.1"), 8),
        address(LO, ip("::1"), 128),
        address(WIRE, ip("192.168.0.10"), 24),
        address(WIRE, ip("fe80::10"), 64),
        address(OTHER, ip("10.9.0.2"), 24),
    ];
    let mut default = route(ip("0.0.0.0"), 0, Some(WIRE), KERNEL);
    default.gateway = Some(ip("192.168.0.1"));
    let routes = vec![
        default,
        route(ip("192.168.0.0"), 24, Some(WIRE), KERNEL),
        route(ip("10.9.0.0"), 24, Some(OTHER), KERNEL),
        route(ip("fe80::"), 64, Some(WIRE), KERNEL),
        route(ip("ff00::"), 8, Some(WIRE), KERNEL),
        route(ip("::1"), 128, Some(LO), KERNEL),
    ];
    (addresses, routes)
}

fn state_of(links: &[Link], addresses: &[Address], routes: &[Route]) -> State {
    state("wire0", "uvt-", links, addresses, routes)
}

/// The events for the usual network becoming what `change` makes of it.
fn events_for(
    change: impl FnOnce(&mut Vec<Link>, &mut Vec<Address>, &mut Vec<Route>),
) -> Vec<NetworkEvent> {
    let (links, (addresses, routes)) = (self::links(), usual());
    let before = state_of(&links, &addresses, &routes);
    let (mut links, mut addresses, mut routes) = (links, addresses, routes);
    change(&mut links, &mut addresses, &mut routes);
    changes(&before, &state_of(&links, &addresses, &routes))
}

// Contract: "physical changed" is sent for the watched interface alone, and
// never for a route this product added, nor for anything on the tunnel.
#[test]
fn only_the_watched_interface_is_a_physical_change() {
    assert_eq!(events_for(|_, _, _| {}), [], "nothing changed");
    // What a connection does: our own gateway route through the watched
    // interface, our routes and address on the tunnel, and full mode's
    // halves, IPv6 ones too.
    let ours = events_for(|links, addresses, routes| {
        let mut gateway = route(ip("192.0.2.1"), 32, Some(WIRE), LINUX_ROUTE_PROTOCOL);
        gateway.gateway = Some(ip("192.168.0.1"));
        routes.push(gateway);
        routes.push(route(
            ip("198.51.100.0"),
            24,
            Some(TUNNEL),
            LINUX_ROUTE_PROTOCOL,
        ));
        routes.push(route(ip("0.0.0.0"), 1, Some(TUNNEL), LINUX_ROUTE_PROTOCOL));
        routes.push(route(ip("::"), 1, Some(TUNNEL), LINUX_ROUTE_PROTOCOL));
        // A blocking half goes nowhere, but is still ours.
        routes.push(route(ip("8000::"), 1, None, LINUX_ROUTE_PROTOCOL));
        addresses.push(address(TUNNEL, ip("198.18.0.2"), 32));
        links[3].flags = IFF_UP;
    });
    assert_eq!(ours, [], "our own routes, or the tunnel");
    // Somebody else's route through the watched interface is a change, as
    // is the same route with our mark taken off.
    let theirs = events_for(|_, _, routes| {
        routes.push(route(ip("192.0.2.1"), 32, Some(WIRE), KERNEL));
    });
    assert_eq!(theirs, [PHYSICAL], "somebody else's route");
    let elsewhere = events_for(|_, addresses, routes| {
        routes.push(route(ip("203.0.113.0"), 24, Some(OTHER), KERNEL));
        addresses.push(address(OTHER, ip("203.0.113.21"), 24));
        addresses.push(address(OTHER, ip("10.9.0.3"), 24));
    });
    assert_eq!(elsewhere, [], "a change to another interface");
    let new_address = events_for(|_, addresses, _| {
        addresses.push(address(WIRE, ip("203.0.113.11"), 24));
    });
    assert_eq!(new_address, [PHYSICAL], "a new address");
    let gone =
        events_for(|_, addresses, _| addresses.retain(|a| a.index != WIRE || a.family != AF_INET));
    assert_eq!(gone, [PHYSICAL], "an address gone");
    let new_router = events_for(|_, _, routes| routes[0].gateway = Some(ip("192.168.0.254")));
    assert_eq!(new_router, [PHYSICAL], "another router");
    for flags in [0, IFF_UP] {
        let down = events_for(|links, _, _| links[1].flags = flags);
        assert_eq!(down, [PHYSICAL], "down, or up with no link: {flags:#x}");
    }
    let removed = events_for(|links, _, _| {
        links.remove(1);
    });
    assert_eq!(removed, [PHYSICAL], "the interface gone");
    // Another interface of the same name: the watched one was replaced.
    let replaced = events_for(|links, _, _| links[1].index = 9);
    assert_eq!(replaced, [PHYSICAL], "the interface replaced");
}

// Security rule: an IPv6 route or address that comes or goes on any
// interface but the tunnel is reported, so that full mode decides again
// whether IPv6 can leak. Those that cannot carry anything off the machine
// are left out, as is everything that is ours.
#[test]
fn an_ipv6_change_anywhere_but_the_tunnel_is_reported() {
    for (what, index) in [("watched", WIRE), ("other", OTHER)] {
        let added = events_for(|_, _, routes| {
            routes.push(route(ip("2001:db8:2::"), 48, Some(index), KERNEL));
        });
        assert_eq!(added, [IPV6], "a route on the {what} interface");
        let default = events_for(|_, _, routes| {
            let mut default = route(ip("::"), 0, Some(index), KERNEL);
            default.gateway = Some(ip("fe80::1"));
            routes.push(default);
        });
        assert_eq!(default, [IPV6], "a default route on the {what} interface");
        let address = events_for(|_, addresses, _| {
            addresses.push(address(index, ip("2001:db8:3::10"), 64));
        });
        assert_eq!(address, [IPV6], "an address on the {what} interface");
    }
    let gone = events_for(|_, _, routes| {
        routes.retain(|r| r.family != AF_INET6);
    });
    assert_eq!(gone, [], "only routes that do not count went");
    let left_out = events_for(|_, addresses, routes| {
        routes.push(route(ip("fe80::"), 64, Some(OTHER), KERNEL));
        routes.push(route(ip("ff02::1"), 128, Some(OTHER), KERNEL));
        routes.push(route(ip("::1"), 128, Some(OTHER), KERNEL));
        routes.push(route(ip("2001:db8:4::"), 48, Some(TUNNEL), KERNEL));
        routes.push(route(
            ip("2001:db8:5::"),
            48,
            Some(OTHER),
            LINUX_ROUTE_PROTOCOL,
        ));
        let mut cloned = route(ip("2001:db8:6::1"), 128, Some(OTHER), KERNEL);
        cloned.flags = RTM_F_CLONED;
        routes.push(cloned);
        addresses.push(address(OTHER, ip("fe80::3"), 64));
        addresses.push(address(OTHER, ip("::1"), 128));
        addresses.push(address(TUNNEL, ip("2001:db8:7::2"), 64));
    });
    assert_eq!(
        left_out,
        [],
        "link-local, multicast, loopback, the tunnel, ours"
    );
}

// A change between capturing the network and subscribing to it is reported,
// not taken as the starting point.
#[test]
fn a_change_since_capture_is_noticed() {
    let captured = PhysicalNetwork {
        interface: "wire0".to_string(),
        next_hop: Some(Ipv4Addr::new(192, 168, 0, 1)),
        own_addresses: vec![Ipv4Addr::new(192, 168, 0, 10), Ipv4Addr::new(10, 9, 0, 2)],
        on_link: Vec::new(),
    };
    let (addresses, routes) = usual();
    let now = |links: &[Link], addresses: &[Address], routes: &[Route]| -> Physical {
        state_of(links, addresses, routes).physical
    };
    assert!(!differs_from_capture(
        &now(&links(), &addresses, &routes),
        &captured
    ));
    let mut down = links();
    down[1].flags = IFF_UP;
    let mut missing = links();
    missing.remove(1);
    let mut moved = addresses.clone();
    moved.push(address(WIRE, ip("10.0.0.5"), 24));
    let mut new_router = routes.clone();
    new_router[0].gateway = Some(ip("192.168.0.254"));
    let changed = [
        now(&down, &addresses, &routes),
        now(&missing, &addresses, &routes),
        now(&links(), &moved, &routes),
        now(&links(), &addresses, &new_router),
    ];
    for physical in changed {
        assert!(differs_from_capture(&physical, &captured), "{physical:?}");
    }
}

/// Wakes in the order given, then stops.
struct Script(Vec<io::Result<Wake>>);

impl Source for Script {
    fn wait(&mut self) -> io::Result<Wake> {
        match self.0.is_empty() {
            true => Ok(Wake::Stop),
            false => self.0.remove(0),
        }
    }
}

/// What the worker sends for `wakes`, starting from `start` and given the
/// looks in `looks`, in order.
fn worker_sends(
    start: &State,
    wakes: Vec<io::Result<Wake>>,
    looks: Vec<io::Result<State>>,
) -> Vec<NetworkEvent> {
    let looks = RefCell::new(looks);
    let look = || looks.borrow_mut().remove(0);
    let (sender, receiver) = mpsc::channel();
    watch(&mut Script(wakes), &look, start.clone(), &sender);
    drop(sender);
    receiver.into_iter().collect()
}

fn two_states() -> (State, State) {
    let (addresses, routes) = usual();
    let before = state_of(&links(), &addresses, &routes);
    let mut more = addresses.clone();
    more.push(address(WIRE, ip("203.0.113.11"), 24));
    (before, state_of(&links(), &more, &routes))
}

// When the kernel drops notices, what changed is unknown: both events go,
// and the worker starts again from a fresh look, so a later notice is
// compared with how things were after the loss, not before.
#[test]
fn lost_notices_are_reported_and_the_worker_starts_afresh() {
    let (before, after) = two_states();
    let wakes = vec![Ok(Wake::Overrun), Ok(Wake::Changed)];
    let sent = worker_sends(&before, wakes, vec![Ok(after.clone()), Ok(after)]);
    assert_eq!(sent, [PHYSICAL, IPV6]);
}

// A look that fails, or a socket that does, is reported the safe way; the
// socket's error also ends the events.
#[test]
fn a_failure_is_reported_as_both_changes() {
    let (before, after) = two_states();
    let failed = || io::Error::from_raw_os_error(libc::EIO);
    let sent = worker_sends(&before, vec![Ok(Wake::Changed)], vec![Err(failed())]);
    assert_eq!(sent, [PHYSICAL, IPV6], "a look that failed");
    let wakes = vec![Err(failed()), Ok(Wake::Changed)];
    let sent = worker_sends(&before, wakes, vec![Ok(after)]);
    assert_eq!(
        sent,
        [PHYSICAL, IPV6],
        "the socket failed, then nothing more"
    );
    let wakes = vec![Ok(Wake::Changed), Ok(Wake::Changed)];
    let sent = worker_sends(&before, wakes, vec![Ok(before.clone()), Ok(two_states().1)]);
    assert_eq!(sent, [PHYSICAL], "only what changed");
}

// Contract: the link group, and the address and route groups for both IPv4
// and IPv6.
#[test]
fn every_group_the_contract_names_is_listened_to() {
    for group in [
        netlink::GROUP_LINK,
        netlink::GROUP_IPV4_ADDRESS,
        netlink::GROUP_IPV4_ROUTE,
        netlink::GROUP_IPV6_ADDRESS,
        netlink::GROUP_IPV6_ROUTE,
    ] {
        assert_eq!(GROUPS & group, group, "{group:#x}");
    }
}

// Full mode is refused until it is written, even though IPv6 changes are
// sent.
#[test]
fn full_mode_stays_refused() {
    let modes = [
        Mode::Installed,
        #[cfg(feature = "dev-mode")]
        Mode::Dev,
    ];
    for mode in modes {
        let events = Platform::native(mode).expect("a platform").events;
        assert!(!events.reports_ipv6_changes());
    }
}

/// Every link a root test makes is named so.
const MADE: &str = "uve-";

/// Waits up to five seconds for `done`.
fn wait_for(done: impl Fn() -> bool) -> bool {
    let started = Instant::now();
    while !done() && started.elapsed() < Duration::from_secs(5) {
        thread::sleep(Duration::from_millis(100));
    }
    done()
}

fn find(name: &str) -> Option<Link> {
    let links = netlink::links().expect("the links");
    links.into_iter().find(|link| link.name == name)
}

/// A veth pair the test made: `name`, which the test uses, and its peer,
/// both up. Both go when this is dropped, with their addresses and routes.
struct Veth {
    name: String,
}

impl Veth {
    fn new(name: &str) -> Self {
        assert!(name.starts_with(MADE) && name.len() < 15, "{name}");
        let peer = format!("{name}p");
        let _ = Command::new("ip").args(["link", "del", name]).output();
        ip_ok(&["link", "add", name, "type", "veth", "peer", "name", &peer]);
        let made = Self {
            name: name.to_string(),
        };
        ip_ok(&["link", "set", "dev", &peer, "up"]);
        ip_ok(&["link", "set", "dev", name, "up"]);
        let running = || find(name).is_some_and(|link| link.running());
        assert!(wait_for(running), "{name} did not come up");
        made
    }
}

impl Drop for Veth {
    fn drop(&mut self) {
        let _ = Command::new("ip")
            .args(["link", "del", &self.name])
            .output();
    }
}

/// Refuses an interface the test did not make: never the runner's own.
fn made(interface: &str) {
    assert!(
        interface.starts_with(MADE),
        "{interface} is not a test's own link"
    );
}

/// [`Outsider`] on the test's own links only.
struct OnTestLinks;

impl Foreign for OnTestLinks {
    fn add_route(&self, interface: &str, net: Ipv4Net) {
        made(interface);
        Outsider.add_route(interface, net);
    }

    fn remove_route(&self, interface: &str, net: Ipv4Net) {
        made(interface);
        Outsider.remove_route(interface, net);
    }

    fn add_address(&self, interface: &str, address: Ipv4Addr) {
        made(interface);
        Outsider.add_address(interface, address);
    }

    fn addresses(&self, interface: &str) -> Vec<Ipv4Addr> {
        Outsider.addresses(interface)
    }

    fn add_route_v6(&self, interface: &str, dest: Ipv6Addr, prefix_len: u8) {
        made(interface);
        Outsider.add_route_v6(interface, dest, prefix_len);
    }

    fn remove_route_v6(&self, interface: &str, dest: Ipv6Addr, prefix_len: u8) {
        made(interface);
        Outsider.remove_route_v6(interface, dest, prefix_len);
    }

    fn add_address_v6(&self, interface: &str, address: Ipv6Addr) {
        made(interface);
        Outsider.add_address_v6(interface, address);
    }

    fn remove_address_v6(&self, interface: &str, address: Ipv6Addr) {
        made(interface);
        Outsider.remove_address_v6(interface, address);
    }

    fn set_link(&self, interface: &str, up: bool) {
        made(interface);
        Outsider.set_link(interface, up);
    }

    fn bind_ipv6(&self, interface: &str, on: bool) {
        made(interface);
        Outsider.bind_ipv6(interface, on);
    }
}

/// [`LinuxRoutes`], with full mode's halves added the way full mode will
/// add them: through the tunnel, IPv4 and IPv6, with the product's mark.
/// They go in a table of their own that no rule uses, so the runner's own
/// traffic never follows them; the events count routes in every table.
/// `remove_all` removes them, as it does every route with the mark.
struct WithHalves;

/// The table the halves go in.
const HALVES_TABLE: &str = "181";

impl Routes for WithHalves {
    fn capture_physical(&self, gateway: Ipv4Addr) -> Result<PhysicalNetwork> {
        LinuxRoutes.capture_physical(gateway)
    }

    fn configure_tunnel(&self, tunnel: &str, address: Ipv4Addr, mtu: u16) -> Result<()> {
        LinuxRoutes.configure_tunnel(tunnel, address, mtu)
    }

    fn add_gateway_route(&self, gateway: Ipv4Addr, via: &PhysicalNetwork) -> Result<()> {
        LinuxRoutes.add_gateway_route(gateway, via)
    }

    fn remove_gateway_route(&self, gateway: Ipv4Addr, via: &PhysicalNetwork) -> Result<()> {
        LinuxRoutes.remove_gateway_route(gateway, via)
    }

    fn add_tunnel_routes(&self, tunnel: &str, subnets: &[Ipv4Net]) -> Result<()> {
        LinuxRoutes.add_tunnel_routes(tunnel, subnets)
    }

    fn remove_tunnel_routes(&self, tunnel: &str, subnets: &[Ipv4Net]) -> Result<()> {
        LinuxRoutes.remove_tunnel_routes(tunnel, subnets)
    }

    fn remove_all(&self) -> Result<()> {
        LinuxRoutes.remove_all()
    }

    fn uses_interface(&self, dest: Ipv4Addr, interface: &str) -> Verified {
        LinuxRoutes.uses_interface(dest, interface)
    }

    fn full_tunnel_ipv6(&self, tunnel: &str) -> Result<Ipv6Block> {
        LinuxRoutes.full_tunnel_ipv6(tunnel)
    }

    fn add_full_tunnel(&self, tunnel: &str) -> Result<Ipv6Block> {
        let protocol = LINUX_ROUTE_PROTOCOL.to_string();
        let halves = [
            ("-4", "0.0.0.0/1"),
            ("-4", "128.0.0.0/1"),
            ("-6", "::/1"),
            ("-6", "8000::/1"),
        ];
        for (family, half) in halves {
            let table = ["table", HALVES_TABLE, "proto", &protocol];
            let route = [family, "route", "add", half, "dev", tunnel];
            ip_ok(&[&route[..], &table[..]].concat());
        }
        Ok(Ipv6Block::Blocked)
    }

    fn remove_full_tunnel(&self, tunnel: &str) -> Result<()> {
        LinuxRoutes.remove_full_tunnel(tunnel)
    }

    fn foreign_full_tunnel(&self, tunnel: &str) -> Result<bool> {
        LinuxRoutes.foreign_full_tunnel(tunnel)
    }

    fn uses_interface_v6(&self, dest: Ipv6Addr, interface: &str) -> Verified {
        LinuxRoutes.uses_interface_v6(dest, interface)
    }
}

/// The events for the test's tunnel devices, saying that IPv6 changes are
/// reported, as they are: the product says so only once full mode exists.
struct Reporting;

const TEST_EVENTS: Watcher = Watcher::new(PREFIX);

impl NetworkEvents for Reporting {
    fn subscribe(&self, watching: &PhysicalNetwork) -> Result<Subscription> {
        TEST_EVENTS.subscribe(watching)
    }

    fn reports_ipv6_changes(&self) -> bool {
        true
    }
}

/// The watched network: `wire`, with only the address it was given.
fn watching(wire: &Veth, own: Ipv4Addr) -> PhysicalNetwork {
    PhysicalNetwork {
        interface: wire.name.clone(),
        next_hop: None,
        own_addresses: vec![own],
        on_link: Vec::new(),
    }
}

/// The next "physical changed" within `wait`, skipping any other event.
fn next_physical(events: &Subscription, wait: Duration) -> Option<NetworkEvent> {
    let started = Instant::now();
    while let Some(left) = wait.checked_sub(started.elapsed()) {
        match events.events().recv_timeout(left).ok()? {
            PHYSICAL => return Some(PHYSICAL),
            _ => continue,
        }
    }
    None
}

// The shared rules on the real kernel: "physical changed" for a new address
// on the watched network and for its link going down and up, never for the
// routes this product adds or removes, full mode's halves included, nor for
// anything on the tunnel or another interface; "IPv6 changed" for an IPv6
// route or address that comes or goes on another interface.
#[test]
fn passes_the_shared_events_check() {
    let test = "passes_the_shared_events_check";
    as_root_in(module_path!(), "events", test, || {
        let wire = Veth::new("uve-wire0");
        let other = Veth::new("uve-other0");
        let tun = Tun::open("uvt-events0");
        let own = Ipv4Addr::new(198, 18, 5, 10);
        ip_ok(&["-4", "addr", "add", "198.18.5.10/24", "dev", &wire.name]);
        // The new links settle before the check starts listening.
        thread::sleep(Duration::from_secs(3));
        say("STEP: check_events");
        let physical = watching(&wire, own);
        suite::check_events(
            &Reporting,
            &WithHalves,
            &OnTestLinks,
            &physical,
            &tun.name,
            &other.name,
        );
    });
}

// Contract: dropping a subscription ends it at once, socket and thread,
// with no change needed to wake it.
#[test]
fn a_dropped_subscription_ends_at_once() {
    let test = "a_dropped_subscription_ends_at_once";
    as_root_in(module_path!(), "events ends", test, || {
        let wire = Veth::new("uve-ends0");
        let physical = watching(&wire, Ipv4Addr::new(198, 18, 5, 20));
        suite::check_subscription_ends(&LinuxEvents, &physical, &events::live);
    });
}

// A change between capturing the network and subscribing is reported, as
// the first event; with no change, nothing is.
#[test]
fn a_change_since_capture_is_reported() {
    let test = "a_change_since_capture_is_reported";
    as_root_in(module_path!(), "events since capture", test, || {
        let wire = Veth::new("uve-cap0");
        ip_ok(&["-4", "addr", "add", "198.18.6.10/24", "dev", &wire.name]);
        thread::sleep(Duration::from_secs(2));
        let captured = LinuxRoutes
            .capture_physical(Ipv4Addr::new(198, 18, 6, 1))
            .expect("capture");
        assert_eq!(captured.interface, wire.name, "captured another interface");

        let unchanged = TEST_EVENTS.subscribe(&captured).expect("subscribe");
        let event = next_physical(&unchanged, Duration::from_secs(3));
        assert_eq!(event, None, "a change was reported when there was none");
        drop(unchanged);

        ip_ok(&["-4", "addr", "add", "198.18.6.11/24", "dev", &wire.name]);
        let changed = TEST_EVENTS.subscribe(&captured).expect("subscribe");
        let first = changed.events().recv_timeout(Duration::from_secs(5)).ok();
        assert_eq!(first, Some(PHYSICAL), "the change since capture was missed");
    });
}

// When notices come faster than they are read, the real kernel says it
// dropped some, and the socket goes on with those it kept: the worker
// reports the loss (see the test of the worker above), never skips it.
#[test]
fn the_kernel_reports_lost_notices() {
    let test = "the_kernel_reports_lost_notices";
    as_root_in(module_path!(), "events overrun", test, || {
        let wire = Veth::new("uve-flood0");
        let index = find(&wire.name).expect("the link").index;
        let flags = EventfdFlags::CLOEXEC | EventfdFlags::NONBLOCK;
        let stop = eventfd(0, flags).expect("an event descriptor");
        // The smallest buffer the kernel allows, and none of it read yet.
        let mut listener = Listener::open(GROUPS, Some(0), stop).expect("listen");
        for n in 1..=64 {
            netlink::add_address(index, Ipv4Addr::new(198, 18, 7, n), 32).expect("add an address");
        }
        let first = listener.wait().expect("wait");
        assert_eq!(first, Wake::Overrun, "the loss was not reported");
        let next = listener.wait().expect("wait");
        assert_eq!(next, Wake::Changed, "the notices kept were not read");
    });
}
