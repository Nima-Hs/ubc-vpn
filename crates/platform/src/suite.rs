//! Checks every implementation of the seam must pass.
//!
//! The fake passes them in this crate's tests, and each real implementation
//! must pass the same functions. They panic on the first property that does
//! not hold. For a real implementation the routing and DNS checks need admin
//! rights and a live tunnel interface, and the transport check needs a way to
//! connect as a second user; the others need nothing special.
//!
//! They use addresses reserved for documentation (192.0.2.0/24,
//! 198.51.100.0/24, 203.0.113.0/24 and 2001:db8::/32), which no real network
//! routes specially, and the full-mode checks a few public addresses that
//! only the halves may carry.
//!
//! [`check_route_ownership`] and [`check_full_tunnel`] restart with a fresh
//! instance in the same process. That a new process, and a restart of the
//! machine, behave the same is left to each real implementation's own tests.

use std::fmt::Debug;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::thread;
use std::time::{Duration, Instant};

use ubc_vpn_core::protocol::MAX_LINE_BYTES;
use ubc_vpn_core::routes::Ipv4Net;

use crate::{
    Connection, Dns, Error, Ipv6Block, NetworkEvent, NetworkEvents, Paths, PhysicalNetwork, Result,
    Routes, SplitDns, Subscription, Transport, Verified,
};

/// Long enough for another thread to get going, short enough for a test.
const PAUSE: Duration = Duration::from_millis(50);

/// How long a real OS may take to report a change, or to take a new DNS
/// rule in. The fake answers at once, so only a failing check waits this
/// long.
const SETTLE: Duration = Duration::from_secs(20);

/// How long a check listens to be sure no event comes.
const QUIET: Duration = Duration::from_secs(3);

/// Asks `ask` until it answers `wanted` or [`SETTLE`] has passed, and gives
/// the last answer, for the caller to assert on.
fn settled<T: PartialEq + Debug>(wanted: &T, ask: impl Fn() -> T) -> T {
    let started = Instant::now();
    loop {
        let answer = ask();
        if answer == *wanted || started.elapsed() > SETTLE {
            return answer;
        }
        thread::sleep(Duration::from_millis(250));
    }
}

/// Checks [`Routes`] against the interface named `tunnel`, which must exist
/// and must not be the physical one. Leaves no route behind when it passes.
///
/// No route check ever answers [`Verified::Unobservable`], on any OS: every
/// answer here is asserted to be `Yes` or `No`.
pub fn check_routes(routes: &dyn Routes, tunnel: &str) {
    let gateway = Ipv4Addr::new(192, 0, 2, 1);
    let inside = Ipv4Addr::new(192, 0, 2, 77);
    let outside = Ipv4Addr::new(198, 51, 100, 1);
    // The routed subnet contains the gateway, as UBC's does.
    let subnets = [Ipv4Net::new(Ipv4Addr::new(192, 0, 2, 0), 24).expect("valid network")];
    let (yes, no) = (Verified::Yes, Verified::No);

    routes.remove_all().expect("remove all with nothing added");
    let physical = routes.capture_physical(gateway).expect("capture");
    let wire = physical.interface();
    assert_ne!(wire, tunnel, "captured the tunnel");
    let before = routes.uses_interface(inside, wire);
    assert!(matches!(before, Verified::Yes | Verified::No), "{before:?}");

    let add_gateway = || routes.add_gateway_route(gateway, &physical);
    let add_tunnel = || routes.add_tunnel_routes(tunnel, &subnets);
    let remove_gateway = || routes.remove_gateway_route(gateway, &physical);
    let remove_tunnel = || routes.remove_tunnel_routes(tunnel, &subnets);
    let assert_applied = || {
        assert_eq!(routes.uses_interface(inside, tunnel), yes, "inside");
        assert_eq!(routes.uses_interface(outside, tunnel), no, "outside");
        let to_gateway = routes.uses_interface(gateway, wire);
        assert_eq!(to_gateway, yes, "the gateway route did not survive");
        assert_eq!(routes.uses_interface(gateway, tunnel), no);
    };
    let assert_restored = || {
        assert_eq!(routes.uses_interface(inside, tunnel), no);
        let after = routes.uses_interface(inside, wire);
        assert_eq!(after, before, "the previous state was not restored");
    };

    // Removing succeeds with nothing applied.
    remove_tunnel().expect("remove tunnel routes, none there");
    remove_gateway().expect("remove gateway route, none there");

    // Adding succeeds when the route is already there.
    add_gateway().expect("add gateway route");
    add_gateway().expect("add gateway route again");
    add_tunnel().expect("add tunnel routes");
    add_tunnel().expect("add tunnel routes again");
    assert_applied();

    // Removing the tunnel routes leaves the gateway route alone. Adding them
    // back shows it: without that route the gateway would follow the subnet.
    remove_tunnel().expect("remove tunnel routes");
    remove_tunnel().expect("remove tunnel routes again");
    assert_eq!(routes.uses_interface(gateway, wire), yes);
    add_tunnel().expect("add tunnel routes back");
    assert_applied();

    remove_tunnel().expect("remove tunnel routes");
    remove_gateway().expect("remove gateway route");
    remove_gateway().expect("remove gateway route again");
    assert_restored();

    // One call undoes everything, and is safe to repeat.
    add_gateway().expect("add gateway route");
    add_tunnel().expect("add tunnel routes");
    routes.remove_all().expect("remove all");
    routes.remove_all().expect("remove all again");
    assert_restored();
    add_tunnel().expect("add tunnel routes after remove all");
    let to_gateway = routes.uses_interface(gateway, tunnel);
    assert_eq!(to_gateway, yes, "remove_all left the gateway route");
    routes.remove_all().expect("remove all");
}

/// Checks [`Routes::configure_tunnel`] on the device named `tunnel`, which must
/// exist and carry no routes. The address it sets stays until the device
/// goes.
pub fn check_configure_tunnel(routes: &dyn Routes, foreign: &dyn Foreign, tunnel: &str) {
    let address = |n| Ipv4Addr::new(198, 51, 100, n);
    // A reused adapter can keep an address from before; it does not stay.
    foreign.add_address(tunnel, address(99));
    let configure = |n, mtu| routes.configure_tunnel(tunnel, address(n), mtu);
    configure(7, 1300).expect("configure");
    configure(7, 1300).expect("configure again");
    assert_eq!(
        foreign.addresses(tunnel),
        [address(7)],
        "another address stayed"
    );

    // Security rule: the address is a single host. Its neighbours, which a
    // netmask would have put on the tunnel's link, are not routed there.
    for neighbour in [1, 6, 8, 254].map(address) {
        let routed = routes.uses_interface(neighbour, tunnel);
        assert_eq!(routed, Verified::No, "{neighbour} follows the address");
    }

    // A new address replaces the old one.
    configure(8, 1400).expect("configure another address");
    assert_eq!(foreign.addresses(tunnel), [address(8)]);

    // A packet size out of range changes nothing.
    for mtu in [0, 575, 1501, u16::MAX] {
        assert_eq!(configure(9, mtu), Err(Error::InvalidInput), "{mtu}");
    }
    assert_eq!(foreign.addresses(tunnel), [address(8)]);
    for mtu in [576, 1500] {
        configure(8, mtu).expect("a size at the edge of the range");
    }
}

/// What a harness does as somebody other than the product, by the OS's own
/// means: on a real OS, the system's route, address and link tools.
pub trait Foreign {
    /// Adds a route to `net` through the interface named `interface`, by
    /// the interface's usual router when it has one.
    fn add_route(&self, interface: &str, net: Ipv4Net);
    /// Removes it again.
    fn remove_route(&self, interface: &str, net: Ipv4Net);
    /// Gives the interface another IPv4 address.
    fn add_address(&self, interface: &str, address: Ipv4Addr);
    /// The interface's IPv4 addresses, as the OS lists them.
    fn addresses(&self, interface: &str) -> Vec<Ipv4Addr>;
    /// Adds an IPv6 route to `dest`/`prefix_len` through the interface named
    /// `interface`, with no next hop.
    fn add_route_v6(&self, interface: &str, dest: Ipv6Addr, prefix_len: u8);
    /// Removes it again. Succeeds when it is not there.
    fn remove_route_v6(&self, interface: &str, dest: Ipv6Addr, prefix_len: u8);
    /// Gives the interface a global IPv6 address, usable at once.
    fn add_address_v6(&self, interface: &str, address: Ipv6Addr);
    /// Removes it again.
    fn remove_address_v6(&self, interface: &str, address: Ipv6Addr);
    /// Takes the interface's link down, as a pulled cable does, or brings it
    /// up again. The interface stays, with its settings.
    fn set_link(&self, interface: &str, up: bool);
    /// Turns IPv6 off for the interface, as an administrator would, or on
    /// again. While it is off the interface takes no IPv6 route.
    fn bind_ipv6(&self, interface: &str, on: bool);
}

/// Checks that the product removes only routes it added, in this run or after
/// a restart. `restarted` makes a fresh instance, as the service gets when it
/// starts again after a crash; `foreign` adds routes as somebody else.
/// Leaves no route behind when it passes.
pub fn check_route_ownership(
    routes: &dyn Routes,
    restarted: &dyn Fn() -> Box<dyn Routes>,
    foreign: &dyn Foreign,
    tunnel: &str,
) {
    let net = |a, b, c| Ipv4Net::new(Ipv4Addr::new(a, b, c, 0), 24).expect("valid network");
    let (theirs, ours) = (net(198, 51, 100), net(192, 0, 2));
    let (in_theirs, in_ours) = (Ipv4Addr::new(198, 51, 100, 9), Ipv4Addr::new(192, 0, 2, 9));
    let (yes, no) = (Verified::Yes, Verified::No);
    let gateway = Ipv4Addr::new(203, 0, 113, 1);

    routes.remove_all().expect("remove all with nothing added");
    let physical = routes.capture_physical(gateway).expect("capture");
    let wire = physical.interface().to_string();
    foreign.add_route(tunnel, theirs);
    assert_eq!(
        routes.uses_interface(in_theirs, tunnel),
        yes,
        "the harness added nothing"
    );

    // Adding a route that is already there succeeds and does not make it ours.
    routes
        .add_tunnel_routes(tunnel, &[theirs, ours])
        .expect("add over theirs");
    routes
        .remove_tunnel_routes(tunnel, &[theirs, ours])
        .expect("remove");
    assert_eq!(
        routes.uses_interface(in_theirs, tunnel),
        yes,
        "removed somebody else's route"
    );
    assert_eq!(routes.uses_interface(in_ours, tunnel), no, "ours stayed");

    // After a restart, removing everything removes only what was ours.
    routes
        .add_tunnel_routes(tunnel, &[theirs, ours])
        .expect("add again");
    restarted()
        .remove_all()
        .expect("remove all after a restart");
    assert_eq!(
        routes.uses_interface(in_theirs, tunnel),
        yes,
        "remove_all took theirs"
    );
    assert_eq!(
        routes.uses_interface(in_ours, tunnel),
        no,
        "remove_all left ours"
    );

    foreign.remove_route(tunnel, theirs);
    routes.remove_all().expect("remove all");

    // A route to the same destination through another interface is not
    // replaced, and the add says so.
    let elsewhere = net(198, 18, 0);
    foreign.add_route(&wire, elsewhere);
    let refused = routes.add_tunnel_routes(tunnel, &[elsewhere]);
    assert_eq!(refused, Err(Error::AlreadyExists), "replaced a route");
    let kept = routes.uses_interface(Ipv4Addr::new(198, 18, 0, 9), &wire);
    assert_eq!(kept, yes, "the route through the other interface went");
    foreign.remove_route(&wire, elsewhere);

    // A host route to the gateway through another interface: the gateway
    // route is refused and that one stays.
    let elsewhere = Ipv4Net::new(gateway, 32).expect("valid network");
    foreign.add_route(tunnel, elsewhere);
    let refused = routes.add_gateway_route(gateway, &physical);
    assert_eq!(
        refused,
        Err(Error::AlreadyExists),
        "replaced a gateway route"
    );
    let kept = routes.uses_interface(gateway, tunnel);
    assert_eq!(kept, yes, "the gateway route through the tunnel went");
    foreign.remove_route(tunnel, elsewhere);

    // The same for the gateway's host route. Somebody else's sends the
    // gateway out of a subnet that is otherwise tunnelled; while it is there,
    // the gateway still leaves by the physical interface.
    let gateway_host = Ipv4Net::new(gateway, 32).expect("valid network");
    foreign.add_route(tunnel, net(203, 0, 113));
    foreign.add_route(&wire, gateway_host);
    let via_wire = || routes.uses_interface(gateway, &wire);
    assert_eq!(via_wire(), yes, "the harness added nothing");
    routes
        .add_gateway_route(gateway, &physical)
        .expect("add over theirs");
    routes
        .remove_gateway_route(gateway, &physical)
        .expect("remove");
    assert_eq!(via_wire(), yes, "removed somebody else's gateway route");
    routes
        .add_gateway_route(gateway, &physical)
        .expect("add again");
    restarted()
        .remove_all()
        .expect("remove all after a restart");
    assert_eq!(via_wire(), yes, "remove_all took their gateway route");

    foreign.remove_route(&wire, gateway_host);
    foreign.remove_route(tunnel, net(203, 0, 113));
    routes.remove_all().expect("remove all");
}

/// Passes for split DNS that is in effect as far as the OS shows: `Yes`, or
/// `Unobservable` where the OS cannot show what its resolver took in. `No`
/// and `Unknown` fail.
pub(crate) fn assert_in_effect(verdict: Verified, what: &str) {
    let in_effect = matches!(verdict, Verified::Yes | Verified::Unobservable);
    assert!(in_effect, "{what} is not in effect: {verdict:?}");
}

/// Checks that dropping a [`Subscription`] ends it at once: before the drop
/// returns, and without any event to wake it. `live` tells how many
/// subscriptions the OS still has registered; the harness supplies it.
pub fn check_subscription_ends(
    events: &dyn NetworkEvents,
    watching: &PhysicalNetwork,
    live: &dyn Fn() -> usize,
) {
    let before = live();
    let subscriptions = [(); 3].map(|()| events.subscribe(watching).expect("subscribe"));
    assert_eq!(live(), before + 3, "a subscription was not registered");
    let mut left = subscriptions.into_iter();
    for dropped in 0..3 {
        let subscription = left.next().expect("three subscriptions");
        // On a thread of its own, so a drop that hangs fails the check
        // instead of stalling it.
        let (done, finished) = std::sync::mpsc::channel();
        thread::spawn(move || {
            drop(subscription);
            let _ = done.send(());
        });
        let ended = finished.recv_timeout(Duration::from_secs(2)).is_ok();
        let registered = live();
        if !ended || registered != before + 2 - dropped {
            // Dropping these while the check unwinds could hang it as well,
            // so they are left as they are.
            left.by_ref().for_each(std::mem::forget);
        }
        assert!(ended, "dropping a subscription did not return");
        assert_eq!(
            registered,
            before + 2 - dropped,
            "dropping left it registered"
        );
    }
}

/// Checks [`Dns`] against the interface named `tunnel`, which must exist.
/// Leaves no split DNS behind when it passes.
///
/// `resolvers_for` asks the OS which resolvers a lookup of a name would go to
/// now. The harness supplies it, because each OS shows that its own way.
pub fn check_dns(dns: &dyn Dns, tunnel: &str, resolvers_for: &dyn Fn(&str) -> Vec<Ipv4Addr>) {
    let first = SplitDns {
        resolvers: vec![Ipv4Addr::new(192, 0, 2, 53)],
        domains: vec!["suite.example".to_string()],
    };
    let other_resolvers = SplitDns {
        resolvers: vec![Ipv4Addr::new(192, 0, 2, 54)],
        ..first.clone()
    };
    let other_domains = SplitDns {
        domains: vec!["other.example".to_string()],
        ..first.clone()
    };
    let more_domains = SplitDns {
        domains: vec!["suite.example".to_string(), "other.example".to_string()],
        ..first.clone()
    };
    let second = SplitDns {
        resolvers: other_resolvers.resolvers.clone(),
        domains: more_domains.domains.clone(),
    };
    let no = Verified::No;

    dns.clear_split_dns().expect("clear when nothing is set");
    assert_eq!(dns.split_dns_matches(&first), no);

    // Names that are not chosen: unrelated, a parent, and one that only ends
    // in the same letters.
    let others = ["other.example", "example", "notsuite.example"];
    let usual = others.map(resolvers_for);

    // A match is exact: the same resolvers and the same domains, no more.
    dns.set_split_dns(tunnel, &first).expect("set");
    // Security rule: only the chosen domain and the names under it change.
    for chosen in ["suite.example", "host.suite.example"] {
        assert_eq!(resolvers_for(chosen), first.resolvers, "{chosen}");
    }
    assert_eq!(others.map(resolvers_for), usual, "another name changed");
    assert_in_effect(dns.split_dns_matches(&first), "the setting");
    assert_eq!(dns.split_dns_matches(&other_resolvers), no, "resolvers");
    assert_eq!(dns.split_dns_matches(&other_domains), no, "domains");
    assert_eq!(dns.split_dns_matches(&more_domains), no, "more domains");
    assert_eq!(dns.split_dns_matches(&second), no);

    // Setting replaces: nothing of the first setting stays in effect.
    dns.set_split_dns(tunnel, &second).expect("set another");
    assert_eq!(dns.split_dns_matches(&first), no, "the old setting stayed");
    assert_in_effect(dns.split_dns_matches(&second), "the new setting");

    dns.clear_split_dns().expect("clear");
    dns.clear_split_dns().expect("clear twice");
    assert_eq!(dns.split_dns_matches(&second), no);
    assert_eq!(others.map(resolvers_for), usual);
}

/// Checks full mode's catch-all DNS beside split DNS. The harness is as for
/// [`check_dns`], and `resolvers_for` must also tell 192.0.2.54 apart, which
/// the catch-all uses. `theirs` adds (`true`) or removes (`false`) a
/// catch-all that is not the product's, as another VPN's would be: on
/// Windows a local name-resolution rule for `.`, on Linux `~.` with the
/// default-route flag on another link, on macOS a supplemental resolver
/// entry matching every name. Leaves nothing set when it passes.
pub fn check_catch_all_dns(
    dns: &dyn Dns,
    tunnel: &str,
    resolvers_for: &dyn Fn(&str) -> Vec<Ipv4Addr>,
    theirs: &dyn Fn(bool),
) {
    let (split_resolver, catch_all) = (Ipv4Addr::new(192, 0, 2, 53), Ipv4Addr::new(192, 0, 2, 54));
    let chosen = SplitDns {
        resolvers: vec![split_resolver],
        domains: vec!["suite.example".to_string()],
    };
    let (split_name, other_name) = ("host.suite.example", "anything.example");
    let no = Verified::No;

    dns.clear_split_dns().expect("clear when nothing is set");
    assert_eq!(
        dns.foreign_catch_all(),
        Ok(false),
        "a catch-all to begin with"
    );
    let usual = resolvers_for(other_name);
    assert!(!usual.contains(&catch_all), "{usual:?}");

    // Names under the split domain still go to the split resolver, every
    // other name to the catch-all's.
    dns.set_split_dns(tunnel, &chosen).expect("set split DNS");
    dns.set_catch_all_dns(&[catch_all])
        .expect("set the catch-all");
    dns.set_catch_all_dns(&[catch_all])
        .expect("set the catch-all again");
    let split = settled(&vec![split_resolver], || resolvers_for(split_name));
    let other = settled(&vec![catch_all], || resolvers_for(other_name));
    assert_eq!(split, [split_resolver], "the catch-all took a split name");
    assert_eq!(other, [catch_all], "the catch-all took no other name");
    assert_in_effect(dns.catch_all_dns_matches(&[catch_all]), "the catch-all");
    let wrong = dns.catch_all_dns_matches(&[split_resolver]);
    assert_eq!(wrong, no, "other resolvers matched");
    assert_in_effect(dns.split_dns_matches(&chosen), "split DNS beside it");
    assert_eq!(dns.foreign_catch_all(), Ok(false), "ours counted as theirs");

    // Somebody else's catch-all is reported and not fought: ours is not in
    // effect while it is there, and cannot be set again over it. It does not
    // take the split names.
    theirs(true);
    let foreign = dns.foreign_catch_all();
    let matches = dns.catch_all_dns_matches(&[catch_all]);
    let split = dns.split_dns_matches(&chosen);
    let cleared = dns.clear_catch_all_dns();
    let set = dns.set_catch_all_dns(&[catch_all]);
    theirs(false);
    assert_eq!(foreign, Ok(true), "their catch-all was not seen");
    assert_eq!(matches, no, "ours counted as in effect beside theirs");
    assert_in_effect(split, "split DNS beside their catch-all");
    assert_eq!(cleared, Ok(()));
    assert_eq!(set, Err(Error::AlreadyExists), "set over theirs");
    assert_eq!(dns.foreign_catch_all(), Ok(false));
    let left = dns.catch_all_dns_matches(&[catch_all]);
    assert_eq!(left, no, "a refused catch-all was set");

    // Clearing the catch-all keeps the split DNS.
    dns.set_catch_all_dns(&[catch_all])
        .expect("set the catch-all once theirs is gone");
    dns.clear_catch_all_dns().expect("clear the catch-all");
    dns.clear_catch_all_dns()
        .expect("clear the catch-all again");
    assert_eq!(dns.catch_all_dns_matches(&[catch_all]), no);
    assert_in_effect(dns.split_dns_matches(&chosen), "split DNS after it");
    let other = settled(&usual, || resolvers_for(other_name));
    assert_eq!(other, usual, "other names did not go back");
    assert_eq!(resolvers_for(split_name), [split_resolver]);

    // Clearing the split DNS removes both.
    dns.set_catch_all_dns(&[catch_all])
        .expect("set the catch-all again");
    dns.clear_split_dns().expect("clear split DNS");
    assert_eq!(dns.catch_all_dns_matches(&[catch_all]), no, "it stayed");
    assert_eq!(dns.split_dns_matches(&chosen), no);
    let other = settled(&usual, || resolvers_for(other_name));
    assert_eq!(other, usual, "other names did not go back");
}

/// The address the full-mode checks expect the halves to carry.
fn ip(text: &str) -> IpAddr {
    text.parse().expect("an address")
}

/// Whether `routes` would take `dest`, of either family, through
/// `interface`.
fn through(routes: &dyn Routes, dest: IpAddr, interface: &str) -> Verified {
    match dest {
        IpAddr::V4(dest) => routes.uses_interface(dest, interface),
        IpAddr::V6(dest) => routes.uses_interface_v6(dest, interface),
    }
}

/// Checks full mode on the device named `tunnel`, which must be configured,
/// take IPv6 routes, and carry no routes. `other` names another interface,
/// which also takes IPv6 routes, where the harness puts somebody else's
/// routes. Apart from `other`'s, the machine must have no IPv6 leak path of
/// its own (see [`Routes::full_tunnel_ipv6`]), and its router, if it has
/// one, must be on its local network. `restarted` makes a fresh instance,
/// as for [`check_route_ownership`]. Leaves no route behind when it passes.
///
/// While the halves are in place every connection of the machine goes to the
/// tunnel, so each step keeps them for as short a time as it can and
/// asserts once they are gone.
pub fn check_full_tunnel(
    routes: &dyn Routes,
    restarted: &dyn Fn() -> Box<dyn Routes>,
    foreign: &dyn Foreign,
    tunnel: &str,
    other: &str,
) {
    let gateway = Ipv4Addr::new(192, 0, 2, 1);
    let (yes, no) = (Verified::Yes, Verified::No);
    // Addresses in each of the four halves.
    let anywhere = ["1.1.1.1", "200.1.1.1", "2001:db8::1", "a000::1"].map(ip);

    routes.remove_all().expect("remove all with nothing added");
    let physical = routes.capture_physical(gateway).expect("capture");
    let wire = physical.interface().to_string();
    assert!(physical.router_is_on_link(), "{physical:?}");
    // The router, and a neighbour on its network: the last address but one,
    // neither the router nor the broadcast.
    let mut local = vec![IpAddr::V4(gateway)];
    if let Some(router) = physical.next_hop() {
        let network = physical.on_link().iter().find(|n| n.contains_addr(router));
        let network = network.expect("the router's network");
        let size = 1u32 << (32 - u32::from(network.prefix_len()));
        let neighbour = Ipv4Addr::from(u32::from(network.addr()) + size - 2);
        local.extend([IpAddr::V4(router), IpAddr::V4(neighbour)]);
    }
    routes
        .add_gateway_route(gateway, &physical)
        .expect("add gateway route");
    assert_eq!(routes.foreign_full_tunnel(tunnel), Ok(false), "before");
    assert_eq!(routes.full_tunnel_ipv6(tunnel), Ok(Ipv6Block::Blocked));

    // The halves take every IPv4 address and block every IPv6 one, while
    // the gateway, the router and the local network stay on the physical
    // network. Added again, nothing changes; they are not somebody else's,
    // but they are to any other interface.
    let added = routes.add_full_tunnel(tunnel);
    let taken = anywhere.map(|dest| through(routes, dest, tunnel));
    let kept: Vec<_> = local.iter().map(|d| through(routes, *d, &wire)).collect();
    let again = routes.add_full_tunnel(tunnel);
    let ours = routes.foreign_full_tunnel(tunnel);
    let elsewhere = routes.foreign_full_tunnel(other);
    let removed = routes.remove_full_tunnel(tunnel);
    assert_eq!(added, Ok(Ipv6Block::Blocked), "add");
    assert_eq!(removed, Ok(()), "remove");
    assert_eq!(taken, [yes; 4], "a half did not take {anywhere:?}");
    assert_eq!(kept, vec![yes; local.len()], "{local:?} left the wire");
    assert_eq!(again, Ok(Ipv6Block::Blocked), "add again");
    assert_eq!(ours, Ok(false), "our own halves counted as foreign");
    assert_eq!(elsewhere, Ok(true), "our halves, seen from another tunnel");
    let left = anywhere.map(|dest| through(routes, dest, tunnel));
    assert_eq!(left, [no; 4], "a half stayed");
    routes
        .remove_full_tunnel(tunnel)
        .expect("remove with nothing there");
    // The gateway route is not a half, and stays.
    assert_eq!(routes.uses_interface(gateway, &wire), yes, "the gateway");

    // After a restart, removing everything removes the halves too.
    routes.add_full_tunnel(tunnel).expect("add the halves");
    let cleared = restarted().remove_all();
    let left = anywhere.map(|dest| through(routes, dest, tunnel));
    assert_eq!(cleared, Ok(()), "remove all after a restart");
    assert_eq!(left, [no; 4], "remove_all left a half");

    // Somebody else's half, such as another VPN's, is theirs: the read-only
    // check reports it, full mode does not fight it, and it stays.
    let theirs_v4: Ipv4Net = "128.0.0.0/1".parse().expect("a network");
    let (theirs_v6, in_theirs_v6) = (Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0), anywhere[3]);
    for v4 in [true, false] {
        match v4 {
            true => foreign.add_route(other, theirs_v4),
            false => foreign.add_route_v6(other, theirs_v6, 1),
        }
        let reported = routes.foreign_full_tunnel(tunnel);
        let refused = routes.add_full_tunnel(tunnel);
        let kept = through(routes, if v4 { anywhere[1] } else { in_theirs_v6 }, other);
        match v4 {
            true => foreign.remove_route(other, theirs_v4),
            false => foreign.remove_route_v6(other, theirs_v6, 1),
        }
        routes.remove_full_tunnel(tunnel).expect("remove");
        assert_eq!(reported, Ok(true), "their half was not seen, v4 {v4}");
        assert_eq!(refused, Err(Error::AlreadyExists), "v4 {v4}");
        assert_eq!(kept, yes, "their half was replaced, v4 {v4}");
    }

    // Security rule: with no IPv6 on the tunnel the IPv6 halves cannot be
    // added. Then full mode is refused, with nothing added, when IPv6 could
    // leave by another interface; and goes on without them when it could
    // not.
    foreign.bind_ipv6(tunnel, false);
    let nothing = routes.full_tunnel_ipv6(tunnel);
    let leak = Ipv6Addr::new(0x2001, 0xdb8, 0x1, 0, 0, 0, 0, 0);
    foreign.add_route_v6(other, leak, 48);
    let decided = routes.full_tunnel_ipv6(tunnel);
    let refused = routes.add_full_tunnel(tunnel);
    let added = routes.uses_interface(Ipv4Addr::new(1, 1, 1, 1), tunnel);
    foreign.remove_route_v6(other, leak, 48);
    let without = routes.add_full_tunnel(tunnel);
    let taken = anywhere.map(|dest| through(routes, dest, tunnel));
    routes.remove_full_tunnel(tunnel).expect("remove");
    foreign.bind_ipv6(tunnel, true);
    let back_on = settled(&Ok(Ipv6Block::Blocked), || routes.full_tunnel_ipv6(tunnel));
    assert_eq!(nothing, Ok(Ipv6Block::NothingToBlock), "the machine leaks");
    assert_eq!(decided, Err(Error::Unsupported), "a leak path was not seen");
    assert_eq!(refused, Err(Error::Unsupported), "full mode with a leak");
    assert_eq!(added, no, "a half was added before the refusal");
    assert_eq!(without, Ok(Ipv6Block::NothingToBlock));
    assert_eq!(taken, [yes, yes, no, no], "only the IPv4 halves");
    assert_eq!(back_on, Ok(Ipv6Block::Blocked), "IPv6 back on");

    routes.remove_all().expect("remove all");
}

/// Checks a change of routes and split DNS on a live connection (#194):
/// some tunnel routes go while the others stay, and split DNS is set again
/// with other domains. `tunnel` must be configured and carry no routes, and
/// `resolvers_for` is as for [`check_dns`]. Leaves no route and no split DNS
/// behind when it passes.
pub fn check_live_route_change(
    routes: &dyn Routes,
    dns: &dyn Dns,
    tunnel: &str,
    resolvers_for: &dyn Fn(&str) -> Vec<Ipv4Addr>,
) {
    let net = |a, b, c, d, len| Ipv4Net::new(Ipv4Addr::new(a, b, c, d), len).expect("a network");
    let (kept, dropped) = (
        [net(198, 51, 100, 0, 25), net(203, 0, 113, 0, 24)],
        net(198, 51, 100, 128, 25),
    );
    let all = [kept[0], dropped, kept[1]];
    let inside = |n: &Ipv4Net| Ipv4Addr::from(u32::from(n.addr()) + 9);
    // The gateway is inside a kept subnet, as UBC's is.
    let gateway = Ipv4Addr::new(203, 0, 113, 1);
    let resolver = Ipv4Addr::new(192, 0, 2, 53);
    let before = SplitDns {
        resolvers: vec![resolver],
        domains: vec!["suite.example".to_string()],
    };
    let after = SplitDns {
        domains: vec!["other.example".to_string()],
        ..before.clone()
    };
    let (yes, no) = (Verified::Yes, Verified::No);

    routes.remove_all().expect("remove all with nothing added");
    dns.clear_split_dns().expect("clear when nothing is set");
    let usual = ["host.suite.example", "host.other.example"].map(resolvers_for);
    let physical = routes.capture_physical(gateway).expect("capture");
    let wire = physical.interface().to_string();

    // Connected.
    routes
        .add_gateway_route(gateway, &physical)
        .expect("add gateway route");
    routes.add_tunnel_routes(tunnel, &all).expect("add routes");
    dns.set_split_dns(tunnel, &before).expect("set split DNS");
    for subnet in &all {
        let routed = routes.uses_interface(inside(subnet), tunnel);
        assert_eq!(routed, yes, "{subnet} before the change");
    }
    assert_in_effect(dns.split_dns_matches(&before), "split DNS before");

    // The change: one subnet goes, and the domains are replaced.
    routes
        .remove_tunnel_routes(tunnel, &[dropped])
        .expect("remove one subnet");
    dns.set_split_dns(tunnel, &after)
        .expect("set split DNS again");

    let dropped_now = routes.uses_interface(inside(&dropped), tunnel);
    assert_eq!(dropped_now, no, "the dropped subnet still goes through");
    for subnet in &kept {
        let routed = routes.uses_interface(inside(subnet), tunnel);
        assert_eq!(routed, yes, "{subnet}, kept, no longer goes through");
    }
    let to_gateway = routes.uses_interface(gateway, &wire);
    assert_eq!(to_gateway, yes, "the gateway route did not survive");
    assert_in_effect(dns.split_dns_matches(&after), "split DNS after");
    assert_eq!(dns.split_dns_matches(&before), no, "the old domains stayed");
    let new_name = settled(&vec![resolver], || resolvers_for("host.other.example"));
    assert_eq!(new_name, [resolver], "the new domain");
    let old_name = settled(&usual[0], || resolvers_for("host.suite.example"));
    assert_eq!(old_name, usual[0], "the old domain still goes to the VPN");

    // Disconnected.
    routes
        .remove_tunnel_routes(tunnel, &kept)
        .expect("remove the rest");
    routes
        .remove_gateway_route(gateway, &physical)
        .expect("remove gateway route");
    dns.clear_split_dns().expect("clear");
    for subnet in &all {
        assert_eq!(routes.uses_interface(inside(subnet), tunnel), no);
    }
    let names = ["host.suite.example", "host.other.example"];
    assert_eq!(names.map(resolvers_for), usual, "a name stayed changed");
    routes.remove_all().expect("remove all");
}

/// The next event within `wait` that is `wanted`, skipping any other, which
/// a change may bring as well, harmlessly.
fn next_of(events: &Subscription, wanted: NetworkEvent, wait: Duration) -> Option<NetworkEvent> {
    let started = Instant::now();
    while let Some(left) = wait.checked_sub(started.elapsed()) {
        match events.events().recv_timeout(left).ok()? {
            event if event == wanted => return Some(event),
            _ => continue,
        }
    }
    None
}

/// Takes every event that is waiting or comes soon, so that the next step
/// starts from quiet.
fn drain(events: &Subscription) {
    while events
        .events()
        .recv_timeout(Duration::from_millis(500))
        .is_ok()
    {}
}

/// Checks which changes a [`Subscription`] reports. `watching` is the
/// network watched: an interface that is up, which the harness may change
/// freely, such as a test adapter standing in for the physical network.
/// `tunnel` must exist and carry no routes, and take IPv6 routes. `other` is
/// a third interface where somebody else's IPv6 routes and addresses come
/// and go. Leaves no route behind, and the watched link up, when it passes.
pub fn check_events(
    events: &dyn NetworkEvents,
    routes: &dyn Routes,
    foreign: &dyn Foreign,
    watching: &PhysicalNetwork,
    tunnel: &str,
    other: &str,
) {
    let wire = watching.interface();
    let (physical, ipv6) = (NetworkEvent::PhysicalChanged, NetworkEvent::Ipv6Changed);
    assert!(
        events.reports_ipv6_changes(),
        "IPv6 changes are not watched"
    );
    let subscription = events.subscribe(watching).expect("subscribe");
    drain(&subscription);

    // Everything a connection does: none of it is a change to the network.
    let gateway = Ipv4Addr::new(192, 0, 2, 1);
    routes
        .configure_tunnel(tunnel, Ipv4Addr::new(198, 18, 0, 2), 1300)
        .expect("configure the tunnel");
    routes
        .add_gateway_route(gateway, watching)
        .expect("add gateway route");
    let subnets = [Ipv4Net::new(Ipv4Addr::new(198, 51, 100, 0), 24).expect("a network")];
    routes
        .add_tunnel_routes(tunnel, &subnets)
        .expect("add tunnel routes");
    // Full mode's halves, the IPv6 ones too, are our own routes.
    let full = routes.add_full_tunnel(tunnel);
    routes.remove_all().expect("remove all");
    assert_eq!(full, Ok(Ipv6Block::Blocked));
    let event = subscription.events().recv_timeout(QUIET).ok();
    assert_eq!(event, None, "an event for our own routes or the tunnel");

    // A new address on the watched network is a change.
    foreign.add_address(wire, Ipv4Addr::new(203, 0, 113, 11));
    let event = next_of(&subscription, physical, SETTLE);
    assert_eq!(event, Some(physical), "a new address was not reported");
    drain(&subscription);

    // Security rule: a new way out for IPv6, on any interface but the
    // tunnel, is reported, so that in full mode the service decides again
    // whether IPv6 can leak. Here a global route appears and goes, then a
    // global address does.
    let route = Ipv6Addr::new(0x2001, 0xdb8, 0x2, 0, 0, 0, 0, 0);
    foreign.add_route_v6(other, route, 48);
    let added = next_of(&subscription, ipv6, SETTLE);
    drain(&subscription);
    foreign.remove_route_v6(other, route, 48);
    let removed = next_of(&subscription, ipv6, SETTLE);
    drain(&subscription);
    assert_eq!(added, Some(ipv6), "an IPv6 route appeared");
    assert_eq!(removed, Some(ipv6), "an IPv6 route went");
    let address = Ipv6Addr::new(0x2001, 0xdb8, 0x3, 0, 0, 0, 0, 0x10);
    foreign.add_address_v6(other, address);
    let added = next_of(&subscription, ipv6, SETTLE);
    drain(&subscription);
    foreign.remove_address_v6(other, address);
    let removed = next_of(&subscription, ipv6, SETTLE);
    drain(&subscription);
    assert_eq!(added, Some(ipv6), "an IPv6 address appeared");
    assert_eq!(removed, Some(ipv6), "an IPv6 address went");

    // The watched link going down is a change, and so is it coming back.
    foreign.set_link(wire, false);
    let down = next_of(&subscription, physical, SETTLE);
    drain(&subscription);
    foreign.set_link(wire, true);
    let up = next_of(&subscription, physical, SETTLE);
    assert_eq!(down, Some(physical), "the link going down");
    assert_eq!(up, Some(physical), "the link coming up");
}

/// Checks [`Transport`], using the channel `name`, which nothing may hold.
///
/// `as_another_user` connects to the given name as a real user other than the
/// one running the check. The harness supplies it, because only it knows how
/// on its OS: the fake does it directly, a real one with a helper process.
pub fn check_transport(
    transport: &dyn Transport,
    name: &str,
    as_another_user: &dyn Fn(&str) -> Result<Connection>,
) {
    let refused = |error| assert_eq!(transport.connect(name).err(), Some(error));

    // The name is claimed exclusively.
    refused(Error::NotFound);
    let listener = transport.listen(name).expect("listen");
    let second = transport.listen(name).err();
    assert_eq!(second, Some(Error::AlreadyExists), "the name was shared");

    // The listener learns who is calling, and tells callers apart.
    let pair = || {
        let client = transport.connect(name).expect("connect");
        let (server, caller) = listener.accept().expect("accept");
        (client, server, caller)
    };
    let (client, server, me) = pair();
    let _other = as_another_user(name).expect("connect as another user");
    let (_, other) = listener.accept().expect("accept another user");
    assert_ne!(other, me, "two users were reported as one");

    // Lines travel both ways, up to the limit. The reader runs on its own
    // thread: a real pipe stops taking bytes nobody reads.
    let longest = "a".repeat(MAX_LINE_BYTES - 1);
    thread::scope(|scope| {
        let reader = scope.spawn(|| [server.read_line(), server.read_line()]);
        client.write_line("ping").expect("write");
        client.write_line(&longest).expect("write the longest line");
        let read = reader.join().expect("reader");
        assert_eq!(read, [Ok(Some("ping".to_string())), Ok(Some(longest))]);
    });
    server.write_line("pong").expect("write back");
    assert_eq!(client.read_line(), Ok(Some("pong".to_string())));

    // A line over the limit is refused, and so is everything after it.
    let oversized = [vec![b'a'; MAX_LINE_BYTES], b"{\"smuggled\":1}\n".to_vec()].concat();
    thread::scope(|scope| {
        scope.spawn(|| client.raw().write_all(&oversized));
        assert_eq!(server.read_line(), Err(Error::LineTooLong));
        assert_eq!(server.read_line(), Err(Error::LineTooLong));
        server.close();
    });

    // A silent peer cannot hold a reader for ever, and what it had sent of a
    // line is not lost.
    let (client, server, _) = pair();
    server.set_read_timeout(Some(PAUSE)).expect("set timeout");
    client.raw().write_all(b"half a ").expect("write half");
    assert_eq!(server.read_line(), Err(Error::TimedOut));
    client.write_line("line").expect("write the rest");
    assert_eq!(server.read_line(), Ok(Some("half a line".to_string())));

    // Closing ends a read waiting on another thread, and the peer sees it.
    server.set_read_timeout(None).expect("clear timeout");
    thread::scope(|scope| {
        let reader = scope.spawn(|| server.read_line());
        thread::sleep(PAUSE);
        server.close();
        assert_eq!(reader.join().expect("reader"), Err(Error::Closed));
    });
    assert_eq!(client.read_line(), Ok(None));

    // Narrowing refuses everyone but the owner, and still admits the owner.
    listener.restrict_to(&me).expect("restrict to the owner");
    let stranger = as_another_user(name).err();
    assert_eq!(stranger, Some(Error::PermissionDenied), "not narrowed");
    let (_client, _server, caller) = pair();
    assert_eq!(caller, me);

    // Closing ends an accept waiting on another thread and frees the name.
    thread::scope(|scope| {
        let waiting = scope.spawn(|| listener.accept().err());
        thread::sleep(PAUSE);
        listener.close();
        assert_eq!(waiting.join().expect("accept"), Some(Error::Closed));
    });
    listener.close();
    refused(Error::NotFound);
    let again = transport.listen(name).expect("listen after release");
    drop(again);
    refused(Error::NotFound);
}

/// Checks that dev mode can never collide with the installed product: a
/// different channel name, and no folder of one at or under a folder of the
/// other.
pub fn check_paths(installed: &Paths, dev: &Paths) {
    assert_ne!(installed.channel_name, dev.channel_name);
    let dirs = |p: &Paths| [&p.policy_dir, &p.state_dir, &p.settings_dir].map(Clone::clone);
    for dev_dir in dirs(dev) {
        for installed_dir in dirs(installed) {
            let nested = dev_dir.starts_with(&installed_dir) || installed_dir.starts_with(&dev_dir);
            assert!(!nested, "{dev_dir:?} and {installed_dir:?} overlap");
        }
    }
}
