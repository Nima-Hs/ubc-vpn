//! Checks every implementation of the seam must pass.
//!
//! The fake passes them in this crate's tests, and each real implementation
//! must pass the same functions. They panic on the first property that does
//! not hold. For a real implementation the routing and DNS checks need admin
//! rights and a live tunnel interface, and the transport check needs a way to
//! connect as a second user; the others need nothing special.
//!
//! They use addresses reserved for documentation (192.0.2.0/24 and
//! 198.51.100.0/24), which no real network routes specially.
//!
//! [`check_route_ownership`] restarts with a fresh instance in the same
//! process. That a new process, and a restart of the machine, behave the same
//! is left to each real implementation's own tests.

use std::net::Ipv4Addr;
use std::thread;
use std::time::{Duration, Instant};

use ubc_vpn_core::protocol::MAX_LINE_BYTES;
use ubc_vpn_core::routes::Ipv4Net;

use crate::{
    Connection, Dns, Error, NetworkEvents, Paths, PhysicalNetwork, Result, Routes, SplitDns,
    Transport, Verified,
};

/// Long enough for another thread to get going, short enough for a test.
const PAUSE: Duration = Duration::from_millis(50);

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
/// means: on a real OS, the system's route and address tools.
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
    for (dropped, subscription) in subscriptions.into_iter().enumerate() {
        let started = Instant::now();
        drop(subscription);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "dropping waited"
        );
        assert_eq!(live(), before + 2 - dropped, "dropping left it registered");
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
