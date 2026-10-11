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
//! Not checked here, and so required of each real implementation's own tests:
//! that [`Routes::remove_all`], called from a new process, removes what an
//! earlier process added and spares every route this product did not add.

use std::net::Ipv4Addr;
use std::thread;
use std::time::Duration;

use ubc_vpn_core::protocol::MAX_LINE_BYTES;
use ubc_vpn_core::routes::Ipv4Net;

use crate::{Connection, Dns, Error, Paths, Result, Routes, SplitDns, Transport, Verified};

/// Long enough for another thread to get going, short enough for a test.
const PAUSE: Duration = Duration::from_millis(50);

/// Checks [`Routes`] against the interface named `tunnel`, which must exist
/// and must not be the physical one. Leaves no route behind when it passes.
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

/// Checks [`Dns`] against the interface named `tunnel`, which must exist.
/// Leaves no split DNS behind when it passes.
pub fn check_dns(dns: &dyn Dns, tunnel: &str) {
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
    let (yes, no) = (Verified::Yes, Verified::No);

    dns.clear_split_dns().expect("clear when nothing is set");
    assert_eq!(dns.split_dns_matches(&first), no);

    // A match is exact: the same resolvers and the same domains, no more.
    dns.set_split_dns(tunnel, &first).expect("set");
    assert_eq!(dns.split_dns_matches(&first), yes);
    assert_eq!(dns.split_dns_matches(&other_resolvers), no, "resolvers");
    assert_eq!(dns.split_dns_matches(&other_domains), no, "domains");
    assert_eq!(dns.split_dns_matches(&more_domains), no, "more domains");
    assert_eq!(dns.split_dns_matches(&second), no);

    // Setting replaces: nothing of the first setting stays in effect.
    dns.set_split_dns(tunnel, &second).expect("set another");
    assert_eq!(dns.split_dns_matches(&first), no, "the old setting stayed");
    assert_eq!(dns.split_dns_matches(&second), yes);

    dns.clear_split_dns().expect("clear");
    dns.clear_split_dns().expect("clear twice");
    assert_eq!(dns.split_dns_matches(&second), no);
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
