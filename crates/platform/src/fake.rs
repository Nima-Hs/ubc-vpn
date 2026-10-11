//! An in-memory implementation of the seam, for tests and for the service's
//! dev mode. It touches nothing outside the process.
//!
//! A [`Fake`] records every routing and DNS call in order and keeps the state
//! those calls add up to, so a test can assert both. It can be told to fail
//! an operation, it delivers the network events a test injects, and its
//! channel lets a test choose who each caller is.

use std::collections::HashMap;
use std::io::{self, BufReader, Read};
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, MutexGuard};

use ubc_vpn_core::routes::Ipv4Net;

use crate::{
    Connection, Dns, Error, Listener, NetworkEvent, NetworkEvents, Paths, PhysicalNetwork,
    Platform, Result, Routes, SplitDns, Transport, UserId, Verified, encode_line, read_line,
};

/// The interface the fake reports as physical.
pub const PHYSICAL_INTERFACE: &str = "fake-eth0";

/// A routing or DNS operation, as recorded by [`Fake::calls`] and chosen for
/// [`Fake::set_failure`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Op {
    /// [`Routes::capture_physical`].
    CapturePhysical,
    /// [`Routes::add_gateway_route`].
    AddGatewayRoute,
    /// [`Routes::remove_gateway_route`].
    RemoveGatewayRoute,
    /// [`Routes::add_tunnel_routes`].
    AddTunnelRoutes,
    /// [`Routes::remove_tunnel_routes`].
    RemoveTunnelRoutes,
    /// [`Routes::uses_interface`].
    VerifyRoute,
    /// [`Dns::set_split_dns`].
    SetSplitDns,
    /// [`Dns::clear_split_dns`].
    ClearSplitDns,
    /// [`Dns::split_dns_matches`].
    VerifyDns,
}

/// What is applied right now. After a full teardown it equals
/// `Applied::default()`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Applied {
    /// Host routes through the physical network, by destination.
    pub gateway_routes: Vec<(Ipv4Addr, PhysicalNetwork)>,
    /// Routes through a tunnel, by interface name.
    pub tunnel_routes: Vec<(String, Ipv4Net)>,
    /// The split DNS in effect and the interface it is on.
    pub split_dns: Option<(String, SplitDns)>,
}

#[derive(Default)]
struct State {
    calls: Vec<Op>,
    failures: HashMap<Op, Error>,
    applied: Applied,
    subscribers: Vec<Sender<NetworkEvent>>,
    listeners: HashMap<String, Endpoint>,
}

struct Endpoint {
    incoming: Sender<(Box<dyn Connection>, UserId)>,
    owner: Option<UserId>,
}

/// The fake OS. Clones share one state, so a test keeps one and hands the
/// service another.
#[derive(Clone, Default)]
pub struct Fake(Arc<Mutex<State>>);

impl Fake {
    /// A machine with one physical network, no tunnel routes and no split DNS.
    pub fn new() -> Self {
        Self::default()
    }

    /// This fake as a [`Platform`], with files under `root`.
    pub fn platform(&self, root: &Path) -> Platform {
        Platform {
            routes: Arc::new(self.clone()),
            dns: Arc::new(self.clone()),
            events: Arc::new(self.clone()),
            transport: Arc::new(self.clone()),
            paths: paths(root),
        }
    }

    /// Every routing and DNS call so far, in order, including failed ones.
    pub fn calls(&self) -> Vec<Op> {
        self.state().calls.clone()
    }

    /// What is applied right now.
    pub fn applied(&self) -> Applied {
        self.state().applied.clone()
    }

    /// Makes every later `op` fail with `error` and change nothing, or with
    /// `None` work again. A failing check answers [`Verified::Unknown`].
    pub fn set_failure(&self, op: Op, error: Option<Error>) {
        let mut state = self.state();
        match error {
            Some(error) => state.failures.insert(op, error),
            None => state.failures.remove(&op),
        };
    }

    /// Delivers `event` to every subscriber.
    pub fn send_event(&self, event: NetworkEvent) {
        let mut state = self.state();
        state.subscribers.retain(|s| s.send(event).is_ok());
    }

    /// Connects to `name` as `user`. [`Transport::connect`] on the fake
    /// connects as the user `fake-user`.
    pub fn connect_as(&self, name: &str, user: &UserId) -> Result<Box<dyn Connection>> {
        let state = self.state();
        let endpoint = state.listeners.get(name).ok_or(Error::NotFound)?;
        if endpoint.owner.as_ref().is_some_and(|owner| owner != user) {
            return Err(Error::PermissionDenied);
        }
        let (client, server) = pipe_pair();
        let accepted = endpoint.incoming.send((Box::new(server), user.clone()));
        accepted.map_err(|_| Error::NotFound)?;
        Ok(Box::new(client))
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.0.lock().expect("a test panicked while using the fake")
    }

    /// Records `op`, then applies it unless it was told to fail.
    fn run<T>(&self, op: Op, apply: impl FnOnce(&mut Applied) -> T) -> Result<T> {
        let mut state = self.state();
        state.calls.push(op);
        match state.failures.get(&op) {
            Some(error) => Err(error.clone()),
            None => Ok(apply(&mut state.applied)),
        }
    }
}

/// The locations the fake uses: folders under `root`, which nothing creates.
pub fn paths(root: &Path) -> Paths {
    Paths {
        policy_dir: root.join("policy"),
        state_dir: root.join("state"),
        settings_dir: root.join("settings"),
        channel_name: "ubc-vpn-fake".to_string(),
    }
}

impl Routes for Fake {
    fn capture_physical(&self, _gateway: Ipv4Addr) -> Result<PhysicalNetwork> {
        self.run(Op::CapturePhysical, |_| PhysicalNetwork {
            interface: PHYSICAL_INTERFACE.to_string(),
            next_hop: Some(Ipv4Addr::new(192, 168, 0, 1)),
        })
    }

    fn add_gateway_route(&self, gateway: Ipv4Addr, via: &PhysicalNetwork) -> Result<()> {
        self.run(Op::AddGatewayRoute, |applied| {
            applied.gateway_routes.retain(|(dest, _)| *dest != gateway);
            applied.gateway_routes.push((gateway, via.clone()));
        })
    }

    fn remove_gateway_route(&self, gateway: Ipv4Addr, via: &PhysicalNetwork) -> Result<()> {
        self.run(Op::RemoveGatewayRoute, |applied| {
            let routes = &mut applied.gateway_routes;
            routes.retain(|(dest, net)| !(*dest == gateway && net == via));
        })
    }

    fn add_tunnel_routes(&self, tunnel: &str, subnets: &[Ipv4Net]) -> Result<()> {
        self.run(Op::AddTunnelRoutes, |applied| {
            for subnet in subnets {
                let route = (tunnel.to_string(), *subnet);
                if !applied.tunnel_routes.contains(&route) {
                    applied.tunnel_routes.push(route);
                }
            }
        })
    }

    fn remove_tunnel_routes(&self, tunnel: &str, subnets: &[Ipv4Net]) -> Result<()> {
        self.run(Op::RemoveTunnelRoutes, |applied| {
            let routes = &mut applied.tunnel_routes;
            routes.retain(|(name, subnet)| !(name == tunnel && subnets.contains(subnet)));
        })
    }

    /// Picks a route as an OS does: the most specific one wins, so a host
    /// route beats any subnet, and everything else leaves by the physical
    /// interface.
    fn uses_interface(&self, dest: Ipv4Addr, interface: &str) -> Verified {
        let verdict = self.run(Op::VerifyRoute, |applied| {
            let host = applied.gateway_routes.iter().find(|(d, _)| *d == dest);
            let subnets = applied.tunnel_routes.iter();
            let widest = subnets
                .filter(|(_, subnet)| subnet.contains_addr(dest))
                .max_by_key(|(_, subnet)| subnet.prefix_len());
            let used = match (host, widest) {
                (Some((_, physical)), _) => physical.interface(),
                (None, Some((tunnel, _))) => tunnel,
                (None, None) => PHYSICAL_INTERFACE,
            };
            if used == interface {
                Verified::Yes
            } else {
                Verified::No
            }
        });
        verdict.unwrap_or(Verified::Unknown)
    }
}

impl Dns for Fake {
    fn set_split_dns(&self, tunnel: &str, dns: &SplitDns) -> Result<()> {
        self.run(Op::SetSplitDns, |applied| {
            applied.split_dns = Some((tunnel.to_string(), dns.clone()));
        })
    }

    fn clear_split_dns(&self) -> Result<()> {
        self.run(Op::ClearSplitDns, |applied| applied.split_dns = None)
    }

    fn split_dns_matches(&self, tunnel: &str, dns: &SplitDns) -> Verified {
        let verdict = self.run(Op::VerifyDns, |applied| match &applied.split_dns {
            Some((name, set)) if name == tunnel && set == dns => Verified::Yes,
            _ => Verified::No,
        });
        verdict.unwrap_or(Verified::Unknown)
    }
}

impl NetworkEvents for Fake {
    fn subscribe(&self) -> Result<Receiver<NetworkEvent>> {
        let (sender, receiver) = mpsc::channel();
        self.state().subscribers.push(sender);
        Ok(receiver)
    }
}

impl Transport for Fake {
    fn listen(&self, name: &str) -> Result<Box<dyn Listener>> {
        let mut state = self.state();
        if state.listeners.contains_key(name) {
            return Err(Error::AlreadyExists);
        }
        let (incoming, accepted) = mpsc::channel();
        let endpoint = Endpoint {
            incoming,
            owner: None,
        };
        state.listeners.insert(name.to_string(), endpoint);
        Ok(Box::new(FakeListener {
            fake: self.clone(),
            name: name.to_string(),
            accepted: Mutex::new(accepted),
        }))
    }

    fn connect(&self, name: &str) -> Result<Box<dyn Connection>> {
        self.connect_as(name, &"fake-user".parse()?)
    }
}

struct FakeListener {
    fake: Fake,
    name: String,
    accepted: Mutex<Receiver<(Box<dyn Connection>, UserId)>>,
}

impl Listener for FakeListener {
    fn accept(&self) -> Result<(Box<dyn Connection>, UserId)> {
        let accepted = self.accepted.lock().expect("accept panicked");
        accepted
            .recv()
            .map_err(|_| Error::Failed("listener closed".to_string()))
    }

    fn restrict_to(&self, owner: &UserId) -> Result<()> {
        let mut state = self.fake.state();
        let endpoint = state.listeners.get_mut(&self.name).ok_or(Error::NotFound)?;
        endpoint.owner = Some(owner.clone());
        Ok(())
    }
}

impl Drop for FakeListener {
    fn drop(&mut self) {
        self.fake.state().listeners.remove(&self.name);
    }
}

/// One end of an in-process connection: bytes go out on one channel and come
/// in on another, through the same line rules as a real pipe or socket.
struct Pipe {
    outgoing: Sender<Vec<u8>>,
    incoming: Mutex<BufReader<PipeReader>>,
}

struct PipeReader {
    chunks: Receiver<Vec<u8>>,
    pending: Vec<u8>,
}

fn pipe_pair() -> (Pipe, Pipe) {
    let end = |outgoing, chunks| Pipe {
        outgoing,
        incoming: Mutex::new(BufReader::new(PipeReader {
            chunks,
            pending: Vec::new(),
        })),
    };
    let (to_server, from_client) = mpsc::channel();
    let (to_client, from_server) = mpsc::channel();
    (end(to_server, from_server), end(to_client, from_client))
}

impl Read for PipeReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.pending.is_empty() {
            // An error means the peer is gone, which reads as end of stream.
            self.pending = self.chunks.recv().unwrap_or_default();
        }
        let n = out.len().min(self.pending.len());
        out[..n].copy_from_slice(&self.pending[..n]);
        self.pending.drain(..n);
        Ok(n)
    }
}

impl Connection for Pipe {
    fn read_line(&self) -> Result<Option<String>> {
        read_line(&mut *self.incoming.lock().expect("read_line panicked"))
    }

    fn write_line(&self, line: &str) -> Result<()> {
        let sent = self.outgoing.send(encode_line(line)?);
        sent.map_err(|_| Error::Failed("connection closed".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::suite;
    use ubc_vpn_core::protocol::MAX_LINE_BYTES;

    const GATEWAY: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

    fn user(name: &str) -> UserId {
        name.parse().unwrap()
    }

    #[test]
    fn passes_the_shared_suite_and_ends_clean() {
        let fake = Fake::new();
        suite::check_routes(&fake, "fake-tun0");
        suite::check_dns(&fake, "fake-tun0");
        assert_eq!(fake.applied(), Applied::default());
    }

    #[test]
    fn records_calls_in_order_and_the_resulting_state() {
        let fake = Fake::new();
        let subnet: Ipv4Net = "192.0.2.0/24".parse().unwrap();
        let physical = fake.capture_physical(GATEWAY).unwrap();
        fake.add_gateway_route(GATEWAY, &physical).unwrap();
        fake.add_tunnel_routes("fake-tun0", &[subnet, subnet])
            .unwrap();
        assert_eq!(
            fake.calls(),
            [
                Op::CapturePhysical,
                Op::AddGatewayRoute,
                Op::AddTunnelRoutes
            ]
        );
        let applied = fake.applied();
        assert_eq!(applied.gateway_routes, [(GATEWAY, physical)]);
        assert_eq!(applied.tunnel_routes, [("fake-tun0".to_string(), subnet)]);
    }

    #[test]
    fn a_failing_operation_changes_nothing_until_healed() {
        let fake = Fake::new();
        let subnets = ["192.0.2.0/24".parse().unwrap()];
        fake.set_failure(Op::AddTunnelRoutes, Some(Error::PermissionDenied));
        assert_eq!(
            fake.add_tunnel_routes("fake-tun0", &subnets),
            Err(Error::PermissionDenied)
        );
        assert_eq!(fake.applied(), Applied::default());
        assert_eq!(fake.calls(), [Op::AddTunnelRoutes]);
        // Teardown still works after a failed setup.
        assert_eq!(fake.remove_tunnel_routes("fake-tun0", &subnets), Ok(()));
        fake.set_failure(Op::AddTunnelRoutes, None);
        assert_eq!(fake.add_tunnel_routes("fake-tun0", &subnets), Ok(()));
    }

    // Security rule: "could not tell" is its own answer, never a "no" and
    // never a "yes", so the service can fail closed on it.
    #[test]
    fn could_not_determine_is_distinct_from_no() {
        let fake = Fake::new();
        let dns = SplitDns {
            resolvers: vec![Ipv4Addr::new(192, 0, 2, 53)],
            domains: vec!["ece.example".to_string()],
        };
        fake.set_split_dns("fake-tun0", &dns).unwrap();
        assert_eq!(fake.uses_interface(GATEWAY, "fake-tun0"), Verified::No);
        assert_eq!(fake.split_dns_matches("fake-tun0", &dns), Verified::Yes);

        let error = Some(Error::Failed("injected".to_string()));
        fake.set_failure(Op::VerifyRoute, error.clone());
        fake.set_failure(Op::VerifyDns, error);
        let route = fake.uses_interface(GATEWAY, PHYSICAL_INTERFACE);
        assert_eq!(route, Verified::Unknown);
        let dns = fake.split_dns_matches("fake-tun0", &dns);
        assert_eq!(dns, Verified::Unknown);
        assert_ne!(Verified::Unknown, Verified::No);
    }

    #[test]
    fn delivers_injected_events_to_every_subscriber() {
        let fake = Fake::new();
        let (first, second) = (fake.subscribe().unwrap(), fake.subscribe().unwrap());
        drop(fake.subscribe().unwrap());
        fake.send_event(NetworkEvent::PhysicalChanged);
        fake.send_event(NetworkEvent::Sleeping);
        assert_eq!(first.try_recv(), Ok(NetworkEvent::PhysicalChanged));
        assert_eq!(first.try_recv(), Ok(NetworkEvent::Sleeping));
        assert_eq!(second.try_recv(), Ok(NetworkEvent::PhysicalChanged));
    }

    // Security rule: the service learns who is calling from the transport,
    // and once narrowed to an owner nobody else gets a connection at all.
    #[test]
    fn reports_the_caller_and_refuses_others_once_restricted() {
        let fake = Fake::new();
        let listener = fake.listen("svc").unwrap();
        let _mallory = fake.connect_as("svc", &user("mallory")).unwrap();
        assert_eq!(listener.accept().unwrap().1, user("mallory"));

        listener.restrict_to(&user("alice")).unwrap();
        let refused = fake.connect_as("svc", &user("mallory")).err();
        assert_eq!(refused, Some(Error::PermissionDenied));
        assert_eq!(fake.connect("svc").err(), Some(Error::PermissionDenied));
        let _alice = fake.connect_as("svc", &user("alice")).unwrap();
        assert_eq!(listener.accept().unwrap().1, user("alice"));
    }

    // Security rule: the service's name cannot be claimed twice, so another
    // process cannot pose as the service.
    #[test]
    fn a_name_is_claimed_exclusively_until_released() {
        let fake = Fake::new();
        assert_eq!(fake.connect("svc").err(), Some(Error::NotFound));
        let listener = fake.listen("svc").unwrap();
        assert_eq!(fake.listen("svc").err(), Some(Error::AlreadyExists));
        drop(listener);
        assert!(fake.listen("svc").is_ok());
    }

    #[test]
    fn connections_carry_lines_both_ways_and_enforce_the_limit() {
        let fake = Fake::new();
        let listener = fake.listen("svc").unwrap();
        let client = fake.connect("svc").unwrap();
        let (server, _) = listener.accept().unwrap();

        client.write_line("ping").unwrap();
        client.write_line("again").unwrap();
        server.write_line("pong").unwrap();
        assert_eq!(server.read_line(), Ok(Some("ping".to_string())));
        assert_eq!(server.read_line(), Ok(Some("again".to_string())));
        assert_eq!(client.read_line(), Ok(Some("pong".to_string())));

        let too_long = "a".repeat(MAX_LINE_BYTES);
        assert_eq!(client.write_line(&too_long), Err(Error::LineTooLong));
        drop(client);
        assert_eq!(server.read_line(), Ok(None));
        assert!(server.write_line("late").is_err());
    }

    // Security rule: dev mode never shares a file or a channel with the
    // installed product. The check must notice when it would.
    #[test]
    fn the_paths_check_catches_a_collision() {
        let installed = paths(Path::new("installed"));
        let mut dev = paths(Path::new("dev"));
        let collides = |dev: &Paths| {
            let (installed, dev) = (installed.clone(), dev.clone());
            std::panic::catch_unwind(move || suite::check_paths(&installed, &dev)).is_err()
        };
        assert!(collides(&dev), "same channel name");
        dev.channel_name = "ubc-vpn-fake-dev".to_string();
        assert!(!collides(&dev));
        dev.state_dir = installed.policy_dir.join("dev");
        assert!(collides(&dev), "a dev folder inside an installed one");
    }
}
