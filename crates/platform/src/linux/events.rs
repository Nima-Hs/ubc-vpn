//! Network change notifications on Linux, from route netlink.
//!
//! A subscription opens a socket on the kernel's notice groups for links,
//! IPv4 and IPv6 addresses, and IPv4 and IPv6 routes, and only then looks at
//! the network for the first time, so a change after that look waits in the
//! socket and is not missed. A notice only wakes a worker thread. The worker
//! reads every notice waiting, then lists the links, addresses and routes
//! again and compares what matters with what it saw last:
//!
//! - `PhysicalChanged` when what the connection relies on, as Windows
//!   compares it, changes: the watched interface is gone or replaced, or its
//!   link stops working (see below for how long); its IPv4 addresses change;
//!   or the routers of its IPv4 default routes, in any table, change. A
//!   route's metric, and any other route through the interface, do not
//!   count: the gateway's own route keeps the tunnel working whatever
//!   somebody else does to them, and a metric is what NetworkManager lowers
//!   after a failed connectivity check.
//! - `Ipv6Changed` when an IPv6 route or address changes on any interface.
//!
//! An address's flags and lifetimes do not count either, so an address
//! growing old (deprecated) or renewed sends nothing.
//!
//! A link that stops working is reported only if it still differs after
//! [`SETTLE`]: a roam between Wi-Fi access points drops the carrier for a
//! moment, which on Windows keeps the connection, so it does here too
//! (`consistency.md`). Once the settle ends, a fresh look is compared with
//! the last one reported: the same interface back with the same addresses
//! and routers sends nothing, anything else is reported. A link that comes
//! back with a different network is reported as soon as it does. IPv6
//! changes are never held back.
//!
//! Neither counts the product's own routes, which carry
//! [`LINUX_ROUTE_PROTOCOL`]: the gateway's route, the tunnel's routes and
//! full mode's halves. Nor does either count anything on the tunnel, whose
//! name starts with [`TUN_PREFIX`]. IPv6 also leaves out link-local,
//! multicast and loopback routes and addresses, and the copies of routes the
//! kernel makes for itself. Since lists are compared, a notice that changes
//! nothing that matters sends nothing.
//!
//! The first look is compared with the captured [`PhysicalNetwork`], so a
//! change between capture and subscribe is reported too.
//!
//! When notices come faster than they are read, the kernel drops some and
//! says so (`ENOBUFS`). What changed is then unknown, so the worker sends
//! both `PhysicalChanged` and `Ipv6Changed`, and takes a fresh look as its
//! new starting point. A look that fails sends both too. Any other error on
//! the socket sends both and ends the subscription's events.
//!
//! Sleep and wake are not sent, which the contract allows (G11). The only
//! source of them on Linux is logind's `PrepareForSleep` signal on D-Bus,
//! which the service does not link, so it would take a `busctl monitor`
//! process. A process started while a connect is under way could inherit
//! the tunnel device's descriptors before they are sealed (issue #305), so
//! none is started. A resume shows up anyway as link and address changes.
//!
//! Dropping the [`Subscription`] wakes the worker through an event
//! descriptor and waits for it to end, which closes the socket.
//!
//! Full mode is not written yet, so [`NetworkEvents::reports_ipv6_changes`]
//! still answers `false`, although `Ipv6Changed` is sent.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Sender};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use rustix::event::{EventfdFlags, PollFd, PollFlags, Timespec, eventfd, poll};
use rustix::io::Errno;
use rustix::net::RecvFlags;

use super::dns::TUN_PREFIX;
use super::netlink::{
    self, AF_INET, AF_INET6, AF_UNSPEC, Address, Link, RTM_F_CLONED, RTN_UNICAST, Route,
};
use super::routes::{is_ours, os};
#[cfg(doc)]
use crate::LINUX_ROUTE_PROTOCOL;
use crate::{NetworkEvent, NetworkEvents, PhysicalNetwork, Result, Subscription};

/// The notice groups a subscription listens to: links, IPv4 and IPv6
/// addresses, and IPv4 and IPv6 routes.
pub(super) const GROUPS: u32 = netlink::GROUP_LINK
    | netlink::GROUP_IPV4_ADDRESS
    | netlink::GROUP_IPV4_ROUTE
    | netlink::GROUP_IPV6_ADDRESS
    | netlink::GROUP_IPV6_ROUTE;

/// What is sent when what changed is unknown.
const BOTH: [NetworkEvent; 2] = [NetworkEvent::PhysicalChanged, NetworkEvent::Ipv6Changed];

/// Room for any one notice.
const BUFFER: usize = 1 << 16;

/// An IPv6 route as compared: its table, destination and prefix length,
/// interface, next hop, metric, kind, and whether it has several next hops.
pub(super) type RouteKey = (
    u32,
    IpAddr,
    u8,
    Option<u32>,
    Option<IpAddr>,
    Option<u32>,
    u8,
    bool,
);

fn key(route: &Route) -> RouteKey {
    (
        route.table,
        route.dst,
        route.dst_len,
        route.oif,
        route.gateway,
        route.priority,
        route.kind,
        route.multipath,
    )
}

/// What a connection relies on about the watched interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Physical {
    /// Its number, and whether it is up and its link works. `None` when no
    /// interface has its name.
    pub(super) link: Option<(u32, bool)>,
    pub(super) addresses: Vec<Ipv4Addr>,
    /// The routers of its IPv4 default routes that are not the product's,
    /// in any table: the unspecified address for one straight onto the link.
    pub(super) routers: Vec<Ipv4Addr>,
}

impl Physical {
    /// The interface is there and its link works.
    fn working(&self) -> bool {
        self.link.is_some_and(|(_, running)| running)
    }
}

/// What a subscription compares from one look to the next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct State {
    pub(super) physical: Physical,
    /// The IPv6 routes that count, on every interface but the tunnel.
    pub(super) ipv6_routes: Vec<RouteKey>,
    /// The IPv6 addresses that count, by interface number and prefix length.
    pub(super) ipv6_addresses: Vec<(u32, Ipv6Addr, u8)>,
}

/// Whether an IPv6 address or destination counts: not link-local,
/// multicast or loopback.
fn counts(addr: Ipv6Addr) -> bool {
    !(addr.is_loopback() || addr.is_multicast() || addr.is_unicast_link_local())
}

fn sorted<T: Ord>(mut list: Vec<T>) -> Vec<T> {
    list.sort();
    list.dedup();
    list
}

/// What matters, from the links, addresses and routes listed: about the
/// interface named `watched`, and about IPv6 on every interface but those
/// whose names start with `tunnel_prefix`.
pub(super) fn state(
    watched: &str,
    tunnel_prefix: &str,
    links: &[Link],
    addresses: &[Address],
    routes: &[Route],
) -> State {
    let link = links.iter().find(|link| link.name == watched);
    let index = link.map(|link| link.index);
    let tunnels: Vec<u32> = links
        .iter()
        .filter(|link| link.name.starts_with(tunnel_prefix))
        .map(|link| link.index)
        .collect();
    let on_tunnel = |oif: Option<u32>| oif.is_some_and(|oif| tunnels.contains(&oif));
    let own = addresses
        .iter()
        .filter(|row| Some(row.index) == index)
        .filter_map(Address::v4);
    let routers = routes
        .iter()
        .filter(|route| route.family == AF_INET && route.dst_len == 0 && route.kind == RTN_UNICAST)
        .filter(|route| index.is_some() && route.oif == index && !is_ours(route))
        .map(|route| match route.gateway {
            Some(IpAddr::V4(router)) => router,
            _ => Ipv4Addr::UNSPECIFIED,
        });
    let ipv6_routes = routes
        .iter()
        .filter(|route| route.family == AF_INET6 && !is_ours(route) && !on_tunnel(route.oif))
        .filter(|route| route.flags & RTM_F_CLONED == 0)
        .filter(|route| matches!(route.dst, IpAddr::V6(dst) if counts(dst)));
    let ipv6_addresses = addresses
        .iter()
        .filter(|row| row.family == AF_INET6 && !tunnels.contains(&row.index))
        .filter_map(|row| match row.local {
            IpAddr::V6(addr) if counts(addr) => Some((row.index, addr, row.prefix_len)),
            _ => None,
        });
    State {
        physical: Physical {
            link: link.map(|link| (link.index, link.running())),
            addresses: sorted(own.collect()),
            routers: sorted(routers.collect()),
        },
        ipv6_routes: sorted(ipv6_routes.map(key).collect()),
        ipv6_addresses: sorted(ipv6_addresses.collect()),
    }
}

/// Lists the network as it is now and picks out what matters.
fn look(watched: &str, tunnel_prefix: &str) -> io::Result<State> {
    let links = netlink::links()?;
    let mut addresses = netlink::addresses(AF_INET)?;
    match netlink::addresses(AF_INET6) {
        Ok(v6) => addresses.extend(v6),
        // No IPv6 at all: none of it to count.
        Err(error) if error.raw_os_error() == Some(libc::EAFNOSUPPORT) => {}
        Err(error) => return Err(error),
    }
    let routes = netlink::routes(AF_UNSPEC)?;
    Ok(state(watched, tunnel_prefix, &links, &addresses, &routes))
}

/// Whether the interface as it is now no longer matches what was captured:
/// gone or not working, an address the capture did not have, or no default
/// route by the captured next hop. (The capture lists the addresses of
/// every interface, so an address that has gone from this one is noticed
/// only from the subscription's own first look onwards.)
pub(super) fn differs_from_capture(now: &Physical, captured: &PhysicalNetwork) -> bool {
    let new_address = now
        .addresses
        .iter()
        .any(|addr| !captured.own_addresses.contains(addr));
    let hop_gone = captured
        .next_hop
        .is_some_and(|hop| !now.routers.contains(&hop));
    !now.working() || new_address || hop_gone
}

/// The events for a change from `before` to `now`, with no settle.
#[cfg(test)]
pub(super) fn changes(before: &State, now: &State) -> Vec<NetworkEvent> {
    let mut events = Vec::new();
    if before.physical != now.physical {
        events.push(NetworkEvent::PhysicalChanged);
    }
    let ipv6 = |state: &State| (state.ipv6_routes.clone(), state.ipv6_addresses.clone());
    if ipv6(before) != ipv6(now) {
        events.push(NetworkEvent::Ipv6Changed);
    }
    events
}

/// The events for `now`, compared with `last`, which becomes what was
/// reported. A watched link that stopped working, and is still the same
/// interface, is held back until `deadline`, which this sets to `settle`
/// from now the first time; it is reported only if it still differs then.
fn compare(
    last: &mut State,
    now: State,
    deadline: &mut Option<Instant>,
    settle: Duration,
) -> Vec<NetworkEvent> {
    let mut events = Vec::new();
    let ipv6 = |state: &State| (state.ipv6_routes.clone(), state.ipv6_addresses.clone());
    if ipv6(last) != ipv6(&now) {
        events.push(NetworkEvent::Ipv6Changed);
        last.ipv6_routes = now.ipv6_routes;
        last.ipv6_addresses = now.ipv6_addresses;
    }
    if now.physical == last.physical {
        // Back as it was, if it had gone: nothing to report.
        *deadline = None;
        return events;
    }
    let same = now.physical.link.map(|(index, _)| index) == last.physical.link.map(|l| l.0);
    let stopped = last.physical.working() && now.physical.link.is_some() && !now.physical.working();
    if same && stopped {
        match *deadline {
            None => {
                *deadline = Some(Instant::now() + settle);
                return events;
            }
            Some(until) if Instant::now() < until => return events,
            Some(_) => {}
        }
    }
    *deadline = None;
    last.physical = now.physical;
    events.insert(0, NetworkEvent::PhysicalChanged);
    events
}

/// How long a watched link that stopped working has to come back as it was
/// before that is reported: longer than a roam between Wi-Fi access points
/// takes.
pub(super) const SETTLE: Duration = Duration::from_secs(2);

/// Why the worker woke.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Wake {
    /// Notices came: something may have changed.
    Changed,
    /// The kernel dropped notices that did not fit.
    Overrun,
    /// The time given ran out.
    Timeout,
    /// The subscription was dropped.
    Stop,
}

/// Where the worker waits, for at most `timeout` when given.
pub(super) trait Source {
    fn wait(&mut self, timeout: Option<Duration>) -> io::Result<Wake>;
}

/// A socket on the notice groups, and the event descriptor that says stop.
pub(super) struct Listener {
    socket: OwnedFd,
    stop: OwnedFd,
    buffer: Vec<u8>,
}

impl Listener {
    /// Listens to `groups`, holding about `buffer` bytes of notices not yet
    /// read when given (see [`netlink::listen`]). `stop` becoming readable
    /// ends the wait.
    pub(super) fn open(groups: u32, buffer: Option<usize>, stop: OwnedFd) -> io::Result<Self> {
        let socket = netlink::listen(groups, buffer)?;
        LIVE.fetch_add(1, Ordering::SeqCst);
        Ok(Self {
            socket,
            stop,
            buffer: vec![0; BUFFER],
        })
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        LIVE.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Source for Listener {
    /// Waits for notices, or to be stopped, and reads every notice waiting.
    /// Their content is not needed: the worker looks for itself.
    fn wait(&mut self, timeout: Option<Duration>) -> io::Result<Wake> {
        let until = timeout.map(|timeout| Instant::now() + timeout);
        loop {
            let left = until.map(|until| until.saturating_duration_since(Instant::now()));
            let left = left.map(Timespec::try_from).transpose();
            let left = left.map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
            let (ready, stopped) = {
                let mut fds = [
                    PollFd::new(&self.socket, PollFlags::IN),
                    PollFd::new(&self.stop, PollFlags::IN),
                ];
                match poll(&mut fds, left.as_ref()) {
                    Ok(0) if until.is_some() => return Ok(Wake::Timeout),
                    Ok(_) => {}
                    Err(Errno::INTR) => continue,
                    Err(error) => return Err(error.into()),
                }
                (!fds[0].revents().is_empty(), !fds[1].revents().is_empty())
            };
            if stopped {
                return Ok(Wake::Stop);
            }
            if !ready {
                continue;
            }
            let mut read = false;
            loop {
                match rustix::net::recv(&self.socket, &mut self.buffer[..], RecvFlags::DONTWAIT) {
                    Ok(_) => read = true,
                    Err(Errno::NOBUFS) => return Ok(Wake::Overrun),
                    Err(Errno::INTR) => {}
                    Err(Errno::AGAIN) => break,
                    Err(error) => return Err(error.into()),
                }
            }
            if read {
                return Ok(Wake::Changed);
            }
        }
    }
}

/// The worker: waits on `source`, looks again with `look` after every
/// wake, and sends what changed since `last` (see [`compare`], with
/// `settle`), until stopped or nobody listens.
pub(super) fn watch(
    source: &mut dyn Source,
    look: &dyn Fn() -> io::Result<State>,
    mut last: State,
    settle: Duration,
    events: &Sender<NetworkEvent>,
) {
    // When a watched link that stopped working is reported unless it is
    // back as it was.
    let mut deadline = None;
    loop {
        let timeout =
            deadline.map(|until: Instant| until.saturating_duration_since(Instant::now()));
        let sent = match source.wait(timeout) {
            Ok(Wake::Stop) => return,
            Ok(Wake::Changed | Wake::Timeout) => match look() {
                Ok(now) => compare(&mut last, now, &mut deadline, settle),
                // Could not look: say so the safe way.
                Err(_) => {
                    deadline = None;
                    BOTH.to_vec()
                }
            },
            // Notices were lost, so anything may have changed: say so, and
            // start again from how things are now.
            Ok(Wake::Overrun) => {
                deadline = None;
                if let Ok(now) = look() {
                    last = now;
                }
                BOTH.to_vec()
            }
            // Nothing more can be heard: say so, and end.
            Err(_) => {
                let _ = BOTH.iter().try_for_each(|event| events.send(*event));
                return;
            }
        };
        if sent.into_iter().any(|event| events.send(event).is_err()) {
            return;
        }
    }
}

/// Network events for the tunnel devices whose names start with a prefix.
/// Tests give their own devices' prefix.
pub(super) struct Watcher {
    tunnel_prefix: &'static str,
}

impl Watcher {
    pub(super) const fn new(tunnel_prefix: &'static str) -> Self {
        Self { tunnel_prefix }
    }
}

impl NetworkEvents for Watcher {
    fn subscribe(&self, watching: &PhysicalNetwork) -> Result<Subscription> {
        let flags = EventfdFlags::CLOEXEC | EventfdFlags::NONBLOCK;
        let stop = eventfd(0, flags).map_err(|error| os(error.into()))?;
        // Listening first: a change after the first look then waits in the
        // socket.
        let mut listener =
            Listener::open(GROUPS, None, stop.try_clone().map_err(os)?).map_err(os)?;
        let (watched, prefix) = (watching.interface.clone(), self.tunnel_prefix);
        let look = move || look(&watched, prefix);
        let last = look().map_err(os)?;
        let (events, receiver) = mpsc::channel();
        if differs_from_capture(&last.physical, watching) {
            let _ = events.send(NetworkEvent::PhysicalChanged);
        }
        let worker = std::thread::Builder::new()
            .name("network events".into())
            .spawn(move || watch(&mut listener, &look, last, SETTLE, &events))
            .map_err(os)?;
        let ending = Ending {
            stop,
            worker: Some(worker),
        };
        Ok(Subscription::new(receiver, ending))
    }

    fn reports_ipv6_changes(&self) -> bool {
        false
    }
}

/// What dropping a [`Subscription`] ends: it tells the worker to stop and
/// waits for it, which closes its socket.
struct Ending {
    stop: OwnedFd,
    worker: Option<JoinHandle<()>>,
}

impl Drop for Ending {
    fn drop(&mut self) {
        // An event descriptor stays readable once written to.
        let _ = rustix::io::write(&self.stop, &1u64.to_ne_bytes());
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

/// Linux network events, for the product's tunnel devices.
pub(super) struct LinuxEvents;

const PRODUCT: Watcher = Watcher::new(TUN_PREFIX);

impl NetworkEvents for LinuxEvents {
    fn subscribe(&self, watching: &PhysicalNetwork) -> Result<Subscription> {
        PRODUCT.subscribe(watching)
    }

    fn reports_ipv6_changes(&self) -> bool {
        PRODUCT.reports_ipv6_changes()
    }
}

/// How many subscriptions have a socket open right now.
static LIVE: AtomicUsize = AtomicUsize::new(0);

/// How many subscriptions have a socket open now, for tests.
#[cfg(test)]
pub(super) fn live() -> usize {
    LIVE.load(Ordering::SeqCst)
}
