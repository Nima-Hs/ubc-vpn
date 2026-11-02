//! Routes, DNS and network events: what the OS does with traffic, and what
//! it reports about the machine's network.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::mpsc::Receiver;

use ubc_vpn_core::routes::Ipv4Net;

#[cfg(doc)]
use crate::Error;
use crate::{Result, Verified};

/// The network the machine uses without the tunnel: an interface and the next
/// hop on it, with the machine's own addresses and the networks it is
/// directly on.
///
/// Only [`Routes::capture_physical`] produces one. There is deliberately no
/// other way to build it and no way to store it: the caller captures it before
/// the tunnel exists and passes the same value back for the life of the
/// connection.
///
/// It is a snapshot. Nothing in it follows the machine afterwards: when the
/// network changes, [`NetworkEvent::PhysicalChanged`] says so and the value
/// is no longer valid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhysicalNetwork {
    pub(crate) interface: String,
    pub(crate) next_hop: Option<Ipv4Addr>,
    pub(crate) own_addresses: Vec<Ipv4Addr>,
    pub(crate) on_link: Vec<Ipv4Net>,
}

impl PhysicalNetwork {
    /// The interface, as the token this OS knows it by: a name. It is only
    /// good for passing back to this crate, which looks the interface up
    /// again on every call.
    pub fn interface(&self) -> &str {
        &self.interface
    }

    /// The router traffic is handed to, or `None` when destinations are
    /// reached directly on the link.
    pub fn next_hop(&self) -> Option<Ipv4Addr> {
        self.next_hop
    }

    /// Every IPv4 address the machine had at capture, on any interface,
    /// used or not, such as a disconnected adapter's tentative one. No
    /// tunnel of ours existed then, so none of them is the tunnel's.
    ///
    /// Unlike [`on_link`](Self::on_link), unused addresses are kept: every
    /// use of this list refuses something that matches it (the gateway or
    /// the tunnel's address being one of the machine's own) or notices an
    /// address it lacks (a change of network), and an address that could
    /// become usable later must still count for those.
    pub fn own_addresses(&self) -> &[Ipv4Addr] {
        &self.own_addresses
    }

    /// The networks the machine was directly on at capture: for every
    /// interface that is up, the network of each address it uses, which is
    /// the address with its prefix and the host bits cleared. An address
    /// still being checked for duplicates, a duplicate one, or any address
    /// on an interface that is down is not used and has no on-link route,
    /// so it puts the machine on no network: a disconnected adapter's
    /// tentative `169.254.x.x` address is not counted. Like the rest of this
    /// value it is a snapshot: an address listed at capture that becomes
    /// usable later is not added, and that change alone raises no
    /// [`NetworkEvent::PhysicalChanged`]. Its new on-link route still wins
    /// over full mode's halves. Interfaces that are
    /// not hardware count, such as a bridge made by a container or virtual
    /// machine program. The service refuses routes that would take one of
    /// these into the tunnel; the rule is
    /// [`check_against_local`](ubc_vpn_core::routes::check_against_local).
    pub fn on_link(&self) -> &[Ipv4Net] {
        &self.on_link
    }

    /// Whether the router stays reachable directly while every other address
    /// goes through the tunnel, as full mode needs: there is no router, or
    /// it is inside one of the [`on_link`](Self::on_link) networks, whose
    /// routes are more specific than the halves
    /// [`Routes::add_full_tunnel`] adds. A router outside all of them (a
    /// `/32` or point-to-point address, or a router a DHCP classless route
    /// names) would itself be routed into the tunnel, so full mode must be
    /// refused on such a network.
    pub fn router_is_on_link(&self) -> bool {
        match self.next_hop {
            None => true,
            Some(router) => self.on_link.iter().any(|net| net.contains_addr(router)),
        }
    }
}

/// What full mode does about IPv6: see [`Routes::full_tunnel_ipv6`] and
/// [`Routes::add_full_tunnel`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipv6Block {
    /// The IPv6 halves go through the tunnel, which has no IPv6 address:
    /// every IPv6 connection that no more specific route takes elsewhere
    /// (such as the local network's own link-local and on-link prefixes)
    /// fails at once, and programs fall back to IPv4.
    Blocked,
    /// The tunnel device has no IPv6 at all, so the IPv6 halves cannot be
    /// added; and there is no IPv6 leak path (see
    /// [`Routes::full_tunnel_ipv6`]), so there is no IPv6 to block. Nothing
    /// can leak, as of when it was read. This is not a refusal: the caller
    /// goes on, and checks again at every [`NetworkEvent::Ipv6Changed`].
    NothingToBlock,
}

/// The four routes of full mode: the two halves of IPv4 and the two halves of
/// IPv6. Each is more specific than any default route, so together they take
/// every address a default route would, without touching one.
pub const FULL_TUNNEL_V4: [&str; 2] = ["0.0.0.0/1", "128.0.0.0/1"];

/// See [`FULL_TUNNEL_V4`].
pub const FULL_TUNNEL_V6: [&str; 2] = ["::/1", "8000::/1"];

/// The routing table and the tunnel device's address. IPv4 only, with one
/// exception: IPv6 is left as it is, and nothing here adds an IPv6 address
/// or route, nor may let the OS add one on our behalf, except the two
/// blocking halves [`FULL_TUNNEL_V6`] that [`Routes::add_full_tunnel`] adds
/// on the tunnel in full mode, which block IPv6 rather than carry it.
///
/// # Which routes are ours
///
/// Every operation that removes a route removes only routes this product
/// added.
///
/// Adding is exclusive: an `add_*` creates a route, and never replaces or
/// changes one that is there. Two routes are identical when they have the
/// same destination, the same interface and the same next hop. When an
/// identical route is already there the add succeeds, but that route is not
/// ours, and every later removal leaves it alone. When a route to the same
/// destination is there through another interface or next hop, the add
/// fails with [`Error::AlreadyExists`] and changes nothing: traffic would
/// go where the caller did not ask.
///
/// So that [`Routes::remove_all`] can tell after a crash, from a new process,
/// an implementation marks or records each route **when it adds it**:
///
/// - **Linux** gives its routes the route protocol number
///   [`LINUX_ROUTE_PROTOCOL`], one the system's tables do not list, and
///   removes exactly the routes that carry it. No journal is needed. The
///   number never changes, so a later version finds an earlier one's routes.
/// - **macOS** writes the exact route to a journal in the state folder, which
///   only an administrator can write, and also sets a route flag. It removes
///   a route only when it matches a journal row and carries the flag.
/// - **Windows** has nothing to mark a route with. It writes the exact route
///   to the same kind of journal and removes only exact matches. Windows
///   keeps routes to one destination through two interfaces side by side and
///   refuses only an identical one, so the implementation reads the table
///   before each add to return [`Error::AlreadyExists`].
///
/// A journal row is written **before** the route is added, so a crash between
/// the two leaves a row without a route and never a route without a row. If
/// the OS then reports that the route already existed, the row is withdrawn:
/// that route was there first and must not become ours. The journal records
/// the time the machine was started, and rows from another start are
/// discarded without removing anything: routes do not outlive a restart, and
/// an identical one found later is somebody else's.
///
/// Full mode's IPv6 halves are journalled like the rest, in rows of their
/// own. A version from before full mode cannot read those rows, so a
/// downgrade in the same boot as a full-mode connection would find its
/// journal unreadable and refuse to remove anything. That is accepted
/// before the first release; later, the journal's form must say which rows
/// a version may skip.
///
/// One case is accepted: a crash between writing a row and adding the route,
/// followed in the same boot by somebody else adding the identical route,
/// lets [`Routes::remove_all`] remove that route. It needs the same
/// destination, interface and next hop, within one boot, after a crash.
///
/// The same can happen without a crash: Windows removes a route through an
/// interface when that interface disconnects, but the row stays. If somebody
/// else then adds the identical route in the same boot, [`Routes::remove_all`]
/// removes theirs. This is accepted too.
///
/// The `tunnel` and `interface` arguments are names, as an OS-defined token.
/// An implementation resolves the name on every call and, where it is told
/// the name is the tunnel, checks that the device it finds is one.
pub trait Routes: Send + Sync {
    /// Records how the OS reaches `gateway` right now, together with the
    /// machine's own addresses and on-link networks. Call it once, before
    /// the tunnel device exists: called later it could describe the tunnel,
    /// so an implementation may refuse when it can tell.
    fn capture_physical(&self, gateway: Ipv4Addr) -> Result<PhysicalNetwork>;

    /// Gives the tunnel device named `tunnel` its address and its largest
    /// packet size, and brings it up. The VPN engine creates the device and
    /// sets nothing on it.
    ///
    /// The address is set as a single host, never with the netmask the
    /// gateway assigned: an OS routes a whole on-link network to the device
    /// it is configured on, which would send a subnet the user did not
    /// choose into the tunnel. Only [`Routes::add_tunnel_routes`] decides
    /// what the tunnel carries.
    ///
    /// Where the OS would give a device an IPv6 address of its own accord
    /// when it comes up, the implementation turns that off first.
    ///
    /// The device ends up with this one IPv4 address and no other: any other
    /// IPv4 address it has, such as one left on a reused adapter, is
    /// removed.
    ///
    /// The packet size must be in [`TUNNEL_MTU`], 576 to 1500; anything else
    /// fails with [`Error::InvalidInput`] and changes nothing.
    ///
    /// Succeeds when the device already has this address and size. Fails
    /// with [`Error::NotFound`] when there is no such device. There is no
    /// operation to undo it: the address goes when the engine closes the
    /// device.
    fn configure_tunnel(&self, tunnel: &str, address: Ipv4Addr, mtu: u16) -> Result<()>;

    /// Routes the one address `gateway` through the physical network, so
    /// traffic to the gateway never enters its own tunnel. An exclusive add,
    /// as "Which routes are ours" says: it succeeds over an identical route
    /// and fails with [`Error::AlreadyExists`] over a different one.
    fn add_gateway_route(&self, gateway: Ipv4Addr, via: &PhysicalNetwork) -> Result<()>;

    /// Removes that route if this product added it. Succeeds if it is not
    /// there, and when the physical interface no longer exists.
    fn remove_gateway_route(&self, gateway: Ipv4Addr, via: &PhysicalNetwork) -> Result<()>;

    /// Routes `subnets` through the interface named `tunnel`. Never disturbs a
    /// gateway route, even when a subnet contains the gateway. Exclusive adds,
    /// as "Which routes are ours" says. On error some may have been added:
    /// remove them.
    fn add_tunnel_routes(&self, tunnel: &str, subnets: &[Ipv4Net]) -> Result<()>;

    /// Removes those of the routes that this product added, and nothing else;
    /// a gateway route stays. Succeeds for any that are not there, and when
    /// the interface no longer exists.
    fn remove_tunnel_routes(&self, tunnel: &str, subnets: &[Ipv4Net]) -> Result<()>;

    /// Removes every route this product added, in this run or an earlier one,
    /// and no other. Succeeds when there are none. The service calls it at
    /// start-up and as the last step of every teardown.
    fn remove_all(&self) -> Result<()>;

    /// Asks the OS which interface it would really use to reach `dest`, and
    /// whether that is `interface`.
    ///
    /// It judges the routing table, not passing state: the answer must not
    /// change with whether a neighbour on the local network answered lately.
    /// On Windows it is therefore the forwarding table's choice (longest
    /// prefix, then lowest route plus interface metric, on interfaces that
    /// are up), not the OS's best-route lookup, which skips an on-link route
    /// for a neighbour the cache marks unreachable and falls back to a less
    /// specific route such as a half of full mode. There, equally good
    /// routes through `interface` and elsewhere are `Unknown`.
    ///
    /// It fails closed: `Unknown` when the table, or any route in it, cannot
    /// be read.
    fn uses_interface(&self, dest: Ipv4Addr, interface: &str) -> Verified;

    /// What full mode can do about IPv6 on this machine now, read-only, for
    /// the service to refuse before it changes anything, as with
    /// [`Routes::foreign_full_tunnel`]:
    ///
    /// - [`Ipv6Block::Blocked`]: the tunnel device takes IPv6 routes, so the
    ///   IPv6 halves can block IPv6.
    /// - [`Ipv6Block::NothingToBlock`]: the tunnel device has no IPv6 (on
    ///   Windows, IPv6 is not bound to the adapter), and there is no IPv6
    ///   leak path, so there is nothing to block.
    /// - `Err(`[`Error::Unsupported`]`)`, a refusal: the tunnel device has no
    ///   IPv6, and there is an IPv6 leak path that could not be blocked.
    ///
    /// **An IPv6 leak path** is any unicast IPv6 route on an interface other
    /// than the tunnel, whether that interface is up or down (a down one may
    /// come up), except `fe80::/10` (link-local), `::1/128` (loopback) and
    /// `ff00::/8` (multicast). Teredo's `2001::/32` counts like any other.
    ///
    /// [`Ipv6Block::NothingToBlock`] is a snapshot. In full mode the
    /// service checks again at every [`NetworkEvent::Ipv6Changed`], and
    /// fails closed when a leak path has appeared.
    fn full_tunnel_ipv6(&self, tunnel: &str) -> Result<Ipv6Block>;

    /// Full mode: routes every IPv4 address, and blocks IPv6, through the
    /// tunnel named `tunnel`. It adds [`FULL_TUNNEL_V4`] and
    /// [`FULL_TUNNEL_V6`] on the tunnel with no next hop, and never touches
    /// a default route. The tunnel has no IPv6 address, so the IPv6 halves
    /// make every IPv6 connection that no more specific route takes
    /// elsewhere fail at once, rather than leave by the physical network.
    /// More specific routes still win, as for IPv4: the local network's
    /// link-local and on-link prefixes, and any other interface's.
    ///
    /// It first decides about IPv6 exactly as [`Routes::full_tunnel_ipv6`]
    /// does, and on a refusal fails with [`Error::Unsupported`] having added
    /// nothing. With [`Ipv6Block::NothingToBlock`] it adds the IPv4 halves
    /// only.
    ///
    /// Exclusive adds, journalled, as "Which routes are ours" says: a half
    /// already routed through another interface or next hop, such as
    /// another VPN's, fails with [`Error::AlreadyExists`]. The IPv4 halves
    /// come first. On an error after the IPv6 decision some may have been
    /// added: [`Routes::remove_full_tunnel`] or [`Routes::remove_all`]
    /// removes them.
    ///
    /// Answers what was done about IPv6. An OS that cannot do this at all
    /// fails with [`Error::Unsupported`] and adds nothing.
    fn add_full_tunnel(&self, tunnel: &str) -> Result<Ipv6Block>;

    /// Removes the four halves where this product added them, and nothing
    /// else. Succeeds for any that are not there, and when the interface no
    /// longer exists.
    fn remove_full_tunnel(&self, tunnel: &str) -> Result<()>;

    /// Whether a route to any of the four halves already goes through an
    /// interface other than `tunnel`, or a next hop: somebody else, such as
    /// another VPN, already sends all traffic somewhere, and full mode would
    /// fight it. Read-only, for the service to refuse before it changes
    /// anything. `Ok(false)` when there is none.
    fn foreign_full_tunnel(&self, tunnel: &str) -> Result<bool>;

    /// [`Routes::uses_interface`] for an IPv6 destination: which interface
    /// the OS would use to reach `dest`, and whether that is `interface`.
    ///
    /// It is the choice of the OS's IPv6 forwarding table, by the same rule
    /// as [`Routes::uses_interface`] (longest prefix, then lowest route plus
    /// interface metric, on interfaces that are up with IPv6 bound), not a
    /// question to the OS's own best-route lookup: on Windows that lookup
    /// fails for a destination the IPv6 halves cover, since the tunnel has
    /// no IPv6 source address.
    ///
    /// It fails closed on a tie: `Yes` only when every winning route goes
    /// through `interface`, `No` only when none does or no route matches,
    /// and `Unknown` when they disagree or the table, or any route in it,
    /// cannot be read.
    fn uses_interface_v6(&self, dest: Ipv6Addr, interface: &str) -> Verified;
}

/// The route protocol number Linux marks this product's routes with (see
/// [`Routes`]). It is not in the system's list of protocol numbers, and it
/// never changes.
pub const LINUX_ROUTE_PROTOCOL: u8 = 0xb5;

/// The packet sizes [`Routes::configure_tunnel`] accepts: from the smallest
/// every IPv4 host must take to an Ethernet frame's payload.
pub const TUNNEL_MTU: std::ops::RangeInclusive<u16> = 576..=1500;

/// Resolvers that answer for some domains only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitDns {
    /// The resolvers. They are reached by ordinary routing, so the caller
    /// must route them through the tunnel and check that with
    /// [`Routes::uses_interface`].
    pub resolvers: Vec<Ipv4Addr>,
    /// The domains they answer for, such as `dept.ubc.ca`. Every other name
    /// keeps using the system's resolvers.
    pub domains: Vec<String>,
}

/// Split DNS. There is at most one tunnel, so at most one setting.
///
/// The setting lives in the OS's own resolver, as a rule the product can
/// recognise as its own:
///
/// - **Linux**: systemd-resolved, on the tunnel's link: its DNS servers, the
///   domains as routing-only domains, and the link's default-route, LLMNR and
///   multicast DNS switched off.
/// - **macOS**: a supplemental resolver entry for the domains, flagged so
///   they are not added to the search list, set as a temporary value that the
///   implementation holds for the life of the connection.
/// - **Windows**: name-resolution policy rules for the domains, under keys
///   with identifiers that are the product's own.
pub trait Dns: Send + Sync {
    /// Sends lookups for `dns.domains`, and the names under them, to
    /// `dns.resolvers`, replacing whatever this product set before. `tunnel`
    /// tells an OS that attaches DNS to an interface where to attach it;
    /// Windows has no such notion and ignores it.
    ///
    /// It changes how no other name is resolved: not the search list, not
    /// the resolvers other names use, and not a name that merely ends in the
    /// same letters as a chosen domain.
    ///
    /// Fails with [`Error::Unsupported`], having changed nothing, when the OS
    /// would not honour such a rule. On Linux that is when systemd-resolved
    /// is absent or masked, or when programs are not asking it (its
    /// `resolv.conf` mode is neither `stub` nor `static`). On Windows it is
    /// when name-resolution rules from group policy exist, which replace
    /// local ones. macOS always can.
    fn set_split_dns(&self, tunnel: &str, dns: &SplitDns) -> Result<()>;

    /// Removes any split DNS this product set, including what an earlier run
    /// of the process left behind, and nothing anyone else set. Succeeds
    /// when nothing is set, so teardown calls it unconditionally.
    ///
    /// The service must call it at start-up on every OS, before anything
    /// else: a rule can outlive the process that set it. (On Windows a
    /// restart of the machine removes it.) What it removes is: on Windows, the keys
    /// with the product's identifiers; on macOS, the product's resolver
    /// entry; on Linux, the settings it put on the tunnel's link.
    fn clear_split_dns(&self) -> Result<()>;

    /// Whether the split DNS this product set is in effect and is exactly
    /// `dns`: these domains, these resolvers, nothing more. The interface is
    /// not part of the question, so the answer means the same on every OS.
    ///
    /// The answer is read back from the OS, not remembered from what was
    /// set:
    ///
    /// - **Linux** reads systemd-resolved's own state for the tunnel's link,
    ///   and **macOS** the resolver configuration in effect (what
    ///   `scutil --dns` shows). Both answer `Yes`, `No` or `Unknown`, and
    ///   never [`Verified::Unobservable`].
    /// - **Windows** can show only the rules that were written, not which
    ///   ones its resolver took in. It answers `Unobservable` when the
    ///   product's rules read back as exactly `dns` and no rules from group
    ///   policy exist, and never `Yes`.
    ///
    /// On every OS, rules from group policy, or rules that differ from
    /// `dns`, give `No`, and a read that fails gives `Unknown`.
    fn split_dns_matches(&self, dns: &SplitDns) -> Verified;

    /// Full mode: sends every name the OS resolves to `resolvers`, beside
    /// the split DNS set with [`Dns::set_split_dns`], replacing whatever
    /// catch-all this product set before. The resolvers are reached by
    /// ordinary routing, so the caller routes them through the tunnel.
    ///
    /// On Windows it is one more name-resolution rule, for the namespace
    /// `.`, under a key with an identifier of the product's own, volatile
    /// like the others. It takes precedence over Windows asking every
    /// network's resolver at once. A single-label name is sent with the
    /// local network's suffix added. mDNS, LLMNR and NetBIOS names are not
    /// DNS and are not affected.
    ///
    /// Fails with [`Error::Unsupported`], having changed nothing, where
    /// [`Dns::set_split_dns`] would, and on an OS that cannot do this. Fails
    /// with [`Error::AlreadyExists`], having changed nothing, when a rule
    /// that is not this product's already takes every name (see
    /// [`Dns::foreign_catch_all`]).
    fn set_catch_all_dns(&self, resolvers: &[Ipv4Addr]) -> Result<()>;

    /// Removes the catch-all this product set, and nothing else: the split
    /// DNS stays. Succeeds when there is none. [`Dns::clear_split_dns`]
    /// removes it too, so teardown and start-up need nothing more.
    fn clear_catch_all_dns(&self) -> Result<()>;

    /// Whether the catch-all this product set is in effect and sends every
    /// name to exactly `resolvers`, read back from the OS, with the same
    /// answers as [`Dns::split_dns_matches`]: on Windows `Unobservable` when
    /// it reads back exactly and no rules from group policy exist, never
    /// `Yes`. A rule that is not this product's and also takes every name
    /// gives `No`.
    fn catch_all_dns_matches(&self, resolvers: &[Ipv4Addr]) -> Verified;

    /// Whether a rule that is not this product's already takes every name:
    /// on Windows, a local name-resolution rule for the namespace `.`, such
    /// as Tailscale's "override local DNS" or exit node sets. Read-only, for
    /// the service to refuse full mode before it changes anything.
    /// `Ok(false)` when there is none.
    fn foreign_catch_all(&self) -> Result<bool>;
}

/// Something the OS reported about the machine's network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkEvent {
    /// The physical network being watched changed or went away. The
    /// [`PhysicalNetwork`] is no longer valid.
    PhysicalChanged,
    /// The system is about to sleep. Best effort: some machines and some
    /// kinds of sleep give no warning, so nothing may depend on receiving
    /// it.
    Sleeping,
    /// The system woke up. Best effort, like [`NetworkEvent::Sleeping`].
    Woke,
    /// An IPv6 route or address changed on some interface other than the
    /// tunnel, whatever the physical network: one may now be an IPv6 leak
    /// path (see [`Routes::full_tunnel_ipv6`]). In full mode with
    /// [`Ipv6Block::NothingToBlock`], the service checks again, and fails
    /// closed when there is one. It may be sent when nothing that matters
    /// changed: the check decides.
    Ipv6Changed,
}

/// Notifications pushed by the OS. There is no way to poll.
pub trait NetworkEvents: Send + Sync {
    /// Starts delivering events about `watching`, until the returned
    /// [`Subscription`] is dropped.
    ///
    /// [`NetworkEvent::PhysicalChanged`] is sent only for a change to
    /// `watching` itself. It is never sent for a route this product added or
    /// removed, nor for anything that happens to the tunnel interface.
    ///
    /// [`NetworkEvent::Ipv6Changed`] is sent for an IPv6 route or address
    /// added, changed or removed on any interface but the tunnel, so that
    /// full mode's "nothing to block" is never older than the last such
    /// change. Windows sends it from the same notifications it already
    /// watches (routes and addresses) for IPv6 as well as IPv4.
    fn subscribe(&self, watching: &PhysicalNetwork) -> Result<Subscription>;

    /// Whether a [`Subscription`] here sends [`NetworkEvent::Ipv6Changed`].
    /// Full mode may be had only where it does: without it, "nothing to
    /// block" could go stale unseen. An implementation answers `true` only
    /// once it watches IPv6 routes and addresses.
    fn reports_ipv6_changes(&self) -> bool;
}

/// The events of one subscription. Dropping it ends the subscription at
/// once: everything registered with the OS for it is released before the
/// drop returns, without waiting for another event. The service holds one
/// per connection and drops it at teardown.
pub struct Subscription {
    events: Receiver<NetworkEvent>,
    ends: SubscriptionEnd,
}

/// The part of a [`Subscription`] whose drop ends it. Held apart from the
/// receiver by a caller that reads events on another thread: dropping this
/// ends the subscription, and the receiver then reports the sender gone.
pub struct SubscriptionEnd {
    _ends: Box<dyn Send>,
}

impl Subscription {
    /// A subscription delivering `events`, which `ends` releases when it is
    /// dropped. An implementation makes `ends` a value whose `Drop` unregisters
    /// and stops whatever produces the events, drops every sender of
    /// `events`, and returns only when that is done.
    pub fn new(events: Receiver<NetworkEvent>, ends: impl Send + 'static) -> Self {
        Self {
            events,
            ends: SubscriptionEnd {
                _ends: Box::new(ends),
            },
        }
    }

    /// Where the events arrive.
    pub fn events(&self) -> &Receiver<NetworkEvent> {
        &self.events
    }

    /// The receiver, for a thread that reads the events, and the end, for
    /// whoever decides when the subscription stops.
    pub fn into_parts(self) -> (Receiver<NetworkEvent>, SubscriptionEnd) {
        (self.events, self.ends)
    }
}

impl fmt::Debug for Subscription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Subscription")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Linux's remove_all finds earlier versions' routes by this number, so
    // it can never change.
    #[test]
    fn the_linux_route_protocol_number_never_changes() {
        assert_eq!(LINUX_ROUTE_PROTOCOL, 0xb5);
    }
}
