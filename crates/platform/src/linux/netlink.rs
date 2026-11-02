//! Route netlink (rtnetlink): the kernel's own interface to its links,
//! addresses and routing tables, over a raw socket opened through rustix.
//!
//! Messages are built and read as bytes here, in the machine's byte order
//! as the kernel expects, so there is no unsafe code. Every request opens a
//! socket of its own, waits a few seconds at most for each reply, and reads
//! until the kernel says it is done: an acknowledgement, or the end of a
//! dump. A reply that cannot be read whole is an error, never a shorter
//! answer. A socket from [`listen`] asks nothing: it receives the kernel's
//! notices of changes instead.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use rustix::net::netlink::SocketAddrNetlink;
use rustix::net::sockopt::{self, Timeout};
use rustix::net::{AddressFamily, RecvFlags, SendFlags, SocketFlags, SocketType};

pub(crate) const AF_UNSPEC: u8 = 0;
pub(crate) const AF_INET: u8 = 2;
pub(crate) const AF_INET6: u8 = 10;

const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const RTM_NEWADDR: u16 = 20;
const RTM_DELADDR: u16 = 21;
const RTM_GETADDR: u16 = 22;
const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;
const RTM_GETROUTE: u16 = 26;

const NLMSG_NOOP: u16 = 1;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLMSG_OVERRUN: u16 = 4;

const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_ACK: u16 = 0x4;
const NLM_F_DUMP_INTR: u16 = 0x10;
const NLM_F_DUMP: u16 = 0x300;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;

const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_PRIORITY: u16 = 6;
const RTA_MULTIPATH: u16 = 9;
const RTA_TABLE: u16 = 15;
const RTA_VIA: u16 = 18;

const IFLA_IFNAME: u16 = 3;
const IFLA_MTU: u16 = 4;
const IFLA_LINKINFO: u16 = 18;
const IFLA_INFO_KIND: u16 = 1;
const IFLA_AF_SPEC: u16 = 26;
const IFLA_EXT_MASK: u16 = 29;
/// Leave the statistics out of a list of links.
const RTEXT_FILTER_SKIP_STATS: u32 = 1 << 3;
const IFLA_INET6_ADDR_GEN_MODE: u16 = 8;

const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_FLAGS: u16 = 8;

/// The interface is up, as its administrator set it.
pub(crate) const IFF_UP: u32 = 0x1;
/// The interface is up and its link works (`operstate` up or unknown).
pub(crate) const IFF_RUNNING: u32 = 0x40;

/// The address is still being checked for duplicates.
pub(crate) const IFA_F_TENTATIVE: u32 = 0x40;
/// Another machine on the link has the address.
pub(crate) const IFA_F_DADFAILED: u32 = 0x08;
/// The address is past its preferred lifetime.
pub(crate) const IFA_F_DEPRECATED: u32 = 0x20;

/// The route's next hop is dead.
pub(crate) const RTNH_F_DEAD: u32 = 0x1;
/// The route's next hop has no carrier.
pub(crate) const RTNH_F_LINKDOWN: u32 = 0x10;

/// The route is a copy the kernel made for one destination, such as one
/// that learned a smaller packet size, not one anybody added.
pub(crate) const RTM_F_CLONED: u32 = 0x200;

/// The kernel's notices about links (`RTMGRP_LINK`), as a group bit.
pub(crate) const GROUP_LINK: u32 = 0x1;
/// About IPv4 addresses (`RTMGRP_IPV4_IFADDR`).
pub(crate) const GROUP_IPV4_ADDRESS: u32 = 0x10;
/// About IPv4 routes (`RTMGRP_IPV4_ROUTE`).
pub(crate) const GROUP_IPV4_ROUTE: u32 = 0x40;
/// About IPv6 addresses (`RTMGRP_IPV6_IFADDR`).
pub(crate) const GROUP_IPV6_ADDRESS: u32 = 0x100;
/// About IPv6 routes (`RTMGRP_IPV6_ROUTE`).
pub(crate) const GROUP_IPV6_ROUTE: u32 = 0x400;

/// The main routing table, where routes go unless a rule says otherwise.
pub(crate) const RT_TABLE_MAIN: u32 = 254;
/// A route straight onto the link.
pub(crate) const RT_SCOPE_LINK: u8 = 253;
/// A route through a router.
pub(crate) const RT_SCOPE_UNIVERSE: u8 = 0;
/// An ordinary route to somewhere.
pub(crate) const RTN_UNICAST: u8 = 1;

/// `addr_gen_mode` 1, `IN6_ADDR_GEN_MODE_NONE`: the kernel gives the
/// interface no IPv6 address of its own, link-local included.
pub(crate) const ADDR_GEN_MODE_NONE: u8 = 1;

/// How long to wait for each reply. The kernel answers at once; this only
/// keeps a request from hanging for ever.
const WAIT: Duration = Duration::from_secs(5);
const HEADER: usize = 16;
/// Room for any one read: the kernel fills a dump in parts of at most a
/// page or so each.
const BUFFER: usize = 1 << 16;

static SEQUENCE: AtomicU32 = AtomicU32::new(1);

fn invalid(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("netlink: {what}"))
}

fn align(len: usize) -> usize {
    (len + 3) & !3
}

/// A request to the kernel: a header, a fixed part, and attributes.
#[derive(Debug, Clone)]
pub(crate) struct Request {
    bytes: Vec<u8>,
}

impl Request {
    fn new(kind: u16, flags: u16, fixed: &[u8]) -> Self {
        let mut bytes = vec![0; HEADER];
        bytes[4..6].copy_from_slice(&kind.to_ne_bytes());
        bytes[6..8].copy_from_slice(&(flags | NLM_F_REQUEST).to_ne_bytes());
        bytes.extend_from_slice(fixed);
        bytes.resize(align(bytes.len()), 0);
        Self { bytes }
    }

    fn attr(mut self, kind: u16, data: &[u8]) -> Self {
        self.bytes.extend_from_slice(&attribute(kind, data));
        self
    }

    /// The bytes as sent, with the length and sequence number filled in.
    fn finish(mut self, seq: u32) -> io::Result<Vec<u8>> {
        let len = u32::try_from(self.bytes.len()).map_err(|_| invalid("a request too long"))?;
        self.bytes[0..4].copy_from_slice(&len.to_ne_bytes());
        self.bytes[8..12].copy_from_slice(&seq.to_ne_bytes());
        Ok(self.bytes)
    }
}

/// One attribute, padded to the next four bytes.
fn attribute(kind: u16, data: &[u8]) -> Vec<u8> {
    let len = u16::try_from(4 + data.len()).expect("a short attribute");
    let mut bytes = Vec::with_capacity(align(usize::from(len)));
    bytes.extend_from_slice(&len.to_ne_bytes());
    bytes.extend_from_slice(&kind.to_ne_bytes());
    bytes.extend_from_slice(data);
    bytes.resize(align(bytes.len()), 0);
    bytes
}

/// One message from the kernel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Message {
    pub(crate) kind: u16,
    pub(crate) flags: u16,
    pub(crate) seq: u32,
    pub(crate) body: Vec<u8>,
}

fn u16_at(bytes: &[u8], at: usize) -> io::Result<u16> {
    let raw = bytes
        .get(at..at + 2)
        .ok_or_else(|| invalid("a message cut short"))?;
    Ok(u16::from_ne_bytes([raw[0], raw[1]]))
}

fn u32_at(bytes: &[u8], at: usize) -> io::Result<u32> {
    let raw = bytes
        .get(at..at + 4)
        .ok_or_else(|| invalid("a message cut short"))?;
    Ok(u32::from_ne_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

/// The messages in what one read returned. Anything that does not add up
/// is an error.
pub(crate) fn messages(mut bytes: &[u8]) -> io::Result<Vec<Message>> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let len = usize::try_from(u32_at(bytes, 0)?).map_err(|_| invalid("a length"))?;
        if len < HEADER || len > bytes.len() {
            return Err(invalid("a message whose length does not fit"));
        }
        out.push(Message {
            kind: u16_at(bytes, 4)?,
            flags: u16_at(bytes, 6)?,
            seq: u32_at(bytes, 8)?,
            body: bytes[HEADER..len].to_vec(),
        });
        bytes = &bytes[align(len).min(bytes.len())..];
    }
    Ok(out)
}

/// The attributes in `bytes`, each as its type, without the nested and
/// byte-order flags, and its data.
pub(crate) fn attributes(mut bytes: &[u8]) -> io::Result<Vec<(u16, &[u8])>> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let len = usize::from(u16_at(bytes, 0)?);
        if len < 4 || len > bytes.len() {
            return Err(invalid("an attribute whose length does not fit"));
        }
        out.push((u16_at(bytes, 2)? & 0x3fff, &bytes[4..len]));
        bytes = &bytes[align(len).min(bytes.len())..];
    }
    Ok(out)
}

fn ip(data: &[u8]) -> io::Result<IpAddr> {
    match data.len() {
        4 => Ok(IpAddr::V4(Ipv4Addr::new(
            data[0], data[1], data[2], data[3],
        ))),
        16 => {
            let mut raw = [0; 16];
            raw.copy_from_slice(data);
            Ok(IpAddr::V6(Ipv6Addr::from(raw)))
        }
        _ => Err(invalid("an address of the wrong size")),
    }
}

fn ip_bytes(addr: IpAddr) -> Vec<u8> {
    match addr {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

fn u32_of(data: &[u8]) -> io::Result<u32> {
    match data.len() {
        4 => u32_at(data, 0),
        _ => Err(invalid("a number of the wrong size")),
    }
}

/// A NUL-terminated string attribute.
fn text(data: &[u8]) -> io::Result<String> {
    let end = data.iter().position(|b| *b == 0).unwrap_or(data.len());
    String::from_utf8(data[..end].to_vec()).map_err(|_| invalid("a name that is not UTF-8"))
}

/// A route, as the kernel lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Route {
    pub(crate) family: u8,
    /// The destination: the unspecified address for a default route.
    pub(crate) dst: IpAddr,
    pub(crate) dst_len: u8,
    pub(crate) tos: u8,
    pub(crate) table: u32,
    pub(crate) protocol: u8,
    pub(crate) scope: u8,
    pub(crate) kind: u8,
    pub(crate) flags: u32,
    pub(crate) oif: Option<u32>,
    pub(crate) gateway: Option<IpAddr>,
    pub(crate) priority: Option<u32>,
    /// More than one next hop, listed apart from `oif` and `gateway`.
    pub(crate) multipath: bool,
    /// A next hop of the other family (`RTA_VIA`).
    pub(crate) via: bool,
}

impl Route {
    pub(crate) fn parse(body: &[u8]) -> io::Result<Self> {
        let fixed = body.get(..12).ok_or_else(|| invalid("a route cut short"))?;
        let family = fixed[0];
        let dst = match family {
            AF_INET => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            AF_INET6 => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            _ => return Err(invalid("a route of another family")),
        };
        let mut route = Self {
            family,
            dst,
            dst_len: fixed[1],
            tos: fixed[3],
            table: u32::from(fixed[4]),
            protocol: fixed[5],
            scope: fixed[6],
            kind: fixed[7],
            flags: u32_at(fixed, 8)?,
            oif: None,
            gateway: None,
            priority: None,
            multipath: false,
            via: false,
        };
        for (kind, data) in attributes(&body[12..])? {
            match kind {
                RTA_DST => route.dst = ip(data)?,
                RTA_OIF => route.oif = Some(u32_of(data)?),
                RTA_GATEWAY => route.gateway = Some(ip(data)?),
                RTA_PRIORITY => route.priority = Some(u32_of(data)?),
                RTA_TABLE => route.table = u32_of(data)?,
                RTA_MULTIPATH => route.multipath = true,
                RTA_VIA => route.via = true,
                _ => {}
            }
        }
        let family_of = |addr: &IpAddr| match addr {
            IpAddr::V4(_) => AF_INET,
            IpAddr::V6(_) => AF_INET6,
        };
        let gateway_family = route.gateway.as_ref().map(family_of);
        if family_of(&route.dst) != family || gateway_family.is_some_and(|g| g != family) {
            return Err(invalid("a route with an address of another family"));
        }
        Ok(route)
    }

    fn request(&self, kind: u16, flags: u16) -> Request {
        // A table past 255 is named only by its attribute.
        let table = u8::try_from(self.table).unwrap_or(0);
        let mut fixed = vec![
            self.family,
            self.dst_len,
            0,
            self.tos,
            table,
            self.protocol,
            self.scope,
            self.kind,
        ];
        fixed.extend_from_slice(&0u32.to_ne_bytes());
        let mut request =
            Request::new(kind, flags, &fixed).attr(RTA_TABLE, &self.table.to_ne_bytes());
        if self.dst_len > 0 {
            request = request.attr(RTA_DST, &ip_bytes(self.dst));
        }
        if let Some(oif) = self.oif {
            request = request.attr(RTA_OIF, &oif.to_ne_bytes());
        }
        if let Some(gateway) = self.gateway {
            request = request.attr(RTA_GATEWAY, &ip_bytes(gateway));
        }
        if let Some(priority) = self.priority {
            request = request.attr(RTA_PRIORITY, &priority.to_ne_bytes());
        }
        request
    }
}

/// A network interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Link {
    pub(crate) index: u32,
    pub(crate) name: String,
    pub(crate) flags: u32,
    /// What made it, such as `tun`, when it says.
    pub(crate) kind: Option<String>,
    /// The largest packet it sends, when it says.
    pub(crate) mtu: Option<u32>,
}

impl Link {
    pub(crate) fn parse(body: &[u8]) -> io::Result<Self> {
        let fixed = body.get(..16).ok_or_else(|| invalid("a link cut short"))?;
        let mut name = None;
        let mut kind = None;
        let mut mtu = None;
        for (attr, data) in attributes(&body[16..])? {
            match attr {
                IFLA_IFNAME => name = Some(text(data)?),
                IFLA_MTU => mtu = Some(u32_of(data)?),
                IFLA_LINKINFO => {
                    for (inner, data) in attributes(data)? {
                        if inner == IFLA_INFO_KIND {
                            kind = Some(text(data)?);
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(Self {
            index: u32_at(fixed, 4)?,
            name: name.ok_or_else(|| invalid("a link with no name"))?,
            flags: u32_at(fixed, 8)?,
            kind,
            mtu,
        })
    }

    /// Up, and its link works.
    pub(crate) fn running(&self) -> bool {
        self.flags & (IFF_UP | IFF_RUNNING) == IFF_UP | IFF_RUNNING
    }
}

/// An address of an interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Address {
    pub(crate) family: u8,
    pub(crate) prefix_len: u8,
    pub(crate) flags: u32,
    pub(crate) index: u32,
    /// The interface's own address (`IFA_LOCAL`, or `IFA_ADDRESS` where
    /// there is no other).
    pub(crate) local: IpAddr,
    /// `IFA_ADDRESS`: the same, or the far end of a point-to-point link.
    pub(crate) address: Option<IpAddr>,
}

impl Address {
    pub(crate) fn parse(body: &[u8]) -> io::Result<Self> {
        let fixed = body
            .get(..8)
            .ok_or_else(|| invalid("an address cut short"))?;
        let mut flags = u32::from(fixed[2]);
        let (mut local, mut address) = (None, None);
        for (attr, data) in attributes(&body[8..])? {
            match attr {
                IFA_LOCAL => local = Some(ip(data)?),
                IFA_ADDRESS => address = Some(ip(data)?),
                IFA_FLAGS => flags = u32_of(data)?,
                _ => {}
            }
        }
        Ok(Self {
            family: fixed[0],
            prefix_len: fixed[1],
            flags,
            index: u32_at(fixed, 4)?,
            local: local
                .or(address)
                .ok_or_else(|| invalid("an address with no address"))?,
            address,
        })
    }

    /// The IPv4 address, if it is one.
    pub(crate) fn v4(&self) -> Option<Ipv4Addr> {
        match self.local {
            IpAddr::V4(v4) if self.family == AF_INET => Some(v4),
            _ => None,
        }
    }
}

/// A socket to the kernel's routing part.
struct Socket(OwnedFd);

impl Socket {
    fn open() -> io::Result<Self> {
        let family = AddressFamily::NETLINK;
        // No protocol is `NETLINK_ROUTE`.
        let fd = rustix::net::socket_with(family, SocketType::RAW, SocketFlags::CLOEXEC, None)?;
        sockopt::set_socket_timeout(&fd, Timeout::Recv, Some(WAIT))?;
        sockopt::set_socket_timeout(&fd, Timeout::Send, Some(WAIT))?;
        Ok(Self(fd))
    }

    /// Sends `request` and gathers the replies up to the kernel's last
    /// word: the acknowledgement, or the end of a dump. An error from the
    /// kernel is returned as the error it names.
    fn exchange(&self, request: Request) -> io::Result<Vec<Message>> {
        let seq = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let bytes = request.finish(seq)?;
        let sent = rustix::net::send(&self.0, &bytes, SendFlags::empty())?;
        if sent != bytes.len() {
            return Err(invalid("a request sent in part"));
        }
        let mut buffer = vec![0; BUFFER];
        let mut out = Vec::new();
        loop {
            let (read, whole) = rustix::net::recv(&self.0, &mut buffer[..], RecvFlags::TRUNC)?;
            if whole > read {
                return Err(invalid("a reply longer than the buffer"));
            }
            for message in messages(&buffer[..read])? {
                // A reply to some earlier request on this socket: none.
                if message.seq != seq {
                    continue;
                }
                if message.flags & NLM_F_DUMP_INTR != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "netlink: the table changed while it was read",
                    ));
                }
                match message.kind {
                    NLMSG_NOOP => {}
                    NLMSG_ERROR | NLMSG_DONE => {
                        // An error or acknowledgement always has the code;
                        // the end of a dump may.
                        let code = match (message.kind, message.body.len()) {
                            (NLMSG_DONE, 0..4) => 0,
                            _ => i32::from_ne_bytes(u32_at(&message.body, 0)?.to_ne_bytes()),
                        };
                        return match code {
                            0 => Ok(out),
                            code if code < 0 => Err(io::Error::from_raw_os_error(-code)),
                            _ => Err(invalid("an error code that is not one")),
                        };
                    }
                    NLMSG_OVERRUN => return Err(invalid("the kernel dropped part of a reply")),
                    _ => out.push(message),
                }
            }
        }
    }
}

/// A socket the kernel sends its notices for `groups` to, as they happen.
/// It never blocks, and is closed in any program this one starts. With
/// `buffer`, it holds about that many bytes of notices not yet read, the
/// kernel's least where that is smaller; otherwise the kernel's usual.
pub(crate) fn listen(groups: u32, buffer: Option<usize>) -> io::Result<OwnedFd> {
    let flags = SocketFlags::CLOEXEC | SocketFlags::NONBLOCK;
    let fd = rustix::net::socket_with(AddressFamily::NETLINK, SocketType::RAW, flags, None)?;
    if let Some(size) = buffer {
        sockopt::set_socket_recv_buffer_size(&fd, size)?;
    }
    rustix::net::bind(&fd, &SocketAddrNetlink::new(0, groups))?;
    Ok(fd)
}

/// Sends `request` on a socket of its own.
fn exchange(request: Request) -> io::Result<Vec<Message>> {
    Socket::open()?.exchange(request)
}

/// A dump, tried again when the table changed while it was read.
fn dump(request: impl Fn() -> Request) -> io::Result<Vec<Message>> {
    let mut tries = 0;
    loop {
        match exchange(request()) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted && tries < 3 => tries += 1,
            other => return other,
        }
    }
}

/// Every network interface. Their statistics are left out, as is the
/// virtual-function list (only sent when asked for), which on a network card
/// with many could fill a read.
pub(crate) fn links() -> io::Result<Vec<Link>> {
    let fixed = [0; 16];
    let skip_stats = RTEXT_FILTER_SKIP_STATS.to_ne_bytes();
    let replies =
        dump(|| Request::new(RTM_GETLINK, NLM_F_DUMP, &fixed).attr(IFLA_EXT_MASK, &skip_stats))?;
    replies
        .iter()
        .filter(|m| m.kind == RTM_NEWLINK)
        .map(|m| Link::parse(&m.body))
        .collect()
}

/// Every address of `family`.
pub(crate) fn addresses(family: u8) -> io::Result<Vec<Address>> {
    let fixed = [family, 0, 0, 0, 0, 0, 0, 0];
    let replies = dump(|| Request::new(RTM_GETADDR, NLM_F_DUMP, &fixed))?;
    let all: io::Result<Vec<Address>> = replies
        .iter()
        .filter(|m| m.kind == RTM_NEWADDR)
        .map(|m| Address::parse(&m.body))
        .collect();
    // A kernel without that family answers with all of them.
    Ok(all?.into_iter().filter(|a| a.family == family).collect())
}

/// Every route of `family`, or of both IPv4 and IPv6 for `AF_UNSPEC`, in
/// every table. Routes of other families are left out.
pub(crate) fn routes(family: u8) -> io::Result<Vec<Route>> {
    let mut fixed = vec![family, 0, 0, 0, 0, 0, 0, 0];
    fixed.extend_from_slice(&0u32.to_ne_bytes());
    let replies = dump(|| Request::new(RTM_GETROUTE, NLM_F_DUMP, &fixed))?;
    let wanted = |f: u8| match family {
        AF_UNSPEC => f == AF_INET || f == AF_INET6,
        _ => f == family,
    };
    replies
        .iter()
        .filter(|m| m.kind == RTM_NEWROUTE && m.body.first().copied().is_some_and(wanted))
        .map(|m| Route::parse(&m.body))
        .collect()
}

/// The route the kernel would send a packet to `dest` by, as it would
/// choose it now.
pub(crate) fn route_to(dest: Ipv4Addr) -> io::Result<Route> {
    let mut fixed = vec![AF_INET, 32, 0, 0, 0, 0, 0, 0];
    fixed.extend_from_slice(&0u32.to_ne_bytes());
    let request = Request::new(RTM_GETROUTE, NLM_F_ACK, &fixed).attr(RTA_DST, &dest.octets());
    let replies = exchange(request)?;
    let mut routes = replies.iter().filter(|m| m.kind == RTM_NEWROUTE);
    match (routes.next(), routes.next()) {
        (Some(only), None) => Route::parse(&only.body),
        _ => Err(invalid("not one route in the answer")),
    }
}

/// Adds `route`, and fails if one with the same key is there.
pub(crate) fn add_route(route: &Route) -> io::Result<()> {
    let flags = NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
    exchange(route.request(RTM_NEWROUTE, flags)).map(drop)
}

/// Removes the route matching `route`: its destination, table, protocol,
/// next hop and priority.
pub(crate) fn delete_route(route: &Route) -> io::Result<()> {
    exchange(route.request(RTM_DELROUTE, NLM_F_ACK)).map(drop)
}

/// Gives the interface numbered `index` the address `addr`, as a network
/// of `prefix_len` bits, and fails if it has it already.
pub(crate) fn add_address(index: u32, addr: Ipv4Addr, prefix_len: u8) -> io::Result<()> {
    let mut fixed = vec![AF_INET, prefix_len, 0, RT_SCOPE_UNIVERSE];
    fixed.extend_from_slice(&index.to_ne_bytes());
    let flags = NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
    let request = Request::new(RTM_NEWADDR, flags, &fixed)
        .attr(IFA_LOCAL, &addr.octets())
        .attr(IFA_ADDRESS, &addr.octets());
    exchange(request).map(drop)
}

/// Removes `address` from its interface.
pub(crate) fn delete_address(address: &Address) -> io::Result<()> {
    let mut fixed = vec![address.family, address.prefix_len, 0, 0];
    fixed.extend_from_slice(&address.index.to_ne_bytes());
    let mut request = Request::new(RTM_DELADDR, NLM_F_ACK, &fixed);
    if address.family == AF_INET {
        request = request.attr(IFA_LOCAL, &ip_bytes(address.local));
    }
    let far = address.address.unwrap_or(address.local);
    exchange(request.attr(IFA_ADDRESS, &ip_bytes(far))).map(drop)
}

fn link_request(index: u32, flags: u32, change: u32) -> Request {
    let mut fixed = vec![AF_UNSPEC, 0, 0, 0];
    fixed.extend_from_slice(&index.to_ne_bytes());
    fixed.extend_from_slice(&flags.to_ne_bytes());
    fixed.extend_from_slice(&change.to_ne_bytes());
    Request::new(RTM_NEWLINK, NLM_F_ACK, &fixed)
}

/// Sets the largest packet the interface numbered `index` sends.
pub(crate) fn set_mtu(index: u32, mtu: u16) -> io::Result<()> {
    let request = link_request(index, 0, 0).attr(IFLA_MTU, &u32::from(mtu).to_ne_bytes());
    exchange(request).map(drop)
}

/// Brings the interface numbered `index` up.
pub(crate) fn set_up(index: u32) -> io::Result<()> {
    exchange(link_request(index, IFF_UP, IFF_UP)).map(drop)
}

/// Takes the interface numbered `index` down.
pub(crate) fn set_down(index: u32) -> io::Result<()> {
    exchange(link_request(index, 0, IFF_UP)).map(drop)
}

/// Sets how the kernel makes IPv6 addresses of its own on the interface
/// numbered `index`. Fails with `EAFNOSUPPORT` where it has no IPv6.
pub(crate) fn set_addr_gen_mode(index: u32, mode: u8) -> io::Result<()> {
    let inet6 = attribute(IFLA_INET6_ADDR_GEN_MODE, &[mode]);
    let spec = attribute(u16::from(AF_INET6), &inet6);
    exchange(link_request(index, 0, 0).attr(IFLA_AF_SPEC, &spec)).map(drop)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(len: u32, kind: u16, flags: u16, seq: u32) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&len.to_ne_bytes());
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(&flags.to_ne_bytes());
        bytes.extend_from_slice(&seq.to_ne_bytes());
        bytes.extend_from_slice(&0u32.to_ne_bytes());
        bytes
    }

    fn route_body(attrs: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut body = vec![AF_INET, 24, 0, 0, 254, 0xb5, RT_SCOPE_LINK, RTN_UNICAST];
        body.extend_from_slice(&0u32.to_ne_bytes());
        for (kind, data) in attrs {
            body.extend_from_slice(&attribute(*kind, data));
        }
        body
    }

    // What is sent is what is read back: the header, the fixed part, and
    // each attribute padded to four bytes.
    #[test]
    fn a_route_request_reads_back_as_the_same_route() {
        let route = Route {
            family: AF_INET,
            dst: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)),
            dst_len: 24,
            tos: 0,
            table: RT_TABLE_MAIN,
            protocol: 0xb5,
            scope: RT_SCOPE_UNIVERSE,
            kind: RTN_UNICAST,
            flags: 0,
            oif: Some(7),
            gateway: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))),
            priority: Some(100),
            multipath: false,
            via: false,
        };
        let bytes = route.request(RTM_NEWROUTE, NLM_F_ACK).finish(42).unwrap();
        let read = messages(&bytes).unwrap();
        assert_eq!(read.len(), 1);
        assert_eq!((read[0].kind, read[0].seq), (RTM_NEWROUTE, 42));
        assert_eq!(read[0].flags, NLM_F_ACK | NLM_F_REQUEST);
        assert_eq!(Route::parse(&read[0].body).unwrap(), route);
    }

    // A reply that does not add up is an error, never a shorter answer.
    #[test]
    fn a_reply_cut_short_is_an_error() {
        let body = route_body(&[(RTA_OIF, 3u32.to_ne_bytes().to_vec())]);
        let mut bytes = header(
            u32::try_from(HEADER + body.len()).unwrap(),
            RTM_NEWROUTE,
            0,
            1,
        );
        bytes.extend_from_slice(&body);
        assert!(messages(&bytes).is_ok());
        assert!(
            messages(&bytes[..bytes.len() - 1]).is_err(),
            "a short message"
        );
        assert!(messages(&bytes[..10]).is_err(), "a short header");
        // An attribute that claims more than there is.
        let mut long = body.clone();
        let at = long.len() - 8;
        long[at..at + 2].copy_from_slice(&40u16.to_ne_bytes());
        assert!(Route::parse(&long).is_err());
        // A number of the wrong size.
        let odd = route_body(&[(RTA_OIF, vec![1, 2])]);
        assert!(Route::parse(&odd).is_err());
        assert!(Route::parse(&body[..11]).is_err(), "a short fixed part");
    }

    #[test]
    fn a_route_lists_what_it_says() {
        let body = route_body(&[
            (RTA_DST, vec![192, 0, 2, 0]),
            (RTA_OIF, 3u32.to_ne_bytes().to_vec()),
            (RTA_TABLE, 254u32.to_ne_bytes().to_vec()),
            (RTA_MULTIPATH, vec![0; 8]),
        ]);
        let route = Route::parse(&body).unwrap();
        assert_eq!(route.dst, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)));
        assert_eq!(
            (route.oif, route.gateway, route.priority),
            (Some(3), None, None)
        );
        assert!(route.multipath);
        // An IPv6 gateway on an IPv4 route is not read as an IPv4 one.
        let mixed = route_body(&[(RTA_GATEWAY, vec![0; 16])]);
        assert!(Route::parse(&mixed).is_err());
    }

    #[test]
    fn a_link_has_its_name_kind_and_flags() {
        let mut body = vec![AF_UNSPEC, 0, 0xfe, 0xff];
        body.extend_from_slice(&9u32.to_ne_bytes());
        body.extend_from_slice(&(IFF_UP | IFF_RUNNING).to_ne_bytes());
        body.extend_from_slice(&0u32.to_ne_bytes());
        body.extend_from_slice(&attribute(IFLA_IFNAME, b"uvt0\0"));
        let info = attribute(IFLA_INFO_KIND, b"tun\0");
        body.extend_from_slice(&attribute(IFLA_LINKINFO | 0x8000, &info));
        body.extend_from_slice(&attribute(IFLA_MTU, &1400u32.to_ne_bytes()));
        let link = Link::parse(&body).unwrap();
        assert_eq!(link.index, 9);
        assert_eq!(link.name, "uvt0");
        assert_eq!(link.kind.as_deref(), Some("tun"));
        assert_eq!(link.mtu, Some(1400));
        assert!(link.running());
        let down = Link {
            flags: IFF_UP,
            ..link
        };
        assert!(!down.running(), "up with no link");
    }

    #[test]
    fn an_address_prefers_its_local_part_and_long_flags() {
        let mut body = vec![AF_INET, 24, 0, 0];
        body.extend_from_slice(&4u32.to_ne_bytes());
        body.extend_from_slice(&attribute(IFA_ADDRESS, &[198, 51, 100, 2]));
        body.extend_from_slice(&attribute(IFA_LOCAL, &[198, 51, 100, 1]));
        body.extend_from_slice(&attribute(IFA_FLAGS, &IFA_F_TENTATIVE.to_ne_bytes()));
        let address = Address::parse(&body).unwrap();
        assert_eq!(address.v4(), Some(Ipv4Addr::new(198, 51, 100, 1)));
        assert_eq!(
            address.address,
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)))
        );
        assert_eq!((address.prefix_len, address.index), (24, 4));
        assert_eq!(address.flags, IFA_F_TENTATIVE);
    }
}
