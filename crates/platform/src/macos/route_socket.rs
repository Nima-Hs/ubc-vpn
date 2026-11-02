//! The kernel's IPv4 routing table and network interfaces, by raw calls:
//! route messages on a routing socket (`PF_ROUTE`) to add and delete routes,
//! the `sysctl` that dumps the table, `getifaddrs` for the interfaces, and
//! the interface ioctls that set an address, the packet size and the up
//! flag. What these mean for the product is in `routes.rs`.
//!
//! A route message is an `rt_msghdr` followed by the socket addresses its
//! `rtm_addrs` bits name, in the order of the bits, each padded to a
//! multiple of four bytes (macOS rounds to `uint32_t`, on 64-bit machines
//! too). A netmask in a dump is often cut short: its length byte counts only
//! the bytes up to the last one that is not zero, and a length of zero is a
//! mask of zero.

use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::io;
use std::mem::{size_of, zeroed};
use std::net::Ipv4Addr;
use std::ops::BitOr;
use std::os::fd::{AsRawFd, OwnedFd};
use std::ptr;
use std::sync::atomic::{AtomicI32, Ordering};

use libc::{c_int, c_ulong};
use rustix::io::{FdFlags, fcntl_setfd};
use rustix::net::{AddressFamily, SocketType};
use ubc_vpn_core::routes::Ipv4Net;

use crate::{Error, Result};

/// The size of a route message's header, which the socket addresses follow.
const HEADER: usize = size_of::<libc::rt_msghdr>();

/// Where each socket address goes in a route message, by its `RTA_*` bit.
const RTAX_DST: usize = 0;
const RTAX_GATEWAY: usize = 1;
const RTAX_NETMASK: usize = 2;
const RTAX_MAX: usize = 8;

/// An ioctl's number, as `_IOC` in `<sys/ioccom.h>` makes it: the
/// direction, the size of the argument, the group and the number.
pub(super) const fn ioc(direction: c_ulong, group: u8, number: u8, size: usize) -> c_ulong {
    direction + (((size as c_ulong) & 0x1fff) << 16) + ((group as c_ulong) << 8) + number as c_ulong
}
pub(super) const IOC_IN: c_ulong = 0x8000_0000;
pub(super) const IOC_INOUT: c_ulong = 0xc000_0000;
const IFREQ: usize = size_of::<libc::ifreq>();
const IN6_IFREQ: usize = size_of::<libc::in6_ifreq>();
// The numbers are those of <sys/sockio.h> and <netinet6/in6_var.h>.
pub(super) const SIOCSIFFLAGS: c_ulong = ioc(IOC_IN, b'i', 16, IFREQ);
pub(super) const SIOCGIFFLAGS: c_ulong = ioc(IOC_INOUT, b'i', 17, IFREQ);
pub(super) const SIOCDIFADDR: c_ulong = ioc(IOC_IN, b'i', 25, IFREQ);
pub(super) const SIOCAIFADDR: c_ulong = ioc(IOC_IN, b'i', 26, size_of::<libc::ifaliasreq>());
pub(super) const SIOCSIFMTU: c_ulong = ioc(IOC_IN, b'i', 52, IFREQ);
pub(super) const SIOCDIFADDR_IN6: c_ulong = ioc(IOC_IN, b'i', 25, IN6_IFREQ);

/// One route of the table, as the kernel lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Route {
    pub(super) dest: Ipv4Net,
    /// The index of the interface it goes out of.
    pub(super) index: u16,
    /// The router it hands traffic to, for a route through one
    /// (`RTF_GATEWAY`), or `None` for a route straight onto the link.
    pub(super) router: Option<Ipv4Addr>,
    /// Its `RTF_*` flags.
    pub(super) flags: c_int,
}

/// One network interface, as `getifaddrs` lists it.
#[derive(Debug, Clone, Default)]
pub(super) struct Interface {
    pub(super) name: String,
    pub(super) index: u16,
    /// Its `IFF_*` flags.
    pub(super) flags: c_int,
    pub(super) mtu: u32,
    pub(super) v4: Vec<V4Address>,
    /// Its IPv6 addresses, as the kernel gave them, so that they can be
    /// handed back to it to remove.
    pub(super) v6: Vec<libc::sockaddr_in6>,
}

impl Interface {
    /// The interface `name`, before anything else about it is read.
    fn named(name: String) -> Self {
        Self {
            name,
            index: 0,
            flags: 0,
            mtu: 0,
            v4: Vec::new(),
            v6: Vec::new(),
        }
    }

    /// Whether it is up and running: only then does anything go out of it.
    pub(super) fn is_up(&self) -> bool {
        self.flags & libc::IFF_UP != 0 && self.flags & libc::IFF_RUNNING != 0
    }

    #[cfg(test)]
    pub(super) fn v6_addresses(&self) -> Vec<std::net::Ipv6Addr> {
        let addresses = self.v6.iter();
        addresses.map(|a| a.sin6_addr.s6_addr.into()).collect()
    }
}

/// One IPv4 address of an interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct V4Address {
    pub(super) addr: Ipv4Addr,
    pub(super) prefix_len: u8,
    /// The other end, on a point-to-point interface.
    pub(super) peer: Option<Ipv4Addr>,
}

fn unreadable() -> Error {
    Error::Failed("the routing table cannot be read".to_string())
}

/// The error for a failed call, by its `errno`. The message names the call
/// and the system's reason, never anything secret.
pub(super) fn os_error(call: &str, error: io::Error) -> Error {
    match error.raw_os_error() {
        Some(libc::EEXIST) => Error::AlreadyExists,
        Some(libc::ESRCH | libc::ENXIO | libc::ENODEV | libc::EADDRNOTAVAIL) => Error::NotFound,
        Some(libc::EPERM | libc::EACCES) => Error::PermissionDenied,
        _ => Error::Failed(format!("{call}: {error}")),
    }
}

/// Every IPv4 route in the kernel's table, scoped and cloned ones included.
pub(super) fn table() -> Result<Vec<Route>> {
    let mut name = [
        libc::CTL_NET,
        libc::PF_ROUTE,
        0,
        libc::AF_INET,
        libc::NET_RT_DUMP,
        0,
    ];
    let mut size = 0;
    // SAFETY: `name` holds the six numbers the length says, and a null
    // buffer asks only for the size, which the call writes to `size`.
    let status = unsafe {
        libc::sysctl(
            name.as_mut_ptr(),
            6,
            ptr::null_mut(),
            &mut size,
            ptr::null_mut(),
            0,
        )
    };
    if status != 0 {
        return Err(os_error("sysctl", io::Error::last_os_error()));
    }
    // Room for the table to double between the two calls. Should it grow
    // more, the call fails, and so does this: the answer is then unknown.
    let mut bytes = vec![0u8; size.saturating_mul(2).saturating_add(4096)];
    let mut size = bytes.len();
    // SAFETY: `bytes` is a live buffer of `size` bytes for the call to
    // fill, and it writes how many it filled to `size`.
    let status = unsafe {
        libc::sysctl(
            name.as_mut_ptr(),
            6,
            bytes.as_mut_ptr().cast(),
            &mut size,
            ptr::null_mut(),
            0,
        )
    };
    if status != 0 {
        return Err(os_error("sysctl", io::Error::last_os_error()));
    }
    bytes.truncate(size);
    parse_table(&bytes)
}

/// A plain value copied out of the front of `bytes`, or `None` when they are
/// too few.
fn read<T: Copy>(bytes: &[u8]) -> Option<T> {
    let bytes = bytes.get(..size_of::<T>())?;
    // SAFETY: the bytes cover a whole `T`, every type read here is plain data
    // for which any bytes are valid, and the copy ignores alignment.
    Some(unsafe { ptr::read_unaligned(bytes.as_ptr().cast()) })
}

/// The routes in a dump of the table. Any message that cannot be read makes
/// the whole table unreadable: a route left out could be the one that
/// decides.
pub(super) fn parse_table(mut bytes: &[u8]) -> Result<Vec<Route>> {
    let mut routes = Vec::new();
    while !bytes.is_empty() {
        let length = usize::from(read::<u16>(bytes).ok_or_else(unreadable)?);
        let message = bytes.get(..length).ok_or_else(unreadable)?;
        routes.push(parse_route(message)?);
        bytes = &bytes[length..];
    }
    Ok(routes)
}

fn parse_route(message: &[u8]) -> Result<Route> {
    let header: libc::rt_msghdr = read(message).ok_or_else(unreadable)?;
    if c_int::from(header.rtm_version) != libc::RTM_VERSION {
        return Err(unreadable());
    }
    let after = message.get(HEADER..).ok_or_else(unreadable)?;
    let addresses = socket_addresses(after, header.rtm_addrs)?;
    let flags = header.rtm_flags;
    let dest = addresses[RTAX_DST].and_then(inet).ok_or_else(unreadable)?;
    let mask = match addresses[RTAX_NETMASK] {
        None => u32::MAX,
        Some(mask) => mask_of(mask),
    };
    let prefix_len = prefix_len(mask).ok_or_else(unreadable)?;
    let dest = Ipv4Net::new(Ipv4Addr::from(u32::from(dest) & mask), prefix_len)
        .map_err(|_| unreadable())?;
    let router = if flags & libc::RTF_GATEWAY == 0 {
        None
    } else {
        // A route through a router that is not an IPv4 address is not one
        // this code understands.
        let gateway = addresses[RTAX_GATEWAY].and_then(inet);
        Some(gateway.ok_or_else(unreadable)?)
    };
    Ok(Route {
        dest,
        index: header.rtm_index,
        router,
        flags,
    })
}

/// The socket addresses after a header, by their place, as `addrs` names
/// them: each is the bytes its length byte counts.
fn socket_addresses(bytes: &[u8], addrs: c_int) -> Result<[Option<&[u8]>; RTAX_MAX]> {
    let mut found = [None; RTAX_MAX];
    let mut at = 0;
    for (place, slot) in found.iter_mut().enumerate() {
        if addrs & (1 << place) == 0 {
            continue;
        }
        let rest = bytes.get(at..).ok_or_else(unreadable)?;
        let length = usize::from(*rest.first().ok_or_else(unreadable)?);
        let padded = padded(length);
        rest.get(..padded).ok_or_else(unreadable)?;
        *slot = Some(&rest[..length]);
        at += padded;
    }
    Ok(found)
}

/// A socket address's length rounded up to four bytes, and four for none.
fn padded(length: usize) -> usize {
    if length == 0 {
        4
    } else {
        length.div_ceil(4) * 4
    }
}

/// The IPv4 address in a whole `sockaddr_in`.
fn inet(address: &[u8]) -> Option<Ipv4Addr> {
    match address {
        [_, family, _, _, a, b, c, d, ..] if c_int::from(*family) == libc::AF_INET => {
            Some(Ipv4Addr::new(*a, *b, *c, *d))
        }
        _ => None,
    }
}

/// The mask in a netmask's address bytes, which may be cut short; the
/// bytes left out are zero. Its family byte means nothing.
fn mask_of(address: &[u8]) -> u32 {
    let mut bytes = [0u8; 4];
    for (n, byte) in bytes.iter_mut().enumerate() {
        *byte = address.get(4 + n).copied().unwrap_or(0);
    }
    u32::from_be_bytes(bytes)
}

/// The prefix length of a mask, or `None` when its ones are not all at the
/// front.
pub(super) fn prefix_len(mask: u32) -> Option<u8> {
    let ones = mask.leading_ones();
    let front = u32::MAX.checked_shl(32 - ones).unwrap_or(0);
    // At most 32, so it fits.
    (mask == front).then_some(ones as u8)
}

fn mask(prefix_len: u8) -> u32 {
    u32::MAX
        .checked_shl(32 - u32::from(prefix_len))
        .unwrap_or(0)
}

fn sockaddr_in(addr: Ipv4Addr) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_len: size_of::<libc::sockaddr_in>() as u8,
        sin_family: libc::AF_INET as u8,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from(addr).to_be(),
        },
        sin_zero: [0; 8],
    }
}

/// The plain `sockaddr` that interface requests take, holding `addr`.
fn sockaddr(addr: Ipv4Addr) -> libc::sockaddr {
    // SAFETY: the two are the same size, which `transmute` checks, and a
    // `sockaddr_in` is a `sockaddr` with its data spelt out.
    unsafe { std::mem::transmute::<libc::sockaddr_in, libc::sockaddr>(sockaddr_in(addr)) }
}

/// A link-level address naming only the interface with this index.
fn sockaddr_dl(index: u16) -> libc::sockaddr_dl {
    libc::sockaddr_dl {
        sdl_len: size_of::<libc::sockaddr_dl>() as u8,
        sdl_family: libc::AF_LINK as u8,
        sdl_index: index,
        sdl_type: 0,
        sdl_nlen: 0,
        sdl_alen: 0,
        sdl_slen: 0,
        sdl_data: [0; 12],
    }
}

/// The bytes of a plain value, to put in a message.
fn bytes_of<T>(value: &T) -> &[u8] {
    // SAFETY: the slice covers exactly the value, which outlives it, and
    // every type passed here is plain data with no padding read as
    // uninitialised: each is built from zeroed or fully written fields.
    unsafe { std::slice::from_raw_parts((value as *const T).cast(), size_of::<T>()) }
}

/// What is asked of the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Change {
    Add,
    Delete,
}

static SEQUENCE: AtomicI32 = AtomicI32::new(1);

/// The route message that adds or deletes the route to `dest` out of the
/// interface with this index, through `router` or straight onto the link,
/// with `flags` besides those the route's shape needs. A route through a
/// router also names its interface, so that the kernel does not pick
/// another; a route onto the link names it as its gateway.
pub(super) fn message(
    change: Change,
    dest: Ipv4Net,
    index: u16,
    router: Option<Ipv4Addr>,
    flags: c_int,
) -> Vec<u8> {
    let host = dest.prefix_len() == 32;
    let host_flag = if host { libc::RTF_HOST } else { 0 };
    let gateway_flag = if router.is_some() {
        libc::RTF_GATEWAY
    } else {
        0
    };
    let flags = all(&[
        flags,
        libc::RTF_UP,
        libc::RTF_STATIC,
        host_flag,
        gateway_flag,
    ]);
    // Each socket address with its `RTA_*` bit, in the order of the bits.
    let mut addresses = vec![(libc::RTA_DST, bytes_of(&sockaddr_in(dest.addr())).to_vec())];
    let gateway = match router {
        Some(router) => bytes_of(&sockaddr_in(router)).to_vec(),
        None => bytes_of(&sockaddr_dl(index)).to_vec(),
    };
    addresses.push((libc::RTA_GATEWAY, gateway));
    if !host {
        let netmask = Ipv4Addr::from(mask(dest.prefix_len()));
        addresses.push((libc::RTA_NETMASK, bytes_of(&sockaddr_in(netmask)).to_vec()));
    }
    if router.is_some() && change == Change::Add {
        addresses.push((libc::RTA_IFP, bytes_of(&sockaddr_dl(index)).to_vec()));
    }
    let addrs = all(&addresses.iter().map(|(bit, _)| *bit).collect::<Vec<_>>());
    let body: Vec<u8> = addresses.into_iter().flat_map(|(_, bytes)| bytes).collect();
    // SAFETY: plain data, for which all zeroes is valid.
    let mut header: libc::rt_msghdr = unsafe { zeroed() };
    header.rtm_msglen = (HEADER + body.len()) as u16;
    header.rtm_version = libc::RTM_VERSION as u8;
    header.rtm_type = match change {
        Change::Add => libc::RTM_ADD,
        Change::Delete => libc::RTM_DELETE,
    } as u8;
    // Read by the kernel only for a scoped route, which this never is.
    header.rtm_index = index;
    header.rtm_flags = flags;
    header.rtm_addrs = addrs;
    header.rtm_seq = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let mut message = bytes_of(&header).to_vec();
    message.extend_from_slice(&body);
    message
}

/// Asks the kernel for one change to the table. It answers on the write:
/// `AlreadyExists` when a route to the destination is there already,
/// `NotFound` when there is none to delete.
pub(super) fn change(
    change: Change,
    dest: Ipv4Net,
    index: u16,
    router: Option<Ipv4Addr>,
    flags: c_int,
) -> Result<()> {
    let message = message(change, dest, index, router, flags);
    let socket = new_socket(AddressFamily::ROUTE, SocketType::RAW)?;
    // The kernel takes a route message whole or refuses it.
    match rustix::io::write(&socket, &message) {
        Ok(_) => Ok(()),
        Err(error) => Err(os_error("route", error.into())),
    }
}

/// The flags or bits in `each`, together.
fn all(each: &[c_int]) -> c_int {
    each.iter().copied().fold(0, BitOr::bitor)
}

/// A new socket, closed in any program this one starts.
fn new_socket(family: AddressFamily, kind: SocketType) -> Result<OwnedFd> {
    let socket =
        rustix::net::socket(family, kind, None).map_err(|e| os_error("socket", e.into()))?;
    fcntl_setfd(&socket, FdFlags::CLOEXEC).map_err(|e| os_error("fcntl", e.into()))?;
    Ok(socket)
}

/// Frees what `getifaddrs` returned when dropped.
struct Addresses(*mut libc::ifaddrs);

impl Drop for Addresses {
    fn drop(&mut self) {
        // SAFETY: the list came from `getifaddrs` and is freed once.
        unsafe { libc::freeifaddrs(self.0) }
    }
}

/// The bytes of a socket address the kernel gave, as many as its length
/// byte says.
///
/// # Safety
///
/// `address` is null or points to a socket address that is valid for its
/// length byte and outlives the slice.
unsafe fn address_bytes<'a>(address: *const libc::sockaddr) -> Option<&'a [u8]> {
    // SAFETY: as the caller promises.
    let length = usize::from(unsafe { address.as_ref() }?.sa_len);
    // SAFETY: as the caller promises.
    Some(unsafe { std::slice::from_raw_parts(address.cast(), length) })
}

/// Every network interface, with its addresses, by name.
pub(super) fn interfaces() -> Result<Vec<Interface>> {
    let mut list = ptr::null_mut();
    // SAFETY: the call writes the head of a list it allocates to `list`.
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return Err(os_error("getifaddrs", io::Error::last_os_error()));
    }
    let list = Addresses(list);
    let mut found: BTreeMap<String, Interface> = BTreeMap::new();
    let mut next = list.0;
    // SAFETY: each entry is valid until the list is freed, which is after
    // the loop, and each address in it is valid for its length byte.
    while let Some(entry) = unsafe { next.as_ref() } {
        next = entry.ifa_next;
        // SAFETY: the name is a NUL-terminated string in the entry.
        let name = unsafe { CStr::from_ptr(entry.ifa_name) };
        let name = name.to_string_lossy().into_owned();
        let interface = found
            .entry(name.clone())
            .or_insert_with(|| Interface::named(name));
        interface.flags = entry.ifa_flags as c_int;
        // SAFETY: as above.
        let Some(address) = (unsafe { address_bytes(entry.ifa_addr) }) else {
            continue;
        };
        match address.get(1).map(|family| c_int::from(*family)) {
            Some(libc::AF_LINK) => {
                let link: libc::sockaddr_dl = read(address).ok_or_else(unreadable)?;
                interface.index = link.sdl_index;
                // SAFETY: a link entry's data, when there is any, is the
                // interface's `if_data`.
                if let Some(data) = unsafe { entry.ifa_data.cast::<libc::if_data>().as_ref() } {
                    interface.mtu = data.ifi_mtu;
                }
            }
            Some(libc::AF_INET) => {
                let addr = inet(address).ok_or_else(unreadable)?;
                // SAFETY: as above.
                let netmask = unsafe { address_bytes(entry.ifa_netmask) };
                let prefix_len = prefix_len(netmask.map_or(u32::MAX, mask_of));
                let prefix_len = prefix_len.ok_or_else(unreadable)?;
                let point_to_point = entry.ifa_flags as c_int & libc::IFF_POINTOPOINT != 0;
                // SAFETY: as above.
                let peer = unsafe { address_bytes(entry.ifa_dstaddr) }.and_then(inet);
                interface.v4.push(V4Address {
                    addr,
                    prefix_len,
                    peer: peer.filter(|_| point_to_point),
                });
            }
            Some(libc::AF_INET6) => {
                interface.v6.push(read(address).ok_or_else(unreadable)?);
            }
            _ => {}
        }
    }
    Ok(found.into_values().collect())
}

/// A request naming the interface `name`. A name too long for one is no
/// interface's.
fn request<T>(name: &str) -> Result<T> {
    let name = CString::new(name).map_err(|_| Error::NotFound)?;
    let name = name.as_bytes_with_nul();
    let mut field = [0u8; libc::IFNAMSIZ];
    let room = field.get_mut(..name.len()).ok_or(Error::NotFound)?;
    room.copy_from_slice(name);
    // SAFETY: every request type passed here is plain data that starts
    // with the interface's name, for which all zeroes is valid.
    let mut request: T = unsafe { zeroed() };
    // SAFETY: every such request starts with IFNAMSIZ bytes for the name.
    unsafe { ptr::copy_nonoverlapping(field.as_ptr(), (&raw mut request).cast(), field.len()) };
    Ok(request)
}

/// A socket to send interface requests on, for IPv4 or IPv6.
/// Sends the interface request `request` with the ioctl `number`.
fn ioctl<T>(family: AddressFamily, call: &str, number: c_ulong, request: &mut T) -> Result<()> {
    let socket = new_socket(family, SocketType::DGRAM)?;
    // SAFETY: `request` is a live value of the type the ioctl's number
    // encodes the size of, for the call to read and write.
    let status = unsafe {
        libc::ioctl(
            socket.as_raw_fd(),
            number,
            (request as *mut T).cast::<libc::c_void>(),
        )
    };
    match status {
        0 => Ok(()),
        _ => Err(os_error(call, io::Error::last_os_error())),
    }
}

/// Brings the interface up, or takes it down.
pub(super) fn set_up(name: &str, up: bool) -> Result<()> {
    let mut flags: libc::ifreq = request(name)?;
    ioctl(
        AddressFamily::INET,
        "SIOCGIFFLAGS",
        SIOCGIFFLAGS,
        &mut flags,
    )?;
    // SAFETY: the call filled in the flags.
    let before = unsafe { flags.ifr_ifru.ifru_flags };
    let after = if up {
        before | libc::IFF_UP as libc::c_short
    } else {
        before & !(libc::IFF_UP as libc::c_short)
    };
    if after == before {
        return Ok(());
    }
    flags.ifr_ifru.ifru_flags = after;
    ioctl(
        AddressFamily::INET,
        "SIOCSIFFLAGS",
        SIOCSIFFLAGS,
        &mut flags,
    )
}

/// Sets the interface's largest packet size.
pub(super) fn set_mtu(name: &str, mtu: u16) -> Result<()> {
    let mut request: libc::ifreq = request(name)?;
    request.ifr_ifru.ifru_mtu = c_int::from(mtu);
    ioctl(AddressFamily::INET, "SIOCSIFMTU", SIOCSIFMTU, &mut request)
}

/// Gives the interface the address `addr` with this prefix length and, on
/// a point-to-point interface, the other end `peer`.
pub(super) fn add_address(
    name: &str,
    addr: Ipv4Addr,
    prefix_len: u8,
    peer: Option<Ipv4Addr>,
) -> Result<()> {
    let mut request: libc::ifaliasreq = request(name)?;
    request.ifra_addr = sockaddr(addr);
    if let Some(peer) = peer {
        request.ifra_broadaddr = sockaddr(peer);
    }
    request.ifra_mask = sockaddr(Ipv4Addr::from(mask(prefix_len)));
    ioctl(
        AddressFamily::INET,
        "SIOCAIFADDR",
        SIOCAIFADDR,
        &mut request,
    )
}

/// Takes the address `addr` off the interface.
pub(super) fn remove_address(name: &str, addr: Ipv4Addr) -> Result<()> {
    let mut request: libc::ifreq = request(name)?;
    request.ifr_ifru.ifru_addr = sockaddr(addr);
    ioctl(
        AddressFamily::INET,
        "SIOCDIFADDR",
        SIOCDIFADDR,
        &mut request,
    )
}

/// Takes the IPv6 address `address`, as the kernel listed it, off the
/// interface.
pub(super) fn remove_ipv6(name: &str, address: &libc::sockaddr_in6) -> Result<()> {
    let mut request: libc::in6_ifreq = request(name)?;
    request.ifr_ifru.ifru_addr = *address;
    ioctl(
        AddressFamily::INET6,
        "SIOCDIFADDR_IN6",
        SIOCDIFADDR_IN6,
        &mut request,
    )
}
