//! The routing table and the tunnel's address, through the IP Helper API.
//!
//! Interfaces are named by their alias, which is how the engine reports the
//! tunnel; the alias is looked up again on every call. A route is identified
//! by destination, interface LUID and next hop.
//!
//! Windows keeps routes to one destination through two interfaces side by
//! side and refuses only an identical one, so every add first reads the table
//! and fails with `AlreadyExists` when the destination is routed elsewhere.
//!
//! Full mode adds the two IPv4 halves and, on a tunnel that has IPv6 but no
//! IPv6 address, the two IPv6 halves, which make IPv6 fail at once. The OS's
//! best-route lookup fails for a destination those cover (there is no
//! source address), so IPv6 checks match the forwarding table themselves.
//!
//! IPv4 checks match the forwarding table too, for another reason: the
//! best-route lookup skips an on-link route when the neighbour cache marks
//! the destination unreachable, and falls back to a less specific route, so
//! its answer depends on which neighbours answered lately rather than on the
//! routes. See [`table_through`].

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
#[cfg(test)]
use std::path::Path;
use std::ptr::{null, null_mut};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use ubc_vpn_core::routes::Ipv4Net;
use windows_sys::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToAlias, CreateIpForwardEntry2,
    CreateUnicastIpAddressEntry, DeleteIpForwardEntry2, DeleteUnicastIpAddressEntry, FreeMibTable,
    GetBestRoute2, GetIfEntry2, GetIfTable2, GetIpForwardTable2, GetIpInterfaceEntry,
    GetIpInterfaceTable, GetUnicastIpAddressTable, IF_TYPE_PROP_VIRTUAL, InitializeIpForwardEntry,
    InitializeIpInterfaceEntry, InitializeUnicastIpAddressEntry, MIB_IF_ROW2, MIB_IF_TABLE2,
    MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW, MIB_IPINTERFACE_TABLE,
    MIB_UNICASTIPADDRESS_ROW, MIB_UNICASTIPADDRESS_TABLE, SetIpInterfaceEntry,
};
use windows_sys::Win32::NetworkManagement::Ndis::{IfOperStatusUp, NET_LUID_LH};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, IpDadStateDeprecated, IpDadStateDuplicate, IpDadStatePreferred,
    IpDadStateTentative, MIB_IPPROTO_NETMGMT, NL_DAD_STATE, RouterDiscoveryDisabled, SOCKADDR_INET,
};
use windows_sys::Win32::System::SystemInformation::GetTickCount64;

use super::journal::{Boot, Journal, Prefix, Row, Store};
use super::security::{os_error, wide};
use crate::on_link::{AddressRow, DadState, usable_networks};
use crate::{
    Error, FULL_TUNNEL_V4, FULL_TUNNEL_V6, Ipv6Block, Mode, Paths, PhysicalNetwork, Result, Routes,
    TUNNEL_MTU, Verified, lock,
};

pub(super) fn v4(addr: Ipv4Addr) -> SOCKADDR_INET {
    // SAFETY: SOCKADDR_INET is a plain union for which all zeroes is valid.
    let mut socket: SOCKADDR_INET = unsafe { std::mem::zeroed() };
    socket.si_family = AF_INET;
    socket.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(addr.octets());
    socket
}

pub(super) fn v6(addr: Ipv6Addr) -> SOCKADDR_INET {
    // SAFETY: SOCKADDR_INET is a plain union for which all zeroes is valid.
    let mut socket: SOCKADDR_INET = unsafe { std::mem::zeroed() };
    socket.si_family = AF_INET6;
    socket.Ipv6.sin6_addr.u.Byte = addr.octets();
    socket
}

fn sockaddr(ip: IpAddr) -> SOCKADDR_INET {
    match ip {
        IpAddr::V4(ip) => v4(ip),
        IpAddr::V6(ip) => v6(ip),
    }
}

/// The address in `socket`, of either family.
fn ip_of(socket: &SOCKADDR_INET) -> Option<IpAddr> {
    if let Some(ip) = addr_of(socket) {
        return Some(IpAddr::V4(ip));
    }
    // SAFETY: as in `addr_of`, the IPv6 member is read only when the family
    // says it is the one in use.
    unsafe {
        (socket.si_family == AF_INET6)
            .then(|| IpAddr::V6(Ipv6Addr::from(socket.Ipv6.sin6_addr.u.Byte)))
    }
}

pub(super) fn addr_of(socket: &SOCKADDR_INET) -> Option<Ipv4Addr> {
    // SAFETY: every member of the union starts with the family, and the
    // IPv4 member is read only when the family says it is the one in use.
    unsafe {
        (socket.si_family == AF_INET)
            .then(|| Ipv4Addr::from(socket.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes()))
    }
}

/// The result of an IP Helper call as this crate's result.
pub(super) fn checked(code: u32) -> Result<()> {
    match code {
        0 => Ok(()),
        ERROR_OBJECT_ALREADY_EXISTS => Err(Error::AlreadyExists),
        ERROR_NOT_FOUND | ERROR_FILE_NOT_FOUND => Err(Error::NotFound),
        code => Err(os_error(code)),
    }
}

/// The LUID of the interface named `alias`.
pub(super) fn luid(alias: &str) -> Result<u64> {
    let name = wide(alias);
    let mut luid = NET_LUID_LH { Value: 0 };
    // SAFETY: `name` is NUL-terminated and outlives the call; the out
    // pointer is valid.
    let code = unsafe { ConvertInterfaceAliasToLuid(name.as_ptr(), &mut luid) };
    // An unknown name is reported as an invalid parameter.
    const ERROR_INVALID_PARAMETER: u32 = 87;
    match code {
        ERROR_INVALID_PARAMETER => Err(Error::NotFound),
        code => checked(code).map(|()| value(&luid)),
    }
}

/// A LUID as the number it is.
pub(super) fn value(luid: &NET_LUID_LH) -> u64 {
    // SAFETY: both members of the union are a plain u64 underneath, so
    // either can be read whichever was written.
    unsafe { luid.Value }
}

/// The name of the interface with `luid`.
pub(super) fn alias(luid: u64) -> Result<String> {
    let mut name = [0u16; 257];
    // SAFETY: the LUID is plain data and the buffer is writable for its
    // length, which is what the call is told.
    checked(unsafe {
        ConvertInterfaceLuidToAlias(&net_luid(luid), name.as_mut_ptr(), name.len())
    })?;
    let len = name
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(name.len());
    Ok(String::from_utf16_lossy(&name[..len]))
}

fn net_luid(value: u64) -> NET_LUID_LH {
    NET_LUID_LH { Value: value }
}

/// A table IP Helper allocated. Dropping it frees it.
struct Table<T>(*mut T);

impl<T> Drop for Table<T> {
    fn drop(&mut self) {
        // SAFETY: the pointer came from a Get…Table2 call and is freed once.
        unsafe { FreeMibTable(self.0.cast()) };
    }
}

/// Every IPv4 route in the system's table.
pub(super) fn route_table() -> Result<Vec<MIB_IPFORWARD_ROW2>> {
    routes_of(AF_INET)
}

/// Every route of one family in the system's table.
pub(super) fn routes_of(family: u16) -> Result<Vec<MIB_IPFORWARD_ROW2>> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = null_mut();
    // SAFETY: the out pointer is valid; the table is freed by `Table`.
    checked(unsafe { GetIpForwardTable2(family, &mut table) })?;
    let table = Table(table);
    // SAFETY: on success the table holds `NumEntries` initialised rows.
    let rows = unsafe {
        std::slice::from_raw_parts((*table.0).Table.as_ptr(), (*table.0).NumEntries as usize)
    };
    Ok(rows.to_vec())
}

/// Every IPv4 address on the machine.
pub(super) fn address_table() -> Result<Vec<MIB_UNICASTIPADDRESS_ROW>> {
    addresses_of(AF_INET)
}

/// Every address of one family on the machine.
pub(super) fn addresses_of(family: u16) -> Result<Vec<MIB_UNICASTIPADDRESS_ROW>> {
    let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = null_mut();
    // SAFETY: the out pointer is valid; the table is freed by `Table`.
    checked(unsafe { GetUnicastIpAddressTable(family, &mut table) })?;
    let table = Table(table);
    // SAFETY: on success the table holds `NumEntries` initialised rows.
    let rows = unsafe {
        std::slice::from_raw_parts((*table.0).Table.as_ptr(), (*table.0).NumEntries as usize)
    };
    Ok(rows.to_vec())
}

/// The LUIDs of the interfaces that are up now.
fn up_interfaces() -> Result<HashSet<u64>> {
    let mut table: *mut MIB_IF_TABLE2 = null_mut();
    // SAFETY: the out pointer is valid; the table is freed by `Table`.
    checked(unsafe { GetIfTable2(&mut table) })?;
    let table = Table(table);
    // SAFETY: on success the table holds `NumEntries` initialised rows.
    let rows = unsafe {
        std::slice::from_raw_parts((*table.0).Table.as_ptr(), (*table.0).NumEntries as usize)
    };
    let up = rows.iter().filter(|row| row.OperStatus == IfOperStatusUp);
    Ok(up.map(|row| value(&row.InterfaceLuid)).collect())
}

/// The interfaces a route of `family` can be used on now, each with its
/// interface metric for that family: those that are up and have the family
/// bound. A route on any other interface carries nothing.
fn usable_interfaces(family: u16) -> Result<HashMap<u64, u32>> {
    let up = up_interfaces()?;
    let mut table: *mut MIB_IPINTERFACE_TABLE = null_mut();
    // SAFETY: the out pointer is valid; the table is freed by `Table`.
    checked(unsafe { GetIpInterfaceTable(family, &mut table) })?;
    let table = Table(table);
    // SAFETY: on success the table holds `NumEntries` initialised rows.
    let rows = unsafe {
        std::slice::from_raw_parts((*table.0).Table.as_ptr(), (*table.0).NumEntries as usize)
    };
    Ok(usable(rows.iter().map(ip_interface), &up))
}

/// An interface of one family as (LUID, interface metric). `Metric` is the
/// metric in effect, also when Windows chooses it (`UseAutomaticMetric`).
fn ip_interface(row: &MIB_IPINTERFACE_ROW) -> (u64, u32) {
    (value(&row.InterfaceLuid), row.Metric)
}

/// Of the interfaces with a family bound, as (LUID, interface metric),
/// those that are up.
fn usable(bound: impl Iterator<Item = (u64, u32)>, up: &HashSet<u64>) -> HashMap<u64, u32> {
    bound.filter(|(luid, _)| up.contains(luid)).collect()
}

/// A route as route selection sees it, of either family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TableRoute {
    dest: Prefix,
    luid: u64,
    /// The route's own metric, which Windows adds to its interface's.
    metric: u32,
}

/// A system route as a [`TableRoute`]; `None` for one this code cannot
/// read.
fn table_route(row: &MIB_IPFORWARD_ROW2) -> Option<TableRoute> {
    Some(TableRoute {
        dest: prefix_of(row)?,
        luid: value(&row.InterfaceLuid),
        metric: row.Metric,
    })
}

/// Whether the route Windows' table chooses for `dest` goes through
/// `wanted`, judged from the routes alone, as Windows chooses with every
/// neighbour reachable. The same rule holds for both families:
///
/// - only routes on an interface in `interfaces` count: those up with the
///   family bound, each mapped to its interface metric;
/// - the longest prefix that holds `dest` wins, whatever its metric;
/// - among those, the lowest sum of route and interface metric wins, which
///   is the metric Windows documents for `MIB_IPFORWARD_ROW2`.
///
/// Several winners of equal metric could each be used: `Yes` only when all
/// go through `wanted`, `No` only when none does, and `Unknown` when they
/// disagree, so a tie never passes a check either way. No route at all is
/// `No`.
///
/// An interface's `DisableDefaultRoutes` is not read, so a default route
/// (`0.0.0.0/0` or `::/0`) on such an interface still counts. That is
/// harmless today because the product adds no default route. A check that
/// needs `Yes` asks about an address one of its longer routes covers, which
/// beats any default route. A check that needs `No` could only be misled by
/// a default route somebody else put on the tunnel, beaten on metric by a
/// default route on an interface that disables default routes.
///
/// This is not `GetBestRoute2`. That lookup skips an on-link route when the
/// neighbour cache marks the destination unreachable, as after something
/// scanned the local network, and falls back to a less specific route such
/// as a half of full mode. Its answer then depends on which neighbours
/// answered lately, not on the routes the product set and checks. For IPv6
/// it fails outright for an address the IPv6 halves cover, since the tunnel
/// has no IPv6 source address.
fn table_through(
    routes: &[TableRoute],
    interfaces: &HashMap<u64, u32>,
    dest: IpAddr,
    wanted: u64,
) -> Verified {
    let candidates: Vec<(TableRoute, u64)> = routes
        .iter()
        .filter(|route| route.dest.contains(dest))
        .filter_map(|route| {
            let interface = interfaces.get(&route.luid)?;
            Some((*route, u64::from(route.metric) + u64::from(*interface)))
        })
        .collect();
    let Some(longest) = candidates.iter().map(|(r, _)| r.dest.len()).max() else {
        return Verified::No;
    };
    let longest: Vec<_> = candidates
        .into_iter()
        .filter(|(route, _)| route.dest.len() == longest)
        .collect();
    let Some(lowest) = longest.iter().map(|(_, metric)| *metric).min() else {
        return Verified::No;
    };
    let chosen = longest.iter().filter(|(_, metric)| *metric == lowest);
    let (mut through, mut elsewhere) = (false, false);
    for (route, _) in chosen {
        match route.luid == wanted {
            true => through = true,
            false => elsewhere = true,
        }
    }
    match (through, elsewhere) {
        (true, false) => Verified::Yes,
        (false, true) => Verified::No,
        _ => Verified::Unknown,
    }
}

/// [`table_through`] over the system's table of `family`, for the
/// interface named `interface`. `Unknown` when a table cannot be read.
fn system_through(family: u16, dest: IpAddr, interface: &str) -> Verified {
    let (Ok(table), Ok(interfaces)) = (routes_of(family), usable_interfaces(family)) else {
        return Verified::Unknown;
    };
    let wanted = match luid(interface) {
        Ok(luid) => luid,
        // An interface that does not exist is not the one used.
        Err(Error::NotFound) => return Verified::No,
        Err(_) => return Verified::Unknown,
    };
    let routes: Vec<TableRoute> = table.iter().filter_map(table_route).collect();
    table_through(&routes, &interfaces, dest, wanted)
}

/// An IPv4 address of the system's table, with what decides whether it is
/// used, for [`usable_networks`]. Its interface is up when `up` holds it.
fn address_row(row: &MIB_UNICASTIPADDRESS_ROW, up: &HashSet<u64>) -> Option<AddressRow> {
    Some(AddressRow {
        addr: addr_of(&row.Address)?,
        prefix_len: row.OnLinkPrefixLength,
        state: dad_state(row.DadState),
        interface_up: up.contains(&value(&row.InterfaceLuid)),
    })
}

/// Every IPv4 address among `rows`, used or not, whatever its state and
/// its interface's: see [`PhysicalNetwork::own_addresses`], whose every use
/// is weaker with fewer.
fn own_addresses(rows: &[MIB_UNICASTIPADDRESS_ROW]) -> Vec<Ipv4Addr> {
    rows.iter()
        .filter_map(|row| addr_of(&row.Address))
        .collect()
}

/// Windows' duplicate address detection state as [`DadState`]. One this
/// code does not know is not valid.
// The states are constants of the API, named as Windows names them.
#[allow(non_upper_case_globals)]
fn dad_state(state: NL_DAD_STATE) -> DadState {
    match state {
        IpDadStatePreferred => DadState::Preferred,
        IpDadStateDeprecated => DadState::Deprecated,
        IpDadStateTentative => DadState::Tentative,
        IpDadStateDuplicate => DadState::Duplicate,
        _ => DadState::Invalid,
    }
}

/// The route the system would use to reach `dest`.
pub(super) fn best_route(dest: Ipv4Addr) -> Result<MIB_IPFORWARD_ROW2> {
    // SAFETY: both rows are plain data for which all zeroes is valid.
    let (mut route, mut source): (MIB_IPFORWARD_ROW2, SOCKADDR_INET) =
        unsafe { std::mem::zeroed() };
    let dest = v4(dest);
    // SAFETY: the optional inputs are null, the destination and both out
    // pointers are valid for the call.
    checked(unsafe { GetBestRoute2(null(), 0, null(), &dest, 0, &mut route, &mut source) })?;
    Ok(route)
}

pub(super) fn row_dest(row: &MIB_IPFORWARD_ROW2) -> Option<Ipv4Net> {
    let addr = addr_of(&row.DestinationPrefix.Prefix)?;
    Ipv4Net::new(addr, row.DestinationPrefix.PrefixLength).ok()
}

/// The destination of a system route, of either family.
fn prefix_of(row: &MIB_IPFORWARD_ROW2) -> Option<Prefix> {
    let len = row.DestinationPrefix.PrefixLength;
    match ip_of(&row.DestinationPrefix.Prefix)? {
        IpAddr::V4(addr) => Ipv4Net::new(addr, len).ok().map(Prefix::V4),
        IpAddr::V6(addr) => Prefix::v6(addr, len),
    }
}

/// A forwarding row for one route, ready to add or delete.
fn forward_row(row: &Row) -> MIB_IPFORWARD_ROW2 {
    // SAFETY: plain data for which all zeroes is valid; then initialised.
    let mut forward: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
    // SAFETY: the pointer is to a valid row.
    unsafe { InitializeIpForwardEntry(&mut forward) };
    forward.InterfaceLuid = net_luid(row.luid);
    forward.DestinationPrefix.Prefix = match row.dest {
        Prefix::V4(net) => v4(net.addr()),
        Prefix::V6(addr, _) => v6(addr),
    };
    forward.DestinationPrefix.PrefixLength = row.dest.len();
    forward.NextHop = sockaddr(row.next_hop);
    forward.Metric = 0;
    forward.Protocol = MIB_IPPROTO_NETMGMT;
    forward
}

/// The boot this process runs in.
pub(super) fn boot() -> Boot {
    // SAFETY: no preconditions.
    let uptime = unsafe { GetTickCount64() } / 1000;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    Boot {
        started: now.saturating_sub(uptime),
        uptime,
    }
}

/// What is there already for one route.
enum Present {
    None,
    Identical,
    Elsewhere,
}

fn present(row: &Row) -> Result<Present> {
    let family = match row.dest {
        Prefix::V4(_) => AF_INET,
        Prefix::V6(..) => AF_INET6,
    };
    let table = routes_of(family)?;
    let same_dest = table.iter().filter(|r| prefix_of(r) == Some(row.dest));
    let mut found = Present::None;
    for existing in same_dest {
        let luid = value(&existing.InterfaceLuid);
        if luid == row.luid && ip_of(&existing.NextHop) == Some(row.next_hop) {
            found = Present::Identical;
        } else {
            return Ok(Present::Elsewhere);
        }
    }
    Ok(found)
}

#[cfg(test)]
thread_local! {
    /// Makes an add on this thread stop, as a crash would, between writing
    /// its journal row and adding its route.
    pub(super) static CRASH_BEFORE_ADD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

pub(crate) struct WinRoutes {
    journal: Mutex<Journal>,
}

impl WinRoutes {
    /// Routes whose journal is in the service's state folder for `mode`.
    pub(crate) fn new(mode: Mode, paths: &Paths) -> Self {
        let store = Store::Checked(mode, paths.clone());
        Self {
            journal: Mutex::new(Journal::new(store)),
        }
    }

    /// Routes whose journal is in `dir`, with no checks on the folder.
    #[cfg(test)]
    pub(crate) fn unchecked(dir: &Path) -> Self {
        let store = Store::Unchecked(dir.to_path_buf());
        Self {
            journal: Mutex::new(Journal::new(store)),
        }
    }

    /// Adds one route the exclusive way the contract asks for.
    fn add(&self, row: Row) -> Result<()> {
        let mut journal = lock(&self.journal);
        match present(&row)? {
            Present::Identical => return Ok(()),
            Present::Elsewhere => return Err(Error::AlreadyExists),
            Present::None => {}
        }
        let now = boot();
        let mut rows = journal.rows(now)?;
        if !rows.contains(&row) {
            rows.push(row.clone());
        }
        // The row goes in first, so a crash never leaves a route of ours
        // that the journal does not name.
        journal.write(now, &rows)?;
        #[cfg(test)]
        if CRASH_BEFORE_ADD.with(std::cell::Cell::get) {
            panic!("a crash between writing the row and adding the route");
        }
        // SAFETY: the row is a valid, initialised forwarding row.
        let added = checked(unsafe { CreateIpForwardEntry2(&forward_row(&row)) });
        if added.is_err() {
            rows.retain(|kept| *kept != row);
            journal.write(now, &rows)?;
        }
        match added {
            // Somebody added the same route in the meantime: it is theirs.
            Err(Error::AlreadyExists) => match present(&row)? {
                Present::Identical => Ok(()),
                _ => Err(Error::AlreadyExists),
            },
            other => other,
        }
    }

    /// Removes the rows `which` picks out, and their routes.
    fn remove(&self, which: impl Fn(&Row) -> bool) -> Result<()> {
        let mut journal = lock(&self.journal);
        let now = boot();
        let rows = journal.rows(now)?;
        let mut kept = Vec::new();
        let mut failed = None;
        for row in rows {
            if !which(&row) {
                kept.push(row);
                continue;
            }
            // SAFETY: the row is a valid, initialised forwarding row.
            match checked(unsafe { DeleteIpForwardEntry2(&forward_row(&row)) }) {
                // Gone already, or with its interface.
                Ok(()) | Err(Error::NotFound) => {}
                Err(error) => {
                    failed = Some(error);
                    kept.push(row);
                }
            }
        }
        journal.write(now, &kept)?;
        failed.map_or(Ok(()), Err)
    }
}

/// The tunnel named `alias`, checked to be a virtual device such as Wintun's
/// and not a physical one.
fn tunnel_luid(alias: &str) -> Result<u64> {
    let luid = luid(alias)?;
    // SAFETY: plain data for which all zeroes is valid.
    let mut row: MIB_IF_ROW2 = unsafe { std::mem::zeroed() };
    row.InterfaceLuid = net_luid(luid);
    // SAFETY: the row names the interface and is valid for the call.
    checked(unsafe { GetIfEntry2(&mut row) })?;
    if row.Type != IF_TYPE_PROP_VIRTUAL {
        let message = format!("{alias} is not a tunnel device (type {})", row.Type);
        return Err(Error::Failed(message));
    }
    Ok(luid)
}

/// Turns off what would give the device IPv6 addresses of its own, and
/// removes those it has.
fn quiet_ipv6(luid: u64) -> Result<()> {
    // SAFETY: plain data for which all zeroes is valid; then initialised.
    let mut row: MIB_IPINTERFACE_ROW = unsafe { std::mem::zeroed() };
    // SAFETY: the pointer is to a valid row.
    unsafe { InitializeIpInterfaceEntry(&mut row) };
    row.Family = AF_INET6;
    row.InterfaceLuid = net_luid(luid);
    // SAFETY: the row names the interface and is valid for the call.
    match checked(unsafe { GetIpInterfaceEntry(&mut row) }) {
        // IPv6 is not bound to the device at all.
        Err(Error::NotFound) => return Ok(()),
        other => other?,
    }
    row.RouterDiscoveryBehavior = RouterDiscoveryDisabled;
    row.ManagedAddressConfigurationSupported = false;
    row.OtherStatefulConfigurationSupported = false;
    // Documented: must be zero when setting.
    row.SitePrefixLength = 0;
    // SAFETY: the row was read back for this interface and is valid.
    checked(unsafe { SetIpInterfaceEntry(&mut row) })?;
    for address in addresses_of(AF_INET6)?
        .iter()
        .filter(|r| value(&r.InterfaceLuid) == luid)
    {
        // SAFETY: the row came from the system's own table.
        match checked(unsafe { DeleteUnicastIpAddressEntry(address) }) {
            Ok(()) | Err(Error::NotFound) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

impl Routes for WinRoutes {
    fn capture_physical(&self, gateway: Ipv4Addr) -> Result<PhysicalNetwork> {
        let route = best_route(gateway)?;
        let luid = value(&route.InterfaceLuid);
        let interface = alias(luid)?;
        let next_hop = addr_of(&route.NextHop).filter(|hop| !hop.is_unspecified());
        let addresses = address_table()?;
        let own_addresses = own_addresses(&addresses);
        let up = up_interfaces()?;
        let rows = addresses.iter().filter_map(|row| address_row(row, &up));
        let mut on_link = usable_networks(rows);
        on_link.sort_by_key(|net| (net.addr(), net.prefix_len()));
        on_link.dedup();
        Ok(PhysicalNetwork {
            interface,
            next_hop,
            own_addresses,
            on_link,
        })
    }

    fn configure_tunnel(&self, tunnel: &str, address: Ipv4Addr, mtu: u16) -> Result<()> {
        if !TUNNEL_MTU.contains(&mtu) {
            return Err(Error::InvalidInput);
        }
        let luid = tunnel_luid(tunnel)?;
        quiet_ipv6(luid)?;
        let mut ours = false;
        for row in address_table()?
            .iter()
            .filter(|r| value(&r.InterfaceLuid) == luid)
        {
            if addr_of(&row.Address) == Some(address) && row.OnLinkPrefixLength == 32 {
                ours = true;
                continue;
            }
            // SAFETY: the row came from the system's own table.
            match checked(unsafe { DeleteUnicastIpAddressEntry(row) }) {
                Ok(()) | Err(Error::NotFound) => {}
                Err(error) => return Err(error),
            }
        }
        if !ours {
            // SAFETY: plain data for which all zeroes is valid; then
            // initialised.
            let mut row: MIB_UNICASTIPADDRESS_ROW = unsafe { std::mem::zeroed() };
            // SAFETY: the pointer is to a valid row.
            unsafe { InitializeUnicastIpAddressEntry(&mut row) };
            row.InterfaceLuid = net_luid(luid);
            row.Address = v4(address);
            row.OnLinkPrefixLength = 32;
            row.DadState = IpDadStatePreferred;
            // SAFETY: the row is valid and initialised.
            match checked(unsafe { CreateUnicastIpAddressEntry(&row) }) {
                Ok(()) | Err(Error::AlreadyExists) => {}
                Err(error) => return Err(error),
            }
        }
        // SAFETY: plain data for which all zeroes is valid; then initialised.
        let mut row: MIB_IPINTERFACE_ROW = unsafe { std::mem::zeroed() };
        // SAFETY: the pointer is to a valid row.
        unsafe { InitializeIpInterfaceEntry(&mut row) };
        row.Family = AF_INET;
        row.InterfaceLuid = net_luid(luid);
        // SAFETY: the row names the interface and is valid for the call.
        checked(unsafe { GetIpInterfaceEntry(&mut row) })?;
        row.NlMtu = u32::from(mtu);
        // Documented: must be zero when setting an IPv4 interface.
        row.SitePrefixLength = 0;
        // SAFETY: the row was read back for this interface and is valid.
        checked(unsafe { SetIpInterfaceEntry(&mut row) })
    }

    fn add_gateway_route(&self, gateway: Ipv4Addr, via: &PhysicalNetwork) -> Result<()> {
        let dest = Ipv4Net::new(gateway, 32).map_err(|e| Error::Failed(e.to_string()))?;
        self.add(Row {
            dest: Prefix::V4(dest),
            luid: luid(&via.interface)?,
            next_hop: IpAddr::V4(via.next_hop.unwrap_or(Ipv4Addr::UNSPECIFIED)),
            interface: via.interface.clone(),
        })
    }

    fn remove_gateway_route(&self, gateway: Ipv4Addr, via: &PhysicalNetwork) -> Result<()> {
        let next_hop = IpAddr::V4(via.next_hop.unwrap_or(Ipv4Addr::UNSPECIFIED));
        let dest = Ipv4Net::new(gateway, 32).map_err(|e| Error::Failed(e.to_string()))?;
        self.remove(|row| {
            row.dest == Prefix::V4(dest)
                && row.interface == via.interface
                && row.next_hop == next_hop
        })
    }

    fn add_tunnel_routes(&self, tunnel: &str, subnets: &[Ipv4Net]) -> Result<()> {
        let luid = tunnel_luid(tunnel)?;
        for dest in subnets {
            self.add(Row {
                dest: Prefix::V4(*dest),
                luid,
                next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                interface: tunnel.to_string(),
            })?;
        }
        Ok(())
    }

    fn remove_tunnel_routes(&self, tunnel: &str, subnets: &[Ipv4Net]) -> Result<()> {
        self.remove(|row| {
            let listed = matches!(row.dest, Prefix::V4(net) if subnets.contains(&net));
            row.interface == tunnel && row.next_hop.is_unspecified() && listed
        })
    }

    fn remove_all(&self) -> Result<()> {
        self.remove(|_| true)
    }

    /// The forwarding table's choice, by [`table_through`], not
    /// `GetBestRoute2`'s, whose answer changes with neighbour reachability.
    fn uses_interface(&self, dest: Ipv4Addr, interface: &str) -> Verified {
        system_through(AF_INET, IpAddr::V4(dest), interface)
    }

    fn full_tunnel_ipv6(&self, tunnel: &str) -> Result<Ipv6Block> {
        ipv6_decision(tunnel_luid(tunnel)?)
    }

    fn add_full_tunnel(&self, tunnel: &str) -> Result<Ipv6Block> {
        let luid = tunnel_luid(tunnel)?;
        // Decided before anything is added, so a refusal leaves nothing.
        let blocks = ipv6_decision(luid)? == Ipv6Block::Blocked;
        let row = |dest| Row {
            dest,
            luid,
            next_hop: match dest {
                Prefix::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                Prefix::V6(..) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            },
            interface: tunnel.to_string(),
        };
        let (v4_halves, v6_halves) = halves();
        for half in v4_halves {
            self.add(row(half))?;
        }
        if !blocks {
            return Ok(Ipv6Block::NothingToBlock);
        }
        for half in v6_halves {
            match self.add(row(half)) {
                Ok(()) => {}
                // IPv6 was unbound from the device since it was checked.
                Err(Error::NotFound) => {
                    if leak_path(luid)? {
                        self.remove_full_tunnel(tunnel)?;
                        return Err(Error::Unsupported);
                    }
                    return Ok(Ipv6Block::NothingToBlock);
                }
                Err(error) => return Err(error),
            }
        }
        Ok(Ipv6Block::Blocked)
    }

    fn remove_full_tunnel(&self, tunnel: &str) -> Result<()> {
        let (v4_halves, v6_halves) = halves();
        self.remove(|row| {
            let half = v4_halves.contains(&row.dest) || v6_halves.contains(&row.dest);
            row.interface == tunnel && row.next_hop.is_unspecified() && half
        })
    }

    fn foreign_full_tunnel(&self, tunnel: &str) -> Result<bool> {
        let tunnel = match luid(tunnel) {
            Ok(luid) => Some(luid),
            Err(Error::NotFound) => None,
            Err(error) => return Err(error),
        };
        let mut table = routes_of(AF_INET)?;
        table.extend(routes_of(AF_INET6)?);
        let table: Vec<_> = table
            .iter()
            .filter_map(|route| {
                let hop = ip_of(&route.NextHop)?;
                Some((prefix_of(route)?, value(&route.InterfaceLuid), hop))
            })
            .collect();
        Ok(foreign_halves(&table, tunnel))
    }

    /// The forwarding table's choice, by [`table_through`], as for IPv4.
    fn uses_interface_v6(&self, dest: Ipv6Addr, interface: &str) -> Verified {
        system_through(AF_INET6, IpAddr::V6(dest), interface)
    }
}

/// Whether `table` (destination, interface, next hop) has a half of full
/// mode that is not ours on the tunnel `tunnel`: exactly `0.0.0.0/1`,
/// `128.0.0.0/1`, `::/1` or `8000::/1`, through another interface or
/// through a next hop. Any other route, such as a virtual adapter's own
/// network, is not one, however it is configured.
fn foreign_halves(table: &[(Prefix, u64, IpAddr)], tunnel: Option<u64>) -> bool {
    let (v4_halves, v6_halves) = halves();
    table.iter().any(|(dest, luid, hop)| {
        let half = v4_halves.contains(dest) || v6_halves.contains(dest);
        let ours = Some(*luid) == tunnel && hop.is_unspecified();
        half && !ours
    })
}

/// The halves of full mode, IPv4 and IPv6.
fn halves() -> ([Prefix; 2], [Prefix; 2]) {
    let parse = |text: &str| text.parse::<Prefix>().expect("a half");
    (FULL_TUNNEL_V4.map(parse), FULL_TUNNEL_V6.map(parse))
}

/// What full mode can do about IPv6 with the tunnel `luid`, as
/// [`Routes::full_tunnel_ipv6`] says.
fn ipv6_decision(luid: u64) -> Result<Ipv6Block> {
    if has_ipv6(luid)? {
        Ok(Ipv6Block::Blocked)
    } else if leak_path(luid)? {
        Err(Error::Unsupported)
    } else {
        Ok(Ipv6Block::NothingToBlock)
    }
}

/// Whether IPv6 is bound to the device with `luid`, so that routes of that
/// family can be added on it.
fn has_ipv6(luid: u64) -> Result<bool> {
    // SAFETY: plain data for which all zeroes is valid; then initialised.
    let mut row: MIB_IPINTERFACE_ROW = unsafe { std::mem::zeroed() };
    // SAFETY: the pointer is to a valid row.
    unsafe { InitializeIpInterfaceEntry(&mut row) };
    row.Family = AF_INET6;
    row.InterfaceLuid = net_luid(luid);
    // SAFETY: the row names the interface and is valid for the call.
    match checked(unsafe { GetIpInterfaceEntry(&mut row) }) {
        Ok(()) => Ok(true),
        Err(Error::NotFound) => Ok(false),
        Err(error) => Err(error),
    }
}

/// Whether IPv6 could leave by an interface other than the one with
/// `tunnel`: any unicast IPv6 route there, the interface up or down, other
/// than link-local (`fe80::/10`), loopback (`::1/128`) and multicast
/// (`ff00::/8`), which every interface with IPv6 has and none carries
/// traffic away. Teredo's `2001::/32` counts.
fn leak_path(tunnel: u64) -> Result<bool> {
    let table: Vec<_> = routes_of(AF_INET6)?
        .iter()
        .filter_map(|route| Some((prefix_of(route)?, value(&route.InterfaceLuid))))
        .collect();
    Ok(leaks(&table, tunnel))
}

/// Whether `table` (destination, interface) has a route IPv6 could leave
/// by on an interface other than `tunnel` ([`could_leak`]). An IPv4 route
/// is never one.
fn leaks(table: &[(Prefix, u64)], tunnel: u64) -> bool {
    table
        .iter()
        .any(|(dest, luid)| *luid != tunnel && could_leak(*dest))
}

/// Every IPv6 route that could be a leak path ([`could_leak`]), on any
/// interface, but full mode's own halves, as (interface, destination, next
/// hop), sorted. Windows keeps a host route for each of the machine's own
/// addresses, so an address added or removed changes this too.
pub(super) fn ipv6_paths() -> Result<Vec<(u64, String, String)>> {
    let (_, v6_halves) = halves();
    let mut paths: Vec<_> = routes_of(AF_INET6)?
        .iter()
        .filter_map(|route| {
            let dest = prefix_of(route)?;
            let wanted = could_leak(dest) && !v6_halves.contains(&dest);
            let hop = ip_of(&route.NextHop)?;
            wanted.then(|| {
                (
                    value(&route.InterfaceLuid),
                    dest.to_string(),
                    hop.to_string(),
                )
            })
        })
        .collect();
    paths.sort();
    paths.dedup();
    Ok(paths)
}

/// Every IPv6 address on the machine that is not link-local, loopback or
/// multicast, as (interface, address), sorted. Watched beside
/// [`ipv6_paths`], so a new address is noticed even before, or without,
/// the host route Windows keeps for it.
pub(super) fn ipv6_addresses() -> Result<Vec<(u64, Ipv6Addr)>> {
    let mut found: Vec<_> = addresses_of(AF_INET6)?
        .iter()
        .filter_map(|row| match ip_of(&row.Address)? {
            IpAddr::V6(addr) => Some((value(&row.InterfaceLuid), addr)),
            IpAddr::V4(_) => None,
        })
        .filter(|(_, addr)| Prefix::v6(*addr, 128).is_some_and(could_leak))
        .collect();
    found.sort();
    found.dedup();
    Ok(found)
}

/// Whether an IPv6 route to `dest` could carry traffic off the machine:
/// any but one inside link-local, loopback or multicast space.
fn could_leak(dest: Prefix) -> bool {
    let Prefix::V6(addr, len) = dest else {
        return false;
    };
    let local = [
        Prefix::v6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10),
        Prefix::v6(Ipv6Addr::LOCALHOST, 128),
        Prefix::v6(Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0), 8),
    ];
    !local
        .into_iter()
        .flatten()
        .any(|net| net.len() <= len && net.contains(IpAddr::V6(addr)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("ubc-vpn-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[cfg(feature = "dev-mode")]
    fn paths(state_dir: &Path) -> Paths {
        Paths {
            policy_dir: state_dir.to_path_buf(),
            state_dir: state_dir.to_path_buf(),
            settings_dir: state_dir.to_path_buf(),
            channel_name: String::new(),
        }
    }

    // Security rule: the routes the service runs with keep their journal in
    // the checked state folder. One that others may change is refused, not
    // trusted with naming the routes to remove.
    #[cfg(feature = "dev-mode")]
    #[test]
    fn the_service_journal_is_kept_in_the_checked_state_folder() {
        let base = temp("journal-checked");
        let dir = base.join("state");
        crate::StateDir::open(Mode::Dev, &paths(&dir)).unwrap();
        let users = "*S-1-5-32-545:(OI)(CI)(M)";
        let granted = std::process::Command::new("icacls")
            .args([&dir.to_string_lossy(), "/grant", users])
            .output()
            .unwrap();
        assert!(granted.status.success());
        let refused = WinRoutes::new(Mode::Dev, &paths(&dir)).remove_all();
        let Err(Error::Failed(why)) = refused else {
            panic!("a journal others may change was used: {refused:?}");
        };
        assert!(why.contains("S-1-5-32-545"), "{why}");
        std::fs::remove_dir_all(&base).unwrap();
    }

    fn prefix(text: &str) -> Prefix {
        text.parse().unwrap()
    }

    // Security rule: IPv6 can leave by any unicast route but link-local,
    // loopback and multicast ones, which every interface with IPv6 has.
    // Teredo's prefix and a unique local network count.
    #[test]
    fn only_link_local_loopback_and_multicast_routes_cannot_leak() {
        for local in [
            "fe80::/64",
            "fe80::1/128",
            "::1/128",
            "ff00::/8",
            "ff02::/16",
        ] {
            assert!(!could_leak(prefix(local)), "{local}");
        }
        for leaks in [
            "::/0",
            "2001::/32",
            "2002::/16",
            "fd00::/8",
            "2001:db8::/64",
            "fe80::/9",
            "::/1",
        ] {
            assert!(could_leak(prefix(leaks)), "{leaks}");
        }
        assert!(!could_leak(prefix("0.0.0.0/0")));
    }

    // A machine with two virtual host-only adapters and a physical network
    // (made-up ranges). The adapters' IPv4 on-link routes are not another
    // program's full mode, and IPv4 routes never count as a way out for
    // IPv6. An IPv6 unicast route on any interface but the tunnel does, as
    // do another interface's halves.
    #[test]
    fn virtual_adapters_networks_are_not_halves_but_their_ipv6_routes_leak() {
        let (tunnel, wire, host_a, host_b) = (7, 9, 11, 12);
        let ip = |text: &str| text.parse::<IpAddr>().unwrap();
        let on_link = |text: &str, luid| (prefix(text), luid, ip("0.0.0.0"));
        let host_only = [
            on_link("172.31.130.0/24", host_a),
            on_link("172.31.130.1/32", host_a),
            on_link("172.31.130.255/32", host_a),
            on_link("172.31.140.0/24", host_b),
            on_link("172.31.140.1/32", host_b),
            on_link("172.31.140.255/32", host_b),
            on_link("224.0.0.0/4", host_a),
            on_link("255.255.255.255/32", host_b),
            (prefix("0.0.0.0/0"), wire, ip("198.51.100.1")),
            on_link("198.51.100.0/24", wire),
            (prefix("fe80::/64"), host_a, ip("::")),
            (prefix("ff00::/8"), host_b, ip("::")),
        ];
        let mut table = host_only.to_vec();
        assert!(!foreign_halves(&table, Some(tunnel)));
        assert!(!foreign_halves(&table, None));
        // Ours, on the tunnel with no next hop, are not foreign.
        for half in FULL_TUNNEL_V4.into_iter().chain(FULL_TUNNEL_V6) {
            let any = if half.contains(':') { "::" } else { "0.0.0.0" };
            table.push((prefix(half), tunnel, ip(any)));
        }
        assert!(!foreign_halves(&table, Some(tunnel)));
        assert!(
            foreign_halves(&table, Some(99)),
            "the same halves elsewhere"
        );
        // A half on a host-only adapter, or ours given a next hop, is.
        let elsewhere = [on_link("128.0.0.0/1", host_a)];
        assert!(foreign_halves(&elsewhere, Some(tunnel)));
        let via = [(prefix("::/1"), tunnel, ip("fe80::1"))];
        assert!(foreign_halves(&via, Some(tunnel)));

        let v6 = |table: &[(Prefix, u64, IpAddr)]| -> Vec<(Prefix, u64)> {
            table.iter().map(|(dest, luid, _)| (*dest, *luid)).collect()
        };
        assert!(!leaks(&v6(&host_only), tunnel), "IPv4 is not an IPv6 leak");
        let global = [(prefix("2001:db8:a::/64"), host_a)];
        assert!(leaks(&global, tunnel), "a host-only adapter's IPv6 network");
        let unique_local = [(prefix("fd00:b::1/128"), host_b)];
        assert!(leaks(&unique_local, tunnel));
        // The tunnel's own IPv6 routes are not a way out past it.
        let own = [(prefix("2001:db8::/64"), tunnel), (prefix("::/1"), tunnel)];
        assert!(!leaks(&own, tunnel));
    }

    const WIFI: u64 = 9;
    const WIRED: u64 = 11;
    const TUNNEL_LUID: u64 = 7;

    fn route(dest: &str, luid: u64, metric: u32) -> TableRoute {
        TableRoute {
            dest: dest.parse().unwrap(),
            luid,
            metric,
        }
    }

    /// Full mode on a home network, all made up: the local network
    /// 10.200.0.0/24 on Wi-Fi with the router at .1 and the machine at .10,
    /// the gateway's host route, and the halves on the tunnel with metric 0
    /// on an interface of low metric, as the product adds them.
    fn full_mode_table() -> (Vec<TableRoute>, HashMap<u64, u32>) {
        let routes = vec![
            route("0.0.0.0/0", WIFI, 0),
            route("10.200.0.0/24", WIFI, 256),
            route("10.200.0.10/32", WIFI, 256),
            route("10.200.0.255/32", WIFI, 256),
            route("192.0.2.1/32", WIFI, 0),
            route("0.0.0.0/1", TUNNEL_LUID, 0),
            route("128.0.0.0/1", TUNNEL_LUID, 0),
            route("198.18.0.5/32", TUNNEL_LUID, 256),
        ];
        let interfaces = HashMap::from([(WIFI, 35), (TUNNEL_LUID, 5)]);
        (routes, interfaces)
    }

    fn addr(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    // Security rule, the issue's case: a network the machine is on stays
    // off the tunnel in full mode, at every address in it, because its
    // on-link route is more specific than the halves. Its route's metric is
    // far higher than theirs, and neighbour reachability, which made the
    // best-route lookup answer with the 128.0.0.0/1 half for an unanswered
    // address, is not part of the table.
    #[test]
    fn the_local_network_beats_the_halves_whatever_the_metrics() {
        let (routes, interfaces) = full_mode_table();
        let through = |dest: &str, luid| table_through(&routes, &interfaces, addr(dest), luid);
        for dest in ["10.200.0.1", "10.200.0.2", "10.200.0.200", "10.200.0.10"] {
            assert_eq!(through(dest, WIFI), Verified::Yes, "{dest}");
            assert_eq!(through(dest, TUNNEL_LUID), Verified::No, "{dest}");
        }
        assert_eq!(through("192.0.2.1", WIFI), Verified::Yes, "the gateway");
        for dest in ["100.64.0.9", "203.0.113.9", "10.200.1.2"] {
            assert_eq!(through(dest, TUNNEL_LUID), Verified::Yes, "{dest}");
            assert_eq!(through(dest, WIFI), Verified::No, "{dest}");
        }
    }

    // Among routes of the longest prefix, the lowest sum of route and
    // interface metric wins. A tie between interfaces is `Unknown` for
    // either of them, never `Yes` or `No`, and `No` for a third.
    #[test]
    fn the_lowest_total_metric_wins_and_a_tie_between_interfaces_is_unknown() {
        let routes = [route("0.0.0.0/0", WIFI, 0), route("0.0.0.0/0", WIRED, 10)];
        let dest = addr("203.0.113.9");
        let lower_wifi = HashMap::from([(WIFI, 35), (WIRED, 30)]);
        assert_eq!(
            table_through(&routes, &lower_wifi, dest, WIFI),
            Verified::Yes
        );
        assert_eq!(
            table_through(&routes, &lower_wifi, dest, WIRED),
            Verified::No
        );
        let lower_wired = HashMap::from([(WIFI, 35), (WIRED, 20)]);
        assert_eq!(
            table_through(&routes, &lower_wired, dest, WIRED),
            Verified::Yes
        );
        assert_eq!(
            table_through(&routes, &lower_wired, dest, WIFI),
            Verified::No
        );
        // The route's own metric counts too: 0 + 40 against 10 + 30.
        let tied = HashMap::from([(WIFI, 40), (WIRED, 30)]);
        assert_eq!(table_through(&routes, &tied, dest, WIFI), Verified::Unknown);
        assert_eq!(
            table_through(&routes, &tied, dest, WIRED),
            Verified::Unknown
        );
        assert_eq!(
            table_through(&routes, &tied, dest, TUNNEL_LUID),
            Verified::No
        );
        // Two equal routes through the same interface agree.
        let same = [route("0.0.0.0/0", WIFI, 0), route("0.0.0.0/0", WIFI, 0)];
        assert_eq!(table_through(&same, &tied, dest, WIFI), Verified::Yes);
        // Metrics that would overflow 32 bits still add up.
        let huge = [route("0.0.0.0/0", WIFI, u32::MAX)];
        let interfaces = HashMap::from([(WIFI, u32::MAX)]);
        assert_eq!(table_through(&huge, &interfaces, dest, WIFI), Verified::Yes);
    }

    // Security rule, issue #265: an IPv6 destination follows the same rule
    // as an IPv4 one. Another program's `::/1` beside ours with an equal
    // total metric could take the traffic or not, so it is `Unknown` for
    // the tunnel, never `No`: the check that full mode's IPv6 is gone cannot
    // pass while our half is still there. Otherwise the lower total wins.
    #[test]
    fn an_ipv6_destination_follows_the_same_rule_and_a_tie_is_unknown() {
        let interfaces = HashMap::from([(WIFI, 35), (TUNNEL_LUID, 5)]);
        let dest = addr("2001:db8::1");
        let through = |routes: &[TableRoute], luid| table_through(routes, &interfaces, dest, luid);
        let ours = route("::/1", TUNNEL_LUID, 0);
        let halves = [ours, route("8000::/1", TUNNEL_LUID, 0)];
        assert_eq!(through(&halves, TUNNEL_LUID), Verified::Yes);
        assert_eq!(through(&halves, WIFI), Verified::No);
        // A default route is less specific than a half, whatever its metric.
        let with_default = [halves[0], halves[1], route("::/0", WIFI, 0)];
        assert_eq!(through(&with_default, TUNNEL_LUID), Verified::Yes);
        // Theirs beside ours, both totalling 35: either could be used.
        let tied = [route("::/1", TUNNEL_LUID, 30), route("::/1", WIFI, 0)];
        assert_eq!(through(&tied, TUNNEL_LUID), Verified::Unknown);
        assert_eq!(through(&tied, WIFI), Verified::Unknown);
        // Ours totals 5 against their 35, then 105 against 35.
        let ours_lower = [ours, route("::/1", WIFI, 0)];
        assert_eq!(through(&ours_lower, TUNNEL_LUID), Verified::Yes);
        assert_eq!(through(&ours_lower, WIFI), Verified::No);
        let ours_higher = [route("::/1", TUNNEL_LUID, 100), route("::/1", WIFI, 0)];
        assert_eq!(through(&ours_higher, TUNNEL_LUID), Verified::No);
        assert_eq!(through(&ours_higher, WIFI), Verified::Yes);
        // A more specific route elsewhere wins.
        let narrower = [ours, route("2001:db8::/32", WIFI, 256)];
        assert_eq!(through(&narrower, TUNNEL_LUID), Verified::No);
        // A half on a tunnel that is down carries nothing.
        let down = HashMap::from([(WIFI, 35)]);
        assert_eq!(
            table_through(&halves, &down, dest, TUNNEL_LUID),
            Verified::No
        );
        // An IPv4 route never holds an IPv6 address, nor the reverse.
        let v4 = [route("0.0.0.0/0", TUNNEL_LUID, 0)];
        assert_eq!(through(&v4, TUNNEL_LUID), Verified::No);
        let v4_dest = addr("203.0.113.9");
        let halves_for_v4 = table_through(&halves, &interfaces, v4_dest, TUNNEL_LUID);
        assert_eq!(halves_for_v4, Verified::No);
        // Nothing matches.
        assert_eq!(through(&[], TUNNEL_LUID), Verified::No);
    }

    // An interface counts only when it is up and has IPv4 bound, with the
    // interface metric Windows gives it.
    #[test]
    fn an_interface_is_usable_only_when_up_with_ipv4() {
        let ipv4 = [(WIFI, 35), (TUNNEL_LUID, 5)];
        let up = HashSet::from([WIFI, WIRED]);
        let found = usable(ipv4.into_iter(), &up);
        assert_eq!(found, HashMap::from([(WIFI, 35)]));
    }

    // A route on an interface that is down, or has no IPv4, carries
    // nothing, however specific: the next route that holds the address
    // decides. No route at all is `No`.
    #[test]
    fn only_routes_on_usable_interfaces_count() {
        let (routes, mut interfaces) = full_mode_table();
        let through = |interfaces: &HashMap<u64, u32>, dest: &str, luid| {
            table_through(&routes, interfaces, addr(dest), luid)
        };
        interfaces.remove(&TUNNEL_LUID);
        assert_eq!(
            through(&interfaces, "100.64.0.9", TUNNEL_LUID),
            Verified::No
        );
        assert_eq!(through(&interfaces, "100.64.0.9", WIFI), Verified::Yes);
        let mut lan_down = full_mode_table().1;
        lan_down.remove(&WIFI);
        assert_eq!(through(&lan_down, "10.200.0.2", WIFI), Verified::No);
        assert_eq!(through(&lan_down, "10.200.0.2", TUNNEL_LUID), Verified::Yes);
        assert_eq!(
            through(&HashMap::new(), "10.200.0.2", WIFI),
            Verified::No,
            "no usable route"
        );
        assert_eq!(
            table_through(&[], &interfaces, addr("100.64.0.9"), WIFI),
            Verified::No
        );
    }

    // A system route of either family is read with its destination,
    // interface and own metric.
    #[test]
    fn a_system_route_is_read_with_its_metric() {
        // SAFETY: plain data for which all zeroes is valid.
        let mut row: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
        row.DestinationPrefix.Prefix = v4(Ipv4Addr::new(10, 200, 0, 0));
        row.DestinationPrefix.PrefixLength = 24;
        row.InterfaceLuid = net_luid(WIFI);
        row.Metric = 256;
        assert_eq!(table_route(&row), Some(route("10.200.0.0/24", WIFI, 256)));
        row.DestinationPrefix.Prefix = v6(Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0));
        row.DestinationPrefix.PrefixLength = 1;
        row.Metric = 7;
        assert_eq!(table_route(&row), Some(route("8000::/1", WIFI, 7)));
    }

    // An interface is read with the interface metric Windows has in
    // effect for it, which decides between routes of equal length.
    #[test]
    fn an_interface_is_read_with_its_metric() {
        // SAFETY: plain data for which all zeroes is valid.
        let mut row: MIB_IPINTERFACE_ROW = unsafe { std::mem::zeroed() };
        row.InterfaceLuid = net_luid(WIRED);
        row.Metric = 25;
        assert_eq!(ip_interface(&row), (WIRED, 25));
    }

    #[test]
    fn an_ipv6_prefix_holds_exactly_the_addresses_under_it() {
        let ip = |text: &str| text.parse::<IpAddr>().unwrap();
        assert!(prefix("::/1").contains(ip("7fff::1")));
        assert!(!prefix("::/1").contains(ip("8000::")));
        assert!(prefix("8000::/1").contains(ip("ffff::1")));
        assert!(prefix("::/0").contains(ip("2001:db8::1")));
        assert!(prefix("2001:db8::1/128").contains(ip("2001:db8::1")));
        assert!(!prefix("2001:db8::1/128").contains(ip("2001:db8::2")));
        assert!(!prefix("::/0").contains(ip("192.0.2.1")));
        let (v4, v6) = halves();
        assert_eq!(v4.map(|p| p.to_string()), FULL_TUNNEL_V4);
        assert_eq!(v6.map(|p| p.to_string()), FULL_TUNNEL_V6);
    }

    // Each of Windows' states is read as itself, so the rule that only a
    // preferred or deprecated address counts sees what Windows said.
    #[test]
    fn each_windows_dad_state_is_read_as_itself() {
        use windows_sys::Win32::Networking::WinSock::IpDadStateInvalid;
        let read = [
            (IpDadStatePreferred, DadState::Preferred),
            (IpDadStateDeprecated, DadState::Deprecated),
            (IpDadStateTentative, DadState::Tentative),
            (IpDadStateDuplicate, DadState::Duplicate),
            (IpDadStateInvalid, DadState::Invalid),
            (99, DadState::Invalid),
        ];
        for (state, expected) in read {
            assert_eq!(dad_state(state), expected, "{state}");
        }
    }

    /// A row of the address table as Windows gives it: `addr`/`len` on the
    /// interface `luid`, in `state`.
    fn address(addr: [u8; 4], len: u8, luid: u64, state: NL_DAD_STATE) -> MIB_UNICASTIPADDRESS_ROW {
        // SAFETY: plain data for which all zeroes is valid.
        let mut row: MIB_UNICASTIPADDRESS_ROW = unsafe { std::mem::zeroed() };
        row.Address = v4(Ipv4Addr::from(addr));
        row.OnLinkPrefixLength = len;
        row.InterfaceLuid = net_luid(luid);
        row.DadState = state;
        row
    }

    // Security rule: an address is on an up interface only when Windows
    // lists that interface as up, so one on an interface that is down, or
    // missing from the table, is left out.
    #[test]
    fn an_address_is_up_only_when_its_interface_is() {
        let row = address([10, 200, 0, 10], 24, 7, IpDadStatePreferred);
        let read = |up: &[u64]| address_row(&row, &up.iter().copied().collect()).unwrap();
        let expected = AddressRow {
            addr: Ipv4Addr::new(10, 200, 0, 10),
            prefix_len: 24,
            state: DadState::Preferred,
            interface_up: true,
        };
        assert_eq!(read(&[7]), expected);
        assert_eq!(read(&[3, 7, 9]), expected);
        let down = AddressRow {
            interface_up: false,
            ..expected
        };
        assert_eq!(read(&[]), down);
        assert_eq!(read(&[3, 9]), down);
    }

    // Security rule: the machine's own addresses are every IPv4 address
    // Windows lists, in every state, used or not. Each use of them refuses
    // a match or notices a missing one, so fewer would weaken it.
    #[test]
    fn every_listed_address_is_one_of_the_machines_own() {
        use windows_sys::Win32::Networking::WinSock::IpDadStateInvalid;
        let states = [
            IpDadStatePreferred,
            IpDadStateDeprecated,
            IpDadStateTentative,
            IpDadStateDuplicate,
            IpDadStateInvalid,
        ];
        let rows: Vec<_> = (0u8..)
            .zip(states)
            .map(|(n, state)| address([169, 254, 0, n + 1], 16, u64::from(n), state))
            .collect();
        let own: Vec<Ipv4Addr> = (1..=5).map(|n| Ipv4Addr::new(169, 254, 0, n)).collect();
        assert_eq!(own_addresses(&rows), own);
        // An IPv6 row is not an IPv4 address.
        let mut v6_row = rows[0];
        v6_row.Address = v6(Ipv6Addr::LOCALHOST);
        assert!(own_addresses(&[v6_row]).is_empty());
    }

    // Security rule, on the real tables: every network the machine counts
    // as one it is on has a route of its own, which is what keeps it off
    // the tunnel's halves. An address that is not used, such as a
    // disconnected adapter's tentative 169.254.x.x one, has none, and is
    // not counted. Only reads.
    #[test]
    fn every_network_the_machine_is_on_has_its_own_route() {
        let dir = temp("on-link");
        let physical = WinRoutes::unchecked(&dir)
            .capture_physical(Ipv4Addr::new(192, 0, 2, 1))
            .unwrap();
        let routed: Vec<Ipv4Net> = route_table().unwrap().iter().filter_map(row_dest).collect();
        assert!(!physical.on_link().is_empty(), "{physical:?}");
        for net in physical.on_link() {
            assert!(routed.contains(net), "{net} has no route: {routed:?}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    // A route is written to the journal before it is added, so a crash
    // between the two leaves a row and never a route that nothing names.
    #[test]
    fn the_row_is_written_before_the_route_is_added() {
        let dir = temp("journal-first");
        let routes = WinRoutes::unchecked(&dir);
        let gateway = Ipv4Addr::new(198, 18, 255, 1);
        let physical = routes.capture_physical(gateway).unwrap();
        CRASH_BEFORE_ADD.with(|crash| crash.set(true));
        let added = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            routes.add_gateway_route(gateway, &physical)
        }));
        CRASH_BEFORE_ADD.with(|crash| crash.set(false));
        assert!(added.is_err(), "the add did not stop where it was told to");
        let rows = lock(&routes.journal).rows(boot()).unwrap();
        let dests: Vec<String> = rows.iter().map(|row| row.dest.to_string()).collect();
        assert_eq!(dests, ["198.18.255.1/32"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
