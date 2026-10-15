//! The routing table and the tunnel's address, through the IP Helper API.
//!
//! Interfaces are named by their alias, which is how the engine reports the
//! tunnel; the alias is looked up again on every call. A route is identified
//! by destination, interface LUID and next hop.
//!
//! Windows keeps routes to one destination through two interfaces side by
//! side and refuses only an identical one, so every add first reads the table
//! and fails with `AlreadyExists` when the destination is routed elsewhere.

use std::net::Ipv4Addr;
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
    GetBestRoute2, GetIfEntry2, GetIpForwardTable2, GetIpInterfaceEntry, GetUnicastIpAddressTable,
    IF_TYPE_PROP_VIRTUAL, InitializeIpForwardEntry, InitializeIpInterfaceEntry,
    InitializeUnicastIpAddressEntry, MIB_IF_ROW2, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
    MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_ROW, MIB_UNICASTIPADDRESS_TABLE, SetIpInterfaceEntry,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, IpDadStatePreferred, MIB_IPPROTO_NETMGMT, RouterDiscoveryDisabled,
    SOCKADDR_INET,
};
use windows_sys::Win32::System::SystemInformation::GetTickCount64;

use super::journal::{Boot, Journal, Row, Store};
use super::security::{os_error, wide};
use crate::{Error, Mode, Paths, PhysicalNetwork, Result, Routes, TUNNEL_MTU, Verified, lock};

pub(super) fn v4(addr: Ipv4Addr) -> SOCKADDR_INET {
    // SAFETY: SOCKADDR_INET is a plain union for which all zeroes is valid.
    let mut socket: SOCKADDR_INET = unsafe { std::mem::zeroed() };
    socket.si_family = AF_INET;
    socket.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(addr.octets());
    socket
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
    let mut table: *mut MIB_IPFORWARD_TABLE2 = null_mut();
    // SAFETY: the out pointer is valid; the table is freed by `Table`.
    checked(unsafe { GetIpForwardTable2(AF_INET, &mut table) })?;
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

/// The route the system would use to reach `dest`.
fn best_route(dest: Ipv4Addr) -> Result<MIB_IPFORWARD_ROW2> {
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

/// A forwarding row for one route, ready to add or delete.
fn forward_row(row: &Row) -> MIB_IPFORWARD_ROW2 {
    // SAFETY: plain data for which all zeroes is valid; then initialised.
    let mut forward: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
    // SAFETY: the pointer is to a valid row.
    unsafe { InitializeIpForwardEntry(&mut forward) };
    forward.InterfaceLuid = net_luid(row.luid);
    forward.DestinationPrefix.Prefix = v4(row.dest.addr());
    forward.DestinationPrefix.PrefixLength = row.dest.prefix_len();
    forward.NextHop = v4(row.next_hop);
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
    let table = route_table()?;
    let same_dest = table.iter().filter(|r| row_dest(r) == Some(row.dest));
    let mut found = Present::None;
    for existing in same_dest {
        let luid = value(&existing.InterfaceLuid);
        if luid == row.luid && addr_of(&existing.NextHop) == Some(row.next_hop) {
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
        let own_addresses = addresses
            .iter()
            .filter_map(|row| addr_of(&row.Address))
            .collect();
        let on_link = addresses.iter().filter_map(|row| {
            let addr = u32::from(addr_of(&row.Address)?);
            let len = row.OnLinkPrefixLength.min(32);
            let mask = u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0);
            Ipv4Net::new(Ipv4Addr::from(addr & mask), len).ok()
        });
        let mut on_link: Vec<Ipv4Net> = on_link.collect();
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
            dest,
            luid: luid(&via.interface)?,
            next_hop: via.next_hop.unwrap_or(Ipv4Addr::UNSPECIFIED),
            interface: via.interface.clone(),
        })
    }

    fn remove_gateway_route(&self, gateway: Ipv4Addr, via: &PhysicalNetwork) -> Result<()> {
        let next_hop = via.next_hop.unwrap_or(Ipv4Addr::UNSPECIFIED);
        self.remove(|row| {
            row.dest.addr() == gateway
                && row.dest.prefix_len() == 32
                && row.interface == via.interface
                && row.next_hop == next_hop
        })
    }

    fn add_tunnel_routes(&self, tunnel: &str, subnets: &[Ipv4Net]) -> Result<()> {
        let luid = tunnel_luid(tunnel)?;
        for dest in subnets {
            self.add(Row {
                dest: *dest,
                luid,
                next_hop: Ipv4Addr::UNSPECIFIED,
                interface: tunnel.to_string(),
            })?;
        }
        Ok(())
    }

    fn remove_tunnel_routes(&self, tunnel: &str, subnets: &[Ipv4Net]) -> Result<()> {
        self.remove(|row| {
            row.interface == tunnel && row.next_hop.is_unspecified() && subnets.contains(&row.dest)
        })
    }

    fn remove_all(&self) -> Result<()> {
        self.remove(|_| true)
    }

    fn uses_interface(&self, dest: Ipv4Addr, interface: &str) -> Verified {
        let Ok(route) = best_route(dest) else {
            return Verified::Unknown;
        };
        let wanted = match luid(interface) {
            Ok(luid) => luid,
            // An interface that does not exist is not the one used.
            Err(Error::NotFound) => return Verified::No,
            Err(_) => return Verified::Unknown,
        };
        match value(&route.InterfaceLuid) == wanted {
            true => Verified::Yes,
            false => Verified::No,
        }
    }
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
