//! The routes against a real Wintun adapter. They need an elevated process
//! and the library CI downloads; without them they are skipped with a
//! message, unless `UBC_VPN_REQUIRE_ELEVATED` is set, as it is in CI.

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use ubc_vpn_core::routes::Ipv4Net;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry2, CreateUnicastIpAddressEntry, DeleteIpForwardEntry2,
    InitializeIpForwardEntry, InitializeUnicastIpAddressEntry, MIB_IPFORWARD_ROW2,
    MIB_UNICASTIPADDRESS_ROW,
};
use windows_sys::Win32::Networking::WinSock::IpDadStatePreferred;

use super::routes::{WinRoutes, addr_of, address_table, checked, luid, v4, value};
use super::wintun::Wintun;
use crate::suite::{self, Foreign};
use crate::{Error, Routes, Verified};

pub(super) fn skip(what: &str) {
    let required = std::env::var_os("UBC_VPN_REQUIRE_ELEVATED").is_some();
    assert!(!required, "{what}, and this run requires it");
    println!("SKIPPED: {what}");
}

/// CI searches the log for these lines to prove the tests that can be
/// skipped ran.
pub(super) fn ran(test: &str) {
    println!("RAN: {test}");
}

/// One routing test at a time: they share the gateway's address and the
/// machine's one routing table.
static TURN: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub(super) fn turn() -> std::sync::MutexGuard<'static, ()> {
    TURN.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The last step a routing test reached, for the watchdog's message.
static STEP: std::sync::Mutex<String> = std::sync::Mutex::new(String::new());

/// Notes the step a routing test is at, in the log and for the watchdog.
pub(super) fn step(what: &str) {
    eprintln!("STEP: {what}");
    *STEP
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = what.to_string();
}

/// How long all the routing tests in one process may take together.
const DEADLINE: std::time::Duration = std::time::Duration::from_secs(180);

/// The child process the crash test started, so the watchdog can end it.
static CHILD_PROCESS: std::sync::Mutex<Option<std::process::Child>> = std::sync::Mutex::new(None);

/// Every destination the routing tests use. Nothing else is ever touched.
const TEST_RANGES: [&str; 4] = [
    "192.0.2.0/24",
    "198.51.100.0/24",
    "198.18.0.0/24",
    "203.0.113.0/24",
];

/// Removes every route to a test destination, through any interface, and
/// every route this product's journals name. Used when a test ends, however
/// it ends.
fn scrub(dirs: &[PathBuf]) {
    for dir in dirs {
        let _ = WinRoutes::unchecked(dir).remove_all();
    }
    let ranges = TEST_RANGES.map(|range| range.parse::<Ipv4Net>().expect("a range"));
    for row in super::routes::route_table().unwrap_or_default() {
        let dest = super::routes::row_dest(&row);
        if dest.is_some_and(|dest| ranges.iter().any(|range| range.contains(&dest))) {
            // SAFETY: the row came from the system's own table.
            let _ = unsafe { DeleteIpForwardEntry2(&row) };
        }
    }
}

/// Removes, when dropped, what a test may have left: its routes, and the
/// crash test's child and adapter.
pub(super) struct Cleanup(pub(super) Vec<PathBuf>);

impl Drop for Cleanup {
    fn drop(&mut self) {
        if let Some(mut child) = CHILD_PROCESS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            let _ = child.kill();
            let _ = child.wait();
        }
        scrub(&self.0);
    }
}

/// Ends the whole test run, saying where, if a routing test is stuck: a
/// stuck system call cannot be interrupted any other way. Before it does,
/// it ends the crash test's child and removes the tests' routes. An adapter
/// left behind belongs to a process that is gone, and Wintun removes such
/// adapters the next time one is created.
fn watchdog() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        std::thread::spawn(|| {
            std::thread::sleep(DEADLINE);
            let step = STEP
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            eprintln!("HUNG: a routing test is stuck at: {step}");
            drop(Cleanup(Vec::new()));
            std::process::exit(101);
        });
    });
}

pub(super) fn wintun() -> Option<Wintun> {
    watchdog();
    let loaded = Wintun::load();
    if loaded.is_none() {
        skip("no Wintun library was provided (UBC_VPN_TEST_WINTUN)");
    }
    loaded
}

/// A journal folder of the test's own.
pub(super) fn state_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ubc-vpn-routes-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// Changes routes and addresses as somebody other than the product: through
/// the same API, but recorded nowhere.
pub(super) struct Outsider;

impl Outsider {
    fn row(interface: &str, net: Ipv4Net) -> MIB_IPFORWARD_ROW2 {
        let luid = luid(interface).expect("the interface");
        // The interface's usual router, when the default route uses it.
        let default =
            WinRoutes::unchecked(&state_dir("probe")).capture_physical(Ipv4Addr::new(192, 0, 2, 1));
        let hop = default
            .ok()
            .filter(|physical| physical.interface() == interface)
            .and_then(|physical| physical.next_hop())
            .unwrap_or(Ipv4Addr::UNSPECIFIED);
        // SAFETY: plain data for which all zeroes is valid; then initialised.
        let mut row: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
        // SAFETY: the pointer is to a valid row.
        unsafe { InitializeIpForwardEntry(&mut row) };
        row.InterfaceLuid.Value = luid;
        row.DestinationPrefix.Prefix = v4(net.addr());
        row.DestinationPrefix.PrefixLength = net.prefix_len();
        row.NextHop = v4(hop);
        row
    }
}

impl Foreign for Outsider {
    fn add_route(&self, interface: &str, net: Ipv4Net) {
        // SAFETY: the row is valid and initialised.
        checked(unsafe { CreateIpForwardEntry2(&Self::row(interface, net)) }).expect("add a route");
    }

    fn remove_route(&self, interface: &str, net: Ipv4Net) {
        // SAFETY: the row is valid and initialised.
        let removed = checked(unsafe { DeleteIpForwardEntry2(&Self::row(interface, net)) });
        assert!(
            matches!(removed, Ok(()) | Err(Error::NotFound)),
            "{removed:?}"
        );
    }

    fn add_address(&self, interface: &str, address: Ipv4Addr) {
        // SAFETY: plain data for which all zeroes is valid; then initialised.
        let mut row: MIB_UNICASTIPADDRESS_ROW = unsafe { std::mem::zeroed() };
        // SAFETY: the pointer is to a valid row.
        unsafe { InitializeUnicastIpAddressEntry(&mut row) };
        row.InterfaceLuid.Value = luid(interface).expect("the interface");
        row.Address = v4(address);
        row.OnLinkPrefixLength = 24;
        row.DadState = IpDadStatePreferred;
        // SAFETY: the row is valid and initialised.
        checked(unsafe { CreateUnicastIpAddressEntry(&row) }).expect("add an address");
    }

    fn addresses(&self, interface: &str) -> Vec<Ipv4Addr> {
        let luid = luid(interface).expect("the interface");
        let rows = address_table().expect("the address table");
        let ours = rows.iter().filter(|row| value(&row.InterfaceLuid) == luid);
        ours.filter_map(|row| addr_of(&row.Address)).collect()
    }
}

// The shared rules, on the device that ships.
#[test]
fn passes_the_shared_route_suite_on_a_wintun_adapter() {
    let _turn = turn();
    let Some(wintun) = wintun() else { return };
    let tunnel = "ubc-vpn-suite0";
    let dir = state_dir("suite");
    // Dropped in reverse: the routes go first, then the adapter.
    let _adapter = wintun.adapter(tunnel);
    let _cleanup = Cleanup(vec![dir.clone()]);
    let routes = WinRoutes::unchecked(&dir);
    step("check_configure_tunnel");
    suite::check_configure_tunnel(&routes, &Outsider, tunnel);
    step("check_routes");
    suite::check_routes(&routes, tunnel);
    step("check_route_ownership");
    let restarted = || Box::new(WinRoutes::unchecked(&dir)) as Box<dyn Routes>;
    suite::check_route_ownership(&routes, &restarted, &Outsider, tunnel);
    ran("routes");
}

// The contract leaves IPv6 alone: the tunnel gets no IPv6 address, also
// after it is configured again.
#[test]
fn the_tunnel_has_no_ipv6_address_after_each_configure() {
    let _turn = turn();
    let Some(wintun) = wintun() else { return };
    let tunnel = "ubc-vpn-ipv6-0";
    let dir = state_dir("ipv6");
    let _adapter = wintun.adapter(tunnel);
    let _cleanup = Cleanup(vec![dir.clone()]);
    let routes = WinRoutes::unchecked(&dir);
    let luid = luid(tunnel).unwrap();
    let ipv6 = || {
        let rows = super::routes::addresses_of(windows_sys::Win32::Networking::WinSock::AF_INET6);
        rows.unwrap()
            .iter()
            .filter(|row| value(&row.InterfaceLuid) == luid)
            .count()
    };
    for (n, mtu) in [(2, 1300), (3, 1400), (3, 1400)] {
        routes
            .configure_tunnel(tunnel, Ipv4Addr::new(198, 18, 0, n), mtu)
            .unwrap();
        // Windows adds a link-local address as an interface comes up, a
        // moment later; give it that moment.
        std::thread::sleep(std::time::Duration::from_secs(2));
        assert_eq!(ipv6(), 0, "an IPv6 address after configuring with .{n}");
    }
    ran("ipv6");
}

// A crash between writing a row and adding its route leaves a row with no
// route. The next start drops it without harm.
#[test]
fn a_row_whose_route_was_never_added_is_dropped_at_the_next_start() {
    let _turn = turn();
    let Some(_wintun) = wintun() else { return };
    let dir = state_dir("orphan-row");
    let _cleanup = Cleanup(vec![dir.clone()]);
    let routes = WinRoutes::unchecked(&dir);
    let physical = routes
        .capture_physical(Ipv4Addr::new(192, 0, 2, 1))
        .unwrap();
    let row = super::journal::Row {
        dest: "192.0.2.1/32".parse().unwrap(),
        luid: luid(physical.interface()).unwrap(),
        next_hop: physical.next_hop().unwrap_or(Ipv4Addr::UNSPECIFIED).into(),
        interface: physical.interface().to_string(),
    };
    let mut journal = super::journal::Journal::new(super::journal::Store::Unchecked(dir.clone()));
    journal.write(super::routes::boot(), &[row]).unwrap();
    WinRoutes::unchecked(&dir)
        .remove_all()
        .expect("remove all at the next start");
    assert_eq!(journal.rows(super::routes::boot()), Ok(vec![]));
    ran("orphan row");
}

// Security rule: only a tunnel device is configured or routed through as
// one, never the physical network.
#[test]
fn refuses_to_treat_the_physical_interface_as_the_tunnel() {
    let _turn = turn();
    let Some(_wintun) = wintun() else { return };
    let dir = state_dir("physical");
    let _cleanup = Cleanup(vec![dir.clone()]);
    let routes = WinRoutes::unchecked(&dir);
    let physical = routes
        .capture_physical(Ipv4Addr::new(192, 0, 2, 1))
        .unwrap();
    let wire = physical.interface();
    let configured = routes.configure_tunnel(wire, Ipv4Addr::new(198, 51, 100, 7), 1300);
    assert!(
        matches!(configured, Err(Error::Failed(_))),
        "{configured:?}"
    );
    let routed = routes.add_tunnel_routes(wire, &["198.51.100.0/24".parse().unwrap()]);
    assert!(matches!(routed, Err(Error::Failed(_))), "{routed:?}");
    ran("physical");
}

const CHILD: &str = "UBC_VPN_CRASH_CHILD";

/// The part of `a_killed_service_leaves_what_start_up_removes` that is
/// killed. It does nothing unless that test started it.
#[test]
fn crash_child() {
    let Some(dir) = std::env::var_os(CHILD) else {
        return;
    };
    // Ends this process too if it is stuck, so it never outlives the test.
    watchdog();
    let wintun = Wintun::load().expect("the library");
    let tunnel = "ubc-vpn-crash0";
    let adapter = wintun.adapter(tunnel);
    let routes = WinRoutes::unchecked(&PathBuf::from(dir));
    let gateway = Ipv4Addr::new(192, 0, 2, 1);
    step("child: capture_physical");
    let physical = routes.capture_physical(gateway).unwrap();
    step("child: configure_tunnel");
    routes
        .configure_tunnel(tunnel, Ipv4Addr::new(198, 18, 0, 2), 1300)
        .unwrap();
    step("child: add_gateway_route");
    routes.add_gateway_route(gateway, &physical).unwrap();
    step("child: add_tunnel_routes");
    routes
        .add_tunnel_routes(tunnel, &["198.18.0.0/24".parse().unwrap()])
        .unwrap();
    step("child: ready");
    // A file, not a line on standard output: the test harness's output is
    // not a reliable channel between two processes.
    let dir = PathBuf::from(std::env::var_os(CHILD).unwrap());
    // Written whole, then moved into place, so it is never read half done.
    std::fs::write(dir.join("ready.new"), physical.interface()).unwrap();
    std::fs::rename(dir.join("ready.new"), dir.join("ready")).unwrap();
    std::mem::forget(adapter);
    loop {
        std::thread::park();
    }
}

/// Removes the network device named `name` with the system's own tools.
fn remove_device(name: &str) {
    let script = format!(
        "$id = (Get-NetAdapter -Name '{name}' -IncludeHidden).PnPDeviceID; pnputil /remove-device $id"
    );
    let done = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .expect("powershell");
    println!(
        "REMOVED {name}: {}",
        String::from_utf8_lossy(&done.stdout).trim()
    );
}

/// Whether the system's table has a route to `dest` through `interface`.
fn has_route(dest: &str, interface: &str) -> bool {
    let routes = WinRoutes::unchecked(&state_dir("look"));
    let addr: Ipv4Net = dest.parse().unwrap();
    routes.uses_interface(addr.addr(), interface) == Verified::Yes
}

// What a service killed mid-connection leaves behind, and that the next
// start removes the product's routes and nothing else.
#[test]
fn a_killed_service_leaves_what_start_up_removes() {
    let _turn = turn();
    let Some(wintun) = wintun() else { return };
    let dir = state_dir("crash");
    let _cleanup = Cleanup(vec![dir.clone()]);
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "os::routes_tests::crash_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, &dir)
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    step("waiting for the child");
    *CHILD_PROCESS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(child);
    let started = std::time::Instant::now();
    let wire = loop {
        if let Ok(wire) = std::fs::read_to_string(dir.join("ready")) {
            break wire;
        }
        assert!(
            started.elapsed() < DEADLINE / 2,
            "the child did not get ready in time"
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    };
    step("killing the child");
    let child = CHILD_PROCESS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    let mut child = child.expect("the child");
    child.kill().unwrap();
    child.wait().unwrap();

    let tunnel = "ubc-vpn-crash0";
    let adapter = luid(tunnel).is_ok();
    let gateway_route = has_route("192.0.2.1/32", &wire);
    let tunnel_route = adapter && has_route("198.18.0.0/24", tunnel);
    let journal = std::fs::read_to_string(dir.join("routes.journal")).unwrap_or_default();
    println!(
        "SURVIVED adapter={adapter} gateway_route={gateway_route} tunnel_route={tunnel_route}"
    );
    println!("JOURNAL\n{journal}");
    assert!(
        journal.contains("192.0.2.1/32"),
        "the journal lost the gateway route"
    );

    WinRoutes::unchecked(&dir)
        .remove_all()
        .expect("remove all at the next start");
    let left = std::fs::read_to_string(dir.join("routes.journal")).unwrap();
    assert_eq!(left.lines().count(), 1, "rows left: {left}");
    // The gateway's address now follows the default route again, whatever
    // that is: the host route of ours is gone.
    let routes = WinRoutes::unchecked(&state_dir("after"));
    let physical = routes
        .capture_physical(Ipv4Addr::new(192, 0, 2, 1))
        .unwrap();
    let still = Outsider::row(&wire, "192.0.2.1/32".parse().unwrap());
    // SAFETY: the row is valid; deleting it shows whether it was there.
    let deleted = checked(unsafe { DeleteIpForwardEntry2(&still) });
    assert_eq!(
        deleted,
        Err(Error::NotFound),
        "the gateway route survived start-up"
    );
    let _ = physical;

    // An adapter whose process died is an orphan, which Wintun removes when
    // the next adapter is created. Show that, so none is left on the runner.
    // It does so in the background, so give it a moment; if it has not by
    // then, remove the device the way an administrator would, so the runner
    // is left clean either way.
    step("removing the orphaned adapter");
    drop(wintun.adapter("ubc-vpn-sweep0"));
    let gone = || luid(tunnel).is_err();
    let started = std::time::Instant::now();
    while !gone() && started.elapsed() < std::time::Duration::from_secs(15) {
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    println!(
        "ADAPTER after the next create: {}",
        if gone() { "removed" } else { "still there" }
    );
    if !gone() {
        remove_device(tunnel);
    }
    assert!(gone(), "the killed process's adapter is still there");
    ran("crash");
}
