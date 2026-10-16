//! Network change and sleep notifications, pushed by Windows.
//!
//! Interface, address and route changes arrive on system threads through the
//! IP Helper notification API, and sleep and wake through the power
//! notification API, which needs no window and no service handler. A
//! callback only wakes a worker thread. The worker looks at the watched
//! interface again and sends `PhysicalChanged` only when something about it
//! that the connection relies on differs from what it was:
//!
//! - the interface is gone, or no longer up;
//! - its IPv4 addresses changed;
//! - the router of its default route changed.
//!
//! IPv4 and IPv6 changes are both watched. The worker sends `Ipv6Changed`
//! when, on any interface, an IPv6 route that could be a leak path appeared,
//! changed or went: in full mode the service decides again whether IPv6 can
//! leak, and also when an IPv6 address appeared or went. Full mode's own
//! IPv6 halves, and link-local, loopback and multicast routes and
//! addresses, do not count. The tunnel's are not told apart: an event too
//! many only makes the service check again.
//!
//! The first look is compared with the captured [`PhysicalNetwork`], so a
//! change between capture and subscribe is reported too. Once Windows is
//! asked for notifications, the worker looks once more, so a change between
//! the first look and the registration is not missed either.
//!
//! Routes this product adds are never among these: the gateway's host route
//! is not a default route, and tunnel routes are on the tunnel. So no event
//! is sent for them, as the contract asks, without having to tell them apart.
//!
//! Sleep and wake are best effort. On machines with modern standby Windows
//! may not announce every sleep.
//!
//! A callback gets only a number, never a pointer: it looks the subscription
//! up in a table, so a callback that arrives late finds nothing and touches
//! no freed memory. Dropping the [`Subscription`] cancels the registrations,
//! then removes the subscription from the table, then joins the worker.

use std::collections::HashMap;
use std::ffi::c_void;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ptr::null_mut;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Mutex, MutexGuard, PoisonError};

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CancelMibChangeNotify2, GetIfEntry2, MIB_IF_ROW2, MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW,
    MIB_UNICASTIPADDRESS_ROW, NotifyIpInterfaceChange, NotifyRouteChange2,
    NotifyUnicastIpAddressChange,
};
use windows_sys::Win32::NetworkManagement::Ndis::{IfOperStatusUp, NET_LUID_LH};
use windows_sys::Win32::Networking::WinSock::AF_UNSPEC;
use windows_sys::Win32::System::Power::{
    DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS, PowerRegisterSuspendResumeNotification,
    PowerUnregisterSuspendResumeNotification,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    DEVICE_NOTIFY_CALLBACK, PBT_APMRESUMEAUTOMATIC, PBT_APMSUSPEND,
};

use super::routes::{
    addr_of, address_table, checked, ipv6_addresses, ipv6_paths, luid, route_table, row_dest, value,
};
use crate::{Error, NetworkEvent, NetworkEvents, PhysicalNetwork, Result, Subscription};

/// What a connection relies on about the physical interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Snapshot {
    pub(super) up: bool,
    pub(super) addresses: Vec<Ipv4Addr>,
    pub(super) routers: Vec<Ipv4Addr>,
    /// Where IPv6 could go, on any interface (see [`ipv6_paths`]): in full
    /// mode, a new way out for IPv6 must be checked again.
    pub(super) ipv6: Vec<(u64, String, String)>,
    /// The IPv6 addresses, on any interface, that are not link-local,
    /// loopback or multicast (see [`ipv6_addresses`]).
    pub(super) ipv6_addresses: Vec<(u64, Ipv6Addr)>,
}

/// The interface with `luid` as it is now. A missing interface is down,
/// with nothing on it.
pub(super) fn snapshot(luid: u64) -> Result<Snapshot> {
    // SAFETY: plain data for which all zeroes is valid.
    let mut row: MIB_IF_ROW2 = unsafe { std::mem::zeroed() };
    row.InterfaceLuid = NET_LUID_LH { Value: luid };
    // SAFETY: the row names the interface and is valid for the call.
    let up = match checked(unsafe { GetIfEntry2(&mut row) }) {
        Ok(()) => row.OperStatus == IfOperStatusUp,
        Err(Error::NotFound) => false,
        Err(error) => return Err(error),
    };
    let on_it = |row_luid: &NET_LUID_LH| value(row_luid) == luid;
    let table = address_table()?;
    let addresses = table.iter().filter(|row| on_it(&row.InterfaceLuid));
    let mut addresses: Vec<_> = addresses.filter_map(|row| addr_of(&row.Address)).collect();
    addresses.sort();
    let default =
        |row: &&MIB_IPFORWARD_ROW2| row_dest(row).is_some_and(|dest| dest.prefix_len() == 0);
    let routes = route_table()?;
    let defaults = routes
        .iter()
        .filter(|row| on_it(&row.InterfaceLuid))
        .filter(default);
    let mut routers: Vec<_> = defaults.filter_map(|row| addr_of(&row.NextHop)).collect();
    routers.sort();
    routers.dedup();
    Ok(Snapshot {
        up,
        addresses,
        routers,
        ipv6: ipv6_paths()?,
        ipv6_addresses: ipv6_addresses()?,
    })
}

/// Whether the interface as it is now no longer matches what was captured:
/// down, an address the capture did not have, or a router that is not the
/// captured next hop. (The capture lists the addresses of every interface,
/// so an address that has gone from this one is noticed only from the
/// subscription's own first look onwards.)
pub(super) fn differs_from_capture(now: &Snapshot, captured: &PhysicalNetwork) -> bool {
    let new_address = now
        .addresses
        .iter()
        .any(|addr| !captured.own_addresses.contains(addr));
    let router_moved = captured
        .next_hop
        .is_some_and(|hop| !now.routers.contains(&hop));
    !now.up || new_address || router_moved
}

/// The events for a change from `before` to `now`: `PhysicalChanged` for
/// the watched interface, `Ipv6Changed` for where IPv6 could go.
pub(super) fn changes(before: &Snapshot, now: &Snapshot) -> Vec<NetworkEvent> {
    let physical =
        (before.up, &before.addresses, &before.routers) != (now.up, &now.addresses, &now.routers);
    let mut events = Vec::new();
    if physical {
        events.push(NetworkEvent::PhysicalChanged);
    }
    if (&before.ipv6, &before.ipv6_addresses) != (&now.ipv6, &now.ipv6_addresses) {
        events.push(NetworkEvent::Ipv6Changed);
    }
    events
}

/// What a notification tells the worker.
enum Wake {
    /// Something about the network may have changed.
    Network,
    Power(NetworkEvent),
}

/// Every live subscription's way to wake its worker, by number. A callback
/// is given the number as its context.
static SUBSCRIBERS: Mutex<Option<HashMap<usize, Sender<Wake>>>> = Mutex::new(None);
static NEXT: AtomicUsize = AtomicUsize::new(1);
/// Callbacks that arrived for a subscription that had already ended. Each
/// one would have been a call into freed memory had the context been a
/// pointer; any at all means a registration outlived its subscription.
static LATE: AtomicUsize = AtomicUsize::new(0);

fn subscribers() -> MutexGuard<'static, Option<HashMap<usize, Sender<Wake>>>> {
    SUBSCRIBERS.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Wakes the subscription numbered `context`, or counts a late callback.
fn wake(context: *const c_void, wake: Wake) {
    let id = context as usize;
    match subscribers().as_ref().and_then(|all| all.get(&id)) {
        Some(sender) => {
            let _ = sender.send(wake);
        }
        None => {
            LATE.fetch_add(1, Ordering::SeqCst);
        }
    }
}

unsafe extern "system" fn on_interface(
    context: *const c_void,
    _: *const MIB_IPINTERFACE_ROW,
    _: i32,
) {
    wake(context, Wake::Network);
}

unsafe extern "system" fn on_address(
    context: *const c_void,
    _: *const MIB_UNICASTIPADDRESS_ROW,
    _: i32,
) {
    wake(context, Wake::Network);
}

unsafe extern "system" fn on_route(context: *const c_void, _: *const MIB_IPFORWARD_ROW2, _: i32) {
    wake(context, Wake::Network);
}

/// The event a power broadcast stands for, if any.
pub(super) fn power_event(kind: u32) -> Option<NetworkEvent> {
    match kind {
        PBT_APMSUSPEND => Some(NetworkEvent::Sleeping),
        // Sent on every resume; the "resumed by a user" one follows it only
        // sometimes, so it is not used.
        PBT_APMRESUMEAUTOMATIC => Some(NetworkEvent::Woke),
        _ => None,
    }
}

unsafe extern "system" fn on_power(context: *const c_void, kind: u32, _: *const c_void) -> u32 {
    if let Some(event) = power_event(kind) {
        wake(context, Wake::Power(event));
    }
    0
}

/// The registrations of one subscription. Dropping it cancels them.
struct Registrations {
    network: Vec<HANDLE>,
    power: *mut c_void,
    /// Kept until after the power registration is cancelled. It holds only
    /// the callback and the number, never a pointer to anything that is
    /// freed, so a callback still running after that is harmless.
    _power_parameters: Box<DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS>,
}

// SAFETY: the handles are process-wide and only cancelled, once, by drop.
unsafe impl Send for Registrations {}

impl Drop for Registrations {
    fn drop(&mut self) {
        for handle in self.network.drain(..) {
            // SAFETY: each handle came from a Notify… call and is cancelled
            // once. Never called from a callback, which would deadlock.
            unsafe { CancelMibChangeNotify2(handle) };
        }
        if !self.power.is_null() {
            // SAFETY: as above, for the power registration.
            unsafe { PowerUnregisterSuspendResumeNotification(self.power as _) };
        }
        LIVE.fetch_sub(1, Ordering::SeqCst);
    }
}

fn register(id: usize) -> Result<Registrations> {
    // The number, carried where a pointer would go; never dereferenced.
    let context = id as *const c_void;
    let mut done = Registrations {
        network: Vec::new(),
        power: null_mut(),
        _power_parameters: Box::new(DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS {
            Callback: Some(on_power),
            Context: context.cast_mut(),
        }),
    };
    // Counted from here: dropping `done` on a failure below uncounts it.
    LIVE.fetch_add(1, Ordering::SeqCst);
    let mut handle = null_mut();
    // SAFETY: the callback has the documented signature, and its context is
    // a number, valid for ever.
    checked(unsafe {
        NotifyIpInterfaceChange(AF_UNSPEC, Some(on_interface), context, false, &mut handle)
    })?;
    done.network.push(handle);
    // SAFETY: as above.
    checked(unsafe {
        NotifyUnicastIpAddressChange(AF_UNSPEC, Some(on_address), context, false, &mut handle)
    })?;
    done.network.push(handle);
    // SAFETY: as above.
    checked(unsafe { NotifyRouteChange2(AF_UNSPEC, Some(on_route), context, false, &mut handle) })?;
    done.network.push(handle);
    let mut power = null_mut();
    let recipient: HANDLE = (&raw mut *done._power_parameters).cast();
    // SAFETY: the parameters hold a callback with the documented signature
    // and a number as context; they live as long as the registration.
    checked(unsafe {
        PowerRegisterSuspendResumeNotification(DEVICE_NOTIFY_CALLBACK, recipient, &mut power)
    })?;
    done.power = power;
    Ok(done)
}

pub(crate) struct WinEvents;

impl NetworkEvents for WinEvents {
    fn subscribe(&self, watching: &PhysicalNetwork) -> Result<Subscription> {
        let watched = luid(&watching.interface)?;
        let mut last = snapshot(watched)?;
        let changed_since_capture = differs_from_capture(&last, watching);
        let id = NEXT.fetch_add(1, Ordering::SeqCst);
        let (waker, woken) = mpsc::channel();
        if changed_since_capture {
            let _ = waker.send(Wake::Network);
        }
        // One more look, which the worker takes only once it runs, after the
        // registrations: a change between the first look and them is then
        // reported, not missed.
        let _ = waker.send(Wake::Network);
        subscribers().get_or_insert_default().insert(id, waker);
        // Dropped on a failure below, which removes the entry again.
        let mut ending = Ending {
            id,
            registrations: None,
            worker: None,
        };
        ending.registrations = Some(register(id)?);
        let (events, receiver) = mpsc::channel();
        let mut first = changed_since_capture;
        // Ends when the subscription is removed from the table, which drops
        // the only sender of `woken`.
        let worker = move || {
            for wake in woken {
                let sent = match wake {
                    Wake::Power(event) => vec![event],
                    Wake::Network if std::mem::take(&mut first) => {
                        vec![NetworkEvent::PhysicalChanged]
                    }
                    Wake::Network => match snapshot(watched) {
                        Ok(now) => {
                            let changes = changes(&last, &now);
                            last = now;
                            changes
                        }
                        // Could not look: say so the safe way.
                        Err(_) => vec![NetworkEvent::PhysicalChanged, NetworkEvent::Ipv6Changed],
                    },
                };
                if sent.into_iter().any(|event| events.send(event).is_err()) {
                    break;
                }
            }
        };
        ending.worker = Some(
            std::thread::Builder::new()
                .name("network events".into())
                .spawn(worker)?,
        );
        Ok(Subscription::new(receiver, ending))
    }
}

/// What dropping a [`Subscription`] ends, in this order: the registrations,
/// so no new callback starts; the subscription's entry in the table, which
/// ends the worker's wait; then the worker itself.
struct Ending {
    id: usize,
    registrations: Option<Registrations>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Ending {
    fn drop(&mut self) {
        drop(self.registrations.take());
        if let Some(all) = subscribers().as_mut() {
            all.remove(&self.id);
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

/// How many subscriptions have registrations with Windows right now.
static LIVE: AtomicUsize = AtomicUsize::new(0);

/// How many subscriptions are registered with Windows now, for tests.
#[cfg(test)]
pub(super) fn live() -> usize {
    LIVE.load(Ordering::SeqCst)
}

/// How many callbacks arrived after their subscription ended, for tests.
#[cfg(test)]
pub(super) fn late_callbacks() -> usize {
    LATE.load(Ordering::SeqCst)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn power_broadcasts_map_to_sleep_and_wake_only() {
        assert_eq!(power_event(PBT_APMSUSPEND), Some(NetworkEvent::Sleeping));
        assert_eq!(
            power_event(PBT_APMRESUMEAUTOMATIC),
            Some(NetworkEvent::Woke)
        );
        // Resumed by a user, power status, battery: nothing.
        for other in [7, 10, 0x8013] {
            assert_eq!(power_event(other), None, "{other}");
        }
    }

    // A change between capturing the network and subscribing to it is
    // reported, not taken as the starting point.
    #[test]
    fn a_change_since_capture_is_noticed() {
        let captured = PhysicalNetwork {
            interface: "wire".to_string(),
            next_hop: Some(Ipv4Addr::new(192, 168, 0, 1)),
            own_addresses: vec![Ipv4Addr::new(192, 168, 0, 10)],
            on_link: Vec::new(),
        };
        let same = Snapshot {
            up: true,
            addresses: vec![Ipv4Addr::new(192, 168, 0, 10)],
            routers: vec![Ipv4Addr::new(192, 168, 0, 1)],
            ipv6: Vec::new(),
            ipv6_addresses: Vec::new(),
        };
        assert!(!differs_from_capture(&same, &captured));
        let down = Snapshot {
            up: false,
            ..same.clone()
        };
        let moved = Snapshot {
            addresses: vec![Ipv4Addr::new(10, 0, 0, 5)],
            ..same.clone()
        };
        let new_router = Snapshot {
            routers: vec![Ipv4Addr::new(192, 168, 0, 254)],
            ..same.clone()
        };
        for changed in [down, moved, new_router] {
            assert!(differs_from_capture(&changed, &captured), "{changed:?}");
        }
    }

    // A change to the watched interface is "physical changed"; a change to
    // where IPv6 could go, on any interface, is "IPv6 changed"; both can
    // come at once, and no change sends nothing.
    #[test]
    fn each_kind_of_change_has_its_own_event() {
        let before = Snapshot {
            up: true,
            addresses: vec![Ipv4Addr::new(192, 168, 0, 10)],
            routers: vec![Ipv4Addr::new(192, 168, 0, 1)],
            ipv6: Vec::new(),
            ipv6_addresses: Vec::new(),
        };
        let way_out = vec![(7, "::/0".to_string(), "fe80::1".to_string())];
        let ipv6 = Snapshot {
            ipv6: way_out.clone(),
            ..before.clone()
        };
        let down = Snapshot {
            up: false,
            ..before.clone()
        };
        let both = Snapshot {
            up: false,
            ipv6: way_out,
            ..before.clone()
        };
        let address = Snapshot {
            ipv6_addresses: vec![(7, Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 7))],
            ..before.clone()
        };
        assert_eq!(changes(&before, &before), []);
        assert_eq!(changes(&before, &ipv6), [NetworkEvent::Ipv6Changed]);
        assert_eq!(changes(&before, &address), [NetworkEvent::Ipv6Changed]);
        assert_eq!(changes(&address, &before), [NetworkEvent::Ipv6Changed]);
        assert_eq!(changes(&ipv6, &before), [NetworkEvent::Ipv6Changed]);
        assert_eq!(changes(&before, &down), [NetworkEvent::PhysicalChanged]);
        assert_eq!(
            changes(&before, &both),
            [NetworkEvent::PhysicalChanged, NetworkEvent::Ipv6Changed]
        );
    }

    // Registering needs no rights, and dropping a subscription cancels its
    // registrations with Windows at once, with no event to wake it.
    #[test]
    fn a_dropped_subscription_is_unregistered_at_once() {
        // Other tests subscribe too, and the count is the process's.
        let _turn = super::super::routes_tests::turn();
        let routes = super::super::routes::WinRoutes::unchecked(&std::env::temp_dir());
        let physical =
            crate::Routes::capture_physical(&routes, Ipv4Addr::new(192, 0, 2, 1)).unwrap();
        crate::suite::check_subscription_ends(&WinEvents, &physical, &live);
    }
}
