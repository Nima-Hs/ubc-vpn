//! Network change and sleep notifications, pushed by Windows.
//!
//! Interface, address and route changes arrive on system threads through the
//! IP Helper notification API, and sleep and wake through the power
//! notification API, which needs no window and no service handler. A
//! callback only wakes a worker thread. The worker looks at the watched
//! interface again and sends `PhysicalChanged` only when something about it
//! that the connection relies on differs from when the subscription began:
//!
//! - the interface is gone, or no longer up;
//! - its IPv4 addresses changed;
//! - the router of its default route changed.
//!
//! Routes this product adds are never among these: the gateway's host route
//! is not a default route, and tunnel routes are on the tunnel. So no event
//! is sent for them, as the contract asks, without having to tell them apart.
//!
//! Sleep and wake are best effort. On machines with modern standby Windows
//! may not announce every sleep.
//!
//! Dropping the receiver ends the subscription: the worker notices at its
//! next attempt to send, then cancels the notifications.

use std::ffi::c_void;
use std::net::Ipv4Addr;
use std::ptr::null_mut;
use std::sync::Mutex;
use std::sync::mpsc::{self, Receiver, Sender};

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CancelMibChangeNotify2, GetIfEntry2, MIB_IF_ROW2, MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW,
    MIB_UNICASTIPADDRESS_ROW, NotifyIpInterfaceChange, NotifyRouteChange2,
    NotifyUnicastIpAddressChange,
};
use windows_sys::Win32::NetworkManagement::Ndis::{IfOperStatusUp, NET_LUID_LH};
use windows_sys::Win32::Networking::WinSock::AF_INET;
use windows_sys::Win32::System::Power::{
    DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS, PowerRegisterSuspendResumeNotification,
    PowerUnregisterSuspendResumeNotification,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    DEVICE_NOTIFY_CALLBACK, PBT_APMRESUMEAUTOMATIC, PBT_APMSUSPEND,
};

use super::routes::{addr_of, address_table, checked, luid, route_table, row_dest, value};
use crate::{Error, NetworkEvent, NetworkEvents, PhysicalNetwork, Result};

/// What a connection relies on about the physical interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Snapshot {
    pub(super) up: bool,
    pub(super) addresses: Vec<Ipv4Addr>,
    pub(super) routers: Vec<Ipv4Addr>,
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
    })
}

/// What a notification tells the worker.
enum Wake {
    /// Something about the network may have changed.
    Network,
    Power(NetworkEvent),
}

/// What the callbacks share with the worker. Boxed, so its address stays
/// put for as long as Windows may call back with it.
struct Shared {
    wake: Mutex<Sender<Wake>>,
}

impl Shared {
    fn send(&self, wake: Wake) {
        let sender = self
            .wake
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _ = sender.send(wake);
    }
}

unsafe extern "system" fn on_interface(
    context: *const c_void,
    _: *const MIB_IPINTERFACE_ROW,
    _: i32,
) {
    // SAFETY: the context is the `Shared` the subscription keeps alive until
    // every registration is cancelled.
    unsafe { &*context.cast::<Shared>() }.send(Wake::Network);
}

unsafe extern "system" fn on_address(
    context: *const c_void,
    _: *const MIB_UNICASTIPADDRESS_ROW,
    _: i32,
) {
    // SAFETY: as above.
    unsafe { &*context.cast::<Shared>() }.send(Wake::Network);
}

unsafe extern "system" fn on_route(context: *const c_void, _: *const MIB_IPFORWARD_ROW2, _: i32) {
    // SAFETY: as above.
    unsafe { &*context.cast::<Shared>() }.send(Wake::Network);
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
        // SAFETY: as above.
        unsafe { &*context.cast::<Shared>() }.send(Wake::Power(event));
    }
    0
}

/// The registrations of one subscription. Dropping it cancels them, which
/// waits for callbacks in progress, and only then frees what they use.
struct Registrations {
    /// What the callbacks point at. Dropped after the registrations are
    /// cancelled, which `drop` does first.
    _shared: Box<Shared>,
    network: Vec<HANDLE>,
    power: *mut c_void,
    /// Must live as long as the power registration, which holds its address.
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
    }
}

fn register(shared: Box<Shared>) -> Result<Registrations> {
    let context: *const c_void = (&raw const *shared).cast();
    let mut parameters = Box::new(DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS {
        Callback: Some(on_power),
        Context: context.cast_mut(),
    });
    let mut done = Registrations {
        _shared: shared,
        network: Vec::new(),
        power: null_mut(),
        _power_parameters: Box::new(DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS::default()),
    };
    let mut handle = null_mut();
    // SAFETY: the callback has the documented signature and the context
    // outlives the registration, which `done` cancels first when dropped.
    checked(unsafe {
        NotifyIpInterfaceChange(AF_INET, Some(on_interface), context, false, &mut handle)
    })?;
    done.network.push(handle);
    // SAFETY: as above.
    checked(unsafe {
        NotifyUnicastIpAddressChange(AF_INET, Some(on_address), context, false, &mut handle)
    })?;
    done.network.push(handle);
    // SAFETY: as above.
    checked(unsafe { NotifyRouteChange2(AF_INET, Some(on_route), context, false, &mut handle) })?;
    done.network.push(handle);
    let mut power = null_mut();
    let recipient: HANDLE = (&raw mut *parameters).cast();
    // SAFETY: the parameters hold a callback with the documented signature
    // and a context that outlive the registration.
    checked(unsafe {
        PowerRegisterSuspendResumeNotification(DEVICE_NOTIFY_CALLBACK, recipient, &mut power)
    })?;
    done.power = power;
    done._power_parameters = parameters;
    Ok(done)
}

pub(crate) struct WinEvents;

impl NetworkEvents for WinEvents {
    fn subscribe(&self, watching: &PhysicalNetwork) -> Result<Receiver<NetworkEvent>> {
        let watched = luid(&watching.interface)?;
        let mut last = snapshot(watched)?;
        let (wake, woken) = mpsc::channel();
        let registrations = register(Box::new(Shared {
            wake: Mutex::new(wake),
        }))?;
        let (events, receiver) = mpsc::channel();
        let worker = move || {
            let _registrations = registrations;
            for wake in woken {
                let event = match wake {
                    Wake::Power(event) => event,
                    Wake::Network => match snapshot(watched) {
                        Ok(now) if now == last => continue,
                        Ok(now) => {
                            last = now;
                            NetworkEvent::PhysicalChanged
                        }
                        // Could not look: say so the safe way.
                        Err(_) => NetworkEvent::PhysicalChanged,
                    },
                };
                if send(&events, event).is_err() {
                    break;
                }
            }
        };
        std::thread::Builder::new()
            .name("network events".into())
            .spawn(worker)?;
        Ok(receiver)
    }
}

fn send(events: &Sender<NetworkEvent>, event: NetworkEvent) -> std::result::Result<(), ()> {
    events.send(event).map_err(drop)
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

    // Registering needs no rights, and a subscription can be ended.
    #[test]
    fn subscribes_unprivileged_and_ends_when_dropped() {
        let routes = super::super::routes::WinRoutes::unchecked(&std::env::temp_dir());
        let physical =
            crate::Routes::capture_physical(&routes, Ipv4Addr::new(192, 0, 2, 1)).unwrap();
        let events = WinEvents.subscribe(&physical).unwrap();
        drop(events);
    }
}
