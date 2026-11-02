//! A Wintun adapter for tests: the same kind of device the engine creates,
//! so the routes code is tested against what ships.
//!
//! `wintun.dll` is not in the repository. CI downloads the pinned file named
//! in `native/windows/wintun.pin` and passes its full path in
//! `UBC_VPN_TEST_WINTUN`; it is loaded from that path only, by test code
//! only, and never stored or uploaded.

use std::ffi::c_void;
use std::ptr::null;

use windows_sys::Win32::Foundation::{FreeLibrary, HMODULE};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryExW};
use windows_sys::core::GUID;

use super::security::wide;

type Create = unsafe extern "system" fn(*const u16, *const u16, *const GUID) -> *mut c_void;
type Close = unsafe extern "system" fn(*mut c_void);
type StartSession = unsafe extern "system" fn(*mut c_void, u32) -> *mut c_void;
type EndSession = unsafe extern "system" fn(*mut c_void);
type Found = unsafe extern "system" fn() -> isize;

/// The library, loaded from the path CI gives.
pub(super) struct Wintun {
    library: HMODULE,
    create: Create,
    close: Close,
    start_session: StartSession,
    end_session: EndSession,
}

// SAFETY: the functions are documented as callable from any thread, and the
// module handle is process-wide.
unsafe impl Send for Wintun {}
// SAFETY: as above.
unsafe impl Sync for Wintun {}

impl Wintun {
    /// The library, or `None` when CI did not provide it.
    pub(super) fn load() -> Option<Self> {
        let path = std::env::var("UBC_VPN_TEST_WINTUN").ok()?;
        let path = wide(&path);
        // SAFETY: the path is NUL-terminated and outlives the call. A full
        // path is loaded as given.
        let library = unsafe { LoadLibraryExW(path.as_ptr(), null_mut_handle(), 0) };
        assert!(!library.is_null(), "UBC_VPN_TEST_WINTUN names no library");
        let find = |name: &[u8]| {
            // SAFETY: the name is NUL-terminated and the module is loaded.
            let found = unsafe { GetProcAddress(library, name.as_ptr()) };
            found.unwrap_or_else(|| panic!("wintun.dll has no {:?}", std::str::from_utf8(name)))
        };
        // SAFETY: each function has the signature `wintun.h` declares for it.
        unsafe {
            Some(Self {
                library,
                create: std::mem::transmute::<Found, Create>(find(b"WintunCreateAdapter\0")),
                close: std::mem::transmute::<Found, Close>(find(b"WintunCloseAdapter\0")),
                start_session: std::mem::transmute::<Found, StartSession>(find(
                    b"WintunStartSession\0",
                )),
                end_session: std::mem::transmute::<Found, EndSession>(find(b"WintunEndSession\0")),
            })
        }
    }

    /// Creates an adapter named `name`, with a session running so that
    /// Windows sees it connected. Dropping it removes it.
    pub(super) fn adapter(&self, name: &str) -> Adapter<'_> {
        super::routes_tests::step(&format!("creating the adapter {name}"));
        let (name, kind) = (wide(name), wide("ubc-vpn-test"));
        // SAFETY: both strings are NUL-terminated and outlive the call; a
        // null GUID lets the system choose one.
        let handle = unsafe { (self.create)(name.as_ptr(), kind.as_ptr(), null()) };
        assert!(!handle.is_null(), "creating a Wintun adapter failed");
        super::routes_tests::step("starting a session");
        // SAFETY: the adapter is open; the capacity is a power of two in the
        // documented range.
        let session = unsafe { (self.start_session)(handle, 0x40_0000) };
        assert!(!session.is_null(), "starting a Wintun session failed");
        super::routes_tests::step("the adapter is up");
        Adapter {
            wintun: self,
            handle,
            session,
        }
    }
}

fn null_mut_handle() -> windows_sys::Win32::Foundation::HANDLE {
    std::ptr::null_mut()
}

impl Drop for Wintun {
    fn drop(&mut self) {
        // SAFETY: loaded once by `load`, freed once here, after every adapter
        // that borrows it.
        unsafe { FreeLibrary(self.library) };
    }
}

pub(super) struct Adapter<'a> {
    wintun: &'a Wintun,
    handle: *mut c_void,
    session: *mut c_void,
}

// SAFETY: the handles are used through the library's thread-safe functions.
unsafe impl Send for Adapter<'_> {}
// SAFETY: as above.
unsafe impl Sync for Adapter<'_> {}

impl Adapter<'_> {
    /// Ends the session, so that Windows sees the adapter disconnected, and
    /// keeps the adapter, with its routes, until it is dropped.
    pub(super) fn end_session(&mut self) {
        if self.session.is_null() {
            return;
        }
        // SAFETY: the session is open and owned by this value; it is ended
        // once, here, and never used again.
        unsafe { (self.wintun.end_session)(self.session) };
        self.session = std::ptr::null_mut();
    }
}

impl Drop for Adapter<'_> {
    fn drop(&mut self) {
        self.end_session();
        // SAFETY: the adapter is open, owned by this value, and closed once,
        // after its session has ended.
        unsafe { (self.wintun.close)(self.handle) };
    }
}
