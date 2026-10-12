//! One connection object of the library, and the four ways the library
//! calls back into Rust: for a log line, to judge a certificate, to fill in
//! a login form, and to find the gateway's address.
//!
//! The library gets one pointer to hand back in every callback. It points to
//! a [`Context`], which is boxed when the handle is made, never moves, and is
//! freed only after the library has freed the handle. It is never null.
//!
//! A panic in a callback never unwinds into the library: each entry point
//! catches it and answers with the library's value for failure.

use std::cell::{Cell, RefCell};
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::marker::PhantomData;
use std::net::SocketAddrV4;
use std::panic::{AssertUnwindSafe, catch_unwind};

use ubc_vpn_core::redact::Secret;

use super::{AddrInfo, AuthForm, CmdPipe, FormOpt, Library, OC_FORM_OPT_IGNORE, VpnInfo};

#[link(name = "ubc_vpn_shim", kind = "static")]
unsafe extern "C" {
    /// In `shim.c`: formats a progress line and calls
    /// [`ubc_vpn_progress_line`] with it.
    fn ubc_vpn_progress(privdata: *mut c_void, level: c_int, fmt: *const c_char, ...);
}

/// Whether a log line is all of what the library logged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineState {
    /// The whole line.
    Whole,
    /// The line did not fit the shim's buffer and was cut. A secret in it
    /// may be cut too, and a cut secret matches no registered one: treat
    /// the line as holding part of one.
    Cut,
    /// The line could not be formatted. What arrives may be its beginning,
    /// or nothing.
    Failed,
}

/// Receives each line the library logs, with its `PRG_*` level. A line may
/// hold a secret: an engine passes it to `LogSink::log` and nowhere else.
pub type Lines = Box<dyn Fn(c_int, &CStr, LineState) + Send + Sync>;

/// Judges the gateway's certificate, given its `pin-sha256:` hash.
pub type Judge = Box<dyn FnMut(&str) -> bool>;
/// Fills in a login form.
pub type Fill = Box<dyn FnMut(&mut Form<'_>) -> FormAnswer>;
/// Says where to connect for a host name and port, or refuses with `None`.
pub type Resolve = Box<dyn FnMut(&str, u16) -> Option<SocketAddrV4>>;

/// What the library is to call back into.
pub struct Callbacks {
    /// Every log line.
    pub lines: Lines,
    /// Only `true` lets the connection go on.
    pub certificate: Judge,
    pub form: Fill,
    /// Says where to connect for a host name and port the library wants to
    /// reach, or refuses with `None`. Every connection the library makes to
    /// a new host or port comes through here first.
    pub resolve: Resolve,
}

impl Callbacks {
    /// Logs to `lines` and refuses everything else: every certificate, every
    /// form and every address.
    pub fn refusing(lines: Lines) -> Self {
        Self {
            lines,
            certificate: Box::new(|_| false),
            form: Box::new(|_| FormAnswer::Fail),
            resolve: Box::new(|_, _| None),
        }
    }
}

/// What the library's `privdata` points to for the life of a handle.
pub struct Context {
    lines: Lines,
    certificate: RefCell<Judge>,
    form: RefCell<Fill>,
    resolve: RefCell<Resolve>,
    /// Whether the certificate callback ran and accepted, since it was last
    /// cleared.
    accepted: Cell<bool>,
    /// The handle this belongs to, once there is one.
    handle: Cell<Option<(Library, *mut VpnInfo)>>,
}

impl Context {
    /// Boxes the callbacks, so that their address never changes.
    pub fn new(callbacks: Callbacks) -> Box<Self> {
        Box::new(Self {
            lines: callbacks.lines,
            certificate: RefCell::new(callbacks.certificate),
            form: RefCell::new(callbacks.form),
            resolve: RefCell::new(callbacks.resolve),
            accepted: Cell::new(false),
            handle: Cell::new(None),
        })
    }

    /// The pointer the library is given. Never null.
    pub fn privdata(&self) -> *mut c_void {
        std::ptr::from_ref(self).cast_mut().cast()
    }
}

/// Runs `body` on the context behind `privdata`. Answers `failure` if the
/// pointer is null or `body` panics, so that nothing unwinds into C.
///
/// # Safety
///
/// `privdata` must be null or point to a live [`Context`], and the call must
/// be on the thread that owns it.
unsafe fn enter<T>(privdata: *mut c_void, failure: T, body: impl FnOnce(&Context) -> T) -> T {
    if privdata.is_null() {
        return failure;
    }
    // SAFETY: by the contract above it points to a live `Context`.
    let context = unsafe { &*privdata.cast::<Context>() };
    catch_unwind(AssertUnwindSafe(|| body(context))).unwrap_or(failure)
}

/// Called by `shim.c` with one formatted log line. `state` is one of the
/// `UBC_VPN_LINE_*` values there.
///
/// # Safety
///
/// As for [`enter`], and `line` must be null or a NUL-terminated string
/// valid for the call.
#[unsafe(no_mangle)]
unsafe extern "C" fn ubc_vpn_progress_line(
    privdata: *mut c_void,
    level: c_int,
    line: *const c_char,
    state: c_int,
) {
    if line.is_null() {
        return;
    }
    // A value the shim does not send is read as the cautious one.
    let state = match state {
        0 => LineState::Whole,
        2 => LineState::Failed,
        _ => LineState::Cut,
    };
    // SAFETY: the caller keeps the contract of `enter`, and `line` is a
    // NUL-terminated string for this call.
    unsafe {
        let line = CStr::from_ptr(line);
        enter(privdata, (), |context| (context.lines)(level, line, state));
    }
}

/// `openconnect_validate_peer_cert_vfn`: zero accepts. Anything that goes
/// wrong rejects.
///
/// # Safety
///
/// As for [`enter`]. The library calls it on the handle's own thread.
unsafe extern "C" fn validate_peer_cert(privdata: *mut c_void, _reason: *const c_char) -> c_int {
    let body = |context: &Context| {
        context.accepted.set(false);
        let Some((library, raw)) = context.handle.get() else {
            return 1;
        };
        // SAFETY: `raw` is the live handle that is calling this, on its
        // own thread. The answer is null or a NUL-terminated string that
        // belongs to the handle, and is copied at once.
        let hash = unsafe {
            let hash = (library.get_peer_cert_hash)(raw);
            if hash.is_null() {
                return 1;
            }
            CStr::from_ptr(hash).to_string_lossy().into_owned()
        };
        // A callback already running cannot be entered again.
        let Ok(mut judge) = context.certificate.try_borrow_mut() else {
            return 1;
        };
        let accepted = judge(&hash);
        context.accepted.set(accepted);
        if accepted { 0 } else { 1 }
    };
    // SAFETY: the caller keeps the contract of `enter`.
    unsafe { enter(privdata, 1, body) }
}

/// `openconnect_process_auth_form_vfn`. Anything that goes wrong is
/// `OC_FORM_RESULT_ERR`.
///
/// # Safety
///
/// As for [`enter`], and `form` must be null or a form of the library's that
/// is valid for the call.
unsafe extern "C" fn process_auth_form(privdata: *mut c_void, form: *mut AuthForm) -> c_int {
    let body = |context: &Context| {
        let (Some((library, _)), false) = (context.handle.get(), form.is_null()) else {
            return FormAnswer::Fail as c_int;
        };
        let mut form = Form {
            library,
            raw: form,
            life: PhantomData,
        };
        let Ok(mut fill) = context.form.try_borrow_mut() else {
            return FormAnswer::Fail as c_int;
        };
        fill(&mut form) as c_int
    };
    // SAFETY: the caller keeps the contract of `enter`.
    unsafe { enter(privdata, FormAnswer::Fail as c_int, body) }
}

/// `openconnect_getaddrinfo_vfn`. It asks the resolve callback, and answers
/// only with what the system's own `getaddrinfo` makes of the address that
/// callback gives: the library frees the answer with `freeaddrinfo`.
///
/// # Safety
///
/// As for [`enter`]; `node` and `service` must be null or NUL-terminated
/// strings, and `res` null or valid to write a pointer to.
unsafe extern "C" fn resolve(
    privdata: *mut c_void,
    node: *const c_char,
    service: *const c_char,
    _hints: *const AddrInfo,
    res: *mut *mut AddrInfo,
) -> c_int {
    let body = |context: &Context| {
        if node.is_null() || service.is_null() || res.is_null() {
            return system::EAI_FAIL;
        }
        // SAFETY: both are NUL-terminated strings for this call.
        let (host, port) = unsafe { (CStr::from_ptr(node), CStr::from_ptr(service)) };
        let port = port.to_str().ok().and_then(|port| port.parse().ok());
        let (Ok(host), Some(port)) = (host.to_str(), port) else {
            return system::EAI_FAIL;
        };
        let Ok(mut resolve) = context.resolve.try_borrow_mut() else {
            return system::EAI_FAIL;
        };
        match resolve(host, port) {
            // SAFETY: `res` is valid to write a pointer to.
            Some(address) => unsafe { system::numeric(address, res) },
            None => system::EAI_FAIL,
        }
    };
    // SAFETY: the caller keeps the contract of `enter`.
    unsafe { enter(privdata, system::EAI_FAIL, body) }
}

/// What a form callback tells the library. The values are the library's
/// `OC_FORM_RESULT_*`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormAnswer {
    /// The form is filled in: send it.
    Submit = 0,
    /// The user gave up.
    Cancel = 1,
    /// The form cannot be answered.
    Fail = -1,
}

/// What kind of field a form has, by the library's `OC_FORM_OPT_*` type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldKind {
    Text,
    Password,
    Select,
    Hidden,
    Other,
}

/// One field of a login form, copied out of the library's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub kind: FieldKind,
    pub name: String,
    pub label: String,
    /// The library flags it `OC_FORM_OPT_IGNORE`: not to be shown or filled.
    pub ignored: bool,
}

/// A login form the library is showing, for the length of one callback.
pub struct Form<'a> {
    library: Library,
    raw: *mut AuthForm,
    life: PhantomData<&'a mut AuthForm>,
}

/// Copies one of the library's strings, or `None` if it has none.
///
/// # Safety
///
/// `text` must be null or a NUL-terminated string valid for the call.
unsafe fn copied(text: *const c_char) -> Option<String> {
    if text.is_null() {
        return None;
    }
    // SAFETY: not null, so by the contract above a NUL-terminated string.
    let text = unsafe { CStr::from_ptr(text) };
    Some(text.to_string_lossy().into_owned())
}

impl Form<'_> {
    fn raw(&self) -> &AuthForm {
        // SAFETY: the library keeps the form alive for the callback, which
        // is as long as this `Form` lives.
        unsafe { &*self.raw }
    }

    /// The pointers to the fields, in the form's order.
    fn options(&self) -> Vec<*mut FormOpt> {
        let mut options = Vec::new();
        let mut next = self.raw().opts;
        while !next.is_null() {
            options.push(next);
            // SAFETY: a non-null link in the form's list points to a field
            // that lives as long as the form.
            next = unsafe { (*next).next };
        }
        options
    }

    /// What the gateway says alongside the form.
    pub fn message(&self) -> Option<String> {
        // SAFETY: a string of the form's, alive for the callback.
        unsafe { copied(self.raw().message) }
    }

    /// The gateway's error text. A form shown again with one set is a
    /// rejection of what was sent before.
    pub fn error(&self) -> Option<String> {
        // SAFETY: a string of the form's, alive for the callback.
        unsafe { copied(self.raw().error) }
    }

    /// Whether the form asks for a choice of group.
    pub fn asks_for_group(&self) -> bool {
        !self.raw().authgroup_opt.is_null()
    }

    /// The form's fields, in order.
    pub fn fields(&self) -> Vec<Field> {
        let field = |option: *mut FormOpt| {
            // SAFETY: from `options`, so it is a live field of this form,
            // and its strings are null or NUL-terminated.
            let (option, name, label) = unsafe {
                let option = &*option;
                (option, copied(option.name), copied(option.label))
            };
            let kind = match option.kind {
                1 => FieldKind::Text,
                2 => FieldKind::Password,
                3 => FieldKind::Select,
                4 => FieldKind::Hidden,
                _ => FieldKind::Other,
            };
            Field {
                kind,
                name: name.unwrap_or_default(),
                label: label.unwrap_or_default(),
                ignored: option.flags & OC_FORM_OPT_IGNORE != 0,
            }
        };
        self.options().into_iter().map(field).collect()
    }

    /// Fills in the field at `index` of [`fields`](Self::fields). The
    /// library takes its own copy of `value`. False if there is no such
    /// field or the library refuses.
    pub fn answer(&mut self, index: usize, value: &CStr) -> bool {
        let Some(option) = self.options().get(index).copied() else {
            return false;
        };
        // SAFETY: `option` is a live field of this form, and `value` is a
        // NUL-terminated string the library copies.
        unsafe { (self.library.set_option_value)(option, value.as_ptr()) == 0 }
    }
}

/// One `openconnect_info`, freed on drop. It is not `Send`: the thread that
/// makes it makes every library call on it.
///
/// Every handle is made the way the engine's rules ask of all of them: the
/// system's certificate store is not trusted, so that the certificate
/// callback is the judge; IPv6 is off; and every address comes from the
/// resolve callback.
pub struct Handle {
    library: Library,
    raw: *mut VpnInfo,
    /// What the library holds as `privdata`. Freed after the handle.
    context: *mut Context,
}

impl Handle {
    /// Makes a handle that calls back into `callbacks`.
    pub fn new(library: Library, callbacks: Callbacks) -> Option<Self> {
        let context = Box::into_raw(Context::new(callbacks));
        // SAFETY: the library is loaded. The user agent is a NUL-terminated
        // string the library copies; the callbacks have the signatures the
        // library declares, and one may be absent; `context` is not null and
        // stays valid until `drop` has freed the handle.
        let raw = unsafe {
            (library.vpninfo_new)(
                c"UBC VPN".as_ptr(),
                Some(validate_peer_cert),
                None,
                Some(process_auth_form),
                Some(ubc_vpn_progress),
                context.cast(),
            )
        };
        // From here `drop` frees both, in the right order.
        let handle = Self {
            library,
            raw,
            context,
        };
        if raw.is_null() {
            return None;
        }
        handle.context().handle.set(Some((library, raw)));
        // SAFETY: `raw` is a live handle on its own thread, and `resolve`
        // has the signature the library declares.
        let ipv4_only = unsafe {
            (library.set_system_trust)(raw, 0);
            (library.override_getaddrinfo)(raw, Some(resolve));
            (library.disable_ipv6)(raw) == 0
        };
        ipv4_only.then_some(handle)
    }

    fn context(&self) -> &Context {
        // SAFETY: `context` came from `Box::into_raw` in `new` and is freed
        // only in `drop`.
        unsafe { &*self.context }
    }

    /// `openconnect_parse_url`: zero, or a negative errno.
    pub fn parse_url(&self, url: &CStr) -> c_int {
        // SAFETY: `raw` is a live handle used on its own thread, and `url`
        // is a NUL-terminated string the library copies.
        unsafe { (self.library.parse_url)(self.raw, url.as_ptr()) }
    }

    /// `openconnect_obtain_cookie`: logs in. Zero when the gateway has
    /// issued a cookie. The record of the certificate callback is cleared
    /// first, so that afterwards it speaks for this connection only.
    pub fn obtain_cookie(&self) -> c_int {
        self.context().accepted.set(false);
        // SAFETY: `raw` is a live handle used on its own thread.
        unsafe { (self.library.obtain_cookie)(self.raw) }
    }

    /// Whether the certificate callback ran and accepted since the last
    /// connection began. The library calls it only for a certificate its
    /// own verification did not accept, so a login that succeeded without
    /// this being true was not judged by a pin and must be thrown away.
    pub fn certificate_accepted(&self) -> bool {
        self.context().accepted.get()
    }

    /// The session cookie, copied out of the handle at once.
    pub fn cookie(&self) -> Option<Secret> {
        // SAFETY: `raw` is a live handle used on its own thread. The answer
        // is null or a NUL-terminated string that belongs to the handle.
        unsafe { copied((self.library.get_cookie)(self.raw)) }.map(Secret::new)
    }

    /// Makes the command pipe and returns its write end, or `None` if the
    /// library could not make one. The handle closes both ends when it is
    /// dropped.
    pub fn command_pipe(&self) -> Option<CommandPipe> {
        // SAFETY: `raw` is a live handle used on its own thread.
        let pipe = unsafe { (self.library.setup_cmd_pipe)(self.raw) };
        #[cfg(windows)]
        let failed = pipe == usize::MAX;
        #[cfg(not(windows))]
        let failed = pipe < 0;
        (!failed).then_some(CommandPipe(pipe))
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            // SAFETY: `raw` came from `openconnect_vpninfo_new` and is freed
            // once. The library may call back while freeing, so the context
            // goes last.
            unsafe { (self.library.vpninfo_free)(self.raw) };
        }
        // SAFETY: `context` came from `Box::into_raw` in `new`, and nothing
        // can reach it now that the handle is gone.
        drop(unsafe { Box::from_raw(self.context) });
    }
}

/// The write end of a handle's command pipe. It may go to another thread,
/// which is how a login that is waiting is told to stop.
#[derive(Debug, Clone, Copy)]
pub struct CommandPipe(CmdPipe);

impl CommandPipe {
    /// Writes one command byte, such as `OC_CMD_CANCEL`. False if the write
    /// failed.
    ///
    /// # Safety
    ///
    /// The handle the pipe came from must still be alive: it closes the
    /// pipe when it is dropped, and the number may then belong to something
    /// else.
    pub unsafe fn send(self, command: u8) -> bool {
        // SAFETY: by the contract above the pipe is open, and one byte is
        // read from `command`.
        unsafe { system::write_byte(self.0, command) }
    }
}

/// The system's own name lookup and pipe write.
mod system {
    use std::ffi::{c_char, c_int};
    use std::net::SocketAddrV4;

    use super::{AddrInfo, CString, CmdPipe};

    const AF_INET: c_int = 2;
    const SOCK_STREAM: c_int = 1;
    const AI_NUMERICHOST: c_int = 0x4;
    #[cfg(windows)]
    const AI_NUMERICSERV: c_int = 0x8;
    #[cfg(target_os = "macos")]
    const AI_NUMERICSERV: c_int = 0x1000;
    #[cfg(all(unix, not(target_os = "macos")))]
    const AI_NUMERICSERV: c_int = 0x400;

    /// The lookup failed for good: `EAI_FAIL`, as this system numbers it.
    #[cfg(windows)]
    pub(super) const EAI_FAIL: c_int = 11003;
    #[cfg(target_os = "macos")]
    pub(super) const EAI_FAIL: c_int = 4;
    #[cfg(all(unix, not(target_os = "macos")))]
    pub(super) const EAI_FAIL: c_int = -4;

    #[cfg(windows)]
    #[link(name = "ws2_32")]
    unsafe extern "system" {
        fn getaddrinfo(
            node: *const c_char,
            service: *const c_char,
            hints: *const AddrInfo,
            res: *mut *mut AddrInfo,
        ) -> c_int;
        fn send(socket: usize, buffer: *const c_char, length: c_int, flags: c_int) -> c_int;
    }

    #[cfg(unix)]
    unsafe extern "C" {
        fn getaddrinfo(
            node: *const c_char,
            service: *const c_char,
            hints: *const AddrInfo,
            res: *mut *mut AddrInfo,
        ) -> c_int;
        fn write(fd: c_int, buffer: *const std::ffi::c_void, count: usize) -> isize;
    }

    /// Has the system turn one IPv4 address and port into the list the
    /// library expects, with no lookup of any name.
    ///
    /// # Safety
    ///
    /// `res` must be valid to write a pointer to.
    pub(super) unsafe fn numeric(address: SocketAddrV4, res: *mut *mut AddrInfo) -> c_int {
        let texts = (
            CString::new(address.ip().to_string()),
            CString::new(address.port().to_string()),
        );
        let (Ok(host), Ok(port)) = texts else {
            return EAI_FAIL;
        };
        // SAFETY: all-zero is a valid `addrinfo`: integers and null pointers.
        let mut hints: AddrInfo = unsafe { std::mem::zeroed() };
        hints.flags = AI_NUMERICHOST | AI_NUMERICSERV;
        hints.family = AF_INET;
        hints.socktype = SOCK_STREAM;
        // SAFETY: the strings are NUL-terminated and outlive the call,
        // `hints` is a valid `addrinfo`, and `res` is valid to write to.
        unsafe { getaddrinfo(host.as_ptr(), port.as_ptr(), &hints, res) }
    }

    /// Writes one byte to the write end of a command pipe.
    ///
    /// # Safety
    ///
    /// `pipe` must be an open command pipe of the library's.
    pub(super) unsafe fn write_byte(pipe: CmdPipe, byte: u8) -> bool {
        let buffer = [byte];
        // SAFETY: `pipe` is open by the contract above, and one byte is read
        // from `buffer`, which outlives the call. On Windows the pipe is a
        // socket.
        #[cfg(windows)]
        let written = unsafe { send(pipe, buffer.as_ptr().cast(), 1, 0) as isize };
        // SAFETY: as above; elsewhere it is a file descriptor.
        #[cfg(unix)]
        let written = unsafe { write(pipe, buffer.as_ptr().cast(), 1) };
        written == 1
    }
}
