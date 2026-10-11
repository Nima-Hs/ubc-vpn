// Probe: checks that a Rust binary can drive a given libopenconnect build on this OS.
//   probe   <url>               : TLS + cert callback + login-form callback, then cancel
//   connect <url> <user> <pass> : full login, CSTP connect, tun device with NO script
use std::ffi::{c_char, c_int, c_uint, c_void, CStr, CString};
use std::sync::atomic::{AtomicPtr, AtomicU32, Ordering};
use std::sync::OnceLock;

#[repr(C)]
struct OcInfo {
    _p: [u8; 0],
}
#[repr(C)]
struct FormOpt {
    next: *mut FormOpt,
    typ: c_int,
    name: *mut c_char,
    label: *mut c_char,
    _value: *mut c_char,
    flags: c_uint,
    reserved: *mut c_void,
}
#[repr(C)]
struct AuthForm {
    banner: *mut c_char,
    message: *mut c_char,
    error: *mut c_char,
    auth_id: *mut c_char,
    method: *mut c_char,
    action: *mut c_char,
    opts: *mut FormOpt,
    authgroup_opt: *mut c_void,
    authgroup_selection: c_int,
}
#[repr(C)]
struct SplitInclude {
    route: *const c_char,
    next: *mut SplitInclude,
}
#[repr(C)]
struct IpInfo {
    addr: *const c_char,
    netmask: *const c_char,
    addr6: *const c_char,
    netmask6: *const c_char,
    dns: [*const c_char; 3],
    nbns: [*const c_char; 3],
    domain: *const c_char,
    proxy_pac: *const c_char,
    mtu: c_int,
    split_dns: *mut SplitInclude,
    split_includes: *mut SplitInclude,
    split_excludes: *mut SplitInclude,
    gateway_addr: *mut c_char,
}

type ProgressFn = unsafe extern "C" fn(*mut c_void, c_int, *const c_char, ...);

#[cfg_attr(windows, link(name = "libopenconnect-5", kind = "raw-dylib"))]
#[cfg_attr(not(windows), link(name = "openconnect"))]
extern "C" {
    fn openconnect_init_ssl() -> c_int;
    fn openconnect_get_version() -> *const c_char;
    fn openconnect_vpninfo_new(
        useragent: *const c_char,
        validate: extern "C" fn(*mut c_void, *const c_char) -> c_int,
        write_cfg: Option<extern "C" fn(*mut c_void, *const c_char, c_int) -> c_int>,
        auth_form: extern "C" fn(*mut c_void, *mut AuthForm) -> c_int,
        progress: ProgressFn,
        privdata: *mut c_void,
    ) -> *mut OcInfo;
    fn openconnect_parse_url(v: *mut OcInfo, url: *const c_char) -> c_int;
    fn openconnect_set_system_trust(v: *mut OcInfo, val: c_uint);
    fn openconnect_obtain_cookie(v: *mut OcInfo) -> c_int;
    fn openconnect_get_peer_cert_hash(v: *mut OcInfo) -> *const c_char;
    fn openconnect_set_option_value(opt: *mut FormOpt, value: *const c_char) -> c_int;
    fn openconnect_make_cstp_connection(v: *mut OcInfo) -> c_int;
    fn openconnect_setup_tun_device(
        v: *mut OcInfo,
        script: *const c_char,
        ifname: *const c_char,
    ) -> c_int;
    fn openconnect_get_ifname(v: *mut OcInfo) -> *const c_char;
    fn openconnect_get_ip_info(
        v: *mut OcInfo,
        info: *mut *const IpInfo,
        cstp: *mut *mut c_void,
        dtls: *mut *mut c_void,
    ) -> c_int;
    fn openconnect_vpninfo_free(v: *mut OcInfo);
}

extern "C" {
    fn oc_progress_shim(p: *mut c_void, level: c_int, fmt: *const c_char, ...);
}

static PROGRESS: AtomicU32 = AtomicU32::new(0);
static VALIDATE: AtomicU32 = AtomicU32::new(0);
static FORMS: AtomicU32 = AtomicU32::new(0);
static INFO: AtomicPtr<OcInfo> = AtomicPtr::new(std::ptr::null_mut());
static CREDS: OnceLock<(CString, CString)> = OnceLock::new();

const PRIV: usize = 0xC0FFEE;

fn s(p: *const c_char) -> String {
    if p.is_null() {
        "<null>".into()
    } else {
        unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
    }
}

#[no_mangle]
extern "C" fn rust_progress(_p: *mut c_void, level: c_int, msg: *const c_char) {
    PROGRESS.fetch_add(1, Ordering::SeqCst);
    print!("  [progress L{level}] {}", s(msg));
}

extern "C" fn validate(p: *mut c_void, reason: *const c_char) -> c_int {
    VALIDATE.fetch_add(1, Ordering::SeqCst);
    assert_eq!(p as usize, PRIV, "privdata must round-trip");
    let hash = s(unsafe { openconnect_get_peer_cert_hash(INFO.load(Ordering::SeqCst)) });
    println!("  [validate_peer_cert] reason={:?} hash={hash}", s(reason));
    assert!(hash.starts_with("pin-sha256:"), "unexpected hash form");
    0
}

extern "C" fn auth_form(_p: *mut c_void, form: *mut AuthForm) -> c_int {
    let n = FORMS.fetch_add(1, Ordering::SeqCst) + 1;
    let f = unsafe { &*form };
    println!(
        "  [process_auth_form #{n}] message={:?} error={:?}",
        s(f.message),
        s(f.error)
    );
    let Some((user, pass)) = CREDS.get() else {
        println!("    probe mode -> cancelling, nothing is sent");
        return 1; // OC_FORM_RESULT_CANCELLED
    };
    if n > 4 {
        return -1;
    }
    let mut opt = f.opts;
    while !opt.is_null() {
        let o = unsafe { &*opt };
        println!(
            "    field type={} name={:?} label={:?}",
            o.typ,
            s(o.name),
            s(o.label)
        );
        match o.typ {
            1 => unsafe {
                openconnect_set_option_value(opt, user.as_ptr());
            },
            2 => unsafe {
                openconnect_set_option_value(opt, pass.as_ptr());
            },
            _ => {}
        }
        opt = o.next;
    }
    0 // OC_FORM_RESULT_OK
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let mode = a.get(1).map(String::as_str).unwrap_or("");
    const USAGE: &str = "usage: oc-probe probe <url> | oc-probe connect <url> <user> <pass>";
    let args_ok = match mode {
        "probe" => a.len() == 3,
        "connect" => a.len() == 5,
        _ => false,
    };
    if !args_ok {
        eprintln!("{USAGE}");
        std::process::exit(2);
    }
    let url = &a[2];
    if mode == "connect" {
        CREDS
            .set((
                CString::new(a[3].as_str()).unwrap(),
                CString::new(a[4].as_str()).unwrap(),
            ))
            .unwrap();
    }
    let mut ok = true;
    unsafe {
        println!("init_ssl = {}", openconnect_init_ssl());
        println!("version  = {}", s(openconnect_get_version()));
        let ua = CString::new("AnyConnect-compatible OpenConnect VPN Agent (oc-probe)").unwrap();
        let v = openconnect_vpninfo_new(
            ua.as_ptr(),
            validate,
            None,
            auth_form,
            oc_progress_shim,
            PRIV as *mut c_void,
        );
        assert!(!v.is_null());
        INFO.store(v, Ordering::SeqCst);
        let u = CString::new(url.as_str()).unwrap();
        println!("parse_url = {}", openconnect_parse_url(v, u.as_ptr()));
        openconnect_set_system_trust(v, 0);
        let rc = openconnect_obtain_cookie(v);
        println!("obtain_cookie = {rc}");
        if mode == "connect" {
            ok &= rc == 0;
            if rc == 0 {
                let rc = openconnect_make_cstp_connection(v);
                println!("make_cstp_connection = {rc}");
                ok &= rc == 0;
                let mut info: *const IpInfo = std::ptr::null();
                let rc = openconnect_get_ip_info(
                    v,
                    &mut info,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                );
                println!("get_ip_info = {rc}");
                if rc == 0 && !info.is_null() {
                    let i = &*info;
                    println!(
                        "  addr={} netmask={} dns0={} domain={} mtu={}",
                        s(i.addr),
                        s(i.netmask),
                        s(i.dns[0]),
                        s(i.domain),
                        i.mtu
                    );
                    let mut r = i.split_includes;
                    while !r.is_null() {
                        println!("  split-include {}", s((*r).route));
                        r = (*r).next;
                    }
                }
                // NULL script: the library must create the device and run nothing.
                let rc = openconnect_setup_tun_device(v, std::ptr::null(), std::ptr::null());
                println!("setup_tun_device(no script) = {rc}");
                ok &= rc == 0;
                let ifname = s(openconnect_get_ifname(v));
                println!("ifname = {ifname}");
                let show = if cfg!(target_os = "linux") {
                    std::process::Command::new("ip")
                        .args(["addr", "show", "dev", &ifname])
                        .status()
                } else if cfg!(windows) {
                    // Fails unless an interface with this exact name exists.
                    std::process::Command::new("netsh")
                        .args(["interface", "ipv4", "show", "interfaces"])
                        .arg(format!("interface={ifname}"))
                        .status()
                } else {
                    std::process::Command::new("ifconfig").arg(&ifname).status()
                };
                ok &= show.map(|st| st.success()).unwrap_or(false);
            }
        }
        openconnect_vpninfo_free(v);
    }
    let (p, c, f) = (
        PROGRESS.load(Ordering::SeqCst),
        VALIDATE.load(Ordering::SeqCst),
        FORMS.load(Ordering::SeqCst),
    );
    println!("callbacks: progress={p} validate={c} auth_form={f}");
    ok &= p > 0 && c > 0 && f > 0;
    println!("RESULT: {}", if ok { "PASS" } else { "FAIL" });
    std::process::exit(if ok { 0 } else { 1 });
}
