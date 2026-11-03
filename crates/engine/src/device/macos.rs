//! The tunnel device on macOS: a `utun` device, made by connecting a kernel
//! control socket to `com.apple.net.utun_control`.
//!
//! - It is made close-on-exec, so no program the process starts holds a
//!   copy of it, which would keep the device after the tunnel ends. macOS
//!   has no `SOCK_CLOEXEC`, so the flag is set with `fcntl` straight after
//!   `socket`, before anything else is done with the descriptor.
//! - The kernel picks the unit (`sc_unit` 0), so a new device is made every
//!   time, never an existing one joined, and its name is always `utun` and
//!   a number. Any other name is refused.
//! - Only the superuser may connect to the control, so without that right
//!   nothing is made.
//! - The kernel removes the device once its last descriptor is closed.
//!
//! A `utun` device puts a 4-byte address family, in network byte order,
//! before every packet. The library handles it: on macOS `tun.c` defines
//! `TUN_HAS_AF_PREFIX`, and `os_read_tun` and `os_write_tun` strip and add
//! the prefix on every descriptor it was given with `setup_tun_fd`, whatever
//! its name; only a script's socket goes without. So the engine hands the
//! descriptor over as it is.

use std::ffi::{CString, c_char, c_int, c_uint, c_ulong, c_void};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

use crate::TunnelError;

/// The control that makes `utun` devices.
const CONTROL: &[u8] = b"com.apple.net.utun_control";
const PREFIX: &[u8] = b"utun";

/// `IFNAMSIZ`: a name and its NUL.
const NAME_SIZE: usize = 16;
/// `MAX_KCTL_NAME`.
const CONTROL_NAME_SIZE: usize = 96;

const PF_SYSTEM: c_int = 32;
const AF_SYSTEM: u8 = 32;
const AF_SYS_CONTROL: u16 = 2;
const SOCK_DGRAM: c_int = 2;
const SYSPROTO_CONTROL: c_int = 2;
/// `_IOWR('N', 3, struct ctl_info)`.
const CTLIOCGINFO: c_ulong = 0xc064_4e03;
const UTUN_OPT_IFNAME: c_int = 2;
const F_GETFD: c_int = 1;
const F_SETFD: c_int = 2;
const FD_CLOEXEC: c_int = 1;

/// `struct ctl_info`: the control's id, which the kernel fills in, and its
/// name.
#[repr(C)]
struct CtlInfo {
    id: u32,
    name: [u8; CONTROL_NAME_SIZE],
}

/// `struct sockaddr_ctl`.
#[repr(C)]
struct SockaddrCtl {
    len: u8,
    family: u8,
    sysaddr: u16,
    id: u32,
    unit: u32,
    reserved: [u32; 5],
}

unsafe extern "C" {
    fn socket(domain: c_int, kind: c_int, protocol: c_int) -> c_int;
    fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;
    fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
    fn connect(fd: c_int, addr: *const SockaddrCtl, len: u32) -> c_int;
    fn getsockopt(fd: c_int, level: c_int, name: c_int, value: *mut c_void, len: *mut u32)
    -> c_int;
    fn if_nametoindex(name: *const c_char) -> c_uint;
}

/// Opens a new `utun` device, close-on-exec, and gives its descriptor and
/// the name the kernel gave it. Fails, leaving no device, without the right
/// to make one (only the superuser has it), or if the kernel's answer is not
/// a name of ours. The descriptor is closed on every failure.
pub(super) fn open() -> Result<(OwnedFd, String), TunnelError> {
    // SAFETY: plain integer arguments.
    let fd = unsafe { socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL) };
    if fd < 0 {
        return Err(TunnelError::Failed);
    }
    // SAFETY: `socket` just returned this descriptor, and nothing else owns
    // it. From here on it is closed on every path, which removes a device
    // made on it.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    close_on_exec(&fd)?;
    let mut info = CtlInfo {
        id: 0,
        name: [0; CONTROL_NAME_SIZE],
    };
    info.name[..CONTROL.len()].copy_from_slice(CONTROL);
    // SAFETY: `fd` is open, and `info` is a whole `struct ctl_info` that the
    // kernel reads and writes back during the call only.
    if unsafe { ioctl(fd.as_raw_fd(), CTLIOCGINFO, &mut info as *mut CtlInfo) } < 0 {
        return Err(TunnelError::Failed);
    }
    let address = SockaddrCtl {
        len: size_of::<SockaddrCtl>() as u8,
        family: AF_SYSTEM,
        sysaddr: AF_SYS_CONTROL,
        id: info.id,
        // The kernel picks the next free unit.
        unit: 0,
        reserved: [0; 5],
    };
    // SAFETY: `fd` is open, and `address` is a whole `struct sockaddr_ctl`
    // of the length given, which the kernel only reads during the call.
    let connected = unsafe { connect(fd.as_raw_fd(), &address, size_of::<SockaddrCtl>() as u32) };
    if connected < 0 {
        return Err(TunnelError::Failed);
    }
    let mut field = [0u8; NAME_SIZE];
    let mut len = NAME_SIZE as u32;
    // SAFETY: `fd` is open, `field` has room for `len` bytes, and the kernel
    // writes no more than that and the length it wrote, during the call only.
    let asked = unsafe {
        getsockopt(
            fd.as_raw_fd(),
            SYSPROTO_CONTROL,
            UTUN_OPT_IFNAME,
            field.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if asked < 0 {
        return Err(TunnelError::Failed);
    }
    let name = ours(&field).ok_or(TunnelError::Failed)?;
    Ok((fd, name))
}

/// Marks `fd` close-on-exec.
fn close_on_exec(fd: &OwnedFd) -> Result<(), TunnelError> {
    // SAFETY: `fd` is open, and `F_GETFD` takes no third argument.
    let flags = unsafe { fcntl(fd.as_raw_fd(), F_GETFD) };
    if flags < 0 {
        return Err(TunnelError::Failed);
    }
    // SAFETY: `fd` is open, setting close-on-exec changes nothing for this
    // process, and `F_SETFD` takes an `int`.
    if unsafe { fcntl(fd.as_raw_fd(), F_SETFD, flags | FD_CLOEXEC) } < 0 {
        return Err(TunnelError::Failed);
    }
    Ok(())
}

/// The name the kernel wrote, if it is one of ours: `utun` and a number,
/// NUL-terminated within the field.
fn ours(field: &[u8; NAME_SIZE]) -> Option<String> {
    let end = field.iter().position(|byte| *byte == 0)?;
    let number = field[..end].strip_prefix(PREFIX)?;
    if number.is_empty() || !number.iter().all(u8::is_ascii_digit) {
        return None;
    }
    String::from_utf8(field[..end].to_vec()).ok()
}

/// The longest a closed device is waited for to disappear.
const GONE_LIMIT: Duration = Duration::from_secs(5);

/// Waits, for at most [`GONE_LIMIT`], until the system has no interface
/// named `name`. The kernel removes a `utun` device as its descriptor
/// closes, so this normally returns at once. It also returns once it cannot
/// tell.
pub(super) fn wait_until_gone(name: &str) {
    let Ok(name) = CString::new(name) else {
        return;
    };
    let start = Instant::now();
    while start.elapsed() < GONE_LIMIT {
        // Zero is gone, or no answer, which waiting would not change.
        // SAFETY: `name` is a NUL-terminated string that outlives the call.
        if unsafe { if_nametoindex(name.as_ptr()) } == 0 {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" {
        fn geteuid() -> c_uint;
    }

    fn field(name: &[u8]) -> [u8; NAME_SIZE] {
        let mut field = [0; NAME_SIZE];
        field[..name.len()].copy_from_slice(name);
        field
    }

    fn exists(name: &str) -> bool {
        let name = CString::new(name).unwrap();
        // SAFETY: `name` is a NUL-terminated string that outlives the call.
        unsafe { if_nametoindex(name.as_ptr()) != 0 }
    }

    // Security rule: the device's name is `utun` and a number; any other
    // answer is refused.
    #[test]
    fn only_a_numbered_utun_name_is_ours() {
        for good in ["utun0", "utun7", "utun123456789"] {
            assert_eq!(ours(&field(good.as_bytes())).as_deref(), Some(good));
        }
        for bad in [
            "", "utun", "utunx", "utun1a", "utun-1", "tun0", "Utun0", "xutun0", "ubcvpn0", "en0",
        ] {
            assert_eq!(ours(&field(bad.as_bytes())), None, "{bad:?}");
        }
        // No NUL within the field.
        assert_eq!(ours(&[b'1'; NAME_SIZE]), None);
        let mut full = [b'1'; NAME_SIZE];
        full[..PREFIX.len()].copy_from_slice(PREFIX);
        assert_eq!(ours(&full), None);
    }

    #[test]
    fn the_kernel_structures_have_their_sizes() {
        assert_eq!(size_of::<CtlInfo>(), 100);
        assert_eq!(size_of::<SockaddrCtl>(), 32);
        assert!(CONTROL.len() < CONTROL_NAME_SIZE);
        // `_IOWR('N', 3, struct ctl_info)`: in and out, the size, the group
        // and the number.
        let ctliocginfo = 0xc000_0000 | ((size_of::<CtlInfo>() as c_ulong) << 16) | 0x4e03;
        assert_eq!(CTLIOCGINFO, ctliocginfo);
    }

    // The ordinary test run is not the superuser. Without the right to make
    // a device, opening one fails, and the descriptor it opened is closed.
    #[test]
    fn without_the_right_no_device_is_made() {
        // SAFETY: no arguments, and it cannot fail.
        if unsafe { geteuid() } == 0 {
            println!("SKIPPED: this runs as root, which may make a device");
            return;
        }
        assert_eq!(open().err(), Some(TunnelError::Failed));
        ubc_vpn_test_lines::whole_line!("RAN: device refused without the right to make one");
    }

    /// The numbers of the sockets the shell started from this process was
    /// given.
    fn a_childs_sockets() -> Vec<c_int> {
        // The descriptor that read the folder is a folder, not a socket.
        let listed = std::process::Command::new("/bin/sh")
            .args([
                "-c",
                r#"for fd in /dev/fd/*; do [ -S "$fd" ] && echo "${fd##*/}"; done; :"#,
            ])
            .output()
            .expect("the shell runs");
        assert!(listed.status.success(), "{listed:?}");
        let listed = String::from_utf8_lossy(&listed.stdout);
        listed
            .lines()
            .map(|n| n.parse().expect("a number"))
            .collect()
    }

    /// A socket that a started program does get, to show the listing
    /// works.
    fn an_inherited_socket() -> std::os::unix::net::UnixDatagram {
        let (socket, _) = std::os::unix::net::UnixDatagram::pair().unwrap();
        // SAFETY: `socket` is open, and these take an `int` or nothing.
        unsafe {
            let flags = fcntl(socket.as_raw_fd(), F_GETFD);
            assert!(flags >= 0);
            assert!(fcntl(socket.as_raw_fd(), F_SETFD, flags & !FD_CLOEXEC) >= 0);
        }
        socket
    }

    // Security rule: the device is ours alone from the moment it is opened,
    // before the library makes it close-on-exec. A program started then
    // holds no copy. The device has a `utun` name, and closing the
    // descriptor removes it. Only as root, where the workflow allows it.
    #[test]
    fn as_root_a_device_is_close_on_exec_and_goes_on_close() {
        if std::env::var_os("UBC_VPN_TEST_DEVICE").is_none() {
            println!("SKIPPED: making a tunnel device needs UBC_VPN_TEST_DEVICE");
            return;
        }
        let (fd, name) = open().expect("a device as root");
        assert!(ours(&field(name.as_bytes())).is_some(), "{name:?}");
        assert!(exists(&name), "no interface {name:?}");
        // SAFETY: `fd` is open, and `F_GETFD` takes no third argument.
        let flags = unsafe { fcntl(fd.as_raw_fd(), F_GETFD) };
        assert!(flags >= 0 && flags & FD_CLOEXEC != 0, "{flags}");
        let control = an_inherited_socket();
        let sockets = a_childs_sockets();
        assert!(sockets.contains(&control.as_raw_fd()), "{sockets:?}");
        assert!(!sockets.contains(&fd.as_raw_fd()), "{sockets:?}");
        drop(fd);
        wait_until_gone(&name);
        assert!(
            !exists(&name),
            "{name:?} is left after its descriptor closed"
        );
        ubc_vpn_test_lines::whole_line!("RAN: device is close-on-exec and goes on close");
    }

    // A made-up interface is gone at once; waiting for it returns without
    // using up the limit.
    #[test]
    fn waiting_for_an_interface_that_is_not_there_returns_at_once() {
        let start = Instant::now();
        wait_until_gone("utun-made-up");
        wait_until_gone("nul\0inside");
        assert!(start.elapsed() < Duration::from_secs(1));
    }
}
