//! The tunnel device on Linux: a `tun` device from `/dev/net/tun`.
//!
//! - It is opened close-on-exec, so no program the process starts holds a
//!   copy of it, which would keep the device after the tunnel ends.
//! - It is a layer-3 device with no packet header (`IFF_TUN | IFF_NO_PI`),
//!   as the library expects.
//! - The kernel names it from the pattern `ubcvpn%d`, so the name is always
//!   `ubcvpn` and a number. The service's split DNS changes only links with
//!   that prefix. The pattern can never name a device that exists already,
//!   so a new device is made every time, never an existing one joined.
//! - It is not made persistent (no `TUNSETPERSIST`): the kernel removes it
//!   once the last descriptor of it is closed.
//!
//! The library may use vhost-net with the device: it opens `/dev/vhost-net`
//! without close-on-exec, and that descriptor keeps the device too. So once
//! the library has the device, [`seal_vhost`] marks it close-on-exec. The
//! library closes it only when its main loop ends, so the tunnel runs the
//! main loop on every path after the device was handed over.

use std::ffi::{CStr, CString, c_char, c_int, c_short, c_uint, c_ulong};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

use crate::TunnelError;

/// The name the kernel is asked to number. Only links with this prefix are
/// the service's.
const PATTERN: &CStr = c"ubcvpn%d";
const PREFIX: &[u8] = b"ubcvpn";

/// `IFNAMSIZ`: a name and its NUL.
const NAME_SIZE: usize = 16;

const O_RDWR: c_int = 0o2;
/// The same on x86-64 and arm64, the systems the app is built for.
const O_CLOEXEC: c_int = 0o2000000;
const IFF_TUN: c_short = 0x0001;
const IFF_NO_PI: c_short = 0x1000;
/// `_IOW('T', 202, int)`, with the generic ioctl numbering of x86-64 and
/// arm64.
const TUNSETIFF: c_ulong = 0x4004_54ca;
const F_GETFD: c_int = 1;
const F_SETFD: c_int = 2;
const FD_CLOEXEC: c_int = 1;

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("check the open flags and ioctl numbers for this architecture");

/// `struct ifreq` as `TUNSETIFF` reads and writes it: the name, then the
/// flags at the start of the union, padded to the 40 bytes of a 64-bit
/// system.
#[repr(C)]
struct IfReq {
    name: [u8; NAME_SIZE],
    flags: c_short,
    _rest: [u8; 22],
}

unsafe extern "C" {
    #[link_name = "open"]
    fn open_file(path: *const c_char, flags: c_int, ...) -> c_int;
    fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;
    fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
    fn if_nametoindex(name: *const c_char) -> c_uint;
}

/// Opens a new `tun` device, close-on-exec, and gives its descriptor and
/// the name the kernel gave it. Fails, leaving no device, without the right
/// to make one (`CAP_NET_ADMIN`), or if the kernel's answer is not a name
/// of ours.
pub(super) fn open() -> Result<(OwnedFd, String), TunnelError> {
    // SAFETY: the path is a NUL-terminated string that outlives the call,
    // and these flags take no third argument.
    let fd = unsafe { open_file(c"/dev/net/tun".as_ptr(), O_RDWR | O_CLOEXEC) };
    if fd < 0 {
        return Err(TunnelError::Failed);
    }
    // SAFETY: `open` just returned this descriptor, and nothing else owns
    // it. From here on it is closed on every path, which removes a device
    // made on it: the device is not persistent.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut request = IfReq {
        name: [0; NAME_SIZE],
        flags: IFF_TUN | IFF_NO_PI,
        _rest: [0; 22],
    };
    let pattern = PATTERN.to_bytes_with_nul();
    request.name[..pattern.len()].copy_from_slice(pattern);
    // SAFETY: `fd` is open, and `request` is a whole `struct ifreq` that the
    // kernel reads and writes back during the call only.
    if unsafe { ioctl(fd.as_raw_fd(), TUNSETIFF, &mut request as *mut IfReq) } < 0 {
        return Err(TunnelError::Failed);
    }
    let name = ours(&request.name).ok_or(TunnelError::Failed)?;
    Ok((fd, name))
}

/// The name in a `struct ifreq`, if it is one the kernel makes from
/// [`PATTERN`]: `ubcvpn` and a number, NUL-terminated within the field.
fn ours(field: &[u8; NAME_SIZE]) -> Option<String> {
    let end = field.iter().position(|byte| *byte == 0)?;
    let number = field[..end].strip_prefix(PREFIX)?;
    if number.is_empty() || !number.iter().all(u8::is_ascii_digit) {
        return None;
    }
    String::from_utf8(field[..end].to_vec()).ok()
}

/// Marks close-on-exec every descriptor of this process that is open on
/// `/dev/vhost-net`. The library opens one without it when it uses
/// vhost-net for the device, and that descriptor keeps the device: a
/// program the process started would hold the device after the tunnel
/// ended. Fails if the process's descriptors cannot be read or changed.
pub(crate) fn seal_vhost() -> Result<(), TunnelError> {
    let entries = std::fs::read_dir("/proc/self/fd").map_err(|_| TunnelError::Failed)?;
    let mut listed = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|_| TunnelError::Failed)?;
        let fd = entry.file_name().to_str().and_then(|n| n.parse().ok());
        listed.push((fd, std::fs::read_link(entry.path())));
    }
    seal_listed(listed, set_cloexec)
}

/// The decision [`seal_vhost`] makes for each descriptor it listed: its
/// number and what reading its link gave. Seals every one open on
/// `/dev/vhost-net`, and fails on anything it cannot tell, so a descriptor
/// it could not read is never left inheritable.
fn seal_listed(
    listed: Vec<(Option<c_int>, std::io::Result<std::path::PathBuf>)>,
    mut seal: impl FnMut(c_int) -> Result<(), TunnelError>,
) -> Result<(), TunnelError> {
    for (fd, target) in listed {
        let fd = fd.ok_or(TunnelError::Failed)?;
        let target = match target {
            Ok(target) => target,
            // Closed since it was listed, as the descriptor that read the
            // folder always is: no longer anything a child could get.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(TunnelError::Failed),
        };
        if target.as_os_str() == "/dev/vhost-net" {
            seal(fd)?;
        }
    }
    Ok(())
}

fn set_cloexec(fd: c_int) -> Result<(), TunnelError> {
    // SAFETY: reading the flags of a descriptor number has no effect on
    // it, and `F_GETFD` takes no third argument.
    let flags = unsafe { fcntl(fd, F_GETFD) };
    if flags < 0 {
        return Err(TunnelError::Failed);
    }
    // SAFETY: setting close-on-exec changes nothing for this process, and
    // `F_SETFD` takes an `int`.
    if unsafe { fcntl(fd, F_SETFD, flags | FD_CLOEXEC) } < 0 {
        return Err(TunnelError::Failed);
    }
    Ok(())
}

/// The longest a closed device is waited for to disappear.
const GONE_LIMIT: Duration = Duration::from_secs(5);

/// Waits, for at most [`GONE_LIMIT`], until the system has no link named
/// `name`. The kernel removes a device that is not persistent as its last
/// descriptor closes, so this normally returns at once. It also returns
/// once it cannot tell.
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

    fn field(name: &[u8]) -> [u8; NAME_SIZE] {
        let mut field = [0; NAME_SIZE];
        field[..name.len()].copy_from_slice(name);
        field
    }

    // Security rule: the device's name is `ubcvpn` and a number, which the
    // service's split DNS takes as its own; any other answer is refused.
    #[test]
    fn only_a_numbered_ubcvpn_name_is_ours() {
        for good in ["ubcvpn0", "ubcvpn7", "ubcvpn123456789"] {
            assert_eq!(ours(&field(good.as_bytes())).as_deref(), Some(good));
        }
        for bad in [
            "", "ubcvpn", "ubcvpn%d", "ubcvpnx", "ubcvpn1a", "ubcvpn-1", "tun0", "Ubcvpn0",
            "xubcvpn0",
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
    fn the_pattern_fits_and_has_the_prefix() {
        let pattern = PATTERN.to_bytes();
        assert!(pattern.len() < NAME_SIZE);
        assert!(pattern.starts_with(PREFIX));
        assert_eq!(std::mem::size_of::<IfReq>(), 40);
    }

    // The ordinary test run is not root. Without the right to make a
    // device, opening one fails, and the descriptor it opened is closed.
    #[test]
    fn without_the_right_no_device_is_made() {
        use std::os::unix::fs::MetadataExt;
        let uid = std::fs::metadata("/proc/self").map(|meta| meta.uid());
        if uid.as_ref().is_ok_and(|uid| *uid == 0) {
            println!("SKIPPED: this runs as root, which may make a device");
            return;
        }
        assert_eq!(open().err(), Some(TunnelError::Failed));
        println!("RAN: device refused without the right to make one");
    }

    /// What the shell started from this process was given: the targets
    /// of its descriptors.
    fn a_childs_files() -> Vec<String> {
        // The descriptor that read the folder is closed before it is read.
        let listed = std::process::Command::new("/bin/sh")
            .args([
                "-c",
                r#"for fd in /proc/$$/fd/*; do readlink "$fd" || :; done"#,
            ])
            .output()
            .expect("the shell runs");
        assert!(listed.status.success(), "{listed:?}");
        let listed = String::from_utf8_lossy(&listed.stdout);
        let files: Vec<String> = listed.lines().map(str::to_string).collect();
        // Its input is /dev/null, so the listing worked.
        assert!(files.iter().any(|file| file == "/dev/null"), "{files:?}");
        files
    }

    // Security rule: the device is ours alone from the moment it is opened,
    // before the library makes it close-on-exec. A program started then
    // holds no copy. The device has an `ubcvpn` name, and closing the
    // descriptor removes it. Only as root, where the workflow allows it.
    #[test]
    fn as_root_a_device_is_close_on_exec_and_goes_on_close() {
        if std::env::var_os("UBC_VPN_TEST_DEVICE").is_none() {
            println!("SKIPPED: making a tunnel device needs UBC_VPN_TEST_DEVICE");
            return;
        }
        let (fd, name) = open().expect("a device as root");
        assert!(ours(&field(name.as_bytes())).is_some(), "{name:?}");
        let link = std::path::Path::new("/sys/class/net").join(&name);
        assert!(link.exists(), "no link {name:?}");
        // SAFETY: `fd` is open, and `F_GETFD` takes no third argument.
        let flags = unsafe { fcntl(fd.as_raw_fd(), F_GETFD) };
        assert!(flags >= 0 && flags & FD_CLOEXEC != 0, "{flags}");
        let files = a_childs_files();
        assert!(
            !files.iter().any(|file| file == "/dev/net/tun"),
            "{files:?}"
        );
        drop(fd);
        wait_until_gone(&name);
        assert!(
            !link.exists(),
            "{name:?} is left after its descriptor closed"
        );
        println!("RAN: device is close-on-exec and goes on close");
    }

    // Security rule: every vhost-net descriptor is sealed, one closed since
    // it was listed is passed over, and one whose link cannot be read for
    // any other reason fails the whole call: it might be the vhost-net one.
    #[test]
    fn a_descriptor_that_cannot_be_read_fails_the_seal() {
        use std::io::{Error, ErrorKind};
        use std::path::PathBuf;
        let link = |path: &str| Ok(PathBuf::from(path));
        let sealing = |listed| {
            let mut sealed = Vec::new();
            let result = seal_listed(listed, |fd| {
                sealed.push(fd);
                Ok(())
            });
            (result, sealed)
        };
        let good = vec![
            (Some(3), link("/dev/net/tun")),
            (Some(4), Err(Error::from(ErrorKind::NotFound))),
            (Some(5), link("/dev/vhost-net")),
            (Some(6), link("anon_inode:[eventfd]")),
            (Some(7), link("/dev/vhost-net")),
        ];
        assert_eq!(sealing(good), (Ok(()), vec![5, 7]));
        for refused in [
            Error::from(ErrorKind::PermissionDenied),
            Error::from_raw_os_error(13),
            Error::other("unknown"),
        ] {
            let listed = vec![(Some(3), Err(refused)), (Some(5), link("/dev/vhost-net"))];
            assert_eq!(sealing(listed).0, Err(TunnelError::Failed));
        }
        let unnumbered = vec![(None, link("/dev/vhost-net"))];
        assert_eq!(sealing(unnumbered).0, Err(TunnelError::Failed));
        let failing = seal_listed(vec![(Some(5), link("/dev/vhost-net"))], |_| {
            Err(TunnelError::Failed)
        });
        assert_eq!(failing, Err(TunnelError::Failed));
    }

    // The real listing of this process passes: nothing in it is refused.
    #[test]
    fn this_process_can_be_sealed() {
        assert_eq!(seal_vhost(), Ok(()));
    }

    // A made-up link is gone at once; waiting for it returns without
    // using up the limit.
    #[test]
    fn waiting_for_a_link_that_is_not_there_returns_at_once() {
        let start = Instant::now();
        wait_until_gone("ubcvpn-made-up");
        wait_until_gone("nul\0inside");
        assert!(start.elapsed() < Duration::from_secs(1));
    }
}
