//! The Linux routes against the real kernel, with a tun device made the way
//! the VPN engine makes one. They need root; CI runs them under `sudo`.

use std::fs::{File, OpenOptions};
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::process::Command;

use ubc_vpn_core::routes::Ipv4Net;

use super::Sandbox;
use crate::os::routes::LinuxRoutes;
use crate::suite::{self, Foreign};
use crate::{Error, LINUX_ROUTE_PROTOCOL, Mode, Routes, Verified};

/// A tun device, gone when this is dropped.
struct Tun {
    _file: File,
    name: String,
}

fn tun() -> Tun {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC)
        .open("/dev/net/tun")
        .expect("open the tun driver");
    // The request: a name for the kernel to fill in, then the flags.
    let mut request = [0u8; 40];
    request[..6].copy_from_slice(b"uvt%d\0");
    let flags = (libc::IFF_TUN | libc::IFF_NO_PI) as i16;
    request[16..18].copy_from_slice(&flags.to_ne_bytes());
    // SAFETY: the descriptor is open, and `request` is a live buffer as large
    // as the `struct ifreq` this call reads and writes.
    let status = unsafe { libc::ioctl(file.as_raw_fd(), libc::TUNSETIFF, request.as_mut_ptr()) };
    assert_eq!(status, 0, "make a tun device");
    let end = request[..16]
        .iter()
        .position(|byte| *byte == 0)
        .expect("a name");
    let name = String::from_utf8(request[..end].to_vec()).expect("UTF-8");
    Tun { _file: file, name }
}

/// Runs the system's `ip` tool, as somebody other than the product.
fn ip(args: &[&str]) -> String {
    let output = Command::new("ip").args(args).output().expect("run ip");
    let said = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "ip {}: {said}", args.join(" "));
    String::from_utf8_lossy(&output.stdout).into_owned()
}

struct IpTool;

impl IpTool {
    /// The interface's usual router: the one its default route goes by.
    fn router(interface: &str) -> Option<String> {
        let shown = ip(&["-4", "route", "show", "default", "dev", interface]);
        let words: Vec<&str> = shown.split_whitespace().collect();
        let at = words.iter().position(|word| *word == "via")?;
        words.get(at + 1).map(|router| router.to_string())
    }
}

impl Foreign for IpTool {
    fn add_route(&self, interface: &str, net: Ipv4Net) {
        let net = net.to_string();
        let mut args = vec!["route", "add", net.as_str(), "dev", interface];
        let router = Self::router(interface);
        if let Some(router) = &router {
            args.extend(["via", router.as_str()]);
        }
        ip(&args);
    }

    fn remove_route(&self, interface: &str, net: Ipv4Net) {
        ip(&["route", "del", &net.to_string(), "dev", interface]);
    }

    fn add_address(&self, interface: &str, address: Ipv4Addr) {
        ip(&["addr", "add", &format!("{address}/24"), "dev", interface]);
    }

    fn addresses(&self, interface: &str) -> Vec<Ipv4Addr> {
        let shown = ip(&["-4", "-o", "addr", "show", "dev", interface]);
        let words = shown.split_whitespace().collect::<Vec<_>>();
        let found = words.windows(2).filter(|pair| pair[0] == "inet");
        found
            .filter_map(|pair| pair[1].split('/').next()?.parse().ok())
            .collect()
    }
}

// Security rule: the real routes pass the suite every implementation must
// pass: the address as a single host, only the chosen subnets in the tunnel,
// the gateway outside it, and nobody else's route ever removed or replaced.
#[test]
fn the_linux_routes_pass_the_suite() {
    let Some(_sandbox) = Sandbox::root("routes", Mode::Installed) else {
        return;
    };
    let device = tun();
    let routes = LinuxRoutes;
    routes.remove_all().expect("start clean");
    suite::check_configure_tunnel(&routes, &IpTool, &device.name);
    suite::check_routes(&routes, &device.name);
    let restarted = || Box::new(LinuxRoutes) as Box<dyn Routes>;
    suite::check_route_ownership(&routes, &restarted, &IpTool, &device.name);
}

// What a crashed run left is found by its protocol number alone, and the
// device's routes go with the device.
#[test]
fn a_crashed_runs_routes_are_found_by_their_mark() {
    let Some(_sandbox) = Sandbox::root("routes", Mode::Installed) else {
        return;
    };
    let device = tun();
    let routes = LinuxRoutes;
    routes
        .configure_tunnel(&device.name, Ipv4Addr::new(198, 51, 100, 7), 1300)
        .expect("configure");
    let proto = LINUX_ROUTE_PROTOCOL.to_string();
    let theirs = "198.18.7.0/24";
    ip(&[
        "route",
        "add",
        "192.0.2.0/24",
        "dev",
        &device.name,
        "proto",
        &proto,
    ]);
    ip(&["route", "add", theirs, "dev", &device.name]);
    let inside = Ipv4Addr::new(192, 0, 2, 9);
    assert_eq!(routes.uses_interface(inside, &device.name), Verified::Yes);
    routes.remove_all().expect("remove all");
    assert_eq!(routes.uses_interface(inside, &device.name), Verified::No);
    let kept = routes.uses_interface(Ipv4Addr::new(198, 18, 7, 9), &device.name);
    assert_eq!(kept, Verified::Yes, "took a route without the mark");

    // With the device gone, removing its routes is not an error.
    let name = device.name.clone();
    drop(device);
    let subnet = "192.0.2.0/24".parse().expect("a network");
    routes
        .remove_tunnel_routes(&name, &[subnet])
        .expect("remove after the device went");
    assert_eq!(routes.uses_interface(inside, &name), Verified::No);
}

// Security rule: what is not a tun device is never configured or given the
// tunnel's routes, and a missing one is reported as missing.
#[test]
fn only_a_tun_device_is_treated_as_the_tunnel() {
    let Some(_sandbox) = Sandbox::root("routes", Mode::Installed) else {
        return;
    };
    let routes = LinuxRoutes;
    let address = Ipv4Addr::new(198, 51, 100, 7);
    let subnet: Ipv4Net = "192.0.2.0/24".parse().expect("a network");
    let not_tun = Some(Error::Failed("lo is not a tunnel device".to_string()));
    assert_eq!(routes.configure_tunnel("lo", address, 1300).err(), not_tun);
    assert_eq!(routes.add_tunnel_routes("lo", &[subnet]).err(), not_tun);
    let missing = routes.configure_tunnel("uvt-none", address, 1300);
    assert_eq!(missing.err(), Some(Error::NotFound));
    let missing = routes.add_tunnel_routes("uvt-none", &[subnet]);
    assert_eq!(missing.err(), Some(Error::NotFound));
    assert_eq!(routes.uses_interface(address, "uvt-none"), Verified::No);
}

// The physical network is described with the machine's own addresses and
// the networks it is on, and the way to the gateway is the kernel's.
#[test]
fn the_physical_network_is_the_kernels_view() {
    let Some(_sandbox) = Sandbox::root("routes", Mode::Installed) else {
        return;
    };
    let gateway = Ipv4Addr::new(203, 0, 113, 1);
    let physical = LinuxRoutes.capture_physical(gateway).expect("capture");
    let shown = ip(&["-4", "route", "get", &gateway.to_string()]);
    assert!(
        shown.contains(&format!("dev {} ", physical.interface())),
        "{shown}"
    );
    match physical.next_hop() {
        Some(router) => assert!(shown.contains(&format!("via {router} ")), "{shown}"),
        None => assert!(!shown.contains(" via "), "{shown}"),
    }
    assert!(physical.own_addresses().contains(&Ipv4Addr::LOCALHOST));
    let loopback: Ipv4Net = "127.0.0.0/8".parse().expect("a network");
    assert!(physical.on_link().contains(&loopback));
    for address in IpTool.addresses(physical.interface()) {
        assert!(physical.own_addresses().contains(&address), "{address}");
        let on_it = physical
            .on_link()
            .iter()
            .any(|net| net.contains_addr(address));
        assert!(on_it, "the network of {address}");
    }
}
