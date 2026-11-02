//! Tests of split DNS on Linux, in systemd-resolved.
//!
//! Most need root, a tunnel device and resolved, so they run on GitHub's
//! runners in CI and never on a developer's machine by accident, as the
//! routes tests do (see `routes_tests.rs`): each in a process of its own,
//! one at a time with those, saying `RAN AS ROOT: <name>` when it passed.
//!
//! They change only their own devices, whose names start with [`PREFIX`],
//! and one outsider's device, never the product's (`ubcvpn...`). Where one
//! stops resolved or changes `/etc/resolv.conf`, it puts them back however it
//! ends, also from the parent process should the test's own be stopped.
//!
//! A lookup is seen where it arrives: on the tunnel device the test holds,
//! with the documentation network routed into it. The test reads the query
//! from the device and answers it, so resolved is never left waiting.

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, Timespec, poll};

use super::dns::{Resolved, TUN_PREFIX};
use super::routes::LinuxRoutes;
use super::routes_tests::{Tun, as_root_in, ip_ok, say};
use crate::{Dns, Error, Mode, Platform, Routes, SplitDns, Verified, suite};

/// How the names of the tests' own tunnel devices start: never the
/// product's.
pub(super) const PREFIX: &str = "uvt-";
/// The outsider's device: a name that is not the tests' either.
const FOREIGN: &str = "uvf-other0";
const RESOLVED: &str = "systemd-resolved.service";
const RESOLV_CONF: &str = "/etc/resolv.conf";
/// resolved's own `resolv.conf` for its stub, as `/etc/resolv.conf` links
/// to it in stub mode.
const STUB: &str = "../run/systemd/resolve/stub-resolv.conf";
/// How long one lookup may take, at most.
const LOOKUP: Duration = Duration::from_secs(10);
/// How long to go on listening once the lookup has ended.
const GRACE: Duration = Duration::from_millis(300);

fn as_root(name: &str, test: &str, body: impl FnOnce()) {
    as_root_in(module_path!(), name, test, body);
}

fn split(resolver: [u8; 4], domains: &[&str]) -> SplitDns {
    SplitDns {
        resolvers: vec![Ipv4Addr::from(resolver)],
        domains: domains.iter().map(ToString::to_string).collect(),
    }
}

/// A tunnel device of the tests' own, configured and up, as the service
/// would have it before setting DNS.
fn tunnel(name: &str, last: u8) -> Tun {
    let tun = Tun::open(name);
    LinuxRoutes
        .configure_tunnel(&tun.name, Ipv4Addr::new(198, 18, 0, last), 1300)
        .expect("configure");
    tun
}

/// The first line of what `program` writes, to log.
fn first_line(program: &str, args: &[&str]) -> String {
    let done = Command::new(program).args(args).output();
    let text = done.map(|done| String::from_utf8_lossy(&done.stdout).into_owned());
    let text = text.unwrap_or_else(|error| format!("could not run {program}: {error}"));
    text.lines().next().unwrap_or_default().to_string()
}

/// What `resolvectl <what> <link>` shows after the link's name: its DNS
/// servers or its domains, as somebody else would see them.
fn shown(what: &str, link: &str) -> String {
    let done = Command::new("resolvectl")
        .args([what, link])
        .output()
        .expect("run resolvectl");
    let text = String::from_utf8_lossy(&done.stdout).into_owned();
    assert!(done.status.success(), "resolvectl {what} {link}: {text}");
    let (_, after) = text.split_once("):").expect("resolvectl's usual form");
    after.trim().to_string()
}

/// Runs `systemctl` with `args`, and says whether it succeeded.
fn systemctl(args: &[&str]) -> (bool, String) {
    let done = Command::new("systemctl")
        .args(args)
        .output()
        .expect("run systemctl");
    let text = String::from_utf8_lossy(&done.stdout).trim().to_string();
    (done.status.success(), text)
}

/// One DNS query read from the tunnel.
struct Query {
    source: Ipv4Addr,
    dest: Ipv4Addr,
    port: u16,
    /// The DNS message.
    message: Vec<u8>,
    /// Where its question ends in `message`.
    question_end: usize,
    name: String,
}

impl Query {
    /// The query in an IPv4 packet to UDP port 53, if it is one.
    fn parse(packet: &[u8]) -> Option<Self> {
        let header = usize::from(*packet.first()? & 0x0f) * 4;
        if *packet.first()? >> 4 != 4 || header < 20 || *packet.get(9)? != 17 {
            return None;
        }
        let total = usize::from(u16::from_be_bytes([*packet.get(2)?, *packet.get(3)?]));
        let packet = packet.get(..total)?;
        if total < header + 8 {
            return None;
        }
        let addr =
            |at: usize| Ipv4Addr::new(packet[at], packet[at + 1], packet[at + 2], packet[at + 3]);
        let (source, dest) = (addr(12), addr(16));
        let udp = packet.get(header..)?;
        let port = u16::from_be_bytes([*udp.first()?, *udp.get(1)?]);
        if u16::from_be_bytes([*udp.get(2)?, *udp.get(3)?]) != 53 {
            return None;
        }
        let message = udp.get(8..)?.to_vec();
        if message.len() < 12 || u16::from_be_bytes([message[4], message[5]]) == 0 {
            return None;
        }
        let mut labels = Vec::new();
        let mut at = 12;
        loop {
            let length = usize::from(*message.get(at)?);
            at += 1;
            if length == 0 {
                break;
            }
            if length > 63 {
                return None;
            }
            let label = message.get(at..at + length)?;
            labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
            at += length;
        }
        let question_end = at + 4;
        message.get(..question_end)?;
        Some(Self {
            source,
            dest,
            port,
            message,
            question_end,
            name: labels.join("."),
        })
    }

    /// Whether it asks about `name`, or `name` with a search domain added.
    fn is_for(&self, name: &str) -> bool {
        self.name == name || self.name.starts_with(&format!("{name}."))
    }

    /// An answer that the name does not exist, from the resolver it went to.
    fn answer(&self) -> Vec<u8> {
        let asked = &self.message;
        let flags = u16::from_be_bytes([asked[2], asked[3]]);
        // A response, with the question's opcode and recursion wish,
        // recursion available, and "no such name".
        let flags = 0x8000 | (flags & 0x7900) | 0x0080 | 3;
        let extended = u16::from_be_bytes([asked[10], asked[11]]) > 0;
        let mut message = asked[..2].to_vec();
        message.extend(flags.to_be_bytes());
        message.extend([0, 1, 0, 0, 0, 0, 0, u8::from(extended)]);
        message.extend(&asked[12..self.question_end]);
        if extended {
            // An OPT record: 1232 bytes, nothing else.
            message.extend([0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0]);
        }
        let udp_length = u16::try_from(8 + message.len()).expect("small");
        let total = 20 + udp_length;
        let mut packet = vec![0x45, 0];
        packet.extend(total.to_be_bytes());
        packet.extend([0, 0, 0x40, 0, 64, 17, 0, 0]);
        packet.extend(self.dest.octets());
        packet.extend(self.source.octets());
        let sum = packet
            .chunks(2)
            .map(|pair| u32::from(u16::from_be_bytes([pair[0], pair[1]])))
            .sum::<u32>();
        let sum = (sum & 0xffff) + (sum >> 16);
        let sum = !u16::try_from((sum & 0xffff) + (sum >> 16)).expect("folded");
        packet[10..12].copy_from_slice(&sum.to_be_bytes());
        packet.extend(53u16.to_be_bytes());
        packet.extend(self.port.to_be_bytes());
        packet.extend(udp_length.to_be_bytes());
        packet.extend([0, 0]);
        packet.extend(message);
        packet
    }
}

/// Lookups, as the suite's `resolvers_for` asks for them: which resolvers a
/// lookup of a name goes to, as far as the tunnel shows. A name that goes
/// elsewhere gives none.
pub(super) struct Lookups<'a> {
    tun: &'a Tun,
}

impl<'a> Lookups<'a> {
    /// Routes the documentation network, where the suite's resolvers are,
    /// into `tun`.
    pub(super) fn new(tun: &'a Tun) -> Self {
        ip_ok(&["-4", "route", "replace", "192.0.2.0/24", "dev", &tun.name]);
        Self { tun }
    }

    /// The next packet from the tunnel within `wait`. Each DNS query is
    /// answered, and given.
    fn next(&self, wait: Duration) -> Option<Query> {
        let wait = Timespec::try_from(wait).expect("fits");
        let mut ready = [PollFd::new(&self.tun.fd, PollFlags::IN)];
        if poll(&mut ready, Some(&wait)).expect("poll") == 0 {
            return None;
        }
        let mut packet = [0u8; 2048];
        let read = rustix::io::read(&self.tun.fd, &mut packet[..]).expect("read the tunnel");
        let query = Query::parse(&packet[..read])?;
        rustix::io::write(&self.tun.fd, &query.answer()).expect("answer");
        Some(query)
    }

    pub(super) fn resolvers_for(&self, name: &str) -> Vec<Ipv4Addr> {
        // Whatever came before, answered and forgotten.
        while self.next(Duration::ZERO).is_some() {}
        let mut lookup = Command::new("resolvectl")
            .args(["query", "-4", "--cache=no", "--legend=no", name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start resolvectl");
        let started = Instant::now();
        let mut ended: Option<Instant> = None;
        let mut seen = Vec::new();
        while started.elapsed() < LOOKUP && ended.is_none_or(|at| at.elapsed() < GRACE) {
            if ended.is_none() && lookup.try_wait().expect("wait for resolvectl").is_some() {
                ended = Some(Instant::now());
            }
            if let Some(query) = self.next(Duration::from_millis(50))
                && query.is_for(name)
            {
                seen.push(query.dest);
            }
        }
        let _ = lookup.kill();
        let _ = lookup.wait();
        seen.sort_unstable();
        seen.dedup();
        seen
    }
}

/// Runs a function when dropped, however the test ends.
struct Finally<F: FnMut()>(F);

impl<F: FnMut()> Drop for Finally<F> {
    fn drop(&mut self) {
        (self.0)();
    }
}

/// resolved's `resolv.conf` mode, as busctl shows it, such as `s "stub"`.
fn resolv_conf_mode() -> String {
    first_line(
        "busctl",
        &[
            "get-property",
            "org.freedesktop.resolve1",
            "/org/freedesktop/resolve1",
            "org.freedesktop.resolve1.Manager",
            "ResolvConfMode",
        ],
    )
}

/// What `/etc/resolv.conf` is: a link, a file, or nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ResolvConf {
    Link(PathBuf),
    File(Vec<u8>),
    Missing,
}

impl ResolvConf {
    fn now() -> Self {
        if let Ok(target) = std::fs::read_link(RESOLV_CONF) {
            return Self::Link(target);
        }
        std::fs::read(RESOLV_CONF).map_or(Self::Missing, Self::File)
    }

    /// Makes `/etc/resolv.conf` this again, if it is not.
    fn put_back(&self) {
        if !rustix::process::getuid().is_root() || Self::now() == *self {
            return;
        }
        let _ = std::fs::remove_file(RESOLV_CONF);
        match self {
            Self::Link(target) => {
                std::os::unix::fs::symlink(target, RESOLV_CONF).expect("put the link back");
            }
            Self::File(bytes) => std::fs::write(RESOLV_CONF, bytes).expect("put the file back"),
            Self::Missing => {}
        }
    }
}

/// Puts `/etc/resolv.conf` back as it is now when dropped. Each root test
/// that might change it holds one in the process that starts it, too, so it
/// is put back should the test's own process be stopped.
pub(super) struct AsItWas(ResolvConf);

impl AsItWas {
    pub(super) fn now() -> Self {
        Self(ResolvConf::now())
    }
}

impl Drop for AsItWas {
    fn drop(&mut self) {
        self.0.put_back();
    }
}

/// Makes programs ask resolved through its stub, as they do on GitHub's
/// runners most of the time, until what this gives is dropped. Some runners
/// have a plain `resolv.conf` instead, which resolved counts as `foreign`.
/// The stub answers the runner's lookups as before.
pub(super) fn stub_mode() -> AsItWas {
    let was = AsItWas::now();
    let mode = resolv_conf_mode();
    let what = match &was.0 {
        ResolvConf::Link(target) => format!("a link to {}", target.display()),
        ResolvConf::File(_) => "a file".to_string(),
        ResolvConf::Missing => "missing".to_string(),
    };
    say(&format!(
        "RESOLVED {} / {} / resolv.conf {what}, mode {mode}",
        first_line("resolvectl", &["--version"]),
        first_line("systemctl", &["is-active", RESOLVED]),
    ));
    if !matches!(mode.as_str(), "s \"stub\"" | "s \"static\"") {
        link_stub();
        say(&format!(
            "RESOLV.CONF now the stub's, mode {}",
            resolv_conf_mode()
        ));
    }
    was
}

/// Makes `/etc/resolv.conf` the link to resolved's stub file.
fn link_stub() {
    let _ = std::fs::remove_file(RESOLV_CONF);
    std::os::unix::fs::symlink(STUB, RESOLV_CONF).expect("link resolv.conf to the stub's");
}

// The shared rules, in the real resolved, on a tunnel device like the one
// the engine opens: only the chosen domains go to the VPN's resolvers, the
// search list and every other name stay as they were, and the setting reads
// back exactly.
#[test]
fn passes_the_shared_dns_suite_in_resolved() {
    let _back = AsItWas::now();
    as_root("dns", "passes_the_shared_dns_suite_in_resolved", || {
        let _stub = stub_mode();
        let tun = tunnel("uvt-dns0", 10);
        let lookups = Lookups::new(&tun);
        let dns = Resolved::new(PREFIX);
        suite::check_dns(&dns, &tun.name, &|name| lookups.resolvers_for(name));
    });
}

/// Puts resolved back as it was, running and not masked, if it is not.
fn restore_resolved() {
    if !rustix::process::getuid().is_root() {
        return;
    }
    let (_, enabled) = systemctl(&["is-enabled", RESOLVED]);
    if enabled.starts_with("masked") {
        systemctl(&["unmask", RESOLVED]);
    }
    if systemctl(&["is-active", RESOLVED]).1 != "active" {
        systemctl(&["start", RESOLVED]);
    }
    let started = Instant::now();
    while systemctl(&["is-active", RESOLVED]).1 != "active"
        && started.elapsed() < Duration::from_secs(10)
    {
        std::thread::sleep(Duration::from_millis(100));
    }
}

// Where resolved is masked, split DNS cannot be honoured: it is refused as
// unsupported, having changed nothing. Masked while it still runs, then
// stopped too.
#[test]
fn split_dns_is_unsupported_where_resolved_is_masked() {
    let _back = AsItWas::now();
    let _restore = Finally(restore_resolved);
    let test = "split_dns_is_unsupported_where_resolved_is_masked";
    as_root("dns unsupported", test, || {
        let _stub = stub_mode();
        let _restore = Finally(restore_resolved);
        let tun = tunnel("uvt-dns1", 11);
        let dns = Resolved::new(PREFIX);
        let setting = split([192, 0, 2, 53], &["suite.example"]);

        assert!(systemctl(&["mask", RESOLVED]).0, "mask resolved");
        let (_, enabled) = systemctl(&["is-enabled", RESOLVED]);
        say(&format!("MASKED while running: {enabled}"));
        let refused = dns.set_split_dns(&tun.name, &setting);
        assert_eq!(refused, Err(Error::Unsupported), "masked and running");
        assert_eq!(shown("domain", &tun.name), "", "a refusal set domains");
        assert_eq!(shown("dns", &tun.name), "", "a refusal set servers");
        assert_eq!(dns.split_dns_matches(&setting), Verified::No);

        assert!(systemctl(&["stop", RESOLVED]).0, "stop resolved");
        let refused = dns.set_split_dns(&tun.name, &setting);
        assert_eq!(refused, Err(Error::Unsupported), "masked and stopped");
        assert_eq!(dns.split_dns_matches(&setting), Verified::No);
        dns.clear_split_dns()
            .expect("clear while resolved is stopped");

        restore_resolved();
        assert_eq!(systemctl(&["is-active", RESOLVED]).1, "active");
        assert_eq!(shown("domain", &tun.name), "", "something was set");
        assert_eq!(shown("dns", &tun.name), "", "something was set");
        // Unmasked and running again, it is honoured.
        dns.set_split_dns(&tun.name, &setting).expect("set");
        assert_eq!(dns.split_dns_matches(&setting), Verified::Yes);
        dns.clear_split_dns().expect("clear");
    });
}

// Where programs do not ask resolved, split DNS there would do nothing: a
// `resolv.conf` that resolved does not manage (mode `foreign`) is refused
// as unsupported, having changed nothing. The file is replaced by a copy of
// itself, so the runner's own lookups keep working meanwhile.
#[test]
fn split_dns_is_unsupported_where_programs_do_not_ask_resolved() {
    let _back = AsItWas::now();
    let test = "split_dns_is_unsupported_where_programs_do_not_ask_resolved";
    as_root("dns resolv.conf mode", test, || {
        let _stub = stub_mode();
        let tun = tunnel("uvt-dns2", 12);
        let dns = Resolved::new(PREFIX);
        let setting = split([192, 0, 2, 53], &["suite.example"]);

        let copy = std::fs::read(RESOLV_CONF).expect("read resolv.conf");
        std::fs::remove_file(RESOLV_CONF).expect("remove the link");
        std::fs::write(RESOLV_CONF, copy).expect("write a copy");
        let mode = resolv_conf_mode();
        say(&format!("RESOLV.CONF mode with a copy: {mode}"));
        let refused = dns.set_split_dns(&tun.name, &setting);
        link_stub();
        assert_eq!(refused, Err(Error::Unsupported), "mode {mode}");
        assert_eq!(shown("domain", &tun.name), "", "a refusal set domains");
        assert_eq!(shown("dns", &tun.name), "", "a refusal set servers");

        // Linked to the stub again, it is honoured.
        dns.set_split_dns(&tun.name, &setting).expect("set");
        assert_eq!(dns.split_dns_matches(&setting), Verified::Yes);
        dns.clear_split_dns().expect("clear");
    });
}

// Only the product's own links are changed: somebody else's link keeps its
// servers and domains through a set and a clear of ours, and setting split
// DNS on it is refused.
#[test]
fn another_links_dns_is_untouched() {
    let _back = AsItWas::now();
    as_root("dns foreign", "another_links_dns_is_untouched", || {
        let _stub = stub_mode();
        let tun = tunnel("uvt-dns3", 13);
        let theirs = Tun::open(FOREIGN);
        let dns = Resolved::new(PREFIX);
        let setting = split([192, 0, 2, 53], &["suite.example"]);
        let run = |args: &[&str]| {
            let done = Command::new("resolvectl")
                .args(args)
                .output()
                .expect("resolvectl");
            let stderr = String::from_utf8_lossy(&done.stderr);
            assert!(done.status.success(), "resolvectl {args:?}: {stderr}");
        };
        run(&["dns", &theirs.name, "192.0.2.99"]);
        run(&["domain", &theirs.name, "~foreign.example", "search.example"]);
        let before = (shown("dns", &theirs.name), shown("domain", &theirs.name));
        say(&format!("FOREIGN before: {before:?}"));
        assert!(before.0.contains("192.0.2.99"), "{before:?}");

        let refused = dns.set_split_dns(&theirs.name, &setting);
        assert_eq!(refused, Err(Error::InvalidInput), "set on their link");
        dns.set_split_dns(&tun.name, &setting).expect("set");
        assert_eq!(dns.split_dns_matches(&setting), Verified::Yes);
        let during = (shown("dns", &theirs.name), shown("domain", &theirs.name));
        assert_eq!(during, before, "a set changed their link");
        dns.clear_split_dns().expect("clear");
        let after = (shown("dns", &theirs.name), shown("domain", &theirs.name));
        assert_eq!(after, before, "a clear changed their link");
        assert_eq!(shown("domain", &tun.name), "", "ours stayed");
        run(&["revert", &theirs.name]);
    });
}

// Security rule: a domain that is not a plain name never reaches resolved,
// here on a real link: it is refused before anything changes, and what was
// set stays as it was.
#[test]
fn a_domain_that_is_not_a_plain_name_never_reaches_resolved() {
    let _back = AsItWas::now();
    let test = "a_domain_that_is_not_a_plain_name_never_reaches_resolved";
    as_root("dns refused domain", test, || {
        let _stub = stub_mode();
        let tun = tunnel("uvt-dns4", 14);
        let dns = Resolved::new(PREFIX);
        let good = split([192, 0, 2, 53], &["suite.example"]);
        dns.set_split_dns(&tun.name, &good).expect("set");
        for bad in [
            "--address=unix:path=/nonexistent",
            "~.",
            "evil.example\" false \"x.example",
            "evil.example search.example",
        ] {
            let setting = split([192, 0, 2, 54], &["other.example", bad]);
            let refused = dns.set_split_dns(&tun.name, &setting);
            assert_eq!(refused, Err(Error::InvalidInput), "{bad:?}");
            assert_eq!(shown("domain", &tun.name), "~suite.example", "{bad:?}");
            assert_eq!(shown("dns", &tun.name), "192.0.2.53", "{bad:?}");
            assert_eq!(dns.split_dns_matches(&good), Verified::Yes, "{bad:?}");
        }
        dns.clear_split_dns().expect("clear");
        assert_eq!(shown("domain", &tun.name), "");
    });
}

// Refused before anything is asked, so these need no root and change
// nothing: a setting that is not valid, and a link not named as ours.
#[test]
fn a_setting_or_a_link_that_is_not_ours_is_refused_first() {
    let dns = Resolved::new(PREFIX);
    let good = split([192, 0, 2, 53], &["suite.example"]);
    let mut too_many = good.clone();
    too_many.domains = (0..301).map(|n| format!("d{n}.example")).collect();
    let refused = [
        split([192, 0, 2, 53], &[]),
        SplitDns {
            resolvers: Vec::new(),
            ..good.clone()
        },
        split([0, 0, 0, 0], &["suite.example"]),
        split([255, 255, 255, 255], &["suite.example"]),
        split([224, 0, 0, 251], &["suite.example"]),
        split(
            [192, 0, 2, 53],
            &["suite.example", "--address=unix:path=/x"],
        ),
        split([192, 0, 2, 53], &["~."]),
        split([192, 0, 2, 53], &["Suite.example"]),
        too_many,
    ];
    for setting in &refused {
        let result = dns.set_split_dns("uvt-none0", setting);
        assert_eq!(result, Err(Error::InvalidInput), "{setting:?}");
    }
    for tunnel in ["tun0", "eth0", "ubcvpn0", "uvf-other0"] {
        let result = dns.set_split_dns(tunnel, &good);
        assert_eq!(result, Err(Error::InvalidInput), "{tunnel}");
    }
    assert_eq!(dns.set_split_dns("uvt-none0", &good), Err(Error::NotFound));
}

// The product's DNS goes by the product's own prefix, and refuses the same
// way. Nothing here changes anything, and nothing touches a live VPN's
// settings.
#[test]
fn the_product_changes_only_its_own_links() {
    assert_eq!(TUN_PREFIX, "ubcvpn");
    let good = split([192, 0, 2, 53], &["suite.example"]);
    let bad = split([192, 0, 2, 53], &["--address=unix:path=/x"]);
    let modes = [
        Mode::Installed,
        #[cfg(feature = "dev-mode")]
        Mode::Dev,
    ];
    for mode in modes {
        let dns = Platform::native(mode).expect("a platform").dns;
        assert_eq!(dns.set_split_dns("tun0", &good), Err(Error::InvalidInput));
        assert_eq!(dns.set_split_dns(PREFIX, &good), Err(Error::InvalidInput));
        assert_eq!(
            dns.set_split_dns("ubcvpn-none0", &bad),
            Err(Error::InvalidInput)
        );
        assert_eq!(
            dns.set_split_dns("ubcvpn-none0", &good),
            Err(Error::NotFound)
        );
    }
}

// The test's own reading of a query and its answer, without a device.
#[test]
fn a_query_is_read_and_answered() {
    let mut message = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1];
    message.extend(b"\x04host\x05suite\x07example\x00\x00\x01\x00\x01");
    message.extend([0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0]);
    let udp_length = u16::try_from(8 + message.len()).unwrap();
    let mut packet = vec![0x45, 0];
    packet.extend((20 + udp_length).to_be_bytes());
    packet.extend([0, 0, 0, 0, 64, 17, 0, 0, 198, 18, 0, 10, 192, 0, 2, 53]);
    packet.extend([0xc3, 0x50, 0, 53]);
    packet.extend(udp_length.to_be_bytes());
    packet.extend([0, 0]);
    packet.extend(&message);

    let query = Query::parse(&packet).expect("a query");
    assert_eq!(query.name, "host.suite.example");
    assert_eq!(query.dest, Ipv4Addr::new(192, 0, 2, 53));
    assert!(query.is_for("host.suite.example"));
    assert!(query.is_for("host"), "with a search domain added");
    assert!(!query.is_for("suite.example"));
    assert!(!query.is_for("hos"));

    let answer = query.answer();
    assert_eq!(&answer[12..16], &[192, 0, 2, 53], "from the resolver");
    assert_eq!(&answer[16..20], &[198, 18, 0, 10], "to the asker");
    assert_eq!(&answer[20..24], &[0, 53, 0xc3, 0x50], "the ports swapped");
    let dns = &answer[28..];
    assert_eq!(&dns[..2], &[0x12, 0x34], "the same identifier");
    assert_eq!(dns[3] & 0x0f, 3, "no such name");
    assert_eq!(dns[2] & 0x80, 0x80, "a response");
    let sum = answer[..20]
        .chunks(2)
        .map(|pair| u32::from(u16::from_be_bytes([pair[0], pair[1]])))
        .sum::<u32>();
    let folded = (sum & 0xffff) + (sum >> 16);
    assert_eq!((folded & 0xffff) + (folded >> 16), 0xffff, "the checksum");

    let mut other = packet.clone();
    other[22..24].copy_from_slice(&5353u16.to_be_bytes());
    assert!(Query::parse(&other).is_none(), "not unicast DNS");
}
