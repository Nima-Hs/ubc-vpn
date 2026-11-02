//! Tests of split DNS on macOS, in the dynamic store.
//!
//! The first ones read made-up text and values and need nothing. The rest
//! change the machine's resolver configuration and need root and a `utun`
//! device, so they run as the routes tests do (see `routes_tests.rs`): each
//! in a process of its own, taking turns with those, saying `RAN AS ROOT:
//! <name>` when it passed. CI requires the names in
//! `.github/ran/platform-unix/macos/dns.txt`.
//!
//! They use service ids of their own, never the product's, and session keys
//! that go with the test's process; each also removes its keys however it
//! ends. They use only `.example` names and addresses reserved for
//! documentation.
//!
//! A lookup is seen where it arrives: on the `utun` device the test holds,
//! with the documentation network routed into it. The test reads the query
//! from the device and answers it, so the system's resolver is never left
//! waiting.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, Timespec, poll};

use super::dns::{
    Effective, Entry, MOST_DOMAINS, PRODUCT_SERVICE, Resolver, SCUTIL, SessionDns, TEST_SERVICE,
    check, key_of, platform_service, quiet,
};
use super::dynamic_store::{Store, Value};
use super::routes::MacRoutes;
use super::routes_tests::{
    Cleanup, DEADLINE, Outsider, Utun, alone_as_root_in, ip, net, regain_root, say, state_dir,
    utun, watchdog,
};
use crate::suite::{self, Foreign};
use crate::{Dns, Error, Mode, Platform, Routes, SplitDns, Verified};

/// The service ids of the tests' own entries.
const SUITE_SERVICE: &str = "io.github.nima-hs.ubc-vpn.test.suite";
pub(super) const LIVE_SERVICE: &str = "io.github.nima-hs.ubc-vpn.test.live";
const CRASH_SERVICE: &str = "io.github.nima-hs.ubc-vpn.test.crash";
const SEARCH_SERVICE: &str = "io.github.nima-hs.ubc-vpn.test.search";
const OURS_SERVICE: &str = "io.github.nima-hs.ubc-vpn.test.ours";
/// Somebody else's entry, as another VPN's would be.
const THEIR_SERVICE: &str = "io.github.nima-hs.ubc-vpn.test.theirs";
/// Tells `crash_child` where to say it is ready, and that it is wanted.
const CRASH: &str = "UBC_VPN_DNS_CRASH_CHILD";
/// How long one lookup may take, at most.
const LOOKUP: Duration = Duration::from_secs(10);
/// How long to go on listening once the lookup has ended.
const GRACE: Duration = Duration::from_millis(300);
/// How long the resolver configuration may take to show a change.
const SETTLE: Duration = Duration::from_secs(10);
/// The address family a `utun` device puts before each packet.
const AF_INET: [u8; 4] = [0, 0, 0, 2];

fn as_root(test: &str, ran: &str, body: impl FnOnce()) {
    alone_as_root_in(module_path!(), test, ran, body);
}

fn split(resolver: [u8; 4], domains: &[&str]) -> SplitDns {
    SplitDns {
        resolvers: vec![Ipv4Addr::from(resolver)],
        domains: domains.iter().map(ToString::to_string).collect(),
    }
}

/// Removes the key when dropped, however the test ends, whatever set it.
pub(super) struct Removed(pub(super) String);

impl Drop for Removed {
    fn drop(&mut self) {
        if let Ok(store) = Store::session("ubc-vpn tests cleanup") {
            let _ = store.remove(&self.0);
        }
    }
}

/// The answer of `ask` once it is `wanted`, or after [`SETTLE`].
fn settled<T: PartialEq>(wanted: &T, ask: impl Fn() -> T) -> T {
    let started = Instant::now();
    loop {
        let answer = ask();
        if answer == *wanted || started.elapsed() > SETTLE {
            return answer;
        }
        thread::sleep(Duration::from_millis(100));
    }
}

/// The resolver configuration in effect, which must be readable.
fn effective() -> Effective {
    Effective::now().expect("read the resolver configuration")
}

/// What `scutil --dns` shows, to log.
fn log_scutil(when: &str) {
    let shown = Command::new("/usr/sbin/scutil").arg("--dns").output();
    let text = shown.map(|done| String::from_utf8_lossy(&done.stdout).into_owned());
    say(&format!(
        "SCUTIL --dns {when}:\n{}",
        text.unwrap_or_default()
    ));
}

/// A `utun` device, configured and up, as the service would have it before
/// setting DNS.
fn tunnel(dir: &Path, last: u8) -> Utun {
    let device = utun();
    MacRoutes::unchecked(dir)
        .configure_tunnel(&device.name, Ipv4Addr::new(198, 18, 0, last), 1300)
        .expect("configure");
    device
}

/// One DNS query read from the device.
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
/// lookup of a name goes to, as far as the device shows. A name that goes
/// elsewhere gives none.
pub(super) struct Lookups<'a> {
    device: &'a Utun,
}

impl<'a> Lookups<'a> {
    /// Routes the documentation network, where the tests' resolvers are,
    /// into `device`, as somebody else's route, so that removing all the
    /// product's routes leaves it. The routes tests' cleanup removes it.
    pub(super) fn new(device: &'a Utun) -> Self {
        Outsider.add_route(&device.name, net("192.0.2.0/24"));
        Self { device }
    }

    /// The next packet from the device within `wait`. Each DNS query is
    /// answered, and given.
    fn next(&self, wait: Duration) -> Option<Query> {
        let wait = Timespec::try_from(wait).expect("fits");
        let mut ready = [PollFd::new(&self.device.control, PollFlags::IN)];
        if poll(&mut ready, Some(&wait)).expect("poll") == 0 {
            return None;
        }
        let mut packet = [0u8; 2048];
        let read = rustix::io::read(&self.device.control, &mut packet[..]).expect("read");
        let packet = packet[..read].strip_prefix(&AF_INET)?;
        let query = Query::parse(packet)?;
        let mut answer = AF_INET.to_vec();
        answer.extend(query.answer());
        rustix::io::write(&self.device.control, &answer).expect("answer");
        Some(query)
    }

    pub(super) fn resolvers_for(&self, name: &str) -> Vec<Ipv4Addr> {
        // Whatever came before, answered and forgotten.
        while self.next(Duration::ZERO).is_some() {}
        // Nothing remembered from an earlier lookup.
        for (program, args) in [
            ("/usr/bin/dscacheutil", &["-flushcache"][..]),
            ("/usr/bin/killall", &["-HUP", "mDNSResponder"][..]),
        ] {
            let _ = Command::new(program)
                .args(args)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        // Through the system's resolver, as any program asks.
        let mut lookup = Command::new("/usr/bin/dscacheutil")
            .args(["-q", "host", "-a", "name", name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start dscacheutil");
        let started = Instant::now();
        let mut ended: Option<Instant> = None;
        let mut seen = Vec::new();
        while started.elapsed() < LOOKUP && ended.is_none_or(|at| at.elapsed() < GRACE) {
            if ended.is_none() && lookup.try_wait().expect("wait for dscacheutil").is_some() {
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

/// Somebody else's DNS entry, held by a session of its own, which removes
/// it when dropped.
struct Theirs {
    store: Store,
    key: String,
}

impl Theirs {
    fn set(resolver: [u8; 4], domain: &str) -> Self {
        let store = Store::session("ubc-vpn tests: somebody else").expect("a session");
        let key = key_of(THEIR_SERVICE);
        let value = Value::Dict(vec![
            (
                "ServerAddresses".to_string(),
                Value::Array(vec![Value::String(Ipv4Addr::from(resolver).to_string())]),
            ),
            (
                "SupplementalMatchDomains".to_string(),
                Value::Array(vec![Value::String(domain.to_string())]),
            ),
            (
                "SupplementalMatchDomainsNoSearch".to_string(),
                Value::Number(1),
            ),
        ]);
        store.set(&key, &value).expect("set their entry");
        Self { store, key }
    }

    fn value(&self) -> Option<Value> {
        self.store.get(&self.key).expect("read their entry")
    }
}

impl Drop for Theirs {
    fn drop(&mut self) {
        let _ = self.store.remove(&self.key);
    }
}

// The shared rules, in the real resolver configuration: only the chosen
// domains go to the VPN's resolvers, every other name stays as it was, and
// the setting reads back exactly.
#[test]
fn passes_the_shared_dns_suite() {
    as_root("passes_the_shared_dns_suite", "dns suite", || {
        let dir = state_dir("dns-suite");
        let _cleanup = Cleanup(vec![dir.clone()]);
        let dns = SessionDns::new(SUITE_SERVICE);
        let _gone = Removed(dns.key());
        let device = tunnel(&dir, 20);
        let lookups = Lookups::new(&device);
        log_scutil("before");
        suite::check_dns(&dns, &device.name, &|name| lookups.resolvers_for(name));
    });
}

/// The part of `a_killed_process_leaves_no_entry` that is killed. It does
/// nothing unless that test started it.
#[test]
fn crash_child() {
    let Some(dir) = std::env::var_os(CRASH) else {
        return;
    };
    regain_root();
    watchdog();
    let dir = PathBuf::from(dir);
    let dns = SessionDns::new(CRASH_SERVICE);
    let setting = split([192, 0, 2, 53], &["crash.example"]);
    dns.set_split_dns("utun-unused", &setting).expect("set");
    // Written whole, then moved into place, so it is never read half done.
    std::fs::write(dir.join("ready.new"), "").expect("write ready");
    std::fs::rename(dir.join("ready.new"), dir.join("ready")).expect("ready");
    loop {
        thread::park();
    }
}

// The entry is a session key: a process killed with it set leaves nothing,
// in the store or in the resolver configuration, and needs no start-up to
// remove it.
#[test]
fn a_killed_process_leaves_no_entry() {
    as_root("a_killed_process_leaves_no_entry", "dns crash", || {
        let dir = state_dir("dns-crash");
        let _cleanup = Cleanup(vec![dir.clone()]);
        std::fs::create_dir_all(&dir).expect("the folder");
        let key = key_of(CRASH_SERVICE);
        let _gone = Removed(key.clone());
        let setting = split([192, 0, 2, 53], &["crash.example"]);
        let mut child = Command::new(std::env::current_exe().expect("this program"))
            .args([
                "--exact",
                "os::dns_tests::crash_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CRASH, &dir)
            .spawn()
            .expect("start the child");
        let started = Instant::now();
        while !dir.join("ready").exists() {
            if started.elapsed() > DEADLINE / 2 || child.try_wait().ok().flatten().is_some() {
                let _ = child.kill();
                let _ = child.wait();
                panic!("the child did not get ready");
            }
            thread::sleep(Duration::from_millis(100));
        }
        let store = Store::session("ubc-vpn tests: watching").expect("a session");
        let held = store.get(&key).expect("read the child's entry");
        let held = held.as_ref().map(Entry::of);
        let in_effect = settled(&true, || effective().sends(&setting));
        child.kill().expect("kill the child");
        child.wait().expect("wait for the child");

        assert_eq!(held, Some(Entry::wanted(&setting)), "the child set nothing");
        assert!(in_effect, "the child's entry was not in effect");
        let left = settled(&None, || store.get(&key).expect("read the key"));
        assert_eq!(left, None, "the killed child's entry is still there");
        let still = settled(&0, || effective().for_domain("crash.example").count());
        assert_eq!(still, 0, "the killed child's resolver is still in effect");
    });
}

// Security rule: split DNS never changes the search list, so a short name
// is never sent to the VPN's resolvers with a chosen domain added.
#[test]
fn the_search_list_is_unchanged() {
    as_root("the_search_list_is_unchanged", "dns search list", || {
        let dns = SessionDns::new(SEARCH_SERVICE);
        let _gone = Removed(dns.key());
        let setting = split([192, 0, 2, 53], &["search-test.example", "more.example"]);
        dns.clear_split_dns().expect("clear");
        let before = effective().search();
        say(&format!("SEARCH before: {before:?}"));

        dns.set_split_dns("utun-unused", &setting).expect("set");
        assert!(settled(&true, || effective().sends(&setting)), "not set");
        log_scutil("with the setting");
        // Long enough for a change of the search list to show too.
        thread::sleep(Duration::from_secs(1));
        let during = effective();
        let searched = during.main.iter().flat_map(|r| r.search.iter());
        let added: Vec<&String> = searched
            .filter(|domain| setting.domains.contains(domain))
            .collect();
        assert_eq!(added, Vec::<&String>::new(), "a chosen domain is searched");
        assert_eq!(during.search(), before, "the search list changed");
        // A match is exact: one of the two domains is not the setting.
        assert_eq!(dns.split_dns_matches(&setting), Verified::Yes);
        let one = split([192, 0, 2, 53], &["search-test.example"]);
        assert_eq!(dns.split_dns_matches(&one), Verified::No, "a subset");

        dns.clear_split_dns().expect("clear");
        assert_eq!(effective().search(), before, "the search list changed");
    });
}

// Only the product's own entry is changed: somebody else's supplemental
// entry stays as it was, and in effect, through a set and a clear of ours.
#[test]
fn another_services_entry_is_untouched() {
    as_root("another_services_entry_is_untouched", "dns foreign", || {
        let dir = state_dir("dns-foreign");
        let _cleanup = Cleanup(vec![dir.clone()]);
        let device = tunnel(&dir, 21);
        let lookups = Lookups::new(&device);
        let dns = SessionDns::new(OURS_SERVICE);
        let _gone = Removed(dns.key());
        let setting = split([192, 0, 2, 53], &["suite.example"]);
        let foreign = split([192, 0, 2, 99], &["foreign.example"]);
        let theirs = Theirs::set([192, 0, 2, 99], "foreign.example");
        let before = theirs.value();
        assert!(before.is_some(), "their entry was not set");
        assert!(settled(&true, || effective().sends(&foreign)), "not theirs");

        dns.set_split_dns(&device.name, &setting).expect("set");
        assert_eq!(dns.split_dns_matches(&setting), Verified::Yes);
        assert_eq!(theirs.value(), before, "a set changed their entry");
        assert!(effective().sends(&foreign), "a set moved their domain");

        dns.clear_split_dns().expect("clear");
        assert_eq!(theirs.value(), before, "a clear changed their entry");
        assert!(effective().sends(&foreign), "a clear moved their domain");
        let host = lookups.resolvers_for("host.foreign.example");
        assert_eq!(host, [Ipv4Addr::new(192, 0, 2, 99)], "their lookups");
        assert_eq!(dns.split_dns_matches(&setting), Verified::No);
    });
}

// What is in effect is read back, not what was set: with somebody else's
// entry for the same domain and other resolvers, the system may send the
// domain to either, so ours is not in effect exactly, though its key reads
// back as set. Once theirs goes, it is.
#[test]
fn another_entry_for_the_same_domain_is_not_ours() {
    as_root(
        "another_entry_for_the_same_domain_is_not_ours",
        "dns conflict",
        || {
            let dns = SessionDns::new(OURS_SERVICE);
            let _gone = Removed(dns.key());
            let setting = split([192, 0, 2, 53], &["suite.example"]);
            let theirs = Theirs::set([192, 0, 2, 99], "suite.example");
            dns.set_split_dns("utun-unused", &setting).expect("set");
            let both = settled(&2, || effective().for_domain("suite.example").count());
            log_scutil("with two entries for one domain");
            assert_eq!(both, 2, "both entries should be in effect");
            assert_eq!(dns.split_dns_matches(&setting), Verified::No, "theirs too");

            drop(theirs);
            let alone = settled(&Verified::Yes, || dns.split_dns_matches(&setting));
            assert_eq!(alone, Verified::Yes, "ours alone");
            dns.clear_split_dns().expect("clear");
            assert_eq!(dns.split_dns_matches(&setting), Verified::No);
        },
    );
}

// Refused before anything is asked, so these need no root and change
// nothing: a setting that is not valid.
#[test]
fn a_setting_that_is_not_valid_is_refused_first() {
    let good = split([192, 0, 2, 53], &["suite.example"]);
    let mut too_many = good.clone();
    too_many.domains = (0..=MOST_DOMAINS)
        .map(|n| format!("d{n}.example"))
        .collect();
    let refused = [
        split([192, 0, 2, 53], &[]),
        SplitDns {
            resolvers: Vec::new(),
            ..good.clone()
        },
        split([0, 0, 0, 0], &["suite.example"]),
        split([255, 255, 255, 255], &["suite.example"]),
        split([224, 0, 0, 251], &["suite.example"]),
        split([192, 0, 2, 53], &["suite.example", "-x.example"]),
        split([192, 0, 2, 53], &["."]),
        split([192, 0, 2, 53], &["example"]),
        split([192, 0, 2, 53], &["Suite.example"]),
        split([192, 0, 2, 53], &["suite.example."]),
        split([192, 0, 2, 53], &["*.example"]),
        split([192, 0, 2, 53], &["192.0.2.1"]),
        too_many,
    ];
    let dns = SessionDns::new(OURS_SERVICE);
    for setting in &refused {
        assert_eq!(check(setting), Err(Error::InvalidInput), "{setting:?}");
        let result = dns.set_split_dns("utun-unused", setting);
        assert_eq!(result, Err(Error::InvalidInput), "{setting:?}");
    }
    assert_eq!(check(&good), Ok(()));
}

// The platform's DNS is this one, under the tests' own service id in a
// test build, never the product's. Nothing here changes anything.
#[test]
fn the_platform_uses_this_dns_under_the_tests_id() {
    // Never changed: a later version must find an earlier one's entry.
    assert_eq!(PRODUCT_SERVICE, "io.github.nima-hs.ubc-vpn");
    assert_eq!(TEST_SERVICE, "io.github.nima-hs.ubc-vpn.test");
    // Security rule: a test, even one run as root where the product is in
    // use, never reads, sets or removes the product's entry.
    assert_eq!(key_of(platform_service()), key_of(TEST_SERVICE));
    assert_ne!(key_of(platform_service()), key_of(PRODUCT_SERVICE));
    let bad = split([192, 0, 2, 53], &["--x"]);
    let good = split([192, 0, 2, 53], &["suite.example"]);
    let modes = [
        Mode::Installed,
        #[cfg(feature = "dev-mode")]
        Mode::Dev,
    ];
    for mode in modes {
        let dns = Platform::native(mode).expect("a platform").dns;
        assert_eq!(dns.set_split_dns("utun9", &bad), Err(Error::InvalidInput));
        // Nothing is set under the tests' id, so nothing is in effect.
        assert_eq!(dns.split_dns_matches(&good), Verified::No);
        // The catch-all is not written yet.
        assert_eq!(
            dns.set_catch_all_dns(&good.resolvers),
            Err(Error::Unsupported)
        );
        assert_eq!(
            dns.catch_all_dns_matches(&good.resolvers),
            Verified::Unknown
        );
    }
}

// The entry as it is written, and read back.
#[test]
fn the_entry_is_written_and_read_back_exactly() {
    let setting = SplitDns {
        resolvers: vec![Ipv4Addr::new(192, 0, 2, 53), Ipv4Addr::new(192, 0, 2, 54)],
        domains: vec!["suite.example".to_string(), "other.example".to_string()],
    };
    let wanted = Entry::wanted(&setting);
    assert_eq!(wanted.servers, ["192.0.2.53", "192.0.2.54"]);
    assert!(wanted.no_search, "the domains would be searched");
    let value = wanted.value();
    assert_eq!(
        value.field("SupplementalMatchDomainsNoSearch"),
        Some(&Value::Number(1))
    );
    assert_eq!(Entry::of(&value), wanted);

    // Anything else is not the entry wanted.
    let Value::Dict(fields) = value else {
        panic!("not a dictionary")
    };
    let without = |key: &str| {
        let kept = fields.iter().filter(|(k, _)| k != key).cloned().collect();
        Entry::of(&Value::Dict(kept))
    };
    assert!(!without("SupplementalMatchDomainsNoSearch").no_search);
    assert_ne!(without("SupplementalMatchDomainsNoSearch"), wanted);
    assert_ne!(without("ServerAddresses"), wanted);
    assert_ne!(without("SupplementalMatchDomains"), wanted);
    let mut more = fields.clone();
    more.push(("SearchDomains".to_string(), Value::Array(Vec::new())));
    assert_ne!(Entry::of(&Value::Dict(more)), wanted);
    let mut zero = fields.clone();
    zero.retain(|(k, _)| k != "SupplementalMatchDomainsNoSearch");
    zero.push((
        "SupplementalMatchDomainsNoSearch".to_string(),
        Value::Number(0),
    ));
    assert_ne!(Entry::of(&Value::Dict(zero)), wanted);
    assert_ne!(Entry::of(&Value::String("x".to_string())), wanted);
    let fewer = Entry::wanted(&split([192, 0, 2, 53], &["suite.example"]));
    assert_ne!(fewer, wanted, "a subset is not the entry");
}

/// What `scutil --dns` shows, in the form macOS 15 writes it, with a
/// supplemental entry for `suite.example` and `other.example`.
const SCUTIL_TEXT: &str = "\
DNS configuration

resolver #1
  search domain[0] : corp.example
  search domain[1] : lab.example
  nameserver[0] : 198.51.100.1
  if_index : 14 (en0)
  flags    : Request A records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)

resolver #2
  domain   : suite.example
  nameserver[0] : 192.0.2.53
  nameserver[1] : 192.0.2.54
  flags    : Supplemental, Request A records
  reach    : 0x00000002 (Reachable)
  order    : 102400

resolver #3
  domain   : other.example
  nameserver[0] : 192.0.2.53
  nameserver[1] : 192.0.2.54
  flags    : Supplemental, Request A records
  reach    : 0x00000002 (Reachable)
  order    : 102401

resolver #4
  domain   : local
  options  : mdns
  timeout  : 5
  flags    : Request A records
  reach    : 0x00000000 (Not Reachable)
  order    : 300000

DNS configuration (for scoped queries)

resolver #1
  search domain[0] : corp.example
  nameserver[0] : 198.51.100.1
  if_index : 14 (en0)
  flags    : Scoped, Request A records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)

resolver #2
  domain   : scoped.example
  nameserver[0] : 192.0.2.53
  if_index : 20 (utun4)
  flags    : Scoped, Request A records
  reach    : 0x00000002 (Reachable)
";

#[test]
fn reads_the_resolver_configuration() {
    let shown = Effective::parse(SCUTIL_TEXT).expect("readable");
    assert_eq!(shown.main.len(), 4, "only the ordinary resolvers");
    assert_eq!(shown.search(), ["corp.example", "lab.example"]);
    assert_eq!(
        shown.main[1],
        Resolver {
            domain: Some("suite.example".to_string()),
            search: Vec::new(),
            nameservers: vec!["192.0.2.53".to_string(), "192.0.2.54".to_string()],
        }
    );
    let both = SplitDns {
        resolvers: vec![Ipv4Addr::new(192, 0, 2, 53), Ipv4Addr::new(192, 0, 2, 54)],
        domains: vec!["suite.example".to_string(), "other.example".to_string()],
    };
    assert!(shown.sends(&both));
    let one = SplitDns {
        domains: vec!["suite.example".to_string()],
        ..both.clone()
    };
    assert!(shown.sends(&one));
    // Other resolvers, a resolver too few, and a domain with none.
    assert!(!shown.sends(&split([192, 0, 2, 53], &["suite.example"])));
    let reversed = SplitDns {
        resolvers: vec![both.resolvers[1], both.resolvers[0]],
        ..both.clone()
    };
    assert!(!shown.sends(&reversed));
    let more = SplitDns {
        domains: vec!["suite.example".to_string(), "missing.example".to_string()],
        ..both.clone()
    };
    assert!(!shown.sends(&more));
    // A scoped resolver does not answer ordinary lookups.
    assert!(!shown.sends(&split([192, 0, 2, 53], &["scoped.example"])));
    // Nor does a parent's, or one that only ends in the same letters.
    assert!(!shown.sends(&SplitDns {
        domains: vec!["example".to_string()],
        ..both.clone()
    }));
}

// Two entries for one domain with other resolvers: the system may take
// either, so neither is in effect exactly.
#[test]
fn a_second_resolver_for_the_domain_is_not_exact() {
    let text = SCUTIL_TEXT.replace("domain   : other.example", "domain   : suite.example");
    let shown = Effective::parse(&text).expect("readable");
    let both = SplitDns {
        resolvers: vec![Ipv4Addr::new(192, 0, 2, 53), Ipv4Addr::new(192, 0, 2, 54)],
        domains: vec!["suite.example".to_string()],
    };
    assert!(shown.sends(&both), "two identical entries agree");
    // Whichever comes first: the order does not make either one ours.
    let old = "nameserver[1] : 192.0.2.54";
    let new = "nameserver[1] : 192.0.2.99";
    let first_differs = text.replacen(old, new, 1);
    let shown = Effective::parse(&first_differs).expect("readable");
    assert!(!shown.sends(&both), "the first sends elsewhere");
    let (at, _) = text.match_indices(old).nth(1).expect("a second entry");
    let second_differs = format!("{}{new}{}", &text[..at], &text[at + old.len()..]);
    let shown = Effective::parse(&second_differs).expect("readable");
    assert_eq!(shown.main[1].nameservers[1], "192.0.2.54", "the first kept");
    assert!(!shown.sends(&both), "the second sends elsewhere");
}

// Fail closed: text in a form it does not know is unreadable, never read as
// "nothing set".
#[test]
fn refuses_text_it_cannot_read() {
    let empty = Effective::parse("No DNS configuration available\n").expect("none");
    assert_eq!(empty, Effective::default());
    for text in [
        "",
        "something else\n",
        "resolver #1\n  domain : suite.example\n",
        "DNS configuration\n\n  domain : suite.example\n",
        "DNS configuration\n\nresolver #x\n",
        "DNS configuration\n\nresolver #1\n  no separator here\n",
        "DNS configuration\n\nresolver #1\n  nameserver[1] : 192.0.2.53\n",
        "DNS configuration\n\nresolver #1\n  search domain[1] : a.example\n",
        "DNS configuration\n\nresolver #1\n  domain : a.example\n  domain : b.example\n",
    ] {
        assert!(Effective::parse(text).is_err(), "{text:?}");
    }
}

// Security rule: nothing from the environment reaches the system's tools,
// and they start in `/`. A tool run as scutil is run shows no variable and
// that folder, where the control, run as this process would by default,
// shows this process's variables. Needs no root and changes nothing.
#[test]
fn nothing_from_the_environment_reaches_scutil() {
    let scutil = quiet(SCUTIL, &["--dns"]);
    assert_eq!(scutil.get_program(), "/usr/sbin/scutil");
    assert_eq!(scutil.get_current_dir(), Some(Path::new("/")));

    let inherited = Command::new("/usr/bin/env").output().expect("run env");
    let inherited = String::from_utf8_lossy(&inherited.stdout).into_owned();
    assert!(inherited.contains("PATH="), "the control saw nothing");
    let given = quiet("/usr/bin/env", &[]).output().expect("run env");
    assert!(given.status.success());
    let given = String::from_utf8_lossy(&given.stdout).into_owned();
    assert_eq!(given, "", "the environment reached the tool");

    let folder = quiet("/bin/pwd", &[]).output().expect("run pwd");
    assert_eq!(String::from_utf8_lossy(&folder.stdout), "/\n");
    // And scutil itself runs so.
    assert!(Effective::now().is_ok(), "scutil --dns could not be read");
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
    assert_eq!(query.dest, ip("192.0.2.53"));
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
