//! Split DNS on macOS: a supplemental resolver entry in the dynamic store
//! (see [`dynamic_store`](super::dynamic_store)), as VPNs set them. Full
//! mode's catch-all is not written yet: those operations report
//! [`Error::Unsupported`] and their check answers [`Verified::Unknown`].
//!
//! The entry is the key `State:/Network/Service/<id>/DNS`, where the id is
//! the product's own, holding the resolvers (`ServerAddresses`), the domains
//! (`SupplementalMatchDomains`), and `SupplementalMatchDomainsNoSearch` set,
//! so that the domains are never added to the search list. configd turns it
//! into a resolver for those domains alone, and every other name resolves as
//! before.
//!
//! It is a session key, so it goes when the process that set it ends, even
//! killed: nothing outlives the service. Clearing removes that one key, and
//! never anyone else's entry.
//!
//! The check reads the key back, and then the resolver configuration in
//! effect as `scutil --dns` shows it, which is what the system's resolver
//! uses. It never answers from what was set alone.

use std::io::Read;
use std::net::Ipv4Addr;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use super::dynamic_store::{Store, Value};
use crate::unsupported::Native;
use crate::{Dns, Error, Result, SplitDns, Verified, lock};

/// The product's own service id in the dynamic store. Never change it: a
/// later version must find an earlier one's entry to remove it.
#[cfg_attr(all(feature = "fake", not(test)), allow(dead_code))]
pub(super) const PRODUCT_SERVICE: &str = "io.github.nima-hs.ubc-vpn";
/// The id tests use instead, so that no test, even one run as root on a
/// machine where the product is in use, can change or remove the product's
/// entry. It is chosen in this crate's tests and whenever the `fake` feature
/// is on, which every other crate's tests enable and a release build never
/// does.
#[cfg(any(test, feature = "fake"))]
pub(super) const TEST_SERVICE: &str = "io.github.nima-hs.ubc-vpn.test";
/// The id this build reads, writes and removes.
#[cfg(not(any(test, feature = "fake")))]
const SERVICE: &str = PRODUCT_SERVICE;
#[cfg(any(test, feature = "fake"))]
const SERVICE: &str = TEST_SERVICE;

/// The most domains one setting may hold, as on the other systems.
pub(super) const MOST_DOMAINS: usize = 300;
/// How long a set or a clear waits for the resolver configuration to show
/// it, at most.
const SETTLE: Duration = Duration::from_secs(5);
/// How long `scutil --dns` may take, at most.
const SCUTIL_LIMIT: Duration = Duration::from_secs(10);
/// The most of its output that is read.
const MOST_OUTPUT: u64 = 4 << 20;
const SCUTIL: &str = "/usr/sbin/scutil";

const SERVERS: &str = "ServerAddresses";
const DOMAINS: &str = "SupplementalMatchDomains";
const NO_SEARCH: &str = "SupplementalMatchDomainsNoSearch";

/// macOS DNS: [`SessionDns`] under the product's service id.
pub(super) struct MacDns;

/// One session for the whole process, so its entry is one key, held as long
/// as the process runs.
static PRODUCT: SessionDns = SessionDns::new(SERVICE);

/// Split DNS as one supplemental resolver entry under `service`, held by a
/// dynamic store session of its own. Tests give their own ids.
pub(super) struct SessionDns {
    service: &'static str,
    /// Opened at the first change, and kept: closing it would remove the
    /// entry.
    store: Mutex<Option<Store>>,
}

impl SessionDns {
    pub(super) const fn new(service: &'static str) -> Self {
        Self {
            service,
            store: Mutex::new(None),
        }
    }

    /// The key of this service's DNS entry.
    pub(super) fn key(&self) -> String {
        key_of(self.service)
    }

    /// Runs `act` with the session, opening it first if need be. A call
    /// that fails closes the session and tries once more with a new one, in
    /// case configd started again and the old one is gone.
    fn with_store<T>(&self, act: impl Fn(&Store) -> Result<T>) -> Result<T> {
        let mut held = lock(&self.store);
        for attempt in 0..2 {
            let store = match held.take() {
                Some(store) => store,
                None => Store::session(&format!("ubc-vpn {}", self.service))?,
            };
            match act(&store) {
                Ok(done) => {
                    *held = Some(store);
                    return Ok(done);
                }
                Err(error) if attempt == 1 || error == Error::PermissionDenied => {
                    return Err(error);
                }
                Err(_) => continue,
            }
        }
        unreachable!("the second attempt returns")
    }

    /// The entry this service has now, read from the store.
    fn entry(&self) -> Result<Option<Entry>> {
        let value = self.with_store(|store| store.get(&self.key()))?;
        Ok(value.map(|value| Entry::of(&value)))
    }
}

pub(super) fn key_of(service: &str) -> String {
    format!("State:/Network/Service/{service}/DNS")
}

/// A plain lower-case host name: at least two dot-separated labels of
/// letters, digits and hyphens, the last one not all digits. No wildcard, no
/// trailing dot, no root, and so no IP address. The same rule as the
/// profile's.
fn is_valid_domain(domain: &str) -> bool {
    let label_ok = |label: &str| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    let top_level_ok = domain
        .rsplit('.')
        .next()
        .is_some_and(|top| !top.bytes().all(|b| b.is_ascii_digit()));
    domain.len() <= 253 && domain.contains('.') && domain.split('.').all(label_ok) && top_level_ok
}

/// An address a resolver can have: not unspecified, broadcast or multicast.
fn is_valid_resolver(addr: Ipv4Addr) -> bool {
    !addr.is_unspecified() && !addr.is_broadcast() && !addr.is_multicast()
}

/// The setting checked before anything is asked: resolvers and domains
/// there are, not too many, and each one valid.
pub(super) fn check(dns: &SplitDns) -> Result<()> {
    let domains_ok = !dns.domains.is_empty()
        && dns.domains.len() <= MOST_DOMAINS
        && dns.domains.iter().all(|name| is_valid_domain(name));
    let resolvers_ok =
        !dns.resolvers.is_empty() && dns.resolvers.iter().all(|r| is_valid_resolver(*r));
    match domains_ok && resolvers_ok {
        true => Ok(()),
        false => Err(Error::InvalidInput),
    }
}

/// A DNS entry in the dynamic store, as far as split DNS goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Entry {
    pub(super) servers: Vec<String>,
    pub(super) domains: Vec<String>,
    /// Whether `SupplementalMatchDomainsNoSearch` is set.
    pub(super) no_search: bool,
    /// Whether it holds anything else, which configd would read too.
    pub(super) more: bool,
}

impl Entry {
    /// The entry that sends `dns.domains` to `dns.resolvers`.
    pub(super) fn wanted(dns: &SplitDns) -> Self {
        Self {
            servers: dns.resolvers.iter().map(ToString::to_string).collect(),
            domains: dns.domains.clone(),
            no_search: true,
            more: false,
        }
    }

    pub(super) fn value(&self) -> Value {
        let strings =
            |items: &[String]| Value::Array(items.iter().cloned().map(Value::String).collect());
        let mut fields = vec![
            (SERVERS.to_string(), strings(&self.servers)),
            (DOMAINS.to_string(), strings(&self.domains)),
        ];
        if self.no_search {
            fields.push((NO_SEARCH.to_string(), Value::Number(1)));
        }
        Value::Dict(fields)
    }

    /// The entry a value read from the store holds. Anything that is not
    /// as [`Entry::value`] writes it counts as more.
    pub(super) fn of(value: &Value) -> Self {
        let strings = |key: &str| match value.field(key) {
            Some(Value::Array(items)) => items
                .iter()
                .map(|item| match item {
                    Value::String(text) => Some(text.clone()),
                    _ => None,
                })
                .collect::<Option<Vec<_>>>(),
            _ => None,
        };
        let (servers, domains) = (strings(SERVERS), strings(DOMAINS));
        let no_search = match value.field(NO_SEARCH) {
            None => Some(false),
            Some(Value::Number(1)) => Some(true),
            Some(_) => None,
        };
        let known = [SERVERS, DOMAINS, NO_SEARCH];
        let others = match value {
            Value::Dict(fields) => fields.iter().any(|(k, _)| !known.contains(&k.as_str())),
            _ => true,
        };
        let bad = servers.is_none() || domains.is_none() || no_search.is_none();
        Self {
            servers: servers.unwrap_or_default(),
            domains: domains.unwrap_or_default(),
            no_search: no_search.unwrap_or(false),
            more: others || bad,
        }
    }
}

/// Which list of resolvers `scutil --dns` showed one in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Section {
    /// The resolvers for ordinary lookups.
    Main,
    /// Those for lookups scoped to an interface or a service.
    Scoped,
}

/// One resolver as `scutil --dns` shows it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct Resolver {
    pub(super) domain: Option<String>,
    pub(super) search: Vec<String>,
    pub(super) nameservers: Vec<String>,
}

/// The resolver configuration in effect.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct Effective {
    /// The resolvers for ordinary lookups, in order.
    pub(super) main: Vec<Resolver>,
}

impl Effective {
    /// Reads what `scutil --dns` shows. Text it does not know is an error,
    /// so a change of its form gives `Unknown`, never a guess.
    pub(super) fn parse(text: &str) -> Result<Self> {
        let unreadable = |line: &str| Error::Failed(format!("scutil --dns: unexpected {line:?}"));
        let mut main = Vec::new();
        let mut section = None;
        let mut current: Option<Resolver> = None;
        let mut close = |current: &mut Option<Resolver>, section: Option<Section>| {
            if let (Some(resolver), Some(Section::Main)) = (current.take(), section) {
                main.push(resolver);
            }
        };
        if text.trim() == "No DNS configuration available" {
            return Ok(Self::default());
        }
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if trimmed.starts_with("DNS configuration") {
                close(&mut current, section);
                section = Some(match trimmed == "DNS configuration" {
                    true if section.is_none() => Section::Main,
                    _ => Section::Scoped,
                });
                continue;
            }
            if let Some(number) = trimmed.strip_prefix("resolver #") {
                if section.is_none() || number.parse::<u32>().is_err() {
                    return Err(unreadable(line));
                }
                close(&mut current, section);
                current = Some(Resolver::default());
                continue;
            }
            let Some(resolver) = current.as_mut() else {
                return Err(unreadable(line));
            };
            let Some((name, value)) = trimmed.split_once(':') else {
                return Err(unreadable(line));
            };
            let (name, value) = (name.trim(), value.trim().to_string());
            if name == "domain" {
                if resolver.domain.replace(value).is_some() {
                    return Err(unreadable(line));
                }
            } else if let Some(at) = indexed(name, "search domain") {
                if at != resolver.search.len() {
                    return Err(unreadable(line));
                }
                resolver.search.push(value);
            } else if let Some(at) = indexed(name, "nameserver") {
                if at != resolver.nameservers.len() {
                    return Err(unreadable(line));
                }
                resolver.nameservers.push(value);
            }
            // Anything else about a resolver (its interface, flags, order,
            // timeout and so on) does not decide where a name goes.
        }
        close(&mut current, section);
        match section {
            Some(_) => Ok(Self { main }),
            None => Err(unreadable(text.lines().next().unwrap_or_default())),
        }
    }

    /// Reads the configuration in effect now.
    pub(super) fn now() -> Result<Self> {
        Self::parse(&scutil_dns()?)
    }

    /// The resolvers for ordinary lookups whose domain is `domain`.
    pub(super) fn for_domain<'a>(&'a self, domain: &'a str) -> impl Iterator<Item = &'a Resolver> {
        self.main
            .iter()
            .filter(move |r| r.domain.as_deref() == Some(domain))
    }

    /// The search list: the first resolver's, which is the default one.
    #[cfg(test)]
    pub(super) fn search(&self) -> Vec<String> {
        self.main
            .first()
            .filter(|r| r.domain.is_none())
            .map(|r| r.search.clone())
            .unwrap_or_default()
    }

    /// Whether every name under `dns.domains` goes to exactly
    /// `dns.resolvers`: each domain has a resolver of its own, and every
    /// resolver for it has exactly those servers, in order. Another entry
    /// for the same domain with other servers makes it not so, as the
    /// system might take either.
    pub(super) fn sends(&self, dns: &SplitDns) -> bool {
        let servers: Vec<String> = dns.resolvers.iter().map(ToString::to_string).collect();
        dns.domains.iter().all(|domain| {
            let mut found = self.for_domain(domain).peekable();
            found.peek().is_some() && found.all(|r| r.nameservers == servers)
        })
    }

    /// Whether any name under `domains` still goes to `servers` through an
    /// entry for that domain.
    fn still_sends(&self, domains: &[String], servers: &[String]) -> bool {
        domains
            .iter()
            .any(|domain| self.for_domain(domain).any(|r| r.nameservers == servers))
    }
}

/// `name` as `<prefix>[<n>]`, gives `n`.
fn indexed(name: &str, prefix: &str) -> Option<usize> {
    let rest = name.strip_prefix(prefix)?.strip_prefix('[')?;
    rest.strip_suffix(']')?.parse().ok()
}

/// What `scutil --dns` writes, run with no environment.
fn scutil_dns() -> Result<String> {
    let mut child = Command::new(SCUTIL)
        .arg("--dns")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| Error::Failed(format!("could not run scutil: {error}")))?;
    let output = child.stdout.take();
    let reader = thread::spawn(move || {
        let mut text = String::new();
        if let Some(output) = output {
            let _ = output.take(MOST_OUTPUT).read_to_string(&mut text);
        }
        text
    });
    let status = finish(&mut child)?;
    let text = reader
        .join()
        .map_err(|_| Error::Failed("scutil's output was lost".to_string()))?;
    match status.success() {
        true => Ok(text),
        false => Err(Error::Failed(format!("scutil --dns failed: {status}"))),
    }
}

/// Waits up to [`SCUTIL_LIMIT`] for `child`, and stops it after that.
fn finish(child: &mut Child) -> Result<std::process::ExitStatus> {
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if started.elapsed() < SCUTIL_LIMIT => {
                thread::sleep(Duration::from_millis(5));
            }
            outcome => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(Error::Failed(format!("scutil --dns: {outcome:?}")));
            }
        }
    }
}

/// Waits, up to [`SETTLE`], until the configuration in effect is as `done`
/// says. configd takes in a change of the store a moment after it is made.
/// Best effort: the check reads it again, whatever this finds.
fn settle(done: impl Fn(&Effective) -> bool) {
    let started = Instant::now();
    while started.elapsed() < SETTLE {
        if Effective::now().is_ok_and(|now| done(&now)) {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
}

impl Dns for SessionDns {
    // macOS does not attach this entry to an interface: the resolvers are
    // reached by ordinary routing, which sends them into the tunnel. So the
    // tunnel's name is not used.
    fn set_split_dns(&self, _tunnel: &str, dns: &SplitDns) -> Result<()> {
        check(dns)?;
        let wanted = Entry::wanted(dns);
        self.with_store(|store| store.set(&self.key(), &wanted.value()))?;
        settle(|now| now.sends(dns));
        Ok(())
    }

    fn clear_split_dns(&self) -> Result<()> {
        let was = self.entry()?;
        self.with_store(|store| store.remove(&self.key()))?;
        if let Some(was) = was {
            settle(|now| !now.still_sends(&was.domains, &was.servers));
        }
        Ok(())
    }

    fn split_dns_matches(&self, dns: &SplitDns) -> Verified {
        match self.entry() {
            Ok(Some(entry)) if entry == Entry::wanted(dns) => {}
            Ok(_) => return Verified::No,
            Err(_) => return Verified::Unknown,
        }
        match Effective::now() {
            Ok(now) if now.sends(dns) => Verified::Yes,
            Ok(_) => Verified::No,
            Err(_) => Verified::Unknown,
        }
    }

    fn set_catch_all_dns(&self, resolvers: &[Ipv4Addr]) -> Result<()> {
        Native.set_catch_all_dns(resolvers)
    }

    fn clear_catch_all_dns(&self) -> Result<()> {
        Native.clear_catch_all_dns()
    }

    fn catch_all_dns_matches(&self, resolvers: &[Ipv4Addr]) -> Verified {
        Native.catch_all_dns_matches(resolvers)
    }

    fn foreign_catch_all(&self) -> Result<bool> {
        Native.foreign_catch_all()
    }
}

impl Dns for MacDns {
    fn set_split_dns(&self, tunnel: &str, dns: &SplitDns) -> Result<()> {
        PRODUCT.set_split_dns(tunnel, dns)
    }

    fn clear_split_dns(&self) -> Result<()> {
        PRODUCT.clear_split_dns()
    }

    fn split_dns_matches(&self, dns: &SplitDns) -> Verified {
        PRODUCT.split_dns_matches(dns)
    }

    fn set_catch_all_dns(&self, resolvers: &[Ipv4Addr]) -> Result<()> {
        PRODUCT.set_catch_all_dns(resolvers)
    }

    fn clear_catch_all_dns(&self) -> Result<()> {
        PRODUCT.clear_catch_all_dns()
    }

    fn catch_all_dns_matches(&self, resolvers: &[Ipv4Addr]) -> Verified {
        PRODUCT.catch_all_dns_matches(resolvers)
    }

    fn foreign_catch_all(&self) -> Result<bool> {
        PRODUCT.foreign_catch_all()
    }
}
