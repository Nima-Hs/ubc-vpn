//! systemd-resolved, asked through `/usr/bin/busctl` (decision G3), so that
//! the service never links D-Bus itself.
//!
//! Security rule: busctl is started by its absolute path, with an empty
//! environment and no shell. Its arguments are fixed words, numbers, and
//! domains checked by [`is_valid_domain`] here, just before they are passed.
//! A `--` ends busctl's own options before them, so not even an argument
//! that looks like an option could change what busctl does.
//!
//! Its answers are read strictly: anything this does not fully understand is
//! an error, which a check turns into [`crate::Verified::Unknown`].

use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::{Error, Result};

/// The only busctl this ever starts.
const BUSCTL: &str = "/usr/bin/busctl";
/// The system bus, nothing started on demand, a limit on each call, and the
/// end of busctl's options.
const OPTIONS: [&str; 5] = [
    "--system",
    "--no-pager",
    "--auto-start=no",
    "--timeout=10",
    "--",
];
/// How long busctl may take before it is stopped. Longer than its own limit.
const LIMIT: Duration = Duration::from_secs(15);
/// The most of busctl's output, or its error, that is read.
const MOST_OUTPUT: u64 = 1 << 20;

const RESOLVE1: &str = "org.freedesktop.resolve1";
const MANAGER_PATH: &str = "/org/freedesktop/resolve1";
const MANAGER: &str = "org.freedesktop.resolve1.Manager";
const LINK: &str = "org.freedesktop.resolve1.Link";
/// systemd-resolved's unit, as systemd names its object.
const UNIT_PATH: &str = "/org/freedesktop/systemd1/unit/systemd_2dresolved_2eservice";
/// `AF_INET`, as resolved takes an address's family.
const AF_INET: &str = "2";
/// `SD_RESOLVED_DNS` in a link's `ScopesMask`: it has a unicast DNS scope,
/// so resolved sends lookups there.
const DNS_SCOPE: u64 = 1;

/// The most domains one setting takes, as on Windows.
pub(super) const MOST_DOMAINS: usize = 300;

/// A plain lower-case host name: at least two dot-separated labels of
/// letters, digits and hyphens, the last one not all digits. No wildcard, no
/// trailing dot, no root, and so no IP address and nothing busctl or resolved
/// could read as anything but a name. The same rule as the profile's.
pub(super) fn is_valid_domain(domain: &str) -> bool {
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
pub(super) fn is_valid_resolver(addr: Ipv4Addr) -> bool {
    !addr.is_unspecified() && !addr.is_broadcast() && !addr.is_multicast()
}

/// Reads all of `from`, up to [`MOST_OUTPUT`], on a thread of its own, so a
/// full pipe never stalls busctl.
fn collect(from: Option<impl Read + Send + 'static>) -> thread::JoinHandle<String> {
    thread::spawn(move || {
        let mut text = String::new();
        if let Some(from) = from {
            let _ = from.take(MOST_OUTPUT).read_to_string(&mut text);
        }
        text
    })
}

/// Waits up to [`LIMIT`] for `child`, and stops it after that.
fn finish(child: &mut Child) -> Result<std::process::ExitStatus> {
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if started.elapsed() < LIMIT => thread::sleep(Duration::from_millis(5)),
            outcome => {
                let _ = child.kill();
                let _ = child.wait();
                let message = match outcome {
                    Err(error) => format!("waiting for busctl failed: {error}"),
                    _ => "busctl did not finish".to_string(),
                };
                return Err(Error::Failed(message));
            }
        }
    }
}

/// The busctl command for `args`: busctl by its absolute path, with nothing
/// from this process's environment, and the fixed options, ending in `--`,
/// before `args`.
fn command(args: &[&str]) -> Command {
    let mut command = Command::new(BUSCTL);
    command
        .env_clear()
        .current_dir("/")
        .args(OPTIONS)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

/// Runs busctl with `args` after the fixed options, and gives what it wrote.
/// [`Error::Unsupported`] when there is no busctl, as on a system without
/// systemd.
fn busctl(args: &[&str]) -> Result<String> {
    let spawned = command(args).spawn();
    let mut child = match spawned {
        Ok(child) => child,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Err(Error::Unsupported),
        Err(error) => return Err(Error::Failed(format!("busctl did not start: {error}"))),
    };
    let output = collect(child.stdout.take());
    let errors = collect(child.stderr.take());
    let status = finish(&mut child);
    let output = output.join().unwrap_or_default();
    let errors = errors.join().unwrap_or_default();
    if status?.success() {
        return Ok(output);
    }
    // Which call, and busctl's own first line about it. Neither holds a
    // secret: nothing secret is ever passed here.
    let what = args.iter().take(5).copied().collect::<Vec<_>>().join(" ");
    let why = errors.lines().next().unwrap_or("no reason given");
    let why: String = why.chars().take(200).collect();
    Err(Error::Failed(format!("busctl {what}: {why}")))
}

/// One word of busctl's output: a plain word, or a string it put in quotes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Word<'a> {
    Plain(&'a str),
    Text(&'a str),
}

/// The words of one line, or `None` when it holds something not understood:
/// a quote out of place, or a string with an escape in it, which no valid
/// domain or answer of ours needs.
fn words(line: &str) -> Option<Vec<Word<'_>>> {
    let mut found = Vec::new();
    let mut rest = line.trim();
    while !rest.is_empty() {
        let tail = if let Some(open) = rest.strip_prefix('"') {
            let end = open.find('"')?;
            let text = &open[..end];
            if text.contains('\\') {
                return None;
            }
            found.push(Word::Text(text));
            &open[end + 1..]
        } else {
            let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
            let word = &rest[..end];
            if word.contains('"') {
                return None;
            }
            found.push(Word::Plain(word));
            &rest[end..]
        };
        if !tail.is_empty() && !tail.starts_with(char::is_whitespace) {
            return None;
        }
        rest = tail.trim_start();
    }
    Some(found)
}

/// Reads words one value at a time, for a reply with a known signature.
struct Reader<'a> {
    words: std::vec::IntoIter<Word<'a>>,
}

impl<'a> Reader<'a> {
    /// A reader of `line`, whose first word must be the signature `wanted`.
    fn new(line: &'a str, wanted: &str) -> Option<Self> {
        let mut words = words(line)?.into_iter();
        (words.next()? == Word::Plain(wanted)).then_some(Self { words })
    }

    fn plain(&mut self) -> Option<&'a str> {
        match self.words.next()? {
            Word::Plain(word) => Some(word),
            Word::Text(_) => None,
        }
    }

    fn text(&mut self) -> Option<&'a str> {
        match self.words.next()? {
            Word::Text(text) => Some(text),
            Word::Plain(_) => None,
        }
    }

    fn bool(&mut self) -> Option<bool> {
        match self.plain()? {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        }
    }

    fn number<T: std::str::FromStr>(&mut self) -> Option<T> {
        let word = self.plain()?;
        // Digits only: no sign, no space, nothing `parse` would forgive.
        if word.is_empty() || !word.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        word.parse().ok()
    }

    /// The value, if every word was read.
    fn end<T>(mut self, value: T) -> Option<T> {
        self.words.next().is_none().then_some(value)
    }
}

/// A reply of one string, `s "..."`.
fn string(line: &str) -> Option<&str> {
    let mut reader = Reader::new(line, "s")?;
    let text = reader.text()?;
    reader.end(text)
}

/// A reply of one boolean, `b true`.
fn boolean(line: &str) -> Option<bool> {
    let mut reader = Reader::new(line, "b")?;
    let value = reader.bool()?;
    reader.end(value)
}

/// A link's DNS servers, `a(iay) <count> (<family> <length> <bytes>...)...`.
fn servers(line: &str) -> Option<Vec<IpAddr>> {
    let mut reader = Reader::new(line, "a(iay)")?;
    let count: usize = reader.number()?;
    let mut found = Vec::new();
    for _ in 0..count {
        let family: u32 = reader.number()?;
        let length: usize = reader.number()?;
        if length != 4 && length != 16 {
            return None;
        }
        let mut bytes = Vec::new();
        for _ in 0..length {
            bytes.push(reader.number::<u8>()?);
        }
        let addr = match (family, <[u8; 4]>::try_from(bytes.as_slice())) {
            (2, Ok(v4)) => IpAddr::V4(Ipv4Addr::from(v4)),
            (10, _) => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(bytes).ok()?)),
            _ => return None,
        };
        found.push(addr);
    }
    reader.end(found)
}

/// A link's domains, `a(sb) <count> ("<name>" <routing only>)...`.
fn domains(line: &str) -> Option<Vec<(String, bool)>> {
    let mut reader = Reader::new(line, "a(sb)")?;
    let count: usize = reader.number()?;
    let mut found = Vec::new();
    for _ in 0..count {
        let name = reader.text()?.to_string();
        found.push((name, reader.bool()?));
    }
    reader.end(found)
}

/// What resolved holds for one link, read back from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct LinkState {
    /// Whether resolved sends unicast DNS lookups to the link at all.
    pub(super) dns_scope: bool,
    pub(super) servers: Vec<IpAddr>,
    /// Each domain, and whether it is for routing only (`~domain`).
    pub(super) domains: Vec<(String, bool)>,
    pub(super) default_route: bool,
    pub(super) llmnr: String,
    pub(super) multicast_dns: String,
}

impl LinkState {
    /// Whether anything that routes lookups is set on the link.
    pub(super) fn has_dns(&self) -> bool {
        !self.servers.is_empty() || !self.domains.is_empty()
    }

    /// Whether the link takes exactly these domains, for routing only, to
    /// exactly these resolvers, with nothing more: no default route, no
    /// LLMNR and no multicast DNS, and resolved sending lookups there.
    pub(super) fn is_exactly(&self, resolvers: &[Ipv4Addr], names: &[String]) -> bool {
        let mut servers = self.servers.clone();
        servers.sort_unstable();
        servers.dedup();
        let mut wanted: Vec<IpAddr> = resolvers.iter().copied().map(IpAddr::V4).collect();
        wanted.sort_unstable();
        wanted.dedup();
        let mut domains = self.domains.clone();
        domains.sort_unstable();
        domains.dedup();
        let mut wanted_domains: Vec<(String, bool)> =
            names.iter().map(|name| (name.clone(), true)).collect();
        wanted_domains.sort_unstable();
        wanted_domains.dedup();
        self.dns_scope
            && servers == wanted
            && domains == wanted_domains
            && !self.default_route
            && self.llmnr == "no"
            && self.multicast_dns == "no"
    }
}

/// [`LinkState`] from busctl's answer to the properties [`link_state`] asks
/// for, in that order, or `None` when it is not fully understood.
pub(super) fn parse_link_state(output: &str) -> Option<LinkState> {
    let lines: Vec<&str> = output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    let [
        scopes,
        servers_line,
        domains_line,
        default_route,
        llmnr,
        multicast_dns,
    ] = lines.as_slice()
    else {
        return None;
    };
    let mut reader = Reader::new(scopes, "t")?;
    let mask: u64 = reader.number()?;
    let mask = reader.end(mask)?;
    Some(LinkState {
        dns_scope: mask & DNS_SCOPE != 0,
        servers: servers(servers_line)?,
        domains: domains(domains_line)?,
        default_route: boolean(default_route)?,
        llmnr: string(llmnr)?.to_string(),
        multicast_dns: string(multicast_dns)?.to_string(),
    })
}

/// An answer not understood, as an error.
fn unclear(what: &str) -> Error {
    Error::Failed(format!("busctl's answer about {what} was not understood"))
}

/// Whether resolved is running on the system bus. `Ok(false)` too when
/// there is no busctl.
pub(super) fn running() -> Result<bool> {
    let args = [
        "call",
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
        "NameHasOwner",
        "s",
        RESOLVE1,
    ];
    match busctl(&args) {
        Ok(output) => boolean(&output).ok_or_else(|| unclear("resolved running")),
        Err(Error::Unsupported) => Ok(false),
        Err(error) => Err(error),
    }
}

/// The `resolv.conf` modes in which programs ask resolved: through its stub,
/// or with its own list of servers in a file it does not write.
pub(super) fn honoured_mode(mode: &str) -> bool {
    matches!(mode, "stub" | "static")
}

/// Whether split DNS can be honoured: resolved runs, is not masked, and
/// programs ask it. `Ok(false)` when any of that is clearly not so, an error
/// when it could not be told.
pub(super) fn usable() -> Result<bool> {
    if !running()? {
        return Ok(false);
    }
    let load = busctl(&[
        "get-property",
        "org.freedesktop.systemd1",
        UNIT_PATH,
        "org.freedesktop.systemd1.Unit",
        "LoadState",
    ])?;
    match string(&load) {
        Some("masked" | "not-found") => return Ok(false),
        Some(_) => {}
        None => return Err(unclear("resolved's unit")),
    }
    let mode = busctl(&[
        "get-property",
        RESOLVE1,
        MANAGER_PATH,
        MANAGER,
        "ResolvConfMode",
    ])?;
    let mode = string(&mode).ok_or_else(|| unclear("resolv.conf"))?;
    Ok(honoured_mode(mode))
}

/// resolved's object for the link numbered `index`.
fn link_path(index: u32) -> Result<String> {
    let index = index.to_string();
    let output = busctl(&[
        "call",
        RESOLVE1,
        MANAGER_PATH,
        MANAGER,
        "GetLink",
        "i",
        &index,
    ])?;
    let mut reader = Reader::new(&output, "o").ok_or_else(|| unclear("a link"))?;
    let path = reader.text().ok_or_else(|| unclear("a link"))?;
    let path = reader.end(path).ok_or_else(|| unclear("a link"))?;
    let tail = path.strip_prefix("/org/freedesktop/resolve1/link/");
    let plain = |tail: &str| {
        !tail.is_empty() && tail.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    };
    match tail {
        Some(tail) if plain(tail) => Ok(path.to_string()),
        _ => Err(unclear("a link")),
    }
}

/// What resolved holds for the link numbered `index`.
pub(super) fn link_state(index: u32) -> Result<LinkState> {
    let path = link_path(index)?;
    let output = busctl(&[
        "get-property",
        RESOLVE1,
        &path,
        LINK,
        "ScopesMask",
        "DNS",
        "Domains",
        "DefaultRoute",
        "LLMNR",
        "MulticastDNS",
    ])?;
    parse_link_state(&output).ok_or_else(|| unclear("a link's settings"))
}

/// Calls a method of resolved's manager with `signature` and `args`.
fn manage(method: &str, signature: &str, args: &[String]) -> Result<()> {
    let mut all = vec!["call", RESOLVE1, MANAGER_PATH, MANAGER, method, signature];
    all.extend(args.iter().map(String::as_str));
    busctl(&all).map(drop)
}

/// The arguments of `SetLinkDNS` for these resolvers, or `None` when one is
/// not an address a resolver can have.
pub(super) fn dns_args(index: u32, resolvers: &[Ipv4Addr]) -> Option<Vec<String>> {
    let mut args = vec![index.to_string(), resolvers.len().to_string()];
    for resolver in resolvers {
        if !is_valid_resolver(*resolver) {
            return None;
        }
        args.extend([AF_INET.to_string(), "4".to_string()]);
        args.extend(resolver.octets().iter().map(u8::to_string));
    }
    Some(args)
}

/// The arguments of `SetLinkDomains` for these domains, each for routing
/// only, or `None` when one is not a valid domain.
pub(super) fn domain_args(index: u32, names: &[String]) -> Option<Vec<String>> {
    let mut args = vec![index.to_string(), names.len().to_string()];
    for name in names {
        if !is_valid_domain(name) {
            return None;
        }
        args.extend([name.clone(), "true".to_string()]);
    }
    Some(args)
}

/// Puts split DNS on the link numbered `index`: the default route, LLMNR and
/// multicast DNS off first, so it never takes other names even for a moment,
/// then the domains for routing only, then the resolvers.
///
/// Security rule: every value is checked again here, just before it goes to
/// busctl. [`Error::InvalidInput`] when one is not valid, before anything
/// changes.
pub(super) fn set_link(index: u32, resolvers: &[Ipv4Addr], names: &[String]) -> Result<()> {
    let dns = dns_args(index, resolvers).ok_or(Error::InvalidInput)?;
    let domains = domain_args(index, names).ok_or(Error::InvalidInput)?;
    let link = index.to_string();
    manage(
        "SetLinkDefaultRoute",
        "ib",
        &[link.clone(), "false".to_string()],
    )?;
    manage("SetLinkLLMNR", "is", &[link.clone(), "no".to_string()])?;
    manage("SetLinkMulticastDNS", "is", &[link, "no".to_string()])?;
    manage("SetLinkDomains", "ia(sb)", &domains)?;
    manage("SetLinkDNS", "ia(iay)", &dns)
}

/// Takes back everything set on the link numbered `index` through resolved's
/// manager.
pub(super) fn revert_link(index: u32) -> Result<()> {
    manage("RevertLink", "i", &[index.to_string()])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words_are_split_and_strings_kept_whole() {
        let line = r#"a(sb) 2 "suite.example" true "x y" false"#;
        let expected = [
            Word::Plain("a(sb)"),
            Word::Plain("2"),
            Word::Text("suite.example"),
            Word::Plain("true"),
            Word::Text("x y"),
            Word::Plain("false"),
        ];
        assert_eq!(words(line).as_deref(), Some(&expected[..]));
        assert_eq!(words(""), Some(Vec::new()));
        // Fail closed: an escape, a quote that is not closed, a quote in a
        // word, or a string run into the next word.
        for unclear in [r#"s "a\"b""#, r#"s "open"#, r#"s a"b"#, r#"s "a"b"#] {
            assert_eq!(words(unclear), None, "{unclear}");
        }
    }

    #[test]
    fn a_link_state_is_read_exactly() {
        let output = "t 1\na(iay) 1 2 4 192 0 2 53\na(sb) 2 \"suite.example\" true \
                      \"other.example\" true\nb false\ns \"no\"\ns \"no\"\n";
        let state = parse_link_state(output).expect("understood");
        assert_eq!(
            state,
            LinkState {
                dns_scope: true,
                servers: vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53))],
                domains: vec![
                    ("suite.example".to_string(), true),
                    ("other.example".to_string(), true)
                ],
                default_route: false,
                llmnr: "no".to_string(),
                multicast_dns: "no".to_string(),
            }
        );
        let resolver = [Ipv4Addr::new(192, 0, 2, 53)];
        let both = ["other.example".to_string(), "suite.example".to_string()];
        assert!(state.is_exactly(&resolver, &both), "order does not count");
        assert!(!state.is_exactly(&resolver, &both[..1]), "fewer domains");
        assert!(!state.is_exactly(&[Ipv4Addr::new(192, 0, 2, 54)], &both));
        // Settings that resolved holds but does not use, as on a link that is
        // down: no unicast DNS scope, so not in effect.
        let unused = LinkState {
            dns_scope: false,
            ..state.clone()
        };
        assert!(!unused.is_exactly(&resolver, &both), "no DNS scope");
        let unused = "t 6\na(iay) 1 2 4 192 0 2 53\na(sb) 1 \"suite.example\" true\n\
                      b false\ns \"no\"\ns \"no\"\n";
        let unused = parse_link_state(unused).expect("understood");
        assert!(!unused.dns_scope, "only LLMNR scopes");
        assert!(!unused.is_exactly(&resolver, &both[1..]), "no DNS scope");

        let empty = "t 6\na(iay) 0\na(sb) 0\nb true\ns \"yes\"\ns \"no\"\n";
        let state = parse_link_state(empty).expect("understood");
        assert!(!state.has_dns());
        assert!(!state.dns_scope);
        let v6 = "t 1\na(iay) 1 10 16 32 1 13 184 0 0 0 0 0 0 0 0 0 0 0 1\na(sb) 0\n\
                  b false\ns \"no\"\ns \"no\"\n";
        let state = parse_link_state(v6).expect("understood");
        assert!(state.has_dns());
        assert_eq!(state.servers, ["2001:db8::1".parse::<IpAddr>().unwrap()]);
    }

    // Security rule: an answer not fully understood is never taken as a
    // match. Each of these is cut, padded or changed in one place.
    #[test]
    fn a_link_state_not_fully_understood_is_none() {
        let good = [
            "t 1",
            "a(iay) 1 2 4 192 0 2 53",
            "a(sb) 1 \"suite.example\" true",
            "b false",
            "s \"no\"",
            "s \"no\"",
        ];
        assert!(parse_link_state(&good.join("\n")).is_some());
        let changes: [(usize, &str); 14] = [
            (0, "t -1"),
            (0, "t 1 2"),
            (0, "u 1"),
            (1, "a(iay) 2 2 4 192 0 2 53"),
            (1, "a(iay) 1 2 4 192 0 2"),
            (1, "a(iay) 1 2 4 192 0 2 300"),
            (1, "a(iay) 1 7 4 192 0 2 53"),
            (1, "a(iay) 1 2 4 192 0 2 53 9"),
            (2, "a(sb) 1 \"suite.example\" maybe"),
            (2, "a(sb) 1 suite.example true"),
            (2, "a(sb) 2 \"suite.example\" true"),
            (3, "b no"),
            (4, "s no"),
            (5, "s \"n\\x6f\""),
        ];
        for (at, changed) in changes {
            let mut lines = good;
            lines[at] = changed;
            assert_eq!(parse_link_state(&lines.join("\n")), None, "{changed}");
        }
        assert_eq!(
            parse_link_state(&good[..5].join("\n")),
            None,
            "a line short"
        );
        let more = format!("{}\ns \"no\"", good.join("\n"));
        assert_eq!(parse_link_state(&more), None, "a line more");
    }

    #[test]
    fn only_stub_and_static_are_honoured() {
        assert!(honoured_mode("stub"));
        assert!(honoured_mode("static"));
        for mode in ["uplink", "foreign", "missing", "", "Stub"] {
            assert!(!honoured_mode(mode), "{mode}");
        }
    }

    // Security rule: only a plain name reaches busctl. Each of these is
    // refused: an option for busctl, the catch-all, a search-list form,
    // spaces, quotes, escapes, control characters, upper case, non-ASCII, a
    // wildcard, an address, a trailing dot, and names too long.
    #[test]
    fn a_domain_that_is_not_a_plain_name_is_refused() {
        let long_label = format!("{}.example", "a".repeat(64));
        let long_name = format!("{}example", "abcdefghi.".repeat(25));
        let refused = [
            "--address=unix:path=/tmp/x",
            "-h",
            ".",
            "~.",
            "~suite.example",
            "",
            "example",
            "suite.example extra",
            "suite.example\" false \"x.example",
            "suite\\.example",
            "suite.example\n",
            "suite.example\0",
            "Suite.example",
            "s\u{e9}te.example",
            "*.example",
            "192.0.2.1",
            "suite.example.",
            "a..example",
            "-suite.example",
            "suite-.example",
            "suite.example/x",
            &long_label,
            &long_name,
        ];
        for domain in refused {
            assert!(!is_valid_domain(domain), "{domain:?}");
            let names = [domain.to_string()];
            assert_eq!(domain_args(7, &names), None, "{domain:?}");
            let resolvers = [Ipv4Addr::new(192, 0, 2, 53)];
            // Link 0 is no link, which resolved refuses: were the check ever
            // lost, no real link's DNS could change here.
            assert_eq!(set_link(0, &resolvers, &names), Err(Error::InvalidInput));
        }
        for domain in ["suite.example", "a-b.c1.example", "x.y.z.example"] {
            assert!(is_valid_domain(domain), "{domain}");
        }
    }

    #[test]
    fn the_arguments_are_numbers_and_checked_names() {
        let names = ["suite.example".to_string(), "other.example".to_string()];
        let args = domain_args(7, &names).expect("valid");
        let expected = ["7", "2", "suite.example", "true", "other.example", "true"];
        assert_eq!(args, expected);
        let resolvers = [Ipv4Addr::new(192, 0, 2, 53), Ipv4Addr::new(198, 51, 100, 1)];
        let args = dns_args(7, &resolvers).expect("valid");
        let expected = [
            "7", "2", "2", "4", "192", "0", "2", "53", "2", "4", "198", "51", "100", "1",
        ];
        assert_eq!(args, expected);
        for bad in [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
            Ipv4Addr::new(224, 0, 0, 251),
        ] {
            assert_eq!(dns_args(7, &[bad]), None, "{bad}");
            let names = ["suite.example".to_string()];
            assert_eq!(set_link(0, &[bad], &names), Err(Error::InvalidInput));
        }
    }

    // Security rule: busctl by its absolute path, and `--` right before the
    // caller's arguments, after the fixed options and nothing else, so no
    // argument can be read as an option.
    #[test]
    fn busctl_is_named_by_its_path_and_options_end_before_the_arguments() {
        let args = ["call", "--address=unix:path=/x", "-h"];
        let command = command(&args);
        assert_eq!(command.get_program(), BUSCTL);
        assert!(std::path::Path::new(BUSCTL).is_absolute());
        let given: Vec<&std::ffi::OsStr> = command.get_args().collect();
        let mut expected: Vec<&str> = OPTIONS.to_vec();
        expected.extend(args);
        assert_eq!(given, expected);
        let end = given.iter().position(|arg| *arg == "--");
        assert_eq!(end, Some(given.len() - args.len() - 1), "-- before them");
        assert_eq!(OPTIONS.last(), Some(&"--"));
        assert_eq!(command.get_current_dir(), Some(std::path::Path::new("/")));
    }

    /// Set in the process that [`nothing_from_the_environment_reaches_busctl`]
    /// starts.
    const ENV_CHILD: &str = "UBC_VPN_BUSCTL_ENV_CHILD";

    // Security rule: nothing from the environment reaches busctl. A process
    // of its own, with a system bus address and systemd settings that would
    // send busctl nowhere, still asks the real bus. The control shows that a
    // busctl that did inherit them would fail. Needs no root.
    #[test]
    fn nothing_from_the_environment_reaches_busctl() {
        if std::env::var_os(ENV_CHILD).is_some() {
            let asked = running();
            assert!(asked.is_ok(), "busctl took the environment: {asked:?}");
            if std::path::Path::new(BUSCTL).exists() {
                let mut inherited = Command::new(BUSCTL);
                inherited.args(OPTIONS).args([
                    "call",
                    "org.freedesktop.DBus",
                    "/org/freedesktop/DBus",
                    "org.freedesktop.DBus",
                    "NameHasOwner",
                    "s",
                    RESOLVE1,
                ]);
                let status = inherited.output().expect("run busctl").status;
                assert!(!status.success(), "the environment did not matter");
            }
            return;
        }
        let module = module_path!();
        let local = module.split_once("::").map_or(module, |(_, rest)| rest);
        let test = format!("{local}::nothing_from_the_environment_reaches_busctl");
        let status = Command::new(std::env::current_exe().expect("this program"))
            .args(["--exact", &test, "--nocapture", "--test-threads=1"])
            .env(ENV_CHILD, "1")
            .env(
                "DBUS_SYSTEM_BUS_ADDRESS",
                "unix:path=/nonexistent/ubc-vpn-test",
            )
            .env("SYSTEMD_LOG_LEVEL", "debug")
            .env("SYSTEMD_BUS_TIMEOUT", "1")
            .env("SYSTEMD_PAGER", "/nonexistent/ubc-vpn-test")
            .status()
            .expect("start the test's own process");
        assert!(status.success(), "the test's own process failed: {status}");
    }
}
