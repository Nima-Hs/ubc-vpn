//! Split DNS against the real DNS client, with DNS servers of the test's own
//! on a Wintun adapter. Like the routing tests they need an elevated process
//! and the Wintun library, and are skipped without them unless CI requires
//! them.

use std::net::{Ipv4Addr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use windows_sys::Win32::NetworkManagement::Dns::{
    DNS_QUERY_BYPASS_CACHE, DNS_QUERY_NO_HOSTS_FILE, DNS_TYPE_A, DnsFree, DnsFreeRecordList,
    DnsQuery_W,
};

use super::dns::{LOCAL, POLICY, Rule, WinDns, delete_rule_at, write_rule_at};
use super::routes_tests::{Cleanup, Outsider, ran, state_dir, turn, wintun};
use super::security::wide;
use crate::suite::{self, Foreign};
use crate::{Dns, Error, SplitDns, Verified};

/// The resolvers the shared suite names, which the test serves itself.
const SERVERS: [Ipv4Addr; 2] = [Ipv4Addr::new(192, 0, 2, 53), Ipv4Addr::new(192, 0, 2, 54)];

/// The names each server was asked for.
type Asked = Arc<Mutex<Vec<(Ipv4Addr, String)>>>;

/// A DNS server that answers every question "no such name" and notes it.
struct Server {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

/// The name in a DNS question, lower case and without the final dot.
fn question(packet: &[u8]) -> Option<String> {
    let mut labels = Vec::new();
    let mut at = 12;
    loop {
        let len = usize::from(*packet.get(at)?);
        if len == 0 {
            break;
        }
        labels
            .push(String::from_utf8_lossy(packet.get(at + 1..at + 1 + len)?).to_ascii_lowercase());
        at += 1 + len;
    }
    Some(labels.join("."))
}

impl Server {
    fn start(addr: Ipv4Addr, asked: Asked) -> Self {
        let socket = UdpSocket::bind((addr, 53)).expect("serve DNS on the test address");
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let thread = std::thread::spawn(move || {
            let mut packet = [0u8; 512];
            while !stopping.load(Ordering::SeqCst) {
                let Ok((len, from)) = socket.recv_from(&mut packet) else {
                    continue;
                };
                if len < 12 {
                    continue;
                }
                if let Some(name) = question(&packet[..len]) {
                    asked.lock().unwrap().push((addr, name));
                }
                // The same message back: a response, "no such name".
                let mut reply = packet[..len].to_vec();
                reply[2] |= 0x80;
                reply[3] = (reply[3] & 0xf0) | 0x03;
                let _ = socket.send_to(&reply, from);
            }
        });
        Self {
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Asks the DNS client to look `name` up, past its cache, and reports which
/// of the test's servers it asked. Every other server is the machine's own
/// business; the answer itself does not matter.
fn resolvers_for(asked: &Asked, name: &str) -> Vec<Ipv4Addr> {
    asked.lock().unwrap().clear();
    let wide_name = wide(name);
    let mut results = std::ptr::null_mut();
    let options = DNS_QUERY_BYPASS_CACHE | DNS_QUERY_NO_HOSTS_FILE;
    // SAFETY: the name is NUL-terminated, the result pointer is valid, and
    // the other optional arguments are null.
    let code = unsafe {
        DnsQuery_W(
            wide_name.as_ptr(),
            DNS_TYPE_A,
            options,
            std::ptr::null_mut(),
            &mut results,
            std::ptr::null_mut(),
        )
    };
    if code == 0 && !results.is_null() {
        // SAFETY: the list came from DnsQuery_W and is freed once.
        unsafe { DnsFree(results.cast(), DnsFreeRecordList) };
    }
    let asked = asked.lock().unwrap();
    let wanted = name.to_ascii_lowercase();
    let served = |server: &Ipv4Addr| {
        asked
            .iter()
            .any(|(at, name)| at == server && *name == wanted)
    };
    SERVERS.into_iter().filter(served).collect()
}

/// Removes, however a test ends, every rule a DNS test may have written.
struct DnsCleanup;

const FOREIGN: &str = "{0D1E2F3A-4B5C-4D6E-8F70-81929A0B0C0D}";

impl Drop for DnsCleanup {
    fn drop(&mut self) {
        let _ = WinDns.clear_split_dns();
        let _ = delete_rule_at(POLICY, FOREIGN);
        let _ = delete_rule_at(LOCAL, FOREIGN);
    }
}

// The shared rules, with the real DNS client: only the chosen domains and
// the names under them reach the chosen servers.
#[test]
fn passes_the_shared_dns_suite_with_servers_of_its_own() {
    let _turn = turn();
    let Some(wintun) = wintun() else { return };
    let tunnel = "ubc-vpn-dns0";
    let dir = state_dir("dns");
    let _adapter = wintun.adapter(tunnel);
    let _routes = Cleanup(vec![dir]);
    let _rules = DnsCleanup;
    for server in SERVERS {
        Outsider.add_address(tunnel, server);
    }
    // Windows takes a moment to make a new address usable.
    std::thread::sleep(Duration::from_secs(3));
    let asked = Asked::default();
    let _servers = SERVERS.map(|server| Server::start(server, asked.clone()));
    suite::check_dns(&WinDns, tunnel, &|name| resolvers_for(&asked, name));
    ran("dns");
}

fn chosen() -> SplitDns {
    SplitDns {
        resolvers: vec![SERVERS[0]],
        domains: vec!["suite.example".to_string()],
    }
}

// Security rule: with group policy rules in place Windows ignores ours, so
// setting them would only look applied. It is refused, and nothing written.
#[test]
fn refuses_split_dns_while_group_policy_rules_exist() {
    let _turn = turn();
    let Some(_wintun) = wintun() else { return };
    let _rules = DnsCleanup;
    let theirs = Rule {
        names: vec![".policy.example".to_string()],
        servers: "192.0.2.99".to_string(),
    };
    write_rule_at(POLICY, FOREIGN, &theirs).unwrap();
    assert_eq!(WinDns.set_split_dns("", &chosen()), Err(Error::Unsupported));
    assert_eq!(WinDns.split_dns_matches(&chosen()), Verified::No);
    delete_rule_at(POLICY, FOREIGN).unwrap();
    WinDns
        .set_split_dns("", &chosen())
        .expect("set once the policy is gone");
    assert_eq!(WinDns.split_dns_matches(&chosen()), Verified::Unobservable);
    ran("dns policy");
}

/// Whether `Get-DnsClientNrptPolicy -Effective` lists `namespace`.
fn effective_lists(namespace: &str) -> bool {
    let script = "Get-DnsClientNrptPolicy -Effective | ForEach-Object { $_.Namespace }";
    let done = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .expect("powershell");
    String::from_utf8_lossy(&done.stdout)
        .lines()
        .any(|line| line.trim() == namespace)
}

/// How long until `effective_lists(namespace)` is `wanted`, up to a limit.
fn until_effective(namespace: &str, wanted: bool) -> Option<Duration> {
    let started = std::time::Instant::now();
    while started.elapsed() < Duration::from_secs(30) {
        if effective_lists(namespace) == wanted {
            return Some(started.elapsed());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    None
}

// A record, not a rule: whether Windows' "effective" rule table follows our
// keys, and how fast. It decides whether reading that table could one day
// replace the Unobservable answer.
#[test]
fn records_whether_the_effective_rule_table_follows_our_keys() {
    let _turn = turn();
    let Some(_wintun) = wintun() else { return };
    let _rules = DnsCleanup;
    let namespace = ".suite.example";
    let before = effective_lists(namespace);
    WinDns.set_split_dns("", &chosen()).unwrap();
    let appeared = until_effective(namespace, true);
    WinDns.clear_split_dns().unwrap();
    let removed = until_effective(namespace, false);
    println!("NRPT-EFFECTIVE before={before} appeared={appeared:?} removed={removed:?}");
    ran("dns effective");
}

// Security rule: another program's rule for one of our domains could send
// its names elsewhere, so the setting is not reported in effect.
#[test]
fn another_rule_for_our_domain_is_not_in_effect() {
    let _turn = turn();
    let Some(_wintun) = wintun() else { return };
    let _rules = DnsCleanup;
    WinDns.set_split_dns("", &chosen()).unwrap();
    assert_eq!(WinDns.split_dns_matches(&chosen()), Verified::Unobservable);
    let theirs = Rule {
        names: vec![".suite.example".to_string()],
        servers: "192.0.2.99".to_string(),
    };
    write_rule_at(LOCAL, FOREIGN, &theirs).unwrap();
    assert_eq!(WinDns.split_dns_matches(&chosen()), Verified::No);
    // Clearing ours leaves theirs alone.
    WinDns.clear_split_dns().unwrap();
    let still = super::dns::read_rule_at(LOCAL, FOREIGN).unwrap();
    assert_eq!(still.map(|rule| rule.names), Some(theirs.names));
    ran("dns foreign");
}
