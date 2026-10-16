//! The record of routes this product added, kept in the state folder, which
//! only an administrator can write. Windows has nothing to mark a route with,
//! so this file is the only way a later process can tell ours from others.
//!
//! The file is text: a first line naming the boot it belongs to, then one
//! line per route.
//!
//! ```text
//! boot 1760300000 5212
//! route 192.0.2.0/24 0x47008000000000 0.0.0.0 ubc-vpn0
//! route ::/1 0x47008000000000 :: ubc-vpn0
//! ```
//!
//! A route line holds the destination, the interface's LUID, the next hop
//! and, last so that it may contain spaces, the interface's name. The
//! destination and the next hop are both IPv4 or both IPv6.
//!
//! IPv6 rows came with full mode. A version from before it cannot read a
//! journal that has one, and fails at start-up rather than guess; nothing
//! was released before then, so no installed version is that old.

use std::fmt;
use std::net::{IpAddr, Ipv6Addr};
#[cfg(test)]
use std::path::PathBuf;

use ubc_vpn_core::routes::Ipv4Net;

use crate::{Error, Mode, Paths, Result, StateDir};

/// A route's destination: an IPv4 network, or an IPv6 one (only the halves
/// of full mode, which block IPv6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Prefix {
    V4(Ipv4Net),
    V6(Ipv6Addr, u8),
}

impl Prefix {
    /// An IPv6 prefix, refused unless its address has no bits set past `len`.
    pub(super) fn v6(addr: Ipv6Addr, len: u8) -> Option<Self> {
        let host = u128::MAX.checked_shr(u32::from(len)).unwrap_or(0);
        (len <= 128 && u128::from(addr) & host == 0).then_some(Self::V6(addr, len))
    }

    /// Whether `ip` lies inside this prefix.
    pub(super) fn contains(&self, ip: IpAddr) -> bool {
        match (self, ip) {
            (Self::V4(net), IpAddr::V4(ip)) => net.contains_addr(ip),
            (Self::V6(addr, len), IpAddr::V6(ip)) => {
                let host = u128::MAX.checked_shr(u32::from(*len)).unwrap_or(0);
                u128::from(ip) & !host == u128::from(*addr)
            }
            _ => false,
        }
    }

    /// The prefix length.
    pub(super) fn len(&self) -> u8 {
        match self {
            Self::V4(net) => net.prefix_len(),
            Self::V6(_, len) => *len,
        }
    }
}

impl fmt::Display for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V4(net) => net.fmt(f),
            Self::V6(addr, len) => write!(f, "{addr}/{len}"),
        }
    }
}

impl std::str::FromStr for Prefix {
    type Err = ();

    fn from_str(text: &str) -> std::result::Result<Self, ()> {
        if !text.contains(':') {
            return text.parse().map(Self::V4).map_err(|_| ());
        }
        let (addr, len) = text.split_once('/').ok_or(())?;
        let len = len.parse().map_err(|_| ())?;
        Self::v6(addr.parse().map_err(|_| ())?, len).ok_or(())
    }
}

/// One route exactly as it was added.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Row {
    pub(super) dest: Prefix,
    pub(super) luid: u64,
    /// Of the same family as `dest`.
    pub(super) next_hop: IpAddr,
    pub(super) interface: String,
}

/// Which start of the machine a journal belongs to. Windows gives no boot
/// identifier, so it is worked out from the clock and the time since start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Boot {
    /// When the machine started, in seconds since 1970, as far as the clock
    /// can tell. It moves when the clock is set.
    pub(super) started: u64,
    /// Seconds since the machine started, when this was taken.
    pub(super) uptime: u64,
}

/// How far the start time worked out at two moments may differ for one
/// boot. The clock can be set between them; a restart of the machine takes
/// longer than this, and the uptime check below catches most that do not.
const SAME_BOOT_SLACK: u64 = 120;

impl Boot {
    /// Whether `now` can be the same boot as `self`, which was taken earlier.
    /// Time since start only grows within a boot, so a smaller value means a
    /// restart, whatever the clock says.
    pub(super) fn same_as(&self, now: &Boot) -> bool {
        now.uptime >= self.uptime && self.started.abs_diff(now.started) <= SAME_BOOT_SLACK
    }
}

/// Where the journal is kept: the service's checked state folder, opened
/// when the journal is first used, so that a process that never touches a
/// route (such as the command-line client) never opens it.
pub(super) enum Store {
    Checked(Mode, Paths),
    #[cfg(test)]
    Unchecked(PathBuf),
}

pub(super) struct Journal {
    store: Store,
    opened: Option<StateDir>,
}

const FILE: &str = "routes.journal";

fn corrupt() -> Error {
    Error::Failed("the route journal cannot be read".to_string())
}

impl Journal {
    pub(super) fn new(store: Store) -> Self {
        Self {
            store,
            opened: None,
        }
    }

    /// The state folder. `StateDir` checks it before every read and write.
    fn state(&mut self) -> Result<&StateDir> {
        if self.opened.is_none() {
            self.opened = Some(match &self.store {
                Store::Checked(mode, paths) => StateDir::open(*mode, paths)?,
                #[cfg(test)]
                Store::Unchecked(dir) => StateDir::unchecked(dir)?,
            });
        }
        Ok(self.opened.as_ref().expect("opened just now"))
    }

    /// The rows written in boot `now`. Rows from another boot are dropped,
    /// with nothing removed: the routes they stood for went with the
    /// restart, and an identical one there now is somebody else's.
    pub(super) fn rows(&mut self, now: Boot) -> Result<Vec<Row>> {
        let Some(bytes) = self.state()?.read(FILE)? else {
            return Ok(Vec::new());
        };
        let text = String::from_utf8(bytes).map_err(|_| corrupt())?;
        let (boot, rows) = parse(&text).ok_or_else(corrupt)?;
        Ok(if boot.same_as(&now) { rows } else { Vec::new() })
    }

    /// Replaces the journal with `rows`, for boot `now`. A crash leaves the
    /// old journal or the new one.
    pub(super) fn write(&mut self, now: Boot, rows: &[Row]) -> Result<()> {
        let text = render(now, rows);
        self.state()?.write(FILE, text.as_bytes())
    }
}

fn render(boot: Boot, rows: &[Row]) -> String {
    let mut text = format!("boot {} {}\n", boot.started, boot.uptime);
    for row in rows {
        let Row {
            dest,
            luid,
            next_hop,
            interface,
        } = row;
        text += &format!("route {dest} {luid:#x} {next_hop} {interface}\n");
    }
    text
}

fn parse(text: &str) -> Option<(Boot, Vec<Row>)> {
    let mut lines = text.lines();
    let mut boot = lines.next()?.strip_prefix("boot ")?.split(' ');
    let started = boot.next()?.parse().ok()?;
    let uptime = boot.next()?.parse().ok()?;
    if boot.next().is_some() {
        return None;
    }
    let rows = lines.map(|line| {
        let mut parts = line.strip_prefix("route ")?.splitn(4, ' ');
        let dest: Prefix = parts.next()?.parse().ok()?;
        let luid = u64::from_str_radix(parts.next()?.strip_prefix("0x")?, 16).ok()?;
        let next_hop: IpAddr = parts.next()?.parse().ok()?;
        if matches!(dest, Prefix::V4(_)) != next_hop.is_ipv4() {
            return None;
        }
        let interface = parts.next().filter(|name| !name.is_empty())?.to_string();
        Some(Row {
            dest,
            luid,
            next_hop,
            interface,
        })
    });
    Some((Boot { started, uptime }, rows.collect::<Option<_>>()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn row(dest: &str, interface: &str) -> Row {
        Row {
            dest: dest.parse().unwrap(),
            luid: 0x4700_8000_0000_0000,
            next_hop: if dest.contains(':') {
                IpAddr::from(Ipv6Addr::UNSPECIFIED)
            } else {
                IpAddr::from([192, 168, 0, 1])
            },
            interface: interface.to_string(),
        }
    }

    const BOOT: Boot = Boot {
        started: 1_760_300_000,
        uptime: 5_000,
    };

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("ubc-vpn-journal-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn round_trips_rows_with_spaces_in_the_name() {
        let dir = scratch("round");
        let mut journal = Journal::new(Store::Unchecked(dir.clone()));
        assert_eq!(journal.rows(BOOT), Ok(vec![]), "no file is no rows");
        let rows = [
            row("192.0.2.0/24", "Wi-Fi 2"),
            row("198.51.100.1/32", "ubc-vpn0"),
            row("::/1", "ubc-vpn0"),
            row("8000::/1", "ubc-vpn0"),
        ];
        journal.write(BOOT, &rows).unwrap();
        assert_eq!(journal.rows(BOOT), Ok(rows.to_vec()));
        journal.write(BOOT, &rows[1..]).unwrap();
        assert_eq!(journal.rows(BOOT), Ok(rows[1..].to_vec()));
        fs::remove_dir_all(&dir).unwrap();
    }

    // Security rule: routes do not outlive a restart, so after one the rows
    // are dropped and nothing is removed for them: an identical route found
    // then is somebody else's.
    #[test]
    fn rows_from_another_boot_are_dropped() {
        let dir = scratch("boot");
        let mut journal = Journal::new(Store::Unchecked(dir.clone()));
        journal
            .write(BOOT, &[row("192.0.2.0/24", "ubc-vpn0")])
            .unwrap();
        let later = Boot {
            uptime: BOOT.uptime + 3_600,
            started: BOOT.started + 30,
        };
        assert_eq!(journal.rows(later).unwrap().len(), 1, "the same boot");
        let restarted = Boot {
            started: BOOT.started + 7_200,
            uptime: 100,
        };
        assert_eq!(journal.rows(restarted), Ok(vec![]));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn tells_boots_apart() {
        let same = |started: u64, uptime: u64| BOOT.same_as(&Boot { started, uptime });
        assert!(same(BOOT.started, BOOT.uptime));
        assert!(same(BOOT.started + SAME_BOOT_SLACK, BOOT.uptime + 10));
        assert!(same(BOOT.started - SAME_BOOT_SLACK, BOOT.uptime + 10));
        // The clock moved further than a setting does: another start.
        assert!(!same(BOOT.started + SAME_BOOT_SLACK + 1, BOOT.uptime + 10));
        // Up for less time than when written: a restart, whatever the clock.
        assert!(!same(BOOT.started, BOOT.uptime - 1));
    }

    // A journal that cannot be read is an error, never "nothing is ours":
    // that would leave our routes behind for good.
    #[test]
    fn refuses_a_journal_it_cannot_read() {
        for bad in [
            "",
            "boot x 1\n",
            "boot 1 2 3\n",
            "boot 1 2\nroute 10.0.0.0/8 0x1 0.0.0.0\n",
            "boot 1 2\nroute 10.0.0.1/8 0x1 0.0.0.0 a\n",
            "boot 1 2\nroute 10.0.0.0/8 1 0.0.0.0 a\n",
            "boot 1 2\nsomething else\n",
            // A destination and a next hop of different families.
            "boot 1 2\nroute ::/1 0x1 0.0.0.0 a\n",
            "boot 1 2\nroute 0.0.0.0/1 0x1 :: a\n",
            // An IPv6 network with bits past its length, or too long.
            "boot 1 2\nroute 8000::/0 0x1 :: a\n",
            "boot 1 2\nroute ::/129 0x1 :: a\n",
        ] {
            assert_eq!(parse(bad), None, "{bad:?}");
        }
        let dir = scratch("bad");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("routes.journal"), "boot 1\n").unwrap();
        assert!(matches!(
            Journal::new(Store::Unchecked(dir.clone())).rows(BOOT),
            Err(Error::Failed(_))
        ));
        fs::remove_dir_all(&dir).unwrap();
    }
}
