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
//! ```
//!
//! A route line holds the destination, the interface's LUID, the next hop
//! and, last so that it may contain spaces, the interface's name.

use std::fs;
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use ubc_vpn_core::routes::Ipv4Net;

use crate::{Error, Result};

/// One route exactly as it was added.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Row {
    pub(super) dest: Ipv4Net,
    pub(super) luid: u64,
    pub(super) next_hop: Ipv4Addr,
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

pub(super) struct Journal {
    path: PathBuf,
}

fn corrupt() -> Error {
    Error::Failed("the route journal cannot be read".to_string())
}

impl Journal {
    pub(super) fn new(state_dir: &Path) -> Self {
        Self {
            path: state_dir.join("routes.journal"),
        }
    }

    /// The rows written in boot `now`. Rows from another boot are dropped,
    /// with nothing removed: the routes they stood for went with the
    /// restart, and an identical one there now is somebody else's.
    pub(super) fn rows(&self, now: Boot) -> Result<Vec<Row>> {
        let text = match fs::read_to_string(&self.path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        let (boot, rows) = parse(&text).ok_or_else(corrupt)?;
        Ok(if boot.same_as(&now) { rows } else { Vec::new() })
    }

    /// Replaces the journal with `rows`, for boot `now`. Written to a new
    /// file and moved into place, so a crash leaves the old or the new.
    pub(super) fn write(&self, now: Boot, rows: &[Row]) -> Result<()> {
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir)?;
        }
        let fresh = self.path.with_extension("journal.new");
        let mut file = fs::File::create(&fresh)?;
        file.write_all(render(now, rows).as_bytes())?;
        file.sync_all()?;
        drop(file);
        fs::rename(&fresh, &self.path)?;
        Ok(())
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
        let dest = parts.next()?.parse().ok()?;
        let luid = u64::from_str_radix(parts.next()?.strip_prefix("0x")?, 16).ok()?;
        let next_hop = parts.next()?.parse().ok()?;
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

    fn row(dest: &str, interface: &str) -> Row {
        Row {
            dest: dest.parse().unwrap(),
            luid: 0x4700_8000_0000_0000,
            next_hop: Ipv4Addr::new(192, 168, 0, 1),
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
        let journal = Journal::new(&dir);
        assert_eq!(journal.rows(BOOT), Ok(vec![]), "no file is no rows");
        let rows = [
            row("192.0.2.0/24", "Wi-Fi 2"),
            row("198.51.100.1/32", "ubc-vpn0"),
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
        let journal = Journal::new(&dir);
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
        ] {
            assert_eq!(parse(bad), None, "{bad:?}");
        }
        let dir = scratch("bad");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("routes.journal"), "boot 1\n").unwrap();
        assert!(matches!(
            Journal::new(&dir).rows(BOOT),
            Err(Error::Failed(_))
        ));
        fs::remove_dir_all(&dir).unwrap();
    }
}
