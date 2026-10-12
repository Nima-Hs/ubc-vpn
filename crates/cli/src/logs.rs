//! `ubc-vpn logs` and `ubc-vpn diagnostics`: what the service has logged and
//! what it says about itself, for a person at a terminal.
//!
//! Both only read. Neither makes the user the owner of a service nobody
//! owns yet: a service that has never been used has nothing to say, and
//! looking at it should not decide who controls it.
//!
//! With `--json` each prints the protocol's own shapes, one to a line: a
//! `LogLine` for each line of the log, and one `Diagnostics`. Without it the
//! text comes from the service, so it goes through [`clean`] like any text
//! that is not this program's own before it reaches the terminal.

use std::io::Write;

use ubc_vpn_core::protocol::{
    ClientKind, Diagnostics, ErrorCode, Event, LogCursor, LogLine, LogsParams, RequestBody,
    ResponseBody, WatchLogsParams, encode,
};
use ubc_vpn_platform::Platform;

use crate::client::{Client, ClientError};
use crate::{FAILED, clean, explain, say};

/// How `logs` was asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    /// One `LogLine` of JSON to a line, not text.
    pub json: bool,
    /// Go on printing lines as the service writes them.
    pub follow: bool,
}

impl Options {
    /// The options after `logs`, if they are ones this command has.
    pub fn parse(args: &[&str]) -> Option<Self> {
        let mut options = Self {
            json: false,
            follow: false,
        };
        for arg in args {
            let flag = match *arg {
                "--json" => &mut options.json,
                "--follow" => &mut options.follow,
                _ => return None,
            };
            // Said twice, it is not a command this program has.
            if std::mem::replace(flag, true) {
                return None;
            }
        }
        Some(options)
    }
}

type Chosen<'a> = &'a dyn Fn() -> ubc_vpn_platform::Result<Platform>;

/// Why a command stopped before its end.
enum Stopped {
    /// Standard output is closed: whoever was reading has gone, and that is
    /// no failure of this command.
    NobodyReads,
    Failed(ClientError),
}

impl From<ClientError> for Stopped {
    fn from(error: ClientError) -> Self {
        Self::Failed(error)
    }
}

/// Connects to the service without claiming it.
fn service(platform: Chosen) -> Result<Client, ClientError> {
    let platform = platform()?;
    let name = &platform.paths.channel_name;
    Client::connect(&*platform.transport, name, ClientKind::Cli)
}

/// The sentence and exit status for a failure. A service nobody owns yet
/// gets a sentence of its own: the service's says to claim it, which is not
/// something a person at a terminal can do by that name.
fn failed(error: &ClientError, err: &mut dyn Write) -> u8 {
    let unclaimed =
        matches!(error, ClientError::Refused(refusal) if refusal.code == ErrorCode::NotClaimed);
    let (code, message) = match unclaimed {
        true => {
            let message = "Nobody has used UBC VPN on this computer yet, so there is nothing \
                           to show. Run `ubc-vpn status` first.";
            (FAILED, message.to_string())
        }
        false => explain(error),
    };
    say(err, &format!("ubc-vpn: {message}"), code)
}

fn ended(done: Result<(), Stopped>, err: &mut dyn Write) -> u8 {
    match done {
        Ok(()) | Err(Stopped::NobodyReads) => 0,
        Err(Stopped::Failed(error)) => failed(&error, err),
    }
}

/// Runs `logs` and returns the exit status.
pub fn logs(options: Options, platform: Chosen, out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    let done = service(platform)
        .map_err(Stopped::from)
        .and_then(|mut client| read(&mut client, options, out, err));
    ended(done, err)
}

/// Runs `diagnostics` and returns the exit status.
pub fn diagnostics(json: bool, platform: Chosen, out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    let asked = service(platform).and_then(|mut client| {
        match client.request(RequestBody::Diagnostics)? {
            ResponseBody::Diagnostics(report) => Ok(*report),
            other => Err(ClientError::Lost(format!("unexpected answer: {other:?}"))),
        }
    });
    let shown = asked.and_then(|report| match json {
        true => Ok(encode(&report)?.trim_end().to_string()),
        false => Ok(summary(&report)),
    });
    match shown {
        Ok(text) => say(out, &text, 0),
        Err(error) => failed(&error, err),
    }
}

/// Where the reading has got to, and how each line is written.
struct Reading<'a> {
    json: bool,
    /// The run the lines read so far belong to, and the last of them.
    at: Option<LogCursor>,
    out: &'a mut dyn Write,
    err: &'a mut dyn Write,
}

impl Reading<'_> {
    /// Asks for every line after the last one read and writes them.
    fn catch_up(&mut self, client: &mut Client) -> Result<(), Stopped> {
        loop {
            let after = self.at;
            let page = match client.request(RequestBody::Logs(LogsParams { after }))? {
                ResponseBody::Logs(page) => page,
                other => {
                    let odd = format!("unexpected answer: {other:?}");
                    return Err(ClientError::Lost(odd).into());
                }
            };
            if page.dropped {
                let gone = "ubc-vpn: Some earlier lines are no longer kept by the service.";
                let _ = writeln!(self.err, "{gone}");
            }
            let (run, seq) = (page.run, page.next);
            self.at = Some(LogCursor { run, seq });
            if page.lines.is_empty() {
                return Ok(());
            }
            for line in &page.lines {
                self.write(line)?;
            }
        }
    }

    /// Writes one line: as the protocol has it, or as text for a terminal.
    fn write(&mut self, line: &LogLine) -> Result<(), Stopped> {
        let text = match self.json {
            true => encode(line).map_err(ClientError::from)?,
            false => format!("{}\n", shown(line)),
        };
        let written = self.out.write_all(text.as_bytes());
        let written = written.and_then(|()| self.out.flush());
        written.map_err(|_| Stopped::NobodyReads)
    }
}

/// Writes the log, and with `follow` goes on writing lines as they come,
/// until the service goes away or nobody reads any more.
fn read(
    client: &mut Client,
    options: Options,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<(), Stopped> {
    let Options { json, follow } = options;
    let mut reading = Reading {
        json,
        at: None,
        out,
        err,
    };
    if !follow {
        return reading.catch_up(client);
    }
    // Watching first, then reading, misses nothing; what then arrives twice
    // is told by its number.
    let on = WatchLogsParams { on: true };
    client.request(RequestBody::WatchLogs(on))?;
    reading.catch_up(client)?;
    loop {
        let Event::Log(line) = client.next_event(None)? else {
            continue;
        };
        let last = reading.at.map_or(0, |at| at.seq);
        match line.seq {
            seq if seq <= last => {}
            // The next line, as expected.
            seq if seq == last + 1 => {
                reading.write(&line)?;
                reading.at = reading.at.map(|at| LogCursor { seq, ..at });
            }
            // The service dropped some for being asked too slowly. They
            // are still in its log, and this one with them.
            _ => reading.catch_up(client)?,
        }
    }
}

/// One line of the log for a terminal.
fn shown(line: &LogLine) -> String {
    let name = |value: serde_json::Result<String>| {
        let quoted = value.unwrap_or_default();
        quoted.trim_matches('"').to_string()
    };
    let level = name(serde_json::to_string(&line.level));
    let source = name(serde_json::to_string(&line.source));
    let text = clean(line.text.as_str());
    format!("{}  {level:<5}  {source:<7}  {text}", time(line.at_unix_ms))
}

/// A time in milliseconds since the start of 1970 as a date and a time of
/// day, in UTC: `2026-10-12 08:41:07Z`.
fn time(at_unix_ms: u64) -> String {
    let seconds = at_unix_ms / 1000;
    let (days, of_day) = (seconds / 86_400, seconds % 86_400);
    // The calendar date of a day number, by the usual reckoning in whole
    // 400-year eras that start on 1 March.
    let shifted = days + 719_468;
    let (era, day_of_era) = (shifted / 146_097, shifted % 146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = match shifted_month {
        0..=9 => shifted_month + 3,
        _ => shifted_month - 9,
    };
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    let (hour, minute, second) = (of_day / 3600, of_day % 3600 / 60, of_day % 60);
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}Z")
}

/// A number of things in words: `1 pin`, `2 pins`.
fn count(many: u32, one: &str) -> String {
    match many {
        1 => format!("1 {one}"),
        _ => format!("{many} {one}s"),
    }
}

/// The diagnostics in words, a few lines for a person to read out.
fn summary(report: &Diagnostics) -> String {
    let name = |value: serde_json::Result<String>| {
        let quoted = value.unwrap_or_default();
        quoted.trim_matches('"').replace('_', " ")
    };
    let (hours, minutes) = (report.uptime_s / 3600, report.uptime_s % 3600 / 60);
    let system = match &report.os_version {
        Some(version) => format!("{} {}", report.os, version.as_str()),
        None => report.os.clone(),
    };
    let carried = match (report.subnets, report.dns_domains) {
        (0, 0) => String::new(),
        (subnets, domains) => format!(
            ", {} and {}",
            count(subnets, "subnet"),
            count(domains, "DNS domain")
        ),
    };
    let last_error = match &report.last_error {
        Some(last) => {
            let code = name(serde_json::to_string(&last.code));
            format!("{} ({code})", last.message.as_str())
        }
        None => "none".to_string(),
    };
    let policy = match (&report.gateway, report.policy_readable) {
        (Some(gateway), true) => format!("gateway {gateway}, {}", count(report.pins, "pin")),
        _ => "missing or not valid".to_string(),
    };
    let owner = match report.owner_claimed {
        true => "claimed",
        false => "nobody yet",
    };
    let lines = [
        format!(
            "Service: {} (protocol {}), running for {hours} h {minutes} min",
            report.service_version, report.protocol_version
        ),
        format!("System: {system} on {}", report.arch),
        format!(
            "State: {}{carried}",
            name(serde_json::to_string(&report.state))
        ),
        format!("Last failure: {last_error}"),
        format!("Policy: {policy}"),
        format!("Owner: {owner}"),
    ];
    clean_lines(&lines)
}

/// Each line cleaned for the terminal, and the lines joined.
fn clean_lines(lines: &[String]) -> String {
    let cleaned: Vec<String> = lines.iter().map(|line| clean(line)).collect();
    cleaned.join("\n")
}

#[cfg(test)]
#[path = "logs_tests.rs"]
mod tests;
