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
    /// Standard output is a pipe whose reader has gone, and that is no
    /// failure of this command.
    NobodyReads,
    /// Standard output could not be written for any other reason, such as
    /// a disk that is full.
    Unwritten(std::io::ErrorKind),
    /// What answered did not behave as the service does. The reading
    /// stops, so that nothing can make it go on for ever.
    Odd(&'static str),
    Failed(ClientError),
}

/// The most pages one `logs` reads, when it is not following. The service
/// holds 600 lines at most, and the fewest lines a page of them can hold
/// is about 40, so its whole log is some 15 pages. This leaves room for
/// lines written while it is read, and no more: whatever answers, one
/// command prints a few megabytes at most.
const MAX_PAGES: usize = 64;

/// The most of a name in the diagnostics that is printed, in bytes. The
/// service cuts them to this itself; a program in its place might not.
const MAX_NAME_BYTES: usize = 255;

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
    let complain = |err: &mut dyn Write, message: &str| say(err, message, FAILED);
    match done {
        Ok(()) | Err(Stopped::NobodyReads) => 0,
        Err(Stopped::Unwritten(why)) => {
            let message = format!("ubc-vpn: The output could not be written: {why}.");
            complain(err, &message)
        }
        Err(Stopped::Odd(why)) => {
            let message = format!("ubc-vpn: The service's log could not be read: {why}.");
            complain(err, &message)
        }
        Err(Stopped::Failed(error)) => failed(&error, err),
    }
}

/// Writes `text` to standard output at once. Only a pipe whose reader has
/// gone is passed over in silence.
fn put(out: &mut dyn Write, text: &str) -> Result<(), Stopped> {
    let written = out.write_all(text.as_bytes()).and_then(|()| out.flush());
    written.map_err(|error| match error.kind() {
        std::io::ErrorKind::BrokenPipe => Stopped::NobodyReads,
        other => Stopped::Unwritten(other),
    })
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
            ResponseBody::Diagnostics(report) => Ok(tidy(*report)),
            other => Err(ClientError::Lost(format!("unexpected answer: {other:?}"))),
        }
    });
    let shown = asked.and_then(|report| match json {
        true => Ok(encode(&report)?),
        false => Ok(format!("{}\n", summary(&report))),
    });
    let done = shown
        .map_err(Stopped::from)
        .and_then(|text| put(out, &text));
    ended(done, err)
}

/// The diagnostics with their names made fit to print, in either form:
/// with no character that misleads, and no longer than a name may be.
/// The rest of it is numbers, words from a closed list, and text the
/// protocol has already checked.
fn tidy(report: Diagnostics) -> Diagnostics {
    let name = |text: String| {
        let mut room = MAX_NAME_BYTES;
        let fits = |c: &char| {
            let fit = c.len_utf8() <= room;
            room = room.saturating_sub(c.len_utf8());
            fit
        };
        clean(&text).chars().take_while(fits).collect::<String>()
    };
    Diagnostics {
        service_version: name(report.service_version),
        os: name(report.os),
        arch: name(report.arch),
        gateway: report.gateway.map(name),
        ..report
    }
}

/// Where the reading has got to, and how each line is written.
struct Reading<'a> {
    json: bool,
    /// The run the lines read so far belong to, once a page has said.
    run: Option<u64>,
    /// The number of the last line written.
    last: u64,
    /// Whether it has been said that earlier lines are gone.
    said_lost: bool,
    out: &'a mut dyn Write,
    err: &'a mut dyn Write,
}

impl Reading<'_> {
    /// Asks for every line after the last one written and writes them,
    /// until a page comes back empty. Returns whether an event arrived
    /// meanwhile: there may then be more lines already.
    ///
    /// Nothing that answers can make this print a line twice, print lines
    /// out of order, or, with `most` pages given, go on without end: a
    /// page must hold only lines numbered above the last one written, in
    /// rising order, all of one run.
    fn catch_up(&mut self, client: &mut Client, most: Option<usize>) -> Result<bool, Stopped> {
        let (mut came, mut pages) = (false, 0);
        loop {
            if most.is_some_and(|most| pages >= most) {
                return Err(Stopped::Odd("it did not come to an end"));
            }
            pages += 1;
            let after = self.run.map(|run| LogCursor {
                run,
                seq: self.last,
            });
            let asked = RequestBody::Logs(LogsParams { after });
            // Events are not kept while a page is on its way: whatever they
            // told of is read by its number, here or in the next reading.
            let (answer, during) = client.request_past_events(asked)?;
            came |= during;
            let ResponseBody::Logs(page) = answer else {
                let odd = format!("unexpected answer: {answer:?}");
                return Err(ClientError::Lost(odd).into());
            };
            if self.run.is_some_and(|run| run != page.run) {
                return Err(Stopped::Odd(
                    "the service started again part-way; run the command again",
                ));
            }
            self.run = Some(page.run);
            if page.dropped && !self.said_lost {
                self.said_lost = true;
                let gone = "ubc-vpn: Some earlier lines are no longer kept by the service.";
                let _ = writeln!(self.err, "{gone}");
            }
            if page.lines.is_empty() {
                return Ok(came);
            }
            // The whole page is judged before any of it is written.
            let mut before = self.last;
            for line in &page.lines {
                if line.seq <= before {
                    return Err(Stopped::Odd("its lines were not in order"));
                }
                before = line.seq;
            }
            for line in &page.lines {
                self.write(line)?;
            }
        }
    }

    /// Writes one line, as the protocol has it or as text for a terminal,
    /// and remembers its number.
    fn write(&mut self, line: &LogLine) -> Result<(), Stopped> {
        let text = match self.json {
            true => encode(line).map_err(ClientError::from)?,
            false => format!("{}\n", shown(line)),
        };
        put(self.out, &text)?;
        self.last = line.seq;
        Ok(())
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
        run: None,
        last: 0,
        said_lost: false,
        out,
        err,
    };
    if !follow {
        return reading.catch_up(client, Some(MAX_PAGES)).map(drop);
    }
    // Watching first, then reading, misses nothing; what then arrives twice
    // is told by its number.
    let on = WatchLogsParams { on: true };
    client.request_past_events(RequestBody::WatchLogs(on))?;
    loop {
        // Read until a reading ends with no event having come meanwhile:
        // only then is every line the service has told of written. A busy
        // service keeps this going, and each round writes more lines.
        while reading.catch_up(client, None)? {}
        // Then each event as it comes, for as long as they come in order.
        loop {
            let Event::Log(line) = client.next_event(None)? else {
                continue;
            };
            match line.seq {
                seq if seq <= reading.last => {}
                seq if seq == reading.last + 1 => reading.write(&line)?,
                // The service dropped some events, as it does for a
                // client it has too many waiting for. The lines are still
                // in its log, and this one with them.
                _ => break,
            }
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

/// The diagnostics in words, a few lines for a person to read out. The
/// report is one [`tidy`] has made fit to print.
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
    lines.join("\n")
}

#[cfg(test)]
#[path = "logs_tests.rs"]
mod tests;
