//! Runs this test program again, as a workflow runs tests: `--nocapture`, its
//! standard output and standard error in one pipe. Its tests print part lines
//! on both from many threads while the harness prints its own, and every line
//! they say must come out whole, exactly once.

use std::collections::HashMap;
use std::io::Read;
use std::process::{Command, Stdio};

use ubc_vpn_test_lines::whole_line;

/// Set in the program this test starts, whose tests then do the printing.
const PRINTING: &str = "UBC_VPN_TEST_LINES_PRINTING";
const ROUNDS: usize = 200;
const TESTS: usize = 12;
/// What it prints is fixed and far less. The limit is for a mistake here.
const MOST_OUTPUT: u64 = 32 * 1024 * 1024;

fn print(test: usize) {
    if std::env::var_os(PRINTING).is_none() {
        return;
    }
    for round in 0..ROUNDS {
        // What the harness does, on both streams. The part line on standard
        // output is in the same buffer the line goes to, so a line that
        // does not end it first comes out mid-line every time.
        print!("test {test} ... ");
        eprint!("{test} on standard error ... ");
        whole_line!("RAN: {test} {round}");
    }
}

macro_rules! printers {
    ($($name:ident $test:literal)*) => {
        $(#[test] fn $name() { print($test) })*
    };
}
printers! {
    printer_0 0 printer_1 1 printer_2 2 printer_3 3 printer_4 4 printer_5 5
    printer_6 6 printer_7 7 printer_8 8 printer_9 9 printer_10 10 printer_11 11
}

/// Every line of `log` that starts with `RAN:` or holds it, and how often.
fn said(log: &str) -> HashMap<&str, usize> {
    let mut lines = HashMap::new();
    for line in log.lines().map(|line| line.trim_end_matches('\r')) {
        if line.contains("RAN:") {
            *lines.entry(line).or_insert(0) += 1;
        }
    }
    lines
}

#[test]
fn every_line_is_whole_among_part_lines_from_many_threads() {
    if std::env::var_os(PRINTING).is_some() {
        return;
    }
    let (mut reader, writer) = std::io::pipe().expect("a pipe");
    let mut child = Command::new(std::env::current_exe().expect("this program"))
        .args(["--nocapture", "--test-threads=8", "printer_"])
        .env(PRINTING, "1")
        .stdin(Stdio::null())
        .stdout(writer.try_clone().expect("a copy of the pipe"))
        .stderr(writer)
        .spawn()
        .expect("start the program again");
    let mut log = Vec::new();
    (&mut reader)
        .take(MOST_OUTPUT)
        .read_to_end(&mut log)
        .expect("read its output");
    if log.len() as u64 == MOST_OUTPUT {
        let _ = child.kill();
        let _ = child.wait();
        panic!("it printed far more than it should");
    }
    let status = child.wait().expect("wait for it");
    assert!(status.success(), "its tests failed: {status}");

    let log = String::from_utf8_lossy(&log);
    let lines = said(&log);
    let mut wrong: Vec<_> = lines
        .iter()
        .filter(|(line, count)| {
            let name = line.strip_prefix("RAN: ").unwrap_or_default();
            let known = name.split_once(' ').is_some_and(|(test, round)| {
                test.parse().is_ok_and(|test: usize| test < TESTS)
                    && round.parse().is_ok_and(|round: usize| round < ROUNDS)
            });
            !known || **count != 1
        })
        .collect();
    wrong.sort();
    assert_eq!(
        wrong,
        Vec::<(&&str, &usize)>::new(),
        "not whole, or not once"
    );
    assert_eq!(lines.len(), TESTS * ROUNDS, "every line was said");
}

/// The check's other half: a line that holds the words but is not all of them
/// is not one of ours, so a line said mid-line is seen as wrong above.
#[test]
fn a_line_said_mid_line_is_seen() {
    let lines = said("test x ... RAN: 0 0\nok\n");
    assert_eq!(lines.get("test x ... RAN: 0 0"), Some(&1));
    assert_eq!(lines.get("RAN: 0 0"), None);
}
