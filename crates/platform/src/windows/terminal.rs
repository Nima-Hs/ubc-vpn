//! The Windows half of `terminal`: the terminal is the console, opened as
//! `CONIN$` and `CONOUT$`, and its mode is the console input mode.

use std::ptr::{null, null_mut};

use ubc_vpn_core::redact::Secret;
use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::Console::{
    ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT, ENABLE_VIRTUAL_TERMINAL_INPUT,
    GetConsoleMode, ReadConsoleW, SetConsoleMode, WriteConsoleW,
};

use super::security::{Handle, last_error, os_error, wide};
use crate::terminal::read_keys;
use crate::{Error, Result};

/// Opens the console's input or output, whatever the program's standard
/// handles are. A program without a console cannot.
fn console(name: &str) -> Result<Handle> {
    let (name, share) = (wide(name), FILE_SHARE_READ | FILE_SHARE_WRITE);
    let access = GENERIC_READ | GENERIC_WRITE;
    // SAFETY: `name` is NUL-terminated and outlives the call; the other
    // pointers may be null.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            access,
            share,
            null(),
            OPEN_EXISTING,
            0,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(Error::NotATerminal);
    }
    Ok(Handle(handle))
}

pub(crate) fn read_hidden_line(prompt: &str) -> Result<Secret> {
    let (input, output) = (console("CONIN$")?, console("CONOUT$")?);
    read_hidden_from(input.0, output.0, prompt)
}

/// Puts the console's mode back when dropped, so on every way out.
struct Restore(HANDLE, u32);

impl Drop for Restore {
    fn drop(&mut self) {
        // SAFETY: the handle is open for as long as the caller's borrow.
        unsafe { SetConsoleMode(self.0, self.1) };
    }
}

fn write(output: HANDLE, text: &str) -> Result<()> {
    let text: Vec<u16> = text.encode_utf16().collect();
    let mut written = 0;
    // SAFETY: the pointer and length describe `text`, which outlives the
    // call, and `written` is a live integer.
    let done = unsafe {
        WriteConsoleW(
            output,
            text.as_ptr(),
            text.len() as u32,
            &mut written,
            null(),
        )
    };
    match done {
        0 => Err(os_error(last_error())),
        _ => Ok(()),
    }
}

/// Reads one UTF-16 unit, or `None` when the console is gone.
fn unit(input: HANDLE) -> Result<Option<u16>> {
    let (mut unit, mut read) = (0u16, 0);
    // SAFETY: the buffer is one live UTF-16 unit and one unit is asked for;
    // `read` is a live integer.
    let done = unsafe { ReadConsoleW(input, (&raw mut unit).cast(), 1, &mut read, null()) };
    match (done, read) {
        (0, _) => Err(os_error(last_error())),
        (_, 0) => Ok(None),
        _ => Ok(Some(unit)),
    }
}

pub(crate) fn read_hidden_from(input: HANDLE, output: HANDLE, prompt: &str) -> Result<Secret> {
    let mut before = 0;
    // Anything that has no console mode is not a console.
    // SAFETY: `before` is a live integer; a handle of another kind fails.
    if unsafe { GetConsoleMode(input, &mut before) } == 0 {
        return Err(Error::NotATerminal);
    }
    // Security rule: what is typed is not shown. Nor is it edited or turned
    // into a Ctrl-C event by the console: every key comes here, one at a
    // time, so that Ctrl-C finds the program alive to put the mode back.
    let off = ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT;
    let quiet = before & !(off | ENABLE_VIRTUAL_TERMINAL_INPUT);
    // SAFETY: a plain call on a handle that was just shown to be a console.
    if unsafe { SetConsoleMode(input, quiet) } == 0 {
        return Err(os_error(last_error()));
    }
    let _restore = Restore(input, before);

    // The bytes of the character being handed on, as UTF-8.
    let (mut bytes, mut at, mut len) = ([0u8; 4], 0, 0);
    let typed = write(output, prompt).and_then(|()| {
        read_keys(|| {
            while at == len {
                let Some(first) = unit(input)? else {
                    return Ok(None);
                };
                // A character outside the basic plane comes as two units.
                let second = match first {
                    0xd800..=0xdbff => unit(input)?,
                    _ => None,
                };
                let decoded = char::decode_utf16([first].into_iter().chain(second)).next();
                let Some(Ok(character)) = decoded else {
                    continue;
                };
                (at, len) = (0, character.encode_utf8(&mut bytes).len());
            }
            at += 1;
            Ok(Some(bytes[at - 1]))
        })
    });
    bytes.fill(0);
    // The newline that Enter did not show.
    let _ = write(output, "\r\n");
    typed
}

#[cfg(test)]
mod tests {
    use std::os::windows::io::AsRawHandle;
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    use std::time::{Duration, Instant};

    use windows_sys::Win32::System::Console::{
        COORD, INPUT_RECORD, INPUT_RECORD_0, KEY_EVENT, KEY_EVENT_RECORD, KEY_EVENT_RECORD_0,
        ReadConsoleOutputCharacterW, WriteConsoleInputW,
    };
    use windows_sys::Win32::System::Threading::{CREATE_NEW_CONSOLE, DETACHED_PROCESS};

    use super::*;

    const CHILD: &str = "UBC_VPN_TERMINAL_CHILD";

    // A file is not a console, and nothing is written to it.
    #[test]
    fn a_handle_that_is_no_console_is_refused() {
        let file = std::fs::File::open("NUL").expect("the null device");
        let handle = file.as_raw_handle();
        let read = read_hidden_from(handle, handle, "Password: ");
        assert_eq!(read.map(|_| ()), Err(Error::NotATerminal));
    }

    /// Runs `child_with_or_without_a_console` in a process of its own, made
    /// with `flags`, and returns what it printed if it succeeded.
    fn child(kind: &str, flags: u32) -> String {
        let mut child = Command::new(std::env::current_exe().expect("this program"));
        let (_, tests) = module_path!().split_once("::").expect("a module path");
        let name = format!("{tests}::child_with_or_without_a_console");
        child.args(["--exact", name.as_str()]);
        child.args(["--nocapture", "--test-threads=1"]);
        let output = child.env(CHILD, kind).creation_flags(flags).output();
        let output = output.expect("run the child");
        let printed = String::from_utf8_lossy(&output.stdout).into_owned();
        let failed = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{kind}: {printed}\n{failed}");
        printed
    }

    // A program with no console at all, as a service is.
    #[test]
    fn without_a_console_the_call_says_so() {
        assert!(child("none", DETACHED_PROCESS).contains("CHILD RAN: none"));
    }

    // Security rule: what is typed comes back and is never shown, and the
    // console is as it was afterwards. The child gets a console of its own
    // and types into that one; nobody's real console is touched. It opens a
    // window, so it only runs under CI.
    #[test]
    fn a_typed_line_is_returned_and_never_shown() {
        if std::env::var_os("GITHUB_ACTIONS").is_none() {
            println!("SKIPPED: console (it would open a window; CI runs it)");
            return;
        }
        assert!(child("console", CREATE_NEW_CONSOLE).contains("CHILD RAN: console"));
        println!("RAN: console");
    }

    fn mode(input: &Handle) -> u32 {
        let mut mode = 0;
        // SAFETY: `mode` is a live integer and the handle is open.
        assert_ne!(unsafe { GetConsoleMode(input.0, &mut mode) }, 0);
        mode
    }

    /// Types `keys` into this process's own console once it stops echoing,
    /// and returns the mode the console was in by then.
    fn type_when_quiet(keys: &str) -> u32 {
        let input = console("CONIN$").expect("the console");
        let started = Instant::now();
        while mode(&input) & ENABLE_ECHO_INPUT != 0 && started.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(10));
        }
        let quiet = mode(&input);
        for unit in keys.encode_utf16() {
            let key = KEY_EVENT_RECORD {
                bKeyDown: 1,
                wRepeatCount: 1,
                wVirtualKeyCode: 0,
                wVirtualScanCode: 0,
                uChar: KEY_EVENT_RECORD_0 { UnicodeChar: unit },
                dwControlKeyState: 0,
            };
            let record = INPUT_RECORD {
                EventType: KEY_EVENT as u16,
                Event: INPUT_RECORD_0 { KeyEvent: key },
            };
            let mut written = 0;
            // SAFETY: one live record is passed with the count one.
            let done = unsafe { WriteConsoleInputW(input.0, &record, 1, &mut written) };
            assert_ne!(done, 0, "type a key");
        }
        quiet
    }

    // Not a test of its own: the two tests above run it in a new process.
    #[test]
    fn child_with_or_without_a_console() {
        let Some(kind) = std::env::var_os(CHILD) else {
            return;
        };
        if kind == "none" {
            let read = read_hidden_line("Password: ");
            assert_eq!(read.map(|_| ()), Err(Error::NotATerminal));
            println!("CHILD RAN: none");
            return;
        }
        let input = console("CONIN$").expect("the new console");
        let before = mode(&input);
        assert_ne!(before & ENABLE_ECHO_INPUT, 0, "a new console echoes");
        let typist = std::thread::spawn(|| type_when_quiet("s3cret fakx\u{8}e\r"));
        let read = read_hidden_line("Password: ").expect("read");
        let quiet = typist.join().expect("the typist");
        assert_eq!(read.expose(), "s3cret fake");
        assert_eq!(mode(&input), before, "the mode was not put back");
        // While it read, the console neither edited the line nor stood
        // ready to turn Ctrl-C into an event that ends the program.
        let cooked = ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT;
        assert_eq!(quiet & cooked, 0, "the console's mode while reading");

        // Ctrl-C comes as a key: the call gives up and the mode is put back.
        let typist = std::thread::spawn(|| type_when_quiet("half\u{3}"));
        let read = read_hidden_line("").map(|_| ());
        typist.join().expect("the typist");
        assert_eq!(read, Err(Error::Closed));
        assert_eq!(mode(&input), before, "the mode after Ctrl-C");

        // The first line of the screen: the prompt, and nothing typed.
        let output = console("CONOUT$").expect("the screen");
        let (mut line, mut read) = ([0u16; 40], 0);
        let origin = COORD { X: 0, Y: 0 };
        // SAFETY: the pointer and length describe `line`; `read` is live.
        let done = unsafe {
            ReadConsoleOutputCharacterW(output.0, line.as_mut_ptr(), 40, origin, &mut read)
        };
        assert_ne!(done, 0, "read the screen");
        let line = String::from_utf16_lossy(&line[..read as usize]);
        assert_eq!(line.trim_end(), "Password:", "the screen");
        println!("CHILD RAN: console");
    }
}
