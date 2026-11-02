//! The channel between the service and its clients: the OS transport, and
//! the line rules every connection keeps.

use std::fmt;
use std::str::FromStr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use ubc_vpn_core::protocol::MAX_LINE_BYTES;

use crate::{Error, Result, lock};
#[cfg(doc)]
use crate::{Mode, Platform};

/// An OS user, as text in one canonical form: the decimal user ID with no
/// leading zeros on macOS and Linux (`1001`), the upper-case SID string on
/// Windows (`S-1-5-21-…`).
///
/// Values are compared as text. Implementations only ever produce the
/// canonical form, so the same user always compares equal; any other spelling
/// of the same user compares unequal, which refuses rather than admits.
///
/// A `UserId` must only come from [`Listener::accept`] or from the service's
/// own state file. Never build one from anything a client sent.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UserId(String);

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for UserId {
    type Err = Error;

    /// Reads back a value written with `to_string`. Accepts printable ASCII
    /// only, with no spaces, so no two values can look alike.
    fn from_str(s: &str) -> Result<Self> {
        if s.is_empty() || !s.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(Error::Failed("not a user identity".to_string()));
        }
        Ok(Self(s.to_string()))
    }
}

/// The channel's transport: a named pipe on Windows, a Unix socket elsewhere.
///
/// A transport is built for one [`Mode`] by [`Platform::native`], which is how
/// it knows what [`Transport::connect`] has to verify.
pub trait Transport: Send + Sync {
    /// Claims `name` and starts listening. The claim is exclusive: it fails
    /// with [`Error::AlreadyExists`] while any other listener holds the name.
    /// Only programs on this machine can connect; remote clients are refused.
    fn listen(&self, name: &str) -> Result<Box<dyn Listener>>;

    /// Connects to the service listening on `name`. Fails with
    /// [`Error::NotFound`] when nothing listens there and with
    /// [`Error::PermissionDenied`] when the channel is narrowed to another
    /// user.
    ///
    /// In [`Mode::Installed`] it must also refuse a listener that is not the
    /// privileged service, such as another local user who claimed the name
    /// while the service was down, with [`Error::NotTheService`] and before
    /// anything is sent. It must never lend the caller's identity to the
    /// listener. On Windows that means checking the pipe's owner and
    /// allowing identification-level impersonation only; elsewhere, a socket
    /// in a folder only root can write.
    fn connect(&self, name: &str) -> Result<Connection>;
}

/// The service's end of the channel. Dropping it closes it.
pub trait Listener: Send + Sync {
    /// Waits for the next connection and reports who is calling. The identity
    /// comes from the OS, not from anything the caller sent. Fails with
    /// [`Error::Closed`] once the listener is closed.
    fn accept(&self) -> Result<(Connection, UserId)>;

    /// Narrows the channel so the OS itself refuses every user but `owner`,
    /// replacing any earlier narrowing. May be called while another thread
    /// waits in [`Listener::accept`].
    ///
    /// The system's own administrative accounts are never shut out by this:
    /// on Windows, SYSTEM and Administrators can still connect. Before any
    /// narrowing, Windows admits users who are logged on interactively, which
    /// leaves out sessions such as SSH, services and scheduled tasks; the
    /// first claim cannot come from one of those.
    ///
    /// It only affects connections made afterwards. One already accepted, or
    /// already waiting to be accepted, stays attached whoever made it. So the
    /// service must still compare the caller's [`UserId`] with the owner on
    /// every request, and close other users' connections once an owner
    /// exists.
    fn restrict_to(&self, owner: &UserId) -> Result<()>;

    /// Stops listening and releases the name. An [`Listener::accept`] waiting
    /// on another thread returns [`Error::Closed`]. Closing twice is fine.
    ///
    /// Connections already accepted may be closed too: Windows cannot
    /// release the name while they are open. So close the listener only when
    /// shutting down, never to turn new callers away while keeping old ones.
    fn close(&self);
}

/// The bytes of one channel connection, as an OS implementation provides
/// them. Only [`Connection`] calls this; nothing else reads or writes a
/// channel. Dropping it closes it.
pub trait RawConnection: Send + Sync {
    /// Waits for bytes and copies up to `buf.len()` of them. `Ok(0)` means
    /// the peer closed. Fails with [`Error::TimedOut`] when the read timeout
    /// passes first.
    fn read(&self, buf: &mut [u8]) -> Result<usize>;

    /// Sends all of `bytes`. Fails with [`Error::TimedOut`] when the peer
    /// has not taken them all within the write timeout.
    fn write_all(&self, bytes: &[u8]) -> Result<()>;

    /// Sets how long each later [`RawConnection::read`] waits; `None` waits
    /// for ever. Never called with zero.
    fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<()>;

    /// Sets how long each later [`RawConnection::write_all`] may take as a
    /// whole; `None` waits for ever. Never called with zero.
    fn set_write_timeout(&self, timeout: Option<Duration>) -> Result<()>;

    /// Closes both directions. A `read` or `write_all` waiting on another
    /// thread returns promptly, with any result, and one started afterwards
    /// returns at once. Closing twice is fine.
    fn close(&self);
}

/// One end of a channel connection, carrying whole lines of text.
///
/// Any number of threads may share it: one line is read at a time, and lines
/// written from different threads never mix.
pub struct Connection {
    raw: Box<dyn RawConnection>,
    reading: Mutex<Reading>,
    writing: Mutex<()>,
    read_timeout: Mutex<Option<Duration>>,
    write_timeout: Mutex<Option<Duration>>,
    closed: AtomicBool,
}

#[derive(Default)]
struct Reading {
    /// Bytes received and not yet returned. Never more than the line limit.
    pending: Vec<u8>,
    too_long: bool,
}

/// Refuses a timeout of zero, which could only ever fail.
fn nonzero(timeout: Option<Duration>) -> Result<Option<Duration>> {
    match timeout {
        Some(Duration::ZERO) => Err(Error::Failed("a timeout cannot be zero".to_string())),
        timeout => Ok(timeout),
    }
}

impl Connection {
    /// Wraps an implementation's bytes. Every [`Transport`] and [`Listener`]
    /// hands out connections made here, so none can skip the line rules.
    pub fn new(raw: Box<dyn RawConnection>) -> Self {
        Self {
            raw,
            reading: Mutex::default(),
            writing: Mutex::default(),
            read_timeout: Mutex::default(),
            write_timeout: Mutex::default(),
            closed: AtomicBool::new(false),
        }
    }

    /// Waits for the next line and returns it without its newline, or `None`
    /// when the peer closed the connection.
    ///
    /// A line longer than [`MAX_LINE_BYTES`], newline included, fails with
    /// [`Error::LineTooLong`]: at most the limit is buffered before it is
    /// refused, and nothing beyond. Every read after it fails the same way,
    /// so the rest of that line is never mistaken for a message.
    ///
    /// Fails with [`Error::TimedOut`] when no whole line arrives within the
    /// read timeout; the part that did arrive is kept for the next call.
    /// Fails with [`Error::Closed`] after [`Connection::close`], even when
    /// lines had already arrived.
    pub fn read_line(&self) -> Result<Option<String>> {
        let mut reading = lock(&self.reading);
        if self.closed.load(Ordering::SeqCst) {
            return Err(Error::Closed);
        }
        if reading.too_long {
            return Err(Error::LineTooLong);
        }
        let deadline = lock(&self.read_timeout).map(|timeout| Instant::now() + timeout);
        let mut searched = 0;
        loop {
            let unsearched = &reading.pending[searched..];
            if let Some(at) = unsearched.iter().position(|byte| *byte == b'\n') {
                let mut line: Vec<u8> = reading.pending.drain(..=searched + at).collect();
                line.pop();
                let text = String::from_utf8(line);
                return text
                    .map(Some)
                    .map_err(|_| Error::Failed("line is not UTF-8".to_string()));
            }
            searched = reading.pending.len();
            if searched >= MAX_LINE_BYTES {
                *reading = Reading {
                    pending: Vec::new(),
                    too_long: true,
                };
                return Err(Error::LineTooLong);
            }
            let left = deadline.map(|at| at.saturating_duration_since(Instant::now()));
            if left.is_some_and(|left| left.is_zero()) {
                return Err(Error::TimedOut);
            }
            self.raw.set_read_timeout(left)?;
            let mut chunk = [0; 4096];
            let room = chunk.len().min(MAX_LINE_BYTES - searched);
            let read = self.raw.read(&mut chunk[..room]);
            if self.closed.load(Ordering::SeqCst) {
                return Err(Error::Closed);
            }
            match read? {
                0 if reading.pending.is_empty() => return Ok(None),
                0 => {
                    reading.pending.clear();
                    return Err(Error::Closed);
                }
                n => reading.pending.extend_from_slice(&chunk[..n]),
            }
        }
    }

    /// Sends one line, whole: lines from other threads go before or after it,
    /// never inside it. Refuses a line that is too long or contains a
    /// newline, and sends nothing in that case. Any other failure, including
    /// [`Error::TimedOut`] when the peer does not take the line within the
    /// write timeout, closes the connection, because part of the line may
    /// have been sent.
    pub fn write_line(&self, line: &str) -> Result<()> {
        let bytes = encode_line(line)?;
        let _writing = lock(&self.writing);
        if self.closed.load(Ordering::SeqCst) {
            return Err(Error::Closed);
        }
        let timeout = *lock(&self.write_timeout);
        let ready = self.raw.set_write_timeout(timeout);
        let sent = ready.and_then(|()| self.raw.write_all(&bytes));
        sent.inspect_err(|_| self.close())
    }

    /// Limits how long each later [`Connection::read_line`] waits for a whole
    /// line, however slowly its bytes arrive. `None`, the default, waits for
    /// ever. Zero is refused. The service sets one so a silent client cannot
    /// hold it up.
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        *lock(&self.read_timeout) = nonzero(timeout)?;
        Ok(())
    }

    /// Limits how long each later [`Connection::write_line`] waits for the
    /// peer to take the line. `None`, the default, waits for ever. Zero is
    /// refused. The service sets one so a client that never reads cannot hold
    /// a writer, and every writer waiting behind it, for ever.
    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        *lock(&self.write_timeout) = nonzero(timeout)?;
        Ok(())
    }

    /// Closes the connection. A [`Connection::read_line`] or
    /// [`Connection::write_line`] waiting on another thread returns
    /// [`Error::Closed`], and the peer sees the end of the stream. Closing
    /// twice is fine.
    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.raw.close();
    }

    /// For the suite only: lets it send bytes no `write_line` would.
    #[cfg(any(test, feature = "fake"))]
    pub(crate) fn raw(&self) -> &dyn RawConnection {
        &*self.raw
    }
}

/// The bytes sent for `line`: the line and one newline. Refuses a line the
/// peer would reject.
fn encode_line(line: &str) -> Result<Vec<u8>> {
    if line.len() >= MAX_LINE_BYTES {
        return Err(Error::LineTooLong);
    }
    if line.contains('\n') {
        return Err(Error::Failed("line contains a newline".to_string()));
    }
    Ok([line.as_bytes(), b"\n"].concat())
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::AtomicUsize;
    use std::sync::{Arc, Condvar};
    use std::thread;

    use super::*;

    /// A raw connection that plays back `input` at most `step` bytes at a
    /// time, counts what was taken from it, and keeps what was written. Its
    /// writes can be made to fail, or to wait as for a peer that never reads.
    #[derive(Default)]
    struct Script {
        input: Mutex<VecDeque<u8>>,
        step: usize,
        delay: Duration,
        taken: AtomicUsize,
        written: Mutex<Vec<u8>>,
        write_error: Option<Error>,
        stalled: bool,
        write_timeout: Mutex<Option<Duration>>,
        closed: Mutex<bool>,
        closing: Condvar,
    }

    fn script(input: &[u8], step: usize, delay: Duration) -> Arc<Script> {
        Arc::new(Script {
            input: Mutex::new(input.iter().copied().collect()),
            step,
            delay,
            ..Script::default()
        })
    }

    /// A connection whose peer never reads.
    fn stalled() -> Connection {
        Connection::new(Box::new(Arc::new(Script {
            stalled: true,
            ..Script::default()
        })))
    }

    fn connection(script: &Arc<Script>) -> Connection {
        Connection::new(Box::new(script.clone()))
    }

    impl RawConnection for Arc<Script> {
        fn read(&self, buf: &mut [u8]) -> Result<usize> {
            thread::sleep(self.delay);
            let mut input = lock(&self.input);
            let n = buf.len().min(self.step).min(input.len());
            for (slot, byte) in buf.iter_mut().zip(input.drain(..n)) {
                *slot = byte;
            }
            self.taken.fetch_add(n, Ordering::SeqCst);
            Ok(n)
        }

        // One byte at a time, so unguarded writers would interleave.
        fn write_all(&self, bytes: &[u8]) -> Result<()> {
            if let Some(error) = &self.write_error {
                return Err(error.clone());
            }
            if self.stalled {
                let timeout = lock(&self.write_timeout).unwrap_or(Duration::from_secs(5));
                let open = |closed: &mut bool| !*closed;
                let waited = self
                    .closing
                    .wait_timeout_while(lock(&self.closed), timeout, open);
                let (closed, _) = waited.unwrap();
                return Err(if *closed {
                    Error::Closed
                } else {
                    Error::TimedOut
                });
            }
            for byte in bytes {
                lock(&self.written).push(*byte);
                thread::yield_now();
            }
            Ok(())
        }

        fn set_read_timeout(&self, _timeout: Option<Duration>) -> Result<()> {
            Ok(())
        }

        fn set_write_timeout(&self, timeout: Option<Duration>) -> Result<()> {
            *lock(&self.write_timeout) = timeout;
            Ok(())
        }

        fn close(&self) {
            *lock(&self.closed) = true;
            self.closing.notify_all();
        }
    }

    // Closing means no more messages, even ones that had already arrived.
    #[test]
    fn a_closed_connection_returns_no_buffered_line() {
        let raw = script(b"first\nsecond\n", usize::MAX, Duration::ZERO);
        let connection = connection(&raw);
        assert_eq!(connection.read_line(), Ok(Some("first".to_string())));
        connection.close();
        assert_eq!(connection.read_line(), Err(Error::Closed));
    }

    // Part of a line may have gone out, so nothing more may follow it.
    #[test]
    fn a_failed_write_closes_the_connection() {
        let broken = Error::Failed("broken".to_string());
        let connection = Connection::new(Box::new(Arc::new(Script {
            input: Mutex::new(b"waiting\n".iter().copied().collect()),
            step: usize::MAX,
            write_error: Some(broken.clone()),
            ..Script::default()
        })));
        assert_eq!(connection.write_line("{}"), Err(broken));
        assert_eq!(connection.read_line(), Err(Error::Closed));
        assert_eq!(connection.write_line("{}"), Err(Error::Closed));
    }

    // Security rule: a client that never reads cannot hold a writer, or the
    // writers queued behind it, for ever.
    #[test]
    fn a_write_nobody_takes_times_out_and_closes() {
        let connection = stalled();
        let timeout = Some(Duration::from_millis(50));
        connection.set_write_timeout(timeout).unwrap();
        let started = Instant::now();
        assert_eq!(connection.write_line("{}"), Err(Error::TimedOut));
        assert!(started.elapsed() < Duration::from_secs(2), "not passed on");
        assert_eq!(connection.write_line("{}"), Err(Error::Closed));
    }

    #[test]
    fn close_ends_a_blocked_write_and_those_queued_behind_it() {
        let connection = stalled();
        thread::scope(|scope| {
            let writers = [(); 2].map(|()| scope.spawn(|| connection.write_line("{}")));
            thread::sleep(Duration::from_millis(50));
            connection.close();
            for writer in writers {
                assert_eq!(writer.join().unwrap(), Err(Error::Closed));
            }
        });
    }

    // A zero timeout could only ever fail, so it is refused, not stored.
    #[test]
    fn a_zero_timeout_is_refused() {
        let connection = connection(&script(b"waiting\n", usize::MAX, Duration::ZERO));
        let zero = Some(Duration::ZERO);
        assert!(matches!(
            connection.set_read_timeout(zero),
            Err(Error::Failed(_))
        ));
        assert!(matches!(
            connection.set_write_timeout(zero),
            Err(Error::Failed(_))
        ));
        assert_eq!(connection.read_line(), Ok(Some("waiting".to_string())));
        assert_eq!(connection.write_line("{}"), Ok(()));
    }

    // Security rule: the rest of an oversized line is never read as the next
    // message, and no more than the limit is taken in to find that out.
    #[test]
    fn an_oversized_line_poisons_the_connection() {
        let input = [vec![b'a'; MAX_LINE_BYTES], b"{\"smuggled\":1}\n".to_vec()].concat();
        let raw = script(&input, usize::MAX, Duration::ZERO);
        let connection = connection(&raw);
        assert_eq!(connection.read_line(), Err(Error::LineTooLong));
        assert_eq!(connection.read_line(), Err(Error::LineTooLong));
        assert_eq!(raw.taken.load(Ordering::SeqCst), MAX_LINE_BYTES);
    }

    #[test]
    fn reads_lines_up_to_the_limit_however_they_are_split() {
        let longest = "a".repeat(MAX_LINE_BYTES - 1);
        let input = format!("one\ntwo\n{longest}\nthr");
        for step in [1, 7, usize::MAX] {
            let connection = connection(&script(input.as_bytes(), step, Duration::ZERO));
            assert_eq!(connection.read_line(), Ok(Some("one".to_string())));
            assert_eq!(connection.read_line(), Ok(Some("two".to_string())));
            assert_eq!(connection.read_line(), Ok(Some(longest.clone())));
            // The peer went away in the middle of a line.
            assert_eq!(connection.read_line(), Err(Error::Closed));
            assert_eq!(connection.read_line(), Ok(None));
        }
    }

    // Security rule: nothing is sent that the peer's limit would reject, and
    // one call can never smuggle a second message.
    #[test]
    fn refuses_to_write_an_oversized_or_multi_line_message() {
        let raw = script(b"", 1, Duration::ZERO);
        let connection = connection(&raw);
        let longest = "a".repeat(MAX_LINE_BYTES - 1);
        assert_eq!(connection.write_line(&longest), Ok(()));
        assert_eq!(lock(&raw.written).len(), MAX_LINE_BYTES);
        let too_long = format!("{longest}a");
        assert_eq!(connection.write_line(&too_long), Err(Error::LineTooLong));
        assert!(matches!(
            connection.write_line("{}\n{}"),
            Err(Error::Failed(_))
        ));
        assert_eq!(lock(&raw.written).len(), MAX_LINE_BYTES);
    }

    // A reply and a pushed event are written by different threads. Neither
    // may land inside the other.
    #[test]
    fn lines_written_by_two_threads_never_interleave() {
        let raw = script(b"", 1, Duration::ZERO);
        let connection = connection(&raw);
        thread::scope(|scope| {
            for letter in ["a", "b"] {
                let connection = &connection;
                scope.spawn(move || {
                    for _ in 0..50 {
                        connection.write_line(&letter.repeat(200)).unwrap();
                    }
                });
            }
        });
        let written = String::from_utf8(lock(&raw.written).clone()).unwrap();
        assert_eq!(written.lines().count(), 100);
        for line in written.lines() {
            assert!(line == "a".repeat(200) || line == "b".repeat(200), "{line}");
        }
    }

    // Security rule: the timeout covers the whole line, so a client cannot
    // hold the service by sending one byte at a time.
    #[test]
    fn a_slow_line_times_out_as_a_whole() {
        let raw = script(&[b'a'; 1000], 1, Duration::from_millis(5));
        let connection = connection(&raw);
        let timeout = Some(Duration::from_millis(50));
        connection.set_read_timeout(timeout).unwrap();
        assert_eq!(connection.read_line(), Err(Error::TimedOut));
        assert!(raw.taken.load(Ordering::SeqCst) < 100);
    }

    #[test]
    fn a_closed_connection_refuses_reads_and_writes() {
        let connection = connection(&script(b"waiting\n", 1, Duration::ZERO));
        connection.close();
        assert_eq!(connection.read_line(), Err(Error::Closed));
        assert_eq!(connection.write_line("late"), Err(Error::Closed));
    }

    // Security rule: an identity is one exact piece of text. Anything that
    // could be confused with another spelling of it is refused or unequal.
    #[test]
    fn user_ids_round_trip_and_refuse_odd_text() {
        let id: UserId = "S-1-5-21-1-2-3-1001".parse().unwrap();
        assert_eq!(id.to_string().parse::<UserId>().unwrap(), id);
        assert_ne!("1001".parse::<UserId>(), "01001".parse::<UserId>());
        // Empty, spaces, controls, no-break space, zero-width space, a
        // right-to-left override, and full-width digits.
        let odd = [
            "",
            " 1001",
            "1001\n",
            "10 01",
            "1001\0",
            "1001\u{a0}",
            "1001\u{200b}",
            "\u{202e}1001",
            "\u{ff11}\u{ff10}\u{ff10}\u{ff11}",
        ];
        for odd in odd {
            assert!(odd.parse::<UserId>().is_err(), "{odd:?}");
        }
    }
}
