//! Terminal output that survives a closed pipe.
//!
//! `oftc status | head -1` closes our stdout early. `println!` panics on the
//! resulting `EPIPE`, and the release profile's `panic = "abort"` turns that
//! into SIGABRT. Every write goes through [`Stream`] instead: a broken pipe
//! marks the stream dead, later writes are dropped, and the command runs to
//! completion with its own exit code (so `oftc connect | head -1` still
//! finishes the work after the first line).

use std::fmt;
use std::io::{self, ErrorKind, Write};
use std::sync::{LazyLock, Mutex};

/// A writer that goes quiet, rather than failing, once its reader is gone.
pub struct Stream<W: Write> {
    inner: W,
    dead: bool,
}

impl<W: Write> Stream<W> {
    pub fn new(inner: W) -> Self {
        Self { inner, dead: false }
    }

    /// Writes bytes. A broken pipe is success; any other error is returned.
    pub fn write_bytes(&mut self, bytes: &[u8]) -> io::Result<()> {
        if self.dead {
            return Ok(());
        }
        let result = self.inner.write_all(bytes);
        self.settle(result)
    }

    pub fn write_args(&mut self, args: fmt::Arguments<'_>) -> io::Result<()> {
        if self.dead {
            return Ok(());
        }
        let result = self.inner.write_fmt(args);
        self.settle(result)
    }

    pub fn flush(&mut self) -> io::Result<()> {
        if self.dead {
            return Ok(());
        }
        let result = self.inner.flush();
        self.settle(result)
    }

    fn settle(&mut self, result: io::Result<()>) -> io::Result<()> {
        match result {
            Err(error) if error.kind() == ErrorKind::BrokenPipe => {
                self.dead = true;
                Ok(())
            }
            other => other,
        }
    }
}

static STDOUT: LazyLock<Mutex<Stream<io::Stdout>>> =
    LazyLock::new(|| Mutex::new(Stream::new(io::stdout())));
static STDERR: LazyLock<Mutex<Stream<io::Stderr>>> =
    LazyLock::new(|| Mutex::new(Stream::new(io::stderr())));

fn locked<W: Write, T>(
    stream: &Mutex<Stream<W>>,
    f: impl FnOnce(&mut Stream<W>) -> io::Result<T>,
) -> io::Result<T> {
    f(&mut stream.lock().unwrap_or_else(|poisoned| poisoned.into_inner()))
}

pub fn stdout_args(args: fmt::Arguments<'_>) {
    // Console output is best effort, as it was with `println!`, but never
    // fatal. A non-pipe failure (for example a full disk) is ignored too.
    let _ = locked(&STDOUT, |s| s.write_args(args));
}

pub fn stderr_args(args: fmt::Arguments<'_>) {
    let _ = locked(&STDERR, |s| s.write_args(args));
}

/// Writes raw bytes to stdout (profile exports); the error is the caller's.
pub fn stdout_bytes(bytes: &[u8]) -> io::Result<()> {
    locked(&STDOUT, |s| s.write_bytes(bytes))
}

pub fn flush_stdout() -> io::Result<()> {
    locked(&STDOUT, Stream::flush)
}

macro_rules! out {
    ($($arg:tt)*) => { $crate::out::stdout_args(format_args!($($arg)*)) };
}
macro_rules! outln {
    () => { $crate::out::stdout_args(format_args!("\n")) };
    ($($arg:tt)*) => { $crate::out::stdout_args(format_args!("{}\n", format_args!($($arg)*))) };
}
macro_rules! errln {
    ($($arg:tt)*) => { $crate::out::stderr_args(format_args!("{}\n", format_args!($($arg)*))) };
}
pub(crate) use {errln, out, outln};

#[cfg(test)]
mod tests {
    use super::*;

    /// Fails with `BrokenPipe` on every call, counting attempts.
    struct Closed {
        attempts: usize,
    }

    impl Write for Closed {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            self.attempts += 1;
            Err(ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            self.attempts += 1;
            Err(ErrorKind::BrokenPipe.into())
        }
    }

    #[test]
    fn a_closed_pipe_is_quiet_and_stops_writing() {
        let mut stream = Stream::new(Closed { attempts: 0 });
        stream.write_args(format_args!("first")).unwrap();
        stream.write_bytes(b"second").unwrap();
        stream.flush().unwrap();
        assert_eq!(stream.inner.attempts, 1, "later writes must be dropped");

        // Only a broken pipe is quiet; any other failure still surfaces.
        struct Full;
        impl Write for Full {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(ErrorKind::StorageFull.into())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        assert!(Stream::new(Full).write_bytes(b"x").is_err());
    }
}
