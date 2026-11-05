//! Standard output that survives a closed pipe.
//!
//! `println!` panics when the reader has gone (`oftc status | head -1`), and the
//! app builds with `panic = "unwind"` only so the entry point can catch that. An
//! [`Out`] instead marks the stream dead on `BrokenPipe`, drops later writes and
//! lets the command run to completion, so the exit code is the command's own.

use std::io::{self, Write};
use std::sync::{Arc, Mutex};

struct Stream {
    writer: Box<dyn Write + Send>,
    dead: bool,
}

impl Stream {
    fn new(writer: Box<dyn Write + Send>) -> Stream {
        Stream {
            writer,
            dead: false,
        }
    }

    fn write(&mut self, bytes: &[u8]) {
        if self.dead {
            return;
        }
        // Any failure ends the stream: there is nowhere left to report it.
        if self.writer.write_all(bytes).is_err() {
            self.dead = true;
        }
    }

    fn flush(&mut self) {
        if !self.dead && self.writer.flush().is_err() {
            self.dead = true;
        }
    }
}

/// A command's output. Every host verb writes its result, errors included, to
/// stdout (the Swift host did), so there is no second stream.
pub struct Out(Stream);

impl Out {
    pub fn new(stdout: Box<dyn Write + Send>) -> Out {
        Out(Stream::new(stdout))
    }

    /// The process's own stdout.
    pub fn process() -> Out {
        Out::new(Box::new(io::stdout()))
    }

    /// `text` and a newline on stdout.
    pub fn line(&mut self, text: &str) {
        self.0.write(text.as_bytes());
        self.0.write(b"\n");
    }

    /// Raw bytes, with no newline added (an exported bundle).
    pub fn bytes(&mut self, data: &[u8]) {
        self.0.write(data);
    }

    /// Flushes. A dead stream is not an error.
    pub fn flush(&mut self) {
        self.0.flush();
    }
}

/// A shared buffer for tests: hand one clone to [`Out`], read the other.
#[derive(Clone, Default)]
pub struct Capture(Arc<Mutex<Vec<u8>>>);

impl Capture {
    pub fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Closed(Arc<Mutex<usize>>);

    impl Write for Closed {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            *self.0.lock().unwrap() += 1;
            Err(io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
    }

    #[test]
    fn a_closed_pipe_is_swallowed() {
        let writes = Arc::new(Mutex::new(0));
        let mut out = Out::new(Box::new(Closed(writes.clone())));
        out.line("first");
        out.line("second");
        out.flush();
        // Only the first write reached the closed pipe; the rest were dropped.
        assert_eq!(*writes.lock().unwrap(), 1);
    }
}
