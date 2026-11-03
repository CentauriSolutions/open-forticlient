//! Turning an Apple completion handler into a blocking call with a timeout.
//!
//! Each call site starts the operation and hands its handler a [`Resolver`]; the
//! caller blocks here until the handler resolves or the timeout passes. A late
//! handler is ignored, which replaces the per-call epoch counters the Swift code
//! used.

use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::error::AppleError;

/// The one timeout for handlers that may never fire.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Delivers a completion handler's result. The first `resolve` wins; later ones
/// (including after the caller timed out) are dropped.
pub struct Resolver<T>(Arc<Mutex<Option<Sender<T>>>>);

impl<T> Clone for Resolver<T> {
    fn clone(&self) -> Self {
        Resolver(Arc::clone(&self.0))
    }
}

impl<T> Resolver<T> {
    pub fn resolve(&self, value: T) {
        let sender = self.0.lock().unwrap().take();
        if let Some(sender) = sender {
            // The receiver is gone if the caller already timed out.
            let _ = sender.send(value);
        }
    }
}

/// Runs `start`, which must arrange for the returned [`Resolver`] to be resolved
/// from the Apple handler, and waits up to `timeout` for the result.
///
/// `is_main` reports whether the calling thread is the main thread; the real
/// backend passes `NSThread.isMainThread`. Waiting there would deadlock, so it
/// is refused before `start` runs.
pub fn await_callback<T>(
    timeout: Duration,
    is_main: fn() -> bool,
    start: impl FnOnce(Resolver<T>),
) -> Result<T, AppleError> {
    if is_main() {
        return Err(AppleError::MainThread);
    }
    let (tx, rx) = channel();
    start(Resolver(Arc::new(Mutex::new(Some(tx)))));
    rx.recv_timeout(timeout).map_err(|_| AppleError::TimedOut)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::thread;

    fn off_main() -> bool {
        false
    }
    fn on_main() -> bool {
        true
    }

    #[test]
    fn resolves_once_or_fails_closed() {
        let wait = Duration::from_millis(50);

        // A handler on another thread resolves twice: the first value wins.
        let got = await_callback(Duration::from_secs(5), off_main, |r| {
            thread::spawn(move || {
                r.resolve(1);
                r.resolve(2);
            });
        });
        assert_eq!(got, Ok(1));

        // A handler that never fires times out; resolving afterwards is harmless.
        let kept = Cell::new(None);
        let got = await_callback(wait, off_main, |r| kept.set(Some(r)));
        assert_eq!(got, Err(AppleError::TimedOut));
        kept.take().unwrap().resolve(3);

        // On the main thread it refuses without starting the operation.
        let started = Cell::new(false);
        let got: Result<i32, _> = await_callback(wait, on_main, |_| started.set(true));
        assert_eq!(got, Err(AppleError::MainThread));
        assert!(!started.get());
    }
}
