//! Shared plumbing for the Objective-C backends: the only code here that is not
//! specific to one framework. Kept small and generic on purpose.

use std::panic::{catch_unwind, AssertUnwindSafe};

use objc2::rc::Retained;
use objc2::Message;
use objc2_foundation::{NSError, NSThread};

use crate::error::AppleError;

/// Marks a class whose instances may be used from any thread.
///
/// # Safety
/// Implement only for a class whose documentation states that its instances are
/// thread safe, and quote that statement in the `SAFETY` comment.
pub(crate) unsafe trait ThreadSafeObject: Message {}

/// An owned object of a [`ThreadSafeObject`] class, movable across threads.
pub(crate) struct Shared<T: ThreadSafeObject>(Retained<T>);

// SAFETY: `T: ThreadSafeObject`, so the class is documented thread safe; moving
// or sharing the retain count itself is atomic.
unsafe impl<T: ThreadSafeObject> Send for Shared<T> {}
// SAFETY: as above.
unsafe impl<T: ThreadSafeObject> Sync for Shared<T> {}

impl<T: ThreadSafeObject> Shared<T> {
    pub(crate) fn new(object: Retained<T>) -> Self {
        Shared(object)
    }
}

impl<T: ThreadSafeObject> std::ops::Deref for Shared<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

/// Converts an `NSError` to an [`AppleError`].
pub(crate) fn from_ns_error(error: &NSError) -> AppleError {
    AppleError::from_nserror(
        error.domain().to_string(),
        error.code() as i64,
        error.localizedDescription().to_string(),
    )
}

/// Reads a possibly-null `NSError*` handed to a completion block.
///
/// # Safety
/// `error` must be null or point to a live `NSError` for the call.
pub(crate) unsafe fn error_from_ptr(error: *mut NSError) -> Option<AppleError> {
    // SAFETY: forwarded from the caller.
    unsafe { error.as_ref() }.map(from_ns_error)
}

/// Runs `f`, turning an Objective-C exception into an error. NetworkExtension
/// raises for misuse (for example an unsaved entry); unwinding one through Rust
/// frames is undefined behaviour.
pub(crate) fn catch<R>(f: impl FnOnce() -> R) -> Result<R, AppleError> {
    objc2::exception::catch(AssertUnwindSafe(f)).map_err(|exception| {
        let reason = exception
            .map(|e| format!("{e:?}"))
            .unwrap_or_else(|| "unknown exception".to_string());
        AppleError::from_nserror("NSException", 0, reason)
    })
}

/// Run `f`, turning a Rust panic or an Objective-C exception into `false`.
/// Both must stay out of `extern "C"` trampolines: a panic there aborts the
/// process, and an exception unwinding through Rust is undefined behaviour.
pub(crate) fn guarded(f: impl FnOnce()) -> bool {
    catch_unwind(AssertUnwindSafe(|| {
        objc2::exception::catch(AssertUnwindSafe(f)).is_ok()
    }))
    .unwrap_or(false)
}

/// Whether the calling thread is the main thread.
pub(crate) fn is_main() -> bool {
    NSThread::isMainThread_class()
}

#[cfg(test)]
mod tests {
    use super::*;
    use objc2::msg_send;
    use objc2_foundation::{NSException, NSString};

    #[test]
    fn catch_turns_an_exception_into_an_error() {
        let result = catch(|| {
            let name = NSString::from_str("OftcTestException");
            let reason = NSString::from_str("boom");
            // SAFETY: a valid exception object; raising it inside `catch`.
            unsafe {
                let exception =
                    NSException::exceptionWithName_reason_userInfo(&name, Some(&reason), None);
                let _: () = msg_send![&*exception, raise];
            }
        });
        match result {
            Err(AppleError::Ns { domain, .. }) => assert_eq!(domain, "NSException"),
            other => panic!("expected an Ns error, got {other:?}"),
        }
    }
}
