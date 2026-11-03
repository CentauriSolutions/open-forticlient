//! Shared plumbing for the Objective-C backends: the only code here that is not
//! specific to one framework. Kept small and generic on purpose.

use std::panic::AssertUnwindSafe;

use objc2::rc::Retained;
use objc2::runtime::ProtocolObject;
use objc2::Message;
use objc2_foundation::{NSError, NSObjectProtocol, NSThread};
use objc2_network_extension::{NETunnelProviderManager, NEVPNConnection};

use crate::error::AppleError;

/// Marks a class whose instances may be used from any thread.
///
/// # Safety
/// Implement only for a class whose documentation states that its instances are
/// thread safe, and quote that statement in the `SAFETY` comment.
pub(crate) unsafe trait ThreadSafeObject: Message {}

// SAFETY: NETunnelProviderManager.h in the macOS SDK says "Instances of this
// class are thread safe." (line 28), and NEVPNManager.h says the same of its
// superclass (line 66).
unsafe impl ThreadSafeObject for NETunnelProviderManager {}

// SAFETY: NEVPNConnection.h says "Instances of this class are thread safe."
// (line 99). Its subclass NETunnelProviderSession adds only a message call.
unsafe impl ThreadSafeObject for NEVPNConnection {}

// SAFETY: this is the opaque token `addObserverForName:...` returns. We only
// ever pass it to `removeObserver:`, and NSNotificationCenter is documented as
// safe to use from any thread.
unsafe impl ThreadSafeObject for ProtocolObject<dyn NSObjectProtocol> {}

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

/// Whether the calling thread is the main thread.
pub(crate) fn is_main() -> bool {
    NSThread::isMainThread_class()
}
