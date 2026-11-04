//! Errors from Apple APIs, reduced to what callers branch on.

use std::fmt;

/// An error from an Apple API call, or from the wrapper around one.
///
/// Callers branch on `domain` and `code` (for example the `NEVPNConnectionError`
/// codes the supervisor uses to decide whether to recover), and report `message`
/// (the `localizedDescription`) to the operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppleError {
    /// An `NSError`.
    Ns {
        domain: String,
        code: i64,
        message: String,
    },
    /// A completion handler did not run within its timeout. Several Apple
    /// handlers (provider messages, disconnect errors) can never fire, so every
    /// wait carries one.
    TimedOut,
    /// Every resolver was dropped without resolving: the handler block was
    /// released without firing, so no result will ever come.
    HandlerDropped,
    /// The caller was on the main thread, where waiting for a completion
    /// handler would deadlock: the handlers need the main run loop.
    MainThread,
    /// The entry was used after it was removed.
    StaleEntry,
    /// A read-only system extension request would need the user's approval, so
    /// it was refused instead of waiting on them.
    ApprovalRequired,
    /// A system callback panicked or raised; the request's result is unknown.
    CallbackFailed,
}

impl AppleError {
    /// Builds the `Ns` variant from an `NSError`'s three fields.
    ///
    /// The real backend reads `domain`, `code` and `localizedDescription` off the
    /// `NSError` and passes them here, so the conversion rules live in one place
    /// and this crate stays free of Apple types.
    pub fn from_nserror(domain: impl Into<String>, code: i64, message: impl Into<String>) -> Self {
        AppleError::Ns {
            domain: domain.into(),
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for AppleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppleError::Ns {
                domain,
                code,
                message,
            } => write!(f, "{message} ({domain} {code})"),
            AppleError::TimedOut => f.write_str("timed out waiting for the system"),
            AppleError::HandlerDropped => f.write_str("the system dropped the completion handler"),
            AppleError::MainThread => f.write_str("blocking call made on the main thread"),
            AppleError::StaleEntry => f.write_str("the VPN entry was removed"),
            AppleError::ApprovalRequired => f.write_str("approval required"),
            AppleError::CallbackFailed => f.write_str("a system callback failed"),
        }
    }
}

impl std::error::Error for AppleError {}
