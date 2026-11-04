//! System extension requests, as a trait.
//!
//! [`ExtensionControl`] is what the host's `activate` and `deactivate` verbs and
//! the readiness check call; [`MockExtensions`] stands in for SystemExtensions in
//! tests. A request is event-driven: the system may ask the user for approval or
//! offer a replacement long before it finishes, so activation and deactivation
//! have no timeout and report those moments through an [`EventSink`]. Only the
//! read-only properties request carries one.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::error::AppleError;

pub type Result<T> = std::result::Result<T, AppleError>;

/// `OSSystemExtensionErrorDomain`, the domain of every error a request fails
/// with.
pub const ERROR_DOMAIN: &str = "OSSystemExtensionErrorDomain";

/// `OSSystemExtensionErrorExtensionNotFound`: no such extension is installed.
pub const EXTENSION_NOT_FOUND: i64 = 4;

/// Whether `error` says the extension is not installed, which readiness reports
/// as "missing" rather than "unavailable".
pub fn is_extension_not_found(error: &AppleError) -> bool {
    matches!(error, AppleError::Ns { domain, code, .. }
        if domain == ERROR_DOMAIN && *code == EXTENSION_NOT_FOUND)
}

/// One side of a replacement: `bundleShortVersion` and `bundleVersion`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionVersion {
    pub short: String,
    pub build: String,
}

/// A moment during an activation or deactivation that the operator sees.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtensionEvent {
    /// The user must approve the extension in System Settings.
    NeedsApproval,
    /// An installed extension is being replaced. The request always accepts.
    Replacing {
        from: ExtensionVersion,
        to: ExtensionVersion,
    },
}

/// How a request that did not fail ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Finish {
    Completed,
    /// The system accepted the change but applies it after a reboot; the host
    /// reports it with its own exit code.
    WillCompleteAfterReboot,
}

/// One installed copy of an extension, from a properties request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionProperties {
    pub short_version: String,
    pub build: String,
    pub enabled: bool,
    pub awaiting_approval: bool,
    pub uninstalling: bool,
}

/// Receives [`ExtensionEvent`]s, in order, before the request returns. It may
/// be called from any thread (the real backend uses the main queue, not the
/// caller's), so it must be `Send + Sync` and must not block on the caller.
pub type EventSink = Arc<dyn Fn(ExtensionEvent) + Send + Sync>;

pub trait ExtensionControl: Send + Sync {
    /// Submits an activation request and waits for it to end, however long the
    /// user takes. A failure is an [`AppleError::Ns`] in [`ERROR_DOMAIN`].
    fn activate(&self, identifier: &str, events: EventSink) -> Result<Finish>;
    /// As `activate`, for deactivation.
    fn deactivate(&self, identifier: &str, events: EventSink) -> Result<Finish>;
    /// The installed copies of `identifier`. Read-only: it never prompts, so a
    /// request that would need approval fails with
    /// [`AppleError::ApprovalRequired`]. A missing extension is the error
    /// [`is_extension_not_found`] recognises. On timeout the request is
    /// abandoned, not cancelled (the API has no cancel); its late reply is
    /// dropped.
    fn properties(&self, identifier: &str, timeout: Duration) -> Result<Vec<ExtensionProperties>>;
}

pub use mock::MockExtensions;

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
mod se;
#[cfg(target_os = "macos")]
pub use se::SystemExtensions;

mod mock {
    use super::*;

    /// A scripted activation or deactivation: the events it raises, then how it
    /// ends.
    type Script = (Vec<ExtensionEvent>, Result<Finish>);

    #[derive(Default)]
    struct State {
        activations: VecDeque<Script>,
        deactivations: VecDeque<Script>,
        properties: HashMap<String, Result<Vec<ExtensionProperties>>>,
        requests: Vec<(&'static str, String)>,
    }

    /// An in-memory [`ExtensionControl`]. A request with nothing scripted ends
    /// in `TimedOut`, as one the system never answers would.
    #[derive(Default)]
    pub struct MockExtensions {
        state: Mutex<State>,
    }

    impl MockExtensions {
        pub fn new() -> Self {
            Self::default()
        }

        /// Queues the next `activate`: it raises `events`, then returns `end`.
        pub fn script_activate(&self, events: Vec<ExtensionEvent>, end: Result<Finish>) {
            self.state
                .lock()
                .unwrap()
                .activations
                .push_back((events, end));
        }

        /// Queues the next `deactivate`, as `script_activate` does.
        pub fn script_deactivate(&self, events: Vec<ExtensionEvent>, end: Result<Finish>) {
            self.state
                .lock()
                .unwrap()
                .deactivations
                .push_back((events, end));
        }

        /// Sets what `properties` returns for `identifier`. Unset, it reports the
        /// extension as not found.
        pub fn set_properties(&self, identifier: &str, result: Result<Vec<ExtensionProperties>>) {
            self.state
                .lock()
                .unwrap()
                .properties
                .insert(identifier.to_string(), result);
        }

        /// Every request so far, as `("activate" | "deactivate" | "properties",
        /// identifier)`.
        pub fn requests(&self) -> Vec<(&'static str, String)> {
            self.state.lock().unwrap().requests.clone()
        }

        fn run(
            &self,
            kind: &'static str,
            identifier: &str,
            events: EventSink,
            pick: fn(&mut State) -> &mut VecDeque<Script>,
        ) -> Result<Finish> {
            let (raised, end) = {
                let mut s = self.state.lock().unwrap();
                s.requests.push((kind, identifier.to_string()));
                pick(&mut s)
                    .pop_front()
                    .unwrap_or((Vec::new(), Err(AppleError::TimedOut)))
            };
            raised.into_iter().for_each(|e| events(e));
            end
        }
    }

    impl ExtensionControl for MockExtensions {
        fn activate(&self, identifier: &str, events: EventSink) -> Result<Finish> {
            self.run("activate", identifier, events, |s| &mut s.activations)
        }

        fn deactivate(&self, identifier: &str, events: EventSink) -> Result<Finish> {
            self.run("deactivate", identifier, events, |s| &mut s.deactivations)
        }

        fn properties(
            &self,
            identifier: &str,
            _timeout: Duration,
        ) -> Result<Vec<ExtensionProperties>> {
            let mut s = self.state.lock().unwrap();
            s.requests.push(("properties", identifier.to_string()));
            s.properties.get(identifier).cloned().unwrap_or_else(|| {
                Err(AppleError::from_nserror(
                    ERROR_DOMAIN,
                    EXTENSION_NOT_FOUND,
                    "extension not found",
                ))
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version(s: &str) -> ExtensionVersion {
        ExtensionVersion {
            short: s.into(),
            build: "1".into(),
        }
    }

    /// The mock is what the host's verbs are tested against, so it must behave as
    /// the real backend does: events arrive in order before the request returns,
    /// both directions end as scripted, unanswered requests time out, and a
    /// missing extension fails the properties request with the recognised error.
    #[test]
    fn mock_honours_the_extension_control_contract() {
        let ext = MockExtensions::new();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink: EventSink = {
            let seen = seen.clone();
            Arc::new(move |e| seen.lock().unwrap().push(e))
        };

        let replacing = ExtensionEvent::Replacing {
            from: version("1.0"),
            to: version("1.1"),
        };
        ext.script_activate(
            vec![ExtensionEvent::NeedsApproval, replacing.clone()],
            Ok(Finish::WillCompleteAfterReboot),
        );
        assert_eq!(
            ext.activate("id", sink.clone()),
            Ok(Finish::WillCompleteAfterReboot)
        );
        assert_eq!(
            *seen.lock().unwrap(),
            [ExtensionEvent::NeedsApproval, replacing]
        );

        // Deactivation has its own script: a failure keeps its domain and code.
        let failure = AppleError::from_nserror(ERROR_DOMAIN, 8, "bad signature");
        ext.script_deactivate(Vec::new(), Err(failure.clone()));
        assert_eq!(ext.deactivate("id", sink.clone()), Err(failure));
        // Nothing left scripted: the request is never answered.
        assert_eq!(ext.activate("id", sink), Err(AppleError::TimedOut));

        let wait = Duration::from_millis(10);
        let err = ext.properties("id", wait).unwrap_err();
        assert!(is_extension_not_found(&err));
        let props = ExtensionProperties {
            short_version: "1.0".into(),
            build: "7".into(),
            enabled: true,
            awaiting_approval: false,
            uninstalling: false,
        };
        ext.set_properties("id", Ok(vec![props.clone()]));
        assert_eq!(ext.properties("id", wait), Ok(vec![props]));

        let kinds: Vec<_> = ext.requests().into_iter().map(|(k, _)| k).collect();
        assert_eq!(
            kinds,
            [
                "activate",
                "deactivate",
                "activate",
                "properties",
                "properties"
            ]
        );
    }

    #[test]
    fn only_extension_not_found_in_the_system_domain_counts_as_missing() {
        let ns = |domain, code| AppleError::from_nserror(domain, code, "m");
        assert!(is_extension_not_found(&ns(ERROR_DOMAIN, 4)));
        assert!(!is_extension_not_found(&ns(ERROR_DOMAIN, 1)));
        assert!(!is_extension_not_found(&ns("NSCocoaErrorDomain", 4)));
        assert!(!is_extension_not_found(&AppleError::TimedOut));
    }
}
