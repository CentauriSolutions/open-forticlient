//! [`ExtensionControl`] over SystemExtensions, through `objc2`.
//!
//! A request needs a delegate object; [`Delegate`] forwards the system's four
//! callbacks to an [`EventSink`] and a [`Resolver`], and the request's caller
//! waits on [`await_callback`] (no timeout for activation and deactivation,
//! which can wait on the user). Callbacks arrive on the main queue, so the caller
//! must not be on it; `await_callback` refuses otherwise. A panic or exception in
//! a callback is contained, as in the provider. Request construction and
//! submission off the main thread, and every callback, are unverified against a
//! live system.

use std::time::Duration;

use dispatch2::DispatchQueue;
use objc2::rc::Retained;
use objc2::runtime::ProtocolObject;
use objc2::{define_class, msg_send, AnyThread, DefinedClass};
use objc2_foundation::{NSArray, NSError, NSObject, NSObjectProtocol, NSString};
use objc2_system_extensions::{
    OSSystemExtensionManager, OSSystemExtensionProperties, OSSystemExtensionReplacementAction,
    OSSystemExtensionRequest, OSSystemExtensionRequestDelegate, OSSystemExtensionRequestResult,
};

use super::{
    EventSink, ExtensionControl, ExtensionEvent, ExtensionProperties, ExtensionVersion, Finish,
    Result,
};
use crate::completion::{await_callback, Resolver};
use crate::error::AppleError;
use crate::objc::{catch, from_ns_error, guarded, is_main};

/// Activation and deactivation wait for the user, so they wait for as long as
/// the process lives: a year, far past any session.
const NO_TIMEOUT: Duration = Duration::from_secs(365 * 24 * 60 * 60);

/// What a request ends with, before it is narrowed to the caller's type.
enum Reply {
    Finished(Finish),
    Found(Vec<ExtensionProperties>),
}

struct Handlers {
    events: EventSink,
    /// What to answer when the system offers to replace an extension.
    action: OSSystemExtensionReplacementAction,
    /// Fail the request on an approval prompt instead of reporting it.
    refuse_approval: bool,
    done: Resolver<Result<Reply>>,
}

define_class!(
    #[unsafe(super(NSObject))]
    #[name = "OFTCExtensionRequestDelegate"]
    #[ivars = Handlers]
    struct Delegate;

    unsafe impl NSObjectProtocol for Delegate {}

    unsafe impl OSSystemExtensionRequestDelegate for Delegate {
        #[unsafe(method(request:actionForReplacingExtension:withExtension:))]
        fn replacing(
            &self,
            _request: &OSSystemExtensionRequest,
            existing: &OSSystemExtensionProperties,
            ext: &OSSystemExtensionProperties,
        ) -> OSSystemExtensionReplacementAction {
            guarded(|| {
                (self.ivars().events)(ExtensionEvent::Replacing {
                    from: version(existing),
                    to: version(ext),
                })
            });
            self.ivars().action
        }

        #[unsafe(method(requestNeedsUserApproval:))]
        fn needs_approval(&self, _request: &OSSystemExtensionRequest) {
            if self.ivars().refuse_approval {
                self.finish(Err(AppleError::ApprovalRequired));
            } else {
                guarded(|| (self.ivars().events)(ExtensionEvent::NeedsApproval));
            }
        }

        #[unsafe(method(request:didFinishWithResult:))]
        fn finished(
            &self,
            _request: &OSSystemExtensionRequest,
            result: OSSystemExtensionRequestResult,
        ) {
            self.finish(Ok(Reply::Finished(map_result(result))));
        }

        #[unsafe(method(request:didFailWithError:))]
        fn failed(&self, _request: &OSSystemExtensionRequest, error: &NSError) {
            self.finish(Err(from_ns_error(error)));
        }

        #[unsafe(method(request:foundProperties:))]
        fn found(
            &self,
            _request: &OSSystemExtensionRequest,
            properties: &NSArray<OSSystemExtensionProperties>,
        ) {
            let mut found = None;
            guarded(|| found = Some(properties.iter().map(|p| describe(&p)).collect()));
            self.finish(found.map(Reply::Found).ok_or(AppleError::CallbackFailed));
        }
    }
);

impl Delegate {
    fn new(handlers: Handlers) -> Retained<Self> {
        let this = Self::alloc().set_ivars(handlers);
        // SAFETY: `NSObject`'s `init`.
        unsafe { msg_send![super(this), init] }
    }

    /// Resolves the request. Guarded: this runs inside an `extern "C"` method.
    fn finish(&self, reply: Result<Reply>) {
        guarded(|| self.ivars().done.resolve(reply));
    }
}

fn version(properties: &OSSystemExtensionProperties) -> ExtensionVersion {
    // SAFETY: property reads on a live object the system passed to a callback.
    unsafe {
        ExtensionVersion {
            short: properties.bundleShortVersion().to_string(),
            build: properties.bundleVersion().to_string(),
        }
    }
}

fn describe(properties: &OSSystemExtensionProperties) -> ExtensionProperties {
    let ExtensionVersion { short, build } = version(properties);
    // SAFETY: property reads on a live object the system passed to a callback.
    unsafe {
        ExtensionProperties {
            short_version: short,
            build,
            enabled: properties.isEnabled(),
            awaiting_approval: properties.isAwaitingUserApproval(),
            uninstalling: properties.isUninstalling(),
        }
    }
}

fn map_result(result: OSSystemExtensionRequestResult) -> Finish {
    if result == OSSystemExtensionRequestResult::WillCompleteAfterReboot {
        Finish::WillCompleteAfterReboot
    } else {
        Finish::Completed
    }
}

pub struct SystemExtensions;

type Make = unsafe fn(&NSString, &DispatchQueue) -> Retained<OSSystemExtensionRequest>;

impl SystemExtensions {
    /// Builds a request with `make`, submits it, and waits for `done`.
    fn submit(
        make: Make,
        identifier: &str,
        timeout: Duration,
        events: EventSink,
        action: OSSystemExtensionReplacementAction,
        refuse_approval: bool,
    ) -> Result<Reply> {
        Self::submit_with(timeout, events, action, refuse_approval, |delegate| {
            catch(|| {
                // SAFETY: live arguments; the request and the shared manager are
                // used only inside `catch`.
                unsafe {
                    let request = make(&NSString::from_str(identifier), DispatchQueue::main());
                    request.setDelegate(Some(ProtocolObject::from_ref(delegate)));
                    OSSystemExtensionManager::sharedManager().submitRequest(&request);
                }
            })
        })
    }

    /// Runs `send` with a fresh delegate and waits for the delegate's result. If
    /// `send` fails, its error is the result at once: the delegate (and its
    /// resolver) stays alive here, so without this the wait would only end at the
    /// timeout.
    fn submit_with(
        timeout: Duration,
        events: EventSink,
        action: OSSystemExtensionReplacementAction,
        refuse_approval: bool,
        send: impl FnOnce(&Delegate) -> Result<()>,
    ) -> Result<Reply> {
        // The request holds its delegate weakly, so it lives here until the end.
        let mut delegate = None;
        let waited = await_callback(timeout, is_main, |done: Resolver<Result<Reply>>| {
            let failed = done.clone();
            let d = Delegate::new(Handlers {
                events,
                action,
                refuse_approval,
                done,
            });
            if let Err(e) = send(&d) {
                failed.resolve(Err(e));
            }
            delegate = Some(d);
        });
        drop(delegate);
        waited?
    }

    fn change(make: Make, identifier: &str, events: EventSink) -> Result<Finish> {
        match Self::submit(
            make,
            identifier,
            NO_TIMEOUT,
            events,
            OSSystemExtensionReplacementAction::Replace,
            false,
        )? {
            Reply::Finished(finish) => Ok(finish),
            Reply::Found(_) => Err(unexpected()),
        }
    }
}

fn unexpected() -> AppleError {
    AppleError::from_nserror("oftc.apple", 0, "unexpected system extension reply")
}

impl ExtensionControl for SystemExtensions {
    fn activate(&self, identifier: &str, events: EventSink) -> Result<Finish> {
        Self::change(
            OSSystemExtensionRequest::activationRequestForExtension_queue,
            identifier,
            events,
        )
    }

    fn deactivate(&self, identifier: &str, events: EventSink) -> Result<Finish> {
        Self::change(
            OSSystemExtensionRequest::deactivationRequestForExtension_queue,
            identifier,
            events,
        )
    }

    fn properties(&self, identifier: &str, timeout: Duration) -> Result<Vec<ExtensionProperties>> {
        // A properties request never replaces, and one that would need approval
        // fails instead of waiting on the user.
        let events: EventSink = std::sync::Arc::new(|_| {});
        match Self::submit(
            OSSystemExtensionRequest::propertiesRequestForExtension_queue,
            identifier,
            timeout,
            events,
            OSSystemExtensionReplacementAction::Cancel,
            true,
        )? {
            Reply::Found(found) => Ok(found),
            Reply::Finished(_) => Err(unexpected()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use objc2_foundation::{NSDictionary, NSError};
    use objc2_system_extensions::{OSSystemExtensionErrorCode, OSSystemExtensionErrorDomain};

    use super::*;

    fn off_main() -> bool {
        false
    }

    fn ns_error(domain: &str, code: isize) -> Retained<NSError> {
        // SAFETY: a plain error built from a live string.
        unsafe {
            NSError::errorWithDomain_code_userInfo(
                &NSString::from_str(domain),
                code,
                None::<&NSDictionary<_, _>>,
            )
        }
    }

    /// Runs `deliver` against a delegate whose handlers record into the returned
    /// events and resolve the returned reply.
    fn deliver(
        deliver: impl FnOnce(&Delegate, &OSSystemExtensionRequest),
    ) -> (Vec<ExtensionEvent>, Result<Reply>) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let events: EventSink = {
            let seen = seen.clone();
            Arc::new(move |e| seen.lock().unwrap().push(e))
        };
        let reply = await_callback(Duration::from_secs(5), off_main, |done| {
            let delegate = Delegate::new(Handlers {
                events,
                action: OSSystemExtensionReplacementAction::Replace,
                refuse_approval: false,
                done,
            });
            // SAFETY: a request object that is never submitted.
            let request = unsafe { OSSystemExtensionRequest::new() };
            deliver(&delegate, &request);
        })
        .unwrap();
        let events = seen.lock().unwrap().clone();
        (events, reply)
    }

    #[test]
    fn the_framework_constants_match_ours() {
        // SAFETY: reads a constant string exported by the framework.
        let domain = unsafe { OSSystemExtensionErrorDomain }.to_string();
        assert_eq!(domain, super::super::ERROR_DOMAIN);
        assert_eq!(
            OSSystemExtensionErrorCode::ExtensionNotFound.0 as i64,
            super::super::EXTENSION_NOT_FOUND
        );
    }

    #[test]
    fn the_delegate_reports_approval_then_finish_and_reboot() {
        for (result, want) in [
            (OSSystemExtensionRequestResult::Completed, Finish::Completed),
            (
                OSSystemExtensionRequestResult::WillCompleteAfterReboot,
                Finish::WillCompleteAfterReboot,
            ),
        ] {
            let (events, reply) = deliver(|d, r| {
                // SAFETY: the selectors and argument types are the protocol's.
                let _: () = unsafe { msg_send![d, requestNeedsUserApproval: r] };
                let _: () = unsafe { msg_send![d, request: r, didFinishWithResult: result] };
                // The first result wins; a later callback changes nothing.
                let late = ns_error("late", 1);
                let _: () = unsafe { msg_send![d, request: r, didFailWithError: &*late] };
            });
            assert_eq!(events, [ExtensionEvent::NeedsApproval]);
            assert!(matches!(reply, Ok(Reply::Finished(f)) if f == want));
        }
    }

    #[test]
    fn the_delegate_reports_a_failure_with_its_domain_and_code() {
        let (events, reply) = deliver(|d, r| {
            let error = ns_error(super::super::ERROR_DOMAIN, 8);
            let _: () = unsafe { msg_send![d, request: r, didFailWithError: &*error] };
        });
        assert!(events.is_empty());
        assert!(matches!(
            reply,
            Err(AppleError::Ns { ref domain, code: 8, .. }) if domain == super::super::ERROR_DOMAIN
        ));
    }

    fn no_events() -> EventSink {
        Arc::new(|_| {})
    }

    #[test]
    fn a_send_that_fails_ends_the_wait_at_once_even_for_an_objc_exception() {
        use objc2_foundation::NSException;
        // Five seconds: only the error path ends this before then.
        let sent = |send: &dyn Fn() -> Result<()>| {
            SystemExtensions::submit_with(
                Duration::from_secs(5),
                no_events(),
                OSSystemExtensionReplacementAction::Replace,
                false,
                |_| send(),
            )
            .err()
        };
        let plain = AppleError::from_nserror("d", 1, "m");
        assert_eq!(sent(&|| Err(plain.clone())), Some(plain));
        let raised = sent(&|| {
            catch(|| {
                let name = NSString::from_str("OftcTestException");
                // SAFETY: a valid exception object, raised inside `catch`.
                unsafe {
                    let e = NSException::exceptionWithName_reason_userInfo(&name, None, None);
                    let _: () = msg_send![&*e, raise];
                }
            })
        });
        assert!(
            matches!(raised, Some(AppleError::Ns { ref domain, .. }) if domain == "NSException")
        );
    }

    #[test]
    fn a_refusing_delegate_fails_on_approval_and_a_normal_one_only_reports_it() {
        for (refuse, want_events, want_err) in [(true, 0, true), (false, 1, false)] {
            let seen = Arc::new(Mutex::new(0));
            let events: EventSink = {
                let seen = seen.clone();
                Arc::new(move |_| *seen.lock().unwrap() += 1)
            };
            let reply = await_callback(Duration::from_millis(200), off_main, |done| {
                let d = Delegate::new(Handlers {
                    events,
                    action: OSSystemExtensionReplacementAction::Cancel,
                    refuse_approval: refuse,
                    done,
                });
                // SAFETY: a request object that is never submitted; the selector
                // and argument are the protocol's.
                unsafe {
                    let r = OSSystemExtensionRequest::new();
                    let _: () = msg_send![&*d, requestNeedsUserApproval: &*r];
                }
            });
            assert_eq!(*seen.lock().unwrap(), want_events);
            if want_err {
                assert!(matches!(reply, Ok(Err(AppleError::ApprovalRequired))));
            } else {
                // Not refused: nothing resolved, and the delegate was dropped.
                assert_eq!(reply.err(), Some(AppleError::HandlerDropped));
            }
        }
    }
}
