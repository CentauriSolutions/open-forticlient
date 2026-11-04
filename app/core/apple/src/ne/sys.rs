//! The unsafe edge of the provider: the Objective-C class, and the helpers that
//! let a copied completion block and a main-queue closure cross threads.
//!
//! Small and generic on purpose. Nothing here knows about tunnels.

use std::panic::{catch_unwind, AssertUnwindSafe};

use block2::{DynBlock, RcBlock};
use dispatch2::DispatchQueue;
use objc2::rc::{autoreleasepool, Retained, Weak};
use objc2::runtime::AnyObject;
use objc2::{define_class, ClassType, Message};
use objc2_foundation::{NSData, NSDictionary, NSError, NSString};
use objc2_network_extension::{NEPacketTunnelProvider, NEProviderStopReason};
use oftc_provider::provider::Failure;

use super::provider;

/// A completion block NetworkExtension handed us, copied to the heap so it can
/// be completed from a worker thread or the main queue.
pub struct SendBlock<T: ?Sized>(RcBlock<T>);

// SAFETY: a copied heap block is an immutable, reference-counted object that
// NetworkExtension documents as callable once, from any thread. This wrapper
// moves it between threads and never shares it: it is neither `Sync` nor
// `Clone`, so exactly one thread owns a given copy at a time.
unsafe impl<T: ?Sized> Send for SendBlock<T> {}

impl<T: ?Sized> SendBlock<T> {
    pub fn copy(block: &DynBlock<T>) -> Self {
        Self(block.copy())
    }

    pub fn block(&self) -> &DynBlock<T> {
        &self.0
    }
}

/// Run `f`, turning a Rust panic or an Objective-C exception into `false`.
/// Both must stay out of `extern "C"` trampolines: a panic there aborts the
/// process, and an exception unwinding through Rust is undefined behaviour.
pub fn guarded(f: impl FnOnce()) -> bool {
    catch_unwind(AssertUnwindSafe(|| {
        objc2::exception::catch(AssertUnwindSafe(f)).is_ok()
    }))
    .unwrap_or(false)
}

/// Post `f` to the main queue. Every Objective-C object is created and released
/// inside `f`, so the main queue's per-block autorelease pool drains it.
pub fn on_main(f: impl FnOnce() + Send + 'static) {
    DispatchQueue::main().exec_async(move || {
        guarded(f);
    });
}

/// Run `f` in an autorelease pool, for worker threads that have none.
pub fn pooled<R>(f: impl FnOnce() -> R) -> R {
    autoreleasepool(|_| f())
}

type StartDone = SendBlock<dyn Fn(*mut NSError)>;
type StopDone = SendBlock<dyn Fn()>;
type ReplyDone = SendBlock<dyn Fn(*mut NSData)>;

pub fn complete_start(done: StartDone, result: Result<(), Failure>) {
    on_main(move || {
        let error = result.err().map(provider::ns_error);
        let pointer = error
            .as_ref()
            .map_or(std::ptr::null_mut(), |e| Retained::as_ptr(e).cast_mut());
        done.block().call((pointer,));
    });
}

pub fn complete_stop(done: StopDone) {
    on_main(move || done.block().call(()));
}

pub fn complete_reply(done: Option<ReplyDone>, reply: Option<Vec<u8>>) {
    let Some(done) = done else { return };
    on_main(move || {
        let data = reply.map(|bytes| NSData::with_bytes(&bytes));
        let pointer = data
            .as_ref()
            .map_or(std::ptr::null_mut(), |d| Retained::as_ptr(d).cast_mut());
        done.block().call((pointer,));
    });
}

/// An `NSError` with a localized description.
pub fn ns_error(domain: &str, code: i32, description: &str) -> Retained<NSError> {
    let key = NSString::from_str("NSLocalizedDescription");
    let value: Retained<AnyObject> =
        Retained::into_super(Retained::into_super(NSString::from_str(description)));
    let info = NSDictionary::from_retained_objects(&[&*key], &[value]);
    // SAFETY: both strings are valid, and the dictionary is a valid userInfo.
    unsafe {
        NSError::errorWithDomain_code_userInfo(
            &NSString::from_str(domain),
            code as isize,
            Some(&info),
        )
    }
}

define_class!(
    #[unsafe(super(NEPacketTunnelProvider))]
    #[name = "OFTCPacketTunnelProvider"]
    pub struct OftcProvider;

    impl OftcProvider {
        #[unsafe(method(startTunnelWithOptions:completionHandler:))]
        fn start_tunnel(
            &self,
            options: Option<&NSDictionary<NSString, AnyObject>>,
            completion: &DynBlock<dyn Fn(*mut NSError)>,
        ) {
            // The block is copied outside the panic guard so a panic still
            // completes it (with stage 900) instead of leaving NE waiting.
            let done = SendBlock::copy(completion);
            let options = provider::start_options(options);
            // `self` is borrowed; the engine factory gets a weak reference so
            // the engine never keeps the provider object alive.
            let weak = Weak::from_retained(&self.retain_as_super());
            provider::begin_start(weak, options, done);
        }

        #[unsafe(method(stopTunnelWithReason:completionHandler:))]
        fn stop_tunnel(&self, _reason: NEProviderStopReason, completion: &DynBlock<dyn Fn()>) {
            let done = SendBlock::copy(completion);
            provider::begin_stop(done);
        }

        #[unsafe(method(handleAppMessage:completionHandler:))]
        fn handle_app_message(
            &self,
            message: &NSData,
            completion: Option<&DynBlock<dyn Fn(*mut NSData)>>,
        ) {
            let done = completion.map(SendBlock::copy);
            provider::begin_message(message.to_vec(), done);
        }
    }
);

impl OftcProvider {
    fn retain_as_super(&self) -> Retained<NEPacketTunnelProvider> {
        Retained::into_super(self.retain())
    }
}

/// Force class registration (objc2 registers lazily) before NetworkExtension
/// looks the class up by name.
pub fn register() -> &'static objc2::runtime::AnyClass {
    OftcProvider::class()
}

#[cfg(test)]
mod tests {
    use objc2::runtime::Sel;
    use objc2::sel;
    use objc2_network_extension::NEProvider;

    use super::*;

    /// The class name is what `NEProviderClasses` in Info.plist refers to, and
    /// each selector is an override: a typo in a selector would still compile
    /// but leave the superclass's implementation in place, failing only live.
    #[test]
    fn class_is_registered_under_its_plist_name_and_overrides_the_entry_points() {
        // Referencing NEProvider makes a plain test binary link NetworkExtension.
        let _ = NEProvider::class();
        let class = register();
        assert_eq!(class.name().to_str(), Ok("OFTCPacketTunnelProvider"));
        let superclass = class.superclass().expect("superclass");
        assert_eq!(superclass.name().to_str(), Ok("NEPacketTunnelProvider"));
        let selectors: [Sel; 3] = [
            sel!(startTunnelWithOptions:completionHandler:),
            sel!(stopTunnelWithReason:completionHandler:),
            sel!(handleAppMessage:completionHandler:),
        ];
        for selector in selectors {
            let ours = class
                .instance_method(selector)
                .expect("our method")
                .implementation();
            let theirs = superclass
                .instance_method(selector)
                .expect("super method")
                .implementation();
            assert_ne!(
                ours as usize, theirs as usize,
                "{selector:?} is not overridden"
            );
        }
    }
}
