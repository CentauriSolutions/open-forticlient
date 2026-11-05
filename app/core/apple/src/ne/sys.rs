//! The unsafe edge of the provider: the Objective-C class, and the helpers that
//! let a copied completion block and a main-queue closure cross threads.
//!
//! Small and generic on purpose. Nothing here knows about tunnels.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr::NonNull;

use block2::{DynBlock, RcBlock};
use dispatch2::DispatchQueue;
use objc2::rc::{autoreleasepool, Retained, Weak};
use objc2::runtime::AnyObject;
use objc2::{define_class, AnyThread, ClassType, Message};
use objc2_foundation::{
    MainThreadMarker, NSArray, NSData, NSDictionary, NSError, NSNumber, NSString,
};
use objc2_network_extension::{
    NEDNSSettings, NEIPv4Route, NEIPv4Settings, NEPacketTunnelNetworkSettings,
    NEPacketTunnelProvider, NEProvider, NEProviderStopReason,
};
use oftc_provider::provider::Failure;

use super::provider;
use super::tunnel::{Host, MainQueue, ReadDone, SettingsDone, AF_INET};
use crate::objc::guarded;
use crate::settings::{NeRoute, NeSettings};

/// A completion block NetworkExtension handed us, copied to the heap so it can
/// be completed from a worker thread or the main queue.
pub struct SendBlock<T: ?Sized>(RcBlock<T>);

// SAFETY: a copied heap block is an immutable, reference-counted object, so
// moving the one owning reference to another thread is sound. Whether
// NetworkExtension tolerates its handler being *called* from a thread other
// than the one it was delivered on is not documented; the glue therefore calls
// every block from the main queue, and the live gate (#48) observes it. The
// wrapper is neither `Sync` nor `Clone`: one thread owns a given copy at a time.
unsafe impl<T: ?Sized> Send for SendBlock<T> {}

impl<T: ?Sized> SendBlock<T> {
    pub fn copy(block: &DynBlock<T>) -> Self {
        Self(block.copy())
    }

    pub fn block(&self) -> &DynBlock<T> {
        &self.0
    }
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
            // The block is copied first and kept outside every panic guard, so
            // a panic anywhere below still completes it (stage 900).
            let done = SendBlock::copy(completion);
            // `self` is borrowed; the engine factory gets a weak reference so
            // the engine never keeps the provider object alive.
            let prepared = catch_unwind(AssertUnwindSafe(|| {
                (
                    provider::start_options(options),
                    Weak::from_retained(&self.retain_as_super()),
                )
            }));
            match prepared {
                Ok((options, weak)) => provider::begin_start(self.key(), weak, options, done),
                Err(_) => provider::fail_start(done),
            }
        }

        #[unsafe(method(stopTunnelWithReason:completionHandler:))]
        fn stop_tunnel(&self, _reason: NEProviderStopReason, completion: &DynBlock<dyn Fn()>) {
            let done = SendBlock::copy(completion);
            provider::begin_stop(self.key(), done);
        }

        #[unsafe(method(handleAppMessage:completionHandler:))]
        fn handle_app_message(
            &self,
            message: &NSData,
            completion: Option<&DynBlock<dyn Fn(*mut NSData)>>,
        ) {
            let done = completion.map(SendBlock::copy);
            provider::begin_message(self.key(), message.to_vec(), done);
        }
    }
);

impl OftcProvider {
    /// This object's identity, which keys its engine.
    fn key(&self) -> provider::Key {
        std::ptr::from_ref(self) as provider::Key
    }

    fn retain_as_super(&self) -> Retained<NEPacketTunnelProvider> {
        Retained::into_super(self.retain())
    }
}

/// Force class registration (objc2 registers lazily) before NetworkExtension
/// looks the class up by name.
pub fn register() -> &'static objc2::runtime::AnyClass {
    OftcProvider::class()
}

/// The real main queue.
pub struct MainDispatch;

impl MainQueue for MainDispatch {
    fn post(&self, work: Box<dyn FnOnce() + Send>) {
        on_main(work);
    }

    fn is_main(&self) -> bool {
        MainThreadMarker::new().is_some()
    }
}

/// A weak reference to the provider object, used only on the main queue.
struct MainOnly(Weak<NEPacketTunnelProvider>);

// SAFETY: the reference is created on the NetworkExtension calling thread and
// afterwards upgraded and dereferenced only inside main-queue closures (every
// `NeHost` method runs on the main queue); moving or dropping a weak reference
// on another thread is thread-safe in the Objective-C runtime.
unsafe impl Send for MainOnly {}
unsafe impl Sync for MainOnly {}

/// The real NetworkExtension calls. Every method runs on the main queue.
pub struct NeHost(MainOnly);

impl NeHost {
    pub fn new(provider: Weak<NEPacketTunnelProvider>) -> Self {
        Self(MainOnly(provider))
    }

    fn provider(&self) -> Option<Retained<NEPacketTunnelProvider>> {
        self.0 .0.load()
    }
}

fn strings(values: &[String]) -> Retained<NSArray<NSString>> {
    let values: Vec<Retained<NSString>> = values.iter().map(|v| NSString::from_str(v)).collect();
    NSArray::from_retained_slice(&values)
}

fn routes(values: &[NeRoute]) -> Retained<NSArray<NEIPv4Route>> {
    let values: Vec<Retained<NEIPv4Route>> = values
        .iter()
        .map(|route| unsafe {
            NEIPv4Route::initWithDestinationAddress_subnetMask(
                NEIPv4Route::alloc(),
                &NSString::from_str(&route.destination),
                &NSString::from_str(&route.mask),
            )
        })
        .collect();
    NSArray::from_retained_slice(&values)
}

fn network_settings(settings: &NeSettings) -> Retained<NEPacketTunnelNetworkSettings> {
    // SAFETY: plain property setters and initialisers on freshly created
    // objects, with valid strings and arrays.
    unsafe {
        let network = NEPacketTunnelNetworkSettings::initWithTunnelRemoteAddress(
            NEPacketTunnelNetworkSettings::alloc(),
            &NSString::from_str(&settings.remote_address),
        );
        let ipv4 = NEIPv4Settings::initWithAddresses_subnetMasks(
            NEIPv4Settings::alloc(),
            &strings(std::slice::from_ref(&settings.address)),
            &strings(std::slice::from_ref(&settings.subnet_mask)),
        );
        ipv4.setIncludedRoutes(Some(&routes(&settings.included_routes)));
        if !settings.excluded_routes.is_empty() {
            ipv4.setExcludedRoutes(Some(&routes(&settings.excluded_routes)));
        }
        network.setIPv4Settings(Some(&ipv4));
        if let Some(dns) = &settings.dns {
            let block =
                NEDNSSettings::initWithServers(NEDNSSettings::alloc(), &strings(&dns.servers));
            block.setMatchDomains(Some(&strings(&dns.match_domains)));
            if !dns.search_domains.is_empty() {
                block.setSearchDomains(Some(&strings(&dns.search_domains)));
            }
            block.setMatchDomainsNoSearch(dns.match_domains_no_search);
            network.setDNSSettings(Some(&block));
        }
        network.setMTU(Some(&NSNumber::new_u32(settings.mtu)));
        network
    }
}

/// A one-shot completion that an `Fn` block can call: taken on first use.
fn once<A: 'static>(f: impl FnOnce(A) + 'static) -> impl Fn(A) {
    let cell = std::cell::RefCell::new(Some(f));
    move |argument| {
        if let Some(f) = cell.borrow_mut().take() {
            f(argument);
        }
    }
}

impl Host for NeHost {
    fn set_settings(&self, settings: Option<NeSettings>, done: SettingsDone) {
        let Some(provider) = self.provider() else {
            return done(false);
        };
        let handler = RcBlock::new(once(move |error: *mut NSError| done(error.is_null())));
        let network = settings.as_ref().map(network_settings);
        // SAFETY: called on the main queue with a valid settings object (or
        // nil to clear) and a handler block.
        unsafe {
            provider.setTunnelNetworkSettings_completionHandler(
                network.as_deref().map(|n| n.as_super()),
                Some(&handler),
            );
        }
    }

    fn read_packets(&self, done: ReadDone) {
        let Some(provider) = self.provider() else {
            // The flow is gone: leave the read unanswered. Dropping `done`
            // closes the tunnel; an empty answer would be re-issued forever.
            drop(done);
            return;
        };
        // The arrays are valid only during the call: copy into owned vectors.
        // `RcBlock::new` takes an `Fn`, so the one-shot completion is taken on
        // first call.
        let done = std::cell::RefCell::new(Some(done));
        let handler = RcBlock::new(
            move |packets: NonNull<NSArray<NSData>>, protocols: NonNull<NSArray<NSNumber>>| {
                let Some(done) = done.borrow_mut().take() else {
                    return;
                };
                // SAFETY: NetworkExtension passes valid arrays for the
                // duration of the completion.
                let (packets, protocols) = unsafe { (packets.as_ref(), protocols.as_ref()) };
                done(
                    packets.iter().map(|data| data.to_vec()).collect(),
                    protocols.iter().map(|number| number.intValue()).collect(),
                );
            },
        );
        // SAFETY: main queue; the handler is a valid block.
        unsafe {
            provider
                .packetFlow()
                .readPacketsWithCompletionHandler(&handler)
        };
    }

    fn write_packet(&self, packet: &[u8]) -> bool {
        let Some(provider) = self.provider() else {
            return false;
        };
        pooled(|| unsafe {
            let data = NSData::with_bytes(packet);
            let packets = NSArray::from_retained_slice(&[data]);
            let protocols = NSArray::from_retained_slice(&[NSNumber::new_i32(AF_INET)]);
            provider
                .packetFlow()
                .writePackets_withProtocols(&packets, &protocols)
        })
    }

    fn cancel(&self, failure: Failure) {
        let Some(provider) = self.provider() else {
            return;
        };
        let error = ns_error(
            super::provider::ERROR_DOMAIN,
            failure.0,
            &failure.to_string(),
        );
        // SAFETY: main queue, valid error.
        unsafe { provider.cancelTunnelWithError(Some(&error)) };
    }
}

/// Hand the process to NetworkExtension: register the class, enter system
/// extension mode and run the main queue. Never returns.
pub fn run_extension() -> ! {
    pooled(|| {
        register();
        // SAFETY: called once, early, from the main thread, as documented.
        unsafe { NEProvider::startSystemExtensionMode() };
    });
    dispatch2::dispatch_main()
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
