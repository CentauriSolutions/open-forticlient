//! Smallest possible Rust packet tunnel provider: registers an Objective-C
//! class under a plain name and hands control to NetworkExtension.
//!
//! `--check-class` registers the class, resolves it by name like NetworkExtension
//! does for NEProviderClasses, prints what it found, and exits. It needs no
//! entitlement and touches no system state.

use block2::DynBlock;
use objc2::rc::Retained;
use objc2::runtime::AnyClass;
use objc2::{define_class, ClassType};
use objc2_foundation::{NSDictionary, NSError, NSString};
use objc2_network_extension::{NEProvider, NEPacketTunnelProvider, NEProviderStopReason};
use std::ffi::{c_int, CStr};

const CLASS_NAME: &CStr = c"OFTCPacketTunnelProvider";

define_class!(
    #[unsafe(super(NEPacketTunnelProvider))]
    #[name = "OFTCPacketTunnelProvider"]
    struct Provider;

    impl Provider {
        #[unsafe(method(startTunnelWithOptions:completionHandler:))]
        fn start_tunnel(
            &self,
            _options: Option<&NSDictionary<NSString, objc2::runtime::AnyObject>>,
            completion: &DynBlock<dyn Fn(*mut NSError)>,
        ) {
            eprintln!("OFTC spike provider: startTunnel");
            completion.call((std::ptr::null_mut(),));
        }

        #[unsafe(method(stopTunnelWithReason:completionHandler:))]
        fn stop_tunnel(&self, _reason: NEProviderStopReason, completion: &DynBlock<dyn Fn()>) {
            eprintln!("OFTC spike provider: stopTunnel");
            completion.call(());
        }
    }
);

unsafe extern "C" {
    fn dispatch_main() -> !;
}

fn main() {
    // Registration is lazy in objc2: touch the class so the runtime knows it
    // before NetworkExtension looks it up by name.
    let class = Provider::class();
    if std::env::args().any(|a| a == "--check-class") {
        let found = AnyClass::get(CLASS_NAME).map(|c| (c.name().to_string_lossy().into_owned(),
            c.superclass().map(|s| s.name().to_string_lossy().into_owned())));
        println!("registered: {}", class.name().to_string_lossy());
        println!("by-name lookup: {found:?}");
        std::process::exit(if found.is_some() { 0 } else { 1 });
    }
    let _: Option<Retained<NEProvider>> = None; // keep the NEProvider binding linked
    unsafe {
        NEProvider::startSystemExtensionMode();
        let _: c_int = 0;
        dispatch_main()
    }
}
