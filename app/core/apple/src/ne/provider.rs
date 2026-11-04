//! Safe glue between the three NetworkExtension entry points and the provider
//! logic: threads, error conversion and option conversion.
//!
//! Rule 1: the main queue is never blocked. [`Engine`] calls block, so every
//! entry point copies its completion block, hands the work to a thread and
//! returns; the thread posts the completion back to the main queue.
//!
//! One provider per process: the engine lives in a static, is created on the
//! first `startTunnel`, and is never dropped (its `Drop` blocks, so it must not
//! run on the main thread, and process exit does not run it).

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::thread;

use objc2::rc::{Retained, Weak};
use objc2::runtime::AnyObject;
use objc2_foundation::{NSData, NSDictionary, NSError, NSString};
use objc2_network_extension::NEPacketTunnelProvider;
use oftc_provider::envelope::{
    OptionValue, Secret, StartOptions, LIVE_KEY, MODE_KEY, PREFLIGHT_KEY,
};
use oftc_provider::provider::Failure;

use super::sys::{self, SendBlock};

/// `NSError` domain the host logs (the Swift provider's).
pub const ERROR_DOMAIN: &str = "OFTCProvider";
/// A worker panicked, or the provider could not be set up.
const PANICKED: Failure = Failure(900);

/// What the glue needs from the provider logic: `Provider<B, NeTunnel>` in
/// production. Object-safe so it can live in a static.
pub trait Engine: Send + Sync {
    /// Bring the tunnel up. Blocks.
    fn start(&self, options: &StartOptions) -> Result<(), Failure>;
    /// Called by the glue immediately after the start completion was enqueued
    /// on the main queue, on the start thread, on every path including a
    /// failed or panicked start. `on_failure` waits on this so the host sees
    /// the start complete before the cancel.
    fn start_completion_enqueued(&self) {}
    /// Stop the tunnel and wait for cleanup. Blocks.
    fn stop(&self);
    /// Answer a provider message. Blocks.
    fn handle_message(&self, message: &[u8]) -> Option<Vec<u8>>;
}

/// Builds the engine on the first `startTunnel`. Given a weak reference to the
/// provider object, because the engine must not keep it alive.
pub type Factory = Box<dyn Fn(Weak<NEPacketTunnelProvider>) -> Box<dyn Engine> + Send + Sync>;

static FACTORY: OnceLock<Factory> = OnceLock::new();
static ENGINE: OnceLock<Box<dyn Engine>> = OnceLock::new();

/// Register how to build the engine. Hands the factory back if one is already
/// registered.
pub fn install_factory(factory: Factory) -> Result<(), Factory> {
    FACTORY.set(factory)
}

/// Register the provider class and return its name, so the system can find it.
pub fn register_class() -> String {
    sys::register().name().to_string_lossy().into_owned()
}

/// `NSError` for a failure: the Swift provider's domain, the failure code and
/// the `OFTC provider stage N failed` description.
pub fn ns_error(failure: Failure) -> Retained<NSError> {
    sys::ns_error(ERROR_DOMAIN, failure.0, &failure.to_string())
}

fn lookup(options: &NSDictionary<NSString, AnyObject>, key: &str) -> Option<OptionValue> {
    let value = options.objectForKey(&NSString::from_str(key))?;
    Some(match value.downcast_ref::<NSData>() {
        // Copied once into a type that zeroes on drop; NE's own copy cannot be
        // wiped, as in the Swift provider.
        Some(data) => OptionValue::Data(Secret::new(data.to_vec())),
        None => OptionValue::NotData,
    })
}

/// `options[key] as? NSData`, per key. Every accept or reject decision stays in
/// `envelope::consume`.
pub fn start_options(options: Option<&NSDictionary<NSString, AnyObject>>) -> StartOptions {
    let Some(options) = options else {
        return StartOptions::default();
    };
    StartOptions {
        live: lookup(options, LIVE_KEY),
        preflight: lookup(options, PREFLIGHT_KEY),
        mode: lookup(options, MODE_KEY),
    }
}

type StartDone = SendBlock<dyn Fn(*mut NSError)>;
type StopDone = SendBlock<dyn Fn()>;
type ReplyDone = SendBlock<dyn Fn(*mut NSData)>;

/// Hand `value` to a new thread. If the thread cannot be spawned the value
/// comes back, so a completion block is never lost and NetworkExtension never
/// waits forever.
fn spawn_owning<T: Send + 'static>(
    name: &str,
    value: T,
    body: impl FnOnce(T) + Send + 'static,
) -> Result<(), T> {
    let cell = Arc::new(Mutex::new(Some(value)));
    let theirs = Arc::clone(&cell);
    let spawned = thread::Builder::new().name(name.into()).spawn(move || {
        let value = theirs.lock().unwrap_or_else(PoisonError::into_inner).take();
        if let Some(value) = value {
            body(value);
        }
    });
    match spawned {
        Ok(_) => Ok(()),
        Err(_) => Err(cell
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
            .expect("a thread that was never spawned cannot have taken the value")),
    }
}

/// The engine, created on first use. `None` if no factory was registered or
/// building the engine panicked.
fn engine(provider: Weak<NEPacketTunnelProvider>) -> Option<&'static dyn Engine> {
    if let Some(engine) = ENGINE.get() {
        return Some(&**engine);
    }
    let factory = FACTORY.get()?;
    catch_unwind(AssertUnwindSafe(|| {
        &**ENGINE.get_or_init(|| factory(provider))
    }))
    .ok()
}

pub fn begin_start(provider: Weak<NEPacketTunnelProvider>, options: StartOptions, done: StartDone) {
    let Some(engine) = engine(provider) else {
        sys::complete_start(done, Err(PANICKED));
        return;
    };
    if let Err(done) = spawn_owning("oftc-start", done, move |done| {
        sys::pooled(|| {
            let result =
                catch_unwind(AssertUnwindSafe(|| engine.start(&options))).unwrap_or(Err(PANICKED));
            sys::complete_start(done, result);
            // A panic here must not skip the latch, or a failure waits forever.
            let _ = catch_unwind(AssertUnwindSafe(|| engine.start_completion_enqueued()));
        });
    }) {
        sys::complete_start(done, Err(PANICKED));
    }
}

pub fn begin_stop(done: StopDone) {
    let Some(engine) = ENGINE.get() else {
        sys::complete_stop(done);
        return;
    };
    if let Err(done) = spawn_owning("oftc-stop", done, move |done| {
        sys::pooled(|| {
            let _ = catch_unwind(AssertUnwindSafe(|| engine.stop()));
            sys::complete_stop(done);
        });
    }) {
        sys::complete_stop(done);
    }
}

pub fn begin_message(message: Vec<u8>, done: Option<ReplyDone>) {
    let Some(engine) = ENGINE.get() else {
        sys::complete_reply(done, None);
        return;
    };
    if let Err((_, done)) = spawn_owning("oftc-message", (message, done), move |(message, done)| {
        sys::pooled(|| {
            let reply =
                catch_unwind(AssertUnwindSafe(|| engine.handle_message(&message))).unwrap_or(None);
            sys::complete_reply(done, reply);
        });
    }) {
        sys::complete_reply(done, None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failure_becomes_the_nserror_the_host_logs() {
        let error = ns_error(Failure(5));
        assert_eq!(error.domain().to_string(), "OFTCProvider");
        assert_eq!(error.code(), 5);
        assert_eq!(
            error.localizedDescription().to_string(),
            "OFTC provider stage 5 failed"
        );
    }

    fn any(value: Retained<NSData>) -> Retained<AnyObject> {
        Retained::into_super(Retained::into_super(value))
    }

    #[test]
    fn option_values_map_to_data_notdata_or_absent() {
        let envelope = NSData::with_bytes(b"secret");
        let not_data: Retained<AnyObject> =
            Retained::into_super(Retained::into_super(NSString::from_str("text")));
        let keys = [NSString::from_str(LIVE_KEY), NSString::from_str(MODE_KEY)];
        let dictionary = NSDictionary::from_retained_objects(
            &[&*keys[0], &*keys[1]],
            &[any(envelope), not_data],
        );
        let options = start_options(Some(&dictionary));
        assert!(matches!(&options.live, Some(OptionValue::Data(s)) if s.as_bytes() == b"secret"));
        assert!(matches!(options.mode, Some(OptionValue::NotData)));
        assert!(options.preflight.is_none());
        assert!(start_options(None).live.is_none());
    }
}
