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
use std::sync::{Arc, Condvar, Mutex, OnceLock, PoisonError};
use std::thread;

use objc2::rc::{Retained, Weak};
use objc2::runtime::AnyObject;
use objc2_foundation::{NSData, NSDictionary, NSError, NSString};
use objc2_network_extension::NEPacketTunnelProvider;
use oftc_provider::envelope::{
    OptionValue, Secret, StartOptions, LIVE_KEY, MODE_KEY, PREFLIGHT_KEY,
};
use oftc_provider::link::Backend;
use oftc_provider::provider::{Failure, Provider};

use super::sys::{self, SendBlock};
use super::tunnel::{Host, MainQueue, NeTunnel};

/// `NSError` domain the host logs (the Swift provider's).
pub const ERROR_DOMAIN: &str = "OFTCProvider";
/// A worker panicked, or the provider could not be set up.
const PANICKED: Failure = Failure(900);

/// What the glue needs from the provider logic: `Provider<B, NeTunnel>` in
/// production. Object-safe so it can live in a static.
pub trait Engine: Send + Sync {
    /// Bring the tunnel up. Blocks.
    fn start(&self, options: &StartOptions) -> Result<(), Failure>;
    /// Called by the glue on the start thread immediately after the start
    /// completion was enqueued on the main queue, on every path that ran
    /// [`start`](Self::start), including a failed or panicked one. It is *not*
    /// called when there was no engine to run or the thread could not be
    /// spawned (nothing was started, so nothing can fail afterwards).
    /// `on_failure` waits on it so the host sees the start complete before the
    /// cancel, and then posts `cancelTunnelWithError` through the main queue.
    fn start_completion_enqueued(&self) {}
    /// Stop the tunnel and wait for cleanup. Blocks.
    fn stop(&self);
    /// Answer a provider message. Blocks.
    fn handle_message(&self, message: &[u8]) -> Option<Vec<u8>>;
}

/// Builds the engine on the first `startTunnel`. Given a weak reference to the
/// provider object, because the engine must not keep it alive.
pub type Factory = Box<dyn FnOnce(Weak<NEPacketTunnelProvider>) -> Box<dyn Engine> + Send>;

static FACTORY: Mutex<Option<Factory>> = Mutex::new(None);
static ENGINE: OnceLock<Box<dyn Engine>> = OnceLock::new();

/// Register how to build the engine. Hands the factory back if one is already
/// registered.
pub fn install_factory(factory: Factory) -> Result<(), Factory> {
    let mut slot = FACTORY.lock().unwrap_or_else(PoisonError::into_inner);
    if slot.is_some() || ENGINE.get().is_some() {
        return Err(factory);
    }
    *slot = Some(factory);
    Ok(())
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

/// Complete a start block on the main queue: nil on success, else the `NSError`.
fn complete_start(queue: &dyn MainQueue, done: StartDone, result: Result<(), Failure>) {
    queue.post(Box::new(move || complete_start_now(done, result)));
}

fn complete_stop(queue: &dyn MainQueue, done: StopDone) {
    queue.post(Box::new(move || done.block().call(())));
}

fn complete_reply(queue: &dyn MainQueue, done: Option<ReplyDone>, reply: Option<Vec<u8>>) {
    let Some(done) = done else { return };
    queue.post(Box::new(move || {
        let data = reply.map(|bytes| NSData::with_bytes(&bytes));
        let pointer = data
            .as_ref()
            .map_or(std::ptr::null_mut(), |d| Retained::as_ptr(d).cast_mut());
        done.block().call((pointer,));
    }));
}

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
    // Held across the build so a concurrent first start sees the engine, not
    // an empty factory.
    let mut slot = FACTORY.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(engine) = ENGINE.get() {
        return Some(&**engine);
    }
    let factory = slot.take()?;
    let built = catch_unwind(AssertUnwindSafe(|| factory(provider))).ok()?;
    Some(&**ENGINE.get_or_init(|| built))
}

/// The start thread's body: run the start, post its completion to the main
/// queue, then release anything waiting for that completion to be enqueued.
fn start_body(
    queue: &dyn MainQueue,
    engine: &dyn Engine,
    options: &StartOptions,
    complete: impl FnOnce(Result<(), Failure>) + Send + 'static,
) {
    let result = catch_unwind(AssertUnwindSafe(|| engine.start(options))).unwrap_or(Err(PANICKED));
    queue.post(Box::new(move || complete(result)));
    // A panic here must not skip the latch, or a failure waits forever.
    let _ = catch_unwind(AssertUnwindSafe(|| engine.start_completion_enqueued()));
}

/// Complete a start whose setup panicked before anything ran.
pub fn fail_start(done: StartDone) {
    complete_start(&sys::MainDispatch, done, Err(PANICKED));
}

pub fn begin_start(provider: Weak<NEPacketTunnelProvider>, options: StartOptions, done: StartDone) {
    let queue = &sys::MainDispatch;
    let Some(engine) = engine(provider) else {
        complete_start(queue, done, Err(PANICKED));
        return;
    };
    if let Err(done) = spawn_owning("oftc-start", done, move |done| {
        sys::pooled(|| {
            start_body(queue, engine, &options, move |result| {
                complete_start_now(done, result);
            });
        });
    }) {
        complete_start(queue, done, Err(PANICKED));
    }
}

/// Run on the main queue: complete the block directly.
fn complete_start_now(done: StartDone, result: Result<(), Failure>) {
    let error = result.err().map(ns_error);
    let pointer = error
        .as_ref()
        .map_or(std::ptr::null_mut(), |e| Retained::as_ptr(e).cast_mut());
    done.block().call((pointer,));
}

pub fn begin_stop(done: StopDone) {
    let queue = &sys::MainDispatch;
    let Some(engine) = ENGINE.get() else {
        complete_stop(queue, done);
        return;
    };
    if let Err(done) = spawn_owning("oftc-stop", done, move |done| {
        sys::pooled(|| {
            let _ = catch_unwind(AssertUnwindSafe(|| engine.stop()));
            complete_stop(queue, done);
        });
    }) {
        complete_stop(queue, done);
    }
}

pub fn begin_message(message: Vec<u8>, done: Option<ReplyDone>) {
    let queue = &sys::MainDispatch;
    let Some(engine) = ENGINE.get() else {
        complete_reply(queue, done, None);
        return;
    };
    if let Err((_, done)) = spawn_owning("oftc-message", (message, done), move |(message, done)| {
        sys::pooled(|| {
            let reply =
                catch_unwind(AssertUnwindSafe(|| engine.handle_message(&message))).unwrap_or(None);
            complete_reply(queue, done, reply);
        });
    }) {
        complete_reply(queue, done, None);
    }
}

/// Set once the start completion has been enqueued on the main queue.
#[derive(Default)]
pub struct Latch {
    set: Mutex<bool>,
    changed: Condvar,
}

impl Latch {
    pub fn set(&self) {
        *self.set.lock().unwrap_or_else(PoisonError::into_inner) = true;
        self.changed.notify_all();
    }

    /// Block until [`set`](Self::set). The start thread always reaches it, so
    /// this is bounded.
    pub fn wait(&self) {
        let mut set = self.set.lock().unwrap_or_else(PoisonError::into_inner);
        while !*set {
            set = self
                .changed
                .wait(set)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }
}

/// `Provider`'s `on_failure`: wait until the start completion is enqueued, then
/// post `cancelTunnelWithError`. Two threads posting to the main queue are not
/// ordered, so without the latch the host could see the cancel first.
pub fn failure_hook(
    latch: Arc<Latch>,
    queue: Arc<dyn MainQueue>,
    host: Arc<dyn Host>,
) -> impl Fn(Failure) + Send + Sync + 'static {
    move |failure| {
        latch.wait();
        let host = Arc::clone(&host);
        queue.post(Box::new(move || host.cancel(failure)));
    }
}

/// `Provider<B, NeTunnel>` as an [`Engine`], plus the latch.
struct NeEngine<B: Backend> {
    provider: Provider<B, NeTunnel>,
    latch: Arc<Latch>,
}

impl<B: Backend> Engine for NeEngine<B> {
    fn start(&self, options: &StartOptions) -> Result<(), Failure> {
        self.provider.start(options)
    }
    fn start_completion_enqueued(&self) {
        self.latch.set();
    }
    fn stop(&self) {
        self.provider.stop();
    }
    fn handle_message(&self, message: &[u8]) -> Option<Vec<u8>> {
        self.provider.handle_message(message)
    }
}

fn build_engine<B: Backend>(backend: B, provider: Weak<NEPacketTunnelProvider>) -> Box<dyn Engine> {
    let queue: Arc<dyn MainQueue> = Arc::new(sys::MainDispatch);
    let host: Arc<dyn Host> = Arc::new(sys::NeHost::new(provider));
    let latch = Arc::new(Latch::default());
    let tunnel = NeTunnel::new(Arc::clone(&queue), Arc::clone(&host));
    let on_failure = failure_hook(Arc::clone(&latch), queue, host);
    Box::new(NeEngine {
        provider: Provider::new(backend, tunnel, on_failure),
        latch,
    })
}

/// The extension process's entry point: register the provider class over
/// `backend`, hand control to NetworkExtension and run the main queue. The
/// engine is built on the first `startTunnel`, never dropped.
pub fn run<B: Backend>(backend: B) -> ! {
    let installed = install_factory(Box::new(move |provider| build_engine(backend, provider)));
    assert!(installed.is_ok(), "run called twice");
    sys::run_extension()
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

    use std::sync::mpsc;
    use std::time::Duration;

    use block2::RcBlock;

    use super::super::tunnel::fake::{FakeHost, FakeQueue};

    struct TestEngine {
        latch: Arc<Latch>,
        outcome: Result<(), Failure>,
    }

    impl Engine for TestEngine {
        fn start(&self, _options: &StartOptions) -> Result<(), Failure> {
            // Long enough for the failure thread to be waiting on the latch.
            thread::sleep(Duration::from_millis(30));
            self.outcome
        }
        fn start_completion_enqueued(&self) {
            self.latch.set();
        }
        fn stop(&self) {}
        fn handle_message(&self, _message: &[u8]) -> Option<Vec<u8>> {
            None
        }
    }

    /// A failure raised right after `start` returns must reach the host after
    /// the start completion, although a different thread posts it.
    #[test]
    fn the_cancel_is_posted_after_the_start_completion_even_on_a_failed_start() {
        for outcome in [Ok(()), Err(Failure(100))] {
            let queue = FakeQueue::new();
            let host = FakeHost::new();
            let latch = Arc::new(Latch::default());
            let hook = failure_hook(latch.clone(), queue.clone(), host.clone());
            let failing = thread::spawn(move || hook(Failure(300)));

            let engine = TestEngine { latch, outcome };
            let log = host.clone();
            start_body(&*queue, &engine, &StartOptions::default(), move |_| {
                log.log.lock().unwrap().push("completion");
            });
            failing.join().unwrap();
            // The queue is FIFO and single-threaded: wait for both bodies.
            let (sender, receiver) = mpsc::channel();
            queue.post(Box::new(move || sender.send(()).unwrap()));
            receiver.recv().unwrap();
            assert_eq!(*host.log.lock().unwrap(), ["completion", "cancel"]);
        }
    }

    /// A completion block copied on the NetworkExtension thread is completed
    /// from the queue's thread, with nil on success and the `NSError` on failure.
    #[test]
    #[allow(unsafe_code)]
    fn a_copied_start_block_is_completed_on_the_queue_with_nil_or_the_error() {
        let queue = FakeQueue::new();
        let (sender, receiver) = mpsc::channel();
        let block = RcBlock::new(move |error: *mut NSError| {
            // SAFETY: the pointer is nil or valid for the call.
            let seen = unsafe { error.as_ref() }.map(|e| (e.domain().to_string(), e.code()));
            sender.send((seen, thread::current().id())).unwrap();
        });
        let heap = block2::DynBlock::copy(&block);
        let ok = SendBlock::copy(&heap);
        complete_start(&*queue, ok, Ok(()));
        let (seen, ran_on) = receiver.recv().unwrap();
        assert_eq!(seen, None);
        assert_ne!(ran_on, thread::current().id());
        complete_start(&*queue, SendBlock::copy(&heap), Err(Failure(7)));
        assert_eq!(
            receiver.recv().unwrap().0,
            Some(("OFTCProvider".to_string(), 7))
        );
    }
}
