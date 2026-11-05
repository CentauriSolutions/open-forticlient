//! Safe glue between the three NetworkExtension entry points and the provider
//! logic: threads, error conversion and option conversion.
//!
//! Rule 1: the main queue is never blocked. [`Engine`] calls block, so every
//! entry point copies its completion block, hands the work to a thread and
//! returns; the thread posts the completion back to the main queue.
//!
//! One engine per provider object: NetworkExtension keeps the process across a
//! stop and creates a new provider object for every start, and runs several
//! profiles' provider objects in that one process at the same time. An engine
//! is one tunnel's worth of state and refuses to start after a stop, so each
//! `startTunnel` builds a fresh engine and stores it in a static map keyed by
//! the identity of the provider object that started it. Stop and app messages
//! go to the engine of the provider object they were sent to, never to "the
//! latest": another profile's start must not touch this profile's tunnel.
//! Dropping an engine stops it and blocks, so it only ever runs on a worker
//! thread, and only for a provider object whose key is reused (a freed object's
//! address) or after its stop.

use std::collections::BTreeMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, PoisonError};
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

/// Builds an engine for one `startTunnel`. Given a weak reference to that
/// start's provider object, because the engine must not keep it alive.
///
/// NetworkExtension creates a new provider object for every start but keeps the
/// process, and a `Provider` is one tunnel's worth of state (once stopped it
/// refuses to start), so every start gets a fresh engine, and a fresh latch.
pub type Factory = Box<dyn Fn(Weak<NEPacketTunnelProvider>) -> Box<dyn Engine> + Send + Sync>;

type Shared = Arc<dyn Engine>;
type Replaced = (Shared, Option<Shared>);
type Build<A> = Box<dyn Fn(A) -> Box<dyn Engine> + Send + Sync>;

/// Identity of a provider object (its address), for as long as it is alive.
pub type Key = usize;

/// The factory, and the engine of every provider object that has started and
/// not yet been stopped (what stop and messages are routed to).
struct Engines<A> {
    factory: OnceLock<Build<A>>,
    live: Mutex<BTreeMap<Key, Shared>>,
}

static ENGINES: Engines<Weak<NEPacketTunnelProvider>> =
    Engines { factory: OnceLock::new(), live: Mutex::new(BTreeMap::new()) };

/// Register how to build the engine. Hands the factory back if one is already
/// registered.
pub fn install_factory(factory: Factory) -> Result<(), Factory> {
    ENGINES.factory.set(factory)
}

impl<A> Engines<A> {
    fn live(&self) -> MutexGuard<'_, BTreeMap<Key, Shared>> {
        self.live.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The engine of the provider object `key`, if it started and has not stopped.
    fn get(&self, key: Key) -> Option<Shared> {
        self.live().get(&key).cloned()
    }

    /// Forget the engine of `key` once it is stopped.
    fn remove(&self, key: Key) {
        self.live().remove(&key);
    }

    /// Build the engine for a new start of provider object `key`. Returns it
    /// with the engine it replaced, which only exists if the key was reused by
    /// a new object after the old one was freed, and which the caller drops off
    /// the main queue (dropping a provider stops it). Other keys' engines are
    /// never touched. `None` if no factory was registered or building the
    /// engine panicked.
    fn replace(&self, key: Key, arg: A) -> Option<Replaced> {
        let factory = self.factory.get()?;
        let built: Arc<dyn Engine> = catch_unwind(AssertUnwindSafe(|| factory(arg))).ok()?.into();
        let old = self.live().insert(key, Arc::clone(&built));
        Some((built, old))
    }
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

pub fn begin_start(
    key: Key,
    provider: Weak<NEPacketTunnelProvider>,
    options: StartOptions,
    done: StartDone,
) {
    let queue = &sys::MainDispatch;
    let Some((engine, old)) = ENGINES.replace(key, provider) else {
        complete_start(queue, done, Err(PANICKED));
        return;
    };
    if let Err((done, _)) = spawn_owning("oftc-start", (done, old), move |(done, old)| {
        sys::pooled(|| {
            // Only a freed provider object's engine can be here; drop it here.
            drop(old);
            start_body(queue, &*engine, &options, move |result| {
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

pub fn begin_stop(key: Key, done: StopDone) {
    let queue = &sys::MainDispatch;
    let Some(engine) = ENGINES.get(key) else {
        complete_stop(queue, done);
        return;
    };
    if let Err(done) = spawn_owning("oftc-stop", done, move |done| {
        sys::pooled(|| {
            let _ = catch_unwind(AssertUnwindSafe(|| engine.stop()));
            ENGINES.remove(key);
            complete_stop(queue, done);
        });
    }) {
        complete_stop(queue, done);
    }
}

pub fn begin_message(key: Key, message: Vec<u8>, done: Option<ReplyDone>) {
    let queue = &sys::MainDispatch;
    let Some(engine) = ENGINES.get(key) else {
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
/// engine is built on each `startTunnel`.
pub fn run<B: Backend + Clone>(backend: B) -> ! {
    let installed =
        install_factory(Box::new(move |provider| build_engine(backend.clone(), provider)));
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

    /// Like `Provider`: one tunnel's worth of state. Once stopped it refuses to
    /// start again, with code 1.
    #[derive(Default)]
    struct OneShot {
        stopped: Mutex<bool>,
        started: Mutex<bool>,
    }

    impl Engine for OneShot {
        fn start(&self, _options: &StartOptions) -> Result<(), Failure> {
            let stopped = *self.stopped.lock().unwrap();
            let mut started = self.started.lock().unwrap();
            if stopped || *started {
                return Err(Failure(1));
            }
            *started = true;
            Ok(())
        }
        fn stop(&self) {
            *self.stopped.lock().unwrap() = true;
        }
        fn handle_message(&self, _message: &[u8]) -> Option<Vec<u8>> {
            None
        }
    }

    /// NetworkExtension keeps the process across a stop and starts the next
    /// tunnel with a new provider object: the second start must get a fresh
    /// engine, and stop must reach it. A refused start reports its real code.
    #[test]
    fn a_start_after_a_stop_gets_a_fresh_engine() {
        let engines: Engines<()> =
            Engines { factory: OnceLock::new(), live: Mutex::new(BTreeMap::new()) };
        assert!(engines.factory.set(Box::new(|()| Box::new(OneShot::default()))).is_ok());
        let queue = FakeQueue::new();
        let options = StartOptions::default();

        let (first, old) = engines.replace(1, ()).unwrap();
        assert!(old.is_none());
        start_body(&*queue, &*first, &options, |r| assert_eq!(r, Ok(())));
        engines.get(1).unwrap().stop();
        engines.remove(1);
        assert!(engines.get(1).is_none());

        let (second, old) = engines.replace(2, ()).unwrap();
        assert!(old.is_none());
        start_body(&*queue, &*second, &options, |r| assert_eq!(r, Ok(())));
        assert!(Arc::ptr_eq(&engines.get(2).unwrap(), &second));

        // The engine that was reused would have refused, with its real code.
        let (code, done) = mpsc::channel();
        start_body(&*queue, &*first, &options, move |r| code.send(r).unwrap());
        assert_eq!(done.recv().unwrap(), Err(Failure(1)));
    }

    /// Counts stops, to see which engine a call reached.
    #[derive(Default)]
    struct Counting {
        stops: Mutex<u32>,
    }

    impl Engine for Counting {
        fn start(&self, _options: &StartOptions) -> Result<(), Failure> {
            Ok(())
        }
        fn stop(&self) {
            *self.stops.lock().unwrap() += 1;
        }
        fn handle_message(&self, _message: &[u8]) -> Option<Vec<u8>> {
            None
        }
    }

    /// Issue #86: two profiles run two provider objects in this one process.
    /// Starting the second must neither stop nor replace the first (a dropped
    /// provider stops its tunnel), and stop and messages must reach the engine
    /// of the object they were sent to, not the latest one.
    #[test]
    fn a_second_provider_object_leaves_the_first_one_running_and_addressable() {
        let engines: Engines<()> =
            Engines { factory: OnceLock::new(), live: Mutex::new(BTreeMap::new()) };
        assert!(engines.factory.set(Box::new(|()| Box::new(Counting::default()))).is_ok());

        let (a, old) = engines.replace(10, ()).unwrap();
        assert!(old.is_none());
        let (b, old) = engines.replace(20, ()).unwrap();
        // Nothing came back to be dropped, so A's engine was not stopped.
        assert!(old.is_none());
        assert!(!Arc::ptr_eq(&a, &b));
        assert!(Arc::ptr_eq(&engines.get(10).unwrap(), &a));
        assert!(Arc::ptr_eq(&engines.get(20).unwrap(), &b));

        // Stopping A reaches A only, and leaves B routable.
        engines.get(10).unwrap().stop();
        engines.remove(10);
        assert!(engines.get(10).is_none());
        assert!(Arc::ptr_eq(&engines.get(20).unwrap(), &b));

        // A reused key (a freed object's address) hands back the stale engine.
        let (_c, old) = engines.replace(20, ()).unwrap();
        assert!(Arc::ptr_eq(&old.unwrap(), &b));
    }

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
