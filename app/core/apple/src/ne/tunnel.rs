//! [`NeTunnel`]: the engine's [`Tunnel`] over NetworkExtension's packet flow.
//!
//! Every NetworkExtension call is made from the main queue, as the Swift
//! provider did. The tunnel's threads never touch NE objects: they post a
//! closure to a [`MainQueue`] that calls a [`Host`], and block on a channel or
//! condition variable for the answer. Both traits are seams: `sys` has the real
//! ones, the tests below have a single-thread FIFO queue and a recording host.
//!
//! Rules this file keeps:
//! - The main queue is never blocked: a method that would wait for the main
//!   queue refuses (`Closed`) when called on it.
//! - Exactly one `readPackets` is outstanding; a batch with no IPv4 packet
//!   re-issues it.
//! - A waiter treats a dropped sender as failure (`SettingsRejected` /
//!   `Closed`), never `unwrap()`: a main-queue body that panics or throws is
//!   dropped by the guard, and its channel with it.

use std::collections::VecDeque;
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};

use oftc_engine::tunnel::{Tunnel, TunnelError};
use oftc_engine::NetworkSettings;
use oftc_provider::provider::Failure;

use crate::settings::{convert, NeSettings};

/// `AF_INET` on macOS. The packet flow is read and written as IPv4 only.
pub const AF_INET: i32 = 2;

/// Where closures run. The real one is the main dispatch queue.
pub trait MainQueue: Send + Sync {
    /// Run `work` later, in order, on the main thread. Must not run it inline.
    fn post(&self, work: Box<dyn FnOnce() + Send>);
    /// The caller is on the main thread.
    fn is_main(&self) -> bool;
}

/// A readPackets completion: the batch and its protocol families.
pub type ReadDone = Box<dyn FnOnce(Vec<Vec<u8>>, Vec<i32>) + Send>;
/// A settings completion: `true` when the system accepted them.
pub type SettingsDone = Box<dyn FnOnce(bool) + Send>;

/// The NetworkExtension calls. Every method runs on the main queue only.
pub trait Host: Send + Sync {
    /// Install, or with `None` clear, the tunnel network settings.
    fn set_settings(&self, settings: Option<NeSettings>, done: SettingsDone);
    /// Ask for the next batch of outbound packets. If the packet flow is gone
    /// (the provider object was freed), drop `done` without calling it: that
    /// closes the tunnel, ending the reader. Answering with an empty batch
    /// instead would make the reader re-issue the read in a tight loop on the
    /// main queue.
    fn read_packets(&self, done: ReadDone);
    /// Write one `AF_INET` packet; `false` if the flow refused it.
    fn write_packet(&self, packet: &[u8]) -> bool;
    /// End the tunnel with an error (`cancelTunnelWithError`).
    fn cancel(&self, failure: Failure);
}

/// Keep the `AF_INET` packets, in order. Swift's
/// `where protocols[index] == AF_INET` over `min(count)`.
pub fn keep_inet(packets: Vec<Vec<u8>>, protocols: &[i32]) -> Vec<Vec<u8>> {
    packets
        .into_iter()
        .zip(protocols)
        .filter(|(_, protocol)| **protocol == AF_INET)
        .map(|(packet, _)| packet)
        .collect()
}

struct Inbox {
    closed: bool,
    /// A `readPackets` is outstanding.
    reading: bool,
    batches: VecDeque<Vec<Vec<u8>>>,
}

struct Shared {
    inbox: Mutex<Inbox>,
    ready: Condvar,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, Inbox> {
        self.inbox.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// If a read's completion is dropped without running (its main-queue body
/// panicked or threw), the flow is broken: close, so no reader waits forever.
struct ReadGuard {
    shared: Arc<Shared>,
    completed: bool,
}

impl Drop for ReadGuard {
    fn drop(&mut self) {
        if !self.completed {
            let mut inbox = self.shared.lock();
            inbox.reading = false;
            inbox.closed = true;
            drop(inbox);
            self.shared.ready.notify_all();
        }
    }
}

pub struct NeTunnel {
    queue: Arc<dyn MainQueue>,
    host: Arc<dyn Host>,
    shared: Arc<Shared>,
}

impl NeTunnel {
    pub fn new(queue: Arc<dyn MainQueue>, host: Arc<dyn Host>) -> Self {
        Self {
            queue,
            host,
            shared: Arc::new(Shared {
                inbox: Mutex::new(Inbox {
                    closed: false,
                    reading: false,
                    batches: VecDeque::new(),
                }),
                ready: Condvar::new(),
            }),
        }
    }

    fn is_closed(&self) -> bool {
        self.shared.lock().closed
    }

    /// Post a read to the main queue. Call without the inbox lock held.
    fn issue_read(&self) {
        let host = Arc::clone(&self.host);
        let mut guard = ReadGuard {
            shared: Arc::clone(&self.shared),
            completed: false,
        };
        self.queue.post(Box::new(move || {
            host.read_packets(Box::new(move |packets, protocols| {
                let batch = keep_inet(packets, &protocols);
                let mut inbox = guard.shared.lock();
                inbox.reading = false;
                if !batch.is_empty() {
                    inbox.batches.push_back(batch);
                }
                drop(inbox);
                guard.completed = true;
                guard.shared.ready.notify_all();
            }));
        }));
    }

    fn apply(&self, settings: Option<NeSettings>) -> Result<(), TunnelError> {
        if self.queue.is_main() {
            return Err(TunnelError::Closed);
        }
        let (sender, receiver) = mpsc::channel();
        let host = Arc::clone(&self.host);
        self.queue.post(Box::new(move || {
            host.set_settings(
                settings,
                Box::new(move |accepted| {
                    let _ = sender.send(accepted);
                }),
            );
        }));
        match receiver.recv() {
            Ok(true) => Ok(()),
            Ok(false) | Err(_) => Err(TunnelError::SettingsRejected),
        }
    }
}

impl Tunnel for NeTunnel {
    fn apply_settings(&self, settings: &NetworkSettings) -> Result<(), TunnelError> {
        if self.is_closed() {
            return Err(TunnelError::Closed);
        }
        self.apply(Some(convert(settings)?))
    }

    fn read_packets(&self) -> Result<Vec<Vec<u8>>, TunnelError> {
        let mut inbox = self.shared.lock();
        loop {
            // A queued batch is drained even after close, as the trait says.
            if let Some(batch) = inbox.batches.pop_front() {
                return Ok(batch);
            }
            if inbox.closed {
                return Err(TunnelError::Closed);
            }
            if !inbox.reading {
                inbox.reading = true;
                // Posted without the lock: a body dropped inline by the queue
                // runs `ReadGuard::drop`, which takes it.
                drop(inbox);
                self.issue_read();
                inbox = self.shared.lock();
                continue;
            }
            inbox = self
                .shared
                .ready
                .wait(inbox)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    fn write_packet(&self, packet: &[u8]) -> Result<(), TunnelError> {
        if self.is_closed() || self.queue.is_main() {
            return Err(TunnelError::Closed);
        }
        let (sender, receiver) = mpsc::channel();
        let host = Arc::clone(&self.host);
        let packet = packet.to_vec();
        self.queue.post(Box::new(move || {
            let _ = sender.send(host.write_packet(&packet));
        }));
        match receiver.recv() {
            Ok(true) => Ok(()),
            Ok(false) | Err(_) => Err(TunnelError::Closed),
        }
    }

    fn close(&self) {
        self.shared.lock().closed = true;
        self.shared.ready.notify_all();
    }

    fn clear_settings(&self) -> Result<(), TunnelError> {
        self.apply(None)
    }
}

#[cfg(test)]
pub(crate) mod fake {
    //! A single-thread FIFO stand-in for the main queue, and a recording host.

    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::thread::{self, ThreadId};

    use super::*;

    pub struct FakeQueue {
        sender: Mutex<mpsc::Sender<Box<dyn FnOnce() + Send>>>,
        thread: ThreadId,
    }

    impl FakeQueue {
        pub fn new() -> Arc<Self> {
            let (sender, receiver) = mpsc::channel::<Box<dyn FnOnce() + Send>>();
            let handle = thread::spawn(move || {
                for work in receiver {
                    work();
                }
            });
            let thread = handle.thread().id();
            Arc::new(Self {
                sender: Mutex::new(sender),
                thread,
            })
        }
    }

    impl MainQueue for FakeQueue {
        fn post(&self, work: Box<dyn FnOnce() + Send>) {
            let _ = self.sender.lock().unwrap().send(work);
        }
        fn is_main(&self) -> bool {
            thread::current().id() == self.thread
        }
    }

    #[derive(Default)]
    pub struct FakeHost {
        pub accept: AtomicBool,
        pub write_ok: AtomicBool,
        pub reads: AtomicUsize,
        pub settings_calls: Mutex<Vec<Option<NeSettings>>>,
        pub cancels: Mutex<Vec<Failure>>,
        pub pending: Mutex<Vec<ReadDone>>,
        /// Order in which main-queue bodies ran, for ordering tests.
        pub log: Mutex<Vec<&'static str>>,
    }

    impl FakeHost {
        pub fn new() -> Arc<Self> {
            let host = Self::default();
            host.accept.store(true, Ordering::SeqCst);
            host.write_ok.store(true, Ordering::SeqCst);
            Arc::new(host)
        }

        /// Wait until a `readPackets` is outstanding, then answer it.
        pub fn answer_read(&self, packets: Vec<Vec<u8>>, protocols: Vec<i32>) {
            loop {
                if let Some(done) = self.pending.lock().unwrap().pop() {
                    done(packets, protocols);
                    return;
                }
                thread::yield_now();
            }
        }
    }

    impl Host for FakeHost {
        fn set_settings(&self, settings: Option<NeSettings>, done: SettingsDone) {
            self.settings_calls.lock().unwrap().push(settings);
            done(self.accept.load(Ordering::SeqCst));
        }
        fn read_packets(&self, done: ReadDone) {
            self.reads.fetch_add(1, Ordering::SeqCst);
            self.pending.lock().unwrap().push(done);
        }
        fn write_packet(&self, _packet: &[u8]) -> bool {
            self.write_ok.load(Ordering::SeqCst)
        }
        fn cancel(&self, failure: Failure) {
            self.log.lock().unwrap().push("cancel");
            self.cancels.lock().unwrap().push(failure);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::Ordering;
    use std::thread;

    use oftc_engine::AddressRange;

    use super::fake::{FakeHost, FakeQueue};
    use super::*;

    fn tunnel() -> (Arc<NeTunnel>, Arc<FakeHost>, Arc<FakeQueue>) {
        let queue = FakeQueue::new();
        let host = FakeHost::new();
        let tunnel = Arc::new(NeTunnel::new(queue.clone(), host.clone()));
        (tunnel, host, queue)
    }

    fn good_settings() -> NetworkSettings {
        NetworkSettings {
            outer_remote_ipv4: Ipv4Addr::new(203, 0, 113, 1),
            outer_remote_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
            assigned_ipv4: Ipv4Addr::new(10, 0, 0, 5),
            netmask: None,
            split_routes: vec![AddressRange {
                first: IpAddr::V4(Ipv4Addr::new(10, 1, 0, 0)),
                last: IpAddr::V4(Ipv4Addr::new(10, 1, 255, 255)),
            }],
            dns_servers: vec![],
            dns_domains: vec![],
            inner_mtu: 1400,
        }
    }

    #[test]
    fn only_ipv4_packets_are_kept_in_order_and_mismatched_lengths_are_cut() {
        let packets = vec![vec![1], vec![2], vec![3], vec![4]];
        assert_eq!(
            keep_inet(packets.clone(), &[AF_INET, 30, AF_INET, AF_INET]),
            [vec![1], vec![3], vec![4]]
        );
        // Swift zipped to min(count): extra packets without a protocol are dropped.
        assert_eq!(keep_inet(packets, &[AF_INET, AF_INET]), [vec![1], vec![2]]);
    }

    #[test]
    fn a_read_returns_the_batch_and_a_batch_without_ipv4_reissues_the_read() {
        let (tunnel, host, _queue) = tunnel();
        let reader = {
            let tunnel = tunnel.clone();
            thread::spawn(move || tunnel.read_packets())
        };
        host.answer_read(vec![vec![9]], vec![30]);
        host.answer_read(vec![vec![1], vec![2]], vec![AF_INET, AF_INET]);
        assert_eq!(reader.join().unwrap(), Ok(vec![vec![1], vec![2]]));
        assert_eq!(host.reads.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn close_wakes_a_blocked_read_but_a_queued_batch_is_drained_first() {
        let (tunnel, host, _queue) = tunnel();
        let blocked = {
            let tunnel = tunnel.clone();
            thread::spawn(move || tunnel.read_packets())
        };
        // Wait until the read is outstanding, then close without answering it.
        while host.reads.load(Ordering::SeqCst) == 0 {
            thread::yield_now();
        }
        tunnel.close();
        assert_eq!(blocked.join().unwrap(), Err(TunnelError::Closed));

        // The late completion still arrives; its batch is delivered once, then Closed.
        host.answer_read(vec![vec![7]], vec![AF_INET]);
        assert_eq!(tunnel.read_packets(), Ok(vec![vec![7]]));
        assert_eq!(tunnel.read_packets(), Err(TunnelError::Closed));
        // Only one readPackets was ever outstanding.
        assert_eq!(host.reads.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn settings_outcomes_and_what_still_works_after_close() {
        let (tunnel, host, _queue) = tunnel();
        assert_eq!(tunnel.apply_settings(&good_settings()), Ok(()));
        assert!(host.settings_calls.lock().unwrap()[0].is_some());

        host.accept.store(false, Ordering::SeqCst);
        assert_eq!(
            tunnel.apply_settings(&good_settings()),
            Err(TunnelError::SettingsRejected)
        );

        // Settings the conversion refuses never reach the host.
        host.accept.store(true, Ordering::SeqCst);
        let mut bad = good_settings();
        bad.split_routes[0].last = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 2));
        let calls = host.settings_calls.lock().unwrap().len();
        assert_eq!(
            tunnel.apply_settings(&bad),
            Err(TunnelError::SettingsRejected)
        );
        assert_eq!(host.settings_calls.lock().unwrap().len(), calls);

        // After close: apply and write are refused, clear still reaches the host.
        tunnel.close();
        assert_eq!(
            tunnel.apply_settings(&good_settings()),
            Err(TunnelError::Closed)
        );
        assert_eq!(tunnel.write_packet(&[1]), Err(TunnelError::Closed));
        assert_eq!(tunnel.clear_settings(), Ok(()));
        assert_eq!(host.settings_calls.lock().unwrap().last(), Some(&None));
    }

    #[test]
    fn a_refused_write_is_closed_and_waiting_on_the_main_queue_is_refused() {
        let (tunnel, host, queue) = tunnel();
        assert_eq!(tunnel.write_packet(&[1]), Ok(()));
        host.write_ok.store(false, Ordering::SeqCst);
        assert_eq!(tunnel.write_packet(&[1]), Err(TunnelError::Closed));

        // From inside the main queue a blocking call would deadlock: it errors.
        let (sender, receiver) = mpsc::channel();
        let from_main = tunnel.clone();
        queue.post(Box::new(move || {
            let _ = sender.send((from_main.write_packet(&[1]), from_main.clear_settings()));
        }));
        assert_eq!(
            receiver.recv().unwrap(),
            (Err(TunnelError::Closed), Err(TunnelError::Closed))
        );
    }

    #[test]
    fn a_dropped_main_queue_body_fails_the_waiter_instead_of_hanging_it() {
        // A queue that drops every body, as the guard does for a panic.
        struct Dropping;
        impl MainQueue for Dropping {
            fn post(&self, work: Box<dyn FnOnce() + Send>) {
                drop(work);
            }
            fn is_main(&self) -> bool {
                false
            }
        }
        let tunnel = NeTunnel::new(Arc::new(Dropping), FakeHost::new());
        assert_eq!(tunnel.write_packet(&[1]), Err(TunnelError::Closed));
        assert_eq!(tunnel.clear_settings(), Err(TunnelError::SettingsRejected));
        // A read whose completion is dropped closes the tunnel rather than waiting.
        assert_eq!(tunnel.read_packets(), Err(TunnelError::Closed));
    }
}
