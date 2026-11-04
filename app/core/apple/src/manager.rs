//! The VPN configuration and connection calls the host makes, as a trait.
//!
//! [`VpnControl`] is what the host's commands and the reconnect supervisor call;
//! [`MockVpn`] stands in for NetworkExtension in tests. Rust owns every write to
//! the NetworkExtension preferences; the Swift UI only reads them.

use std::any::Any;
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::time::Duration;

use zeroize::Zeroizing;

use crate::error::AppleError;

pub type Result<T> = std::result::Result<T, AppleError>;

/// Connection state, mirroring `NEVPNStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnStatus {
    Invalid,
    Disconnected,
    Connecting,
    Connected,
    Reasserting,
    Disconnecting,
}

/// One VPN entry: a snapshot of its fields plus an opaque handle to the backend
/// object. Cloning shares the handle; dropping the last clone releases it.
///
/// `load_all` returns fresh entries and callers swap them in. The fields are the
/// snapshot at load or reload; `status` reads live state through the handle.
#[derive(Clone)]
pub struct VpnEntry {
    pub provider_id: String,
    /// The profile this entry belongs to, or `None` for an unkeyed entry.
    pub profile_key: Option<String>,
    pub enabled: bool,
    handle: Arc<dyn Any + Send + Sync>,
}

impl VpnEntry {
    /// For backends: wraps their object. Callers outside a backend never need it.
    pub fn new(
        provider_id: String,
        profile_key: Option<String>,
        enabled: bool,
        handle: Arc<dyn Any + Send + Sync>,
    ) -> Self {
        VpnEntry {
            provider_id,
            profile_key,
            enabled,
            handle,
        }
    }

    /// For backends: the object `new` was given, if it is a `T`.
    pub fn handle<T: Any>(&self) -> Option<&T> {
        self.handle.downcast_ref()
    }
}

/// Whether `start` begins a real connection or a preflight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartKind {
    Live,
    Preflight,
}

/// The options passed to `startVPNTunnel`. The key strings belong to the
/// provider crate; the backend maps `kind` to the right one.
pub struct StartOptions {
    pub kind: StartKind,
    /// The serialized start envelope, which carries secrets.
    pub envelope: Zeroizing<Vec<u8>>,
    /// The outer-mode value, if any. Not secret.
    pub mode: Option<Vec<u8>>,
}

/// Removes a status observer when dropped.
pub struct Subscription(Option<Box<dyn FnOnce() + Send>>);

impl Subscription {
    /// For backends: `cancel` runs once, on drop.
    pub fn new(cancel: impl FnOnce() + Send + 'static) -> Self {
        Subscription(Some(Box::new(cancel)))
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        if let Some(cancel) = self.0.take() {
            cancel();
        }
    }
}

pub trait VpnControl: Send + Sync {
    /// Every VPN entry for this app's providers, as fresh snapshots.
    fn load_all(&self) -> Result<Vec<VpnEntry>>;
    /// Rechecks one entry just before acting on it.
    fn reload(&self, entry: &VpnEntry) -> Result<VpnEntry>;
    fn status(&self, entry: &VpnEntry) -> VpnStatus;
    /// Creates and saves a new entry. Callers check for an existing one first.
    fn create(&self, provider_id: &str, profile_key: &str, name: &str) -> Result<()>;
    /// Sets `enabled` on an existing entry and saves it.
    fn set_enabled(&self, entry: &VpnEntry, enabled: bool) -> Result<()>;
    fn remove(&self, entry: &VpnEntry) -> Result<()>;
    fn start(&self, entry: &VpnEntry, options: StartOptions) -> Result<()>;
    fn stop(&self, entry: &VpnEntry);
    /// Sends a message to the running provider and waits for its reply.
    fn send_provider_message(
        &self,
        entry: &VpnEntry,
        message: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>>;
    /// The error the last disconnect recorded, if any.
    fn last_disconnect_error(
        &self,
        entry: &VpnEntry,
        timeout: Duration,
    ) -> Result<Option<AppleError>>;
    /// Sends `()` on `notify` whenever the entry's status changes, until the
    /// returned [`Subscription`] is dropped. Re-attach after swapping in a fresh
    /// entry.
    fn observe_status(&self, entry: &VpnEntry, notify: Sender<()>) -> Result<Subscription>;
}

pub use mock::{MockEntry, MockVpn, StartRecord};

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
mod ne;
#[cfg(target_os = "macos")]
pub use ne::{NeVpnControl, StartKeys};

mod mock {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex, MutexGuard};

    use super::*;

    /// One recorded `start`: kind, envelope (kept wiped-on-drop), mode.
    pub type StartRecord = (StartKind, Zeroizing<Vec<u8>>, Option<Vec<u8>>);

    /// The backend handle inside a mock [`VpnEntry`]. A newtype so `live` can
    /// downcast to a concrete type and recover the `Arc`.
    struct MockHandle(Arc<MockEntry>);

    /// The state of one mock entry; also the backend handle inside its
    /// [`VpnEntry`].
    pub struct MockEntry {
        state: Mutex<MockState>,
    }

    struct MockState {
        provider_id: String,
        profile_key: Option<String>,
        enabled: bool,
        removed: bool,
        status: VpnStatus,
        started: Vec<StartRecord>,
        stops: usize,
        replies: VecDeque<Result<Vec<u8>>>,
        sent: Vec<Vec<u8>>,
        last_error: Option<AppleError>,
        observers: Vec<(u64, Sender<()>)>,
        next_observer: u64,
    }

    impl MockEntry {
        fn lock(&self) -> MutexGuard<'_, MockState> {
            self.state.lock().unwrap()
        }

        fn snapshot(self: &Arc<Self>) -> VpnEntry {
            let s = self.lock();
            VpnEntry::new(
                s.provider_id.clone(),
                s.profile_key.clone(),
                s.enabled,
                Arc::new(MockHandle(self.clone())),
            )
        }

        /// Sets the status and wakes every observer.
        pub fn set_status(&self, status: VpnStatus) {
            let mut s = self.lock();
            s.status = status;
            s.observers.retain(|(_, tx)| tx.send(()).is_ok());
        }
        /// Queues the reply to the next `send_provider_message`; with none
        /// queued the call times out, as a provider that never answers does.
        pub fn push_reply(&self, reply: Result<Vec<u8>>) {
            self.lock().replies.push_back(reply);
        }
        pub fn set_last_error(&self, error: Option<AppleError>) {
            self.lock().last_error = error;
        }
        /// The `(kind, envelope, mode)` of every `start` so far.
        pub fn started(&self) -> Vec<StartRecord> {
            self.lock().started.clone()
        }
        pub fn stops(&self) -> usize {
            self.lock().stops
        }
        pub fn sent(&self) -> Vec<Vec<u8>> {
            self.lock().sent.clone()
        }
        pub fn is_enabled(&self) -> bool {
            self.lock().enabled
        }
    }

    /// An in-memory [`VpnControl`] with scripted replies and fireable observers.
    #[derive(Default)]
    pub struct MockVpn {
        entries: Mutex<Vec<Arc<MockEntry>>>,
    }

    impl MockVpn {
        pub fn new() -> Self {
            Self::default()
        }

        /// Adds an entry as `create` would, and returns it for scripting.
        pub fn add_entry(
            &self,
            provider_id: &str,
            profile_key: Option<&str>,
            enabled: bool,
        ) -> Arc<MockEntry> {
            let entry = Arc::new(MockEntry {
                state: Mutex::new(MockState {
                    provider_id: provider_id.to_string(),
                    profile_key: profile_key.map(str::to_string),
                    enabled,
                    removed: false,
                    status: VpnStatus::Disconnected,
                    started: Vec::new(),
                    stops: 0,
                    replies: VecDeque::new(),
                    sent: Vec::new(),
                    last_error: None,
                    observers: Vec::new(),
                    next_observer: 0,
                }),
            });
            self.entries.lock().unwrap().push(entry.clone());
            entry
        }

        /// The live mock behind `entry`, or `StaleEntry` once it was removed.
        fn live(&self, entry: &VpnEntry) -> Result<Arc<MockEntry>> {
            let mock = entry
                .handle::<MockHandle>()
                .map(|h| h.0.clone())
                .ok_or(AppleError::StaleEntry)?;
            if mock.lock().removed {
                return Err(AppleError::StaleEntry);
            }
            Ok(mock)
        }
    }

    impl VpnControl for MockVpn {
        fn load_all(&self) -> Result<Vec<VpnEntry>> {
            Ok(self
                .entries
                .lock()
                .unwrap()
                .iter()
                .map(|e| e.snapshot())
                .collect())
        }

        fn reload(&self, entry: &VpnEntry) -> Result<VpnEntry> {
            Ok(self.live(entry)?.snapshot())
        }

        fn status(&self, entry: &VpnEntry) -> VpnStatus {
            match self.live(entry) {
                Ok(mock) => mock.lock().status,
                Err(_) => VpnStatus::Invalid,
            }
        }

        fn create(&self, provider_id: &str, profile_key: &str, _name: &str) -> Result<()> {
            self.add_entry(provider_id, Some(profile_key), true);
            Ok(())
        }

        fn set_enabled(&self, entry: &VpnEntry, enabled: bool) -> Result<()> {
            self.live(entry)?.lock().enabled = enabled;
            Ok(())
        }

        fn remove(&self, entry: &VpnEntry) -> Result<()> {
            let mock = self.live(entry)?;
            mock.lock().removed = true;
            self.entries
                .lock()
                .unwrap()
                .retain(|e| !Arc::ptr_eq(e, &mock));
            Ok(())
        }

        fn start(&self, entry: &VpnEntry, options: StartOptions) -> Result<()> {
            let mock = self.live(entry)?;
            mock.lock()
                .started
                .push((options.kind, options.envelope, options.mode));
            Ok(())
        }

        fn stop(&self, entry: &VpnEntry) {
            if let Ok(mock) = self.live(entry) {
                mock.lock().stops += 1;
            }
        }

        fn send_provider_message(
            &self,
            entry: &VpnEntry,
            message: &[u8],
            _timeout: Duration,
        ) -> Result<Vec<u8>> {
            let mock = self.live(entry)?;
            let mut s = mock.lock();
            s.sent.push(message.to_vec());
            s.replies.pop_front().unwrap_or(Err(AppleError::TimedOut))
        }

        fn last_disconnect_error(
            &self,
            entry: &VpnEntry,
            _timeout: Duration,
        ) -> Result<Option<AppleError>> {
            Ok(self.live(entry)?.lock().last_error.clone())
        }

        fn observe_status(&self, entry: &VpnEntry, notify: Sender<()>) -> Result<Subscription> {
            let mock = self.live(entry)?;
            let id = {
                let mut s = mock.lock();
                let id = s.next_observer;
                s.next_observer += 1;
                s.observers.push((id, notify));
                id
            };
            Ok(Subscription::new(move || {
                mock.lock().observers.retain(|(i, _)| *i != id);
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::{channel, TryRecvError};

    /// The mock is what the host's logic is tested against, so it must behave as
    /// the real backend does: entries load and reload, writes stick, replies and
    /// observers work, and a removed entry goes stale.
    #[test]
    fn mock_honours_the_vpn_control_contract() {
        let vpn = MockVpn::new();
        let wait = Duration::from_millis(10);
        let mock = vpn.add_entry("provider", Some("key"), false);

        let entries = vpn.load_all().unwrap();
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.profile_key.as_deref(), Some("key"));
        assert!(!entry.enabled);
        assert_eq!(vpn.status(entry), VpnStatus::Disconnected);

        vpn.set_enabled(entry, true).unwrap();
        assert!(vpn.reload(entry).unwrap().enabled);
        vpn.set_enabled(entry, false).unwrap();
        assert!(!vpn.reload(entry).unwrap().enabled);
        assert!(!mock.is_enabled());

        vpn.start(
            entry,
            StartOptions {
                kind: StartKind::Preflight,
                envelope: Zeroizing::new(b"env".to_vec()),
                mode: Some(b"m".to_vec()),
            },
        )
        .unwrap();
        let started = mock.started();
        assert_eq!(started.len(), 1);
        assert_eq!(started[0].0, StartKind::Preflight);
        assert_eq!(&started[0].1[..], b"env");
        assert_eq!(started[0].2.as_deref(), Some(&b"m"[..]));

        vpn.stop(entry);
        assert_eq!(mock.stops(), 1);

        mock.push_reply(Ok(b"pong".to_vec()));
        assert_eq!(
            vpn.send_provider_message(entry, b"ping", wait),
            Ok(b"pong".to_vec())
        );
        assert_eq!(
            vpn.send_provider_message(entry, b"ping", wait),
            Err(AppleError::TimedOut)
        );
        assert_eq!(mock.sent(), vec![b"ping".to_vec(), b"ping".to_vec()]);

        assert_eq!(vpn.last_disconnect_error(entry, wait), Ok(None));
        mock.set_last_error(Some(AppleError::TimedOut));
        assert_eq!(
            vpn.last_disconnect_error(entry, wait),
            Ok(Some(AppleError::TimedOut))
        );
        // Reads do not consume the error.
        assert_eq!(
            vpn.last_disconnect_error(entry, wait),
            Ok(Some(AppleError::TimedOut))
        );

        let (tx, rx) = channel();
        let subscription = vpn.observe_status(entry, tx).unwrap();
        mock.set_status(VpnStatus::Connected);
        assert!(rx.try_recv().is_ok());
        assert_eq!(vpn.status(entry), VpnStatus::Connected);
        let (tx2, rx2) = channel();
        let _second = vpn.observe_status(entry, tx2).unwrap();
        drop(subscription);
        mock.set_status(VpnStatus::Disconnected);
        assert_eq!(rx.try_recv(), Err(TryRecvError::Disconnected));
        // Dropping one subscription leaves the other attached.
        assert!(rx2.try_recv().is_ok());

        vpn.create("p2", "k2", "n").unwrap();
        let created = vpn
            .load_all()
            .unwrap()
            .into_iter()
            .find(|e| e.profile_key.as_deref() == Some("k2"))
            .unwrap();
        assert_eq!(created.provider_id, "p2");
        assert!(created.enabled);

        vpn.remove(entry).unwrap();
        assert_eq!(vpn.load_all().unwrap().len(), 1);
        vpn.stop(entry);
        assert_eq!(mock.stops(), 1);
        assert_eq!(
            vpn.last_disconnect_error(entry, wait),
            Err(AppleError::StaleEntry)
        );
        assert_eq!(vpn.reload(entry).err(), Some(AppleError::StaleEntry));
        assert_eq!(vpn.status(entry), VpnStatus::Invalid);
    }
}
