//! The host's local socket service (`docs/ui-edge.md`): `OFTCAgent host serve`.
//!
//! [`listener`] takes the single-instance lock and binds the socket; each accepted
//! connection is checked against the server's own user id and served by [`session`];
//! [`collect`] builds the status document that [`hub`] holds and fans out; [`traffic`]
//! samples the provider while a client wants it; [`state`] holds the rules that decide
//! what each row shows. Everything outside this process comes in through [`Services`].

pub mod collect;
pub mod frame;
pub mod hub;
pub mod info;
pub mod listener;
pub mod ops;
pub mod ops_setup;
pub mod ops_system;
pub mod ops_update;
pub mod session;
pub mod state;
pub mod traffic;

use std::collections::HashMap;
use std::os::unix::net::UnixStream;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Mutex, PoisonError};
use std::thread;
use std::time::{Duration, SystemTime};

use oftc_apple::login::LoginItems;
use oftc_apple::manager::VpnControl;
use oftc_apple::sysext::ExtensionControl;
use oftc_ui_edge::{HostBlock, TrafficSample, MAX_CONNECTIONS};

use crate::env::HostEnv;
use crate::supervisor::Signals;
use collect::Collector;
use hub::Hub;
use session::Shared;
use traffic::TrafficRates;

/// Everything the server reaches outside this process, all shareable between threads.
pub struct Services<'a> {
    pub env: &'a HostEnv,
    pub vpn: &'a dyn VpnControl,
    pub extensions: &'a dyn ExtensionControl,
    pub login: &'a dyn LoginItems,
    /// The bundle's versions; empty strings when the bundle could not be read.
    pub host: HostBlock,
    pub now: &'a (dyn Fn() -> SystemTime + Sync),
    /// How long a new connection has, in total, to say `hello`.
    pub hello_timeout: Duration,
    /// What the ops beyond `status` reach.
    pub ops: ops::OpsDeps<'a>,
}

/// How often the provider is asked for a traffic reading while someone listens.
const SAMPLE_INTERVAL: Duration = Duration::from_secs(1);
/// The system extension request behind `component.state` is repeated at this age.
const COMPONENT_MAX_AGE: Duration = Duration::from_secs(30);
const COMPONENT_TIMEOUT: Duration = Duration::from_secs(10);
/// With a client subscribed the files are re-read this often; otherwise as often as
/// the component check.
const POLL: Duration = Duration::from_secs(1);
const IDLE_POLL: Duration = Duration::from_secs(30);
const ACCEPT_POLL: Duration = Duration::from_millis(20);

/// Runs `body`, and calls `then` when it ends however it ends, a panic included.
struct OnDrop<F: FnMut()>(F);

impl<F: FnMut()> Drop for OnDrop<F> {
    fn drop(&mut self) {
        (self.0)();
    }
}

/// Serves `listener` until `stop` says so, or until the document or sampling loop dies
/// (then false: a host that can no longer refresh must not keep answering with stale
/// documents, so the caller exits non-zero and launchd restarts it). A connection
/// whose peer user is not `uid` (per `peer`) is closed without a word.
pub fn serve(
    listener: &std::os::unix::net::UnixListener,
    services: &Services,
    uid: u32,
    peer: &dyn Fn(&UnixStream) -> Option<u32>,
    stop: &dyn Fn() -> bool,
) -> bool {
    let hub = Hub::new();
    let (wake, woken) = mpsc::channel();
    let collector = Collector::new(services, &hub, wake.clone());
    let busy = ops::Busy::default();
    let shared = Shared {
        hub: &hub,
        collector: &collector,
        host: &services.host,
        hello_timeout: services.hello_timeout,
        services,
        busy: &busy,
    };
    let open: Mutex<HashMap<u64, UnixStream>> = Mutex::new(HashMap::new());
    let failed = AtomicBool::new(false);
    // A loop that ends while the hub is open (a panic) takes the server down with it.
    let guard = || {
        OnDrop(|| {
            if !hub.closing() {
                failed.store(true, Ordering::SeqCst);
            }
        })
    };
    thread::scope(|scope| {
        scope.spawn(|| {
            let _alive = guard();
            let _ = catch_unwind(AssertUnwindSafe(|| {
                refresh_loop(scope, &collector, &hub, services, &wake, woken)
            }));
        });
        scope.spawn(|| {
            let _alive = guard();
            let _ = catch_unwind(AssertUnwindSafe(|| sample_loop(&hub, services.vpn)));
        });
        let mut next = 0u64;
        while !stop() && !failed.load(Ordering::SeqCst) {
            let stream = match listener.accept() {
                Ok((stream, _)) => stream,
                Err(_) => {
                    thread::sleep(ACCEPT_POLL);
                    continue;
                }
            };
            // A socket accepted from a non-blocking listener may inherit that mode.
            let _ = stream.set_nonblocking(false);
            if peer(&stream) != Some(uid) {
                continue;
            }
            let mut connections = open.lock().unwrap_or_else(PoisonError::into_inner);
            let Ok(clone) = stream.try_clone() else {
                continue;
            };
            if connections.len() >= MAX_CONNECTIONS {
                continue;
            }
            next += 1;
            let id = next;
            connections.insert(id, clone);
            drop(connections);
            let (shared, open) = (&shared, &open);
            scope.spawn(move || {
                // The slot is freed however the connection ends, a panic included, and
                // a panic costs only this connection.
                let _slot = OnDrop(|| {
                    open.lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .remove(&id);
                });
                let _ = catch_unwind(AssertUnwindSafe(|| session::serve(stream, shared)));
            });
        }
        hub.close();
        let _ = wake.send(());
        for stream in open.lock().unwrap_or_else(PoisonError::into_inner).values() {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    });
    !failed.load(Ordering::SeqCst)
}

/// Keeps the status document current: on a wake-up from a NetworkExtension status
/// change or a finished component check, and on a timer for the files that have no
/// notification.
fn refresh_loop<'scope, 'env>(
    scope: &'scope thread::Scope<'scope, 'env>,
    collector: &'scope Collector<'env>,
    hub: &'scope Hub,
    services: &'scope Services<'env>,
    wake: &'scope mpsc::Sender<()>,
    woken: mpsc::Receiver<()>,
) {
    while !hub.closing() {
        collector.refresh();
        if hub.claim_component_check(COMPONENT_MAX_AGE) {
            scope.spawn(move || {
                let expected = &services.host.provider_build;
                let result = if expected.is_empty() {
                    (oftc_ui_edge::ComponentState::Unavailable, None)
                } else {
                    state::component_from_request(
                        expected,
                        services
                            .extensions
                            .properties(&services.env.provider_id(), COMPONENT_TIMEOUT),
                    )
                };
                hub.finish_component_check(result);
                let _ = wake.send(());
            });
        }
        let wait = if hub.has_subscribers() {
            POLL
        } else {
            IDLE_POLL
        };
        if let Err(mpsc::RecvTimeoutError::Disconnected) = woken.recv_timeout(wait) {
            return;
        }
    }
}

/// While some client listens for traffic, asks each connected profile's provider
/// for a reading once a second and hands the results to the hub.
fn sample_loop(hub: &Hub, vpn: &dyn VpnControl) {
    let mut rates: HashMap<String, TrafficRates> = HashMap::new();
    while hub.wait_for_traffic_demand() {
        let mut round = Vec::new();
        let connected = hub.connected_entries();
        rates.retain(|id, _| connected.iter().any(|(c, _)| c == id));
        for (id, entry) in connected {
            let rates = rates.entry(id.clone()).or_default();
            traffic::measure(vpn, &entry, rates);
            if let Some(latest) = &rates.latest {
                round.push((
                    id,
                    TrafficSample {
                        session: latest.session_id.replace('-', "").to_lowercase()[..8].to_owned(),
                        rx_bytes: latest.received_bytes,
                        tx_bytes: latest.sent_bytes,
                        rx_rate: rates.receiving,
                        tx_rate: rates.sending,
                        sample_seq: 0,
                    },
                ));
            }
        }
        hub.push_samples(round);
        if hub.sleep(SAMPLE_INTERVAL) {
            return;
        }
    }
}

/// `host serve`: takes the lock, binds the socket in `directory` (the host's
/// per-user directory, `env.root()`, outside tests) and serves until SIGINT or
/// SIGTERM. The text to print and the exit code.
pub fn run(
    env: &HostEnv,
    directory: &Path,
    vpn: &dyn VpnControl,
    extensions: &dyn ExtensionControl,
    login: &dyn LoginItems,
    signals: &dyn Signals,
    ops: ops::OpsDeps,
) -> (String, i32) {
    use listener::StartError;
    signals.arm();
    let bound = match listener::bind(directory) {
        Ok(bound) => bound,
        // Another host owns the socket; this one has nothing to do.
        Err(StartError::AlreadyRunning) => return (String::new(), 0),
        Err(StartError::PathTooLong) => return ("host_unavailable: path too long".into(), 1),
        Err(StartError::Unusable(why)) => return (format!("host_unavailable: {why}"), 1),
    };
    let services = Services {
        env,
        vpn,
        extensions,
        login,
        host: info::host_block(env.exe(), &env.provider_id()),
        now: &SystemTime::now,
        hello_timeout: Duration::from_secs(10),
        ops,
    };
    let healthy = serve(
        &bound.listener,
        &services,
        crate::os::euid(),
        &|stream| crate::os::peer_uid(stream),
        &|| signals.raised(),
    );
    if healthy {
        (String::new(), 0)
    } else {
        ("host_unavailable: internal failure".into(), 1)
    }
}

#[cfg(test)]
mod tests_ops;

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::profile::testutil::TempDir;
    use crate::profile::{Profile, Transport};
    use crate::registry;
    use crate::supervisor::ManualSignals;
    use oftc_apple::login::{LoginItem, LoginStatus, MockLoginItems};
    use oftc_apple::manager::{MockEntry, MockVpn, VpnStatus};
    use crate::agent::RecordingLaunchctl;
    use crate::commands::{FortiClientProfile, FortiClientProfiles};
    use crate::keychain::{Keychain, MemoryKeychain};
    use crate::registry::FortiClientSource;
    use ops::OpsDeps;
    use ops_system::{SettingsOpener, Spawner};
    use ops_update::UpdateSource;
    use oftc_apple::error::AppleError;
    use oftc_apple::sysext::{
        EventSink, ExtensionControl, ExtensionEvent, ExtensionProperties, Finish, MockExtensions,
    };
    use oftc_ui_edge::{Pane, UpdateOffer};
    use std::sync::{Condvar, Mutex as StdMutex};
    use zeroize::Zeroizing;
    use serde_json::{json, Value};
    use std::io::{BufRead, BufReader, Write};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Instant;

    const SESSION: &str = "11111111-2222-4333-8444-555555555555";

    /// The world the server sees: one profile ("lab") with a VPN entry, a bundle at
    /// build 24, and an extension at build 24 enabled.
    pub(super) struct Rig {
        pub dir: TempDir,
        pub env: HostEnv,
        pub vpn: MockVpn,
        pub entry: Arc<MockEntry>,
        pub extensions: Gated,
        pub login: MockLoginItems,
        pub keychain: MemoryKeychain,
        pub forticlient: Forti,
        pub launchctl: RecordingLaunchctl,
        pub spawner: Spawned,
        pub opener: Opened,
        pub feed: Feed,
        /// Runs at every `pause` of an op (`remove` waiting for the tunnel).
        pub on_pause: PauseHook,
        pause: Box<dyn Fn(Duration) + Sync>,
    }

    pub(super) type PauseHook = Arc<StdMutex<Option<Box<dyn Fn() + Send>>>>;

    /// A system extension whose `activate` can be held open, as one waiting on the user.
    pub(super) struct Gated {
        pub mock: MockExtensions,
        /// While true, `activate` blocks after raising `NeedsApproval`.
        pub hold: StdMutex<bool>,
        pub changed: Condvar,
        pub entered: StdMutex<u32>,
    }

    impl Gated {
        pub fn hold(&self) {
            *self.hold.lock().unwrap() = true;
        }
        pub fn release(&self) {
            *self.hold.lock().unwrap() = false;
            self.changed.notify_all();
        }
        /// Waits until an `activate` is blocked.
        pub fn wait_entered(&self) {
            let deadline = Instant::now() + Duration::from_secs(10);
            while *self.entered.lock().unwrap() == 0 {
                assert!(Instant::now() < deadline, "activate never started");
                thread::sleep(Duration::from_millis(5));
            }
        }
    }

    impl ExtensionControl for Gated {
        fn activate(&self, id: &str, events: EventSink) -> Result<Finish, AppleError> {
            let mut held = self.hold.lock().unwrap();
            if *held {
                events(ExtensionEvent::NeedsApproval);
                *self.entered.lock().unwrap() += 1;
                while *held {
                    held = self.changed.wait(held).unwrap();
                }
            }
            drop(held);
            self.mock.activate(id, events)
        }
        fn deactivate(&self, id: &str, events: EventSink) -> Result<Finish, AppleError> {
            self.mock.deactivate(id, events)
        }
        fn properties(
            &self,
            id: &str,
            timeout: Duration,
        ) -> Result<Vec<ExtensionProperties>, AppleError> {
            self.mock.properties(id, timeout)
        }
    }

    #[derive(Default)]
    pub(super) struct Spawned {
        pub ids: StdMutex<Vec<String>>,
        pub fail: AtomicBool,
    }

    impl Spawner for Spawned {
        fn spawn_supervisor(&self, id: &str) -> std::io::Result<()> {
            if self.fail.load(Ordering::SeqCst) {
                return Err(std::io::Error::other("no"));
            }
            self.ids.lock().unwrap().push(id.to_owned());
            Ok(())
        }
    }

    #[derive(Default)]
    pub(super) struct Opened(pub StdMutex<Vec<Pane>>);

    impl SettingsOpener for Opened {
        fn open(&self, pane: Pane) -> bool {
            self.0.lock().unwrap().push(pane);
            true
        }
    }

    pub(super) struct Feed(pub StdMutex<Result<Option<UpdateOffer>, ops_update::FeedUnreachable>>);

    impl UpdateSource for Feed {
        fn latest(&self, _: &str) -> Result<Option<UpdateOffer>, ops_update::FeedUnreachable> {
            self.0.lock().unwrap().clone()
        }
    }

    /// FortiClient with one importable profile, "Example Office", whose PSK is
    /// `FORTI_PSK`.
    pub(super) struct Forti;

    pub(super) const FORTI_PSK: &str = "forti-secret-psk";

    impl FortiClientProfiles for Forti {
        fn list(&self) -> Vec<FortiClientSource> {
            vec![FortiClientSource {
                label: "Example Office".into(),
                gateway: "vpn.example.com".into(),
                saml_port: 9443,
            }]
        }
        fn import(&self, _: &str) -> Option<FortiClientProfile> {
            None
        }
        fn psk(&self, name: &str, gateway: &str) -> Option<Zeroizing<Vec<u8>>> {
            (name == "Example Office" && gateway == "vpn.example.com")
                .then(|| Zeroizing::new(FORTI_PSK.as_bytes().to_vec()))
        }
    }

    impl Rig {
        pub fn new() -> Rig {
            let dir = TempDir::new("serve");
            let env = HostEnv::new("a", &dir.0.join("h")).unwrap();
            let lab = Profile::new("lab.example.com", 8443, Transport::Tcp, Some("Lab"), None);
            registry::add(env.root(), &lab.unwrap(), None).unwrap();
            let vpn = MockVpn::new();
            let entry = vpn.add_entry(&env.provider_id(), Some("lab"), true);
            let extensions = Gated {
                mock: MockExtensions::new(),
                hold: StdMutex::new(false),
                changed: Condvar::new(),
                entered: StdMutex::new(0),
            };
            extensions.mock.set_properties(
                &env.provider_id(),
                Ok(vec![ExtensionProperties {
                    short_version: "1.0".into(),
                    build: "50".into(),
                    enabled: true,
                    awaiting_approval: false,
                    uninstalling: false,
                }]),
            );
            let login = MockLoginItems::new();
            login.set_status(&LoginItem::MainApp, LoginStatus::Enabled);
            let host_agent = LoginItem::Agent(crate::agent::HOST_PLIST.to_owned());
            login.set_status(&host_agent, LoginStatus::RequiresApproval);
            let on_pause: PauseHook = Arc::new(StdMutex::new(None));
            let hook = on_pause.clone();
            let keychain = MemoryKeychain::default();
            keychain.set("lab.example.com", b"lab-secret-psk").unwrap();
            Rig {
                dir,
                env,
                vpn,
                entry,
                extensions,
                login,
                keychain,
                forticlient: Forti,
                launchctl: RecordingLaunchctl::new(true),
                spawner: Spawned::default(),
                opener: Opened::default(),
                feed: Feed(StdMutex::new(Ok(None))),
                on_pause,
                pause: Box::new(move |_| {
                    if let Some(hook) = hook.lock().unwrap().as_ref() {
                        hook();
                    }
                }),
            }
        }

        pub fn ops(&self) -> OpsDeps<'_> {
            OpsDeps {
                keychain: &self.keychain,
                forticlient: &self.forticlient,
                launchctl: &self.launchctl,
                spawner: &self.spawner,
                updates: &self.feed,
                opener: &self.opener,
                pause: &*self.pause,
            }
        }

        pub fn services(&self) -> Services<'_> {
            Services {
                env: &self.env,
                vpn: &self.vpn,
                extensions: &self.extensions,
                login: &self.login,
                host: HostBlock {
                    version: "0.9.0".into(),
                    build: "24".into(),
                    provider_build: "50".into(),
                },
                now: &|| SystemTime::UNIX_EPOCH + Duration::from_secs(1_793_794_800),
                hello_timeout: Duration::from_millis(400),
                ops: self.ops(),
            }
        }

        /// Runs the server on a socket in the rig's directory for the length of `body`,
        /// with `peer` standing in for the kernel's credential read.
        pub fn serving<R>(
            &self,
            peer: &(dyn Fn(&UnixStream) -> Option<u32> + Sync),
            body: impl FnOnce(&Path) -> R,
        ) -> R {
            let bound = listener::bind(&self.dir.0).unwrap();
            let socket = listener::socket_path(&self.dir.0);
            let stop = AtomicBool::new(false);
            let services = self.services();
            thread::scope(|scope| {
                scope.spawn(|| {
                    serve(&bound.listener, &services, 501, peer, &|| {
                        stop.load(Ordering::SeqCst)
                    })
                });
                // Stops the server even if `body` panics, or the scope would wait forever.
                let _stop = OnDrop(|| stop.store(true, Ordering::SeqCst));
                body(&socket)
            })
        }
    }

    pub(super) fn me(_: &UnixStream) -> Option<u32> {
        Some(501)
    }

    pub(super) struct Client {
        pub writer: UnixStream,
        pub reader: BufReader<UnixStream>,
        /// Every line received, as sent, for checks that something never appears.
        pub log: Vec<String>,
    }

    impl Client {
        pub fn connect(socket: &Path) -> Client {
            let stream = UnixStream::connect(socket).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            Client {
                reader: BufReader::new(stream.try_clone().unwrap()),
                writer: stream,
                log: Vec::new(),
            }
        }

        pub fn send(&mut self, line: &str) {
            // The server may already have closed on us; that shows in the next read.
            let _ = self.writer.write_all(format!("{line}\n").as_bytes());
        }

        /// The next line, or `None` at end of stream.
        pub fn next(&mut self) -> Option<Value> {
            let mut line = String::new();
            match self.reader.read_line(&mut line) {
                Ok(0) | Err(_) => None,
                Ok(_) => {
                    self.log.push(line.clone());
                    Some(serde_json::from_str(&line).unwrap())
                }
            }
        }

        pub fn call(&mut self, line: &str) -> Value {
            self.send(line);
            self.next().expect("a reply")
        }

        pub fn hello(&mut self) -> Value {
            self.call(r#"{"id":1,"op":"hello","protocol":[1,1],"client":{"kind":"test","version":"0","build":"0"}}"#)
        }
    }

    /// The `status` result once the background component check has answered; the
    /// sequence number is only deterministic from then on.
    pub(super) fn settled(client: &mut Client) -> Value {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let status = client.call(r#"{"id":90,"op":"status"}"#)["result"].clone();
            if status["component"]["state"] != "checking" || Instant::now() > deadline {
                return status;
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn connected_with_replies(rig: &Rig, uptimes: &[u32]) {
        rig.entry.set_status(VpnStatus::Connected);
        for (n, uptime) in uptimes.iter().enumerate() {
            let received = 1000 * (n as u64 + 1);
            rig.entry.push_reply(Ok(format!(
                r#"{{"version":1,"sessionID":"{SESSION}","receivedBytes":{received},"sentBytes":{},"uptime":{uptime}}}"#,
                received / 10
            )
            .into_bytes()));
        }
    }

    /// `hello` negotiates and reports the host; everything before it, a protocol
    /// range with no overlap, and a malformed range are refused with
    /// `unsupported_schema` (exit 5) and the connection closes.
    #[test]
    fn handshake_rules() {
        let rig = Rig::new();
        rig.serving(&me, |socket| {
            let mut client = Client::connect(socket);
            let reply = client.hello();
            assert_eq!(
                reply,
                json!({"id":1,"ok":true,"result":{"protocol":1,
                    "host":{"version":"0.9.0","build":"24","provider_build":"50"}}})
            );
            // A newer client range is negotiated down; hello again is answered again.
            let again = client.call(r#"{"id":2,"op":"hello","protocol":[1,9]}"#);
            assert_eq!(again["result"]["protocol"], 1);
            // Unknown ops are answered and the connection stays.
            let unknown = client.call(r#"{"id":3,"op":"teleport"}"#);
            assert_eq!(unknown["error"]["code"], "unknown_op");
            assert_eq!(unknown["error"]["exit"], 2);
            assert_eq!(unknown["id"], 3);
            let status = client.call(r#"{"id":4,"op":"status"}"#);
            assert_eq!(status["ok"], true);

            for first in [
                r#"{"id":1,"op":"status"}"#,
                r#"{"id":1,"op":"hello","protocol":[2,3]}"#,
                r#"{"id":1,"op":"hello","protocol":[2,1]}"#,
                r#"{"id":1,"op":"hello"}"#,
            ] {
                let mut client = Client::connect(socket);
                let refused = client.call(first);
                assert_eq!(refused["ok"], false, "{first}");
                assert_eq!(refused["error"]["code"], "unsupported_schema", "{first}");
                assert_eq!(refused["error"]["exit"], 5, "{first}");
                assert_eq!(client.next(), None, "closed after {first}");
            }
        });
    }

    /// A connection whose peer is not this user, or whose peer the system will not name,
    /// is closed with nothing said; the next good one is served.
    #[test]
    fn a_peer_of_another_user_gets_nothing() {
        let rig = Rig::new();
        let calls = AtomicUsize::new(0);
        let peer = |_: &UnixStream| match calls.fetch_add(1, Ordering::SeqCst) {
            0 => Some(502),
            1 => None,
            _ => Some(501),
        };
        rig.serving(&peer, |socket| {
            for _ in 0..2 {
                let mut stranger = Client::connect(socket);
                stranger.send(r#"{"id":1,"op":"hello","protocol":[1,1]}"#);
                assert_eq!(stranger.next(), None);
            }
            assert_eq!(Client::connect(socket).hello()["ok"], true);
        });
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    /// Framing over the socket: blank lines are skipped, two requests in one write
    /// are answered in order, and a line that is too long, not JSON, or has no `id`
    /// and `op` closes the connection with no reply.
    #[test]
    fn framing_limits() {
        let rig = Rig::new();
        rig.serving(&me, |socket| {
            let mut client = Client::connect(socket);
            client.send(&format!(
                "\n\r\n{}",
                r#"{"id":1,"op":"hello","protocol":[1,1]}"#
            ));
            assert_eq!(client.next().unwrap()["id"], 1);
            client.send(&format!(
                "{}\n{}",
                r#"{"id":2,"op":"profiles"}"#, r#"{"id":3,"op":"profiles"}"#
            ));
            assert_eq!(client.next().unwrap()["id"], 2);
            assert_eq!(client.next().unwrap()["id"], 3);
            // 64 KiB of padding in a valid request is a line; one byte more is not.
            let pad = |n: usize| format!(r#"{{"id":4,"op":"profiles","pad":"{}"}}"#, "x".repeat(n));
            let base = pad(0).len();
            assert_eq!(client.call(&pad(oftc_ui_edge::MAX_LINE - base))["id"], 4);
            for bad in [
                pad(oftc_ui_edge::MAX_LINE - base + 1),
                "not json".to_owned(),
                r#"{"op":"profiles"}"#.to_owned(),
            ] {
                let mut client = Client::connect(socket);
                client.hello();
                client.send(&bad);
                assert_eq!(client.next(), None, "{}", &bad[..bad.len().min(30)]);
            }
        });
    }

    /// `status` and `profiles` report the profile as the files, the entry and the
    /// supervisor say, with the state resolved on the host.
    #[test]
    fn status_and_profiles() {
        let rig = Rig::new();
        rig.serving(&me, |socket| {
            let mut client = Client::connect(socket);
            client.hello();
            let profiles = client.call(r#"{"id":2,"op":"profiles"}"#);
            assert_eq!(
                profiles["result"],
                json!({"profiles":[{"id":"lab","name":"Lab","gateway":"lab.example.com",
                    "saml_port":8443,"transport":"tcp","auto_start":false}]})
            );
            let status = settled(&mut client);
            let seq = status["seq"].as_u64().unwrap();
            assert_eq!(status["component"]["state"], "ready");
            assert_eq!(status["schema"], 1);
            assert_eq!(status["generated"], "2026-11-04T12:20:00Z");
            assert_eq!(status["host"]["provider_build"], "50");
            assert_eq!(
                status["login"],
                json!({"menu_item":"enabled","agent":"disabled","host_agent":"requires_approval"})
            );
            let lab = &status["profiles"][0];
            assert_eq!(
                (lab["state"].as_str(), lab["ne_status"].as_str()),
                (Some("disconnected"), Some("disconnected"))
            );
            assert_eq!(lab["phase"], Value::Null);

            // The tunnel comes up: the next `status` says so, the sequence moves on, and
            // `connected_since` is when this host first saw it.
            rig.entry.set_status(VpnStatus::Connected);
            let status = client.call(r#"{"id":4,"op":"status"}"#)["result"].clone();
            assert_eq!(status["seq"], seq + 1);
            let lab = &status["profiles"][0];
            assert_eq!(lab["state"], "connected");
            assert_eq!(lab["connected_since"], "2026-11-04T12:20:00Z");
            assert_eq!(lab["traffic"], Value::Null);
            // Nothing changed: the same document keeps its number.
            let again = client.call(r#"{"id":5,"op":"status"}"#)["result"].clone();
            assert_eq!(again["seq"], seq + 1);
        });
    }

    /// A failed supervisor's recorded provider code (the rig's profile is TCP-only, so 201 is "no answer") becomes `profiles[].error` (code
    /// and plain message); a failure with no plain reason, or any other phase, has none.
    #[test]
    fn a_failed_profile_says_why() {
        let rig = Rig::new();
        let directory = registry::entry_directory(rig.env.root(), "lab");
        let record = |phase, failure| {
            let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_793_794_800);
            let lease = "A4DF24C9-D3A9-4D2E-896A-95AC0C2B535A";
            crate::status::StatusStore::new(&directory)
                .publish_failure(phase, failure, lease, now);
        };
        rig.serving(&me, |socket| {
            let mut client = Client::connect(socket);
            client.hello();
            settled(&mut client);
            for (phase, failure, want) in [
                (crate::status::Phase::Failed, Some(201), Some("gateway_no_answer")),
                (crate::status::Phase::Failed, Some(900), None),
                // `Stopped` is returned by the reader without a lock, so this pins the failed-only gate.
                (crate::status::Phase::Stopped, Some(201), None),
            ] {
                record(phase, failure);
                let status = client.call(r#"{"id":3,"op":"status"}"#)["result"].clone();
                let error = &status["profiles"][0]["error"];
                assert_eq!(error["code"].as_str(), want, "{phase:?} {failure:?}");
                if want.is_some() {
                    assert!(error["detail"].as_str().unwrap().contains("TCP"));
                    assert_eq!(status["profiles"][0]["state"], "attention");
                } else {
                    assert_eq!(*error, Value::Null);
                }
            }
        });
    }

    /// The component is `checking` until the extension request answers, then what
    /// the request says, and the change reaches a subscriber as a `status` event.
    #[test]
    fn the_component_check_runs_in_the_background() {
        let rig = Rig::new();
        rig.serving(&me, |socket| {
            let mut client = Client::connect(socket);
            client.hello();
            client.call(r#"{"id":2,"op":"subscribe","topics":["status"]}"#);
            let mut component = String::new();
            let deadline = Instant::now() + Duration::from_secs(10);
            while component != "ready" && Instant::now() < deadline {
                let event = client.next().expect("events");
                component = event["status"]["component"]["state"]
                    .as_str()
                    .unwrap()
                    .to_owned();
                if component == "ready" {
                    assert_eq!(event["status"]["component"]["installed_build"], "50");
                    assert_eq!(event["status"]["component"]["expected_build"], "50");
                }
            }
            assert_eq!(component, "ready");
        });
    }

    /// The installed extension is compared with the bundled provider's build, never the
    /// host's: here they differ (host 24, provider 50), so an extension at the host's build is
    /// out of date, and one at the provider's build is ready (the test above).
    #[test]
    fn the_extension_is_compared_with_the_provider_build_not_the_host_build() {
        let rig = Rig::new();
        rig.extensions.mock.set_properties(
            &rig.env.provider_id(),
            Ok(vec![ExtensionProperties {
                short_version: "1.0".into(),
                build: "24".into(),
                enabled: true,
                awaiting_approval: false,
                uninstalling: false,
            }]),
        );
        rig.serving(&me, |socket| {
            let mut client = Client::connect(socket);
            client.hello();
            client.call(r#"{"id":2,"op":"subscribe","topics":["status"]}"#);
            let mut component = String::new();
            let deadline = Instant::now() + Duration::from_secs(10);
            while component != "update_required" && Instant::now() < deadline {
                let event = client.next().expect("events");
                component = event["status"]["component"]["state"].as_str().unwrap().to_owned();
                if component == "update_required" {
                    assert_eq!(event["status"]["component"]["installed_build"], "24");
                    assert_eq!(event["status"]["component"]["expected_build"], "50");
                }
            }
            assert_eq!(component, "update_required");
        });
    }

    /// Subscribe: the reply comes first, then the current status at once; a change then
    /// arrives as the next `seq`, and two events on one connection are at least 100 ms
    /// apart however fast the world changes. A status-only subscriber causes no
    /// provider traffic, even with a connected tunnel.
    #[test]
    fn subscribe_ordering_and_debounce() {
        let rig = Rig::new();
        connected_with_replies(&rig, &[100]);
        rig.serving(&me, |socket| {
            let mut client = Client::connect(socket);
            client.hello();
            let before = settled(&mut client)["seq"].as_u64().unwrap();
            client.send(r#"{"id":2,"op":"subscribe","topics":["status","nonsense"]}"#);
            let reply = client.next().unwrap();
            assert_eq!(reply, json!({"id":2,"ok":true,"result":{}}));
            let first = client.next().unwrap();
            assert_eq!(
                (first["event"].as_str(), first["seq"].as_u64()),
                (Some("status"), Some(before))
            );
            assert_eq!(first["status"]["profiles"][0]["state"], "connected");
            assert_eq!(first["status"]["seq"], first["seq"]);

            // Three changes in a burst; the last wins, and the events are spaced.
            let sent = Instant::now();
            rig.entry.set_status(VpnStatus::Reasserting);
            rig.entry.set_status(VpnStatus::Disconnecting);
            rig.entry.set_status(VpnStatus::Disconnected);
            let mut last = first.clone();
            let mut stamps = vec![Instant::now()];
            while last["status"]["profiles"][0]["state"] != "disconnected" {
                last = client.next().unwrap();
                stamps.push(Instant::now());
            }
            assert!(last["seq"].as_u64().unwrap() > before);
            for pair in stamps.windows(2) {
                assert!(
                    pair[1] - pair[0] >= Duration::from_millis(95),
                    "{:?}",
                    pair[1] - pair[0]
                );
            }
            assert!(sent.elapsed() < Duration::from_secs(5));
            // Re-subscribing is owed the current status again.
            client.send(r#"{"id":3,"op":"subscribe","topics":["status"]}"#);
            assert_eq!(client.next().unwrap()["id"], 3);
            assert_eq!(client.next().unwrap()["status"]["seq"], last["seq"]);
            // And an unsubscribed connection hears nothing more.
            client.send(r#"{"id":4,"op":"unsubscribe"}"#);
            assert_eq!(client.next().unwrap()["id"], 4);
            rig.entry.set_status(VpnStatus::Connecting);
            let deadline = Instant::now() + Duration::from_millis(1500);
            client
                .reader
                .get_ref()
                .set_read_timeout(Some(Duration::from_millis(300)))
                .unwrap();
            while Instant::now() < deadline {
                assert_eq!(client.next(), None);
            }
        });
        // Status subscribers never made the provider send traffic.
        assert!(rig.entry.sent().is_empty());
    }

    /// With a `traffic` subscriber the host samples once a second: the first sample
    /// has totals and no rates (a rate needs two), the next has the rates from the
    /// provider's own uptime, and each sample has its own, increasing `sample_seq`.
    #[test]
    fn traffic_sample_sequence() {
        let rig = Rig::new();
        connected_with_replies(&rig, &[100, 101, 102]);
        rig.serving(&me, |socket| {
            let mut client = Client::connect(socket);
            client.hello();
            client.send(r#"{"id":2,"op":"subscribe","topics":["status","traffic"]}"#);
            assert_eq!(client.next().unwrap()["id"], 2);
            assert_eq!(client.next().unwrap()["event"], "status");
            let mut samples = Vec::new();
            while samples.len() < 3 {
                let event = client.next().expect("traffic");
                if event["event"] == "traffic" {
                    samples.push(event);
                }
            }
            for sample in &samples {
                assert_eq!(sample["profile"], "lab");
                assert_eq!(sample["session"], "11111111");
            }
            let rows: Vec<(u64, u64, Option<f64>, Option<f64>)> = samples
                .iter()
                .map(|s| {
                    (
                        s["sample_seq"].as_u64().unwrap(),
                        s["rx_bytes"].as_u64().unwrap(),
                        s["rx_rate"].as_f64(),
                        s["tx_rate"].as_f64(),
                    )
                })
                .collect();
            assert_eq!(rows[0].1, 1000);
            assert_eq!((rows[0].2, rows[0].3), (None, None));
            assert_eq!(
                (rows[1].1, rows[1].2, rows[1].3),
                (2000, Some(1000.0), Some(100.0))
            );
            assert_eq!(
                (rows[2].1, rows[2].2, rows[2].3),
                (3000, Some(1000.0), Some(100.0))
            );
            assert!(rows[0].0 < rows[1].0 && rows[1].0 < rows[2].0);
        });
        let sent = rig.entry.sent();
        assert!(sent.len() >= 3 && sent.iter().all(|m| m == b"oftc.traffic.v1"));
    }

    /// The 17th simultaneous connection is closed with nothing said; when one of the 16
    /// ends its slot is free again.
    #[test]
    fn the_connection_cap_is_sixteen() {
        let rig = Rig::new();
        rig.serving(&me, |socket| {
            let mut held: Vec<Client> = (0..MAX_CONNECTIONS)
                .map(|_| {
                    let mut client = Client::connect(socket);
                    assert_eq!(client.hello()["ok"], true);
                    client
                })
                .collect();
            let mut seventeenth = Client::connect(socket);
            seventeenth.send(r#"{"id":1,"op":"hello","protocol":[1,1]}"#);
            assert_eq!(seventeenth.next(), None);
            drop(held.pop());
            // The slot is released when the server notices the close; allow it a moment.
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                let mut again = Client::connect(socket);
                again.send(r#"{"id":1,"op":"hello","protocol":[1,1]}"#);
                if again.next().is_some() {
                    break;
                }
                assert!(Instant::now() < deadline, "slot never freed");
                thread::sleep(Duration::from_millis(20));
            }
        });
    }

    /// `hello` has one deadline for the whole exchange: a client that keeps sending a
    /// byte at a time, never finishing a line, is cut off at it (a per-read timeout
    /// would never fire).
    #[test]
    fn the_hello_deadline_is_total() {
        let rig = Rig::new();
        rig.serving(&me, |socket| {
            let mut client = Client::connect(socket);
            let started = Instant::now();
            let mut closed = false;
            while started.elapsed() < Duration::from_secs(5) {
                if client.writer.write_all(b" ").is_err() {
                    closed = true;
                    break;
                }
                thread::sleep(Duration::from_millis(50));
            }
            assert!(closed, "still open after 5 s of dribbling");
            assert!(started.elapsed() >= Duration::from_millis(350));
            assert_eq!(client.next(), None);
            // A client that says hello in time is not cut off later.
            let mut good = Client::connect(socket);
            assert_eq!(good.hello()["ok"], true);
            thread::sleep(Duration::from_millis(700));
            assert_eq!(good.call(r#"{"id":2,"op":"profiles"}"#)["ok"], true);
        });
    }

    /// A VPN backend whose loading panics, as a bug in the refresh path would.
    struct Broken;

    impl oftc_apple::manager::VpnControl for Broken {
        fn load_all(&self) -> oftc_apple::manager::Result<Vec<oftc_apple::manager::VpnEntry>> {
            panic!("broken");
        }
        fn reload(
            &self,
            _: &oftc_apple::manager::VpnEntry,
        ) -> oftc_apple::manager::Result<oftc_apple::manager::VpnEntry> {
            unimplemented!()
        }
        fn status(&self, _: &oftc_apple::manager::VpnEntry) -> VpnStatus {
            unimplemented!()
        }
        fn create(&self, _: &str, _: &str, _: &str) -> oftc_apple::manager::Result<()> {
            unimplemented!()
        }
        fn set_enabled(
            &self,
            _: &oftc_apple::manager::VpnEntry,
            _: bool,
        ) -> oftc_apple::manager::Result<()> {
            unimplemented!()
        }
        fn remove(&self, _: &oftc_apple::manager::VpnEntry) -> oftc_apple::manager::Result<()> {
            unimplemented!()
        }
        fn start(
            &self,
            _: &oftc_apple::manager::VpnEntry,
            _: oftc_apple::manager::StartOptions,
        ) -> oftc_apple::manager::Result<()> {
            unimplemented!()
        }
        fn stop(&self, _: &oftc_apple::manager::VpnEntry) {
            unimplemented!()
        }
        fn send_provider_message(
            &self,
            _: &oftc_apple::manager::VpnEntry,
            _: &[u8],
            _: Duration,
        ) -> oftc_apple::manager::Result<Vec<u8>> {
            unimplemented!()
        }
        fn last_disconnect_error(
            &self,
            _: &oftc_apple::manager::VpnEntry,
            _: Duration,
        ) -> oftc_apple::manager::Result<Option<oftc_apple::error::AppleError>> {
            unimplemented!()
        }
        fn observe_status(
            &self,
            _: &oftc_apple::manager::VpnEntry,
            _: mpsc::Sender<()>,
        ) -> oftc_apple::manager::Result<oftc_apple::manager::Subscription> {
            unimplemented!()
        }
    }

    /// A host whose refresh loop has died must stop (reporting failure, so the verb exits
    /// non-zero and launchd restarts it) instead of serving stale documents forever.
    #[test]
    fn a_dead_refresh_loop_stops_the_server() {
        let rig = Rig::new();
        let bound = listener::bind(&rig.dir.0).unwrap();
        let services = Services {
            vpn: &Broken,
            ..rig.services()
        };
        let started = Instant::now();
        let healthy = serve(&bound.listener, &services, 501, &me, &|| {
            started.elapsed() > Duration::from_secs(20)
        });
        assert!(!healthy);
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    /// `host serve` as the verb runs it: it serves with the real peer check until the
    /// stop signal, and removes its socket; a second one is told it is not needed.
    #[test]
    fn the_verb_serves_until_signalled() {
        let rig = Rig::new();
        let signals = ManualSignals::default();
        let socket = listener::socket_path(&rig.dir.0);
        let long = socket.as_os_str().len();
        assert!(long <= 103, "test path too long: {long}");
        thread::scope(|scope| {
            let served = scope.spawn(|| {
                run(
                    &rig.env,
                    &rig.dir.0,
                    &rig.vpn,
                    &rig.extensions,
                    &rig.login,
                    &signals,
                    rig.ops(),
                )
            });
            let _stop = OnDrop(|| signals.raise());
            let deadline = Instant::now() + Duration::from_secs(10);
            while !socket.exists() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(10));
            }
            assert_eq!(Client::connect(&socket).hello()["ok"], true);
            let second = ManualSignals::default();
            assert_eq!(
                run(
                    &rig.env,
                    &rig.dir.0,
                    &rig.vpn,
                    &rig.extensions,
                    &rig.login,
                    &second,
                    rig.ops()
                ),
                (String::new(), 0)
            );
            assert!(socket.exists(), "a second host must not displace the first");
            signals.raise();
            assert_eq!(served.join().unwrap(), (String::new(), 0));
        });
        assert!(!socket.exists());
    }

    /// A user name that pushes the socket path past `sun_path` is refused up front,
    /// with the documented message, and nothing is created.
    #[test]
    fn the_verb_refuses_a_path_that_is_too_long() {
        let dir = TempDir::new("serve-long");
        let home: PathBuf = dir.0.join("u".repeat(60));
        let env = HostEnv::new("com.example.oftc", &home).unwrap();
        let signals = ManualSignals::default();
        let rig = Rig::new();
        let (vpn, extensions, login) =
            (MockVpn::new(), MockExtensions::new(), MockLoginItems::new());
        assert_eq!(
            run(&env, env.root(), &vpn, &extensions, &login, &signals, rig.ops()),
            ("host_unavailable: path too long".to_owned(), 1)
        );
        assert!(!home.exists());
    }
}
