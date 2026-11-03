//! The provider's state machine. Ports `PacketTunnelProvider.swift`.
//!
//! Swift confined state to the main queue and ran work on a session queue and a
//! receive queue. Here the host calls [`Provider::start`] and [`Provider::stop`]
//! from its own threads (a stop may arrive while a start is still blocked), and
//! three worker threads run once the tunnel is up:
//!
//! - **receiver**: blocks in [`Link::receive`], writes inbound packets to the OS;
//! - **sender**: blocks in [`Tunnel::read_packets`], sends outbound packets in
//!   slices of 64;
//! - **liveness**: every 5 s ticks DPD, and every third tick a NAT keepalive.
//!
//! No thread holds the state lock across a call into the link or the tunnel, so
//! sends and ticks never wait behind a blocked receive (Issue 39).
//!
//! Shutdown order is the Swift one: cancel the engine, send the DELETEs, close
//! the OS side so the blocked reader returns, join the workers, clear the
//! settings, then release every `stop` waiter. A start that is still connecting
//! or applying settings (`busy`) defers all of that until it returns, which is
//! what `settingsApplyPending` did.

use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use oftc_engine::tunnel::Tunnel;
use oftc_engine::Cancellation;

use crate::envelope::{StartEnvelopes, StartMode, StartOptions};
use crate::link::{Backend, Inbound, Link, PACKET_DROPPED, RECONNECT_NEEDED};
use crate::settings;
use crate::traffic::TrafficCounters;

const LIVENESS_INTERVAL: Duration = Duration::from_secs(5);
/// Every third tick also refreshes the outer NAT mapping. The keepalive does
/// not extend the authenticated DPD grace period.
const KEEPALIVE_EVERY: u32 = 3;
/// One batch from the OS is split so inbound ESP is not starved.
const SEND_SLICE: usize = 64;
const MAX_INNER_PACKET: usize = 65_535;

/// Why the tunnel stopped; the code is the `OFTCProvider` NSError code the
/// Swift provider reported, which the host logs. 1 busy, 2 bad start options,
/// 3 no session id, 4 settings invalid, 5 settings refused by the OS, 6 bad
/// inbound packet, 7 write refused, 8 peer deleted the SA, 9 stopped by the
/// host, 10 tunnel closed by the OS (new: Swift's packet flow cannot close),
/// 900 a worker panicked (new); 100+n connect, 200+n send, 300+n receive,
/// 400+n liveness, 500+n rekey probe, with n the engine status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Failure(pub i32);

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OFTC provider stage {} failed", self.0)
    }
}

impl std::error::Error for Failure {}

const STOPPED_BY_HOST: Failure = Failure(9);

struct State<L> {
    starts: StartEnvelopes,
    /// A `start` has not finished (Swift's `pendingStart`).
    starting: bool,
    /// `start` is inside connect, preflight or `apply_settings`; cleanup waits.
    busy: bool,
    running: bool,
    stopping: bool,
    /// The tunnel had come up when it was told to stop.
    was_started: bool,
    cleanup_started: bool,
    cleanup_finished: bool,
    failure: Failure,
    /// `stop` calls waiting for cleanup to finish.
    waiters: usize,
    link: Option<Arc<L>>,
    workers: Vec<JoinHandle<()>>,
    preflight: Option<i32>,
    traffic: Option<TrafficCounters>,
    rekey_pending: bool,
    ticks: u32,
}

struct Shared<B: Backend, T> {
    backend: B,
    tunnel: T,
    cancel: Cancellation,
    on_failure: Box<dyn Fn(Failure) + Send + Sync>,
    liveness_interval: Duration,
    epoch: Instant,
    state: Mutex<State<B::Link>>,
    /// Signalled on every state change that a waiter cares about.
    changed: Condvar,
}

/// One tunnel's worth of provider logic. Create one per provider process.
pub struct Provider<B: Backend, T: Tunnel + 'static>(Arc<Shared<B, T>>);

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

impl<B: Backend, T: Tunnel + 'static> Provider<B, T> {
    /// `on_failure` is called, once, when the provider ends a tunnel that had
    /// come up and no `stop` is waiting (Swift's `cancelTunnelWithError`).
    pub fn new(backend: B, tunnel: T, on_failure: impl Fn(Failure) + Send + Sync + 'static) -> Self {
        Self::with_liveness_interval(backend, tunnel, on_failure, LIVENESS_INTERVAL)
    }

    pub(crate) fn with_liveness_interval(
        backend: B,
        tunnel: T,
        on_failure: impl Fn(Failure) + Send + Sync + 'static,
        liveness_interval: Duration,
    ) -> Self {
        Self(Arc::new(Shared {
            backend,
            tunnel,
            cancel: Cancellation::default(),
            on_failure: Box::new(on_failure),
            liveness_interval,
            epoch: Instant::now(),
            state: Mutex::new(State {
                starts: StartEnvelopes::default(),
                starting: false,
                busy: false,
                running: false,
                stopping: false,
                was_started: false,
                cleanup_started: false,
                cleanup_finished: false,
                failure: STOPPED_BY_HOST,
                waiters: 0,
                link: None,
                workers: Vec::new(),
                preflight: None,
                traffic: None,
                rekey_pending: false,
                ticks: 0,
            }),
            changed: Condvar::new(),
        }))
    }

    /// Bring the tunnel up, or run the preflight, and return once it is
    /// running. Blocks; a concurrent [`stop`](Self::stop) makes it return the
    /// stop's failure after cleanup.
    pub fn start(&self, options: &StartOptions) -> Result<(), Failure> {
        self.0.start(options)
    }

    /// Stop the tunnel and block until cleanup has finished. Safe to call
    /// concurrently, repeatedly, and before or during a start.
    pub fn stop(&self) {
        self.0.stop();
    }

    /// Answer a provider message (`docs/provider-messages.md`); `None` is "no reply data".
    pub fn handle_message(&self, message: &[u8]) -> Option<Vec<u8>> {
        self.0.handle_message(message)
    }
}

impl<B: Backend, T: Tunnel + 'static> Shared<B, T> {
    fn lock(&self) -> MutexGuard<'_, State<B::Link>> {
        // A panicking worker must not turn every later call into a panic.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn wait<'a>(&self, st: MutexGuard<'a, State<B::Link>>) -> MutexGuard<'a, State<B::Link>> {
        self.changed.wait(st).unwrap_or_else(PoisonError::into_inner)
    }

    // ---- start ---------------------------------------------------------

    fn start(self: &Arc<Self>, options: &StartOptions) -> Result<(), Failure> {
        let mode = {
            let mut st = self.lock();
            if st.starting || st.link.is_some() || st.stopping {
                return Err(Failure(1));
            }
            let mode = st.starts.consume(options, unix_now()).map_err(|_| Failure(2))?;
            st.starting = true;
            st.busy = true;
            mode
        };
        match mode {
            StartMode::Preflight(input) => {
                // A diagnostic-only connection: no settings, routes, DNS or packets.
                let status = self.backend.preflight(&input);
                drop(input);
                let mut st = self.leave_busy(self.lock())?;
                st.preflight = Some(status);
                st.starting = false;
                Ok(())
            }
            StartMode::Live(input, mode) => {
                let connected = self.backend.connect(input, mode.0, self.cancel.clone());
                let link = match connected {
                    Ok(link) => Arc::new(link),
                    Err(status) => return self.fail_start(Failure(100 + status)),
                };
                {
                    let mut st = self.lock();
                    // Visible to a stop that arrives from here on, so it is cancelled.
                    st.link = Some(link.clone());
                    if st.stopping {
                        link.cancel();
                        return self.leave_busy(st).map(drop);
                    }
                }
                self.finish_live_start(link)
            }
        }
    }

    fn finish_live_start(self: &Arc<Self>, link: Arc<B::Link>) -> Result<(), Failure> {
        let settings = link.settings();
        if settings::validate(&settings).is_err() {
            return self.fail_start(Failure(4));
        }
        // A stop that arrives now is deferred until this call returns: the
        // OS may be applying the settings, and they must be cleared after.
        let applied = self.tunnel.apply_settings(&settings);
        let mut st = self.leave_busy(self.lock())?;
        if applied.is_err() {
            self.begin_shutdown(&mut st, Failure(5));
            return Err(self.await_cleanup(st));
        }
        let Ok(traffic) = TrafficCounters::new() else {
            self.begin_shutdown(&mut st, Failure(3));
            return Err(self.await_cleanup(st));
        };
        st.running = true;
        st.traffic = Some(traffic);
        st.starting = false;
        let workers = [
            self.spawn_worker(Self::receive_loop, &link),
            self.spawn_worker(Self::send_loop, &link),
            self.spawn_worker(Self::liveness_loop, &link),
        ];
        st.workers.extend(workers);
        Ok(())
    }

    /// Leave the blocking part of a start. If a stop arrived meanwhile, finish
    /// the shutdown it deferred and report its failure.
    fn leave_busy<'a>(
        self: &'a Arc<Self>,
        mut st: MutexGuard<'a, State<B::Link>>,
    ) -> Result<MutexGuard<'a, State<B::Link>>, Failure> {
        st.busy = false;
        if st.stopping {
            self.spawn_cleanup(&mut st);
            return Err(self.await_cleanup(st));
        }
        Ok(st)
    }

    fn fail_start(self: &Arc<Self>, failure: Failure) -> Result<(), Failure> {
        let mut st = self.lock();
        self.begin_shutdown(&mut st, failure);
        self.leave_busy(st).map(drop)
    }

    // ---- shutdown ------------------------------------------------------

    fn stop(self: &Arc<Self>) {
        let mut st = self.lock();
        st.waiters += 1;
        self.begin_shutdown(&mut st, STOPPED_BY_HOST);
        self.await_cleanup(st);
    }

    /// The first failure wins. Cancels the engine; starts cleanup unless a
    /// start is still in a blocking call, which will start it when it returns.
    fn begin_shutdown(self: &Arc<Self>, st: &mut State<B::Link>, failure: Failure) {
        if st.stopping {
            return;
        }
        st.stopping = true;
        st.running = false;
        st.failure = failure;
        st.was_started = !st.starting;
        // Cancels a connect in progress; a connected link is cancelled too.
        self.cancel.cancel();
        if let Some(link) = &st.link {
            link.cancel();
        }
        self.changed.notify_all();
        if !st.busy {
            self.spawn_cleanup(st);
        }
    }

    fn shutdown(self: &Arc<Self>, failure: Failure) {
        let mut st = self.lock();
        self.begin_shutdown(&mut st, failure);
    }

    fn await_cleanup(&self, mut st: MutexGuard<'_, State<B::Link>>) -> Failure {
        while !st.cleanup_finished {
            st = self.wait(st);
        }
        st.failure
    }

    fn spawn_cleanup(self: &Arc<Self>, st: &mut State<B::Link>) {
        if st.cleanup_started {
            return;
        }
        st.cleanup_started = true;
        let this = self.clone();
        std::thread::spawn(move || this.cleanup());
    }

    fn cleanup(self: &Arc<Self>) {
        let link = self.lock().link.clone();
        if let Some(link) = &link {
            link.teardown();
        }
        // Wake the sender, which is blocked in `read_packets`, then join the
        // workers; the engine was cancelled, so the receiver returns too.
        self.tunnel.close();
        let workers = std::mem::take(&mut self.lock().workers);
        for worker in workers {
            let _ = worker.join();
        }
        let _ = self.tunnel.clear_settings();
        let (notify, failure) = {
            let mut st = self.lock();
            st.link = None;
            st.cleanup_finished = true;
            self.changed.notify_all();
            (st.was_started && st.waiters == 0, st.failure)
        };
        if notify {
            (self.on_failure)(failure);
        }
    }

    // ---- workers -------------------------------------------------------

    fn spawn_worker(
        self: &Arc<Self>,
        body: fn(&Arc<Self>, &B::Link),
        link: &Arc<B::Link>,
    ) -> JoinHandle<()> {
        let (this, link) = (self.clone(), link.clone());
        std::thread::spawn(move || {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| body(&this, &link)));
            if outcome.is_err() {
                this.shutdown(Failure(900));
            }
        })
    }

    fn is_stopping(&self) -> bool {
        self.lock().stopping
    }

    fn receive_loop(self: &Arc<Self>, link: &B::Link) {
        while !self.is_stopping() {
            let event = link.receive();
            if self.is_stopping() {
                return;
            }
            match event {
                Ok(Inbound::Packet(packet)) => {
                    if !(20..=MAX_INNER_PACKET).contains(&packet.len()) || packet[0] >> 4 != 4 {
                        return self.shutdown(Failure(6));
                    }
                    if self.tunnel.write_packet(&packet).is_err() {
                        return self.shutdown(Failure(7));
                    }
                    if let Some(traffic) = self.lock().traffic.as_mut() {
                        traffic.received(packet.len());
                    }
                }
                Ok(Inbound::PeerDeleted) => return self.shutdown(Failure(8)),
                Ok(Inbound::Idle) => {}
                Err(status) => return self.shutdown(Failure(300 + status)),
            }
        }
    }

    fn send_loop(self: &Arc<Self>, link: &B::Link) {
        loop {
            let Ok(batch) = self.tunnel.read_packets() else {
                // Closed by the OS, or by our own shutdown.
                return self.shutdown(Failure(10));
            };
            for slice in batch.chunks(SEND_SLICE) {
                if self.is_stopping() {
                    return;
                }
                let (mut sent, mut failed) = (0, None);
                for packet in slice {
                    match link.send_ip(packet) {
                        Ok(()) => sent += packet.len(),
                        Err(PACKET_DROPPED) => {}
                        Err(status) => {
                            failed = Some(status);
                            break;
                        }
                    }
                }
                {
                    let mut st = self.lock();
                    if st.stopping {
                        return;
                    }
                    if let Some(traffic) = st.traffic.as_mut() {
                        traffic.sent(sent);
                    }
                }
                if let Some(status) = failed {
                    return self.shutdown(Failure(200 + status));
                }
            }
        }
    }

    fn liveness_loop(self: &Arc<Self>, _link: &B::Link) {
        loop {
            {
                let st = self.lock();
                let (st, _) = self
                    .changed
                    .wait_timeout_while(st, self.liveness_interval, |s| !s.stopping)
                    .unwrap_or_else(PoisonError::into_inner);
                if st.stopping {
                    return;
                }
            }
            self.liveness_tick();
        }
    }

    /// One liveness tick; the timer in `liveness_loop` and the tests call this.
    pub(crate) fn liveness_tick(self: &Arc<Self>) {
        let (link, refresh_mapping) = {
            let mut st = self.lock();
            let Some(link) = st.link.clone().filter(|_| st.running && !st.stopping) else {
                return;
            };
            st.ticks += 1;
            (link, st.ticks.is_multiple_of(KEEPALIVE_EVERY))
        };
        let mut result = link.tick_liveness();
        if result.is_ok() && refresh_mapping {
            result = link.send_nat_keepalive();
        }
        if let Err(status) = result {
            let failure = if status == RECONNECT_NEEDED { 409 } else { 400 + status };
            let mut st = self.lock();
            if st.running && !st.stopping {
                self.begin_shutdown(&mut st, Failure(failure));
            }
        }
    }

    // ---- provider messages ----------------------------------------------

    fn handle_message(self: &Arc<Self>, message: &[u8]) -> Option<Vec<u8>> {
        match message {
            b"oftc.traffic.v1" => {
                let st = self.lock();
                let traffic = st.traffic.as_ref().filter(|_| st.running && !st.stopping)?;
                Some(traffic.snapshot_json(self.epoch.elapsed().as_secs_f64()))
            }
            b"oftc.rekey-counts.v1" => {
                let link = self.running_link()?;
                let counts = link.rekey_counts();
                let st = self.lock();
                match counts {
                    Ok((local, peer, ike)) if st.running && !st.stopping => Some(
                        format!("child_rekeys local={local} peer={peer} ike={ike}").into_bytes(),
                    ),
                    _ => None,
                }
            }
            b"oftc.rekey-child-once.v1" => Some(self.rekey_probe(|l| l.rekey_child_once())),
            b"oftc.rekey-ike-once.v1" => Some(self.rekey_probe(|l| l.rekey_ike_once())),
            b"oftc.preflight-status.v1" => {
                let result = self.lock().preflight?;
                Some(
                    if result == 0 {
                        "preflight_passed responder_auth_and_eap_challenge".to_owned()
                    } else {
                        format!("preflight_failed stage={result}")
                    }
                    .into_bytes(),
                )
            }
            _ => None,
        }
    }

    fn running_link(&self) -> Option<Arc<B::Link>> {
        let st = self.lock();
        st.link.clone().filter(|_| st.running && !st.stopping)
    }

    /// A rekey probe fails closed: a failed probe also stops the tunnel.
    fn rekey_probe(self: &Arc<Self>, probe: impl FnOnce(&B::Link) -> Result<(), i32>) -> Vec<u8> {
        let link = {
            let mut st = self.lock();
            match st.link.clone().filter(|_| st.running && !st.stopping && !st.rekey_pending) {
                Some(link) => {
                    st.rekey_pending = true;
                    link
                }
                None => return b"rekey_unavailable".to_vec(),
            }
        };
        let status = probe(&link);
        let mut st = self.lock();
        st.rekey_pending = false;
        if st.stopping {
            return b"rekey_stopped".to_vec();
        }
        match status {
            Ok(()) => b"rekey_passed".to_vec(),
            Err(status) => {
                self.begin_shutdown(&mut st, Failure(500 + status));
                format!("rekey_failed stage={status}").into_bytes()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::tests::{id, live};
    use crate::link::{Backend, Inbound, Link, Status, CANCELLED};
    use oftc_engine::tunnel::{loopback, LoopbackPeer, LoopbackTunnel, TunnelError};
    use oftc_engine::{AddressRange, NetworkSettings};
    use std::collections::VecDeque;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc::{channel, Receiver, Sender};
    use std::sync::Condvar;
    use std::thread;

    type Log = Arc<Mutex<Vec<String>>>;

    fn note(log: &Log, event: &str) {
        log.lock().unwrap().push(event.to_owned());
    }

    fn events(log: &Log) -> Vec<String> {
        log.lock().unwrap().clone()
    }

    /// Spin (no sleeps) until `condition` holds. A broken test hits the deadline
    /// instead of hanging the suite.
    fn eventually(mut condition: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while !condition() {
            assert!(Instant::now() < deadline, "condition never became true");
            thread::yield_now();
        }
    }

    fn good_settings() -> NetworkSettings {
        NetworkSettings {
            outer_remote_ipv4: Ipv4Addr::new(203, 0, 113, 7),
            outer_remote_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
            assigned_ipv4: Ipv4Addr::new(10, 99, 0, 12),
            netmask: None,
            split_routes: vec![AddressRange {
                first: IpAddr::V4(Ipv4Addr::new(10, 0, 8, 0)),
                last: IpAddr::V4(Ipv4Addr::new(10, 0, 15, 255)),
            }],
            dns_servers: vec![Ipv4Addr::new(10, 0, 8, 1)],
            dns_domains: vec!["corp.example".into()],
            inner_mtu: 1280,
        }
    }

    // ---- a scriptable engine session ------------------------------------

    struct LinkState {
        inbound: VecDeque<Result<Inbound, Status>>,
        sent: Vec<Vec<u8>>,
        send_errors: VecDeque<Status>,
        receiving: usize,
        cancelled: bool,
        ticks: u32,
        keepalives: u32,
        tick_error: Option<Status>,
        rekey_result: Result<(), Status>,
        rekey_gate: Option<Receiver<()>>,
    }

    #[derive(Clone)]
    struct FakeLink {
        log: Log,
        state: Arc<(Mutex<LinkState>, Condvar)>,
        settings: NetworkSettings,
    }

    impl FakeLink {
        fn new(log: &Log) -> Self {
            Self {
                log: log.clone(),
                settings: good_settings(),
                state: Arc::new((
                    Mutex::new(LinkState {
                        inbound: VecDeque::new(),
                        sent: Vec::new(),
                        send_errors: VecDeque::new(),
                        receiving: 0,
                        cancelled: false,
                        ticks: 0,
                        keepalives: 0,
                        tick_error: None,
                        rekey_result: Ok(()),
                        rekey_gate: None,
                    }),
                    Condvar::new(),
                )),
            }
        }

        fn with<R>(&self, f: impl FnOnce(&mut LinkState) -> R) -> R {
            let (lock, changed) = &*self.state;
            let result = f(&mut lock.lock().unwrap());
            changed.notify_all();
            result
        }

        fn push(&self, event: Result<Inbound, Status>) {
            self.with(|s| s.inbound.push_back(event));
        }

        fn wait_receiving(&self) {
            let (lock, changed) = &*self.state;
            let mut s = lock.lock().unwrap();
            while s.receiving == 0 {
                s = changed.wait(s).unwrap();
            }
        }

        fn wait_sent(&self, count: usize) -> Vec<Vec<u8>> {
            let (lock, changed) = &*self.state;
            let mut s = lock.lock().unwrap();
            while s.sent.len() < count {
                s = changed.wait(s).unwrap();
            }
            s.sent.clone()
        }
    }

    impl Link for FakeLink {
        fn settings(&self) -> NetworkSettings {
            self.settings.clone()
        }

        fn receive(&self) -> Result<Inbound, Status> {
            let (lock, changed) = &*self.state;
            let mut s = lock.lock().unwrap();
            s.receiving += 1;
            changed.notify_all();
            let result = loop {
                if s.cancelled {
                    break Err(CANCELLED);
                }
                if let Some(event) = s.inbound.pop_front() {
                    break event;
                }
                s = changed.wait(s).unwrap();
            };
            s.receiving -= 1;
            result
        }

        fn send_ip(&self, packet: &[u8]) -> Result<(), Status> {
            self.with(|s| {
                s.sent.push(packet.to_vec());
                s.send_errors.pop_front().map_or(Ok(()), Err)
            })
        }

        fn tick_liveness(&self) -> Result<(), Status> {
            self.with(|s| {
                s.ticks += 1;
                s.tick_error.map_or(Ok(()), Err)
            })
        }

        fn send_nat_keepalive(&self) -> Result<(), Status> {
            self.with(|s| s.keepalives += 1);
            Ok(())
        }

        fn rekey_counts(&self) -> Result<(u32, u32, u32), Status> {
            Ok((3, 2, 1))
        }

        fn rekey_child_once(&self) -> Result<(), Status> {
            let gate = self.with(|s| s.rekey_gate.take());
            if let Some(gate) = gate {
                gate.recv().unwrap();
            }
            self.with(|s| s.rekey_result)
        }

        fn rekey_ike_once(&self) -> Result<(), Status> {
            self.rekey_child_once()
        }

        fn cancel(&self) {
            note(&self.log, "link.cancel");
            self.with(|s| s.cancelled = true);
        }

        fn teardown(&self) {
            note(&self.log, "link.teardown");
        }
    }

    struct FakeBackend {
        log: Log,
        link: FakeLink,
        connect_status: Mutex<Option<Status>>,
        /// `(entered, release)`: connect signals it has started, then waits.
        connect_gate: Mutex<Option<(Sender<()>, Receiver<()>)>>,
        preflight_status: Status,
    }

    impl Backend for FakeBackend {
        type Link = FakeLink;

        fn connect(
            &self,
            input: crate::envelope::BootstrapInput,
            _options: oftc_engine::transport::ConnectOptions,
            _cancel: oftc_engine::Cancellation,
        ) -> Result<FakeLink, Status> {
            assert_eq!(input.token.as_bytes(), b"synthetic-token");
            note(&self.log, "connect");
            if let Some((entered, release)) = self.connect_gate.lock().unwrap().take() {
                entered.send(()).unwrap();
                release.recv().unwrap();
            }
            self.connect_status.lock().unwrap().map_or(Ok(self.link.clone()), Err)
        }

        fn preflight(&self, _input: &crate::envelope::BootstrapInput) -> Status {
            note(&self.log, "preflight");
            self.preflight_status
        }
    }

    // ---- the OS side: a loopback with hooks ------------------------------

    struct FakeTunnel {
        log: Log,
        inner: LoopbackTunnel,
        /// `(entered, release)`: apply signals it has started, then waits.
        apply_gate: Mutex<Option<(Sender<()>, Receiver<()>)>>,
        fail_writes: AtomicBool,
    }

    impl Tunnel for FakeTunnel {
        fn apply_settings(&self, settings: &NetworkSettings) -> Result<(), TunnelError> {
            note(&self.log, "tunnel.apply");
            if let Some((entered, release)) = self.apply_gate.lock().unwrap().take() {
                entered.send(()).unwrap();
                release.recv().unwrap();
            }
            self.inner.apply_settings(settings)
        }

        fn read_packets(&self) -> Result<Vec<Vec<u8>>, TunnelError> {
            self.inner.read_packets()
        }

        fn write_packet(&self, packet: &[u8]) -> Result<(), TunnelError> {
            if self.fail_writes.load(Ordering::SeqCst) {
                return Err(TunnelError::Closed);
            }
            self.inner.write_packet(packet)
        }

        fn close(&self) {
            note(&self.log, "tunnel.close");
            self.inner.close();
        }

        fn clear_settings(&self) -> Result<(), TunnelError> {
            note(&self.log, "tunnel.clear");
            self.inner.clear_settings()
        }
    }

    struct Rig {
        provider: Arc<Provider<FakeBackend, FakeTunnel>>,
        link: FakeLink,
        peer: LoopbackPeer,
        log: Log,
        failures: Receiver<Failure>,
    }

    impl Rig {
        fn new() -> Self {
            Self::build(|_, _| {})
        }

        fn build(configure: impl FnOnce(&mut FakeBackend, &mut FakeTunnel)) -> Self {
            let log: Log = Arc::default();
            let link = FakeLink::new(&log);
            let (tunnel, peer) = loopback();
            let mut backend = FakeBackend {
                log: log.clone(),
                link: link.clone(),
                connect_status: Mutex::new(None),
                connect_gate: Mutex::new(None),
                preflight_status: 0,
            };
            let mut tunnel = FakeTunnel {
                log: log.clone(),
                inner: tunnel,
                apply_gate: Mutex::new(None),
                fail_writes: AtomicBool::new(false),
            };
            configure(&mut backend, &mut tunnel);
            let (report, failures) = channel();
            let report = Mutex::new(report);
            // An hour: the tests drive ticks themselves, never the timer.
            let provider = Provider::with_liveness_interval(
                backend,
                tunnel,
                move |failure| report.lock().unwrap().send(failure).unwrap(),
                Duration::from_secs(3600),
            );
            Self { provider: Arc::new(provider), link, peer, log, failures }
        }

        fn live(&self) -> Result<(), Failure> {
            self.provider.start(&live(unix_now(), id()))
        }

        fn running() -> Self {
            let rig = Self::new();
            rig.live().unwrap();
            rig
        }

        fn is_stopping(&self) -> bool {
            self.provider.0.lock().stopping
        }
    }

    fn packet(tag: u8, len: usize) -> Vec<u8> {
        let mut p = vec![tag; len];
        p[0] = 0x45;
        p
    }

    fn text(reply: Option<Vec<u8>>) -> Option<String> {
        reply.map(|bytes| String::from_utf8(bytes).unwrap())
    }

    // ---- start and stop ---------------------------------------------------

    #[test]
    fn a_live_start_installs_the_settings_and_a_stop_tears_down_in_order() {
        let rig = Rig::running();
        assert_eq!(rig.peer.settings(), Some(good_settings()));
        assert_eq!(events(&rig.log), ["connect", "tunnel.apply"]);
        rig.provider.stop();
        // Cancel the engine, send the DELETEs, wake the OS side, clear settings.
        assert_eq!(
            events(&rig.log),
            ["connect", "tunnel.apply", "link.cancel", "link.teardown", "tunnel.close", "tunnel.clear"]
        );
        assert_eq!(rig.peer.settings(), None);
        // A host-requested stop is not reported as a failure.
        assert!(rig.failures.try_recv().is_err());
    }

    #[test]
    fn stop_is_idempotent_and_safe_before_any_start() {
        let rig = Rig::new();
        rig.provider.stop();
        rig.provider.stop();
        assert_eq!(events(&rig.log), ["tunnel.close", "tunnel.clear"]);
        assert_eq!(rig.live(), Err(Failure(1)), "a stopped provider does not restart");
    }

    #[test]
    fn a_second_start_is_refused_and_a_bad_envelope_changes_nothing() {
        let rig = Rig::new();
        assert_eq!(rig.provider.start(&StartOptions::default()), Err(Failure(2)));
        rig.live().unwrap();
        assert_eq!(rig.provider.start(&live(unix_now(), [7; 16])), Err(Failure(1)));
        rig.provider.stop();
    }

    #[test]
    fn a_connect_failure_reports_100_plus_the_status_and_clears_settings() {
        let rig = Rig::build(|backend, _| *backend.connect_status.lock().unwrap() = Some(5));
        assert_eq!(rig.live(), Err(Failure(105)));
        assert_eq!(events(&rig.log), ["connect", "tunnel.close", "tunnel.clear"]);
        // The start itself failed, so there is nothing to cancel on the host.
        assert!(rig.failures.try_recv().is_err());
    }

    #[test]
    fn rejected_settings_are_never_applied() {
        let rig = Rig::build(|backend, _| backend.link.settings.inner_mtu = 100);
        assert_eq!(rig.live(), Err(Failure(4)));
        assert_eq!(
            events(&rig.log),
            ["connect", "link.cancel", "link.teardown", "tunnel.close", "tunnel.clear"]
        );
    }

    #[test]
    fn settings_the_os_refuses_fail_the_start_and_are_cleared() {
        let rig = Rig::new();
        rig.peer.reject_settings();
        assert_eq!(rig.live(), Err(Failure(5)));
        assert_eq!(rig.peer.settings(), None);
        assert_eq!(events(&rig.log).last().unwrap(), "tunnel.clear");
        assert!(events(&rig.log).contains(&"link.teardown".to_owned()));
    }

    #[test]
    fn a_stop_during_connect_cancels_it_and_never_applies_settings() {
        let (entered, entered_rx) = channel();
        let (release, release_rx) = channel();
        let rig = Rig::build(|backend, _| {
            *backend.connect_gate.lock().unwrap() = Some((entered, release_rx));
        });
        let starter = {
            let provider = rig.provider.clone();
            thread::spawn(move || provider.start(&live(unix_now(), id())))
        };
        entered_rx.recv().unwrap();
        let stopper = {
            let provider = rig.provider.clone();
            thread::spawn(move || provider.stop())
        };
        eventually(|| rig.is_stopping());
        // Cleanup waits for the connect to return; nothing has been torn down.
        assert_eq!(events(&rig.log), ["connect"]);
        release.send(()).unwrap();
        assert_eq!(starter.join().unwrap(), Err(Failure(9)));
        stopper.join().unwrap();
        assert_eq!(
            events(&rig.log),
            ["connect", "link.cancel", "link.teardown", "tunnel.close", "tunnel.clear"]
        );
    }

    #[test]
    fn a_stop_while_settings_are_being_applied_waits_for_the_apply_and_then_clears_them() {
        let (entered, entered_rx) = channel();
        let (release, release_rx) = channel();
        let rig = Rig::build(|_, tunnel| {
            *tunnel.apply_gate.lock().unwrap() = Some((entered, release_rx));
        });
        let starter = {
            let provider = rig.provider.clone();
            thread::spawn(move || provider.start(&live(unix_now(), id())))
        };
        entered_rx.recv().unwrap();
        let stopper = {
            let provider = rig.provider.clone();
            thread::spawn(move || provider.stop())
        };
        eventually(|| rig.is_stopping());
        // The engine is cancelled at once, but the settings are not cleared and
        // the session not torn down while the OS is still applying them.
        assert_eq!(events(&rig.log), ["connect", "tunnel.apply", "link.cancel"]);
        assert_eq!(rig.peer.clear_count(), 0);
        release.send(()).unwrap();
        assert_eq!(starter.join().unwrap(), Err(Failure(9)));
        stopper.join().unwrap();
        assert_eq!(
            events(&rig.log),
            ["connect", "tunnel.apply", "link.cancel", "link.teardown", "tunnel.close", "tunnel.clear"]
        );
        assert_eq!(rig.peer.settings(), None, "what the late apply installed was cleared");
    }

    // ---- data path ---------------------------------------------------------

    #[test]
    fn outbound_packets_are_sent_in_order_across_slices_and_counted() {
        let rig = Rig::running();
        rig.peer.wait_until_blocked();
        let batch: Vec<Vec<u8>> = (0..130u8).map(|n| packet(n, 40)).collect();
        for p in &batch {
            rig.peer.inject(p);
        }
        // Whatever the sender's batching, order and content are preserved.
        assert_eq!(rig.link.wait_sent(130), batch);
        eventually(|| {
            let json = text(rig.provider.handle_message(b"oftc.traffic.v1")).unwrap();
            json.contains("\"sentBytes\":5200,")
        });
        rig.provider.stop();
    }

    #[test]
    fn a_dropped_packet_is_skipped_and_not_counted_but_other_errors_stop_the_tunnel() {
        let rig = Rig::running();
        rig.link.with(|s| s.send_errors.extend([PACKET_DROPPED, 3]));
        for tag in 1..=3 {
            rig.peer.inject(&packet(tag, 100));
        }
        // The first is dropped, the second fails the tunnel, the third is not sent.
        assert_eq!(rig.failures.recv().unwrap(), Failure(203));
        assert_eq!(rig.link.wait_sent(2).len(), 2);
        assert_eq!(rig.link.with(|s| s.sent.len()), 2);
    }

    #[test]
    fn inbound_packets_reach_the_os_and_are_counted() {
        let rig = Rig::running();
        rig.link.push(Ok(Inbound::Packet(packet(1, 60))));
        rig.link.push(Ok(Inbound::Idle));
        rig.link.push(Ok(Inbound::Packet(packet(2, 40))));
        let mut written = Vec::new();
        eventually(|| {
            written.extend(rig.peer.take_written());
            written.len() == 2
        });
        assert_eq!(written, [packet(1, 60), packet(2, 40)]);
        eventually(|| {
            text(rig.provider.handle_message(b"oftc.traffic.v1"))
                .unwrap()
                .contains("\"receivedBytes\":100,")
        });
        rig.provider.stop();
    }

    #[test]
    fn a_malformed_inbound_packet_stops_the_tunnel_and_is_not_written() {
        for bad in [vec![0x45; 19], vec![0x60; 40], vec![0x45; MAX_INNER_PACKET + 1]] {
            let rig = Rig::running();
            rig.link.push(Ok(Inbound::Packet(bad)));
            assert_eq!(rig.failures.recv().unwrap(), Failure(6));
            assert!(rig.peer.take_written().is_empty());
        }
    }

    #[test]
    fn a_refused_write_stops_the_tunnel() {
        let rig = Rig::build(|_, tunnel| tunnel.fail_writes.store(true, Ordering::SeqCst));
        rig.live().unwrap();
        rig.link.push(Ok(Inbound::Packet(packet(1, 40))));
        assert_eq!(rig.failures.recv().unwrap(), Failure(7));
    }

    #[test]
    fn a_peer_delete_and_a_receive_error_stop_the_tunnel_with_their_codes() {
        let rig = Rig::running();
        rig.link.push(Ok(Inbound::PeerDeleted));
        assert_eq!(rig.failures.recv().unwrap(), Failure(8));
        let rig = Rig::running();
        rig.link.push(Err(112));
        assert_eq!(rig.failures.recv().unwrap(), Failure(412));
    }

    #[test]
    fn the_os_closing_the_tunnel_stops_it_and_tears_down() {
        let rig = Rig::running();
        rig.peer.wait_until_blocked();
        rig.peer.close();
        assert_eq!(rig.failures.recv().unwrap(), Failure(10));
        let log = events(&rig.log);
        assert_eq!(&log[log.len() - 3..], ["link.teardown", "tunnel.close", "tunnel.clear"]);
        // A later stop returns at once and does not report a second failure.
        rig.provider.stop();
        assert!(rig.failures.try_recv().is_err());
    }

    #[test]
    fn sends_and_liveness_ticks_do_not_wait_behind_a_blocked_receive() {
        let rig = Rig::running();
        rig.link.wait_receiving();
        rig.peer.inject(&packet(1, 40));
        assert_eq!(rig.link.wait_sent(1).len(), 1);
        rig.provider.0.liveness_tick();
        assert_eq!(rig.link.with(|s| s.ticks), 1);
        // The receive is still pending throughout.
        assert_eq!(rig.link.with(|s| s.receiving), 1);
        rig.provider.stop();
    }

    // ---- liveness ------------------------------------------------------------

    #[test]
    fn every_third_liveness_tick_also_sends_a_nat_keepalive() {
        let rig = Rig::running();
        for _ in 0..7 {
            rig.provider.0.liveness_tick();
        }
        assert_eq!(rig.link.with(|s| (s.ticks, s.keepalives)), (7, 2));
        rig.provider.stop();
    }

    #[test]
    fn a_failed_liveness_tick_stops_the_tunnel_and_reconnect_needed_is_409() {
        let rig = Rig::running();
        rig.link.with(|s| s.tick_error = Some(RECONNECT_NEEDED));
        rig.provider.0.liveness_tick();
        assert_eq!(rig.failures.recv().unwrap(), Failure(409));
        let rig = Rig::running();
        rig.link.with(|s| s.tick_error = Some(102));
        rig.provider.0.liveness_tick();
        assert_eq!(rig.failures.recv().unwrap(), Failure(502));
    }

    #[test]
    fn liveness_ticks_after_a_stop_do_nothing() {
        let rig = Rig::running();
        rig.provider.stop();
        rig.provider.0.liveness_tick();
        assert_eq!(rig.link.with(|s| s.ticks), 0);
    }

    // ---- provider messages -----------------------------------------------------

    #[test]
    fn messages_without_a_running_tunnel_get_no_data() {
        let rig = Rig::new();
        for message in [&b"oftc.traffic.v1"[..], b"oftc.rekey-counts.v1", b"oftc.preflight-status.v1", b"nope"] {
            assert_eq!(rig.provider.handle_message(message), None);
        }
        assert_eq!(text(rig.provider.handle_message(b"oftc.rekey-child-once.v1")).unwrap(), "rekey_unavailable");
        assert_eq!(text(rig.provider.handle_message(b"oftc.rekey-ike-once.v1")).unwrap(), "rekey_unavailable");
        rig.live().unwrap();
        rig.provider.stop();
        assert_eq!(rig.provider.handle_message(b"oftc.traffic.v1"), None);
        assert_eq!(rig.provider.handle_message(b"oftc.rekey-counts.v1"), None);
    }

    #[test]
    fn the_traffic_message_is_the_documented_json() {
        let rig = Rig::running();
        let json = text(rig.provider.handle_message(b"oftc.traffic.v1")).unwrap();
        assert!(json.starts_with("{\"version\":1,\"sessionID\":\""), "{json}");
        assert!(json.contains("\"receivedBytes\":0,\"sentBytes\":0,\"uptime\":"), "{json}");
        rig.provider.stop();
    }

    #[test]
    fn rekey_counts_and_probes_reply_as_documented() {
        let rig = Rig::running();
        assert_eq!(
            text(rig.provider.handle_message(b"oftc.rekey-counts.v1")).unwrap(),
            "child_rekeys local=3 peer=2 ike=1"
        );
        assert_eq!(text(rig.provider.handle_message(b"oftc.rekey-child-once.v1")).unwrap(), "rekey_passed");
        assert_eq!(text(rig.provider.handle_message(b"oftc.rekey-ike-once.v1")).unwrap(), "rekey_passed");
        rig.link.with(|s| s.rekey_result = Err(125));
        assert_eq!(
            text(rig.provider.handle_message(b"oftc.rekey-child-once.v1")).unwrap(),
            "rekey_failed stage=125"
        );
        // A failed probe also stops the tunnel, with 500 plus the stage.
        assert_eq!(rig.failures.recv().unwrap(), Failure(625));
    }

    #[test]
    fn a_second_rekey_probe_while_one_is_in_flight_is_unavailable() {
        let rig = Rig::running();
        let (release, gate) = channel();
        rig.link.with(|s| s.rekey_gate = Some(gate));
        let probe = {
            let provider = rig.provider.clone();
            thread::spawn(move || provider.handle_message(b"oftc.rekey-child-once.v1"))
        };
        eventually(|| rig.provider.0.lock().rekey_pending);
        assert_eq!(text(rig.provider.handle_message(b"oftc.rekey-ike-once.v1")).unwrap(), "rekey_unavailable");
        release.send(()).unwrap();
        assert_eq!(text(probe.join().unwrap()).unwrap(), "rekey_passed");
        rig.provider.stop();
    }

    #[test]
    fn a_probe_that_finishes_after_a_stop_replies_stopped() {
        let rig = Rig::running();
        let (release, gate) = channel();
        rig.link.with(|s| s.rekey_gate = Some(gate));
        let probe = {
            let provider = rig.provider.clone();
            thread::spawn(move || provider.handle_message(b"oftc.rekey-child-once.v1"))
        };
        eventually(|| rig.provider.0.lock().rekey_pending);
        let stopper = {
            let provider = rig.provider.clone();
            thread::spawn(move || provider.stop())
        };
        eventually(|| rig.is_stopping());
        release.send(()).unwrap();
        assert_eq!(text(probe.join().unwrap()).unwrap(), "rekey_stopped");
        stopper.join().unwrap();
    }

    #[test]
    fn a_preflight_reports_its_status_and_installs_nothing() {
        for (status, reply) in [
            (0, "preflight_passed responder_auth_and_eap_challenge"),
            (4, "preflight_failed stage=4"),
        ] {
            let rig = Rig::build(|backend, _| backend.preflight_status = status);
            let options = {
                let secret = crate::envelope::tests::hbr1(
                    "integration.invalid", crate::envelope::tests::UID, b"synthetic", b"");
                crate::envelope::StartOptions {
                    preflight: Some(crate::envelope::OptionValue::Data(
                        crate::envelope::tests::envelope(unix_now() + 60, id(), &secret))),
                    ..Default::default()
                }
            };
            rig.provider.start(&options).unwrap();
            assert_eq!(text(rig.provider.handle_message(b"oftc.preflight-status.v1")).unwrap(), reply);
            assert_eq!(events(&rig.log), ["preflight"]);
            assert_eq!(rig.peer.settings(), None);
            rig.provider.stop();
        }
    }
}
