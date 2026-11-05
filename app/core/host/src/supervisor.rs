//! The reconnect supervisor behind `supervise-live` and `supervise-profile`.
//!
//! One supervisor owns one profile's VPN entry. It signs in through the browser,
//! starts the tunnel once with the fresh single-use token, and when an established
//! tunnel drops for a reason that is safe to retry it signs in again. A token is
//! never reused and an uncertain failure is never retried: a spent token cannot be
//! told from an unspent one, so only "the gateway was unreachable before the browser
//! opened" is retried without the user.
//!
//! Ported from the Swift `ReconnectSupervisor`. [`ReconnectPolicy`] is the rule for
//! which drops recover. [`Supervisor`] is the event machine: its `begin_attempt`,
//! `observe`, `tick` and `refresh_status` methods are the Swift ones, each reading the
//! clock through [`Clock`] so scenario tests drive it with explicit time. The runner
//! ([`Supervisor::run`]) only waits for a VPN status change or a one-second tick and
//! calls them. Every outside call goes through [`Deps`].
//!
//! The Swift code ran the sign-in on a background queue and made the preference
//! reload and the disconnect-error fetch asynchronous. Here the sign-in, reload and
//! fetch block the supervisor's own thread (each has its own timeout, and the sign-in
//! polls for a stop request and for SIGINT/SIGTERM), so there is no concurrent state
//! to reason about. `docs/host-verbs.md` lists the resulting differences.

use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::time::{Duration, UNIX_EPOCH};

use oftc_apple::error::{ne_vpn_error, AppleError};
use oftc_apple::manager::{StartOptions, Subscription, VpnControl, VpnEntry, VpnStatus};
use oftc_host_bootstrap::{AcquireFailure, TunnelProfile};
use oftc_provider::envelope::ConnectMode;

use crate::acquire::{Acquirer, Clock};
use crate::agent::{Launchctl, AGENT_LABEL};
use crate::keychain::Keychain;
use crate::lease::{SamlLock, SupervisorLease};
use crate::registry::ProfileEntry;
use crate::start::live_options;
use crate::status::{Phase, StatusStore};
use crate::trust::Outcome as Trust;

/// SIGINT and SIGTERM, as a flag the supervisor polls. The real implementation is
/// in `os`; tests raise it by hand.
pub trait Signals {
    /// Starts catching the signals. Called once, when the supervisor starts.
    fn arm(&self);
    fn raised(&self) -> bool;
}

/// A [`Signals`] raised by hand, for tests (the `MockVpn` convention: a plain item).
#[derive(Default)]
pub struct ManualSignals(std::sync::atomic::AtomicBool);

impl ManualSignals {
    pub fn raise(&self) {
        self.0.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

impl Signals for ManualSignals {
    fn arm(&self) {}

    fn raised(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Everything the supervisor reaches outside itself.
pub struct Deps<'a> {
    pub vpn: &'a dyn VpnControl,
    pub keychain: &'a dyn Keychain,
    pub acquirer: &'a dyn Acquirer,
    pub clock: &'a dyn Clock,
    pub session_id: &'a dyn Fn() -> [u8; 16],
    pub launchctl: &'a dyn Launchctl,
    pub signals: &'a dyn Signals,
    /// Asks the user about an untrusted gateway certificate: host, port, profile name.
    pub review: &'a dyn Fn(&str, u32, &str) -> Trust,
    /// One diagnostic line (stderr in the host).
    pub diagnostic: &'a dyn Fn(&str),
}

/// What to supervise.
pub struct Job<'a> {
    pub entry: &'a ProfileEntry,
    pub provider_id: String,
    /// The profile's VPN entry, already checked to be enabled, ours and disconnected.
    pub vpn_entry: VpnEntry,
    pub gateway: String,
    pub saml_port: u32,
    pub mode: ConnectMode,
    pub insecure: bool,
    /// Where `saml.lock` lives: the host's root directory.
    pub root: &'a std::path::Path,
}

// ---------------------------------------------------------------------- policy

/// How many recoveries are allowed in [`WINDOW`].
const MAXIMUM: usize = 3;
const WINDOW: Duration = Duration::from_secs(600);

/// Codes of the provider's own errors that come from an established SA: the peer's
/// DELETE, a socket failure while sending, receiving or keeping alive, or an
/// explicit reconnect request. Initial IKE/EAP failures are not in the list: after
/// a spent token they stay down.
const PROVIDER_DOMAIN: &str = "OFTCProvider";
const PROVIDER_RECOVERABLE: [i64; 8] = [8, 301, 401, 501, 209, 309, 409, 509];
const NE_RECOVERABLE: [i64; 6] = [
    ne_vpn_error::OVERSLEPT,
    ne_vpn_error::NO_NETWORK_AVAILABLE,
    ne_vpn_error::UNRECOVERABLE_NETWORK_CHANGE,
    ne_vpn_error::SERVER_NOT_RESPONDING,
    ne_vpn_error::SERVER_DEAD,
    ne_vpn_error::SERVER_DISCONNECTED,
];

/// Which drops are worth a fresh sign-in, at most [`MAXIMUM`] in [`WINDOW`].
#[derive(Default)]
pub struct ReconnectPolicy {
    attempts: Vec<Duration>,
}

impl ReconnectPolicy {
    pub fn recoverable(error: &AppleError) -> bool {
        let AppleError::Ns { domain, code, .. } = error else {
            return false;
        };
        match domain.as_str() {
            PROVIDER_DOMAIN => PROVIDER_RECOVERABLE.contains(code),
            ne_vpn_error::DOMAIN => NE_RECOVERABLE.contains(code),
            _ => false,
        }
    }

    /// Whether to recover from `error` at `now`. Only a recoverable error uses up
    /// one of the allowed recoveries.
    pub fn allow_recovery(&mut self, error: &AppleError, now: Duration) -> bool {
        if !Self::recoverable(error) {
            return false;
        }
        self.attempts.retain(|at| now.saturating_sub(*at) < WINDOW);
        if self.attempts.len() >= MAXIMUM {
            return false;
        }
        self.attempts.push(now);
        true
    }
}

// --------------------------------------------------------------------- machine

/// A tick every second drives the deadlines and the periodic checks.
const TICK: Duration = Duration::from_secs(1);
/// The whole of the first sign-in: browser SSO plus the tunnel start.
const ACQUISITION_DEADLINE: Duration = Duration::from_secs(390);
/// From the start request to an established tunnel.
const START_DEADLINE: Duration = Duration::from_secs(90);
/// Wait before the fresh sign-in after a recoverable drop.
const RECOVERY_DELAY: Duration = Duration::from_secs(2);
/// How long the system may take to report why the tunnel dropped.
const ERROR_FETCH: Duration = Duration::from_secs(10);
/// First and longest wait between attempts while the gateway is unreachable.
const BACKOFF_FIRST: Duration = Duration::from_secs(5);
const BACKOFF_LAST: Duration = Duration::from_secs(30);
/// After a certificate the user just trusted, the retry is almost immediate.
const BACKOFF_TRUSTED: Duration = Duration::from_secs(1);
const SAML_LOCK_POLL: Duration = Duration::from_millis(250);

pub struct Supervisor<'a> {
    d: &'a Deps<'a>,
    job: Job<'a>,
    lease: SupervisorLease,
    status: StatusStore,
    vpn_entry: VpnEntry,
    policy: ReconnectPolicy,
    events: Receiver<()>,
    notify: Sender<()>,
    subscription: Option<Subscription>,
    starting: bool,
    saw_connecting: bool,
    ever_connected: bool,
    connected_this_attempt: bool,
    fresh_disconnected: u32,
    ticks: u64,
    owns_connection: bool,
    start_deadline: Option<Duration>,
    acquisition_deadline: Option<Duration>,
    unreachable_backoff: Duration,
    restart_after: Option<Duration>,
    published: Phase,
    /// The message and exit code, once the supervisor has stopped.
    exit: Option<(String, i32)>,
}

impl<'a> Supervisor<'a> {
    pub fn new(d: &'a Deps<'a>, job: Job<'a>, lease: SupervisorLease) -> Supervisor<'a> {
        let (notify, events) = channel();
        Supervisor {
            d,
            status: StatusStore::new(&crate::registry::entry_directory(job.root, &job.entry.id)),
            vpn_entry: job.vpn_entry.clone(),
            job,
            lease,
            policy: ReconnectPolicy::default(),
            events,
            notify,
            subscription: None,
            starting: false,
            saw_connecting: false,
            ever_connected: false,
            connected_this_attempt: false,
            fresh_disconnected: 0,
            ticks: 0,
            owns_connection: false,
            start_deadline: None,
            acquisition_deadline: None,
            unreachable_backoff: BACKOFF_FIRST,
            restart_after: None,
            published: Phase::Acquiring,
            exit: None,
        }
    }

    /// Runs until the supervisor stops; returns what to print and the exit code.
    pub fn run(&mut self) -> (String, i32) {
        self.d.signals.arm();
        self.attach_observer();
        self.diag("timer armed");
        self.begin_attempt();
        let mut next_tick = self.d.clock.now() + TICK;
        while self.exit.is_none() {
            let wait = next_tick.saturating_sub(self.d.clock.now());
            match self.events.recv_timeout(wait) {
                Ok(()) => {
                    while self.events.try_recv().is_ok() {}
                    self.observe();
                }
                Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => {}
            }
            if self.exit.is_none() && self.d.clock.now() >= next_tick {
                // From now, not from the last tick: after a long sleep one tick is due, not hundreds.
                next_tick = self.d.clock.now() + TICK;
                self.tick();
            }
        }
        self.exit.take().unwrap_or_default()
    }

    // ------------------------------------------------------------- small helpers

    fn now(&self) -> Duration {
        self.d.clock.now()
    }

    fn diag(&self, event: &str) {
        (self.d.diagnostic)(&format!("OFTC supervisor: {event}"));
    }

    fn status_now(&self) -> VpnStatus {
        self.d.vpn.status(&self.vpn_entry)
    }

    fn stop_requested(&self) -> bool {
        self.lease.stop_requested()
    }

    fn interrupted(&self) -> bool {
        self.stop_requested() || self.d.signals.raised()
    }

    fn publish(&mut self, phase: Phase) {
        self.published = phase;
        let now = UNIX_EPOCH + Duration::from_secs(self.d.clock.unix_secs());
        self.status.publish(phase, self.lease.id(), now);
    }

    fn attach_observer(&mut self) {
        // Dropping the old subscription removes its observer.
        self.subscription = self
            .d
            .vpn
            .observe_status(&self.vpn_entry, self.notify.clone())
            .ok();
    }

    fn stop(&mut self, message: &str, code: i32) {
        if self.exit.is_some() {
            return;
        }
        self.publish(if code == 0 {
            Phase::Stopped
        } else {
            Phase::Failed
        });
        self.subscription = None;
        if self.owns_connection && self.status_now() != VpnStatus::Disconnected {
            self.d.vpn.stop(&self.vpn_entry);
        }
        self.exit = Some((message.to_owned(), code));
    }

    // ----------------------------------------------------------------- the clock

    /// Once a second: look at the status, and every fifth tick check that the
    /// configuration is still ours and that the status is not stale.
    fn tick(&mut self) {
        self.observe();
        if self.exit.is_some() {
            return;
        }
        self.ticks += 1;
        if self.ticks.is_multiple_of(5) {
            self.refresh_status();
        }
        if self.ticks.is_multiple_of(30) {
            self.publish(self.published);
            self.diag(&format!(
                "heartbeat status={} established={} current={}",
                status_word(self.status_now()),
                u8::from(self.ever_connected),
                u8::from(self.connected_this_attempt)
            ));
        }
    }

    /// Reloads the VPN preferences. A status read through an old object can stay
    /// "connected" after the tunnel went away, so two fresh "disconnected" readings
    /// in a row replace the object and count as a drop. If the entry is no longer
    /// exactly one of ours, stop.
    fn refresh_status(&mut self) {
        if self.exit.is_some()
            || !self.ever_connected
            || !self.connected_this_attempt
            || self.starting
            || self.restart_after.is_some()
            || self.status_now() == VpnStatus::Disconnected
        {
            return;
        }
        let Ok(all) = self.d.vpn.load_all() else {
            self.diag("preference refresh failed");
            return;
        };
        let mut matching = all
            .into_iter()
            .filter(|candidate| crate::vpn::owns(&self.job.provider_id, self.job.entry, candidate));
        let (Some(fresh), None) = (matching.next(), matching.next()) else {
            self.stop("OFTC configuration changed during supervision", 1);
            return;
        };
        if !self.connected_this_attempt || self.starting || self.restart_after.is_some() {
            return;
        }
        if self.ticks.is_multiple_of(30) {
            self.diag(&format!(
                "fresh status={}",
                status_word(self.d.vpn.status(&fresh))
            ));
        }
        if self.d.vpn.status(&fresh) == VpnStatus::Disconnected {
            self.fresh_disconnected += 1;
            if self.fresh_disconnected < 2 {
                return;
            }
            self.fresh_disconnected = 0;
            self.vpn_entry = fresh;
            self.attach_observer();
            self.diag("refreshed disconnected status");
            self.observe();
        } else {
            self.fresh_disconnected = 0;
        }
    }

    // ----------------------------------------------------------------- an attempt

    /// Signs in and starts the tunnel. Blocks for the browser sign-in.
    fn begin_attempt(&mut self) {
        if self.exit.is_some() {
            return;
        }
        if self.d.signals.raised() {
            return self.stop("Supervisor stopped", 0);
        }
        if self.stop_requested() || self.status_now() != VpnStatus::Disconnected {
            return self.stop("OFTC status changed before supervised start", 1);
        }
        self.starting = true;
        self.publish(Phase::Acquiring);
        self.diag("begin attempt");
        self.saw_connecting = false;
        self.connected_this_attempt = false;
        self.fresh_disconnected = 0;
        if self.acquisition_deadline.is_none() {
            self.acquisition_deadline = Some(self.now() + ACQUISITION_DEADLINE);
            self.unreachable_backoff = BACKOFF_FIRST;
        }
        self.start_deadline = self.acquisition_deadline;

        let signed_in = self.sign_in();
        if self.exit.is_some() {
            return;
        }
        if self.interrupted() {
            return self.stop("Supervisor stopped", 0);
        }
        if signed_in.trust == Trust::Declined {
            return self.stop("Gateway certificate not trusted; supervisor stopped", 1);
        }
        let Some(options) = signed_in.options else {
            if matches!(signed_in.trust, Trust::Trusted(_)) {
                self.unreachable_backoff = BACKOFF_TRUSTED;
            }
            let retry_until = self
                .acquisition_deadline
                .filter(|deadline| self.now() < *deadline);
            if signed_in.before_browser
                && self.status_now() == VpnStatus::Disconnected
                && retry_until.is_some()
            {
                self.starting = false;
                self.publish(Phase::Recovering);
                self.restart_after = Some(self.now() + self.unreachable_backoff);
                self.unreachable_backoff = (self.unreachable_backoff * 2).min(BACKOFF_LAST);
                self.diag("SAML bootstrap unavailable; retrying before token use");
                return;
            }
            return self.stop("Fresh SAML acquisition failed; supervisor stopped", 1);
        };
        // Another process may have changed the entry while the browser was open.
        let fresh = self.d.vpn.reload(&self.vpn_entry).ok().filter(|fresh| {
            fresh.enabled
                && crate::vpn::owns(&self.job.provider_id, self.job.entry, fresh)
                && self.d.vpn.status(fresh) == VpnStatus::Disconnected
        });
        let Some(fresh) = fresh.filter(|_| !self.stop_requested()) else {
            return self.stop("OFTC configuration or status changed before start", 1);
        };
        self.vpn_entry = fresh;
        self.attach_observer();
        self.diag("start request entering");
        self.publish(Phase::Connecting);
        if self.d.vpn.start(&self.vpn_entry, options).is_err() {
            return self.stop("VPN start failed; no token retry", 1);
        }
        self.diag("start request returned");
        self.owns_connection = true;
        self.start_deadline = Some(self.now() + START_DEADLINE);
        self.observe();
    }

    /// The sign-in half of an attempt: the PSK, the one-at-a-time browser lock, the
    /// browser itself and, when the gateway was unreachable, the certificate review.
    fn sign_in(&self) -> SignedIn {
        let mut result = SignedIn {
            options: None,
            before_browser: false,
            trust: Trust::NotACertificateProblem,
        };
        // A missing or unusable PSK ends the attempt like any other sign-in failure.
        let Ok(psk) = self.d.keychain.get(&self.job.gateway) else {
            return result;
        };
        let cancelled = || self.interrupted();
        let outcome = {
            // One browser sign-in at a time: each listens on a local port.
            let lock = SamlLock::acquire(self.job.root, &mut || cancelled(), SAML_LOCK_POLL);
            if lock.is_some() && !self.stop_requested() {
                let profile = TunnelProfile {
                    name: self.job.entry.name().to_owned(),
                    gateway: self.job.gateway.clone(),
                };
                Some(live_options(
                    self.d.acquirer,
                    self.d.clock,
                    self.d.session_id,
                    &self.job.gateway,
                    &psk,
                    self.job.saml_port,
                    self.job.insecure,
                    profile,
                    self.job.mode,
                    &cancelled,
                ))
            } else {
                None
            }
            // The lock is released here, before any prompt.
        };
        match outcome {
            Some(Ok(options)) => result.options = Some(options),
            Some(Err(AcquireFailure::BeforeBrowser)) => {
                result.before_browser = true;
                if !self.job.insecure && !self.interrupted() {
                    result.trust = (self.d.review)(
                        &self.job.gateway,
                        self.job.saml_port,
                        self.job.entry.name(),
                    );
                }
            }
            Some(Err(AcquireFailure::Other)) | None => {}
        }
        result
    }

    // ------------------------------------------------------------------- observe

    /// Reacts to the tunnel's current status.
    fn observe(&mut self) {
        if self.exit.is_some() {
            return;
        }
        if self.interrupted() {
            return self.stop("Supervisor stopped", 0);
        }
        let status = self.status_now();
        if status == VpnStatus::Connected {
            self.restart_after = None;
            self.acquisition_deadline = None;
            self.unreachable_backoff = BACKOFF_FIRST;
            if !self.connected_this_attempt {
                self.diag("VPN connected");
                self.connected_this_attempt = true;
                self.ever_connected = true;
                self.publish(Phase::Connected);
            }
            self.starting = false;
            self.start_deadline = None;
            return;
        }
        if matches!(status, VpnStatus::Connecting | VpnStatus::Reasserting) {
            self.saw_connecting = true;
        }
        if self
            .start_deadline
            .is_some_and(|deadline| self.now() >= deadline)
        {
            return self.stop("VPN start deadline expired", 1);
        }
        if self.restart_after.is_some_and(|at| self.now() >= at) {
            self.restart_after = None;
            return self.begin_attempt();
        }
        if status != VpnStatus::Disconnected || self.restart_after.is_some() {
            return;
        }
        // A request can briefly remain disconnected before NE reports connecting.
        if self.starting && !self.saw_connecting {
            return;
        }
        if !(self.ever_connected && self.connected_this_attempt) {
            return self.stop("VPN disconnected before establishment; no token retry", 1);
        }
        self.connected_this_attempt = false;
        self.owns_connection = false;
        self.publish(Phase::Recovering);
        self.diag("VPN disconnected; fetching error");
        // A timeout or failure here is the same as no error: the cause is unknown.
        let error = self
            .d
            .vpn
            .last_disconnect_error(&self.vpn_entry, ERROR_FETCH)
            .ok()
            .flatten();
        self.finish_disconnect(error);
    }

    fn finish_disconnect(&mut self, error: Option<AppleError>) {
        if self.stop_requested() {
            return self.stop("Supervisor stopped", 0);
        }
        let now = self.now();
        let Some(error) = error else {
            // A user stop through macOS can have no disconnect error. Never spend a
            // new SAML token when the cause is unknown.
            self.pause_automatic_start();
            return self.stop(
                "VPN disconnected without a recoverable error; staying down",
                0,
            );
        };
        if let AppleError::Ns { domain, code, .. } = &error {
            self.diag(&format!("disconnect error domain={domain} code={code}"));
        }
        if !self.policy.allow_recovery(&error, now) {
            return self.stop("VPN disconnected; automatic recovery unavailable", 1);
        }
        self.restart_after = Some(now + RECOVERY_DELAY);
        self.publish(Phase::Recovering);
        self.acquisition_deadline = None;
        self.unreachable_backoff = BACKOFF_FIRST;
        self.diag("starting fresh SSO recovery");
    }

    /// Keeps the login agent from reconnecting after a drop nobody explained.
    fn pause_automatic_start(&self) {
        if self.d.launchctl.disable(AGENT_LABEL) {
            self.diag("automatic start paused after unclassified disconnect");
        } else {
            self.diag("could not pause automatic start after unclassified disconnect");
        }
    }
}

/// What the sign-in half of an attempt produced.
struct SignedIn {
    options: Option<StartOptions>,
    /// The gateway could not be reached before the browser opened, so no token was spent.
    before_browser: bool,
    trust: Trust,
}

fn status_word(status: VpnStatus) -> &'static str {
    match status {
        VpnStatus::Invalid => "invalid",
        VpnStatus::Disconnected => "disconnected",
        VpnStatus::Connecting => "connecting",
        VpnStatus::Connected => "connected",
        VpnStatus::Reasserting => "reasserting",
        VpnStatus::Disconnecting => "disconnecting",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    use oftc_apple::manager::{MockEntry, MockVpn, Result as VpnResult, StartKind};
    use oftc_host_bootstrap::TunnelProfile;
    use oftc_provider::envelope::encode_hbr1;
    use zeroize::Zeroizing;

    use crate::agent::RecordingLaunchctl;
    use crate::keychain::MemoryKeychain;
    use crate::lease::request_stop;
    use crate::profile::testutil::TempDir;
    use crate::profile::{Profile, Transport};
    use crate::trust::Certificate;

    const GATEWAY: &str = "vpn.example.com";
    const UID: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const BASE_UNIX: u64 = 1_700_000_000;

    // ------------------------------------------------------------------ policy

    fn provider(code: i64) -> AppleError {
        AppleError::from_nserror(PROVIDER_DOMAIN, code, "")
    }

    fn ne(code: i64) -> AppleError {
        AppleError::from_nserror(ne_vpn_error::DOMAIN, code, "")
    }

    /// Which errors are worth a fresh sign-in: the provider's established-SA codes and
    /// the NE drops, nothing from an initial IKE/EAP failure or another domain.
    #[test]
    fn recoverable_table() {
        for code in [8, 301, 401, 501, 209, 309, 409, 509] {
            assert!(
                ReconnectPolicy::recoverable(&provider(code)),
                "provider {code}"
            );
        }
        for code in [201, 302, 403, 500, 601] {
            assert!(
                !ReconnectPolicy::recoverable(&provider(code)),
                "provider {code}"
            );
        }
        for code in [1, 2, 3, 6, 7, 16] {
            assert!(ReconnectPolicy::recoverable(&ne(code)), "ne {code}");
        }
        for code in [4, 5, 8, 15, 17] {
            assert!(!ReconnectPolicy::recoverable(&ne(code)), "ne {code}");
        }
        assert!(!ReconnectPolicy::recoverable(&AppleError::from_nserror(
            "NSPOSIXErrorDomain",
            8,
            ""
        )));
        assert!(!ReconnectPolicy::recoverable(&AppleError::TimedOut));
    }

    /// Three recoveries in ten minutes; only a recoverable error uses one up.
    #[test]
    fn policy_window() {
        let at = |secs| Duration::from_secs(secs);
        let mut policy = ReconnectPolicy::default();
        assert!(!policy.allow_recovery(&provider(102), at(0)));
        assert!(!policy.allow_recovery(&ne(8), at(0)));
        assert!(policy.allow_recovery(&provider(409), at(0)));
        assert!(policy.allow_recovery(&ne(2), at(1)));
        assert!(policy.allow_recovery(&provider(409), at(2)));
        assert!(!policy.allow_recovery(&provider(409), at(3)));
        assert!(!policy.allow_recovery(&provider(409), at(599)));
        // The first has aged out at exactly the window.
        assert!(policy.allow_recovery(&provider(409), at(600)));
        // After a sleep of hours every earlier recovery has aged out at once.
        for _ in 0..3 {
            assert!(policy.allow_recovery(&provider(409), at(100_000)));
        }
        assert!(!policy.allow_recovery(&provider(409), at(100_001)));
    }

    // --------------------------------------------------------------- the rig

    /// One scripted answer of the browser sign-in.
    struct Step {
        takes: Duration,
        result: Result<(), AcquireFailure>,
        meanwhile: Option<Box<dyn Fn()>>,
    }

    impl Step {
        fn ok() -> Step {
            Step {
                takes: Duration::ZERO,
                result: Ok(()),
                meanwhile: None,
            }
        }
        fn fail(failure: AcquireFailure) -> Step {
            Step {
                result: Err(failure),
                ..Step::ok()
            }
        }
        fn takes(mut self, secs: u64) -> Step {
            self.takes = Duration::from_secs(secs);
            self
        }
        fn meanwhile(mut self, action: impl Fn() + 'static) -> Step {
            self.meanwhile = Some(Box::new(action));
            self
        }
    }

    /// Time that moves only when told, from any thread.
    #[derive(Default)]
    struct Clk(AtomicU64);

    impl Clock for Clk {
        fn unix_secs(&self) -> u64 {
            BASE_UNIX + self.now().as_secs()
        }
        fn now(&self) -> Duration {
            Duration::from_nanos(self.0.load(Ordering::SeqCst))
        }
        fn sleep(&self, duration: Duration) {
            self.0
                .fetch_add(duration.as_nanos() as u64, Ordering::SeqCst);
        }
    }

    /// The mock with three knobs: entries it loads read the truth while the one the
    /// supervisor holds reads "connected" once `stale` is set (loaded entries are
    /// marked `enabled == false`); `start` can fail; and it records the timeout of
    /// each disconnect-error fetch.
    struct Tweaked {
        inner: Arc<MockVpn>,
        stale: AtomicBool,
        fail_start: AtomicBool,
        error_timeouts: Mutex<Vec<Duration>>,
    }

    impl VpnControl for Tweaked {
        fn load_all(&self) -> VpnResult<Vec<VpnEntry>> {
            let mut all = self.inner.load_all()?;
            if self.stale.load(Ordering::SeqCst) {
                all.iter_mut().for_each(|entry| entry.enabled = false);
            }
            Ok(all)
        }
        fn reload(&self, e: &VpnEntry) -> VpnResult<VpnEntry> {
            self.inner.reload(e)
        }
        fn status(&self, e: &VpnEntry) -> VpnStatus {
            if e.enabled && self.stale.load(Ordering::SeqCst) {
                VpnStatus::Connected
            } else {
                self.inner.status(e)
            }
        }
        fn create(&self, p: &str, k: &str, n: &str) -> VpnResult<()> {
            self.inner.create(p, k, n)
        }
        fn set_enabled(&self, e: &VpnEntry, on: bool) -> VpnResult<()> {
            self.inner.set_enabled(e, on)
        }
        fn remove(&self, e: &VpnEntry) -> VpnResult<()> {
            self.inner.remove(e)
        }
        fn start(&self, e: &VpnEntry, o: oftc_apple::manager::StartOptions) -> VpnResult<()> {
            if self.fail_start.load(Ordering::SeqCst) {
                return Err(AppleError::CallbackFailed);
            }
            self.inner.start(e, o)
        }
        fn stop(&self, e: &VpnEntry) {
            self.inner.stop(e)
        }
        fn send_provider_message(&self, e: &VpnEntry, m: &[u8], t: Duration) -> VpnResult<Vec<u8>> {
            self.inner.send_provider_message(e, m, t)
        }
        fn last_disconnect_error(
            &self,
            e: &VpnEntry,
            t: Duration,
        ) -> VpnResult<Option<AppleError>> {
            self.error_timeouts.lock().unwrap().push(t);
            self.inner.last_disconnect_error(e, t)
        }
        fn observe_status(
            &self,
            e: &VpnEntry,
            n: std::sync::mpsc::Sender<()>,
        ) -> VpnResult<oftc_apple::manager::Subscription> {
            self.inner.observe_status(e, n)
        }
    }

    struct Browser<'a> {
        clock: &'a Clk,
        root: &'a std::path::Path,
        script: RefCell<VecDeque<Step>>,
        /// The clock at each sign-in, and what `cancelled` said after the step ran.
        calls: RefCell<Vec<(Duration, bool)>>,
        /// Whether `saml.lock` was held while the browser was open.
        lock_held: RefCell<Vec<bool>>,
    }

    impl Acquirer for Browser<'_> {
        fn acquire(
            &self,
            _gateway: &str,
            _psk: &[u8],
            _saml_port: u32,
            _insecure: bool,
            _profile: TunnelProfile,
            cancelled: &dyn Fn() -> bool,
        ) -> Result<Zeroizing<Vec<u8>>, AcquireFailure> {
            let at = self.clock.now();
            let step = self
                .script
                .borrow_mut()
                .pop_front()
                .expect("no sign-in scripted");
            self.clock.sleep(step.takes);
            if let Some(action) = &step.meanwhile {
                action();
            }
            self.calls.borrow_mut().push((at, cancelled()));
            let busy = SamlLock::acquire(self.root, &mut || true, Duration::ZERO).is_none();
            self.lock_held.borrow_mut().push(busy);
            match step.result {
                Ok(()) => Ok(Zeroizing::new(
                    encode_hbr1(GATEWAY, UID, b"secret", b"token")
                        .unwrap()
                        .as_bytes()
                        .to_vec(),
                )),
                Err(failure) => Err(failure),
            }
        }
    }

    /// Everything a supervisor needs, with scripts for the browser and the review.
    struct Rig {
        _dir: TempDir,
        root: PathBuf,
        entry: ProfileEntry,
        vpn: Arc<MockVpn>,
        tweak: Arc<Tweaked>,
        mock: Arc<MockEntry>,
        keychain: MemoryKeychain,
        clock: Arc<Clk>,
        launchctl: RecordingLaunchctl,
        signals: Arc<ManualSignals>,
        script: RefCell<VecDeque<Step>>,
        calls: RefCell<Vec<(Duration, bool)>>,
        lock_held: RefCell<Vec<bool>>,
        reviews: RefCell<VecDeque<Trust>>,
        /// Whether `saml.lock` was free each time the review was asked.
        lock_free_at_review: RefCell<Vec<bool>>,
        asked: Cell<u32>,
        insecure: bool,
    }

    impl Rig {
        fn new() -> Rig {
            let dir = TempDir::new("supervisor");
            let root = dir.0.clone();
            let profile = Profile::new(GATEWAY, 9443, Transport::Udp, Some("Lab"), None).unwrap();
            let entry = crate::registry::add(&root, &profile, None).unwrap();
            let vpn = Arc::new(MockVpn::new());
            let mock = vpn.add_entry("com.example.oftc.provider", Some(&entry.id), true);
            let keychain = MemoryKeychain::default();
            keychain.set(GATEWAY, b"secret").unwrap();
            Rig {
                _dir: dir,
                root,
                entry,
                tweak: Arc::new(Tweaked {
                    inner: vpn.clone(),
                    stale: AtomicBool::new(false),
                    fail_start: AtomicBool::new(false),
                    error_timeouts: Mutex::new(Vec::new()),
                }),
                vpn,
                mock,
                keychain,
                clock: Arc::new(Clk::default()),
                launchctl: RecordingLaunchctl::new(true),
                signals: Arc::new(ManualSignals::default()),
                script: RefCell::new(VecDeque::new()),
                calls: RefCell::new(Vec::new()),
                lock_held: RefCell::new(Vec::new()),
                reviews: RefCell::new(VecDeque::new()),
                lock_free_at_review: RefCell::new(Vec::new()),
                asked: Cell::new(0),
                insecure: false,
            }
        }

        fn script(&self, steps: Vec<Step>) {
            self.script.borrow_mut().extend(steps);
        }

        fn directory(&self) -> PathBuf {
            crate::registry::entry_directory(&self.root, &self.entry.id)
        }

        fn stop_request(&self) -> impl Fn() + 'static {
            let directory = self.directory();
            move || assert!(request_stop(&directory))
        }

        fn advance(&self, secs: u64) {
            self.clock.sleep(Duration::from_secs(secs));
        }

        fn phase(&self) -> Option<Phase> {
            let now = UNIX_EPOCH + Duration::from_secs(self.clock.unix_secs());
            StatusStore::new(&self.directory())
                .read(now)
                .map(|status| status.phase)
        }
    }

    /// Runs `body` with a supervisor on `rig`, not yet started.
    fn with_supervisor<R>(rig: &Rig, body: impl FnOnce(&mut Supervisor) -> R) -> R {
        let browser = Browser {
            clock: &rig.clock,
            root: &rig.root,
            script: std::mem::take(&mut *rig.script.borrow_mut()).into(),
            calls: RefCell::new(Vec::new()),
            lock_held: RefCell::new(Vec::new()),
        };
        let review = |_: &str, _: u32, _: &str| {
            rig.asked.set(rig.asked.get() + 1);
            let free = SamlLock::acquire(&rig.root, &mut || true, Duration::ZERO).is_some();
            rig.lock_free_at_review.borrow_mut().push(free);
            rig.reviews
                .borrow_mut()
                .pop_front()
                .unwrap_or(Trust::NotACertificateProblem)
        };
        let deps = Deps {
            vpn: &*rig.tweak,
            keychain: &rig.keychain,
            acquirer: &browser,
            clock: &*rig.clock,
            session_id: &|| [7; 16],
            launchctl: &rig.launchctl,
            signals: &*rig.signals,
            review: &review,
            diagnostic: &|_| {},
        };
        let vpn_entry = rig.vpn.load_all().unwrap().remove(0);
        let job = Job {
            entry: &rig.entry,
            provider_id: "com.example.oftc.provider".to_owned(),
            vpn_entry,
            gateway: GATEWAY.to_owned(),
            saml_port: 9443,
            mode: crate::start::parse_start_flags(&[]).unwrap().0,
            insecure: rig.insecure,
            root: &rig.root,
        };
        let lease = SupervisorLease::acquire(&rig.directory()).unwrap();
        let mut supervisor = Supervisor::new(&deps, job, lease);
        let result = body(&mut supervisor);
        rig.calls
            .borrow_mut()
            .extend(browser.calls.borrow().iter().copied());
        rig.lock_held
            .borrow_mut()
            .extend(browser.lock_held.borrow().iter().copied());
        result
    }

    fn exit<'s>(supervisor: &'s Supervisor) -> Option<(&'s str, i32)> {
        supervisor.exit.as_ref().map(|(m, c)| (m.as_str(), *c))
    }

    /// Starts, and brings the tunnel up.
    fn connect(rig: &Rig, supervisor: &mut Supervisor) {
        supervisor.begin_attempt();
        assert_eq!(exit(supervisor), None);
        rig.mock.set_status(VpnStatus::Connected);
        supervisor.observe();
        assert_eq!(rig.phase(), Some(Phase::Connected));
    }

    // -------------------------------------------------------------- scenarios

    /// Connect, then a stop request: the tunnel is stopped and the status says so.
    #[test]
    fn connect_then_stop_request() {
        let rig = Rig::new();
        rig.script(vec![Step::ok()]);
        with_supervisor(&rig, |s| {
            s.begin_attempt();
            // The start carries the live envelope and the mode, after the sign-in.
            let started = rig.mock.started();
            assert_eq!(started.len(), 1);
            assert_eq!(
                (started[0].0, started[0].2.is_some()),
                (StartKind::Live, true)
            );
            assert_eq!(rig.phase(), Some(Phase::Connecting));
            rig.mock.set_status(VpnStatus::Connected);
            s.observe();
            assert_eq!(rig.phase(), Some(Phase::Connected));
            assert!(request_stop(&rig.directory()));
            s.observe();
            assert_eq!(exit(s), Some(("Supervisor stopped", 0)));
        });
        assert_eq!(rig.mock.stops(), 1);
        assert_eq!(rig.phase(), Some(Phase::Stopped));
    }

    /// A stop request or SIGTERM while the browser is open abandons the sign-in:
    /// `cancelled` is true when it is polled, nothing starts, nobody is asked (even
    /// though the failure is the kind that normally leads to a certificate review).
    #[test]
    fn stop_while_signing_in() {
        for by_signal in [false, true] {
            let rig = Rig::new();
            let step = if by_signal {
                let signals = rig.signals.clone();
                Step::fail(AcquireFailure::BeforeBrowser).meanwhile(move || signals.raise())
            } else {
                Step::fail(AcquireFailure::BeforeBrowser).meanwhile(rig.stop_request())
            };
            rig.script(vec![step]);
            with_supervisor(&rig, |s| {
                s.begin_attempt();
                assert_eq!(
                    exit(s),
                    Some(("Supervisor stopped", 0)),
                    "signal={by_signal}"
                );
            });
            assert_eq!(rig.calls.borrow()[..], [(Duration::ZERO, true)]);
            assert!(rig.mock.started().is_empty());
            assert_eq!(rig.asked.get(), 0);
            assert_eq!(rig.phase(), Some(Phase::Stopped));
        }
    }

    /// An entry that is not disconnected at the start, or that changes while the
    /// browser is open, is never started.
    #[test]
    fn the_entry_is_rechecked_around_the_sign_in() {
        // Already connected when the supervisor begins: no sign-in at all.
        let rig = Rig::new();
        rig.mock.set_status(VpnStatus::Connected);
        with_supervisor(&rig, |s| {
            s.begin_attempt();
            assert_eq!(
                exit(s),
                Some(("OFTC status changed before supervised start", 1))
            );
        });
        assert!(rig.calls.borrow().is_empty());

        // Someone else starts the VPN, or disables the entry, while the browser is open.
        for disable in [false, true] {
            let rig = Rig::new();
            let (mock, vpn) = (rig.mock.clone(), rig.vpn.clone());
            rig.script(vec![Step::ok().meanwhile(move || {
                if disable {
                    let entry = vpn.load_all().unwrap().remove(0);
                    vpn.set_enabled(&entry, false).unwrap();
                } else {
                    mock.set_status(VpnStatus::Connected);
                }
            })]);
            with_supervisor(&rig, |s| {
                s.begin_attempt();
                assert_eq!(
                    exit(s),
                    Some(("OFTC configuration or status changed before start", 1))
                );
            });
            assert!(rig.mock.started().is_empty(), "disable={disable}");
        }
    }

    /// A tunnel that drops before it was ever established is not retried, but a status
    /// that is still "disconnected" right after the start request is not a drop.
    #[test]
    fn a_drop_before_establishment_is_final() {
        let rig = Rig::new();
        rig.script(vec![Step::ok()]);
        with_supervisor(&rig, |s| {
            s.begin_attempt();
            s.observe(); // still disconnected, NE has not reported connecting yet
            assert_eq!(exit(s), None);
            rig.mock.set_status(VpnStatus::Connecting);
            s.observe();
            rig.mock.set_status(VpnStatus::Disconnected);
            s.observe();
            assert_eq!(
                exit(s),
                Some(("VPN disconnected before establishment; no token retry", 1))
            );
        });
        assert_eq!(rig.calls.borrow().len(), 1);
    }

    /// After an established tunnel drops: what the disconnect error decides.
    #[test]
    fn disconnect_outcomes() {
        type Row = (Option<AppleError>, Option<(&'static str, i32)>, bool);
        let rows: Vec<Row> = vec![
            // Recoverable: a fresh sign-in after two seconds, no exit.
            (Some(provider(409)), None, false),
            (Some(ne(2)), None, false),
            // Not recoverable.
            (
                Some(ne(8)),
                Some(("VPN disconnected; automatic recovery unavailable", 1)),
                false,
            ),
            // No error at all: the user stopped it in macOS, so stay down and keep the
            // login agent from starting it again.
            (
                None,
                Some((
                    "VPN disconnected without a recoverable error; staying down",
                    0,
                )),
                true,
            ),
        ];
        for (error, expected, disabled) in rows {
            let rig = Rig::new();
            rig.script(vec![Step::ok(), Step::ok()]);
            with_supervisor(&rig, |s| {
                connect(&rig, s);
                rig.mock.set_last_error(error.clone());
                rig.mock.set_status(VpnStatus::Disconnected);
                s.observe();
                assert_eq!(exit(s), expected, "{error:?}");
                if expected.is_none() {
                    assert_eq!(rig.phase(), Some(Phase::Recovering));
                    rig.advance(1);
                    s.observe();
                    assert_eq!(rig.mock.started().len(), 1, "not before two seconds");
                    rig.advance(1);
                    s.observe();
                    assert_eq!(rig.mock.started().len(), 2, "fresh sign-in, fresh start");
                    assert_eq!(rig.phase(), Some(Phase::Connecting));
                }
            });
            // The system is given ten seconds to say why the tunnel dropped.
            assert_eq!(
                rig.tweak.error_timeouts.lock().unwrap()[..],
                [Duration::from_secs(10)]
            );
            assert_eq!(
                rig.launchctl.disabled().len(),
                usize::from(disabled),
                "{error:?}"
            );
            if disabled {
                assert_eq!(rig.launchctl.disabled(), [AGENT_LABEL]);
            }
        }
    }

    /// The fourth recovery in ten minutes is refused.
    #[test]
    fn the_fourth_recovery_exits() {
        let rig = Rig::new();
        rig.script((0..4).map(|_| Step::ok()).collect());
        with_supervisor(&rig, |s| {
            connect(&rig, s);
            for round in 1..=3 {
                rig.mock.set_last_error(Some(provider(409)));
                rig.mock.set_status(VpnStatus::Disconnected);
                s.observe();
                assert_eq!(exit(s), None, "round {round}");
                rig.advance(2);
                s.observe(); // starts again
                rig.mock.set_status(VpnStatus::Connected);
                s.observe();
            }
            rig.mock.set_status(VpnStatus::Disconnected);
            s.observe();
            assert_eq!(
                exit(s),
                Some(("VPN disconnected; automatic recovery unavailable", 1))
            );
        });
    }

    /// An unreachable gateway is retried with 5, 10, 20, then 30 second waits until
    /// the 390 second deadline; a sign-in that ends past the deadline is final.
    #[test]
    fn unreachable_gateway_backs_off_until_the_deadline() {
        let rig = Rig::new();
        rig.script(
            (0..40)
                .map(|_| Step::fail(AcquireFailure::BeforeBrowser))
                .collect(),
        );
        with_supervisor(&rig, |s| {
            s.begin_attempt();
            let mut guard = 0;
            while exit(s).is_none() && guard < 1000 {
                rig.advance(1);
                s.observe();
                guard += 1;
            }
            assert_eq!(exit(s), Some(("VPN start deadline expired", 1)));
        });
        let times: Vec<u64> = rig
            .calls
            .borrow()
            .iter()
            .map(|(t, _)| t.as_secs())
            .collect();
        let gaps: Vec<u64> = times.windows(2).map(|w| w[1] - w[0]).collect();
        assert_eq!(&gaps[..6], [5, 10, 20, 30, 30, 30]);
        assert!(gaps.iter().skip(3).all(|gap| *gap == 30));
        assert_eq!(times.last().copied(), Some(365));
        assert!(rig.mock.started().is_empty());
        assert_eq!(
            rig.asked.get() as usize,
            times.len(),
            "each failure asks the review"
        );

        // The sign-in itself ran out the deadline: no retry is scheduled.
        let rig = Rig::new();
        rig.script(vec![Step::fail(AcquireFailure::BeforeBrowser).takes(391)]);
        with_supervisor(&rig, |s| {
            s.begin_attempt();
            assert_eq!(
                exit(s),
                Some(("Fresh SAML acquisition failed; supervisor stopped", 1))
            );
        });
    }

    /// What the certificate review changes about the retry.
    #[test]
    fn certificate_review_outcomes() {
        let certificate = Certificate::new(vec![0x30, 0x01, 0x00], "s", "i", "1", "v");
        // (review answer, insecure, expected wait before the retry or the exit)
        let rows = [
            (Trust::Trusted(certificate), false, Ok(1u64)),
            (Trust::NotACertificateProblem, false, Ok(5)),
            (
                Trust::Declined,
                false,
                Err(("Gateway certificate not trusted; supervisor stopped", 1)),
            ),
            // --insecure-saml skips the check altogether.
            (Trust::Declined, true, Ok(5)),
        ];
        for (answer, insecure, expected) in rows {
            let mut rig = Rig::new();
            rig.insecure = insecure;
            rig.reviews.borrow_mut().push_back(answer.clone());
            rig.script(vec![
                Step::fail(AcquireFailure::BeforeBrowser),
                Step::fail(AcquireFailure::BeforeBrowser),
            ]);
            with_supervisor(&rig, |s| {
                s.begin_attempt();
                match expected {
                    Err(message) => assert_eq!(exit(s), Some(message), "{answer:?}"),
                    Ok(wait) => {
                        assert_eq!(exit(s), None);
                        assert_eq!(rig.phase(), Some(Phase::Recovering));
                        rig.advance(wait - 1);
                        s.observe();
                        assert_eq!(rig.script.borrow().len(), 0); // (consumed by the browser)
                        rig.advance(1);
                        s.observe();
                    }
                }
            });
            let expect_calls = if expected.is_ok() { 2 } else { 1 };
            assert_eq!(
                rig.calls.borrow().len(),
                expect_calls,
                "{answer:?} insecure={insecure}"
            );
            assert_eq!(
                rig.asked.get(),
                u32::from(!insecure) + u32::from(!insecure && expected.is_ok()),
                "{answer:?}"
            );
        }
    }

    /// Anything but "unreachable before the browser" may have spent the token, so it
    /// is never retried; neither is a missing PSK.
    #[test]
    fn an_uncertain_sign_in_is_never_retried() {
        for psk in [true, false] {
            let rig = Rig::new();
            if !psk {
                rig.keychain.delete(GATEWAY).unwrap();
            }
            rig.script(vec![Step::fail(AcquireFailure::Other)]);
            with_supervisor(&rig, |s| {
                s.begin_attempt();
                assert_eq!(
                    exit(s),
                    Some(("Fresh SAML acquisition failed; supervisor stopped", 1))
                );
            });
            assert_eq!(rig.calls.borrow().len(), usize::from(psk));
            assert_eq!(rig.asked.get(), 0);
            assert_eq!(rig.phase(), Some(Phase::Failed));
        }
    }

    /// A start that never reaches "connected" ends after 90 seconds, stopping the
    /// half-started tunnel.
    #[test]
    fn the_start_deadline() {
        let rig = Rig::new();
        rig.script(vec![Step::ok()]);
        with_supervisor(&rig, |s| {
            s.begin_attempt();
            rig.mock.set_status(VpnStatus::Connecting);
            rig.advance(89);
            s.observe();
            assert_eq!(exit(s), None);
            rig.advance(1);
            s.observe();
            assert_eq!(exit(s), Some(("VPN start deadline expired", 1)));
        });
        assert_eq!(rig.mock.stops(), 1);
    }

    /// Every fifth second the entry is reloaded: if it is no longer exactly one of
    /// ours, supervision ends.
    #[test]
    fn the_configuration_changing_during_supervision() {
        for duplicate in [false, true] {
            let rig = Rig::new();
            rig.script(vec![Step::ok()]);
            with_supervisor(&rig, |s| {
                connect(&rig, s);
                if duplicate {
                    rig.vpn
                        .add_entry("com.example.oftc.provider", Some(&rig.entry.id), true);
                } else {
                    let entry = rig.vpn.load_all().unwrap().remove(0);
                    rig.vpn.remove(&entry).unwrap();
                }
                for _ in 0..4 {
                    s.tick();
                }
                assert_eq!(exit(s), None);
                s.tick();
                assert_eq!(
                    exit(s),
                    Some(("OFTC configuration changed during supervision", 1)),
                    "duplicate={duplicate}"
                );
            });
        }
    }

    /// An entry whose status reads "connected" after the tunnel is gone is only
    /// replaced after two fresh readings in a row say "disconnected".
    #[test]
    fn a_stale_connected_status_needs_two_fresh_disconnected_readings() {
        let rig = Rig::new();
        rig.script(vec![Step::ok()]);
        with_supervisor(&rig, |s| {
            connect(&rig, s);
            // From here the held entry says connected whatever the tunnel does.
            rig.tweak.stale.store(true, Ordering::SeqCst);
            let five = |s: &mut Supervisor| (0..5).for_each(|_| s.tick());
            rig.mock.set_status(VpnStatus::Disconnected);
            five(s); // one fresh disconnected reading
            assert_eq!(exit(s), None);
            rig.mock.set_status(VpnStatus::Connected);
            five(s); // a fresh connected reading resets the count
            rig.mock.set_status(VpnStatus::Disconnected);
            five(s);
            assert_eq!(exit(s), None);
            five(s); // the second in a row: a drop (no error, so it stays down)
            assert_eq!(
                exit(s),
                Some((
                    "VPN disconnected without a recoverable error; staying down",
                    0
                ))
            );
        });
    }

    /// The status record is rewritten every 30 ticks, so a long-lived supervisor's
    /// record does not age out (readers distrust one older than 300 s).
    #[test]
    fn the_heartbeat_keeps_the_status_record_fresh() {
        let rig = Rig::new();
        rig.script(vec![Step::ok()]);
        with_supervisor(&rig, |s| {
            connect(&rig, s);
            rig.advance(250);
            for _ in 0..30 {
                s.tick();
            }
            rig.advance(250); // 500 s after the connect, 250 s after the heartbeat
            assert_eq!(rig.phase(), Some(Phase::Connected));
        });
    }

    /// A start request that fails is final: the token may be spent.
    #[test]
    fn a_failed_start_request_is_final() {
        let rig = Rig::new();
        rig.script(vec![Step::ok()]);
        rig.tweak.fail_start.store(true, Ordering::SeqCst);
        with_supervisor(&rig, |s| {
            s.begin_attempt();
            assert_eq!(exit(s), Some(("VPN start failed; no token retry", 1)));
        });
        assert_eq!(rig.phase(), Some(Phase::Failed));
        assert_eq!(rig.calls.borrow().len(), 1);
    }

    /// The browser step holds `saml.lock` (one sign-in at a time) and the review
    /// prompt, which can stay open for minutes, does not.
    #[test]
    fn the_saml_lock_covers_the_browser_and_not_the_prompt() {
        let rig = Rig::new();
        rig.script(vec![Step::fail(AcquireFailure::BeforeBrowser)]);
        with_supervisor(&rig, |s| s.begin_attempt());
        assert_eq!(rig.lock_held.borrow()[..], [true]);
        assert_eq!(rig.lock_free_at_review.borrow()[..], [true]);
        // And the lock is free once the attempt is over.
        assert!(SamlLock::acquire(&rig.root, &mut || true, Duration::ZERO).is_some());
    }

    /// A tunnel someone else starts while we wait to recover is not ours to stop.
    #[test]
    fn a_connection_we_no_longer_own_is_left_alone() {
        let rig = Rig::new();
        rig.script(vec![Step::ok()]);
        with_supervisor(&rig, |s| {
            connect(&rig, s);
            rig.mock.set_last_error(Some(provider(409)));
            rig.mock.set_status(VpnStatus::Disconnected);
            s.observe();
            rig.mock.set_status(VpnStatus::Connecting); // started elsewhere
            rig.advance(2);
            s.observe();
            assert_eq!(
                exit(s),
                Some(("OFTC status changed before supervised start", 1))
            );
        });
        assert_eq!(rig.mock.stops(), 0);
    }

    /// The runner: woken by status changes, it ends on a stop request.
    #[test]
    fn run_ends_when_a_stop_is_requested_after_the_tunnel_comes_up() {
        let rig = Rig::new();
        rig.script(vec![Step::ok()]);
        let (mock, directory) = (rig.mock.clone(), rig.directory());
        let helper = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            while mock.started().is_empty() && std::time::Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
            mock.set_status(VpnStatus::Connected);
            std::thread::sleep(Duration::from_millis(100));
            assert!(request_stop(&directory));
            mock.set_status(VpnStatus::Connected);
        });
        let result = with_supervisor(&rig, |s| s.run());
        helper.join().unwrap();
        assert_eq!(result, ("Supervisor stopped".to_owned(), 0));
        assert_eq!(rig.mock.stops(), 1);
        assert_eq!(rig.phase(), Some(Phase::Stopped));
    }

    /// With no status change at all, the once-a-second tick alone ends a start that
    /// runs past its deadline.
    #[test]
    fn run_ticks_observe_without_any_status_event() {
        let rig = Rig::new();
        rig.script(vec![Step::ok()]);
        let (mock, clock) = (rig.mock.clone(), rig.clock.clone());
        let helper = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            while mock.started().is_empty() && std::time::Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
            clock.sleep(Duration::from_secs(100)); // no event: only the tick can notice
        });
        let result = with_supervisor(&rig, |s| s.run());
        helper.join().unwrap();
        assert_eq!(result, ("VPN start deadline expired".to_owned(), 1));
    }
}
