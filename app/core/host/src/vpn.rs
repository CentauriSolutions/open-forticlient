//! The verbs that touch the macOS VPN entry: install, status, remove, erase, the
//! rekey probes, and the one-shot starts.
//!
//! Each returns the text to print and the exit code. Every OS call goes through
//! [`VpnControl`], so the logic runs against [`oftc_apple::manager::MockVpn`].
//! Messages and codes are the verb protocol the Swift host used.

use std::time::Duration;

use oftc_apple::manager::{StartOptions, VpnControl, VpnEntry, VpnStatus};
use oftc_host_bootstrap::TunnelProfile;
use oftc_provider::envelope::ConnectMode;

use crate::commands::{require_entry, Backends};
use crate::env::HostEnv;
use crate::keychain::Keychain;
use crate::lease::SupervisorLease;
use crate::profile::Transport;
use crate::registry::{self, ProfileEntry};
use crate::start::{live_options, parse_start_flags, preflight_options};
use crate::supervisor::{Deps, Job, Supervisor};
use crate::typed::Failure;
use oftc_ui_edge::ErrorCode;

/// What a verb prints and returns.
pub(crate) type Outcome = (String, i32);

fn ok(text: &str) -> Outcome {
    (text.to_owned(), 0)
}

fn fail(text: &str) -> Outcome {
    (text.to_owned(), 1)
}

/// Whether `vpn` is `entry`'s VPN entry under `provider_id`: keyed to the profile,
/// or unkeyed and adopted by a profile migrated from the single-profile layout.
pub(crate) fn owns(provider_id: &str, entry: &ProfileEntry, vpn: &VpnEntry) -> bool {
    owns_key(
        provider_id,
        &entry.id,
        entry.profile.adopts_unkeyed_vpn_entry == Some(true),
        vpn,
    )
}

/// [`owns`] for a profile known by its id and whether it adopted the unkeyed entry.
pub(crate) fn owns_key(provider_id: &str, id: &str, adopted: bool, vpn: &VpnEntry) -> bool {
    vpn.provider_id == provider_id
        && (vpn.profile_key.as_deref() == Some(id) || (vpn.profile_key.is_none() && adopted))
}

/// What the typed internals below need. The verbs reach it through [`Ctx`], the
/// socket ops build it directly, so both run the same code.
pub(crate) struct Access<'a> {
    pub env: &'a HostEnv,
    pub vpn: &'a dyn VpnControl,
    pub keychain: &'a dyn Keychain,
}

impl Access<'_> {
    fn belongs(&self, entry: &ProfileEntry, vpn: &VpnEntry) -> bool {
        owns(&self.env.provider_id(), entry, vpn)
    }

    /// The profile's one VPN entry, if any.
    pub(crate) fn load_manager(&self, entry: &ProfileEntry) -> Result<Option<VpnEntry>, Failure> {
        let all = self
            .vpn
            .load_all()
            .map_err(|_| Failure::internal("Could not load VPN configuration"))?;
        let mut ours = all.into_iter().filter(|vpn| self.belongs(entry, vpn));
        let first = ours.next();
        match ours.next() {
            Some(_) => Err(Failure::internal(
                "Multiple OFTC configurations; refusing to guess",
            )),
            None => Ok(first),
        }
    }
}

/// How `install-config` ended.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Installed {
    Saved,
    AlreadyThere,
}

/// Creates the profile's VPN entry unless it has one. Idempotent.
pub(crate) fn install_profile(a: &Access, entry: &ProfileEntry) -> Result<Installed, Failure> {
    match a.load_manager(entry)? {
        Some(_) => Ok(Installed::AlreadyThere),
        None => a
            .vpn
            .create(&a.env.provider_id(), &entry.id, entry.name())
            .map(|()| Installed::Saved)
            .map_err(|_| Failure::internal("Could not save OFTC configuration")),
    }
}

/// How `stop` ended.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Stopped {
    Requested,
    NoConfiguration,
}

/// Asks the supervisor to stand down, then stops the tunnel. The supervisor is told
/// first so an intentional disconnect cannot start another sign-in; if it cannot be
/// told, the VPN is left running.
pub(crate) fn stop_profile(a: &Access, entry: &ProfileEntry) -> Result<Stopped, Failure> {
    if !crate::lease::request_stop(&registry::entry_directory(a.env.root(), &entry.id)) {
        return Err(Failure::internal(
            "Could not signal OFTC supervisor; VPN left running",
        ));
    }
    match a.load_manager(entry)? {
        None => Ok(Stopped::NoConfiguration),
        Some(vpn) => {
            a.vpn.stop(&vpn);
            Ok(Stopped::Requested)
        }
    }
}

/// How `erase-profile` ended.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Erased {
    Done,
    NothingToErase,
}

/// Erases `targets` (every profile when the verb has no `--profile`): each one's VPN
/// entry, PSK, trusted gateway certificate and files. Nothing is erased while any of
/// them is up.
pub(crate) fn erase_profiles(a: &Access, targets: &[ProfileEntry]) -> Result<Erased, Failure> {
    if targets.is_empty() {
        return Ok(Erased::NothingToErase);
    }
    let all = a
        .vpn
        .load_all()
        .map_err(|_| Failure::internal("Could not load VPN configuration"))?;
    let mut doomed: Vec<&VpnEntry> = Vec::new();
    for entry in targets {
        for vpn in all.iter().filter(|vpn| a.belongs(entry, vpn)) {
            if !matches!(
                a.vpn.status(vpn),
                VpnStatus::Disconnected | VpnStatus::Invalid
            ) {
                return Err(Failure::new(
                    ErrorCode::TunnelsActive,
                    &format!("Disconnect {} before erasing its profile", entry.name()),
                ));
            }
            doomed.push(vpn);
        }
    }
    // Each profile's VPN entry goes with it, so none is left orphaned.
    for vpn in doomed {
        if a.vpn.remove(vpn).is_err() {
            return Err(Failure::internal(
                "Could not remove an OFTC VPN entry; profile left in place",
            ));
        }
    }
    for entry in targets {
        if a.keychain.delete(&entry.profile.gateway).is_err() {
            return Err(Failure::internal(&format!(
                "Could not erase OFTC Keychain PSK for {}; profile left in place",
                entry.name()
            )));
        }
        // Its trusted gateway certificate goes too; a re-added VPN asks again.
        let pin = a.env.pin_dir().join(format!(
            "{}_{}.pem",
            entry.profile.gateway, entry.profile.saml_port
        ));
        let _ = std::fs::remove_file(pin);
        if std::fs::remove_dir_all(registry::entry_directory(a.env.root(), &entry.id)).is_err() {
            return Err(Failure::internal(&format!(
                "Keychain PSK erased, but profile {} could not be removed",
                entry.name()
            )));
        }
    }
    Ok(Erased::Done)
}

pub(crate) struct Ctx<'a> {
    pub env: &'a HostEnv,
    pub backends: &'a Backends<'a>,
    pub selected: &'a Option<String>,
}

const PREFLIGHT_STATUS: &[u8] = b"oftc.preflight-status.v1";
const PREFLIGHT_DEADLINE: Duration = Duration::from_secs(45);
const PREFLIGHT_POLL: Duration = Duration::from_millis(250);
/// One preflight-status request; the loop asks again until the deadline.
const PREFLIGHT_REPLY: Duration = Duration::from_secs(10);
const REKEY_TIMEOUT: Duration = Duration::from_secs(45);
const COUNTS_TIMEOUT: Duration = Duration::from_secs(10);

impl Ctx<'_> {
    fn vpn(&self) -> &dyn VpnControl {
        self.backends.vpn
    }

    pub(crate) fn entry(&self) -> Result<ProfileEntry, Outcome> {
        require_entry(self.selected, self.env.root()).map_err(|message| (message, 1))
    }

    /// Whether `vpn` is this profile's entry: this app's provider, keyed to the
    /// profile, or unkeyed and adopted by a profile migrated from the
    /// single-profile layout.
    fn belongs(&self, entry: &ProfileEntry, vpn: &VpnEntry) -> bool {
        owns(&self.env.provider_id(), entry, vpn)
    }

    pub(crate) fn access(&self) -> Access<'_> {
        Access {
            env: self.env,
            vpn: self.backends.vpn,
            keychain: self.backends.keychain,
        }
    }

    /// The profile's one VPN entry, if any.
    pub(crate) fn load_manager(&self, entry: &ProfileEntry) -> Result<Option<VpnEntry>, Outcome> {
        self.access().load_manager(entry).map_err(Failure::outcome)
    }

    /// Rechecks the entry just before acting: another process may have changed
    /// it, for instance while a browser sign-in was open. `Some` only if it is
    /// still enabled, ours, and in `status`.
    pub(crate) fn recheck(
        &self,
        entry: &ProfileEntry,
        vpn: &VpnEntry,
        status: VpnStatus,
    ) -> Option<VpnEntry> {
        let fresh = self.vpn().reload(vpn).ok()?;
        (fresh.enabled && self.belongs(entry, &fresh) && self.vpn().status(&fresh) == status)
            .then_some(fresh)
    }
}

pub(crate) fn install_config(ctx: &Ctx) -> Outcome {
    let entry = match ctx.entry() {
        Ok(entry) => entry,
        Err(outcome) => return outcome,
    };
    match install_profile(&ctx.access(), &entry) {
        Ok(Installed::Saved) => ok("OFTC configuration saved"),
        Ok(Installed::AlreadyThere) => ok("OFTC configuration already exists"),
        Err(failure) => failure.outcome(),
    }
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

pub(crate) fn status(ctx: &Ctx) -> Outcome {
    let entry = match ctx.entry() {
        Ok(entry) => entry,
        Err(outcome) => return outcome,
    };
    match ctx.load_manager(&entry) {
        Err(outcome) => outcome,
        Ok(None) => ok("OFTC configuration absent"),
        Ok(Some(vpn)) => (
            format!("OFTC VPN status: {}", status_word(ctx.vpn().status(&vpn))),
            0,
        ),
    }
}

/// `stop`: [`stop_profile`] for the selected profile.
pub(crate) fn stop(ctx: &Ctx) -> Outcome {
    let entry = match ctx.entry() {
        Ok(entry) => entry,
        Err(outcome) => return outcome,
    };
    match stop_profile(&ctx.access(), &entry) {
        Ok(Stopped::Requested) => ok("Stop requested"),
        Ok(Stopped::NoConfiguration) => ok("OFTC configuration absent"),
        Err(failure) => failure.outcome(),
    }
}

/// Removes every OFTC VPN entry, with or without a profile key, so it needs no
/// profile.
pub(crate) fn remove_config(ctx: &Ctx) -> Outcome {
    let all = match ctx.vpn().load_all() {
        Ok(all) => all,
        Err(_) => return fail("Could not load VPN configuration"),
    };
    let provider = ctx.env.provider_id();
    let ours: Vec<VpnEntry> = all
        .into_iter()
        .filter(|v| v.provider_id == provider)
        .collect();
    if ours.is_empty() {
        return ok("OFTC configuration absent");
    }
    for vpn in &ours {
        if ctx.vpn().remove(vpn).is_err() {
            return fail("Could not remove OFTC configuration");
        }
    }
    ok("OFTC configuration removed")
}

/// `erase-profile`: [`erase_profiles`] for the selected profile, or every profile
/// when none is selected (so an uninstall can clean up).
pub(crate) fn erase_profile(ctx: &Ctx) -> Outcome {
    let targets = if ctx.selected.is_some() {
        match ctx.entry() {
            Ok(entry) => vec![entry],
            Err(outcome) => return outcome,
        }
    } else {
        registry::entries(ctx.env.root())
    };
    match erase_profiles(&ctx.access(), &targets) {
        Ok(Erased::Done) => ok("OFTC profile, VPN entry and Keychain PSK erased"),
        Ok(Erased::NothingToErase) => ok("OFTC profile absent; nothing erased"),
        Err(failure) => failure.outcome(),
    }
}

#[derive(Clone, Copy)]
pub(crate) enum Rekey {
    Child,
    Ike,
}

/// Asks the running provider to rekey once and reports the result.
pub(crate) fn rekey_once(ctx: &Ctx, which: Rekey) -> Outcome {
    let (kind, message) = match which {
        Rekey::Child => ("CHILD_SA", &b"oftc.rekey-child-once.v1"[..]),
        Rekey::Ike => ("IKE_SA", &b"oftc.rekey-ike-once.v1"[..]),
    };
    let entry = match ctx.entry() {
        Ok(entry) => entry,
        Err(outcome) => return outcome,
    };
    let vpn = match ctx.load_manager(&entry) {
        Ok(Some(vpn)) => vpn,
        Ok(None) => return fail("No OFTC configuration"),
        Err(outcome) => return outcome,
    };
    let Some(vpn) = ctx.recheck(&entry, &vpn, VpnStatus::Connected) else {
        return fail("OFTC VPN is not connected");
    };
    match ctx
        .vpn()
        .send_provider_message(&vpn, message, REKEY_TIMEOUT)
    {
        Ok(reply) if reply == b"rekey_passed" => ok(&format!("{kind} rekey probe passed")),
        Ok(reply) => {
            let stage = String::from_utf8(reply)
                .ok()
                .and_then(|text| text.strip_prefix("rekey_failed stage=").map(str::to_owned))
                .and_then(|digits| digits.parse::<i32>().ok())
                .filter(|stage| (0..=200).contains(stage));
            match stage {
                Some(stage) => fail(&format!("{kind} rekey probe failed (stage {stage})")),
                None => fail(&format!("{kind} rekey probe failed")),
            }
        }
        Err(oftc_apple::error::AppleError::TimedOut) => {
            fail(&format!("{kind} rekey probe timed out"))
        }
        Err(_) => fail(&format!("Could not request {kind} rekey probe")),
    }
}

pub(crate) fn rekey_counts(ctx: &Ctx) -> Outcome {
    let entry = match ctx.entry() {
        Ok(entry) => entry,
        Err(outcome) => return outcome,
    };
    let vpn = match ctx.load_manager(&entry) {
        Ok(Some(vpn)) => vpn,
        Ok(None) => return fail("No OFTC configuration"),
        Err(outcome) => return outcome,
    };
    // Unlike the probes, this does not require the entry to be enabled.
    let connected = ctx
        .vpn()
        .reload(&vpn)
        .ok()
        .filter(|fresh| ctx.vpn().status(fresh) == VpnStatus::Connected);
    let Some(vpn) = connected else {
        return fail("OFTC VPN is not connected");
    };
    const UNAVAILABLE: &str = "CHILD_SA rekey counts unavailable";
    match ctx
        .vpn()
        .send_provider_message(&vpn, b"oftc.rekey-counts.v1", COUNTS_TIMEOUT)
    {
        Ok(reply) => match String::from_utf8(reply) {
            Ok(text) if text.starts_with("child_rekeys local=") => (text, 0),
            _ => fail(UNAVAILABLE),
        },
        Err(oftc_apple::error::AppleError::TimedOut) => fail(UNAVAILABLE),
        Err(_) => fail("Could not request CHILD_SA rekey counts"),
    }
}

/// Starts the tunnel with `options`, after rechecking the entry. `preflight`
/// then waits for the provider to report a stage.
fn start_with(
    ctx: &Ctx,
    entry: &ProfileEntry,
    vpn: &VpnEntry,
    options: StartOptions,
    preflight: bool,
) -> Outcome {
    let Some(vpn) = ctx.recheck(entry, vpn, VpnStatus::Disconnected) else {
        return fail("OFTC configuration or status changed before start");
    };
    if ctx.vpn().start(&vpn, options).is_err() {
        return fail("Start request failed; acquire a fresh token before another live attempt");
    }
    if preflight {
        await_preflight(ctx, &vpn)
    } else {
        ok("Live start requested; inspect status before any fresh-token retry")
    }
}

/// Polls the provider until it reports a preflight stage, then stops the tunnel.
fn await_preflight(ctx: &Ctx, vpn: &VpnEntry) -> Outcome {
    let clock = ctx.backends.clock;
    let deadline = clock.now() + PREFLIGHT_DEADLINE;
    loop {
        if clock.now() >= deadline {
            ctx.vpn().stop(vpn);
            return fail("Provider preflight did not report a stage before timeout");
        }
        if ctx.vpn().status(vpn) == VpnStatus::Connected {
            if let Ok(reply) =
                ctx.vpn()
                    .send_provider_message(vpn, PREFLIGHT_STATUS, PREFLIGHT_REPLY)
            {
                // The provider answers with nothing (a nil reply, an empty one here)
                // until a stage exists, so an early poll is the normal case.
                if let Some(stage) = String::from_utf8(reply).ok().filter(|s| !s.is_empty()) {
                    ctx.vpn().stop(vpn);
                    let code = i32::from(!stage.starts_with("preflight_passed"));
                    return (stage, code);
                }
            }
        }
        clock.sleep(PREFLIGHT_POLL);
    }
}

fn stored_psk(ctx: &Ctx, gateway: &str) -> Result<zeroize::Zeroizing<Vec<u8>>, Outcome> {
    ctx.backends
        .keychain
        .get(gateway)
        .map_err(|_| fail("PSK unavailable in OFTC Keychain service"))
}

pub(crate) fn preflight(ctx: &Ctx, gateway: &str, uid: &str) -> Outcome {
    if uid.len() != 32 || !uid.bytes().all(|b| b.is_ascii_hexdigit()) {
        return ("Expected a 32-character hexadecimal UID".to_owned(), 2);
    }
    let psk = match stored_psk(ctx, gateway) {
        Ok(psk) => psk,
        Err(outcome) => return outcome,
    };
    let options = match preflight_options(
        ctx.backends.clock,
        ctx.backends.session_id,
        gateway,
        uid,
        &psk,
    ) {
        Ok(options) => options,
        Err(crate::start::PreflightError::Input) => {
            return ("Invalid preflight input".to_owned(), 2)
        }
        Err(crate::start::PreflightError::Envelope) => {
            return ("Could not make preflight envelope".to_owned(), 2)
        }
    };
    let entry = match ctx.entry() {
        Ok(entry) => entry,
        Err(outcome) => return outcome,
    };
    match ctx.load_manager(&entry) {
        Err(outcome) => outcome,
        Ok(None) => fail("No OFTC configuration; run install-config"),
        Ok(Some(vpn)) => start_with(ctx, &entry, &vpn, options, true),
    }
}

/// Signs in through the browser, then starts the tunnel once. Never supervised:
/// a failure here is reported, not retried, because the token is single-use.
fn start_live_for(
    ctx: &Ctx,
    entry: &ProfileEntry,
    gateway: &str,
    port: u32,
    mode: ConnectMode,
    insecure: bool,
) -> Outcome {
    let vpn = match ctx.load_manager(entry) {
        Err(outcome) => return outcome,
        Ok(None) => return fail("No OFTC configuration; run install-config"),
        Ok(Some(vpn)) => vpn,
    };
    let Some(vpn) = ctx.recheck(entry, &vpn, VpnStatus::Disconnected) else {
        return fail("OFTC configuration unavailable or VPN already active");
    };
    let psk = match stored_psk(ctx, gateway) {
        Ok(psk) => psk,
        Err(outcome) => return outcome,
    };
    let profile = TunnelProfile {
        name: entry.name().to_owned(),
        gateway: gateway.to_owned(),
    };
    let options = match live_options(
        ctx.backends.acquirer,
        ctx.backends.clock,
        ctx.backends.session_id,
        gateway,
        &psk,
        port,
        insecure,
        profile,
        mode,
        &|| false,
    ) {
        Ok(options) => options,
        Err(_) => return fail("SAML bootstrap failed"),
    };
    start_with(ctx, entry, &vpn, options, false)
}

pub(crate) fn start_live(
    ctx: &Ctx,
    gateway: &str,
    port: u32,
    mode: ConnectMode,
    insecure: bool,
) -> Outcome {
    match ctx.entry() {
        Ok(entry) => start_live_for(ctx, &entry, gateway, port, mode, insecure),
        Err(outcome) => outcome,
    }
}

/// `start-profile`: `start-live` for the selected profile's own gateway, port and
/// transport. The flags are checked after the profile, as the Swift verb did.
pub(crate) fn start_profile(ctx: &Ctx, flags: &[String]) -> Outcome {
    let entry = match ctx.entry() {
        Ok(entry) => entry,
        Err(outcome) => return outcome,
    };
    let flags = profile_flags(&entry, flags);
    let Some((mode, insecure)) = parse_start_flags(&flags) else {
        return (crate::commands::usage(), 2);
    };
    let (gateway, port) = (entry.profile.gateway.clone(), entry.profile.saml_port);
    start_live_for(ctx, &entry, &gateway, port, mode, insecure)
}

/// Takes the profile's supervisor lease and supervises until it stops. The checks
/// before it are `start-live`'s, and the browser's confirmation page names the tunnel
/// from `entry`, not from the environment.
fn supervise_for(
    ctx: &Ctx,
    entry: &ProfileEntry,
    gateway: &str,
    port: u32,
    mode: ConnectMode,
    insecure: bool,
) -> Outcome {
    let vpn = match ctx.load_manager(entry) {
        Err(outcome) => return outcome,
        Ok(None) => return fail("No OFTC configuration; run install-config"),
        Ok(Some(vpn)) => vpn,
    };
    let Some(vpn) = ctx.recheck(entry, &vpn, VpnStatus::Disconnected) else {
        return fail("OFTC configuration unavailable or VPN already active");
    };
    let Ok(lease) = SupervisorLease::acquire(&registry::entry_directory(ctx.env.root(), &entry.id))
    else {
        return fail("Another OFTC supervisor is active");
    };
    let b = ctx.backends;
    let deps = Deps {
        vpn: b.vpn,
        keychain: b.keychain,
        acquirer: b.acquirer,
        clock: b.clock,
        session_id: b.session_id,
        launchctl: b.launchctl,
        signals: b.signals,
        presence: b.presence,
        review: b.review,
        diagnostic: b.diagnostic,
    };
    let job = Job {
        entry,
        provider_id: ctx.env.provider_id(),
        vpn_entry: vpn,
        gateway: gateway.to_owned(),
        saml_port: port,
        mode,
        insecure,
        root: ctx.env.root(),
    };
    Supervisor::new(&deps, job, lease).run()
}

pub(crate) fn supervise_live(
    ctx: &Ctx,
    gateway: &str,
    port: u32,
    mode: ConnectMode,
    insecure: bool,
) -> Outcome {
    match ctx.entry() {
        Ok(entry) => supervise_for(ctx, &entry, gateway, port, mode, insecure),
        Err(outcome) => outcome,
    }
}

/// `supervise-profile`: `supervise-live` for the selected profile's own gateway, port
/// and transport.
pub(crate) fn supervise_profile(ctx: &Ctx, flags: &[String]) -> Outcome {
    let entry = match ctx.entry() {
        Ok(entry) => entry,
        Err(outcome) => return outcome,
    };
    let flags = profile_flags(&entry, flags);
    let Some((mode, insecure)) = parse_start_flags(&flags) else {
        return (crate::commands::usage(), 2);
    };
    let (gateway, port) = (entry.profile.gateway.clone(), entry.profile.saml_port);
    supervise_for(ctx, &entry, &gateway, port, mode, insecure)
}

/// The flags with `--tcp` added when the profile's transport is TCP.
fn profile_flags(entry: &ProfileEntry, flags: &[String]) -> Vec<String> {
    let mut flags = flags.to_vec();
    if entry.profile.transport == Transport::Tcp && !flags.iter().any(|f| f == "--tcp") {
        flags.insert(0, "--tcp".to_owned());
    }
    flags
}
