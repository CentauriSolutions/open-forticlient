//! The setup ops: `add_profile`, `list_sources`, `component_update`, `open_settings`.
//!
//! `add_profile` runs the same steps as `oftc setup` (PSK, profile, system extension,
//! VPN entry), each reported as a progress line, and is safe to run again: a setup
//! that stopped half way is finished by the next call, and one that is complete says
//! `already_configured` with the profile's id. A PSK is never an argument; a typed one
//! was stored by `provision-psk --stdin` before the call (4.4).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use oftc_apple::error::AppleError;
use oftc_apple::manager::VpnStatus;
use oftc_apple::sysext::{EventSink, ExtensionEvent, Finish};
use oftc_ui_edge::{
    AddProfileArgs, AddProfileResult, ComponentState, ErrorCode, Pane, PskSource, SourceInfo,
    SourcesResult, Step, StepState,
};
use serde_json::json;

use super::ops::{value, OpCx, OpResult};
use super::state::component_from_request;
use crate::commands;
use crate::profile::{Profile, Transport};
use crate::registry::{self, ProfileEntry};
use crate::typed::Failure;
use crate::vpn::{self, Installed};

const COMPONENT_TIMEOUT: Duration = Duration::from_secs(10);

fn transport(wire: oftc_ui_edge::Transport) -> Transport {
    match wire {
        oftc_ui_edge::Transport::Udp => Transport::Udp,
        oftc_ui_edge::Transport::Tcp => Transport::Tcp,
    }
}

/// Reports a step as started, runs it, and reports it done.
fn step<T>(cx: &OpCx, step: Step, body: impl FnOnce() -> Result<T, Failure>) -> Result<T, Failure> {
    cx.checkpoint()?;
    (cx.progress)(step, StepState::Running);
    let done = body()?;
    (cx.progress)(step, StepState::Done);
    Ok(done)
}

/// The PSK for `gateway` is in the Keychain: from the item a `provision-psk --stdin`
/// child stored (`saved`), or taken from a FortiClient profile that is for exactly this
/// gateway, which never leaves the host.
fn secure_psk(cx: &OpCx, args: &AddProfileArgs) -> Result<(), Failure> {
    let keychain = cx.services.ops.keychain;
    if args.psk_source == PskSource::Forticlient {
        let label = args
            .label
            .as_deref()
            .ok_or_else(|| Failure::new(ErrorCode::BadRequest, "forticlient needs a label"))?;
        if let Some(psk) = cx.services.ops.forticlient.psk(label, &args.gateway) {
            return commands::save_psk(keychain, &args.gateway, &psk);
        }
    }
    // The FortiClient profile had no importable key; an item stored earlier still
    // counts, as it did in the setup window.
    keychain.get(&args.gateway).map(|_| ()).map_err(|_| {
        Failure::new(
            ErrorCode::PskUnavailable,
            "OFTC PSK unavailable; store it with provision-psk --stdin first",
        )
    })
}

/// The profile for this gateway: the one a half-finished setup left (no VPN entry
/// yet), or a new one. A gateway that is fully set up is `already_configured`.
fn ensure_profile(
    cx: &OpCx,
    args: &AddProfileArgs,
    profile: &Profile,
) -> Result<ProfileEntry, Failure> {
    let access = cx.access();
    let existing = registry::entries(cx.services.env.root())
        .into_iter()
        .find(|entry| entry.profile.gateway == args.gateway);
    match existing {
        Some(entry) => {
            if access.load_manager(&entry)?.is_some() {
                Err(Failure::new(
                    ErrorCode::AlreadyConfigured,
                    &format!("OFTC already has a profile for {}", args.gateway),
                )
                .for_profile(&entry.id))
            } else {
                Ok(entry)
            }
        }
        None => {
            let _creating = cx.busy.creating();
            commands::save_profile(cx.services.env.root(), profile, None)
        }
    }
}

/// Activates the bundled system extension unless it is already current, reporting
/// `waiting` when macOS needs the user. The request itself cannot be withdrawn; a
/// `cancel` answers the caller at once and the op stops when the request ends.
fn ensure_extension(cx: &OpCx) -> Result<(), Failure> {
    let services = cx.services;
    let provider = services.env.provider_id();
    let expected = &services.host.build;
    if !expected.is_empty() {
        let (state, _) = component_from_request(
            expected,
            services.extensions.properties(&provider, COMPONENT_TIMEOUT),
        );
        if matches!(state, ComponentState::Ready | ComponentState::Newer) {
            return Ok(());
        }
    }
    let (events, heard) = mpsc::channel();
    let sink: EventSink = std::sync::Arc::new(move |event| {
        let _ = events.send(event);
    });
    // The sink needs a 'static handle, so a second thread turns its events into
    // progress while this one waits on the system; the sink's drop ends the relay.
    let ended = AtomicBool::new(false);
    let ended = &ended;
    let finish = thread::scope(|scope| {
        scope.spawn(move || {
            // The system may keep the sink after the request ends, so the relay stops
            // on the flag and does not wait for the channel to close.
            while !ended.load(Ordering::SeqCst) {
                match heard.recv_timeout(Duration::from_millis(50)) {
                    Ok(ExtensionEvent::NeedsApproval) => {
                        (cx.progress)(Step::ExtensionApproval, StepState::Waiting);
                    }
                    Ok(_) | Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(mpsc::RecvTimeoutError::Disconnected) => return,
                }
            }
            // Events raised just before the request returned.
            while let Ok(event) = heard.try_recv() {
                if event == ExtensionEvent::NeedsApproval {
                    (cx.progress)(Step::ExtensionApproval, StepState::Waiting);
                }
            }
        });
        let finish = services.extensions.activate(&provider, sink);
        ended.store(true, Ordering::SeqCst);
        finish
    });
    cx.checkpoint()?;
    match finish {
        Ok(Finish::Completed) => Ok(()),
        Ok(Finish::WillCompleteAfterReboot) => Err(Failure::internal(
            "Extension replacement accepted; reboot required",
        )),
        Err(AppleError::ApprovalRequired) => Err(Failure::new(
            ErrorCode::ApprovalRequired,
            "System extension needs approval in System Settings",
        )),
        Err(error) => Err(Failure::internal(&format!(
            "System extension request failed: {error}"
        ))),
    }
}

/// `add_profile`: PSK, profile, system extension, VPN entry.
pub fn add_profile(cx: &OpCx, args: AddProfileArgs) -> OpResult {
    let profile = Profile::new(
        &args.gateway,
        args.saml_port,
        transport(args.transport),
        args.name.as_deref(),
        None,
    )
    .map_err(|_| Failure::new(ErrorCode::BadRequest, "invalid name, gateway or SAML port"))?;
    let _busy = cx.busy.acquire(vec![format!("gateway:{}", args.gateway)])?;
    step(cx, Step::Keychain, || secure_psk(cx, &args))?;
    let entry = step(cx, Step::Profile, || ensure_profile(cx, &args, &profile))?;
    step(cx, Step::ExtensionApproval, || ensure_extension(cx))?;
    step(cx, Step::VpnEntry, || {
        vpn::install_profile(&cx.access(), &entry).map(|_: Installed| ())
    })?;
    value(&AddProfileResult {
        profile_id: entry.id,
    })
}

/// The FortiClient profiles that could be imported, never with their PSKs.
pub fn list_sources(cx: &OpCx) -> OpResult {
    let configured = registry::entries(cx.services.env.root());
    let sources = cx
        .services
        .ops
        .forticlient
        .list()
        .into_iter()
        .map(|source| SourceInfo {
            already_configured: configured
                .iter()
                .any(|entry| entry.profile.gateway == source.gateway),
            label: source.label,
            gateway: source.gateway,
            saml_port: source.saml_port,
        })
        .collect();
    value(&SourcesResult { sources })
}

/// Replaces the installed system extension with the bundled one. Refused while any
/// tunnel is up; touches no profile, PSK or VPN entry.
pub fn component_update(cx: &OpCx) -> OpResult {
    let _busy = cx.busy.acquire(vec!["component".to_owned()])?;
    let services = cx.services;
    let provider = services.env.provider_id();
    let loaded = services
        .vpn
        .load_all()
        .map_err(|_| Failure::internal("Could not load VPN configuration"))?;
    let active = loaded.iter().any(|vpn| {
        vpn.provider_id == provider
            && !matches!(
                services.vpn.status(vpn),
                VpnStatus::Disconnected | VpnStatus::Invalid
            )
    });
    if active {
        return Err(Failure::new(
            ErrorCode::TunnelsActive,
            "Disconnect every VPN before updating the component",
        ));
    }
    step(cx, Step::ExtensionApproval, || ensure_extension(cx))?;
    Ok(json!({}))
}

/// Opens System Settings at the pane the user has to visit.
pub fn open_settings(cx: &OpCx, pane: Pane) -> OpResult {
    if cx.services.ops.opener.open(pane) {
        Ok(json!({}))
    } else {
        Err(Failure::internal("Could not open System Settings"))
    }
}
