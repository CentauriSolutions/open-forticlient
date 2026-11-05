//! The socket's actions (`docs/ui-edge.md` 4.3): connect, disconnect, remove, the
//! `.oftc` file ops, settings and the rest.
//!
//! Every op is a thin typed wrapper over the internals the verbs use
//! (`vpn::{stop_profile, erase_profiles, install_profile}`, `commands::{export_bundle,
//! import_bundle, change_autostart, save_profile}`), so a verb and its op cannot
//! disagree about what happened or why it failed: both get the same [`Failure`].
//! `ops_setup` holds the multi-step ops, `ops_update` the update feed and
//! `ops_system` the real process-spawning backends.

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use oftc_apple::login::{LoginItem, LoginStatus};
use oftc_apple::manager::VpnStatus;
use oftc_ui_edge::{
    ErrorCode, ExportArgs, ImportResult, PathArgs, PreviewItem, PreviewResult, ProfileArgs,
    ProfileError, RemoveArgs, Request, SettingsArgs, Step, StepState, Transport,
};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};

use super::{ops_setup, ops_update, Services};
use crate::bundle;
use crate::commands;
use crate::lease;
use crate::profile;
use crate::registry::{self, ProfileEntry};
use crate::typed::Failure;
use crate::vpn::{self, Access, Erased};

/// Everything an op reaches beyond the status service's own seams.
pub struct OpsDeps<'a> {
    pub keychain: &'a dyn crate::keychain::Keychain,
    pub forticlient: &'a dyn commands::FortiClientProfiles,
    pub launchctl: &'a dyn crate::agent::Launchctl,
    pub spawner: &'a dyn ops_system::Spawner,
    pub updates: &'a dyn ops_update::UpdateSource,
    pub opener: &'a dyn ops_system::SettingsOpener,
    /// Waits between polls (`remove` waits for the tunnel to come down); a no-op in tests.
    pub pause: &'a (dyn Fn(Duration) + Sync),
}

use super::ops_system;

/// `remove` waits this many polls of [`POLL`] (20 s) for the tunnel to come down.
const REMOVE_POLLS: u32 = 80;
const POLL: Duration = Duration::from_millis(250);
/// Where the host keeps what `settings_set` stores for itself.
const SETTINGS_FILE: &str = "host-settings.json";

/// Which operations are running. A second op that needs a key some other op holds
/// gets `busy` at once; nothing waits. Keys are `profile:<id>`, `gateway:<host>` (a
/// profile being added or imported) and `component`.
#[derive(Default)]
pub struct Busy(Mutex<HashMap<String, ()>>);

pub struct BusyGuard<'a> {
    busy: &'a Busy,
    keys: Vec<String>,
}

impl Busy {
    /// All of `keys` or none of them.
    pub fn acquire(&self, keys: Vec<String>) -> Result<BusyGuard<'_>, Failure> {
        let mut held = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(taken) = keys.iter().find(|key| held.contains_key(*key)) {
            return Err(Failure::new(
                ErrorCode::Busy,
                &format!("another operation holds {taken}"),
            ));
        }
        for key in &keys {
            held.insert(key.clone(), ());
        }
        Ok(BusyGuard { busy: self, keys })
    }
}

impl Drop for BusyGuard<'_> {
    fn drop(&mut self) {
        let mut held = self.busy.0.lock().unwrap_or_else(PoisonError::into_inner);
        for key in &self.keys {
            held.remove(key);
        }
    }
}

/// What one running op can reach.
pub struct OpCx<'a> {
    pub services: &'a Services<'a>,
    pub busy: &'a Busy,
    /// Where `profiles[].error` and the `stopping` flag are recorded.
    pub collector: &'a super::collect::Collector<'a>,
    /// Set by `cancel`; ops look at it between steps.
    pub cancel: &'a AtomicBool,
    pub progress: &'a (dyn Fn(Step, StepState) + Sync),
}

impl OpCx<'_> {
    pub(crate) fn access(&self) -> Access<'_> {
        Access {
            env: self.services.env,
            vpn: self.services.vpn,
            keychain: self.services.ops.keychain,
        }
    }

    pub(crate) fn checkpoint(&self) -> Result<(), Failure> {
        if self.cancel.load(Ordering::SeqCst) {
            Err(Failure::new(ErrorCode::Cancelled, "cancelled"))
        } else {
            Ok(())
        }
    }

    fn root(&self) -> &Path {
        self.services.env.root()
    }
}

/// Ops the dispatcher runs on a worker; `hello`, `status`, `profiles`, `subscribe`,
/// `unsubscribe` and `cancel` are the session's own.
pub const OPS: &[&str] = &[
    "connect",
    "disconnect",
    "remove",
    "export",
    "import_preview",
    "import",
    "settings_set",
    "check_update",
    "open_settings",
    "add_profile",
    "list_sources",
    "component_update",
];

pub type OpResult = Result<Value, Failure>;

fn args<T: DeserializeOwned>(request: &Request) -> Result<T, Failure> {
    request.args::<T>().ok_or_else(|| {
        Failure::new(
            ErrorCode::BadRequest,
            &format!("{} needs different arguments", request.op),
        )
    })
}

pub(super) fn value(result: &impl serde::Serialize) -> OpResult {
    serde_json::to_value(result).map_err(|_| Failure::internal("could not encode the result"))
}

/// Runs `request`'s op. `None` when `op` is not one of [`OPS`].
pub fn run(request: &Request, cx: &OpCx) -> Option<OpResult> {
    let result = match request.op.as_str() {
        "connect" => args::<ProfileArgs>(request).and_then(|a| connect(cx, a.profile.as_deref())),
        "disconnect" => {
            args::<ProfileArgs>(request).and_then(|a| disconnect(cx, a.profile.as_deref()))
        }
        "remove" => args::<RemoveArgs>(request).and_then(|a| remove(cx, &a.profile)),
        "export" => args::<ExportArgs>(request).and_then(|a| export(cx, &a)),
        "import_preview" => args::<PathArgs>(request).and_then(|a| import_preview(cx, &a.path)),
        "import" => args::<PathArgs>(request).and_then(|a| import(cx, &a.path)),
        "settings_set" => args::<SettingsArgs>(request).and_then(|a| settings_set(cx, &a)),
        "open_settings" => args::<oftc_ui_edge::PaneArgs>(request)
            .and_then(|a| ops_setup::open_settings(cx, a.pane)),
        "check_update" => ops_update::check_update(cx),
        "add_profile" => args(request).and_then(|a| ops_setup::add_profile(cx, a)),
        "list_sources" => ops_setup::list_sources(cx),
        "component_update" => ops_setup::component_update(cx),
        _ => return None,
    };
    Some(result)
}

/// The profile `id`, or all profiles when `None`.
fn targets(cx: &OpCx, id: Option<&str>) -> Result<Vec<ProfileEntry>, Failure> {
    let all = registry::entries(cx.root());
    match id {
        None => Ok(all),
        Some(id) => all
            .into_iter()
            .find(|entry| entry.id == id)
            .map(|entry| vec![entry])
            .ok_or_else(|| {
                Failure::new(
                    ErrorCode::NotConfigured,
                    &format!("OFTC profile unavailable: no profile named {id}"),
                )
            }),
    }
}

fn profile_keys(entries: &[ProfileEntry]) -> Vec<String> {
    entries
        .iter()
        .map(|e| format!("profile:{}", e.id))
        .collect()
}

/// Records `failure` on each profile's row (or clears it), the way the next status
/// document shows it.
fn show(cx: &OpCx, entries: &[ProfileEntry], failure: Option<&Failure>) {
    for entry in entries {
        cx.collector.set_error(
            &entry.id,
            failure.map(|f| ProfileError {
                code: f.code,
                detail: f.text.clone(),
            }),
        );
    }
}

/// Starts a supervised connection for the profile (all of them without one). A
/// profile that is already connecting or connected is left alone, so the op is
/// idempotent. Returns once the supervisors are started; progress is in the status.
fn connect(cx: &OpCx, id: Option<&str>) -> OpResult {
    let entries = targets(cx, id)?;
    if entries.is_empty() {
        return Err(Failure::new(
            ErrorCode::NotConfigured,
            "OFTC profile unavailable; run oftc setup",
        ));
    }
    let _busy = cx.busy.acquire(profile_keys(&entries))?;
    show(cx, &entries, None);
    let access = cx.access();
    let mut first: Option<Failure> = None;
    for entry in &entries {
        if let Err(failure) = connect_one(cx, &access, entry) {
            show(cx, std::slice::from_ref(entry), Some(&failure));
            first.get_or_insert(failure);
        }
    }
    first.map_or_else(|| Ok(json!({})), Err)
}

fn connect_one(cx: &OpCx, access: &Access, entry: &ProfileEntry) -> Result<(), Failure> {
    if cx
        .services
        .ops
        .keychain
        .get(&entry.profile.gateway)
        .is_err()
    {
        return Err(Failure::new(
            ErrorCode::PskUnavailable,
            "OFTC PSK unavailable; run oftc setup",
        ));
    }
    let Some(vpn) = access.load_manager(entry)? else {
        return Err(Failure::new(
            ErrorCode::NotConfigured,
            "OFTC configuration absent; run oftc setup",
        ));
    };
    match access.vpn.status(&vpn) {
        VpnStatus::Disconnected => {}
        VpnStatus::Invalid => {
            return Err(Failure::new(
                ErrorCode::NotConfigured,
                "OFTC configuration is not valid; run oftc setup",
            ))
        }
        // Up or on its way: nothing to start.
        _ => return Ok(()),
    }
    // A supervisor that is still signing in has not touched the tunnel yet.
    let directory = registry::entry_directory(cx.root(), &entry.id);
    if lease::is_held(&directory.join(lease::LOCK_FILE)) {
        return Ok(());
    }
    cx.services
        .ops
        .spawner
        .spawn_supervisor(&entry.id)
        .map_err(|_| Failure::internal(&format!("Could not start supervisor for {}", entry.id)))
}

/// Stops the supervisor and tunnel of the profile (all without one). Stopping what is
/// already stopped succeeds.
fn disconnect(cx: &OpCx, id: Option<&str>) -> OpResult {
    let entries = targets(cx, id)?;
    let _busy = cx.busy.acquire(profile_keys(&entries))?;
    show(cx, &entries, None);
    let access = cx.access();
    let mut first: Option<Failure> = None;
    for entry in &entries {
        cx.collector.set_stopping(&entry.id);
        if let Err(failure) = vpn::stop_profile(&access, entry) {
            // Nothing is stopping: the row shows the failure, not a disconnect.
            cx.collector.clear_stopping(&entry.id);
            show(cx, std::slice::from_ref(entry), Some(&failure));
            first.get_or_insert(failure);
        }
    }
    first.map_or_else(|| Ok(json!({})), Err)
}

/// Stops the profile, waits for its tunnel to come down, then erases it, its VPN
/// entry and its PSK. A profile that is not there is already removed.
fn remove(cx: &OpCx, id: &str) -> OpResult {
    let entries = match targets(cx, Some(id)) {
        Ok(entries) => entries,
        Err(failure) if failure.code == ErrorCode::NotConfigured => return Ok(json!({})),
        Err(failure) => return Err(failure),
    };
    let _busy = cx.busy.acquire(profile_keys(&entries))?;
    let access = cx.access();
    let entry = &entries[0];
    cx.collector.set_stopping(&entry.id);
    vpn::stop_profile(&access, entry)?;
    let mut down = false;
    for _ in 0..REMOVE_POLLS {
        cx.checkpoint()?;
        down = match access.load_manager(entry)? {
            None => true,
            Some(vpn) => matches!(
                access.vpn.status(&vpn),
                VpnStatus::Disconnected | VpnStatus::Invalid
            ),
        };
        if down {
            break;
        }
        (cx.services.ops.pause)(POLL);
    }
    if !down {
        return Err(Failure::new(
            ErrorCode::TunnelsActive,
            &format!("{} did not disconnect; nothing was removed", entry.name()),
        ));
    }
    match vpn::erase_profiles(&access, &entries)? {
        Erased::Done | Erased::NothingToErase => Ok(json!({})),
    }
}

/// A path the client names must be absolute: the host's working directory means
/// nothing to the UI.
fn absolute(path: &str) -> Result<&Path, Failure> {
    let path = Path::new(path);
    if path.is_absolute() {
        Ok(path)
    } else {
        Err(Failure::new(ErrorCode::BadRequest, "path must be absolute"))
    }
}

/// Writes the `.oftc` bundle of the named profiles to `path`, mode 0600, never over
/// an existing file or through a symlink. The bundle holds PSKs; it goes to the file,
/// never into the reply.
fn export(cx: &OpCx, args: &ExportArgs) -> OpResult {
    let path = absolute(&args.path)?;
    let ids = args.profiles.clone().unwrap_or_default();
    let data = commands::export_bundle(cx.root(), cx.services.ops.keychain, &ids)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| {
            let code = if error.kind() == std::io::ErrorKind::AlreadyExists {
                ErrorCode::BadRequest
            } else {
                ErrorCode::Internal
            };
            Failure::new(code, "Could not create the export file")
        })?;
    if file.write_all(&data).and_then(|()| file.flush()).is_err() {
        let _ = std::fs::remove_file(path);
        return Err(Failure::internal("Could not write the export file"));
    }
    Ok(json!({}))
}

/// A `.oftc` file read for preview or import: at most [`bundle::MAX_BYTES`].
fn read_bundle(path: &str) -> Result<Vec<bundle::Incoming>, Failure> {
    let path = absolute(path)?;
    let mut data = zeroize::Zeroizing::new(Vec::new());
    std::fs::File::open(path)
        .and_then(|file| {
            file.take(bundle::MAX_BYTES as u64 + 1)
                .read_to_end(&mut data)
        })
        .map_err(|_| Failure::new(ErrorCode::InvalidFile, "Could not read the profile file"))?;
    commands::decode_bundle(&data)
}

fn wire_transport(transport: profile::Transport) -> Transport {
    match transport {
        profile::Transport::Udp => Transport::Udp,
        profile::Transport::Tcp => Transport::Tcp,
    }
}

fn configured(cx: &OpCx, gateway: &str) -> bool {
    registry::entries(cx.root())
        .iter()
        .any(|entry| entry.profile.gateway == gateway)
}

/// What a `.oftc` file holds, without its PSKs, and which of it is already set up.
fn import_preview(cx: &OpCx, path: &str) -> OpResult {
    let profiles = read_bundle(path)?
        .into_iter()
        .map(|item| PreviewItem {
            name: item.profile.display_name().to_owned(),
            already_configured: configured(cx, &item.profile.gateway),
            gateway: item.profile.gateway.clone(),
            saml_port: item.profile.saml_port,
            transport: wire_transport(item.profile.transport),
        })
        .collect();
    value(&PreviewResult { profiles })
}

/// Imports a `.oftc` file. Profiles for gateways that already have one are skipped;
/// `added` lists the ids this call created.
fn import(cx: &OpCx, path: &str) -> OpResult {
    let incoming = read_bundle(path)?;
    let keys = incoming
        .iter()
        .map(|item| format!("gateway:{}", item.profile.gateway))
        .collect();
    let _busy = cx.busy.acquire(keys)?;
    let report = commands::import_bundle(cx.root(), cx.services.ops.keychain, incoming);
    if let Some(failure) = report.failure {
        return Err(failure);
    }
    let added = report
        .done
        .into_iter()
        .filter_map(|done| match done {
            commands::Imported::Added { id, .. } => Some(id),
            commands::Imported::Skipped { .. } => None,
        })
        .collect();
    value(&ImportResult { added })
}

fn flag(setting: &SettingsArgs) -> Result<bool, Failure> {
    setting.value.as_bool().ok_or_else(|| {
        Failure::new(
            ErrorCode::BadRequest,
            &format!("{} takes true or false", setting.key),
        )
    })
}

/// `menu_login`, `auto_start:<id>` and `auto_update`.
fn settings_set(cx: &OpCx, setting: &SettingsArgs) -> OpResult {
    let on = flag(setting)?;
    let services = cx.services;
    match setting.key.as_str() {
        "menu_login" => {
            let item = LoginItem::MainApp;
            let done = if on {
                services.login.register(&item)
            } else {
                services.login.unregister(&item)
            };
            if done.is_err() {
                return Err(Failure::internal("Could not change the menu login item"));
            }
            if on && services.login.status(&item) == LoginStatus::RequiresApproval {
                return Err(Failure::new(
                    ErrorCode::ApprovalRequired,
                    "The menu login item needs approval in System Settings",
                ));
            }
        }
        "auto_update" => {
            let text = serde_json::to_vec(&json!({ "auto_update": on })).unwrap_or_default();
            lease::write_private(cx.root(), SETTINGS_FILE, &text)
                .map_err(|_| Failure::internal("Could not save the setting"))?;
        }
        key => {
            let Some(id) = key.strip_prefix("auto_start:") else {
                return Err(Failure::new(ErrorCode::BadRequest, "unknown setting"));
            };
            let entries = targets(cx, Some(id))?;
            let _busy = cx.busy.acquire(profile_keys(&entries))?;
            commands::change_autostart(
                services.login,
                services.ops.launchctl,
                cx.root(),
                &entries[0],
                on,
                (services.now)(),
            )?;
        }
    }
    Ok(json!({}))
}
