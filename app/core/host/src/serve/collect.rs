//! Builds the status document from the host's files, the VPN entries, login items and
//! the cached component check, and publishes it to the hub when it changed.

use std::collections::HashMap;
use std::sync::mpsc::Sender;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use oftc_apple::login::{LoginItem, LoginStatus};
use oftc_apple::manager::{Subscription, VpnEntry, VpnStatus};
use oftc_ui_edge::{
    rfc3339, Component, ConnectionState, Login, LoginState, NeStatus, Phase, ProfileInfo,
    ProfileError, ProfileStatus, ProfilesResult, StatusDocument, Transport, PROTOCOL,
};

use super::hub::Hub;
use super::state::resolve_connection;
use super::Services;
use crate::agent::{agent_item, HOST_PLIST};
use crate::profile;
use crate::reason;
use crate::snapshot::{self, ProfileFacts};
use crate::status;
use crate::vpn::owns_key;

/// VPN entries are reloaded at least this often, and whenever the profile set changes.
const ENTRY_TTL: Duration = Duration::from_secs(15);
/// A stopping flag that the tunnel never confirms is dropped after this long.
const STOPPING_MAX: Duration = Duration::from_secs(30);
/// Login item states are read at most this often.
const LOGIN_TTL: Duration = Duration::from_secs(10);

pub struct Collector<'a> {
    services: &'a Services<'a>,
    hub: &'a Hub,
    /// Handed to the NetworkExtension status observers; wakes the refresher.
    wake: Sender<()>,
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    entries: Vec<VpnEntry>,
    /// Observers on `entries`; dropping them detaches.
    subscriptions: Vec<Subscription>,
    loaded: Option<Instant>,
    ids: Vec<(String, bool)>,
    login: Option<(Instant, Login)>,
    /// When this host first saw each profile connected.
    since: HashMap<String, String>,
    /// Profiles a `disconnect` or `remove` is stopping, and since when. The flag ends
    /// when the tunnel is down, or after [`STOPPING_MAX`] whatever it shows.
    stopping: HashMap<String, Instant>,
    /// The last op failure of each profile; the next op on it clears it.
    errors: HashMap<String, ProfileError>,
}

fn login_state(status: LoginStatus) -> LoginState {
    match status {
        LoginStatus::Enabled => LoginState::Enabled,
        LoginStatus::NotRegistered => LoginState::Disabled,
        LoginStatus::RequiresApproval => LoginState::RequiresApproval,
        LoginStatus::NotFound | LoginStatus::Unknown => LoginState::NotFound,
    }
}

fn phase(phase: status::Phase) -> Phase {
    match phase {
        status::Phase::Acquiring => Phase::Acquiring,
        status::Phase::Connecting => Phase::Connecting,
        status::Phase::Connected => Phase::Connected,
        status::Phase::Recovering => Phase::Recovering,
        status::Phase::Failed => Phase::Failed,
        status::Phase::Stopped => Phase::Stopped,
    }
}

fn transport(transport: profile::Transport) -> Transport {
    match transport {
        profile::Transport::Udp => Transport::Udp,
        profile::Transport::Tcp => Transport::Tcp,
    }
}

fn ne_status(status: VpnStatus) -> NeStatus {
    match status {
        VpnStatus::Invalid => NeStatus::Invalid,
        VpnStatus::Disconnected => NeStatus::Disconnected,
        VpnStatus::Connecting => NeStatus::Connecting,
        VpnStatus::Connected => NeStatus::Connected,
        VpnStatus::Reasserting => NeStatus::Reasserting,
        VpnStatus::Disconnecting => NeStatus::Disconnecting,
    }
}

impl<'a> Collector<'a> {
    pub fn new(services: &'a Services<'a>, hub: &'a Hub, wake: Sender<()>) -> Collector<'a> {
        Collector {
            services,
            hub,
            wake,
            inner: Mutex::new(Inner::default()),
        }
    }

    /// Marks `id` as being stopped, so its row shows `disconnecting` until the tunnel
    /// is down.
    pub fn set_stopping(&self, id: &str) {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        inner.stopping.insert(id.to_owned(), Instant::now());
        drop(inner);
        let _ = self.wake.send(());
    }

    /// Takes the stopping mark off `id` again, for a stop that did not happen.
    pub fn clear_stopping(&self, id: &str) {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        inner.stopping.remove(id);
    }

    /// Records (or, with `None`, clears) the last failure shown on `id`'s row.
    pub fn set_error(&self, id: &str, error: Option<ProfileError>) {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let changed = match error {
            Some(error) => inner.errors.insert(id.to_owned(), error.clone()) != Some(error),
            None => inner.errors.remove(id).is_some(),
        };
        drop(inner);
        if changed {
            let _ = self.wake.send(());
        }
    }

    /// The profile list, settings only (the `profiles` op).
    pub fn profiles(&self) -> ProfilesResult {
        let agent = self.services.login.status(&agent_item()) == LoginStatus::Enabled;
        let now = (self.services.now)();
        ProfilesResult {
            profiles: snapshot::facts(self.services.env.root(), &|| agent, now)
                .into_iter()
                .map(|p| ProfileInfo {
                    id: p.id,
                    name: p.name,
                    gateway: p.gateway,
                    saml_port: p.saml_port,
                    transport: transport(p.transport),
                    auto_start: p.connect_at_login,
                })
                .collect(),
        }
    }

    fn login(&self, inner: &mut Inner) -> Login {
        if let Some((at, login)) = &inner.login {
            if at.elapsed() < LOGIN_TTL {
                return *login;
            }
        }
        let read = |item: &LoginItem| login_state(self.services.login.status(item));
        let login = Login {
            menu_item: read(&LoginItem::MainApp),
            agent: read(&agent_item()),
            host_agent: read(&LoginItem::Agent(HOST_PLIST.to_owned())),
        };
        inner.login = Some((Instant::now(), login));
        login
    }

    /// Re-reads everything and publishes the document if it changed. Returns whether
    /// it did.
    pub fn refresh(&self) -> bool {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let inner = &mut *inner;
        let services = self.services;
        let now = (services.now)();
        let login = self.login(inner);
        let agent_enabled = login.agent == LoginState::Enabled;
        let facts = snapshot::facts(services.env.root(), &|| agent_enabled, now);
        let ids: Vec<(String, bool)> = facts
            .iter()
            .map(|p| (p.id.clone(), p.adopts_unkeyed_vpn_entry))
            .collect();
        if inner.loaded.is_none_or(|at| at.elapsed() > ENTRY_TTL) || inner.ids != ids {
            self.reload(inner);
            inner.ids = ids;
        }
        let provider = services.env.provider_id();
        let unix = now
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64);
        let mut tunnels = Vec::new();
        let mut profiles = Vec::new();
        for facts in &facts {
            let vpn = inner
                .entries
                .iter()
                .find(|v| owns_key(&provider, &facts.id, facts.adopts_unkeyed_vpn_entry, v));
            let ne = vpn.map(|v| services.vpn.status(v));
            if let Some(v) = vpn {
                tunnels.push((facts.id.clone(), v.clone()));
            }
            if ne == Some(VpnStatus::Connected) {
                inner
                    .since
                    .entry(facts.id.clone())
                    .or_insert_with(|| rfc3339(unix));
            } else {
                inner.since.remove(&facts.id);
            }
            let down = matches!(
                ne,
                None | Some(VpnStatus::Disconnected) | Some(VpnStatus::Invalid)
            );
            if down || inner.stopping.get(&facts.id).is_some_and(|at| at.elapsed() > STOPPING_MAX)
            {
                inner.stopping.remove(&facts.id);
            }
            let mut row = self.profile(
                facts,
                vpn,
                ne,
                inner.since.get(&facts.id),
                inner.stopping.contains_key(&facts.id),
            );
            // A failed op is the newer news; else the supervisor's recorded reason.
            if let Some(op_error) = inner.errors.get(&facts.id) {
                row.error = Some(op_error.clone());
            }
            profiles.push(row);
        }
        inner
            .since
            .retain(|id, _| facts.iter().any(|p| &p.id == id));
        inner.stopping.retain(|id, _| facts.iter().any(|p| &p.id == id));
        inner.errors.retain(|id, _| facts.iter().any(|p| &p.id == id));
        self.hub.set_entries(tunnels);
        let (state, installed) = self.hub.component();
        let expected = &services.host.build;
        self.hub.publish(StatusDocument {
            schema: PROTOCOL,
            generated: rfc3339(unix),
            seq: 0,
            host: services.host.clone(),
            component: Component {
                state,
                installed_build: installed,
                expected_build: (!expected.is_empty()).then(|| expected.clone()),
            },
            login,
            profiles,
        })
    }

    fn profile(
        &self,
        facts: &ProfileFacts,
        vpn: Option<&VpnEntry>,
        ne: Option<VpnStatus>,
        since: Option<&String>,
        stopping: bool,
    ) -> ProfileStatus {
        let phase = facts.phase.map(phase);
        let state: ConnectionState =
            resolve_connection(ne, vpn.is_some_and(|v| v.enabled), phase, stopping);
        ProfileStatus {
            id: facts.id.clone(),
            name: facts.name.clone(),
            gateway: facts.gateway.clone(),
            saml_port: facts.saml_port,
            transport: transport(facts.transport),
            auto_start: facts.connect_at_login,
            state,
            ne_status: ne.map(ne_status),
            phase,
            connected_since: since.cloned(),
            traffic: None,
            error: (phase == Some(Phase::Failed))
                .then(|| facts.failure.and_then(|f| reason::explain(f, facts.transport)))
                .flatten()
                .map(|(code, detail)| ProfileError { code, detail: detail.to_owned() }),
        }
    }

    /// Loads the VPN entries afresh and observes each; a failed load keeps the old set.
    fn reload(&self, inner: &mut Inner) {
        inner.loaded = Some(Instant::now());
        if let Ok(entries) = self.services.vpn.load_all() {
            inner.subscriptions = entries
                .iter()
                .filter_map(|e| self.services.vpn.observe_status(e, self.wake.clone()).ok())
                .collect();
            inner.entries = entries;
        }
    }
}
