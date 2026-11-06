//! What the host reads of its own files for each profile: its settings, what its
//! supervisor is doing and whether it connects at login. The status socket serves this
//! (`serve::collect`); the UI reads none of these files itself.
//!
//! `phase` is `None` when no supervisor stands behind a status record. The original
//! single-profile layout is migrated by `commands::run` before anything reads it.

use std::path::Path;
use std::time::SystemTime;

use crate::intent;
use crate::profile::Transport;
use crate::registry;
use crate::status::{Phase, StatusStore};

/// One profile as the host reads it from its files.
pub struct ProfileFacts {
    pub id: String,
    pub name: String,
    pub gateway: String,
    pub saml_port: u32,
    pub transport: Transport,
    pub adopts_unkeyed_vpn_entry: bool,
    pub phase: Option<Phase>,
    pub connect_at_login: bool,
}

/// Every profile with what its supervisor is doing and whether it connects at
/// login. `agent_enabled` is asked at most once per call, and only if a profile
/// adopted the original layout (the one kind that inherits it). The original layout
/// is not migrated here.
pub fn facts(root: &Path, agent_enabled: &dyn Fn() -> bool, now: SystemTime) -> Vec<ProfileFacts> {
    let mut agent: Option<bool> = None;
    registry::entries(root)
        .into_iter()
        .map(|entry| {
            let directory = registry::entry_directory(root, &entry.id);
            let adopted = entry.profile.adopts_unkeyed_vpn_entry == Some(true);
            let legacy = adopted && *agent.get_or_insert_with(agent_enabled);
            ProfileFacts {
                name: entry.name().to_owned(),
                gateway: entry.profile.gateway.clone(),
                saml_port: entry.profile.saml_port,
                transport: entry.profile.transport,
                adopts_unkeyed_vpn_entry: adopted,
                phase: StatusStore::new(&directory).read(now).map(|s| s.phase),
                connect_at_login: intent::connect_at_login(&directory, legacy),
                id: entry.id,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lease::SupervisorLease;
    use crate::profile::testutil::{fixture, TempDir};
    use crate::profile::{Profile, Transport};
    use std::cell::Cell;
    use std::fs;

    #[test]
    fn lists_profiles_with_phase_and_login_choice() {
        let dir = TempDir::new("snapshot");
        let root = &dir.0;
        // A legacy layout (adopted, stored choice on), migrated first as `run` does.
        for file in ["profile.json", "connection-preferences.json"] {
            fs::create_dir_all(root).unwrap();
            fs::copy(fixture("swift/legacy-root").join(file), root.join(file)).unwrap();
        }
        let lab = Profile::new("lab.example.com", 8443, Transport::Tcp, Some("Lab"), None).unwrap();
        let lab = registry::add(root, &lab, None).unwrap();
        // The lab supervisor is live, so its phase is believed.
        let lease = SupervisorLease::acquire(&registry::entry_directory(root, &lab.id)).unwrap();
        let now = SystemTime::now();
        StatusStore::new(&registry::entry_directory(root, &lab.id)).publish(
            Phase::Connected,
            lease.id(),
            now,
        );

        let asked = Cell::new(0);
        let office =
            |gateway: &str| (gateway == "vpn.example.com").then(|| "Example Office".to_owned());
        let agent = || {
            asked.set(asked.get() + 1);
            true
        };
        registry::migrate_legacy(root, &office);
        let rows = |facts: Vec<ProfileFacts>| -> Vec<(String, String, bool, Option<Phase>, bool)> {
            facts
                .into_iter()
                .map(|f| {
                    (f.id, f.name, f.adopts_unkeyed_vpn_entry, f.phase, f.connect_at_login)
                })
                .collect()
        };
        assert_eq!(
            rows(facts(root, &agent, now)),
            [
                ("example-office".into(), "Example Office".into(), true, None, true),
                ("lab".into(), "Lab".into(), false, Some(Phase::Connected), false),
            ]
        );
        // The agent is asked once however many profiles adopted the original layout.
        assert_eq!(asked.get(), 1);
        let office_dir = registry::entry_directory(root, "example-office");
        fs::remove_file(office_dir.join("connection-preferences.json")).unwrap();
        let again = facts(root, &agent, now);
        assert_eq!(asked.get(), 2);
        assert_eq!((again[0].phase, again[0].connect_at_login), (None, true));
        // With no profiles there is nothing to list, and the agent is never asked.
        let empty = TempDir::new("snapshot-empty");
        assert!(facts(&empty.0, &|| panic!("no profile adopted the layout"), now).is_empty());
    }
}
