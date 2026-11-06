//! The set of configured VPNs. Every profile is a peer, with its own directory
//! `<root>/profiles/<id>/` (the profile, and later its supervisor and startup
//! state); only the SAML lock is shared.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::profile::{Profile, ProfileError, ProfileStore};

/// A configured VPN: its identifier and settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileEntry {
    pub id: String,
    pub profile: Profile,
}

impl ProfileEntry {
    pub fn name(&self) -> &str {
        self.profile.display_name()
    }
}

pub fn entry_directory(root: &Path, id: &str) -> PathBuf {
    root.join("profiles").join(id)
}

/// 1 to 32 characters of `a-z`, `0-9` and `-`, not starting or ending with `-`.
pub fn is_valid_id(id: &str) -> bool {
    (1..=32).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || b.is_ascii_lowercase() || b == b'-')
        && !id.starts_with('-')
        && !id.ends_with('-')
}

/// A stable identifier for a display name: lowercase ASCII letters and digits
/// joined by single hyphens, at most 32 characters, `vpn` when nothing is left.
pub fn slug(text: &str) -> String {
    let mut result = String::new();
    let mut pending_hyphen = false;
    for c in text.to_lowercase().chars() {
        if c.is_ascii_alphanumeric() {
            if pending_hyphen && !result.is_empty() {
                result.push('-');
            }
            pending_hyphen = false;
            result.push(c);
        } else {
            pending_hyphen = true;
        }
    }
    result.truncate(32); // ASCII only
    while result.ends_with('-') {
        result.pop();
    }
    if result.is_empty() {
        "vpn".to_owned()
    } else {
        result
    }
}

/// `base`, or `base-2`, `base-3`, ... the first not in `taken`. The base is cut so
/// the result still fits 32 characters.
pub fn unique_id(base: &str, taken: &HashSet<String>) -> String {
    if !taken.contains(base) {
        return base.to_owned();
    }
    (2u32..)
        .map(|number| {
            let suffix = format!("-{number}");
            let keep = 32 - suffix.len();
            format!("{}{suffix}", &base[..base.len().min(keep)])
        })
        .find(|candidate| !taken.contains(candidate))
        .expect("an unbounded counter yields a free id")
}

/// Every profile that loads, ordered by display name (case-insensitively), then id.
pub fn entries(root: &Path) -> Vec<ProfileEntry> {
    let Ok(listing) = fs::read_dir(root.join("profiles")) else {
        return Vec::new();
    };
    let mut found: Vec<ProfileEntry> = listing
        .filter_map(|item| item.ok()?.file_name().into_string().ok())
        .filter(|id| is_valid_id(id))
        .filter_map(|id| {
            let profile = ProfileStore::new(&entry_directory(root, &id)).load().ok()?;
            Some(ProfileEntry { id, profile })
        })
        .collect();
    found.sort_by_cached_key(|entry| (entry.name().to_lowercase(), entry.id.clone()));
    found
}

/// Creates a profile under `requested`, or under an identifier derived from its
/// name; never replaces an existing one.
pub fn add(
    root: &Path,
    profile: &Profile,
    requested: Option<&str>,
) -> Result<ProfileEntry, ProfileError> {
    let taken: HashSet<String> = entries(root).into_iter().map(|entry| entry.id).collect();
    let id = match requested {
        Some(id) => id.to_owned(),
        None => unique_id(&slug(profile.display_name()), &taken),
    };
    if !is_valid_id(&id) || taken.contains(&id) {
        return Err(ProfileError::Invalid);
    }
    ProfileStore::new(&entry_directory(root, &id)).save(profile)?;
    Ok(ProfileEntry {
        id,
        profile: profile.clone(),
    })
}

/// Moves the original single-profile layout (`<root>/profile.json`) into
/// `profiles/<id>/`. The VPN entry it used has no profile key, so the migrated
/// profile adopts it. Does nothing, and is safe to repeat, when there is no
/// legacy profile.
pub fn migrate_legacy(root: &Path, name_for_gateway: &dyn Fn(&str) -> Option<String>) {
    let legacy_store = ProfileStore::new(root);
    let Ok(legacy) = legacy_store.load() else {
        return;
    };
    if !entries(root)
        .iter()
        .any(|entry| entry.profile.gateway == legacy.gateway)
    {
        let name = name_for_gateway(&legacy.gateway).unwrap_or_else(|| legacy.gateway.clone());
        let Ok(migrated) = legacy.with_name(Some(&name), Some(true)) else {
            return;
        };
        let Ok(entry) = add(root, &migrated, None) else {
            return;
        };
        let preferences = root.join("connection-preferences.json");
        if preferences.exists() {
            let _ = fs::rename(
                &preferences,
                entry_directory(root, &entry.id).join("connection-preferences.json"),
            );
        }
    }
    let _ = legacy_store.remove();
}

pub const FORTICLIENT_VPN_PLIST: &str =
    "/Library/Application Support/Fortinet/FortiClient/conf/vpn.plist";

/// The FortiClient profile name whose `Server` is `gateway`, read from `plist`
/// through `plutil` (the same tool `oftc-migration` uses); used to name a profile
/// migrated from the original layout.
pub fn forticlient_name_for_gateway(plist: &Path, gateway: &str) -> Option<String> {
    let output = Command::new("/usr/bin/plutil")
        .args(["-convert", "json", "-o", "-"])
        .arg(plist)
        .output()
        .ok()?;
    if !output.status.success() || output.stdout.len() > 4_000_000 {
        return None;
    }
    name_in_profiles_json(&output.stdout, gateway)
}

/// One FortiClient profile a user could import: its name, gateway and SAML port.
/// The PSK is not part of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FortiClientSource {
    pub label: String,
    pub gateway: String,
    pub saml_port: u32,
}

/// The importable profiles of the FortiClient `plist`, read through `plutil`.
pub fn forticlient_sources(plist: &Path) -> Vec<FortiClientSource> {
    let Ok(output) = Command::new("/usr/bin/plutil")
        .args(["-convert", "json", "-o", "-"])
        .arg(plist)
        .output()
    else {
        return Vec::new();
    };
    if !output.status.success() || output.stdout.len() > 4_000_000 {
        return Vec::new();
    }
    sources_in_profiles_json(&output.stdout)
}

/// The profiles of a FortiClient `vpn.plist` converted to JSON that this app could
/// import, by name. A name or gateway the profile rules refuse is left out, so what
/// is listed can be added; a missing or unreadable port is FortiClient's default
/// 9443.
pub fn sources_in_profiles_json(json: &[u8]) -> Vec<FortiClientSource> {
    let Some(root) = serde_json::from_slice::<serde_json::Value>(json).ok() else {
        return Vec::new();
    };
    let Some(profiles) = root.get("Profiles").and_then(|p| p.as_object()) else {
        return Vec::new();
    };
    let mut found: Vec<FortiClientSource> = profiles
        .iter()
        .filter_map(|(name, value)| {
            let gateway = value.get("Server")?.as_str()?;
            let port = match value.get("IKESamlPort") {
                Some(serde_json::Value::Number(n)) => n.as_u64(),
                Some(serde_json::Value::String(s)) => s.trim().parse().ok(),
                _ => None,
            }
            .and_then(|p| u32::try_from(p).ok())
            .filter(|p| *p != 0)
            .unwrap_or(9443);
            // The profile rules decide what is importable: the name and gateway
            // checks are theirs.
            let usable = !name.is_empty()
                && name.len() <= 128
                && !name.contains('.')
                && crate::profile::Profile::new(
                    gateway,
                    port,
                    crate::profile::Transport::Udp,
                    Some(name),
                    None,
                )
                .is_ok();
            usable.then(|| FortiClientSource {
                label: name.clone(),
                gateway: gateway.to_owned(),
                saml_port: port,
            })
        })
        .collect();
    found.sort_by(|a, b| a.label.cmp(&b.label));
    found
}

fn name_in_profiles_json(json: &[u8], gateway: &str) -> Option<String> {
    let root: serde_json::Value = serde_json::from_slice(json).ok()?;
    let profiles = root.get("Profiles")?.as_object()?;
    let mut names: Vec<&String> = profiles.keys().collect();
    names.sort();
    names
        .into_iter()
        .find(|name| profiles[*name].get("Server").and_then(|s| s.as_str()) == Some(gateway))
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::testutil::{fixture, TempDir};
    use crate::profile::Transport;
    use serde_json::Value;

    fn copy_tree(from: &Path, to: &Path) {
        fs::create_dir_all(to).unwrap();
        for item in fs::read_dir(from).unwrap() {
            let item = item.unwrap();
            let target = to.join(item.file_name());
            if item.file_type().unwrap().is_dir() {
                copy_tree(&item.path(), &target);
            } else {
                fs::copy(item.path(), target).unwrap();
            }
        }
    }

    fn json(path: &Path) -> Value {
        serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
    }

    #[test]
    fn slug_and_id_table() {
        let slugs = [
            ("Example Office", "example-office"),
            ("  --Lab_01--  ", "lab-01"),
            ("", "vpn"),
            ("☃☃", "vpn"),
            ("İstanbul K", "i-stanbul-k"),
            ("Café Ünï", "caf-n"),
            (&"a".repeat(40), &"a".repeat(32)),
            (&format!("{} b", "a".repeat(31)), &"a".repeat(31)), // cut leaves a trailing hyphen
        ];
        for (text, expected) in slugs {
            assert_eq!(slug(text), expected, "{text:?}");
        }
        for id in ["a", "lab-01", &"a".repeat(32)] {
            assert!(is_valid_id(id), "{id}");
        }
        for id in ["", "-a", "a-", "A", "a_b", "é", &"a".repeat(33)] {
            assert!(!is_valid_id(id), "{id:?}");
        }
        // The numbered fallback still fits 32 characters.
        let taken: HashSet<String> = ["lab", "lab-2"].iter().map(|s| s.to_string()).collect();
        assert_eq!(unique_id("lab", &taken), "lab-3");
        assert_eq!(unique_id("new", &taken), "new");
        let long = "a".repeat(32);
        let taken: HashSet<String> = [long.clone()].into();
        let id = unique_id(&long, &taken);
        assert_eq!(id, format!("{}-2", "a".repeat(30)));
        assert!(is_valid_id(&id));
    }

    /// A registry written by the Swift host reads back, ordered by name.
    #[test]
    fn reads_a_registry_swift_wrote() {
        let found = entries(&fixture("swift/peers"));
        let summary: Vec<_> = found
            .iter()
            .map(|e| {
                (
                    e.id.as_str(),
                    e.name(),
                    e.profile.saml_port,
                    e.profile.transport,
                )
            })
            .collect();
        assert_eq!(
            summary,
            [
                ("example-office", "Example Office", 9443, Transport::Udp),
                ("lab", "Lab", 8443, Transport::Tcp)
            ]
        );
    }

    #[test]
    fn add_never_replaces_and_gives_peers_distinct_ids() {
        let dir = TempDir::new("registry-add");
        let make = |gateway: &str, name: &str| {
            Profile::new(gateway, 9443, Transport::Udp, Some(name), None).unwrap()
        };
        let first = add(&dir.0, &make("a.example.com", "Same Name"), None).unwrap();
        let second = add(&dir.0, &make("b.example.com", "same name"), None).unwrap();
        assert_eq!(
            (first.id.as_str(), second.id.as_str()),
            ("same-name", "same-name-2")
        );
        // An explicit id is used as given, but only once, and only if valid.
        let c = make("c.example.com", "C");
        assert_eq!(add(&dir.0, &c, Some("chosen")).unwrap().id, "chosen");
        assert_eq!(add(&dir.0, &c, Some("chosen")), Err(ProfileError::Invalid));
        assert_eq!(
            add(&dir.0, &c, Some("Not Valid")),
            Err(ProfileError::Invalid)
        );
        let order: Vec<_> = entries(&dir.0).into_iter().map(|e| e.id).collect();
        assert_eq!(order, ["chosen", "same-name", "same-name-2"]);
        // A directory with an unreadable profile is skipped, not fatal.
        fs::create_dir_all(entry_directory(&dir.0, "broken")).unwrap();
        fs::write(entry_directory(&dir.0, "broken").join("profile.json"), "{").unwrap();
        assert_eq!(entries(&dir.0).len(), 3);
    }

    /// Format 2: the tree the Swift host migrated, produced by `migrateLegacy` itself.
    #[test]
    fn migrate_legacy_matches_the_swift_result() {
        let dir = TempDir::new("registry-legacy");
        copy_tree(&fixture("swift/legacy-root"), &dir.0);
        migrate_legacy(&dir.0, &|gateway| {
            assert_eq!(gateway, "vpn.example.com");
            Some("Example Office".to_owned())
        });
        let expected = fixture("swift/legacy-migrated/profiles/example-office");
        let actual = entry_directory(&dir.0, "example-office");
        for file in ["profile.json", "connection-preferences.json"] {
            assert_eq!(
                json(&actual.join(file)),
                json(&expected.join(file)),
                "{file}"
            );
        }
        assert!(!dir.0.join("profile.json").exists());
        assert!(!dir.0.join("connection-preferences.json").exists());
        // Idempotent: a second run, and a run on an already-migrated root, change nothing.
        migrate_legacy(&dir.0, &|_| panic!("no legacy profile is left"));
        assert_eq!(entries(&dir.0).len(), 1);
    }

    /// Format 1 and 2 the other way: what this crate writes. The committed tree is
    /// decoded by the Swift readers in `build.sh` (`check-host-compat.swift`), so the
    /// files here must stay equal to what the Rust writer produces.
    #[test]
    fn writes_the_tree_the_swift_readers_check() {
        let dir = TempDir::new("registry-golden");
        copy_tree(&fixture("swift/legacy-root"), &dir.0);
        migrate_legacy(&dir.0, &|_| Some("Example Office".to_owned()));
        let lab = Profile::new("lab.example.com", 8443, Transport::Tcp, Some("Lab"), None).unwrap();
        let hq = Profile::new(
            "vpn2.example.com",
            9443,
            Transport::Udp,
            Some("Office \"HQ\" / Zürich — ☃"),
            None,
        )
        .unwrap();
        add(&dir.0, &lab, None).unwrap();
        add(&dir.0, &hq, None).unwrap();
        let golden = fixture("rust/profiles");
        let mut ids: Vec<_> = fs::read_dir(&golden)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        ids.sort();
        assert_eq!(ids, ["example-office", "lab", "office-hq-z-rich"]);
        let written: Vec<_> = entries(&dir.0).into_iter().map(|e| e.id).collect();
        assert_eq!(written, ["example-office", "lab", "office-hq-z-rich"]);
        for id in ids {
            for file in ["profile.json", "connection-preferences.json"] {
                let expected = golden.join(&id).join(file);
                let actual = dir.0.join("profiles").join(&id).join(file);
                assert_eq!(actual.exists(), expected.exists(), "{id:?}/{file}");
                if expected.exists() {
                    assert_eq!(json(&actual), json(&expected), "{id:?}/{file}");
                }
            }
        }
    }

    #[test]
    fn migrate_legacy_without_a_name_or_over_an_existing_profile() {
        let dir = TempDir::new("registry-legacy-2");
        copy_tree(&fixture("swift/legacy-root"), &dir.0);
        migrate_legacy(&dir.0, &|_| None);
        // No FortiClient name: the gateway names it.
        assert_eq!(entries(&dir.0)[0].name(), "vpn.example.com");
        // A legacy file whose gateway already has a profile is dropped, not duplicated.
        copy_tree(&fixture("swift/legacy-root"), &dir.0);
        migrate_legacy(&dir.0, &|_| panic!("already migrated"));
        assert_eq!(entries(&dir.0).len(), 1);
        assert!(!dir.0.join("profile.json").exists());
    }

    #[test]
    fn forticlient_name_lookup() {
        let plist = br#"{"Profiles":{"Zeta":{"Server":"vpn.example.com"},
            "Alpha":{"Server":"vpn.example.com"},"Other":{"Server":"other.example.com"}}}"#;
        // Several matches: the first by name.
        assert_eq!(
            name_in_profiles_json(plist, "vpn.example.com").as_deref(),
            Some("Alpha")
        );
        assert_eq!(name_in_profiles_json(plist, "none.example.com"), None);
        assert_eq!(name_in_profiles_json(b"[]", "vpn.example.com"), None);
        assert_eq!(
            forticlient_name_for_gateway(Path::new("/nonexistent/vpn.plist"), "vpn.example.com"),
            None
        );
    }

    /// What FortiClient's converted `vpn.plist` offers for import: by name, port from a
    /// number or a string, 9443 when absent, and nothing the profile rules refuse.
    #[test]
    fn forticlient_sources_table() {
        let json = br#"{"Profiles":{
            "Zed":{"Server":"vpn.example.com","IKESamlPort":"4443"},
            "Alpha":{"Server":"gw.example.com","IKESamlPort":8443},
            "NoPort":{"Server":"203.0.113.7"},
            "Dotted.Name":{"Server":"vpn.example.com"},
            "BadHost":{"Server":"bad host"},
            "NoServer":{"Other":1}}}"#;
        let found: Vec<(String, String, u32)> = sources_in_profiles_json(json)
            .into_iter()
            .map(|s| (s.label, s.gateway, s.saml_port))
            .collect();
        assert_eq!(
            found,
            [
                ("Alpha".to_owned(), "gw.example.com".to_owned(), 8443),
                ("NoPort".to_owned(), "203.0.113.7".to_owned(), 9443),
                ("Zed".to_owned(), "vpn.example.com".to_owned(), 4443),
            ]
        );
        assert!(sources_in_profiles_json(b"[]").is_empty());
    }
}
