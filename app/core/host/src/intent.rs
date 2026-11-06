//! Whether a profile connects when the login agent starts.
//!
//! `profiles/<id>/connection-preferences.json` holds the standing choice,
//! `{"connectAtLogin":true}`. `agent-request.json` is a one-use request,
//! `{"created":<2001-based seconds>,"connect":true}`, that `set-autostart on` leaves
//! so registering the agent does not itself open a browser. Registration alone is
//! never permission to open a sign-in.

use std::fs;
use std::io;
use std::path::Path;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use crate::lease::{make_private_dir, write_private};
use crate::status::{decode_date, encode_date};

/// The Swift reader refused files over this size.
const MAX_BYTES: u64 = 4096;

const PREFERENCES: &str = "connection-preferences.json";
const REQUEST: &str = "agent-request.json";
/// A request older than this (or from the future) is ignored.
const REQUEST_LIFETIME: Duration = Duration::from_secs(60);

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Preferences {
    connect_at_login: bool,
}

#[derive(Serialize, Deserialize)]
struct Request {
    connect: bool,
    created: f64,
}

fn read_small(path: &Path) -> Option<Vec<u8>> {
    fs::read(path)
        .ok()
        .filter(|data| data.len() as u64 <= MAX_BYTES)
}

/// Whether the profile whose files are in `directory` connects at login.
///
/// The stored value wins. With no file at all, a profile that adopted the
/// original single-profile layout inherits an already registered agent
/// (`legacy_enabled`); every other profile starts off. A file that exists but
/// cannot be read or decoded counts as off, never as the legacy default.
pub fn connect_at_login(directory: &Path, legacy_enabled: bool) -> bool {
    let path = directory.join(PREFERENCES);
    let stored =
        read_small(&path).and_then(|data| serde_json::from_slice::<Preferences>(&data).ok());
    match stored {
        Some(preferences) => preferences.connect_at_login,
        None => !path.exists() && legacy_enabled,
    }
}

fn write(directory: &Path, name: &str, value: &impl Serialize) -> io::Result<()> {
    make_private_dir(directory)?;
    write_private(directory, name, &serde_json::to_vec(value)?)
}

/// Stores the standing choice.
pub fn set_connect_at_login(directory: &Path, enabled: bool) -> io::Result<()> {
    write(
        directory,
        PREFERENCES,
        &Preferences {
            connect_at_login: enabled,
        },
    )
}

/// Leaves a one-use request for the next agent start: `connect: false` means
/// "registered, but do not sign in now".
pub fn request(directory: &Path, connect: bool, now: SystemTime) -> io::Result<()> {
    write(
        directory,
        REQUEST,
        &Request {
            connect,
            created: encode_date(now),
        },
    )
}

pub fn cancel_request(directory: &Path) {
    let _ = fs::remove_file(directory.join(REQUEST));
}

/// Whether the login agent should start a supervisor for this profile now. A fresh
/// request (consumed, whatever it says) decides; otherwise the standing choice
/// does. A request that cannot be decoded is left in place and ignored; one that is
/// stale, or dated after `now`, is consumed and ignored.
pub fn should_start(directory: &Path, now: SystemTime, legacy_enabled: bool) -> bool {
    let decoded = read_small(&directory.join(REQUEST))
        .and_then(|data| serde_json::from_slice::<Request>(&data).ok());
    if let Some(request) = decoded {
        cancel_request(directory);
        let fresh = now
            .duration_since(decode_date(request.created))
            .is_ok_and(|age| age < REQUEST_LIFETIME);
        if fresh {
            return request.connect;
        }
    }
    connect_at_login(directory, legacy_enabled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::testutil::{fixture, TempDir};

    #[test]
    fn stored_value_wins_and_only_a_missing_file_inherits_the_legacy_agent() {
        let oversize = format!(
            "{{\"connectAtLogin\":true,\"pad\":\"{}\"}}",
            "x".repeat(5000)
        );
        let rows: [(Option<&str>, bool, bool); 8] = [
            (Some(r#"{"connectAtLogin":true}"#), false, true),
            (Some(r#"{"connectAtLogin":false}"#), true, false),
            (None, true, true),
            (None, false, false),
            (Some("not json"), true, false),
            (Some(r#"{"other":1}"#), true, false),
            (Some(&oversize), true, false),
            (Some(r#"{"connectAtLogin":true,"extra":1}"#), false, true),
        ];
        for (file, legacy, want) in rows {
            let dir = TempDir::new("intent");
            if let Some(text) = file {
                fs::write(dir.0.join("connection-preferences.json"), text).unwrap();
            }
            assert_eq!(connect_at_login(&dir.0, legacy), want, "{file:?} {legacy}");
        }
    }

    fn at(unix_secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(unix_secs)
    }

    /// The Swift writers' files, decoded: the standing choice and the one-use request.
    #[test]
    fn decodes_what_swift_wrote() {
        let dir = TempDir::new("intent-swift");
        for name in [PREFERENCES, REQUEST] {
            fs::copy(
                fixture(&format!("swift/supervisor/{name}")),
                dir.0.join(name),
            )
            .unwrap();
        }
        assert!(!connect_at_login(&dir.0, true)); // stored `false` beats the legacy agent
                                                  // `created` is 815509075.5 on the 2001 clock; the request is fresh for a minute.
        let created = decode_date(815509075.5);
        let stale = created + Duration::from_secs(61);
        assert!(!should_start(&dir.0, stale, false)); // consumed, but too old
        assert!(!dir.0.join(REQUEST).exists());
        fs::copy(
            fixture("swift/supervisor/agent-request.json"),
            dir.0.join(REQUEST),
        )
        .unwrap();
        assert!(should_start(
            &dir.0,
            created + Duration::from_secs(59),
            false
        ));
        assert!(!dir.0.join(REQUEST).exists());
    }

    /// `check-menu.swift`'s startup-intent rows, plus the file shapes written.
    #[test]
    fn startup_decision_and_files_written() {
        let dir = TempDir::new("intent-start");
        let d = dir.0.join("profile");
        let now = at(1_000_000_000);
        let later = |s: u64| at(1_000_000_000 + s);
        // No preferences: only an upgraded agent starts; a new profile stays off.
        assert!(should_start(&d, now, true));
        assert!(!should_start(&d, now, false));
        set_connect_at_login(&d, false).unwrap();
        assert!(!should_start(&d, now, true));
        // A fresh request is honoured once.
        request(&d, true, now).unwrap();
        assert!(should_start(&d, now, false));
        assert!(!should_start(&d, now, false));
        // Too old, or dated after `now`: consumed and ignored.
        request(&d, true, now).unwrap();
        assert!(!should_start(&d, later(61), false));
        request(&d, true, later(1)).unwrap();
        assert!(!should_start(&d, now, false));
        assert!(!d.join(REQUEST).exists());
        // Dates no clock could hold are ignored, not a crash: the choice decides.
        for created in ["1e300", "-1e300", "1e19", "-1e19"] {
            fs::write(
                d.join(REQUEST),
                format!(r#"{{"connect":true,"created":{created}}}"#),
            )
            .unwrap();
            assert!(!should_start(&d, now, false), "{created}");
            assert!(!d.join(REQUEST).exists(), "{created}");
        }
        // `connect: false` is "registered, idle": it suppresses the standing choice once.
        set_connect_at_login(&d, true).unwrap();
        request(&d, false, now).unwrap();
        assert!(!should_start(&d, now, false));
        assert!(should_start(&d, later(1), false));
        // A cancelled request is gone; an undecodable one is left in place.
        request(&d, true, now).unwrap();
        cancel_request(&d);
        set_connect_at_login(&d, false).unwrap();
        assert!(!should_start(&d, now, false));
        fs::write(d.join(REQUEST), "invalid").unwrap();
        assert!(!should_start(&d, now, true));
        assert!(d.join(REQUEST).exists());
        // Malformed preferences fail closed, whatever the legacy agent says.
        fs::write(d.join(PREFERENCES), "invalid").unwrap();
        assert!(!should_start(&d, now, true));

        // What was written: private files, the keys Swift decodes, a 2001-based date.
        use std::os::unix::fs::PermissionsExt;
        set_connect_at_login(&d, true).unwrap();
        request(&d, true, at(978_307_200 + 7)).unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            (mode(&d), mode(&d.join(PREFERENCES)), mode(&d.join(REQUEST))),
            (0o700, 0o600, 0o600)
        );
        let prefs: serde_json::Value =
            serde_json::from_slice(&fs::read(d.join(PREFERENCES)).unwrap()).unwrap();
        assert_eq!(prefs, serde_json::json!({"connectAtLogin": true}));
        let req: serde_json::Value =
            serde_json::from_slice(&fs::read(d.join(REQUEST)).unwrap()).unwrap();
        assert_eq!(req, serde_json::json!({"connect": true, "created": 7.0}));
    }

    /// The Swift `AgentIntent` that once decoded this file is gone; the bytes stay pinned.
    #[test]
    fn writes_the_preferences_the_swift_reader_checks() {
        let dir = TempDir::new("intent-golden");
        set_connect_at_login(&dir.0, true).unwrap();
        assert_eq!(
            fs::read(dir.0.join(PREFERENCES)).unwrap(),
            fs::read(fixture(&format!("rust/supervisor/{PREFERENCES}"))).unwrap()
        );
    }
}
