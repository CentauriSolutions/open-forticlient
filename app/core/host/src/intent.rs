//! The connect-at-login preference, read side.
//!
//! `profiles/<id>/connection-preferences.json` holds `{"connectAtLogin":true}`.
//! Only the reader lives here for now (the verbs that write it, and the one-use
//! start request, move with the supervisor).

use std::fs;
use std::path::Path;

use serde::Deserialize;

/// The Swift reader refused files over this size.
const MAX_BYTES: u64 = 4096;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Preferences {
    connect_at_login: bool,
}

/// Whether the profile whose files are in `directory` connects at login.
///
/// The stored value wins. With no file at all, a profile that adopted the
/// original single-profile layout inherits an already registered agent
/// (`legacy_enabled`); every other profile starts off. A file that exists but
/// cannot be read or decoded counts as off, never as the legacy default.
pub fn connect_at_login(directory: &Path, legacy_enabled: bool) -> bool {
    let path = directory.join("connection-preferences.json");
    let stored = fs::read(&path)
        .ok()
        .filter(|data| data.len() as u64 <= MAX_BYTES)
        .and_then(|data| serde_json::from_slice::<Preferences>(&data).ok());
    match stored {
        Some(preferences) => preferences.connect_at_login,
        None => !path.exists() && legacy_enabled,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::testutil::TempDir;

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
}
