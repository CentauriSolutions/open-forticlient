//! The connection profile: `profile.json`, as the Swift `OFTCProfile` wrote it.
//!
//! Only nonsecret settings live here; the PSK stays in the Keychain, addressed by
//! the gateway name. The file is read by the Swift UI and by older builds, so its
//! shape follows the Swift encoder: `version` is 1, absent optional fields are
//! omitted, and unknown keys are ignored on read.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

const FILE_NAME: &str = "profile.json";
const MAX_BYTES: u64 = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Udp,
    Tcp,
}

impl Transport {
    pub fn as_str(self) -> &'static str {
        match self {
            Transport::Udp => "udp",
            Transport::Tcp => "tcp",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileError {
    /// The settings or the file's contents are not acceptable.
    Invalid,
    /// The file or directory cannot be used (missing, a symlink, unwritable).
    Unavailable,
}

/// Scalars `CharacterSet.controlCharacters` contains: general categories Cc and Cf.
/// Generated from Foundation on macOS 27 by enumerating every scalar; `char::is_control`
/// would miss the Cf ones (U+200B, U+00AD, ...) that Swift refuses in a name.
const CONTROL_RANGES: &[(u32, u32)] = &[
    (0x0, 0x1F),
    (0x7F, 0x9F),
    (0xAD, 0xAD),
    (0x600, 0x605),
    (0x61C, 0x61C),
    (0x6DD, 0x6DD),
    (0x70F, 0x70F),
    (0x890, 0x891),
    (0x8E2, 0x8E2),
    (0x180E, 0x180E),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x2064),
    (0x2066, 0x206F),
    (0xFEFF, 0xFEFF),
    (0xFFF9, 0xFFFB),
    (0x110BD, 0x110BD),
    (0x110CD, 0x110CD),
    (0x13430, 0x1343F),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0001, 0xE0001),
    (0xE0020, 0xE007F),
];

fn is_control(c: char) -> bool {
    let c = c as u32;
    CONTROL_RANGES
        .iter()
        .any(|&(lo, hi)| (lo..=hi).contains(&c))
}

/// One VPN's settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    pub gateway: String,
    pub saml_port: u32,
    pub transport: Transport,
    pub name: Option<String>,
    /// True for the profile that inherited the original unkeyed VPN entry.
    pub adopts_unkeyed_vpn_entry: Option<bool>,
}

/// The on-disk form. Key order is not significant to any reader.
#[derive(Serialize, Deserialize)]
struct Wire {
    version: i64,
    gateway: String,
    #[serde(rename = "samlPort")]
    saml_port: u32,
    transport: Transport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(
        default,
        rename = "adoptsUnkeyedVPNEntry",
        skip_serializing_if = "Option::is_none"
    )]
    adopts_unkeyed_vpn_entry: Option<bool>,
}

impl Profile {
    pub fn new(
        gateway: &str,
        saml_port: u32,
        transport: Transport,
        name: Option<&str>,
        adopts_unkeyed_vpn_entry: Option<bool>,
    ) -> Result<Profile, ProfileError> {
        let profile = Profile {
            gateway: gateway.to_owned(),
            saml_port,
            transport,
            name: name.map(str::to_owned),
            adopts_unkeyed_vpn_entry,
        };
        profile.validate()?;
        Ok(profile)
    }

    /// The name shown to the user: the profile's name, else its gateway.
    pub fn display_name(&self) -> &str {
        self.name.as_deref().unwrap_or(&self.gateway)
    }

    /// The same profile with a new name and, when given, a new adoption flag.
    pub fn with_name(
        &self,
        name: Option<&str>,
        adopts_unkeyed_vpn_entry: Option<bool>,
    ) -> Result<Profile, ProfileError> {
        Profile::new(
            &self.gateway,
            self.saml_port,
            self.transport,
            name,
            adopts_unkeyed_vpn_entry.or(self.adopts_unkeyed_vpn_entry),
        )
    }

    pub fn validate(&self) -> Result<(), ProfileError> {
        if let Some(name) = &self.name {
            if !(1..=64).contains(&name.len()) || name.chars().any(is_control) {
                return Err(ProfileError::Invalid);
            }
        }
        let gateway = self.gateway.as_bytes();
        let ok = (1..=65535).contains(&self.saml_port)
            && (1..=253).contains(&gateway.len())
            && gateway
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'.')
            && !self.gateway.starts_with('.')
            && !self.gateway.ends_with('.')
            && !self.gateway.contains("..");
        if ok {
            Ok(())
        } else {
            Err(ProfileError::Invalid)
        }
    }

    /// The JSON the store writes.
    pub fn to_json(&self) -> Result<Vec<u8>, ProfileError> {
        let wire = Wire {
            version: 1,
            gateway: self.gateway.clone(),
            saml_port: self.saml_port,
            transport: self.transport,
            name: self.name.clone(),
            adopts_unkeyed_vpn_entry: self.adopts_unkeyed_vpn_entry,
        };
        let data = serde_json::to_vec(&wire).map_err(|_| ProfileError::Invalid)?;
        if data.len() as u64 > MAX_BYTES {
            return Err(ProfileError::Invalid);
        }
        Ok(data)
    }

    /// Decodes and validates a `profile.json`; the version must be 1.
    pub fn from_json(data: &[u8]) -> Result<Profile, ProfileError> {
        if data.is_empty() || data.len() as u64 > MAX_BYTES {
            return Err(ProfileError::Invalid);
        }
        let wire: Wire = serde_json::from_slice(data).map_err(|_| ProfileError::Invalid)?;
        if wire.version != 1 {
            return Err(ProfileError::Invalid);
        }
        let profile = Profile {
            gateway: wire.gateway,
            saml_port: wire.saml_port,
            transport: wire.transport,
            name: wire.name,
            adopts_unkeyed_vpn_entry: wire.adopts_unkeyed_vpn_entry,
        };
        profile.validate()?;
        Ok(profile)
    }
}

/// A directory holding one `profile.json`.
#[derive(Debug, Clone)]
pub struct ProfileStore {
    directory: PathBuf,
}

/// `Ok(true)` for a regular file that is not a symlink, `Ok(false)` for anything
/// else that exists, an error when it does not exist.
fn is_plain_file(path: &Path) -> std::io::Result<bool> {
    Ok(fs::symlink_metadata(path)?.file_type().is_file())
}

impl ProfileStore {
    pub fn new(directory: &Path) -> ProfileStore {
        ProfileStore {
            directory: directory.to_owned(),
        }
    }

    pub fn path(&self) -> PathBuf {
        self.directory.join(FILE_NAME)
    }

    /// Writes the profile atomically: directory 0700, file 0600.
    pub fn save(&self, profile: &Profile) -> Result<(), ProfileError> {
        profile.validate()?;
        let data = profile.to_json()?;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.directory)
            .map_err(|_| ProfileError::Unavailable)?;
        let meta = fs::symlink_metadata(&self.directory).map_err(|_| ProfileError::Unavailable)?;
        if !meta.file_type().is_dir() {
            return Err(ProfileError::Unavailable);
        }
        fs::set_permissions(&self.directory, fs::Permissions::from_mode(0o700))
            .map_err(|_| ProfileError::Unavailable)?;
        let temporary = self
            .directory
            .join(format!(".{FILE_NAME}.{}.tmp", std::process::id()));
        let written = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)
            .and_then(|mut file| file.write_all(&data))
            .and_then(|()| fs::rename(&temporary, self.path()));
        if written.is_err() {
            let _ = fs::remove_file(&temporary);
            return Err(ProfileError::Unavailable);
        }
        fs::set_permissions(self.path(), fs::Permissions::from_mode(0o600))
            .map_err(|_| ProfileError::Unavailable)
    }

    pub fn load(&self) -> Result<Profile, ProfileError> {
        let path = self.path();
        let meta = fs::symlink_metadata(&path).map_err(|_| ProfileError::Unavailable)?;
        if !meta.file_type().is_file() || !(1..=MAX_BYTES).contains(&meta.len()) {
            return Err(ProfileError::Unavailable);
        }
        let data = fs::read(&path).map_err(|_| ProfileError::Unavailable)?;
        Profile::from_json(&data)
    }

    /// Deletes the file (not the directory); refuses a symlinked directory or file.
    pub fn remove(&self) -> Result<(), ProfileError> {
        let directory = fs::symlink_metadata(&self.directory)
            .map_err(|_| ProfileError::Unavailable)?
            .file_type()
            .is_dir();
        let file = is_plain_file(&self.path()).map_err(|_| ProfileError::Unavailable)?;
        if !directory || !file {
            return Err(ProfileError::Unavailable);
        }
        fs::remove_file(self.path()).map_err(|_| ProfileError::Unavailable)
    }
}

#[cfg(test)]
pub(crate) mod testutil {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A fresh directory under the system temp dir, removed on drop.
    pub struct TempDir(pub PathBuf);

    impl TempDir {
        pub fn new(tag: &str) -> TempDir {
            static NEXT: AtomicU32 = AtomicU32::new(0);
            let path = std::env::temp_dir().join(format!(
                "oftc-host-{tag}-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&path).unwrap();
            TempDir(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    pub fn fixture(relative: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(relative)
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::{fixture, TempDir};
    use super::*;
    use serde_json::{json, Value};

    fn udp(gateway: &str, port: u32) -> Result<Profile, ProfileError> {
        Profile::new(gateway, port, Transport::Udp, None, None)
    }

    /// Both files were written by the shipped Swift `OFTCProfileStore`.
    #[test]
    fn decodes_what_swift_wrote() {
        let minimal = fs::read(fixture("swift/profile-minimal.json")).unwrap();
        assert_eq!(
            Profile::from_json(&minimal).unwrap(),
            udp("vpn.example.com", 9443).unwrap()
        );
        // `\/` escapes, quotes and non-ASCII in the name, and the adoption flag.
        let full = fs::read(fixture("swift/profile-full.json")).unwrap();
        assert_eq!(
            Profile::from_json(&full).unwrap(),
            Profile::new(
                "vpn.example.com",
                8443,
                Transport::Tcp,
                Some("Office \"HQ\" / Zürich — ☃"),
                Some(true)
            )
            .unwrap()
        );
    }

    /// Absent optional fields are omitted and the rest matches the Swift field
    /// names; compared as parsed JSON because Swift's key order is not stable.
    #[test]
    fn writes_the_swift_shape() {
        let full = Profile::new(
            "vpn.example.com",
            8443,
            Transport::Tcp,
            Some("Office \"HQ\" / Zürich — ☃"),
            Some(true),
        )
        .unwrap();
        let swift: Value =
            serde_json::from_slice(&fs::read(fixture("swift/profile-full.json")).unwrap()).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&full.to_json().unwrap()).unwrap(),
            swift
        );
        let minimal: Value =
            serde_json::from_slice(&udp("vpn.example.com", 9443).unwrap().to_json().unwrap())
                .unwrap();
        assert_eq!(
            minimal,
            json!({"version": 1, "gateway": "vpn.example.com", "samlPort": 9443, "transport": "udp"})
        );
    }

    #[test]
    fn validation_table() {
        let long_gateway = format!("{}.com", "a".repeat(250));
        let bad_gateways = [
            "",
            "/tmp/profile",
            "vpn.example.com:4443",
            "vpn..example.com",
            ".vpn.example.com",
            "vpn.example.com.",
            "vpn example",
            "vpn.éxample.com",
            &long_gateway, // 254 bytes
        ];
        for gateway in bad_gateways {
            assert_eq!(
                udp(gateway, 9443),
                Err(ProfileError::Invalid),
                "{gateway:?}"
            );
        }
        assert!(udp(&format!("{}.com", "a".repeat(249)), 9443).is_ok()); // 253 bytes
        assert_eq!(udp("vpn.example.com", 0), Err(ProfileError::Invalid));
        assert_eq!(udp("vpn.example.com", 65536), Err(ProfileError::Invalid));
        assert!(udp("vpn.example.com", 65535).is_ok());

        let named =
            |name: &str| Profile::new("vpn.example.com", 1, Transport::Udp, Some(name), None);
        let bad_names = [
            "",
            "tab\there",
            "line\nbreak",
            "del\u{7f}",
            "zero\u{200b}width", // Cf: Foundation refuses it, `char::is_control` would not
            "soft\u{ad}hyphen",  // Cf
            "bom\u{feff}",       // Cf
            &"n".repeat(65),
        ];
        for name in bad_names {
            assert_eq!(named(name), Err(ProfileError::Invalid), "{name:?}");
        }
        assert!(named(&"n".repeat(64)).is_ok());
        assert!(named("Zürich ☃").is_ok());
    }

    #[test]
    fn decode_rejects_what_swift_rejected() {
        let ok = br#"{"version":1,"gateway":"vpn.example.com","samlPort":9443,"transport":"udp"}"#;
        assert!(Profile::from_json(ok).is_ok());
        for bad in [
            &br#"{"version":2,"gateway":"vpn.example.com","samlPort":9443,"transport":"udp"}"#[..],
            br#"{"version":1,"gateway":"vpn.example.com","transport":"udp"}"#, // missing port
            br#"{"version":1,"gateway":"vpn.example.com","samlPort":9443,"transport":"sctp"}"#,
            br#"{"version":1,"gateway":"bad host","samlPort":9443,"transport":"udp"}"#,
            b"",
        ] {
            assert_eq!(Profile::from_json(bad), Err(ProfileError::Invalid));
        }
        // Unknown keys are ignored, as the Swift decoder did.
        let extra = br#"{"version":1,"gateway":"vpn.example.com","samlPort":9443,"transport":"udp","future":true}"#;
        assert!(Profile::from_json(extra).is_ok());
    }

    #[test]
    fn store_roundtrip_modes_remove() {
        let dir = TempDir::new("profile");
        let store = ProfileStore::new(&dir.0.join("p"));
        let profile = udp("vpn.example.com", 9443).unwrap();
        store.save(&profile).unwrap();
        assert_eq!(store.load().unwrap(), profile);
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&store.path()), 0o600);
        assert_eq!(mode(&dir.0.join("p")), 0o700);
        // Saving again replaces the file; no temporary file is left behind.
        let tcp = Profile::new("vpn.example.com", 9443, Transport::Tcp, None, None).unwrap();
        store.save(&tcp).unwrap();
        assert_eq!(store.load().unwrap(), tcp);
        assert_eq!(fs::read_dir(dir.0.join("p")).unwrap().count(), 1);
        store.remove().unwrap();
        assert!(!store.path().exists());
        assert_eq!(store.load(), Err(ProfileError::Unavailable));
    }

    #[test]
    fn store_refuses_symlink_and_oversize() {
        let dir = TempDir::new("profile-guards");
        let store = ProfileStore::new(&dir.0);
        // A symlinked profile.json is neither loaded nor removed.
        std::os::unix::fs::symlink("/etc/hosts", store.path()).unwrap();
        assert_eq!(store.load(), Err(ProfileError::Unavailable));
        assert_eq!(store.remove(), Err(ProfileError::Unavailable));
        fs::remove_file(store.path()).unwrap();
        // 4097 bytes is too large however well-formed.
        let padded = format!(
            r#"{{"version":1,"gateway":"vpn.example.com","samlPort":9443,"transport":"udp","pad":"{}"}}"#,
            "x".repeat(4100)
        );
        fs::write(store.path(), padded).unwrap();
        assert_eq!(store.load(), Err(ProfileError::Unavailable));
        // A symlinked directory is not written through.
        let link = dir.0.join("link");
        std::os::unix::fs::symlink(&dir.0, &link).unwrap();
        assert_eq!(
            ProfileStore::new(&link).save(&udp("vpn.example.com", 9443).unwrap()),
            Err(ProfileError::Unavailable)
        );
    }
}
