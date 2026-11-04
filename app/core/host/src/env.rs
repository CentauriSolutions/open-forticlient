//! Where the host keeps its files and what it calls itself.

use std::path::{Path, PathBuf};

/// The bundle identifier and home directory everything else is derived from. Tests
/// pass their own, so nothing here reads the process environment except
/// [`HostEnv::from_process`].
#[derive(Debug, Clone)]
pub struct HostEnv {
    bundle_id: String,
    root: PathBuf,
}

impl HostEnv {
    /// `None` for an empty bundle identifier (the Swift host answered that with
    /// the usage text).
    pub fn new(bundle_id: &str, home: &Path) -> Option<HostEnv> {
        if bundle_id.is_empty() {
            return None;
        }
        Some(HostEnv {
            bundle_id: bundle_id.to_owned(),
            root: home.join("Library/Application Support").join(bundle_id),
        })
    }

    /// The current user's home: `HOME`, else the password database. (Swift's
    /// `homeDirectoryForCurrentUser` ignores `HOME`; the two differ only when `HOME`
    /// is set to something other than the user's home, as tests and `sudo -E` do.)
    pub fn from_process(bundle_id: &str) -> Option<HostEnv> {
        HostEnv::new(bundle_id, &std::env::home_dir()?)
    }

    /// `~/Library/Application Support/<bundle id>`: profiles live under it.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The Keychain service that holds the PSKs: `<bundle id>.psk`.
    pub fn keychain_service(&self) -> String {
        format!("{}.psk", self.bundle_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_derive_from_the_bundle_id() {
        let env = HostEnv::new("com.example.oftc", Path::new("/Users/test")).unwrap();
        assert_eq!(
            env.root(),
            Path::new("/Users/test/Library/Application Support/com.example.oftc")
        );
        assert_eq!(env.keychain_service(), "com.example.oftc.psk");
        assert!(HostEnv::new("", Path::new("/Users/test")).is_none());
    }
}
