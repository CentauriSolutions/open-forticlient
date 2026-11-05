//! Where the host keeps its files and what it calls itself.

use std::path::{Path, PathBuf};

/// The bundle identifier and home directory everything else is derived from. Tests
/// pass their own, so nothing here reads the process environment except
/// [`HostEnv::from_process`].
#[derive(Debug, Clone)]
pub struct HostEnv {
    bundle_id: String,
    home: PathBuf,
    root: PathBuf,
    exe: Option<PathBuf>,
    bundled_agent: bool,
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
            home: home.to_owned(),
            root: home.join("Library/Application Support").join(bundle_id),
            exe: None,
            bundled_agent: false,
        })
    }

    /// The current user's home: `HOME`, else the password database. (Swift's
    /// `homeDirectoryForCurrentUser` ignores `HOME`; the two differ only when `HOME`
    /// is set to something other than the user's home, as tests and `sudo -E` do.)
    pub fn from_process(bundle_id: &str) -> Option<HostEnv> {
        let env = HostEnv::new(bundle_id, &std::env::home_dir()?)?;
        Some(HostEnv {
            exe: std::env::current_exe().ok(),
            bundled_agent: std::env::var_os("OFTC_BUNDLED_AGENT").is_some_and(|v| v == "1"),
            ..env
        })
    }

    /// Runs under a different executable: the one supervisors are started from.
    pub fn with_exe(mut self, exe: &Path) -> HostEnv {
        self.exe = Some(exe.to_owned());
        self
    }

    /// The `OFTCAgent` executable that started this process, to start supervisors.
    pub fn exe(&self) -> Option<&Path> {
        self.exe.as_deref()
    }

    /// True when launchd started this process as the bundled login agent
    /// (`OFTC_BUNDLED_AGENT=1`), so its output belongs in the agent log.
    pub fn bundled_agent(&self) -> bool {
        self.bundled_agent
    }

    /// Pretends to run (or not) as the bundled login agent.
    pub fn with_bundled_agent(mut self, bundled: bool) -> HostEnv {
        self.bundled_agent = bundled;
        self
    }

    /// `~/Library/Logs/OFTC`: the agent's and each supervisor's log.
    pub fn logs_dir(&self) -> PathBuf {
        self.home.join("Library/Logs/OFTC")
    }

    /// `~/Library/Application Support/<bundle id>`: profiles live under it.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The system extension's bundle identifier: `<bundle id>.provider`.
    pub fn provider_id(&self) -> String {
        format!("{}.provider", self.bundle_id)
    }

    /// `~/.config/oftc/gateways`: the trusted gateway certificates, one file per
    /// `<host>_<port>.pem`.
    pub fn pin_dir(&self) -> PathBuf {
        self.home.join(".config/oftc/gateways")
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
        assert_eq!(env.logs_dir(), Path::new("/Users/test/Library/Logs/OFTC"));
        assert_eq!(env.provider_id(), "com.example.oftc.provider");
        assert_eq!(
            env.pin_dir(),
            Path::new("/Users/test/.config/oftc/gateways")
        );
        assert!(HostEnv::new("", Path::new("/Users/test")).is_none());
    }
}
