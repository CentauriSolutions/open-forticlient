//! The real backends of the process-level ops: starting a supervisor and opening
//! System Settings. Tests use the doubles in `serve::tests`.

use std::path::PathBuf;
use std::process::{Command, Stdio};

use oftc_ui_edge::Pane;

use crate::agent;

/// Starts the reconnect supervisor of one profile and returns once it runs.
pub trait Spawner: Send + Sync {
    fn spawn_supervisor(&self, id: &str) -> std::io::Result<()>;
}

/// `<exe> --profile <id> supervise-profile`, logging to `<logs>/<id>.log`. The child is
/// reaped on a thread of its own; detaching it from the host's process group is the
/// launch agent's job (`docs/ui-edge.md` section 15).
pub struct ProcessSpawner {
    pub exe: Option<PathBuf>,
    pub logs: PathBuf,
}

impl Spawner for ProcessSpawner {
    fn spawn_supervisor(&self, id: &str) -> std::io::Result<()> {
        let exe = self
            .exe
            .as_deref()
            .ok_or_else(|| std::io::Error::other("no executable"))?;
        crate::lease::make_private_dir(&self.logs)?;
        let log = agent::open_log(&self.logs.join(format!("{id}.log")))?;
        let mut child = agent::spawn_supervisor(exe, id, Some(log))?;
        std::thread::spawn(move || {
            let _ = child.wait();
        });
        Ok(())
    }
}

/// Opens a System Settings pane.
pub trait SettingsOpener: Send + Sync {
    fn open(&self, pane: Pane) -> bool;
}

pub struct SystemOpener;

impl SettingsOpener for SystemOpener {
    fn open(&self, pane: Pane) -> bool {
        let url = match pane {
            Pane::Extensions => {
                "x-apple.systempreferences:com.apple.ExtensionsPreferences?extensionPointIdentifier=com.apple.system_extension.network_extension.extension-point"
            }
            Pane::LoginItems => "x-apple.systempreferences:com.apple.LoginItems-Settings.extension",
        };
        Command::new("/usr/bin/open")
            .arg(url)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }
}
