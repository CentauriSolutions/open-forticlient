//! The login agent and login items: what `register-agent` and friends do with
//! the status [`LoginItems`] reports.
//!
//! [`LoginItems`] gives the bare system calls; the policy here is the Swift
//! `OFTCAgentService`'s: register only from a state that can succeed, check the
//! result, then clear a launchd "disabled" override with `launchctl enable`.

use std::fs::{File, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::SystemTime;

use oftc_apple::error::AppleError;
use oftc_apple::login::{LoginItem, LoginItems, LoginStatus};

use crate::env::HostEnv;
use crate::intent;

/// The bundled launch agent's property list, by file name.
pub const AGENT_PLIST: &str = "com.chris.openforticlient.oftc.agent.plist";
/// The agent's launchd label.
pub const AGENT_LABEL: &str = "com.chris.openforticlient.oftc.agent";

/// The host service's property list (`host serve`), by file name.
pub const HOST_PLIST: &str = "com.chris.openforticlient.oftc.host.plist";
/// The host service's launchd label.
pub const HOST_LABEL: &str = "com.chris.openforticlient.oftc.host";

pub fn agent_item() -> LoginItem {
    LoginItem::Agent(AGENT_PLIST.to_owned())
}

/// The host service's login item (`OFTCAgent host serve`, `KeepAlive`).
pub fn host_item() -> LoginItem {
    LoginItem::Agent(HOST_PLIST.to_owned())
}

/// Which bundled launch agent a registration call is about. Both register through
/// `SMAppService.agent` and share one policy; they differ in the item, the launchd
/// label and the name an error uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentKind {
    /// The login agent: starts connect-at-login supervisors once and exits.
    Login,
    /// The resident host service that serves the UI socket.
    Host,
}

impl AgentKind {
    pub fn item(self) -> LoginItem {
        match self {
            AgentKind::Login => agent_item(),
            AgentKind::Host => host_item(),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            AgentKind::Login => AGENT_LABEL,
            AgentKind::Host => HOST_LABEL,
        }
    }

    fn noun(self) -> &'static str {
        match self {
            AgentKind::Login => "OFTC login agent",
            AgentKind::Host => "OFTC host service",
        }
    }
}

/// `launchctl`, for the two calls the agent needs.
pub trait Launchctl: Send + Sync {
    /// `launchctl enable gui/<uid>/<label>`; true when it exited 0.
    fn enable(&self, label: &str) -> bool;
    /// `launchctl disable gui/<uid>/<label>`; true when it exited 0. The supervisor
    /// uses it to keep the login agent from reconnecting after an unexplained drop.
    fn disable(&self, label: &str) -> bool;
    /// `launchctl kickstart -k gui/<uid>/<label>`: starts the service, or kills and
    /// restarts it if it runs; true when it exited 0.
    fn kickstart(&self, label: &str) -> bool;
}

/// `/bin/launchctl` in the current user's GUI domain.
pub struct SystemLaunchctl;

impl SystemLaunchctl {
    fn run(verbs: &[&str], label: &str) -> bool {
        Command::new("/bin/launchctl")
            .args(verbs)
            .arg(format!("gui/{}/{label}", crate::os::uid()))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }
}

impl Launchctl for SystemLaunchctl {
    fn enable(&self, label: &str) -> bool {
        SystemLaunchctl::run(&["enable"], label)
    }

    fn disable(&self, label: &str) -> bool {
        SystemLaunchctl::run(&["disable"], label)
    }

    fn kickstart(&self, label: &str) -> bool {
        SystemLaunchctl::run(&["kickstart", "-k"], label)
    }
}

/// A [`Launchctl`] that records the labels it was asked to enable or disable.
pub struct RecordingLaunchctl {
    succeeds: bool,
    calls: Mutex<Vec<String>>,
    disabled: Mutex<Vec<String>>,
    kicked: Mutex<Vec<String>>,
}

impl RecordingLaunchctl {
    pub fn new(succeeds: bool) -> Self {
        RecordingLaunchctl {
            succeeds,
            calls: Mutex::new(Vec::new()),
            disabled: Mutex::new(Vec::new()),
            kicked: Mutex::new(Vec::new()),
        }
    }

    /// The labels passed to `enable`.
    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }

    /// The labels passed to `kickstart`.
    pub fn kicked(&self) -> Vec<String> {
        self.kicked.lock().unwrap().clone()
    }

    /// The labels passed to `disable`.
    pub fn disabled(&self) -> Vec<String> {
        self.disabled.lock().unwrap().clone()
    }
}

impl Launchctl for RecordingLaunchctl {
    fn enable(&self, label: &str) -> bool {
        self.calls.lock().unwrap().push(label.to_owned());
        self.succeeds
    }

    fn disable(&self, label: &str) -> bool {
        self.disabled.lock().unwrap().push(label.to_owned());
        self.succeeds
    }

    fn kickstart(&self, label: &str) -> bool {
        self.kicked.lock().unwrap().push(label.to_owned());
        self.succeeds
    }
}

/// An error as an operator reads it: the system's description, without the
/// domain and code `Display` appends (Swift printed `localizedDescription`).
pub fn describe(error: &AppleError) -> String {
    match error {
        AppleError::Ns { message, .. } => message.clone(),
        other => other.to_string(),
    }
}

fn unavailable(kind: AgentKind, status: &str) -> String {
    format!("{} is {status}", kind.noun())
}

/// The `agent-status` string.
pub fn status(items: &dyn LoginItems) -> &'static str {
    status_of(items, AgentKind::Login)
}

/// The status string of the host service.
pub fn host_status(items: &dyn LoginItems) -> &'static str {
    status_of(items, AgentKind::Host)
}

fn status_of(items: &dyn LoginItems, kind: AgentKind) -> &'static str {
    items.status(&kind.item()).as_str()
}

/// Registers the login agent and clears any launchd disabled override.
pub fn register(items: &dyn LoginItems, launchctl: &dyn Launchctl) -> Result<(), String> {
    register_kind(AgentKind::Login, items, launchctl)
}

/// Registers the host service and clears any launchd disabled override.
pub fn register_host(items: &dyn LoginItems, launchctl: &dyn Launchctl) -> Result<(), String> {
    register_kind(AgentKind::Host, items, launchctl)
}

fn register_kind(
    kind: AgentKind,
    items: &dyn LoginItems,
    launchctl: &dyn Launchctl,
) -> Result<(), String> {
    let agent = kind.item();
    match items.status(&agent) {
        LoginStatus::Enabled => {}
        LoginStatus::NotRegistered | LoginStatus::NotFound => {
            items.register(&agent).map_err(|e| describe(&e))?;
        }
        LoginStatus::RequiresApproval | LoginStatus::Unknown => {
            return Err(unavailable(kind, status_of(items, kind)));
        }
    }
    if items.status(&agent) != LoginStatus::Enabled {
        return Err(unavailable(kind, status_of(items, kind)));
    }
    if !launchctl.enable(kind.label()) {
        return Err(unavailable(kind, "disabled"));
    }
    Ok(())
}

/// Unregisters the login agent; nothing to do when it is not registered.
pub fn unregister(items: &dyn LoginItems) -> Result<(), String> {
    unregister_kind(AgentKind::Login, items)
}

/// Unregisters the host service; nothing to do when it is not registered.
pub fn unregister_host(items: &dyn LoginItems) -> Result<(), String> {
    unregister_kind(AgentKind::Host, items)
}

fn unregister_kind(kind: AgentKind, items: &dyn LoginItems) -> Result<(), String> {
    let agent = kind.item();
    match items.status(&agent) {
        LoginStatus::NotRegistered | LoginStatus::NotFound => Ok(()),
        LoginStatus::Enabled | LoginStatus::RequiresApproval => {
            items.unregister(&agent).map_err(|e| describe(&e))
        }
        LoginStatus::Unknown => Err(unavailable(kind, "unknown")),
    }
}

/// The agent's own log could not be opened.
const LOG_UNAVAILABLE: &str = "Could not open the OFTC supervisor log";

/// Opens (creating, 0600) a log file for appending, never through a symlink.
pub fn open_log(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

/// Under launchd, sends this process's stdout and stderr to `agent.log`: an
/// app-bundled plist cannot name a per-user log path. A direct run keeps its
/// terminal. The log must be a regular file of ours.
pub fn redirect_output(env: &HostEnv) -> Result<(), String> {
    if !env.bundled_agent() {
        return Ok(());
    }
    let logs = env.logs_dir();
    crate::lease::make_private_dir(&logs).map_err(|_| LOG_UNAVAILABLE.to_owned())?;
    let log = open_log(&logs.join("agent.log")).map_err(|_| LOG_UNAVAILABLE.to_owned())?;
    let ours = log
        .metadata()
        .is_ok_and(|meta| meta.is_file() && meta.uid() == crate::os::euid());
    if ours && crate::os::redirect_stdio(&log) {
        Ok(())
    } else {
        Err(LOG_UNAVAILABLE.to_owned())
    }
}

/// Starts `<exe> --profile <id> supervise-profile` with the agent marker removed, its
/// output appended to `log` (or inherited when there is none) and no input.
///
/// The child leads its own process group. The resident host service starts
/// supervisors, and `launchctl kickstart -k` or a crash of the host signals its
/// process group; a supervisor in that group would die with it and drop its tunnel.
/// (`std` offers `process_group` without `unsafe`; `setsid` would need a `pre_exec`
/// hook. A launchd job has no controlling terminal, so the group is what matters, and
/// the host plist sets `AbandonProcessGroup` so launchd does not reap the leftovers.)
pub fn supervisor_command(exe: &Path, id: &str) -> Command {
    let mut command = Command::new(exe);
    command
        .args(["--profile", id, "supervise-profile"])
        .env_remove("OFTC_BUNDLED_AGENT")
        .stdin(Stdio::null())
        .process_group(0);
    command
}

pub fn spawn_supervisor(exe: &Path, id: &str, log: Option<File>) -> std::io::Result<Child> {
    let mut command = supervisor_command(exe, id);
    if let Some(log) = log {
        command.stdout(log.try_clone()?).stderr(log);
    }
    command.spawn()
}

/// Sets whether the profile whose files are in `directory` connects at login.
///
/// Turning it on registers the login agent without starting a sign-in now: when the
/// agent was not yet enabled a one-use `connect: false` request says so, and if
/// registration then fails the request and the previous choice are put back. Turning
/// it on with the agent already enabled only clears a launchd "disabled" override.
/// `adopted` is whether the profile adopted the original single-profile layout, which
/// inherits an enabled agent while it has no stored choice.
pub fn set_connect_at_login(
    login: &dyn LoginItems,
    launchctl: &dyn Launchctl,
    directory: &Path,
    adopted: bool,
    enabled: bool,
    now: SystemTime,
) -> Result<(), String> {
    let was_registered = status(login) == "enabled";
    let previous = intent::connect_at_login(directory, adopted && was_registered);
    intent::set_connect_at_login(directory, enabled).map_err(|e| e.to_string())?;
    if enabled && status(login) != "enabled" {
        intent::request(directory, false, now).map_err(|e| e.to_string())?;
        if let Err(error) = register(login, launchctl) {
            intent::cancel_request(directory);
            let _ = intent::set_connect_at_login(directory, previous);
            return Err(error);
        }
    } else if enabled {
        register(login, launchctl)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use oftc_apple::login::MockLoginItems;
    use std::fs;

    fn denied() -> AppleError {
        AppleError::from_nserror("SMAppServiceErrorDomain", 1, "Operation not permitted")
    }

    /// (start, status after a register call, launchctl ok, register calls,
    /// enable calls, error suffix after "<noun> is ")
    type Row = (
        LoginStatus,
        LoginStatus,
        bool,
        usize,
        usize,
        Option<&'static str>,
    );

    const KINDS: [(AgentKind, &str, &str); 2] = [
        (AgentKind::Login, "OFTC login agent", AGENT_LABEL),
        (AgentKind::Host, "OFTC host service", HOST_LABEL),
    ];

    fn register_for(
        kind: AgentKind,
        items: &MockLoginItems,
        launchctl: &RecordingLaunchctl,
    ) -> Result<(), String> {
        match kind {
            AgentKind::Login => register(items, launchctl),
            AgentKind::Host => register_host(items, launchctl),
        }
    }

    /// Each starting status, for each agent kind: whether `register` calls the
    /// system, what it ends as, whether `launchctl enable` ran and for which label.
    #[test]
    fn register_acts_only_from_a_state_that_can_succeed() {
        use LoginStatus::*;
        let rows: [Row; 8] = [
            (Enabled, Enabled, true, 0, 1, None),
            (NotRegistered, Enabled, true, 1, 1, None),
            (NotFound, Enabled, true, 1, 1, None),
            (
                RequiresApproval,
                Enabled,
                true,
                0,
                0,
                Some("requires-approval"),
            ),
            (Unknown, Enabled, true, 0, 0, Some("unknown")),
            // Registered but left awaiting approval.
            (
                NotRegistered,
                RequiresApproval,
                true,
                1,
                0,
                Some("requires-approval"),
            ),
            // Enabled in the system but disabled in launchd.
            (Enabled, Enabled, false, 0, 1, Some("disabled")),
            (
                NotRegistered,
                NotRegistered,
                true,
                1,
                0,
                Some("not-registered"),
            ),
        ];
        for (kind, noun, label) in KINDS {
            for (start, after, launchctl_ok, calls, enables, want) in rows {
                let items = MockLoginItems::new();
                items.set_status(&kind.item(), start);
                items.script_register(&kind.item(), Ok(after));
                let launchctl = RecordingLaunchctl::new(launchctl_ok);
                let got = register_for(kind, &items, &launchctl);
                let want = match want {
                    None => Ok(()),
                    Some(suffix) => Err(format!("{noun} is {suffix}")),
                };
                assert_eq!(got, want, "{kind:?} {start:?}");
                assert_eq!(items.calls().len(), calls, "{kind:?} {start:?}");
                // Only this kind's item was touched, and only its label enabled.
                assert!(
                    items.calls().iter().all(|(_, item)| *item == kind.item()),
                    "{kind:?} {start:?}"
                );
                assert_eq!(launchctl.calls().len(), enables, "{kind:?} {start:?}");
                assert!(launchctl.calls().iter().all(|l| l == label));
            }
            // A failed registration is reported by its description alone.
            let items = MockLoginItems::new();
            items.script_register(&kind.item(), Err(denied()));
            let got = register_for(kind, &items, &RecordingLaunchctl::new(true));
            assert_eq!(got, Err("Operation not permitted".to_owned()));
        }
    }

    #[test]
    fn unregister_skips_what_is_not_registered_and_refuses_an_unknown_state() {
        use LoginStatus::*;
        for (kind, noun, _) in KINDS {
            let unregister_for = |items: &MockLoginItems| match kind {
                AgentKind::Login => unregister(items),
                AgentKind::Host => unregister_host(items),
            };
            let unknown = format!("{noun} is unknown");
            for (start, calls, want) in [
                (NotRegistered, 0, Ok(())),
                (NotFound, 0, Ok(())),
                (Enabled, 1, Ok(())),
                (RequiresApproval, 1, Ok(())),
                (Unknown, 0, Err(unknown.as_str())),
            ] {
                let items = MockLoginItems::new();
                items.set_status(&kind.item(), start);
                let got = unregister_for(&items);
                assert_eq!(
                    got.as_ref().map(|_| ()).map_err(String::as_str),
                    want,
                    "{kind:?} {start:?}"
                );
                assert_eq!(items.calls().len(), calls, "{kind:?} {start:?}");
            }
            let items = MockLoginItems::new();
            items.set_status(&kind.item(), Enabled);
            items.script_unregister(&kind.item(), Err(denied()));
            assert_eq!(
                unregister_for(&items),
                Err("Operation not permitted".to_owned())
            );
        }
    }

    /// The two agents are separate login items: the status strings and the
    /// registration of one never read or change the other.
    #[test]
    fn the_login_agent_and_the_host_service_are_independent_items() {
        assert_ne!(agent_item(), host_item());
        let items = MockLoginItems::new();
        items.set_status(&agent_item(), LoginStatus::Enabled);
        items.set_status(&host_item(), LoginStatus::RequiresApproval);
        assert_eq!(status(&items), "enabled");
        assert_eq!(host_status(&items), "requires-approval");
        assert_eq!(
            host_item(),
            LoginItem::Agent("com.chris.openforticlient.oftc.host.plist".into())
        );
        assert_eq!(HOST_LABEL, "com.chris.openforticlient.oftc.host");
    }

    /// Set in the child of [`redirect_sends_output_to_the_agent_log`]: it is a
    /// separate process because `dup2` would otherwise redirect the test runner.
    const HOME: &str = "OFTC_REDIRECT_HOME";

    #[test]
    fn redirect_helper() {
        use std::io::Write;
        let Ok(home) = std::env::var(HOME) else {
            return; // an ordinary run of the suite
        };
        let env = HostEnv::new("com.example.oftc", Path::new(&home))
            .unwrap()
            .with_bundled_agent(true);
        if redirect_output(&env).is_err() {
            std::process::exit(3);
        }
        let _ = std::io::stdout().write_all(b"to stdout\n");
        let _ = std::io::stderr().write_all(b"to stderr\n");
        std::process::exit(0);
    }

    #[test]
    fn redirect_sends_output_to_the_agent_log() {
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::profile::testutil::TempDir::new("redirect");
        let run = || {
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "agent::tests::redirect_helper", "--nocapture"])
                .env(HOME, &dir.0)
                .output()
                .unwrap()
        };
        let log = dir.0.join("Library/Logs/OFTC/agent.log");
        let output = run();
        assert_eq!(output.status.code(), Some(0));
        // Nothing reached the terminal; the log has both streams, appended.
        assert!(!String::from_utf8_lossy(&output.stdout).contains("to stdout"));
        let text = fs::read_to_string(&log).unwrap();
        assert!(
            text.contains("to stdout\n") && text.contains("to stderr\n"),
            "{text}"
        );
        run();
        assert_eq!(
            fs::read_to_string(&log)
                .unwrap()
                .matches("to stdout")
                .count(),
            2
        );
        assert_eq!(
            fs::metadata(&log).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let logs = dir.0.join("Library/Logs/OFTC");
        assert_eq!(
            fs::metadata(&logs).unwrap().permissions().mode() & 0o777,
            0o700
        );
        // A log that is a symlink is refused (`O_NOFOLLOW`), and the verb fails.
        fs::remove_file(&log).unwrap();
        std::os::unix::fs::symlink(dir.0.join("elsewhere"), &log).unwrap();
        assert_eq!(run().status.code(), Some(3));
        assert!(!dir.0.join("elsewhere").exists());
    }

    #[test]
    fn a_supervisor_is_started_for_its_profile_without_the_agent_marker() {
        let command = supervisor_command(Path::new("/x/OFTCAgent"), "lab");
        let args: Vec<_> = command.get_args().collect();
        assert_eq!(args, ["--profile", "lab", "supervise-profile"]);
        // `None` means removed from the child's environment.
        let envs: Vec<_> = command.get_envs().collect();
        assert_eq!(envs, [(std::ffi::OsStr::new("OFTC_BUNDLED_AGENT"), None)]);
    }

    /// The supervisor leads its own process group, so a signal to the host's group
    /// (`launchctl kickstart -k`, a crash) does not reach it. The stand-in
    /// executable records its own pid and process group; both differ from ours.
    #[test]
    fn a_spawned_supervisor_leads_its_own_process_group() {
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::profile::testutil::TempDir::new("detach");
        let exe = dir.0.join("fake-oftc");
        fs::write(
            &exe,
            "#!/bin/sh\n/bin/ps -o pgid= -p $$ | /usr/bin/tr -d ' '\necho \"$$ $*\"\n",
        )
        .unwrap();
        fs::set_permissions(&exe, fs::Permissions::from_mode(0o755)).unwrap();
        let log_path = dir.0.join("lab.log");
        let log = open_log(&log_path).unwrap();
        let mut child = spawn_supervisor(&exe, "lab", Some(log)).unwrap();
        assert!(child.wait().unwrap().success());
        let text = fs::read_to_string(&log_path).unwrap();
        let mut lines = text.lines();
        let pgid: i32 = lines.next().unwrap().parse().unwrap();
        let (pid, args) = lines.next().unwrap().split_once(' ').unwrap();
        assert_eq!(args, "--profile lab supervise-profile");
        assert_eq!(pgid, pid.parse::<i32>().unwrap(), "child leads its group");
        let ours = Command::new("/bin/ps")
            .args(["-o", "pgid=", "-p", &std::process::id().to_string()])
            .output()
            .unwrap();
        let ours: i32 = String::from_utf8_lossy(&ours.stdout)
            .trim()
            .parse()
            .unwrap();
        assert_ne!(pgid, ours);
    }

    #[test]
    fn a_direct_run_keeps_its_terminal() {
        let dir = crate::profile::testutil::TempDir::new("direct");
        let env = HostEnv::new("com.example.oftc", &dir.0).unwrap();
        assert_eq!(redirect_output(&env), Ok(()));
        assert!(!env.logs_dir().exists());
    }
}
