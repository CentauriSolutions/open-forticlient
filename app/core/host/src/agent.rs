//! The login agent and login items: what `register-agent` and friends do with
//! the status [`LoginItems`] reports.
//!
//! [`LoginItems`] gives the bare system calls; the policy here is the Swift
//! `OFTCAgentService`'s: register only from a state that can succeed, check the
//! result, then clear a launchd "disabled" override with `launchctl enable`.

use std::process::{Command, Stdio};
use std::sync::Mutex;

use oftc_apple::error::AppleError;
use oftc_apple::login::{LoginItem, LoginItems, LoginStatus};

/// The bundled launch agent's property list, by file name.
pub const AGENT_PLIST: &str = "com.chris.openforticlient.oftc.agent.plist";
/// The agent's launchd label.
pub const AGENT_LABEL: &str = "com.chris.openforticlient.oftc.agent";

pub fn agent_item() -> LoginItem {
    LoginItem::Agent(AGENT_PLIST.to_owned())
}

/// `launchctl`, for the one call the agent needs.
pub trait Launchctl {
    /// `launchctl enable gui/<uid>/<label>`; true when it exited 0.
    fn enable(&self, label: &str) -> bool;
}

/// `/bin/launchctl` in the current user's GUI domain.
pub struct SystemLaunchctl;

impl Launchctl for SystemLaunchctl {
    fn enable(&self, label: &str) -> bool {
        Command::new("/bin/launchctl")
            .arg("enable")
            .arg(format!("gui/{}/{label}", crate::os::uid()))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }
}

/// A [`Launchctl`] that records the labels it was asked to enable.
pub struct RecordingLaunchctl {
    succeeds: bool,
    calls: Mutex<Vec<String>>,
}

impl RecordingLaunchctl {
    pub fn new(succeeds: bool) -> Self {
        RecordingLaunchctl {
            succeeds,
            calls: Mutex::new(Vec::new()),
        }
    }

    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

impl Launchctl for RecordingLaunchctl {
    fn enable(&self, label: &str) -> bool {
        self.calls.lock().unwrap().push(label.to_owned());
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

fn unavailable(status: &str) -> String {
    format!("OFTC login agent is {status}")
}

/// The `agent-status` string.
pub fn status(items: &dyn LoginItems) -> &'static str {
    items.status(&agent_item()).as_str()
}

/// Registers the agent and clears any launchd disabled override.
pub fn register(items: &dyn LoginItems, launchctl: &dyn Launchctl) -> Result<(), String> {
    let agent = agent_item();
    match items.status(&agent) {
        LoginStatus::Enabled => {}
        LoginStatus::NotRegistered | LoginStatus::NotFound => {
            items.register(&agent).map_err(|e| describe(&e))?;
        }
        LoginStatus::RequiresApproval | LoginStatus::Unknown => {
            return Err(unavailable(status(items)));
        }
    }
    if items.status(&agent) != LoginStatus::Enabled {
        return Err(unavailable(status(items)));
    }
    if !launchctl.enable(AGENT_LABEL) {
        return Err(unavailable("disabled"));
    }
    Ok(())
}

/// Unregisters the agent; nothing to do when it is not registered.
pub fn unregister(items: &dyn LoginItems) -> Result<(), String> {
    let agent = agent_item();
    match items.status(&agent) {
        LoginStatus::NotRegistered | LoginStatus::NotFound => Ok(()),
        LoginStatus::Enabled | LoginStatus::RequiresApproval => {
            items.unregister(&agent).map_err(|e| describe(&e))
        }
        LoginStatus::Unknown => Err(unavailable("unknown")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oftc_apple::login::MockLoginItems;

    fn denied() -> AppleError {
        AppleError::from_nserror("SMAppServiceErrorDomain", 1, "Operation not permitted")
    }

    /// (start, status after a register call, launchctl ok, register calls,
    /// enable calls, result)
    type Row = (
        LoginStatus,
        LoginStatus,
        bool,
        usize,
        usize,
        Result<(), &'static str>,
    );

    /// Each starting status: whether `register` calls the system, what it ends
    /// as, and whether `launchctl enable` ran.
    #[test]
    fn register_acts_only_from_a_state_that_can_succeed() {
        use LoginStatus::*;
        let rows: [Row; 8] = [
            (Enabled, Enabled, true, 0, 1, Ok(())),
            (NotRegistered, Enabled, true, 1, 1, Ok(())),
            (NotFound, Enabled, true, 1, 1, Ok(())),
            (
                RequiresApproval,
                Enabled,
                true,
                0,
                0,
                Err("OFTC login agent is requires-approval"),
            ),
            (
                Unknown,
                Enabled,
                true,
                0,
                0,
                Err("OFTC login agent is unknown"),
            ),
            // Registered but left awaiting approval.
            (
                NotRegistered,
                RequiresApproval,
                true,
                1,
                0,
                Err("OFTC login agent is requires-approval"),
            ),
            // Enabled in the system but disabled in launchd.
            (
                Enabled,
                Enabled,
                false,
                0,
                1,
                Err("OFTC login agent is disabled"),
            ),
            (
                NotRegistered,
                NotRegistered,
                true,
                1,
                0,
                Err("OFTC login agent is not-registered"),
            ),
        ];
        for (start, after, launchctl_ok, calls, enables, want) in rows {
            let items = MockLoginItems::new();
            items.set_status(&agent_item(), start);
            items.script_register(&agent_item(), Ok(after));
            let launchctl = RecordingLaunchctl::new(launchctl_ok);
            let got = register(&items, &launchctl);
            assert_eq!(
                got.as_ref().map(|_| ()).map_err(String::as_str),
                want,
                "{start:?}"
            );
            assert_eq!(items.calls().len(), calls, "{start:?}");
            assert_eq!(launchctl.calls().len(), enables, "{start:?}");
        }
        // A failed registration is reported by its description alone.
        let items = MockLoginItems::new();
        items.script_register(&agent_item(), Err(denied()));
        let got = register(&items, &RecordingLaunchctl::new(true));
        assert_eq!(got, Err("Operation not permitted".to_owned()));
    }

    #[test]
    fn unregister_skips_what_is_not_registered_and_refuses_an_unknown_state() {
        use LoginStatus::*;
        for (start, calls, want) in [
            (NotRegistered, 0, Ok(())),
            (NotFound, 0, Ok(())),
            (Enabled, 1, Ok(())),
            (RequiresApproval, 1, Ok(())),
            (Unknown, 0, Err("OFTC login agent is unknown")),
        ] {
            let items = MockLoginItems::new();
            items.set_status(&agent_item(), start);
            let got = unregister(&items);
            assert_eq!(
                got.as_ref().map(|_| ()).map_err(String::as_str),
                want,
                "{start:?}"
            );
            assert_eq!(items.calls().len(), calls, "{start:?}");
        }
        let items = MockLoginItems::new();
        items.set_status(&agent_item(), Enabled);
        items.script_unregister(&agent_item(), Err(denied()));
        assert_eq!(
            unregister(&items),
            Err("Operation not permitted".to_owned())
        );
    }
}
