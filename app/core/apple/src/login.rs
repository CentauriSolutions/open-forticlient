//! Login items and login agents (`SMAppService`), as a trait.
//!
//! [`LoginItems`] is what the host's login verbs call; [`MockLoginItems`]
//! stands in for ServiceManagement in tests. The calls are the bare system ones:
//! what to do for each status (for example refusing to register while approval is
//! pending) is the host's policy, not this crate's.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use crate::error::AppleError;

pub type Result<T> = std::result::Result<T, AppleError>;

/// What can be registered.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum LoginItem {
    /// The app's own launch-at-login item (`SMAppService.mainApp`).
    MainApp,
    /// A launch agent whose property list is bundled in the app, by file name
    /// (`SMAppService.agent(plistName:)`).
    Agent(String),
}

/// An item's registration state, mirroring `SMAppServiceStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginStatus {
    NotRegistered,
    Enabled,
    RequiresApproval,
    NotFound,
    /// A status this build does not know.
    Unknown,
}

impl LoginStatus {
    /// The string the `agent-status` verb prints and callers parse.
    pub fn as_str(self) -> &'static str {
        match self {
            LoginStatus::NotRegistered => "not-registered",
            LoginStatus::Enabled => "enabled",
            LoginStatus::RequiresApproval => "requires-approval",
            LoginStatus::NotFound => "not-found",
            LoginStatus::Unknown => "unknown",
        }
    }
}

pub trait LoginItems: Send + Sync {
    fn status(&self, item: &LoginItem) -> LoginStatus;
    /// Registers `item`. It may succeed and still leave the item at
    /// `RequiresApproval`; callers read `status` afterwards.
    fn register(&self, item: &LoginItem) -> Result<()>;
    fn unregister(&self, item: &LoginItem) -> Result<()>;
}

pub use mock::MockLoginItems;

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
mod sm;
#[cfg(target_os = "macos")]
pub use sm::ServiceLoginItems;

mod mock {
    use super::*;

    #[derive(Default)]
    struct State {
        statuses: HashMap<LoginItem, LoginStatus>,
        register: HashMap<LoginItem, VecDeque<Result<LoginStatus>>>,
        unregister: HashMap<LoginItem, VecDeque<Result<LoginStatus>>>,
        calls: Vec<(&'static str, LoginItem)>,
    }

    impl State {
        fn status(&self, item: &LoginItem) -> LoginStatus {
            self.statuses
                .get(item)
                .copied()
                .unwrap_or(LoginStatus::NotRegistered)
        }
    }

    /// An in-memory [`LoginItems`]. Items start `NotRegistered`; `register` ends
    /// `Enabled` and `unregister` ends `NotRegistered` unless scripted otherwise.
    #[derive(Default)]
    pub struct MockLoginItems {
        state: Mutex<State>,
    }

    impl MockLoginItems {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn set_status(&self, item: &LoginItem, status: LoginStatus) {
            self.state
                .lock()
                .unwrap()
                .statuses
                .insert(item.clone(), status);
        }

        /// Queues the next `register` of `item`: the status it leaves behind, or
        /// the error it fails with (the status is then unchanged).
        pub fn script_register(&self, item: &LoginItem, outcome: Result<LoginStatus>) {
            self.state
                .lock()
                .unwrap()
                .register
                .entry(item.clone())
                .or_default()
                .push_back(outcome);
        }

        /// Queues the next `unregister` of `item`, as `script_register` does.
        pub fn script_unregister(&self, item: &LoginItem, outcome: Result<LoginStatus>) {
            self.state
                .lock()
                .unwrap()
                .unregister
                .entry(item.clone())
                .or_default()
                .push_back(outcome);
        }

        /// Every `register` and `unregister` so far, in order.
        pub fn calls(&self) -> Vec<(&'static str, LoginItem)> {
            self.state.lock().unwrap().calls.clone()
        }

        fn change(
            &self,
            call: &'static str,
            item: &LoginItem,
            default: LoginStatus,
            queue: fn(&mut State) -> &mut HashMap<LoginItem, VecDeque<Result<LoginStatus>>>,
        ) -> Result<()> {
            let mut s = self.state.lock().unwrap();
            s.calls.push((call, item.clone()));
            let outcome = queue(&mut s)
                .get_mut(item)
                .and_then(VecDeque::pop_front)
                .unwrap_or(Ok(default));
            let status = outcome?;
            s.statuses.insert(item.clone(), status);
            Ok(())
        }
    }

    impl LoginItems for MockLoginItems {
        fn status(&self, item: &LoginItem) -> LoginStatus {
            self.state.lock().unwrap().status(item)
        }

        fn register(&self, item: &LoginItem) -> Result<()> {
            self.change("register", item, LoginStatus::Enabled, |s| &mut s.register)
        }

        fn unregister(&self, item: &LoginItem) -> Result<()> {
            self.change("unregister", item, LoginStatus::NotRegistered, |s| {
                &mut s.unregister
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The mock is what the host's login verbs are tested against, so it must
    /// behave as the real backend does: items are independent, a registration can
    /// leave an item awaiting approval, and a failed call changes nothing.
    #[test]
    fn mock_honours_the_login_items_contract() {
        let items = MockLoginItems::new();
        let app = LoginItem::MainApp;
        let agent = LoginItem::Agent("a.plist".into());
        let other = LoginItem::Agent("b.plist".into());
        assert_eq!(items.status(&app), LoginStatus::NotRegistered);

        items.register(&agent).unwrap();
        assert_eq!(items.status(&agent), LoginStatus::Enabled);
        assert_eq!(items.status(&app), LoginStatus::NotRegistered);
        assert_eq!(items.status(&other), LoginStatus::NotRegistered);

        items.script_register(&app, Ok(LoginStatus::RequiresApproval));
        items.register(&app).unwrap();
        assert_eq!(items.status(&app), LoginStatus::RequiresApproval);

        let failure = AppleError::from_nserror("SMAppServiceErrorDomain", 1, "denied");
        items.script_unregister(&agent, Err(failure.clone()));
        assert_eq!(items.unregister(&agent), Err(failure));
        assert_eq!(items.status(&agent), LoginStatus::Enabled);
        items.unregister(&agent).unwrap();
        assert_eq!(items.status(&agent), LoginStatus::NotRegistered);

        assert_eq!(
            items.calls(),
            [
                ("register", agent.clone()),
                ("register", app),
                ("unregister", agent.clone()),
                ("unregister", agent),
            ]
        );
    }

    #[test]
    fn status_strings_are_the_ones_the_verb_prints() {
        for (status, text) in [
            (LoginStatus::NotRegistered, "not-registered"),
            (LoginStatus::Enabled, "enabled"),
            (LoginStatus::RequiresApproval, "requires-approval"),
            (LoginStatus::NotFound, "not-found"),
            (LoginStatus::Unknown, "unknown"),
        ] {
            assert_eq!(status.as_str(), text);
        }
    }
}
