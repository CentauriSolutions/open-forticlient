//! The menu login item ("OFTC at login", `SMAppService.mainApp`) is turned on once, by the
//! first successful setup, so the menu-bar icon comes back after a reboot. It is an
//! offer made once: a marker file in the host's support directory records that it was made or
//! that the user chose for themselves, and nothing registers the item again after that.
//!
//! Registering starts nothing: no sign-in, no connection. If macOS holds the item for the
//! user's approval, that is the login item's own approval state (`login.menu_item` is
//! `requires_approval`, and Settings shows it), not a failure of setup.

use std::path::Path;

use oftc_apple::login::{LoginItem, LoginItems, LoginStatus};

use crate::lease;

/// Present once the default was offered or the user chose; its content is not read.
pub const MARKER: &str = "menu-login-default.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Not offered: not a first setup, already offered or chosen, or already on.
    Skipped,
    Registered,
    /// Registered, and macOS waits for the user to allow it in Login Items.
    NeedsApproval,
    /// The system refused; the offer is spent all the same, the user can turn it on in Settings.
    Failed,
}

/// Records that the item's state is the user's from now on (`settings_set menu_login`).
pub fn remember_choice(root: &Path) {
    let _ = lease::write_private(root, MARKER, b"chosen\n");
}

/// The default after a setup that made the first profile. `first_setup` is the caller's
/// knowledge that no profile existed before this setup and one exists now; a repair or
/// an additional profile never offers it.
pub fn offer(root: &Path, items: &dyn LoginItems, first_setup: bool) -> Outcome {
    if !first_setup || root.join(MARKER).exists() {
        return Outcome::Skipped;
    }
    // Spent first: a crash or a refusal must not offer it again on a later setup.
    if lease::write_private(root, MARKER, b"offered\n").is_err() {
        return Outcome::Skipped;
    }
    let item = LoginItem::MainApp;
    match items.status(&item) {
        LoginStatus::Enabled => return Outcome::Skipped,
        LoginStatus::RequiresApproval => return Outcome::NeedsApproval,
        _ => {}
    }
    if items.register(&item).is_err() {
        return Outcome::Failed;
    }
    if items.status(&item) == LoginStatus::RequiresApproval {
        Outcome::NeedsApproval
    } else {
        Outcome::Registered
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oftc_apple::error::AppleError;
    use crate::profile::testutil::TempDir;
    use oftc_apple::login::MockLoginItems;

    fn root() -> TempDir {
        TempDir::new("menu-login")
    }

    #[test]
    fn the_first_setup_registers_once_and_never_again() {
        let dir = root();
        let items = MockLoginItems::new();
        assert_eq!(offer(&dir.0, &items, true), Outcome::Registered);
        assert_eq!(items.status(&LoginItem::MainApp), LoginStatus::Enabled);
        // The user turns it off in Settings, and a later first-looking setup respects that.
        items.unregister(&LoginItem::MainApp).unwrap();
        assert_eq!(offer(&dir.0, &items, true), Outcome::Skipped);
        assert_eq!(items.status(&LoginItem::MainApp), LoginStatus::NotRegistered);
    }

    #[test]
    fn a_repair_or_an_extra_profile_never_offers_it() {
        let dir = root();
        let items = MockLoginItems::new();
        assert_eq!(offer(&dir.0, &items, false), Outcome::Skipped);
        assert_eq!(items.status(&LoginItem::MainApp), LoginStatus::NotRegistered);
        assert!(!&dir.0.join(MARKER).exists(), "a skipped offer does not spend it");
    }

    #[test]
    fn a_choice_the_user_made_comes_first() {
        let dir = root();
        let items = MockLoginItems::new();
        remember_choice(&dir.0); // they turned it off before the first profile existed
        assert_eq!(offer(&dir.0, &items, true), Outcome::Skipped);
        assert_eq!(items.status(&LoginItem::MainApp), LoginStatus::NotRegistered);
    }

    #[test]
    fn approval_is_a_state_and_a_refusal_spends_the_offer() {
        let dir = root();
        let items = MockLoginItems::new();
        items.script_register(&LoginItem::MainApp, Ok(LoginStatus::RequiresApproval));
        assert_eq!(offer(&dir.0, &items, true), Outcome::NeedsApproval);

        let dir = root();
        let items = MockLoginItems::new();
        items.script_register(&LoginItem::MainApp, Err(AppleError::TimedOut));
        assert_eq!(offer(&dir.0, &items, true), Outcome::Failed);
        assert_eq!(offer(&dir.0, &items, true), Outcome::Skipped, "not retried");
    }
}
