//! Is someone at the keyboard? Used by the supervisor to avoid opening SSO
//! browser tabs into an empty room: an unanswered tab times out, and retrying
//! on a timer just stacks up dead tabs until the user returns.
//!
//! Both signals come from `ioreg` (no deps, no entitlements):
//!   - `HIDIdleTime` on IOHIDSystem: nanoseconds since the last keyboard/mouse/
//!     trackpad event.
//!   - `CGSSessionScreenIsLocked` in the Root node's IOConsoleUsers: present
//!     (=Yes) only while the login session's screen is locked.

use std::process::Command;
use std::time::Duration;

/// Recent-input window that counts as "present". Generous so reading without
/// touching anything still counts; the screen lock covers actually walking away.
const ACTIVE_WITHIN: Duration = Duration::from_secs(300);
const POLL: Duration = Duration::from_secs(5);

/// Time since the last HID input, or None if it couldn't be read.
pub fn idle() -> Option<Duration> {
    let out = Command::new("ioreg").args(["-c", "IOHIDSystem", "-d", "4"]).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text.lines().find(|l| l.contains("\"HIDIdleTime\""))?;
    let ns: u64 = line.rsplit('=').next()?.trim().parse().ok()?;
    Some(Duration::from_nanos(ns))
}

/// Whether the console session's screen is locked (false if unknown).
pub fn screen_locked() -> bool {
    Command::new("ioreg")
        .args(["-n", "Root", "-d1"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("\"CGSSessionScreenIsLocked\"=Yes"))
        .unwrap_or(false)
}

/// Unlocked and touched recently. If idle time is unreadable, assume present so
/// we fail toward reconnecting rather than parking forever.
pub fn user_present() -> bool {
    !screen_locked() && idle().is_none_or(|d| d < ACTIVE_WITHIN)
}

/// Block until `user_present()`.
pub fn wait_for_user() {
    while !user_present() {
        std::thread::sleep(POLL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // macOS-only crate: ioreg is always there, so both signals must parse.
    #[test]
    fn reads_idle_and_lock_state() {
        assert!(idle().is_some(), "HIDIdleTime not found in ioreg output");
        let _ = screen_locked();
    }
}
