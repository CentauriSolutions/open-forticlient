//! What the supervisor is doing right now, written to a small file so
//! `oftc status` can answer "is my VPN up, and if not, what is it waiting for?"
//! without scraping logs. Also posts macOS notifications on the transitions a
//! user cares about (dropped, back up, needs sign-in).
//!
//! The file is plain `key=value` lines; it holds no secrets.

use std::fs;
use std::process::Command;

use crate::log::now_secs;

pub fn path() -> String {
    format!(
        "{}/Library/Application Support/open-forticlient/state",
        std::env::var("HOME").unwrap_or_default()
    )
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Phase {
    /// Browser SSO tab is open, waiting for the login to complete.
    SigningIn,
    /// SSO done; CONNECT sent, waiting for the daemon to bring the tunnel up.
    Connecting,
    Up,
    /// Waiting out a backoff before the next attempt.
    Retrying,
    /// Nobody at the keyboard; waiting for the user to come back.
    WaitingForUser,
    /// The network can't carry the tunnel (IPv6-only/NAT64); waiting for it to change.
    UnusableNetwork,
}

impl Phase {
    pub fn as_str(self) -> &'static str {
        match self {
            Phase::SigningIn => "signing-in",
            Phase::Connecting => "connecting",
            Phase::Up => "up",
            Phase::Retrying => "retrying",
            Phase::WaitingForUser => "waiting-for-user",
            Phase::UnusableNetwork => "unusable-network",
        }
    }
}

/// Supervisor state, persisted on every change.
#[derive(Default)]
pub struct State {
    pub pid: u32,
    pub phase: Option<Phase>,
    /// When the current phase began.
    pub since: i64,
    /// Drops of an established tunnel since this supervisor started.
    pub drops: u32,
    pub last_drop: Option<(i64, String)>,
}

impl State {
    pub fn new() -> State {
        State { pid: std::process::id(), ..Default::default() }
    }

    pub fn set(&mut self, phase: Phase) {
        if self.phase != Some(phase) {
            self.phase = Some(phase);
            self.since = now_secs();
            self.save();
        }
    }

    pub fn dropped(&mut self, why: &str) {
        self.drops += 1;
        self.last_drop = Some((now_secs(), why.to_string()));
        self.save();
    }

    fn save(&self) {
        let mut s = format!(
            "pid={}\nphase={}\nsince={}\ndrops={}\n",
            self.pid,
            self.phase.map(Phase::as_str).unwrap_or(""),
            self.since,
            self.drops
        );
        if let Some((t, why)) = &self.last_drop {
            s += &format!("last_drop={t}\nlast_drop_reason={}\n", why.replace('\n', " "));
        }
        // Write-then-rename so `status` never reads a torn file. Best effort:
        // failing to record state must never take the tunnel down.
        let tmp = format!("{}.tmp", path());
        if fs::write(&tmp, s).is_ok() {
            let _ = fs::rename(&tmp, path());
        }
    }
}

/// Parsed state file, for `oftc status`.
pub struct Snapshot {
    pub pid: u32,
    pub phase: String,
    pub since: i64,
    pub drops: u32,
    pub last_drop: Option<(i64, String)>,
}

pub fn load() -> Option<Snapshot> {
    let text = fs::read_to_string(path()).ok()?;
    let get = |k: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(k).and_then(|r| r.strip_prefix('=')))
            .map(str::to_string)
    };
    let last_drop = match (get("last_drop").and_then(|t| t.parse().ok()), get("last_drop_reason")) {
        (Some(t), Some(r)) => Some((t, r)),
        _ => None,
    };
    Some(Snapshot {
        pid: get("pid")?.parse().ok()?,
        phase: get("phase").unwrap_or_default(),
        since: get("since").and_then(|s| s.parse().ok()).unwrap_or(0),
        drops: get("drops").and_then(|s| s.parse().ok()).unwrap_or(0),
        last_drop,
    })
}

/// Whether the process that wrote the snapshot is still alive.
pub fn alive(pid: u32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Post a macOS notification. Best effort; disabled with OFTC_NOTIFY=0.
pub fn notify(title: &str, body: &str) {
    if std::env::var("OFTC_NOTIFY").is_ok_and(|v| v == "0") {
        return;
    }
    let q = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
    let script = format!("display notification \"{}\" with title \"{}\"", q(body), q(title));
    let _ = Command::new("osascript").args(["-e", &script]).status();
}

/// "3m 12s" / "2h 05m" / "4d 1h".
pub fn human_duration(secs: i64) -> String {
    let s = secs.max(0);
    match s {
        0..=59 => format!("{s}s"),
        60..=3599 => format!("{}m {:02}s", s / 60, s % 60),
        3600..=86399 => format!("{}h {:02}m", s / 3600, (s % 3600) / 60),
        _ => format!("{}d {}h", s / 86400, (s % 86400) / 3600),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(human_duration(5), "5s");
        assert_eq!(human_duration(192), "3m 12s");
        assert_eq!(human_duration(7500), "2h 05m");
        assert_eq!(human_duration(90000), "1d 1h");
    }
}
