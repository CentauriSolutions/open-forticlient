//! The supervisor's status record, `profiles/<id>/supervisor-status.json`.
//!
//! `{"phase","leaseID","processID","updated"}`, where `updated` is a JSON number of
//! seconds since 2001-01-01 UTC (Foundation's reference date, what the Swift
//! encoder writes for a `Date`), not a Unix time. The menu and `oftc` read it to say
//! what a supervisor is doing, so [`StatusStore::read`] only believes a record that a
//! live supervisor still stands behind.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::lease::{self, is_uuid, LOCK_FILE};
use crate::os;

const FILE_NAME: &str = "supervisor-status.json";
const MAX_BYTES: u64 = 4096;
/// Seconds between 1970-01-01 and 2001-01-01.
const REFERENCE_OFFSET: f64 = 978_307_200.0;
/// A record older than this is not described as current.
const MAX_AGE: f64 = 300.0;
/// A record this far in the future is a clock step, not a bug.
const MAX_SKEW: f64 = 5.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    Acquiring,
    Connecting,
    Connected,
    Recovering,
    Failed,
    Stopped,
}

impl Phase {
    pub fn as_str(self) -> &'static str {
        match self {
            Phase::Acquiring => "acquiring",
            Phase::Connecting => "connecting",
            Phase::Connected => "connected",
            Phase::Recovering => "recovering",
            Phase::Failed => "failed",
            Phase::Stopped => "stopped",
        }
    }

    /// Records of a supervisor that has finished stay readable for a while.
    fn is_terminal(self) -> bool {
        matches!(self, Phase::Failed | Phase::Stopped)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SupervisorStatus {
    pub phase: Phase,
    #[serde(rename = "leaseID")]
    pub lease_id: String,
    #[serde(rename = "processID")]
    pub process_id: i32,
    /// Seconds since 2001-01-01 UTC.
    pub updated: f64,
}

fn reference_seconds(time: SystemTime) -> f64 {
    let unix = match time.duration_since(UNIX_EPOCH) {
        Ok(after) => after.as_secs_f64(),
        Err(before) => -before.duration().as_secs_f64(),
    };
    unix - REFERENCE_OFFSET
}

/// The 2001-based seconds Swift's `JSONEncoder` writes for `time`.
pub(crate) fn encode_date(time: SystemTime) -> f64 {
    reference_seconds(time)
}

/// The inverse of [`encode_date`].
pub(crate) fn decode_date(seconds: f64) -> SystemTime {
    let unix = seconds + REFERENCE_OFFSET;
    if unix >= 0.0 {
        UNIX_EPOCH + Duration::from_secs_f64(unix)
    } else {
        UNIX_EPOCH - Duration::from_secs_f64(-unix)
    }
}

pub struct StatusStore {
    directory: PathBuf,
}

impl StatusStore {
    pub fn new(directory: &Path) -> StatusStore {
        StatusStore {
            directory: directory.to_owned(),
        }
    }

    /// Records that this process, holding lease `lease_id`, is in `phase`. Best
    /// effort, like the Swift writer: a failure leaves the previous record.
    pub fn publish(&self, phase: Phase, lease_id: &str, now: SystemTime) {
        self.write(phase, lease_id, std::process::id() as i32, now);
    }

    fn write(&self, phase: Phase, lease_id: &str, process_id: i32, now: SystemTime) {
        let record = SupervisorStatus {
            phase,
            lease_id: lease_id.to_owned(),
            process_id,
            updated: reference_seconds(now),
        };
        if let Ok(data) = serde_json::to_vec(&record) {
            let _ = lease::write_private(&self.directory, FILE_NAME, &data);
        }
    }

    /// The current record, or `None` if there is none worth believing: unreadable,
    /// oversized, not decodable, a lease id that is not a UUID, older than five
    /// minutes (or more than five seconds ahead of `now`). A finished supervisor's
    /// record (`failed`, `stopped`) stands on that. Any other phase also needs the
    /// lock file to hold this lease id, the process to exist, and the lock to be
    /// held: after a crash the record outlives its supervisor and must not read as
    /// live.
    pub fn read(&self, now: SystemTime) -> Option<SupervisorStatus> {
        let path = self.directory.join(FILE_NAME);
        let meta = fs::metadata(&path).ok()?;
        if meta.len() > MAX_BYTES {
            return None;
        }
        let record: SupervisorStatus = serde_json::from_slice(&fs::read(&path).ok()?).ok()?;
        if !is_uuid(&record.lease_id) {
            return None;
        }
        let age = reference_seconds(now) - record.updated;
        if !(-MAX_SKEW..=MAX_AGE).contains(&age) {
            return None;
        }
        if record.phase.is_terminal() {
            return Some(record);
        }
        let lock = self.directory.join(LOCK_FILE);
        let holds_lease = fs::read(&lock).is_ok_and(|bytes| bytes == record.lease_id.as_bytes());
        (holds_lease && os::process_alive(record.process_id) && lease::is_held(&lock))
            .then_some(record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lease::SupervisorLease;
    use crate::profile::testutil::{fixture, TempDir};

    /// What `SupervisorStatus` in the fixtures says is `updated`.
    const FIXTURE_UPDATED: f64 = 815509075.539563;

    fn at(seconds: f64) -> SystemTime {
        decode_date(seconds)
    }

    #[test]
    fn dates_count_from_2001() {
        // The Unix time of the reference date, and a known Swift value.
        assert_eq!(reference_seconds(UNIX_EPOCH), -REFERENCE_OFFSET);
        assert_eq!(
            reference_seconds(UNIX_EPOCH + Duration::from_secs(978_307_200)),
            0.0
        );
        let swift_time = UNIX_EPOCH + Duration::from_secs_f64(FIXTURE_UPDATED + REFERENCE_OFFSET);
        assert!((reference_seconds(swift_time) - FIXTURE_UPDATED).abs() < 1e-3);
        assert!((reference_seconds(decode_date(FIXTURE_UPDATED)) - FIXTURE_UPDATED).abs() < 1e-3);
    }

    /// A record the shipped Swift writer produced, decoded as written.
    #[test]
    fn decodes_what_swift_wrote() {
        let connected = fs::read(fixture("swift/supervisor/status-connected.json")).unwrap();
        let record: SupervisorStatus = serde_json::from_slice(&connected).unwrap();
        assert_eq!(
            record,
            SupervisorStatus {
                phase: Phase::Connected,
                lease_id: "A4DF24C9-D3A9-4D2E-896A-95AC0C2B535A".to_owned(),
                process_id: 4242,
                updated: FIXTURE_UPDATED,
            }
        );
    }

    /// Terminal phases stand alone; every other phase needs a live, locked lease.
    #[test]
    fn read_rules() {
        let dir = TempDir::new("status");
        let store = StatusStore::new(&dir.0);
        let now = at(FIXTURE_UPDATED + 10.0);
        let write = |phase: &str, lease: &str, pid: i32, updated: f64| {
            let text = format!(
                "{{\"phase\":\"{phase}\",\"leaseID\":\"{lease}\",\"processID\":{pid},\"updated\":{updated}}}"
            );
            fs::write(dir.0.join(FILE_NAME), text).unwrap();
        };
        let other = "11111111-2222-4333-8444-555555555555";
        let me = std::process::id() as i32;

        // No record yet.
        assert_eq!(store.read(now), None);

        // Terminal phases: only the id and the age matter.
        write("failed", other, 1, FIXTURE_UPDATED);
        assert_eq!(store.read(now).map(|r| r.phase), Some(Phase::Failed));
        write("stopped", other, 1, FIXTURE_UPDATED);
        assert_eq!(store.read(now).map(|r| r.phase), Some(Phase::Stopped));
        write("failed", "not-a-uuid", 1, FIXTURE_UPDATED);
        assert_eq!(store.read(now), None);
        write("failed", other, 1, FIXTURE_UPDATED);
        // Age: 300 s is still current, 301 s is not, 5 s ahead is, 6 s ahead is not.
        assert!(store.read(at(FIXTURE_UPDATED + 300.0)).is_some());
        assert_eq!(store.read(at(FIXTURE_UPDATED + 301.0)), None);
        assert!(store.read(at(FIXTURE_UPDATED - 5.0)).is_some());
        assert_eq!(store.read(at(FIXTURE_UPDATED - 6.0)), None);

        // A running phase needs the lock to hold the id, the process to exist and
        // the lock to be held.
        let lease = SupervisorLease::acquire(&dir.0).unwrap();
        let id = lease.id().to_owned();
        write("connected", &id, me, FIXTURE_UPDATED);
        assert_eq!(store.read(now).map(|r| r.phase), Some(Phase::Connected));
        write("connected", other, me, FIXTURE_UPDATED); // lease id mismatch
        assert_eq!(store.read(now), None);
        write("connected", &id, 0x7FFF_FFF0, FIXTURE_UPDATED); // no such process
        assert_eq!(store.read(now), None);
        drop(lease); // lock gone
        write("connected", &id, me, FIXTURE_UPDATED);
        assert_eq!(store.read(now), None);
        // Lock file with the right id but nobody holding it: a crashed supervisor.
        fs::write(dir.0.join(LOCK_FILE), &id).unwrap();
        assert_eq!(store.read(now), None);

        // Oversize and undecodable records.
        let pad = "x".repeat(5000);
        fs::write(
            dir.0.join(FILE_NAME),
            format!("{{\"phase\":\"failed\",\"leaseID\":\"{other}\",\"processID\":1,\"updated\":{FIXTURE_UPDATED},\"p\":\"{pad}\"}}"),
        )
        .unwrap();
        assert_eq!(store.read(now), None);
        fs::write(dir.0.join(FILE_NAME), "{\"phase\":\"flying\"}").unwrap();
        assert_eq!(store.read(now), None);
    }

    #[test]
    fn publish_writes_a_record_read_back_for_this_process() {
        let dir = TempDir::new("publish");
        let store = StatusStore::new(&dir.0);
        let lease = SupervisorLease::acquire(&dir.0).unwrap();
        let now = at(FIXTURE_UPDATED);
        store.publish(Phase::Connecting, lease.id(), now);
        let record = store.read(now).unwrap();
        assert_eq!(record.phase, Phase::Connecting);
        assert_eq!(record.process_id, std::process::id() as i32);
        // The shape Swift decodes: the key names and a numeric date.
        let text = fs::read_to_string(dir.0.join(FILE_NAME)).unwrap();
        let json: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(json["leaseID"], lease.id());
        assert!((json["updated"].as_f64().unwrap() - FIXTURE_UPDATED).abs() < 1e-3);
        // A new lease is not described by the old record.
        drop(lease);
        assert_eq!(store.read(now), None);
    }

    /// `fixtures/rust/supervisor` is what the Swift reader in `build.sh`
    /// (`check-host-compat.swift`) decodes, so it must equal what the writer produces.
    #[test]
    fn writes_the_record_the_swift_reader_checks() {
        let dir = TempDir::new("status-golden");
        let lease = "A4DF24C9-D3A9-4D2E-896A-95AC0C2B535A";
        // 2001-based 815509075 exactly, so the golden holds no rounding.
        let now = UNIX_EPOCH + Duration::from_secs(1_793_816_275);
        StatusStore::new(&dir.0).write(Phase::Failed, lease, 4242, now);
        let json =
            |p: &Path| serde_json::from_slice::<serde_json::Value>(&fs::read(p).unwrap()).unwrap();
        assert_eq!(
            json(&dir.0.join(FILE_NAME)),
            json(&fixture("rust/supervisor").join(FILE_NAME))
        );
    }
}
