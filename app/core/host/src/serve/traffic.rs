//! Traffic rates from `oftc.traffic.v1` replies: the host's port of the Swift
//! `TrafficRates` and of the menu's reply validation. The provider's half (the
//! counters and the reply) is `oftc_provider::traffic`.

use std::time::Duration;

use oftc_apple::manager::{VpnControl, VpnEntry, VpnStatus};
use serde::Deserialize;

use crate::lease::is_uuid;

pub const MESSAGE: &[u8] = b"oftc.traffic.v1";
/// How long one provider reply is waited for.
pub const REPLY_TIMEOUT: Duration = Duration::from_secs(3);
/// A reply larger than this is not a snapshot.
const MAX_REPLY: usize = 4096;
/// Two samples further apart than this (sleep, missed samples) give no rate.
const MAX_ELAPSED: f64 = 5.0;

/// The provider's reply.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub version: u32,
    #[serde(rename = "sessionID")]
    pub session_id: String,
    pub received_bytes: u64,
    pub sent_bytes: u64,
    /// Provider monotonic seconds; only differences mean anything.
    pub uptime: f64,
}

impl Snapshot {
    pub fn valid(&self) -> bool {
        self.version == 1 && self.uptime.is_finite() && self.uptime >= 0.0
    }
}

/// A reply as a validated snapshot: at most 4096 bytes, decodable (a UUID session
/// id, unsigned counters), version 1, a finite non-negative uptime.
pub fn decode(reply: &[u8]) -> Option<Snapshot> {
    if reply.len() > MAX_REPLY {
        return None;
    }
    let mut snapshot: Snapshot = serde_json::from_slice(reply).ok()?;
    if !is_uuid(&snapshot.session_id) {
        return None;
    }
    // Swift's `UUID` compares case-insensitively.
    snapshot.session_id.make_ascii_uppercase();
    snapshot.valid().then_some(snapshot)
}

#[derive(Debug, Default)]
pub struct TrafficRates {
    pub latest: Option<Snapshot>,
    pub receiving: Option<f64>,
    pub sending: Option<f64>,
}

impl TrafficRates {
    pub fn reset(&mut self) {
        *self = TrafficRates::default();
    }

    /// A missed measurement says nothing about the cumulative bytes: the last totals
    /// stay and only the rates go.
    pub fn mark_unavailable(&mut self) {
        self.receiving = None;
        self.sending = None;
    }

    pub fn ingest(&mut self, sample: Snapshot) {
        if !sample.valid() {
            self.reset();
            return;
        }
        self.receiving = None;
        self.sending = None;
        if let Some(previous) = &self.latest {
            let elapsed = sample.uptime - previous.uptime;
            // A new session, sleep, a stale reply or a counter reset must not make a
            // negative rate or a spike.
            if previous.session_id == sample.session_id
                && elapsed > 0.0
                && elapsed <= MAX_ELAPSED
                && sample.received_bytes >= previous.received_bytes
                && sample.sent_bytes >= previous.sent_bytes
            {
                self.receiving =
                    Some((sample.received_bytes - previous.received_bytes) as f64 / elapsed);
                self.sending = Some((sample.sent_bytes - previous.sent_bytes) as f64 / elapsed);
            }
        }
        self.latest = Some(sample);
    }
}

/// One measurement of `entry`: asks the provider, and either ingests the reply or,
/// when the entry is not connected before and after, the message fails or the reply
/// is not a valid snapshot, marks the rates unavailable (a disconnected entry also
/// forgets its totals, as the menu did). Returns whether a snapshot was ingested.
pub fn measure(vpn: &dyn VpnControl, entry: &VpnEntry, rates: &mut TrafficRates) -> bool {
    if vpn.status(entry) != VpnStatus::Connected {
        rates.reset();
        return false;
    }
    let snapshot = vpn
        .send_provider_message(entry, MESSAGE, REPLY_TIMEOUT)
        .ok()
        .and_then(|reply| decode(&reply));
    match snapshot {
        // A tunnel that went down while we waited belongs to no session.
        Some(snapshot) if vpn.status(entry) == VpnStatus::Connected => {
            rates.ingest(snapshot);
            true
        }
        _ => {
            rates.mark_unavailable();
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oftc_apple::manager::{MockVpn, VpnStatus};

    const A: &str = "11111111-2222-4333-8444-555555555555";
    const B: &str = "66666666-7777-4888-8999-AAAAAAAAAAAA";

    fn snap(session: &str, received: u64, sent: u64, uptime: f64) -> Snapshot {
        Snapshot {
            version: 1,
            session_id: session.into(),
            received_bytes: received,
            sent_bytes: sent,
            uptime,
        }
    }

    /// The Swift `check-menu.swift` rate cases, in order, with the `TrafficCounters`
    /// steps folded into the totals they produce.
    #[test]
    fn rate_cases() {
        let mut rates = TrafficRates::default();
        // counters: sent 1500, received 4000; zero and negative counts add nothing.
        rates.ingest(snap(A, 4000, 1500, 100.0));
        assert_eq!((rates.receiving, rates.sending), (None, None));
        rates.ingest(snap(A, 6000, 2500, 101.0));
        assert_eq!(
            (rates.receiving, rates.sending),
            (Some(2000.0), Some(1000.0))
        );
        // Rekey has no counter reset: the next sample remains in this session.
        rates.ingest(snap(A, 6000, 3000, 102.0));
        assert_eq!((rates.receiving, rates.sending), (Some(0.0), Some(500.0)));
        rates.mark_unavailable();
        assert_eq!((rates.receiving, rates.sending), (None, None));
        let latest = rates.latest.as_ref().unwrap();
        assert_eq!((latest.received_bytes, latest.sent_bytes), (6000, 3000));
        rates.ingest(snap(A, 6000, 3000, 103.0));
        assert_eq!((rates.receiving, rates.sending), (Some(0.0), Some(0.0))); // real idle
        rates.ingest(snap(A, 6000, 3000, 102.0)); // stale: time went backwards
        assert_eq!(rates.sending, None);
        rates.ingest(snap(A, 6000, 3000, 120.0));
        assert_eq!(rates.receiving, None); // sleep / missed samples
        rates.ingest(snap(B, 50, 0, 121.0)); // a new session
        assert_eq!(rates.receiving, None);
        assert_eq!(rates.latest.as_ref().unwrap().received_bytes, 50);
        // A new session whose counters are higher still gives no rate: the session
        // change alone is enough, with no rollback to blame.
        rates.ingest(snap(A, 100, 0, 121.5));
        rates.ingest(snap(B, 900, 0, 122.0));
        assert_eq!(rates.receiving, None);
        rates.ingest(snap(B, 10, 0, 122.5)); // counter rollback
        assert_eq!(rates.receiving, None);
        let mut wrong_version = snap(B, 10, 0, 123.0);
        wrong_version.version = 2;
        rates.ingest(wrong_version);
        assert!(rates.latest.is_none());
        rates.ingest(snap(B, 10, 0, f64::NAN));
        assert!(rates.latest.is_none());
        // Beyond the Swift cases: the edges of the elapsed window.
        rates.ingest(snap(A, 0, 0, 10.0));
        rates.ingest(snap(A, 5000, 0, 15.0));
        assert_eq!(rates.receiving, Some(1000.0)); // exactly five seconds still counts
        rates.ingest(snap(A, 5000, 0, 15.0));
        assert_eq!(rates.receiving, None); // zero elapsed
        rates.ingest(snap(A, 6000, 0, 20.5));
        assert_eq!(rates.receiving, None); // 5.5 s: past the window
    }

    /// What reaches `ingest` is only what the provider's reply decodes to.
    #[test]
    fn replies_are_validated_before_use() {
        let good = format!(
            r#"{{"version":1,"sessionID":"{A}","receivedBytes":5,"sentBytes":7,"uptime":1.5}}"#
        );
        let decoded = decode(good.as_bytes()).unwrap();
        assert_eq!((decoded.received_bytes, decoded.sent_bytes), (5, 7));
        // A lower-case session id is the same session.
        let lower = good.replace(A, &A.to_lowercase());
        assert_eq!(decode(lower.as_bytes()).unwrap().session_id, A);
        let oversize = format!("{good}{}", " ".repeat(4096));
        for bad in [
            oversize,
            good.replace("\"version\":1", "\"version\":2"),
            good.replace("\"uptime\":1.5", "\"uptime\":-1"),
            good.replace(A, "not-a-uuid"),
            good.replace("\"receivedBytes\":5", "\"receivedBytes\":-5"),
            "{}".into(),
        ] {
            assert_eq!(decode(bad.as_bytes()), None, "{bad}");
        }
    }

    /// The measure step against a scripted provider: replies that fail leave the
    /// totals and drop the rates; a tunnel that is not connected forgets everything.
    #[test]
    fn measuring_a_connected_entry() {
        let vpn = MockVpn::new();
        let mock = vpn.add_entry("p", Some("lab"), true);
        let entry = vpn.load_all().unwrap().remove(0);
        let reply = |received: u64, uptime: f64| {
            Ok(format!(
                r#"{{"version":1,"sessionID":"{A}","receivedBytes":{received},"sentBytes":0,"uptime":{uptime}}}"#
            )
            .into_bytes())
        };
        let mut rates = TrafficRates::default();
        // Not connected: nothing is asked.
        assert!(!measure(&vpn, &entry, &mut rates));
        assert!(mock.sent().is_empty());
        mock.set_status(VpnStatus::Connected);
        mock.push_reply(reply(100, 10.0));
        mock.push_reply(reply(300, 11.0));
        mock.push_reply(Ok(b"garbage".to_vec()));
        assert!(measure(&vpn, &entry, &mut rates));
        assert!(measure(&vpn, &entry, &mut rates));
        assert_eq!(rates.receiving, Some(200.0));
        assert!(!measure(&vpn, &entry, &mut rates));
        assert_eq!(rates.receiving, None);
        assert_eq!(rates.latest.as_ref().unwrap().received_bytes, 300);
        // No scripted reply left: the mock times out, as a silent provider would.
        assert!(!measure(&vpn, &entry, &mut rates));
        assert_eq!(mock.sent(), vec![MESSAGE.to_vec(); 4]);
        mock.set_status(VpnStatus::Disconnected);
        assert!(!measure(&vpn, &entry, &mut rates));
        assert!(rates.latest.is_none());
    }
}
