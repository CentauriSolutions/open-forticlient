//! Inner IP byte counters and the `oftc.traffic.v1` reply. Ports
//! `TrafficStatistics.swift` (the provider half; the host's rate calculation is
//! not part of the provider). The wire format is in `docs/provider-messages.md`.
//!
//! The counters hold inner IP bytes accepted by the engine or the packet flow.
//! ESP, IKE, dropped packets and traffic outside OFTC are not counted.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrafficCounters {
    session_id: [u8; 16],
    received: u64,
    sent: u64,
}

impl TrafficCounters {
    /// A fresh counter pair with a new random session id, as Swift's `UUID()`.
    pub fn new() -> Result<Self, oftc_crypto::Error> {
        let mut id = oftc_crypto::random_array::<16>()?;
        id[6] = (id[6] & 0x0f) | 0x40;
        id[8] = (id[8] & 0x3f) | 0x80;
        Ok(Self { session_id: id, received: 0, sent: 0 })
    }

    pub fn received(&mut self, count: usize) {
        self.received = add(self.received, count);
    }

    pub fn sent(&mut self, count: usize) {
        self.sent = add(self.sent, count);
    }

    /// The JSON reply Swift's default `JSONEncoder` wrote, key for key.
    /// `uptime` is monotonic seconds; the host only ever subtracts two of them.
    pub fn snapshot_json(&self, uptime: f64) -> Vec<u8> {
        let id = self.session_id;
        let hex = |range: std::ops::Range<usize>| -> String {
            id[range].iter().map(|b| format!("{b:02X}")).collect()
        };
        format!(
            "{{\"version\":1,\"sessionID\":\"{}-{}-{}-{}-{}\",\"receivedBytes\":{},\"sentBytes\":{},\"uptime\":{}}}",
            hex(0..4), hex(4..6), hex(6..8), hex(8..10), hex(10..16),
            self.received, self.sent, uptime
        )
        .into_bytes()
    }
}

/// Saturating, and a zero count changes nothing.
fn add(total: u64, count: usize) -> u64 {
    total.saturating_add(u64::try_from(count).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json(counters: &TrafficCounters, uptime: f64) -> String {
        String::from_utf8(counters.snapshot_json(uptime)).unwrap()
    }

    #[test]
    fn counts_both_directions_and_saturates() {
        let mut counters = TrafficCounters::new().unwrap();
        counters.received(40);
        counters.received(0);
        counters.sent(1500);
        assert!(json(&counters, 1.0).contains("\"receivedBytes\":40,\"sentBytes\":1500,"));
        counters.received(usize::MAX);
        counters.received(usize::MAX);
        counters.sent(usize::MAX);
        counters.sent(1);
        let text = json(&counters, 1.0);
        assert!(text.contains(&format!("\"receivedBytes\":{},", u64::MAX)));
        assert!(text.contains(&format!("\"sentBytes\":{},", u64::MAX)));
    }

    #[test]
    fn the_snapshot_matches_the_documented_shape() {
        let mut counters = TrafficCounters::new().unwrap();
        counters.sent(7);
        let text = json(&counters, 12345.6);
        let id = &text[text.find("sessionID\":\"").unwrap() + 12..][..36];
        let groups: Vec<&str> = id.split('-').collect();
        assert_eq!(groups.iter().map(|g| g.len()).collect::<Vec<_>>(), [8, 4, 4, 4, 12]);
        assert!(id.bytes().all(|b| b == b'-' || b.is_ascii_digit() || (b'A'..=b'F').contains(&b)));
        assert!(groups[2].starts_with('4') && "89AB".contains(&groups[3][..1]));
        assert_eq!(
            text,
            format!(
                "{{\"version\":1,\"sessionID\":\"{id}\",\"receivedBytes\":0,\"sentBytes\":7,\"uptime\":12345.6}}"
            )
        );
        assert!(text.len() <= 4096, "the host rejects a reply over 4096 bytes");
    }

    #[test]
    fn each_connection_gets_its_own_session_id() {
        let (a, b) = (TrafficCounters::new().unwrap(), TrafficCounters::new().unwrap());
        assert_ne!(json(&a, 0.0), json(&b, 0.0));
    }
}
