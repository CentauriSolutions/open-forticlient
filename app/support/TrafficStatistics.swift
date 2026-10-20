import Foundation

// Inner IP bytes accepted by the engine / packetFlow. ESP, IKE, dropped
// packets, and traffic outside OFTC are not included. Main-queue confined.
struct TrafficSnapshot: Codable {
    let version: Int
    let sessionID: UUID
    let receivedBytes: UInt64
    let sentBytes: UInt64
    let uptime: TimeInterval

    var valid: Bool { version == 1 && uptime.isFinite && uptime >= 0 }
}

struct TrafficCounters {
    let sessionID = UUID()
    private(set) var receivedBytes: UInt64 = 0
    private(set) var sentBytes: UInt64 = 0

    mutating func received(_ count: Int) {
        guard count > 0 else { return }
        let (sum, overflow) = receivedBytes.addingReportingOverflow(UInt64(count))
        receivedBytes = overflow ? .max : sum
    }

    mutating func sent(_ count: Int) {
        guard count > 0 else { return }
        let (sum, overflow) = sentBytes.addingReportingOverflow(UInt64(count))
        sentBytes = overflow ? .max : sum
    }

    func snapshot(uptime: TimeInterval = ProcessInfo.processInfo.systemUptime) -> TrafficSnapshot {
        TrafficSnapshot(version: 1, sessionID: sessionID,
            receivedBytes: receivedBytes, sentBytes: sentBytes, uptime: uptime)
    }
}

struct TrafficRates {
    private(set) var latest: TrafficSnapshot?
    private(set) var receiving: Double?
    private(set) var sending: Double?

    mutating func reset() { self = TrafficRates() }

    // A missed measurement says nothing about the connection's cumulative
    // bytes. Keep its last totals while marking the current rates unavailable.
    mutating func markUnavailable() {
        receiving = nil
        sending = nil
    }

    mutating func ingest(_ sample: TrafficSnapshot) {
        guard sample.valid else { reset(); return }
        receiving = nil
        sending = nil
        if let previous = latest, previous.sessionID == sample.sessionID {
            let elapsed = sample.uptime - previous.uptime
            // A new session, sleep, a stale response, or a counter reset must
            // not produce a negative rate or a synthetic traffic spike.
            if elapsed > 0, elapsed <= 5,
               sample.receivedBytes >= previous.receivedBytes,
               sample.sentBytes >= previous.sentBytes {
                receiving = Double(sample.receivedBytes - previous.receivedBytes) / elapsed
                sending = Double(sample.sentBytes - previous.sentBytes) / elapsed
            }
        }
        latest = sample
    }
}
