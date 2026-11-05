import Foundation
import NetworkExtension

@main enum MenuCheck {
    static func main() throws {
        let now = Date(timeIntervalSince1970: 10_000)
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("oftc-menu-check-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let intent = AgentIntent(bundleID: "test.oftc", directory: directory)
        // Upgrade fallback preserves an existing pre-menu agent. Once the
        // explicit preference exists, it governs. (Whether the agent starts a
        // supervisor is decided in Rust; its tests cover the request rows.)
        precondition(intent.connectAtLogin(legacyEnabled: true))
        precondition(!intent.connectAtLogin(legacyEnabled: false)) // new profiles start off
        try intent.setConnectAtLogin(false)
        precondition(!intent.connectAtLogin(legacyEnabled: true))
        try intent.setConnectAtLogin(true)
        precondition(intent.connectAtLogin(legacyEnabled: false))
        try Data("invalid".utf8).write(to: directory.appendingPathComponent("connection-preferences.json"))
        precondition(!intent.connectAtLogin(legacyEnabled: true)) // malformed preferences fail closed

        precondition(MenuConnectionState.resolve(status: .connected, configured: true,
                                                phase: .failed) == .connected)
        precondition(MenuConnectionState.resolve(status: .connected, configured: true,
                                                phase: .connected, stopping: true) == .disconnecting)
        precondition(MenuConnectionState.resolve(status: .disconnected, configured: true,
                                                phase: .acquiring) == .signingIn)
        precondition(MenuConnectionState.resolve(status: .disconnected, configured: true,
                                                phase: .recovering) == .reconnecting)
        precondition(MenuConnectionState.resolve(status: .disconnected, configured: true,
                                                phase: .stopped) == .disconnected)
        precondition(MenuConnectionState.resolve(status: nil, configured: false,
                                                phase: nil) == .setup)
        precondition(MenuConnectionState.resolve(status: .reasserting, configured: true,
                                                phase: .connected) == .reconnecting)
        precondition(MenuConnectionState.resolve(status: .invalid, configured: true,
                                                phase: nil) == .setup)

        var counters = TrafficCounters()
        counters.sent(1500)
        counters.received(4000)
        counters.sent(0)
        counters.received(-1)
        var rates = TrafficRates()
        rates.ingest(counters.snapshot(uptime: 100))
        precondition(rates.receiving == nil && rates.sending == nil)
        counters.sent(1000)
        counters.received(2000)
        rates.ingest(counters.snapshot(uptime: 101))
        precondition(rates.receiving == 2000 && rates.sending == 1000)
        // Rekey has no counter reset: the next sample remains in this session.
        counters.sent(500)
        rates.ingest(counters.snapshot(uptime: 102))
        precondition(rates.receiving == 0 && rates.sending == 500)
        rates.markUnavailable()
        precondition(rates.receiving == nil && rates.sending == nil)
        precondition(rates.latest?.receivedBytes == 6000 && rates.latest?.sentBytes == 3000)
        rates.ingest(counters.snapshot(uptime: 103))
        precondition(rates.receiving == 0 && rates.sending == 0) // real idle sample
        rates.ingest(counters.snapshot(uptime: 102))
        precondition(rates.sending == nil)
        rates.ingest(counters.snapshot(uptime: 120))
        precondition(rates.receiving == nil) // sleep / missed samples
        var next = TrafficCounters()
        next.received(50)
        rates.ingest(next.snapshot(uptime: 121))
        precondition(rates.receiving == nil && rates.latest?.receivedBytes == 50)
        rates.ingest(TrafficSnapshot(version: 1, sessionID: next.sessionID,
            receivedBytes: 10, sentBytes: 0, uptime: 122))
        precondition(rates.receiving == nil) // counter rollback
        rates.ingest(TrafficSnapshot(version: 2, sessionID: next.sessionID,
            receivedBytes: 10, sentBytes: 0, uptime: 123))
        precondition(rates.latest == nil)
        rates.ingest(TrafficSnapshot(version: 1, sessionID: next.sessionID,
            receivedBytes: 10, sentBytes: 0, uptime: .nan))
        precondition(rates.latest == nil)
        let data = try JSONEncoder().encode(counters.snapshot(uptime: 125))
        let decoded = try JSONDecoder().decode(TrafficSnapshot.self, from: data)
        precondition(decoded.sessionID == counters.sessionID && decoded.sentBytes == 3000)
        precondition(TrafficFormat.rate(nil) == "—")
        precondition(TrafficFormat.rate(0) == "0 B/s")
        precondition(TrafficFormat.bytes(1_200_000) == "1.2 MB")
        precondition(TrafficFormat.duration(since: now, now: now.addingTimeInterval(2538)) == "42m 18s")
        precondition(TrafficFormat.duration(since: nil) == "—")
        var history = TrafficHistory()
        for second in 0...125 {
            history.record(counters.snapshot(uptime: Double(second)),
                           receiving: Double(second), sending: Double(second) / 10, at: Double(second))
        }
        precondition(history.points.count == 61)
        precondition(history.points.first?.time == 65 && history.points.last?.time == 125)
        let liveTrace = RateSparkline(history: history.points, now: 125, receiving: true)
        precondition(liveTrace.segments.count == 1 && liveTrace.sampleCount == 61)
        precondition(liveTrace.segments[0].first?.x == 0 && liveTrace.segments[0].last?.x == 1)
        precondition(liveTrace.peak == 125)
        history.record(counters.snapshot(uptime: 125), receiving: 99, sending: 99, at: 125)
        history.record(counters.snapshot(uptime: 124), receiving: 99, sending: 99, at: 124)
        precondition(history.points.last?.receiving == 125) // late/duplicate sample ignored
        history.markUnavailable(at: 125.5)
        precondition(history.points.last?.receiving == nil)
        history.record(counters.snapshot(uptime: 125.8), receiving: 0, sending: 0, at: 125.8)
        precondition(RateSparkline(history: history.points, now: 125.8, receiving: true).segments.map(\.count) == [60, 1])
        history.record(next.snapshot(uptime: 126), receiving: nil, sending: nil, at: 126)
        precondition(history.points.count == 1 && history.sessionID == next.sessionID)
        precondition(RateSparkline(history: history.points, now: 126, receiving: true).sampleCount == 0)
        history.prune(now: 187)
        precondition(history.points.isEmpty)
        history.reset()
        precondition(history.sessionID == nil)
        for index in 0..<300 {
            history.record(counters.snapshot(uptime: Double(index) / 10), receiving: 1, sending: 2, at: Double(index) / 10)
        }
        precondition(history.points.count == TrafficHistory.maximumSamples)
        history.record(counters.snapshot(uptime: 30), receiving: .nan, sending: -1, at: 30)
        precondition(history.points.last?.receiving == nil && history.points.last?.sending == nil)

        let gaps = [
            TrafficRatePoint(time: 0, receiving: 0, sending: 100),
            TrafficRatePoint(time: 1, receiving: 1, sending: 200),
            TrafficRatePoint(time: 2, receiving: nil, sending: 300),
            TrafficRatePoint(time: 3, receiving: 2, sending: 400),
            TrafficRatePoint(time: 8, receiving: 4, sending: 500),
        ]
        let receiving = RateSparkline(history: gaps, now: 10, receiving: true)
        let sending = RateSparkline(history: gaps, now: 10, receiving: false)
        precondition(receiving.segments.map(\.count) == [2, 1, 1])
        precondition(sending.segments.map(\.count) == [4, 1])
        precondition(receiving.peak == 4 && sending.peak == 500) // independent scales
        precondition(receiving.segments[0][0].y == 0) // real idle sample retained
        for path in receiving.segments {
            for point in path { precondition((0...1).contains(point.x) && (0...1).contains(point.y)) }
        }
        precondition(RateSparkline(history: gaps, now: 70, receiving: true).segments.isEmpty)
        precondition(RateSparkline(history: gaps, now: .nan, receiving: true).segments.isEmpty)
        precondition(RateSparkline(history: gaps, now: -1, receiving: true).segments.isEmpty)
        // The history clock is independent of provider uptime and includes
        // sleep. Simulate a long pause while the provider's clock barely moves.
        history.record(counters.snapshot(uptime: 30.1), receiving: 10, sending: 20, at: 100)
        precondition(history.points.count == 1)
        let clockStart = TrafficHistoryClock.now
        precondition(TrafficHistoryClock.now >= clockStart)
        var first = TunnelPresentation(id: "c2", name: "Office VPN")
        var second = TunnelPresentation(id: "warehouse", name: "Warehouse")
        precondition(MenuPresentation().needsSetup && MenuPresentation().summary == "Set up your VPN")
        var menu = MenuPresentation(tunnels: [first, second])
        precondition(!menu.anyActive && !menu.anyConnected && menu.summary == "0 of 2 connected")
        first.state = .connected
        second.state = .signingIn
        menu = MenuPresentation(tunnels: [first, second])
        precondition(menu.anyActive && menu.anyConnected && !menu.anyAttention)
        precondition(menu.summary == "1 of 2 connected")
        second.state = .attention
        menu = MenuPresentation(tunnels: [first, second])
        precondition(menu.anyAttention && menu.summary == "1 of 2 connected, needs attention")
        precondition(first.action == "Disconnect" && TunnelPresentation(id: "x", name: "X").action == "Connect")
        precondition(MenuPresentation.preview(.setup).needsSetup)
        precondition(MenuPresentation.preview(.reconnecting).tunnels.count == 2)
        print("menu state, startup intent, traffic rates, bounded history and sparkline gap checks passed")
    }
}
