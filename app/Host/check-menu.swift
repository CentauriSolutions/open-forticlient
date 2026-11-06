import Foundation

@main enum MenuCheck {
    static func main() throws {
        let now = Date(timeIntervalSince1970: 10_000)
        // The host computes the row state; the menu only renames it (sign_in is "sign-in").
        precondition(MenuConnectionState(.signIn) == .signingIn && MenuConnectionState(.attention) == .attention)
        // The one row shown while the host cannot be reached, and what it offers.
        let down: [(HostAvailability, ServiceState, String?)] = [
            (.connecting, .starting, nil), (.ready, .ready, nil),
            (.unavailable(.notRunning), .notRunning, "Start service"),
            (.unavailable(.needsApproval), .needsApproval, "Open Login Items…"),
            (.unavailable(.updating), .updating, nil), (.unavailable(.unsupported("x")), .unsupported, nil),
        ]
        for (availability, service, button) in down {
            precondition(ServiceState(availability) == service && service.button == button)
            precondition((service.message == nil) == (service == .ready))
        }
        precondition(TrafficFormat.rate(nil) == "—")
        precondition(TrafficFormat.rate(0) == "0 B/s")
        precondition(TrafficFormat.bytes(1_200_000) == "1.2 MB")
        precondition(TrafficFormat.duration(since: now, now: now.addingTimeInterval(2538)) == "42m 18s")
        precondition(TrafficFormat.duration(since: nil) == "—")
        // One host counter numbers samples: a repeat (the same sample in a `traffic` event and again in
        // a `status` document) or an older one is dropped; a restarted host numbers from one again.
        func sample(_ seq: UInt64, rx: Double? = 100) -> HostTraffic {
            HostTraffic(session: "9f1c", rxBytes: seq * 10, txBytes: seq, rxRate: rx, txRate: 5, sampleSeq: seq)
        }
        var live = TunnelTraffic()
        precondition(live.ingest(sample(7), at: 1) && live.receiving == 100 && live.latest?.sampleSeq == 7)
        precondition(!live.ingest(sample(7, rx: 999), at: 2) && live.receiving == 100)
        precondition(!live.ingest(sample(6, rx: 999), at: 2) && live.history.points.count == 1)
        precondition(live.ingest(sample(8, rx: nil), at: 2) && live.receiving == nil && live.history.points.count == 2)
        live.hostReconnected()
        precondition(live.ingest(sample(1), at: 3) && live.latest?.sampleSeq == 1)
        live.markStale(at: 4)
        precondition(live.receiving == nil && live.latest?.sampleSeq == 1 && live.history.points.last?.receiving == nil)
        live.clear()
        precondition(live.latest == nil && live.history.points.isEmpty)

        var history = TrafficHistory()
        for second in 0...125 {
            history.record(session: "aaaa", receiving: Double(second), sending: Double(second) / 10, at: Double(second))
        }
        precondition(history.points.count == 61)
        precondition(history.points.first?.time == 65 && history.points.last?.time == 125)
        let liveTrace = RateSparkline(history: history.points, now: 125, receiving: true)
        precondition(liveTrace.segments.count == 1 && liveTrace.sampleCount == 61)
        precondition(liveTrace.segments[0].first?.x == 0 && liveTrace.segments[0].last?.x == 1)
        precondition(liveTrace.peak == 125)
        history.record(session: "aaaa", receiving: 99, sending: 99, at: 125)
        history.record(session: "aaaa", receiving: 99, sending: 99, at: 124)
        precondition(history.points.last?.receiving == 125) // late/duplicate sample ignored
        history.markUnavailable(at: 125.5)
        precondition(history.points.last?.receiving == nil)
        history.record(session: "aaaa", receiving: 0, sending: 0, at: 125.8)
        precondition(RateSparkline(history: history.points, now: 125.8, receiving: true).segments.map(\.count) == [60, 1])
        history.record(session: "bbbb", receiving: nil, sending: nil, at: 126)
        precondition(history.points.count == 1 && history.sessionID == "bbbb")
        precondition(RateSparkline(history: history.points, now: 126, receiving: true).sampleCount == 0)
        history.prune(now: 187)
        precondition(history.points.isEmpty)
        history.reset()
        precondition(history.sessionID == nil)
        for index in 0..<300 {
            history.record(session: "bbbb", receiving: 1, sending: 2, at: Double(index) / 10)
        }
        precondition(history.points.count == TrafficHistory.maximumSamples)
        history.record(session: "bbbb", receiving: .nan, sending: -1, at: 30)
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
        history.record(session: "bbbb", receiving: 10, sending: 20, at: 100)
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
        print("menu state mapping, formatting, bounded history and sparkline gap checks passed")
    }
}
