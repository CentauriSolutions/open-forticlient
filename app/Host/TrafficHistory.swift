import Foundation

enum TrafficHistoryClock {
    private static let clock = ContinuousClock()
    private static let origin = clock.now
    static var now: TimeInterval {
        // ContinuousClock includes sleep, so a minute-old graph expires even
        // when the Mac sleeps. The host derives the rates.
        let start = origin
        let elapsed = start.duration(to: clock.now).components
        return Double(elapsed.seconds) + Double(elapsed.attoseconds) / 1e18
    }
}

struct TrafficRatePoint {
    let time: TimeInterval
    let receiving: Double?
    let sending: Double?
}

struct TrafficHistory {
    static let duration: TimeInterval = 60
    static let maximumSamples = 120
    /// The host's short id of the provider connection the points belong to.
    private(set) var sessionID: String?
    private(set) var points: [TrafficRatePoint] = []

    mutating func reset() { self = TrafficHistory() }

    mutating func record(session: String, receiving: Double?, sending: Double?, at time: TimeInterval) {
        guard time.isFinite, time >= 0 else { return }
        if sessionID != session {
            reset()
            sessionID = session
        }
        guard points.last.map({ time > $0.time }) ?? true else { return }
        func valid(_ rate: Double?) -> Double? {
            guard let rate, rate.isFinite, rate >= 0 else { return nil }
            return rate
        }
        points.append(TrafficRatePoint(time: time,
            receiving: valid(receiving), sending: valid(sending)))
        prune(now: time)
        if points.count > Self.maximumSamples {
            points.removeFirst(points.count - Self.maximumSamples)
        }
    }

    mutating func prune(now: TimeInterval) {
        guard now.isFinite else { return }
        points.removeAll { $0.time < now - Self.duration }
    }

    mutating func markUnavailable(at time: TimeInterval) {
        guard sessionID != nil, time.isFinite, time >= 0,
              points.last.map({ time > $0.time }) ?? true else { return }
        points.append(TrafficRatePoint(time: time, receiving: nil, sending: nil))
        prune(now: time)
        if points.count > Self.maximumSamples {
            points.removeFirst(points.count - Self.maximumSamples)
        }
    }
}

// Unit coordinates keep the drawing independent of view size. A nil rate or
// a missing sampling interval breaks the trace instead of inventing traffic.
struct RateSparkline {
    struct Point { let x: Double; let y: Double }
    let segments: [[Point]]
    let peak: Double
    let sampleCount: Int

    init(history: [TrafficRatePoint], now: TimeInterval, receiving: Bool) {
        guard now.isFinite else { segments = []; peak = 0; sampleCount = 0; return }
        let start = now - TrafficHistory.duration
        let points = history.filter { $0.time >= start && $0.time <= now }
        func value(_ point: TrafficRatePoint) -> Double? {
            guard let value = receiving ? point.receiving : point.sending,
                  value.isFinite, value >= 0 else { return nil }
            return value
        }
        let values = points.compactMap(value)
        peak = values.max() ?? 0
        sampleCount = values.count
        let ceiling = max(1, peak) // A real zero rate is a flat baseline.
        var paths: [[Point]] = []
        var segment: [Point] = []
        var previousTime: TimeInterval?
        for point in points {
            let rate = value(point)
            let gap = previousTime.map { point.time - $0 > 2.5 || point.time <= $0 } ?? false
            if rate == nil || gap {
                if !segment.isEmpty { paths.append(segment) }
                segment = []
            }
            if let rate {
                segment.append(Point(x: (point.time - start) / TrafficHistory.duration,
                                     y: rate / ceiling))
            }
            previousTime = point.time
        }
        if !segment.isEmpty { paths.append(segment) }
        segments = paths
    }
}
