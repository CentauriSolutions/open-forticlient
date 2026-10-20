import AppKit

final class RateSparklineView: NSView {
    private let receiving: Bool
    private var trace = RateSparkline(history: [], now: 0, receiving: true)

    init(receiving: Bool) {
        self.receiving = receiving
        super.init(frame: NSRect(x: 0, y: 0, width: 76, height: 20))
        translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            widthAnchor.constraint(equalToConstant: 76),
            heightAnchor.constraint(equalToConstant: 20),
        ])
        setAccessibilityElement(true)
        setAccessibilityRole(.image)
        setAccessibilityLabel("\(receiving ? "Receiving" : "Sending") rate history, last 60 seconds")
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    func update(history: [TrafficRatePoint], now: TimeInterval) {
        trace = RateSparkline(history: history, now: now, receiving: receiving)
        let scale = TrafficFormat.rate(trace.peak)
        toolTip = trace.sampleCount == 0 ? "No recent samples" : "Last 60 seconds · scale 0–\(scale)"
        setAccessibilityValue(trace.sampleCount == 0 ? "No recent samples"
            : "\(trace.sampleCount) samples; peak \(scale); gaps indicate unavailable samples")
        needsDisplay = true
    }

    override func draw(_ dirtyRect: NSRect) {
        guard trace.sampleCount > 0 else { return }
        let plot = bounds.insetBy(dx: 3, dy: 3)
        func position(_ point: RateSparkline.Point) -> NSPoint {
            NSPoint(x: plot.minX + CGFloat(point.x) * plot.width,
                    y: plot.minY + CGFloat(point.y) * plot.height)
        }
        NSColor.labelColor.withAlphaComponent(0.65).setStroke()
        NSColor.labelColor.withAlphaComponent(0.65).setFill()
        for segment in trace.segments {
            guard let first = segment.first else { continue }
            if segment.count == 1 {
                let point = position(first)
                NSBezierPath(ovalIn: NSRect(x: point.x - 0.9, y: point.y - 0.9,
                                           width: 1.8, height: 1.8)).fill()
            } else {
                let path = NSBezierPath()
                path.lineWidth = 1.15
                path.lineJoinStyle = .round
                path.lineCapStyle = .round
                path.move(to: position(first))
                for point in segment.dropFirst() { path.line(to: position(point)) }
                path.stroke()
            }
        }
    }
}
