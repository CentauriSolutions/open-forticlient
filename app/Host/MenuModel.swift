import Foundation

enum MenuConnectionState: String, CaseIterable {
    case connected, disconnected, connecting, disconnecting
    case signingIn = "sign-in"
    case reconnecting, attention, setup

    var title: String {
        switch self {
        case .connected: return "Connected"
        case .disconnected: return "Disconnected"
        case .connecting: return "Connecting…"
        case .disconnecting: return "Disconnecting…"
        case .signingIn: return "Signing in…"
        case .reconnecting: return "Reconnecting…"
        case .attention: return "Needs attention"
        case .setup: return "Set up your VPN"
        }
    }

    var active: Bool {
        [.connected, .connecting, .disconnecting, .signingIn, .reconnecting].contains(self)
    }

    var detail: String {
        switch self {
        case .connected: return "OFTC VPN"
        case .disconnected: return "Ready when you are."
        case .signingIn: return "Complete sign-in in your browser if prompted."
        case .connecting: return "Establishing the VPN connection."
        case .disconnecting: return "Stopping the VPN and automatic recovery."
        case .reconnecting: return "Connection interrupted. Trying again."
        case .attention: return "Could not connect. Try again or check VPN settings."
        case .setup: return "Choose your VPN gateway and approve OFTC."
        }
    }

    /// The host computes the row state (core/host/src/serve/state.rs); this only maps it to the
    /// UI's text-bearing enum.
    init(_ state: HostConnectionState) {
        switch state {
        case .connected: self = .connected
        case .disconnected: self = .disconnected
        case .connecting: self = .connecting
        case .disconnecting: self = .disconnecting
        case .signIn: self = .signingIn
        case .reconnecting: self = .reconnecting
        case .attention: self = .attention
        case .setup: self = .setup
        }
    }
}

extension VPNComponentState {
    /// The host resolves the extension's state (core/host/src/serve/state.rs); the welcome and
    /// setup flows still speak this enum.
    init(_ state: HostComponentState) {
        switch state {
        case .checking: self = .checking
        case .ready: self = .ready
        case .missing: self = .missing
        case .updateRequired: self = .updateRequired
        case .approval: self = .approval
        case .newer: self = .newer
        case .unavailable: self = .unavailable
        }
    }
}

enum TrafficFormat {
    static func bytes(_ value: Double?) -> String {
        guard var value, value.isFinite, value >= 0 else { return "—" }
        let units = ["B", "KB", "MB", "GB", "TB", "PB", "EB"]
        var index = 0
        while value >= 1000 && index < units.count - 1 { value /= 1000; index += 1 }
        return String(format: index > 0 && value < 10 ? "%.1f %@" : "%.0f %@", value, units[index])
    }
    static func rate(_ value: Double?) -> String {
        guard value != nil else { return "—" }
        let formatted = bytes(value)
        return formatted == "—" ? formatted : formatted + "/s"
    }
    static func duration(since date: Date?, now: Date = Date()) -> String {
        guard let date else { return "—" }
        let elapsed = now.timeIntervalSince(date)
        guard elapsed.isFinite, elapsed >= 0 else { return "—" }
        let seconds = Int(min(elapsed, 365 * 86400))
        if seconds >= 3600 { return "\(seconds / 3600)h \((seconds % 3600) / 60)m" }
        if seconds >= 60 { return "\(seconds / 60)m \(seconds % 60)s" }
        return "\(seconds)s"
    }
}

// One profile's row in the menu: its own state, stats and startup choice.
struct TunnelPresentation {
    var id: String
    var name: String
    var state: MenuConnectionState = .disconnected
    var description = "Ready when you are."
    var duration = "—"
    var receiving = "—"
    var sending = "—"
    var totals = "—"
    var history: [TrafficRatePoint] = []
    var historyTime: TimeInterval = 0
    var autoStart = false
    var busy = false

    var action: String {
        switch state {
        case .connected: return "Disconnect"
        case .connecting, .signingIn, .reconnecting: return "Cancel"
        case .disconnecting: return "Disconnecting…"
        case .setup: return "Set up…"
        default: return "Connect"
        }
    }
}

// Whether the menu can reach the host, and the one row it shows when it cannot.
enum ServiceState: Equatable {
    case starting, ready, notRunning, needsApproval, updating, unsupported

    init(_ availability: HostAvailability) {
        switch availability {
        case .connecting: self = .starting
        case .ready: self = .ready
        case .unavailable(.notRunning): self = .notRunning
        case .unavailable(.needsApproval): self = .needsApproval
        case .unavailable(.updating): self = .updating
        case .unavailable(.unsupported): self = .unsupported
        }
    }

    var message: String? {
        switch self {
        case .ready: return nil
        case .starting: return "Connecting to OFTC's VPN service…"
        case .notRunning: return "OFTC's VPN service is not running"
        case .needsApproval:
            return "Allow OFTC in System Settings → General → Login Items & Extensions to start its VPN service."
        case .updating: return "OFTC is finishing an update…"
        case .unsupported: return "This version of OFTC cannot talk to its VPN service. Update OFTC."
        }
    }

    var button: String? {
        switch self {
        case .notRunning: return "Start service"
        case .needsApproval: return "Open Login Items…"
        default: return nil
        }
    }
}

struct MenuPresentation {
    var service = ServiceState.ready
    var tunnels: [TunnelPresentation] = []
    var busy = false
    var notice: String?
    var update: String?   // version of an available update, if one should be shown

    var anyActive: Bool { tunnels.contains { $0.state.active } }
    var anyConnected: Bool { tunnels.contains { $0.state == .connected } }
    var anyAttention: Bool { tunnels.contains { $0.state == .attention } }
    var needsSetup: Bool { tunnels.isEmpty }

    // One line for the status item's tooltip and accessibility label.
    var summary: String {
        if tunnels.isEmpty { return MenuConnectionState.setup.title }
        let connected = tunnels.filter { $0.state == .connected }.count
        if tunnels.count == 1 { return tunnels[0].state.title }
        var text = "\(connected) of \(tunnels.count) connected"
        if anyAttention { text += ", needs attention" }
        return text
    }

    static func preview(_ state: MenuConnectionState) -> Self {
        guard state != .setup else { return Self() }
        var first = TunnelPresentation(id: "c2", name: "Office VPN")
        first.state = .connected
        first.description = "vpn.office.example"
        first.duration = "42m 18s"
        first.receiving = "1.2 MB/s"
        first.sending = "84 KB/s"
        first.totals = "842 MB / 96 MB"
        first.autoStart = true
        first.historyTime = 60
        let receive: [Double] = [0.12, 0.15, 0.25, 0.9, 1.4, 0.85, 0.3, 0.18, 0.2, 0.55, 1.15, 0.6]
        let send: [Double] = [12, 22, 60, 32, 18, 16, 10, 42, 74, 30, 15, 18]
        var points: [TrafficRatePoint] = []
        for index in 0..<60 {
            let last = index == 59
            let rx: Double = last ? 1_200_000 : receive[index % receive.count] * 1_000_000
            let tx: Double = last ? 84_000 : send[index % send.count] * 1000
            points.append(TrafficRatePoint(time: Double(index + 1), receiving: rx, sending: tx))
        }
        first.history = points
        var second = TunnelPresentation(id: "warehouse", name: "Warehouse")
        second.state = state
        second.description = state == .connected ? "vpn.lab.example.com" : state.detail
        if state == .disconnected { second.description = "vpn.lab.example.com" }
        if state == .connected {
            second.duration = "6m 02s"
            second.receiving = "210 KB/s"
            second.sending = "32 KB/s"
            second.totals = "58 MB / 7.2 MB"
            second.historyTime = first.historyTime
            second.history = first.history.map {
                TrafficRatePoint(time: $0.time, receiving: $0.receiving.map { $0 / 6 },
                                 sending: $0.sending.map { $0 / 3 })
            }
        }
        return Self(tunnels: [first, second])
    }
}
