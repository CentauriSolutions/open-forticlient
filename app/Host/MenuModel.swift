import Foundation
import NetworkExtension

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

    static func resolve(status: NEVPNStatus?, configured: Bool,
                        phase: SupervisorPhase?, stopping: Bool = false) -> Self {
        if stopping { return .disconnecting }
        switch status {
        case .connected: return .connected
        case .connecting: return .connecting
        case .reasserting: return .reconnecting
        case .disconnecting: return .disconnecting
        default: break
        }
        switch phase {
        case .acquiring: return .signingIn
        case .connecting: return .connecting
        case .recovering: return .reconnecting
        case .failed: return .attention
        default: break
        }
        guard configured, status != .invalid else { return .setup }
        return .disconnected
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

struct MenuPresentation {
    var state: MenuConnectionState = .disconnected
    var description = "Ready when you are."
    var duration = "—"
    var receiving = "—"
    var sending = "—"
    var totals = "—"
    var history: [TrafficRatePoint] = []
    var historyTime: TimeInterval = 0
    var busy = false

    var action: String {
        switch state {
        case .connected: return "Disconnect"
        case .connecting, .signingIn, .reconnecting: return "Cancel connection"
        case .disconnecting: return "Disconnecting…"
        case .setup: return "Set up OFTC…"
        default: return "Connect"
        }
    }

    static func preview(_ state: MenuConnectionState) -> Self {
        var result = Self(state: state, description: state.detail)
        switch state {
        case .connected:
            result.description = "vpn.example.com"
            result.duration = "42m 18s"
            result.receiving = "1.2 MB/s"
            result.sending = "84 KB/s"
            result.totals = "842 MB / 96 MB"
            result.historyTime = 60
            let receive = [0.12, 0.15, 0.25, 0.9, 1.4, 0.85, 0.3, 0.18, 0.2, 0.55, 1.15, 0.6]
            let send = [12.0, 22, 60, 32, 18, 16, 10, 42, 74, 30, 15, 18]
            result.history = (0..<60).map { index in
                TrafficRatePoint(time: Double(index + 1),
                    receiving: index == 59 ? 1_200_000 : receive[index % receive.count] * 1_000_000,
                    sending: index == 59 ? 84_000 : send[index % send.count] * 1000)
            }
        default: break
        }
        return result
    }
}
