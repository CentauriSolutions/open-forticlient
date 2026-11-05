import Darwin
import Foundation
import ServiceManagement

enum OFTCAgentService {
    static let plistName = "com.chris.openforticlient.oftc.agent.plist"

    private static var service: SMAppService {
        SMAppService.agent(plistName: plistName)
    }

    static var status: String {
        switch service.status {
        case .notRegistered: return "not-registered"
        case .enabled: return "enabled"
        case .requiresApproval: return "requires-approval"
        case .notFound: return "not-found"
        @unknown default: return "unknown"
        }
    }

    static func register() throws {
        switch service.status {
        case .enabled:
            break
        case .notRegistered, .notFound:
            try service.register()
        case .requiresApproval:
            throw AgentError.unavailable(status)
        @unknown default:
            throw AgentError.unavailable(status)
        }
        guard service.status == .enabled else {
            throw AgentError.unavailable(status)
        }
        let enable = Process()
        enable.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        enable.arguments = ["enable", "gui/\(getuid())/com.chris.openforticlient.oftc.agent"]
        enable.standardOutput = FileHandle.nullDevice
        enable.standardError = FileHandle.nullDevice
        try enable.run()
        enable.waitUntilExit()
        guard enable.terminationStatus == 0 else { throw AgentError.unavailable("disabled") }
    }

    static func unregister() throws {
        switch service.status {
        case .notRegistered, .notFound:
            return
        case .enabled, .requiresApproval:
            try service.unregister()
        @unknown default:
            throw AgentError.unavailable(status)
        }
    }

    static func intent(for entry: OFTCProfileEntry) -> AgentIntent {
        AgentIntent(bundleID: Bundle.main.bundleIdentifier ?? "", directory: entry.directory)
    }

    // The migrated original profile inherits an already registered agent's
    // intent; every other profile starts off.
    static func connectAtLogin(_ entry: OFTCProfileEntry) -> Bool {
        intent(for: entry).connectAtLogin(
            legacyEnabled: entry.profile.adoptsUnkeyedVPNEntry == true && status == "enabled")
    }

    static func setConnectAtLogin(_ enabled: Bool, for entry: OFTCProfileEntry) throws {
        let intent = intent(for: entry)
        let previous = connectAtLogin(entry)
        try intent.setConnectAtLogin(enabled)
        if enabled && status != "enabled" {
            // Register for future logins without starting SSO right now.
            try intent.request(connect: false)
            do { try register() }
            catch {
                intent.cancelRequest()
                try? intent.setConnectAtLogin(previous)
                throw error
            }
        } else if enabled {
            try register() // Clear a launchd disabled override without starting SSO.
        }
    }

    private enum AgentError: LocalizedError {
        case unavailable(String)

        var errorDescription: String? {
            switch self {
            case .unavailable(let status): return "OFTC login agent is \(status)"
            }
        }
    }
}
