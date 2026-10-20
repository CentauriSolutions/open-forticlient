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

    static var connectAtLogin: Bool {
        AgentIntent(bundleID: Bundle.main.bundleIdentifier ?? "")
            .connectAtLogin(legacyEnabled: status == "enabled")
    }

    static func prepareConnect() throws {
        let intent = AgentIntent(bundleID: Bundle.main.bundleIdentifier ?? "")
        if intent.preferences() == nil {
            try intent.setConnectAtLogin(connectAtLogin)
        }
        try intent.request(connect: true)
    }

    static func setConnectAtLogin(_ enabled: Bool) throws {
        let intent = AgentIntent(bundleID: Bundle.main.bundleIdentifier ?? "")
        let previous = connectAtLogin
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

    // An app-bundled plist cannot contain a per-user absolute log path.
    // Redirect only the launchd-started supervisor; direct host commands keep
    // their terminal output.
    static func redirectSupervisorOutput() throws {
        guard ProcessInfo.processInfo.environment["OFTC_BUNDLED_AGENT"] == "1" else { return }
        let logDirectory = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Logs/OFTC", isDirectory: true)
        try FileManager.default.createDirectory(at: logDirectory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        let log = logDirectory.appendingPathComponent("agent.log")
        let descriptor = open(log.path, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW, 0o600)
        guard descriptor >= 0 else { throw AgentError.logUnavailable }
        defer { close(descriptor) }
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0,
              (metadata.st_mode & S_IFMT) == S_IFREG,
              metadata.st_uid == geteuid(),
              dup2(descriptor, STDOUT_FILENO) >= 0,
              dup2(descriptor, STDERR_FILENO) >= 0 else {
            throw AgentError.logUnavailable
        }
        setvbuf(stdout, nil, _IOLBF, 0)
        setvbuf(stderr, nil, _IONBF, 0)
    }

    private enum AgentError: LocalizedError {
        case unavailable(String)
        case logUnavailable

        var errorDescription: String? {
            switch self {
            case .unavailable(let status): return "OFTC login agent is \(status)"
            case .logUnavailable: return "Could not open the OFTC supervisor log"
            }
        }
    }
}
