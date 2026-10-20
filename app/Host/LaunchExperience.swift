import Foundation

enum VPNComponentState: Equatable {
    case checking, ready, missing, updateRequired, approval, newer, unavailable

    struct Record {
        var build: String
        var enabled: Bool
        var awaitingApproval: Bool = false
        var uninstalling: Bool = false
    }

    static func resolve(expected: String, records: [Record]) -> Self {
        guard !expected.isEmpty else { return .unavailable }
        let current = records.filter { !$0.uninstalling }
        let enabled = current.filter(\.enabled)
        guard enabled.count <= 1 else { return .unavailable }
        if let active = enabled.first {
            if active.build == expected { return .ready }
            if active.build.compare(expected, options: .numeric) == .orderedDescending { return .newer }
            return current.contains(where: { $0.build == expected && $0.awaitingApproval })
                ? .approval : .updateRequired
        }
        if current.contains(where: { $0.build.compare(expected, options: .numeric) == .orderedDescending }) {
            return .newer
        }
        if current.contains(where: { $0.build == expected && $0.awaitingApproval }) { return .approval }
        return current.isEmpty ? .missing : .updateRequired
    }

    var needsSetup: Bool { [.missing, .updateRequired, .approval].contains(self) }

    static func canReplace(existing: String, replacement: String) -> Bool {
        replacement.compare(existing, options: .numeric) != .orderedAscending
    }

    var detail: String {
        switch self {
        case .checking: return "Checking the VPN component…"
        case .ready: return "The VPN component is ready."
        case .missing: return "Finish setup and approve OFTC before connecting."
        case .updateRequired: return "Update the VPN component to finish installing OFTC. Your saved VPN settings are kept."
        case .approval: return "In System Settings → Login Items & Extensions, click ⓘ next to OFTC and turn on Network Extension, then return to finish setup."
        case .newer: return "A newer VPN component is installed. Use the latest OFTC installer to continue."
        case .unavailable: return "Could not check the VPN component. Try checking again."
        }
    }
}

struct WelcomePresentation {
    enum Action: Equatable { case setup, controls, check, wait }
    var title: String
    var heading: String
    var detail: String
    var button: String
    var action: Action

    init(upgrade: Bool, configured: Bool, active: Bool, component: VPNComponentState) {
        title = upgrade ? "OFTC is updated" : "Welcome to OFTC"
        if active {
            heading = "Your VPN is running"
            detail = "Open VPN controls to see your connection, traffic, and Disconnect. Any VPN component update can wait until you disconnect."
            button = "Open VPN controls"
            action = .controls
        } else if component == .newer {
            heading = "A newer OFTC version is needed"
            detail = component.detail
            button = "Check again"
            action = .check
        } else if !configured {
            heading = "Set up your VPN"
            detail = "Choose your VPN profile and approve OFTC when macOS asks. Then choose Connect in OFTC and sign in with your browser."
            button = "Set up OFTC"
            action = .setup
        } else {
            detail = component.detail
            switch component {
            case .ready:
                heading = "You're ready to connect"
                detail = "Your saved VPN settings are ready. Open VPN controls and choose Connect, then complete browser sign-in if prompted."
                button = "Open VPN controls"
                action = .controls
            case .checking:
                heading = "Checking your setup"
                button = "Checking…"
                action = .wait
            case .missing, .approval:
                heading = "Finish setting up your VPN"
                button = "Continue setup"
                action = .setup
            case .updateRequired:
                heading = "Finish updating your VPN"
                button = "Update VPN component"
                action = .setup
            case .newer:
                heading = "A newer OFTC version is needed"
                button = "Check again"
                action = .check
            case .unavailable:
                heading = "Check your VPN setup"
                button = "Check again"
                action = .check
            }
        }
    }
}

enum AppLaunchReason {
    // Launch Apple Event Constants: keyAEPropData carries 'lgit' or 'svit'.
    static func isAutomatic(property: UInt32?) -> Bool {
        property == 0x6c676974 || property == 0x73766974
    }
}

// This record contains UI acknowledgement only. It grants no connection,
// service-registration, or extension-activation permission.
struct LaunchExperienceStore {
    private struct Record: Codable { let acknowledgedBuild: String }
    let directory: URL
    private var url: URL { directory.appendingPathComponent("welcome.json") }

    var acknowledgedBuild: String? {
        guard let data = try? Data(contentsOf: url), data.count <= 4096 else { return nil }
        return (try? JSONDecoder().decode(Record.self, from: data))?.acknowledgedBuild
    }

    func shouldWelcome(build: String, automatic: Bool, afterInstall: Bool = false) -> Bool {
        !automatic && (afterInstall || acknowledgedBuild != build)
    }

    func acknowledge(build: String) throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        try JSONEncoder().encode(Record(acknowledgedBuild: build)).write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
}
