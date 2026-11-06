import Foundation

enum VPNComponentState: Equatable {
    case checking, ready, missing, updateRequired, approval, newer, unavailable

    var needsSetup: Bool { [.missing, .updateRequired, .approval].contains(self) }

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

    /// `profilesExist`: profiles are on disk although none is `configured` (their VPN entries are
    /// gone, as after an uninstall and reinstall), so setup finishes them and asks for no form.
    init(upgrade: Bool, configured: Bool, active: Bool, component: VPNComponentState, profilesExist: Bool = false) {
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
        } else if !configured && profilesExist {
            heading = "Finish setting up your VPN"
            detail = "Your saved VPN settings are still here, but macOS needs them added back. Finishing setup asks for no details and starts no sign-in."
            button = "Finish setup"
            action = .setup
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
// Whether the first-run choice for "Launch OFTC at login" has been made. A fresh
// install turns it on so the tray icon is there after every login; an upgrade
// leaves whatever the user had. Either way it is decided once, and never again,
// so turning it off in Settings stays off.
struct MenuLoginDefaultStore {
    let directory: URL
    private var url: URL { directory.appendingPathComponent("menu-login-default.json") }
    var decided: Bool { FileManager.default.fileExists(atPath: url.path) }

    func markDecided() throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        try Data("{}".utf8).write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
}

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

/// What the host's `check_update` found: a newer release and its https page, which the app opens
/// in the browser. Nothing is downloaded or run.
struct UpdateOffer: Equatable {
    let version: String
    let page: URL

    init?(_ offer: HostUpdateOffer) {
        guard let url = URL(string: offer.page), url.scheme == "https", url.host?.isEmpty == false else { return nil }
        version = offer.version
        page = url
    }

    init(version: String, page: URL) {
        self.version = version
        self.page = page
    }
}

// UI-private, like the records above: the host fetches the feed (`check_update`); whether to check,
// when we last did, and which version the user skipped.
struct UpdateStore {
    private struct Record: Codable {
        var lastChecked: Date?
        var skippedVersion: String?
        var automatic: Bool?
    }

    let directory: URL
    static let interval: TimeInterval = 24 * 60 * 60
    private var url: URL { directory.appendingPathComponent("update.json") }

    private var record: Record {
        get {
            guard let data = try? Data(contentsOf: url), data.count <= 4096,
                  let value = try? JSONDecoder().decode(Record.self, from: data) else { return Record() }
            return value
        }
        nonmutating set {
            try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                     attributes: [.posixPermissions: 0o700])
            guard let data = try? JSONEncoder().encode(newValue) else { return }
            try? data.write(to: url, options: .atomic)
            try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        }
    }

    var automatic: Bool {
        get { record.automatic ?? true }
        nonmutating set { var value = record; value.automatic = newValue; record = value }
    }
    var skippedVersion: String? { record.skippedVersion }
    var lastChecked: Date? { record.lastChecked }

    func skip(_ version: String) { var value = record; value.skippedVersion = version; record = value }
    func markChecked(at date: Date = Date()) { var value = record; value.lastChecked = date; record = value }

    func isDue(now: Date = Date()) -> Bool {
        guard automatic else { return false }
        guard let last = lastChecked else { return true }
        return now.timeIntervalSince(last) >= Self.interval || last > now
    }

    func shouldShow(_ offer: UpdateOffer) -> Bool { skippedVersion != offer.version }
}
