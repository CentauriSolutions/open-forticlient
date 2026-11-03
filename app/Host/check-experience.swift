import Foundation

@main enum ExperienceCheck {
    static func main() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("oftc-experience-check-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = LaunchExperienceStore(directory: directory)
        precondition(store.shouldWelcome(build: "25", automatic: false))
        precondition(!store.shouldWelcome(build: "25", automatic: true))
        precondition(!store.shouldWelcome(build: "25", automatic: true, afterInstall: true))
        try store.acknowledge(build: "25")
        precondition(!store.shouldWelcome(build: "25", automatic: false))
        precondition(store.shouldWelcome(build: "25", automatic: false, afterInstall: true))
        precondition(store.shouldWelcome(build: "26", automatic: false))
        precondition(!store.shouldWelcome(build: "26", automatic: true))
        precondition(!FileManager.default.fileExists(atPath: directory.appendingPathComponent("connection-preferences.json").path))
        try Data("malformed".utf8).write(to: directory.appendingPathComponent("welcome.json"))
        precondition(store.shouldWelcome(build: "25", automatic: false))
        precondition(AppLaunchReason.isAutomatic(property: 0x6c676974))
        precondition(AppLaunchReason.isAutomatic(property: 0x73766974))
        precondition(!AppLaunchReason.isAutomatic(property: nil))
        precondition(!AppLaunchReason.isAutomatic(property: 0))

        let loginDefault = MenuLoginDefaultStore(directory: directory.appendingPathComponent("login"))
        precondition(!loginDefault.decided)
        try loginDefault.markDecided()
        precondition(loginDefault.decided)
        let mode = try FileManager.default.attributesOfItem(
            atPath: directory.appendingPathComponent("login/menu-login-default.json").path)[.posixPermissions] as? Int
        precondition(mode == 0o600)

        typealias Component = VPNComponentState
        precondition(Component.resolve(expected: "23", records: []) == .missing)
        precondition(Component.resolve(expected: "23", records: [.init(build: "20", enabled: true)]) == .updateRequired)
        precondition(Component.resolve(expected: "23", records: [
            .init(build: "23", enabled: true), .init(build: "20", enabled: true, uninstalling: true)
        ]) == .ready)
        precondition(Component.resolve(expected: "23", records: [
            .init(build: "20", enabled: true), .init(build: "23", enabled: false, awaitingApproval: true)
        ]) == .approval)
        precondition(Component.resolve(expected: "23", records: [.init(build: "23", enabled: false)]) != .ready)
        precondition(Component.resolve(expected: "23", records: [.init(build: "24", enabled: true)]) == .newer)
        precondition(Component.resolve(expected: "23", records: [
            .init(build: "23", enabled: true), .init(build: "20", enabled: true)
        ]) == .unavailable)
        precondition(Component.resolve(expected: "", records: [.init(build: "23", enabled: true)]) == .unavailable)
        precondition(Component.resolve(expected: "9", records: [.init(build: "10", enabled: true)]) == .newer)
        precondition(Component.canReplace(existing: "20", replacement: "23"))
        precondition(Component.canReplace(existing: "23", replacement: "23"))
        precondition(!Component.canReplace(existing: "24", replacement: "23"))

        for component in [Component.missing, .updateRequired, .approval, .checking, .unavailable, .newer, .ready] {
            let active = WelcomePresentation(upgrade: true, configured: true, active: true, component: component)
            precondition(active.action == .controls) // no provider change during an active session
            let fresh = WelcomePresentation(upgrade: false, configured: false, active: false, component: component)
            precondition(fresh.action == (component == .newer ? .check : .setup))
        }
        precondition(WelcomePresentation(upgrade: true, configured: true, active: false, component: .ready).action == .controls)
        precondition(WelcomePresentation(upgrade: true, configured: true, active: false, component: .updateRequired).action == .setup)
        precondition(WelcomePresentation(upgrade: true, configured: true, active: false, component: .checking).action == .wait)
        precondition(WelcomePresentation(upgrade: true, configured: true, active: false, component: .unavailable).action == .check)
        precondition(WelcomePresentation(upgrade: true, configured: true, active: false, component: .newer).action == .check)
        print("Launch, welcome, and provider-readiness checks passed (offline).")
    }
}
