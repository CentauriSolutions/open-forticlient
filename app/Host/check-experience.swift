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

        typealias Component = VPNComponentState

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
        try checkUpdateStore()
        print("Launch, welcome, update record and component checks passed (offline).")
    }
    // The host fetches the feed and decides whether a release is newer (cargo test); the UI keeps
    // only its own record: on by default, at most a check a day, one skipped version.
    static func checkUpdateStore() throws {
        let page = URL(string: "https://example.com/oftc/releases/tag/v1.2.1")!
        let offer = UpdateOffer(version: "1.2.1", page: page)
        precondition(UpdateOffer(HostUpdateOffer(version: "1.2.1", page: page.absoluteString)) == offer)
        for unsafe in ["http://example.com/r", "file:///etc/passwd", "https:///x", "not a url"] {
            precondition(UpdateOffer(HostUpdateOffer(version: "9", page: unsafe)) == nil, unsafe)
        }
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("oftc-update-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = UpdateStore(directory: directory)
        let now = Date(timeIntervalSince1970: 2_000_000_000)
        precondition(store.automatic && store.isDue(now: now))
        store.markChecked(at: now)
        precondition(!store.isDue(now: now.addingTimeInterval(3600)))
        precondition(store.isDue(now: now.addingTimeInterval(UpdateStore.interval + 1)))
        precondition(store.isDue(now: now.addingTimeInterval(-60))) // clock went backwards
        store.automatic = false
        precondition(!store.automatic && !store.isDue(now: now.addingTimeInterval(10 * UpdateStore.interval)))
        store.automatic = true
        precondition(store.shouldShow(offer))
        store.skip("1.2.1")
        precondition(!store.shouldShow(offer))
        precondition(store.shouldShow(UpdateOffer(version: "1.2.2", page: page)))
        let mode = try FileManager.default.attributesOfItem(
            atPath: directory.appendingPathComponent("update.json").path)[.posixPermissions] as? Int
        precondition(mode == 0o600)
        try Data("garbage".utf8).write(to: directory.appendingPathComponent("update.json"))
        precondition(store.automatic && store.skippedVersion == nil)
    }
}
