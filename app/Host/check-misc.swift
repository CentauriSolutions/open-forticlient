import Foundation

// What is left of the old supervisor check once the supervisor, its lease, the SAML lock
// and gateway trust moved to Rust (cargo test): the Swift profile reader the setup window
// still uses, and the launcher alias and update halves that stay Swift.
@main enum MiscCheck {
    static func main() throws {
        try checkProfiles()
        try checkLauncherAlias()
        try checkUpdates()
        print("profile registry, launcher alias and update checks passed")
    }

    static func checkProfiles() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("oftc-registry-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: root) }
        precondition(OFTCProfileScope.slug("Office VPN") == "office-vpn")
        precondition(OFTCProfileScope.slug("  Warehouse!! ") == "warehouse")
        precondition(OFTCProfileScope.slug("✓✓") == "vpn")
        precondition(OFTCProfileScope.slug(String(repeating: "a", count: 80)).utf8.count == 32)
        precondition(OFTCProfileScope.uniqueID("c2", taken: ["c2"]) == "c2-2")
        precondition(OFTCProfileScope.isValidID("office-vpn"))
        for bad in ["", "Office", "-c2", "c2-", "a/b", "..", String(repeating: "a", count: 33)] {
            precondition(!OFTCProfileScope.isValidID(bad))
        }

        // The original single-profile layout migrates into profiles/<id>/ and
        // keeps its login preference file.
        let legacy = try OFTCProfileStore(bundleID: "test.oftc", directory: root)
        try legacy.save(try OFTCProfile(gateway: "vpn.office.example", samlPort: 9443))
        try Data("{\"connectAtLogin\":true}".utf8)
            .write(to: root.appendingPathComponent("connection-preferences.json"))
        OFTCProfileScope.migrateLegacy(root: root) { $0 == "vpn.office.example" ? "Office VPN" : nil }
        var entries = OFTCProfileScope.entries(root: root)
        precondition(entries.count == 1 && entries[0].id == "office-vpn" && entries[0].name == "Office VPN")
        precondition(entries[0].profile.adoptsUnkeyedVPNEntry == true)
        precondition(!FileManager.default.fileExists(atPath: legacy.url.path))
        precondition(!FileManager.default.fileExists(atPath: root.appendingPathComponent("connection-preferences.json").path))
        OFTCProfileScope.migrateLegacy(root: root) { _ in nil } // idempotent
        precondition(OFTCProfileScope.entries(root: root).count == 1)

        // Peers: independent identity, startup choice, stop request and status.
        let warehouse = try OFTCProfileScope.add(
            try OFTCProfile(gateway: "vpn.warehouse.example", samlPort: 9443, name: "Warehouse"), root: root)
        let again = try OFTCProfileScope.add(
            try OFTCProfile(gateway: "vpn.warehouse2.example", samlPort: 9443, name: "Warehouse"), root: root)
        precondition(warehouse.id == "warehouse" && again.id == "warehouse-2")
        entries = OFTCProfileScope.entries(root: root)
        precondition(entries.map(\.name) == ["Office VPN", "Warehouse", "Warehouse"])
        precondition(entries[0].profile.adoptsUnkeyedVPNEntry == true && warehouse.profile.adoptsUnkeyedVPNEntry == nil)
    }

    static func checkLauncherAlias() throws {
        let fm = FileManager.default
        let root = fm.temporaryDirectory.appendingPathComponent("oftc-alias-\(UUID().uuidString)", isDirectory: true)
        defer { try? fm.removeItem(at: root) }
        let app = root.appendingPathComponent("Open Forticlient.app", isDirectory: true)
        let old = root.appendingPathComponent("OFTC.app", isDirectory: true)
        let alias = root.appendingPathComponent("Applications/OFTC")
        try fm.createDirectory(at: app, withIntermediateDirectories: true)
        try fm.createDirectory(at: old, withIntermediateDirectories: true)

        precondition(LauncherAlias.state(of: alias, target: app) == .absent)
        // A copy that is not the installed app never creates the alias.
        LauncherAlias.ensure(bundle: root.appendingPathComponent("elsewhere.app"), alias: alias, target: app)
        precondition(LauncherAlias.state(of: alias, target: app) == .absent)
        LauncherAlias.ensure(bundle: app, alias: alias, target: app)
        precondition(LauncherAlias.state(of: alias, target: app) == .pointsAtApp)
        LauncherAlias.ensure(bundle: app, alias: alias, target: app) // idempotent
        precondition(LauncherAlias.state(of: alias, target: app) == .pointsAtApp)

        // An alias left pointing at the pre-rename OFTC.app is refreshed.
        try fm.removeItem(at: alias)
        try URL.writeBookmarkData(try old.bookmarkData(options: .suitableForBookmarkFile), to: alias)
        LauncherAlias.ensure(bundle: app, alias: alias, target: app)
        precondition(LauncherAlias.state(of: alias, target: app) == .pointsAtApp)

        // A broken alias is refreshed too.
        let gone = root.appendingPathComponent("Gone.app", isDirectory: true)
        try fm.createDirectory(at: gone, withIntermediateDirectories: true)
        try fm.removeItem(at: alias)
        try URL.writeBookmarkData(try gone.bookmarkData(options: .suitableForBookmarkFile), to: alias)
        try fm.removeItem(at: gone)
        LauncherAlias.ensure(bundle: app, alias: alias, target: app)
        precondition(LauncherAlias.state(of: alias, target: app) == .pointsAtApp)

        // Removal deletes the alias.
        LauncherAlias.remove(alias: alias)
        precondition(LauncherAlias.state(of: alias, target: app) == .absent)

        // A regular file with that name is never replaced or removed.
        try Data("mine".utf8).write(to: alias)
        precondition(LauncherAlias.state(of: alias, target: app) == .notAnAlias)
        LauncherAlias.ensure(bundle: app, alias: alias, target: app)
        LauncherAlias.remove(alias: alias)
        let kept = try String(data: Data(contentsOf: alias), encoding: .utf8)
        precondition(kept == "mine")
    }

    static func checkUpdates() throws {
        // Versions: numeric, padded, never a prerelease.
        precondition(AppVersion("v1.2.1")?.parts == [1, 2, 1] && AppVersion("1.2")?.parts == [1, 2])
        for bad in ["", "v", "abc", "1..2", "1.2.3.4.5", "1.3.0-beta1", "1.2.x", "-1.2", "1.2 beta"] {
            precondition(AppVersion(bad) == nil, "accepted \(bad)")
        }
        precondition(AppVersion("1.2.0")! < AppVersion("1.2.1")!)
        precondition(AppVersion("1.9")! < AppVersion("1.10")!)
        precondition(AppVersion("1.2")! == AppVersion("1.2.0")!)
        precondition(AppVersion("2.0")! > AppVersion("1.99.99")!)

        func feed(_ tag: String, url: String = "https://github.com/o/r/releases/tag/v1.2.1",
                  draft: Bool = false, prerelease: Bool = false) -> Data {
            Data("""
            {"id": 7, "tag_name": "\(tag)", "html_url": "\(url)", "name": "x", "draft": \(draft),
             "prerelease": \(prerelease), "assets": [], "body": "notes"}
            """.utf8)
        }
        let offer = UpdateFeed.offer(from: feed("v1.2.1"), current: "1.2.0")
        precondition(offer == UpdateOffer(version: "1.2.1", page: URL(string: "https://github.com/o/r/releases/tag/v1.2.1")!))
        precondition(UpdateFeed.offer(from: feed("1.2.1"), current: "1.2.0")?.version == "1.2.1")
        precondition(UpdateFeed.offer(from: feed("v1.2.1"), current: "1.2.1") == nil)   // same
        precondition(UpdateFeed.offer(from: feed("v1.2.1"), current: "1.3.0") == nil)   // older
        precondition(UpdateFeed.offer(from: feed("v1.3.0"), current: "1.2.0", ) != nil)
        precondition(UpdateFeed.offer(from: feed("v1.3.0", prerelease: true), current: "1.2.0") == nil)
        precondition(UpdateFeed.offer(from: feed("v1.3.0", draft: true), current: "1.2.0") == nil)
        precondition(UpdateFeed.offer(from: feed("v1.3.0-rc1"), current: "1.2.0") == nil)
        precondition(UpdateFeed.offer(from: feed("v1.3.0", url: "http://example.com/r"), current: "1.2.0") == nil)
        precondition(UpdateFeed.offer(from: feed("v1.3.0", url: "file:///etc/passwd"), current: "1.2.0") == nil)
        precondition(UpdateFeed.offer(from: Data("not json".utf8), current: "1.2.0") == nil)
        precondition(UpdateFeed.offer(from: Data(count: UpdateFeed.maxBytes + 1), current: "1.2.0") == nil)
        precondition(UpdateFeed.offer(from: feed("v1.3.0"), current: "junk") == nil)

        // Feed configuration: https only; a per-user default overrides the bundle.
        let suite = "oftc-update-check-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        precondition(UpdateFeed.configuredURL(defaults: defaults) == nil)
        defaults.set("http://example.com/latest", forKey: "updateFeedURL")
        precondition(UpdateFeed.configuredURL(defaults: defaults) == nil)
        defaults.set("https://api.github.com/repos/o/r/releases/latest", forKey: "updateFeedURL")
        precondition(UpdateFeed.configuredURL(defaults: defaults)?.host == "api.github.com")

        // Store: on by default, at most a check a day, skipping one version only.
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
        precondition(store.shouldShow(offer!))
        store.skip("1.2.1")
        precondition(!store.shouldShow(offer!))
        precondition(store.shouldShow(UpdateOffer(version: "1.2.2", page: offer!.page)))
        let mode = try FileManager.default.attributesOfItem(
            atPath: directory.appendingPathComponent("update.json").path)[.posixPermissions] as? Int
        precondition(mode == 0o600)
        try Data("garbage".utf8).write(to: directory.appendingPathComponent("update.json"))
        precondition(store.automatic && store.skippedVersion == nil)
    }
}
