import Foundation
import NetworkExtension

// One configured VPN: its profile, per-profile state directory and identity.
struct OFTCProfileEntry: Equatable {
    let id: String
    let profile: OFTCProfile
    let root: URL

    var name: String { profile.displayName }
    var directory: URL { OFTCProfileScope.directory(root: root, id: id) }
}

// Every profile is a peer: a profile file, its own macOS VPN entry, supervisor
// lease, stop request, status record and startup preference, all under
// `<root>/profiles/<id>/`. Only the SAML lock is shared, because each browser
// sign-in listens on a local callback port.
enum OFTCProfileScope {
    static let configurationKey = "oftc.profile"

    static func isValidID(_ id: String) -> Bool {
        (1...32).contains(id.utf8.count) && id.utf8.allSatisfy {
            (48...57).contains($0) || (97...122).contains($0) || $0 == 45
        } && !id.hasPrefix("-") && !id.hasSuffix("-")
    }

    static func defaultRoot(bundleID: String) -> URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/\(bundleID)", isDirectory: true)
    }

    static func directory(root: URL, id: String) -> URL {
        root.appendingPathComponent("profiles", isDirectory: true)
            .appendingPathComponent(id, isDirectory: true)
    }

    // A stable identifier for a display name: lowercase letters, digits, hyphens.
    static func slug(_ text: String) -> String {
        var result = ""
        var pendingHyphen = false
        for scalar in text.lowercased().unicodeScalars {
            if scalar.isASCII, CharacterSet.alphanumerics.contains(scalar) {
                if pendingHyphen, !result.isEmpty { result.append("-") }
                pendingHyphen = false
                result.unicodeScalars.append(scalar)
            } else {
                pendingHyphen = true
            }
        }
        result = String(result.prefix(32))
        while result.hasSuffix("-") { result.removeLast() }
        return result.isEmpty ? "vpn" : result
    }

    static func uniqueID(_ base: String, taken: Set<String>) -> String {
        guard taken.contains(base) else { return base }
        for number in 2...999 {
            let suffix = "-\(number)"
            let candidate = String(base.prefix(32 - suffix.count)) + suffix
            if !taken.contains(candidate) { return candidate }
        }
        return base + "-" + UUID().uuidString.prefix(4).lowercased()
    }

    static func entries(root: URL) -> [OFTCProfileEntry] {
        let parent = root.appendingPathComponent("profiles", isDirectory: true)
        let names = (try? FileManager.default.contentsOfDirectory(atPath: parent.path)) ?? []
        let found: [OFTCProfileEntry] = names.filter(isValidID).compactMap { id in
            guard let store = try? OFTCProfileStore(bundleID: "oftc.profile",
                      directory: directory(root: root, id: id)),
                  let profile = try? store.load() else { return nil }
            return OFTCProfileEntry(id: id, profile: profile, root: root)
        }
        return found.sorted {
            let order = $0.name.localizedCaseInsensitiveCompare($1.name)
            return order == .orderedSame ? $0.id < $1.id : order == .orderedAscending
        }
    }

    // Creates a profile with an identifier derived from its name, never
    // replacing an existing one.
    @discardableResult
    static func add(_ profile: OFTCProfile, root: URL, id requested: String? = nil) throws -> OFTCProfileEntry {
        let taken = Set(entries(root: root).map(\.id))
        let id = requested ?? uniqueID(slug(profile.displayName), taken: taken)
        guard isValidID(id), !taken.contains(id) else { throw OFTCProfileStore.Failure.invalid }
        let store = try OFTCProfileStore(bundleID: "oftc.profile", directory: directory(root: root, id: id))
        try store.save(profile)
        return OFTCProfileEntry(id: id, profile: profile, root: root)
    }

    // Moves the original single-profile layout into profiles/<id>/. The VPN
    // entry it used has no profile key, so the migrated profile adopts it.
    static func migrateLegacy(root: URL, nameForGateway: (String) -> String?) {
        guard let legacyStore = try? OFTCProfileStore(bundleID: "oftc.profile", directory: root),
              let legacy = try? legacyStore.load() else { return }
        let existing = entries(root: root)
        if !existing.contains(where: { $0.profile.gateway == legacy.gateway }) {
            let name = nameForGateway(legacy.gateway) ?? legacy.gateway
            guard let migrated = try? legacy.with(name: name, adoptsUnkeyedVPNEntry: true),
                  let entry = try? add(migrated, root: root) else { return }
            let preferences = root.appendingPathComponent("connection-preferences.json")
            if FileManager.default.fileExists(atPath: preferences.path) {
                let target = entry.directory.appendingPathComponent("connection-preferences.json")
                try? FileManager.default.moveItem(at: preferences, to: target)
            }
        }
        try? legacyStore.remove()
    }

    static func profileID(of manager: NETunnelProviderManager) -> String? {
        let configuration = (manager.protocolConfiguration as? NETunnelProviderProtocol)?
            .providerConfiguration
        return configuration?[configurationKey] as? String
    }

    static func matches(_ manager: NETunnelProviderManager, providerID: String,
                        entry: OFTCProfileEntry) -> Bool {
        guard (manager.protocolConfiguration as? NETunnelProviderProtocol)?
                .providerBundleIdentifier == providerID else { return false }
        let key = profileID(of: manager)
        return key == entry.id || (key == nil && entry.profile.adoptsUnkeyedVPNEntry == true)
    }

    static func manager(for entry: OFTCProfileEntry, in managers: [NETunnelProviderManager],
                        providerID: String) -> [NETunnelProviderManager] {
        managers.filter { matches($0, providerID: providerID, entry: entry) }
    }
}
