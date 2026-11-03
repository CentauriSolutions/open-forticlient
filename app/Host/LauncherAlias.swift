import Foundation

// The app's file is "Open Forticlient.app". This keeps a per-user Finder alias
// named "OFTC" in ~/Applications so Spotlight and Launchpad still find the app
// by its short name: Spotlight matches app names by file name, and an alias
// (unlike a symlink) is indexed under its own name.
enum LauncherAlias {
    static let name = "OFTC"
    static let installedApp = URL(fileURLWithPath: "/Applications/Open Forticlient.app")

    static var url: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Applications", isDirectory: true)
            .appendingPathComponent(name)
    }

    enum State: Equatable {
        case absent
        case notAnAlias            // a file of that name that is not ours to touch
        case pointsAtApp
        case pointsElsewhere(URL?) // nil when its target no longer resolves
    }

    static func state(of alias: URL = url, target app: URL = installedApp) -> State {
        guard FileManager.default.fileExists(atPath: alias.path) else { return .absent }
        guard let data = try? URL.bookmarkData(withContentsOf: alias) else { return .notAnAlias }
        var stale = false
        guard let target = try? URL(resolvingBookmarkData: data,
                                    options: [.withoutUI, .withoutMounting],
                                    relativeTo: nil, bookmarkDataIsStale: &stale) else {
            return .pointsElsewhere(nil)
        }
        return target.standardizedFileURL.path == app.standardizedFileURL.path
            ? .pointsAtApp : .pointsElsewhere(target)
    }

    // Only the installed copy owns the alias, so dev builds never touch it. A
    // broken alias, or one left pointing at the pre-rename OFTC.app, is
    // refreshed; a file of that name that is not an alias is left alone.
    static func ensure(bundle: URL = Bundle.main.bundleURL, alias: URL = url,
                       target: URL = installedApp) {
        guard bundle.standardizedFileURL.path == target.standardizedFileURL.path else { return }
        switch state(of: alias, target: target) {
        case .pointsAtApp, .notAnAlias:
            return
        case .pointsElsewhere(let other):
            if let other, other.lastPathComponent != "OFTC.app" { return }
            try? FileManager.default.removeItem(at: alias)
        case .absent:
            break
        }
        do {
            try FileManager.default.createDirectory(
                at: alias.deletingLastPathComponent(), withIntermediateDirectories: true)
            let data = try target.bookmarkData(options: .suitableForBookmarkFile,
                                               includingResourceValuesForKeys: nil, relativeTo: nil)
            try URL.writeBookmarkData(data, to: alias)
        } catch { }
    }

    // Removes the alias if it is one (never a regular file of that name).
    static func remove(alias: URL = url) {
        switch state(of: alias) {
        case .absent, .notAnAlias: return
        default: try? FileManager.default.removeItem(at: alias)
        }
    }
}
