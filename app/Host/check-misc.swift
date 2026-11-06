import Foundation

// What is left of the old supervisor check once the supervisor, its lease, the SAML lock,
// gateway trust, the profile registry and the update feed moved to Rust (cargo test): the
// launcher alias, which stays Swift.
@main enum MiscCheck {
    static func main() throws {
        try checkLauncherAlias()
        print("launcher alias checks passed")
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
}
