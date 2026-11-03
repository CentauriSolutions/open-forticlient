import Foundation

// Nonsecret startup intent shared by the CLI, menu app, and bundled agent.
// Registration alone is not permission to open SSO: an explicit Connect
// request or the separate connect-at-login preference is required.
struct AgentIntent {
    struct Preferences: Codable { var connectAtLogin: Bool }
    private struct Request: Codable {
        let connect: Bool
        let created: Date
    }
    let directory: URL

    init(bundleID: String, directory: URL? = nil) {
        self.directory = directory ?? FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/\(bundleID)", isDirectory: true)
    }

    private var preferencesURL: URL { directory.appendingPathComponent("connection-preferences.json") }
    private var requestURL: URL { directory.appendingPathComponent("agent-request.json") }

    func preferences() -> Preferences? {
        guard let data = try? Data(contentsOf: preferencesURL), data.count <= 4096 else { return nil }
        return try? JSONDecoder().decode(Preferences.self, from: data)
    }

    func connectAtLogin(legacyEnabled: Bool) -> Bool {
        preferences()?.connectAtLogin
            ?? (!FileManager.default.fileExists(atPath: preferencesURL.path) && legacyEnabled)
    }

    private func write<T: Encodable>(_ value: T, to url: URL) throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        try JSONEncoder().encode(value).write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }

    func setConnectAtLogin(_ enabled: Bool) throws {
        try write(Preferences(connectAtLogin: enabled), to: preferencesURL)
    }

    func request(connect: Bool, now: Date = Date()) throws {
        try write(Request(connect: connect, created: now), to: requestURL)
    }

    func cancelRequest() { try? FileManager.default.removeItem(at: requestURL) }

    func shouldStart(now: Date = Date(), legacyEnabled: Bool = true) -> Bool {
        if let data = try? Data(contentsOf: requestURL), data.count <= 4096,
           let request = try? JSONDecoder().decode(Request.self, from: data) {
            cancelRequest()
            let age = now.timeIntervalSince(request.created)
            if age >= 0, age < 60 { return request.connect }
        }
        // Preserve an already registered pre-menu-bar agent on upgrade. New
        // connections initialize the preference explicitly before registration.
        return connectAtLogin(legacyEnabled: legacyEnabled)
    }
}
