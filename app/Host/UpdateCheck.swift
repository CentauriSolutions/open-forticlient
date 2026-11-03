import Foundation

// A dotted release number such as "1.2.1" or "v1.2". Anything with a suffix
// (1.3.0-beta1) is rejected, so a prerelease is never offered.
struct AppVersion: Comparable, Equatable {
    let parts: [Int]

    init?(_ text: String) {
        var value = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if value.hasPrefix("v") || value.hasPrefix("V") { value.removeFirst() }
        let pieces = value.split(separator: ".", omittingEmptySubsequences: false)
        guard (1...4).contains(pieces.count) else { return nil }
        var numbers: [Int] = []
        for piece in pieces {
            guard !piece.isEmpty, piece.allSatisfy({ $0.isASCII && $0.isNumber }),
                  let number = Int(piece), number < 100_000 else { return nil }
            numbers.append(number)
        }
        parts = numbers
    }

    static func < (a: AppVersion, b: AppVersion) -> Bool {
        let count = max(a.parts.count, b.parts.count)
        for index in 0..<count {
            let left = index < a.parts.count ? a.parts[index] : 0
            let right = index < b.parts.count ? b.parts[index] : 0
            if left != right { return left < right }
        }
        return false
    }

    static func == (a: AppVersion, b: AppVersion) -> Bool { !(a < b) && !(b < a) }
}

struct UpdateOffer: Equatable {
    let version: String
    let page: URL
}

// The feed is a GitHub "latest release" document (tag_name, html_url, draft,
// prerelease), which GitHub serves for a repository and any static host can
// imitate. Only an https page is accepted; the app opens it in the browser and
// never downloads or runs anything itself.
enum UpdateFeed {
    private struct Release: Decodable {
        let tag_name: String
        let html_url: String
        let draft: Bool?
        let prerelease: Bool?
    }

    static let maxBytes = 256 * 1024

    static func offer(from data: Data, current: String) -> UpdateOffer? {
        guard data.count <= maxBytes,
              let release = try? JSONDecoder().decode(Release.self, from: data),
              release.draft != true, release.prerelease != true,
              let latest = AppVersion(release.tag_name),
              let installed = AppVersion(current), installed < latest,
              let page = URL(string: release.html_url), page.scheme == "https",
              page.host?.isEmpty == false else { return nil }
        let name = release.tag_name.hasPrefix("v") ? String(release.tag_name.dropFirst()) : release.tag_name
        return UpdateOffer(version: name, page: page)
    }

    enum Failure: Error { case notConfigured, insecure, network, tooLarge }

    // Feed URL: a build-time Info.plist value, overridable per user with
    // `defaults write <bundle id> updateFeedURL <url>`. Empty means no checks.
    static func configuredURL(bundle: Bundle = .main, defaults: UserDefaults = .standard) -> URL? {
        let text = defaults.string(forKey: "updateFeedURL")
            ?? bundle.object(forInfoDictionaryKey: "OFTCUpdateFeedURL") as? String ?? ""
        guard !text.isEmpty, let url = URL(string: text), url.scheme == "https" else { return nil }
        return url
    }

    static func fetch(_ feed: URL, current: String,
                      completion: @escaping (Result<UpdateOffer?, Failure>) -> Void) {
        guard feed.scheme == "https" else { completion(.failure(.insecure)); return }
        var request = URLRequest(url: feed, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 15)
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        request.setValue("Open-Forticlient/\(current)", forHTTPHeaderField: "User-Agent")
        let session = URLSession(configuration: .ephemeral)
        session.dataTask(with: request) { data, response, error in
            session.finishTasksAndInvalidate()
            guard error == nil, let data, let http = response as? HTTPURLResponse,
                  (200..<300).contains(http.statusCode) else { completion(.failure(.network)); return }
            guard data.count <= maxBytes else { completion(.failure(.tooLarge)); return }
            completion(.success(offer(from: data, current: current)))
        }.resume()
    }
}

// Whether to check, when we last did, and which version the user skipped.
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
