import Darwin
import Foundation

enum SupervisorPhase: String, Codable {
    case acquiring, connecting, connected, recovering, failed, stopped
}

struct SupervisorStatus: Codable {
    let phase: SupervisorPhase
    let leaseID: String
    let processID: Int32
    let updated: Date
}

struct SupervisorStatusStore {
    let directory: URL
    init(bundleID: String, directory: URL? = nil) {
        self.directory = directory ?? FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/\(bundleID)", isDirectory: true)
    }
    private var url: URL { directory.appendingPathComponent("supervisor-status.json") }

    func publish(_ phase: SupervisorPhase, leaseID: String) {
        let value = SupervisorStatus(phase: phase, leaseID: leaseID,
                                     processID: getpid(), updated: Date())
        guard let data = try? JSONEncoder().encode(value) else { return }
        try? data.write(to: url, options: .atomic)
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }

    func read(now: Date = Date()) -> SupervisorStatus? {
        guard let data = try? Data(contentsOf: url), data.count <= 4096,
              let value = try? JSONDecoder().decode(SupervisorStatus.self, from: data),
              UUID(uuidString: value.leaseID) != nil else { return nil }
        let age = now.timeIntervalSince(value.updated)
        guard age >= -5, age <= 300 else { return nil }
        if value.phase == .failed || value.phase == .stopped { return value }
        let lock = directory.appendingPathComponent("supervisor.lock")
        guard let bytes = try? Data(contentsOf: lock), bytes == Data(value.leaseID.utf8),
              kill(value.processID, 0) == 0 else { return nil }
        let fd = open(lock.path, O_RDWR | O_NOFOLLOW)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        if flock(fd, LOCK_EX | LOCK_NB) == 0 {
            flock(fd, LOCK_UN)
            return nil // Stale status after a crash; no live supervisor owns it.
        }
        return value
    }
}
