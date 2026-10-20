import Foundation
import NetworkExtension

@main enum SupervisorCheck {
    static func main() throws {
        let now = Date(timeIntervalSince1970: 1_000)
        var policy = ReconnectPolicy()
        let liveness = NSError(domain: "OFTCProvider", code: 409)
        precondition(!policy.allowRecovery(after: nil, now: now))
        precondition(!policy.allowRecovery(after: NSError(domain: "OFTCProvider", code: 102), now: now))
        precondition(!policy.allowRecovery(after: NSError(
            domain: NEVPNConnectionErrorDomain, code: 8), now: now))
        precondition(ReconnectPolicy.recoverable(NSError(domain: "OFTCProvider", code: 8)))
        for code in [301, 401, 501, 209, 309, 409, 509] {
            precondition(ReconnectPolicy.recoverable(NSError(domain: "OFTCProvider", code: code)))
        }
        for code in [201, 302, 403, 500, 601] {
            precondition(!ReconnectPolicy.recoverable(NSError(domain: "OFTCProvider", code: code)))
        }
        precondition(policy.allowRecovery(after: liveness, now: now))
        precondition(policy.allowRecovery(after: NSError(
            domain: NEVPNConnectionErrorDomain, code: 2), now: now.addingTimeInterval(1)))
        precondition(policy.allowRecovery(after: liveness, now: now.addingTimeInterval(2)))
        precondition(!policy.allowRecovery(after: liveness, now: now.addingTimeInterval(3)))
        precondition(policy.allowRecovery(after: liveness, now: now.addingTimeInterval(601)))
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("oftc-supervisor-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let lease = try SupervisorLease(bundleID: "test.oftc", directory: directory)
        let statusStore = SupervisorStatusStore(bundleID: "test.oftc", directory: directory)
        statusStore.publish(.acquiring, leaseID: lease.identifier)
        precondition(statusStore.read()?.phase == .acquiring)
        precondition(!lease.stopRequested)
        do {
            _ = try SupervisorLease(bundleID: "test.oftc", directory: directory)
            preconditionFailure("second supervisor acquired the same lock")
        } catch SupervisorLease.Failure.unavailable { }
        precondition(SupervisorLease.requestStop(bundleID: "test.oftc", directory: directory))
        precondition(lease.stopRequested)
        lease.close()
        precondition(statusStore.read() == nil) // No stale active state after exit.
        let replacement = try SupervisorLease(bundleID: "test.oftc", directory: directory)
        precondition(statusStore.read() == nil) // Old lease cannot describe a new process.
        statusStore.publish(.failed, leaseID: replacement.identifier)
        precondition(statusStore.read()?.phase == .failed)
        precondition(statusStore.read(now: Date().addingTimeInterval(301)) == nil)
        precondition(!replacement.stopRequested)
        replacement.close()
        let invalidState = directory.appendingPathComponent("supervisor.lock")
        try Data("broken".utf8).write(to: invalidState)
        precondition(!SupervisorLease.requestStop(bundleID: "test.oftc", directory: directory))
        print("supervisor policy and stop lease checks passed")
    }
}
