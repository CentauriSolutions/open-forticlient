import Darwin
import Foundation
import NetworkExtension

// This command owns only its own VPN configuration. A stop request is durable
// across the short gap between an external `stop` command and the NE status
// notification, so an intentional disconnect cannot launch another SAML flow.
final class SupervisorLease {
    enum Failure: Error { case unavailable }

    private let stateURL: URL
    private let stopURL: URL
    let identifier = UUID().uuidString
    private var descriptor: Int32 = -1

    init(bundleID: String, directory: URL? = nil) throws {
        let parent = directory ?? FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/\(bundleID)", isDirectory: true)
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        stateURL = parent.appendingPathComponent("supervisor.lock")
        stopURL = parent.appendingPathComponent("supervisor.stop")
        descriptor = open(stateURL.path, O_RDWR | O_CREAT | O_NOFOLLOW, 0o600)
        guard descriptor >= 0, flock(descriptor, LOCK_EX | LOCK_NB) == 0 else {
            if descriptor >= 0 { Darwin.close(descriptor) }
            descriptor = -1
            throw Failure.unavailable
        }
        let bytes = Array(identifier.utf8)
        guard ftruncate(descriptor, 0) == 0,
              bytes.withUnsafeBytes({ write(descriptor, $0.baseAddress, $0.count) }) == bytes.count,
              fsync(descriptor) == 0 else {
            close(); throw Failure.unavailable
        }
        try? FileManager.default.removeItem(at: stopURL)
    }

    @discardableResult static func requestStop(bundleID: String, directory: URL? = nil) -> Bool {
        let parent = directory ?? FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/\(bundleID)", isDirectory: true)
        let state = parent.appendingPathComponent("supervisor.lock")
        guard FileManager.default.fileExists(atPath: state.path) else { return true }
        guard let bytes = try? Data(contentsOf: state),
              let identifier = String(data: bytes, encoding: .utf8),
              UUID(uuidString: identifier) != nil else { return false }
        let stop = parent.appendingPathComponent("supervisor.stop")
        do {
            try Data(identifier.utf8).write(to: stop, options: .atomic)
            return true
        } catch { return false }
    }

    var stopRequested: Bool {
        guard let bytes = try? Data(contentsOf: stopURL) else { return false }
        return String(data: bytes, encoding: .utf8) == identifier
    }

    func close() {
        guard descriptor >= 0 else { return }
        if let bytes = try? Data(contentsOf: stateURL),
           String(data: bytes, encoding: .utf8) == identifier {
            try? FileManager.default.removeItem(at: stateURL)
            try? FileManager.default.removeItem(at: stopURL)
        }
        flock(descriptor, LOCK_UN)
        Darwin.close(descriptor)
        descriptor = -1
    }

    deinit { close() }
}

struct ReconnectPolicy {
    private(set) var attempts: [Date] = []
    private let window: TimeInterval = 600
    private let maximum = 3

    static func recoverable(_ error: NSError?) -> Bool {
        guard let error else { return false }
        // Codes from an established SA: peer DELETE, socket failure during
        // packet send/receive/keepalive, or an explicit reconnect request.
        // Initial IKE/EAP failures remain nonrecoverable after a spent token.
        if error.domain == "OFTCProvider" {
            return [8, 301, 401, 501, 209, 309, 409, 509].contains(error.code)
        }
        guard error.domain == NEVPNConnectionErrorDomain else { return false }
        return [NEVPNConnectionError.overslept,
                .noNetworkAvailable,
                .unrecoverableNetworkChange,
                .serverNotResponding,
                .serverDead,
                .serverDisconnected].contains { $0.rawValue == error.code }
    }

    private mutating func reserve(now: Date) -> Bool {
        attempts.removeAll { now.timeIntervalSince($0) >= window }
        guard attempts.count < maximum else { return false }
        attempts.append(now)
        return true
    }

    mutating func allowRecovery(after error: NSError?, now: Date) -> Bool {
        guard Self.recoverable(error) else { return false }
        return reserve(now: now)
    }

}

final class ReconnectSupervisor {
    private var manager: NETunnelProviderManager
    private let providerID: String
    private let gateway: String
    private let samlPort: UInt32
    private let mode: ProviderStartEnvelope.ConnectMode
    private let insecure: Bool
    private let lease: SupervisorLease
    private let loadPSK: () throws -> Data
    private var policy = ReconnectPolicy()
    private var observer: NSObjectProtocol?
    private var timer: DispatchSourceTimer?
    private var signals: [DispatchSourceSignal] = []
    private var starting = false
    private var sawConnecting = false
    private var everConnected = false
    private var connectedThisAttempt = false
    private var fetchingError = false
    private var errorFetchDeadline: Date?
    private var disconnectEpoch = 0
    private var statusRefreshInFlight = false
    private var statusRefreshStartedAt: Date?
    private var statusRefreshEpoch = 0
    private var freshDisconnectedCount = 0
    private var timerTicks = 0
    private var ownsConnection = false
    private var startDeadline: Date?
    private var acquisitionDeadline: Date?
    private var unreachableBackoff: TimeInterval = 5
    private var restartAfter: Date?
    private var stopped = false
    private let statusStore: SupervisorStatusStore
    private var publishedPhase: SupervisorPhase = .acquiring

    private func publish(_ phase: SupervisorPhase) {
        publishedPhase = phase
        statusStore.publish(phase, leaseID: lease.identifier)
    }

    private func diagnostic(_ event: String) {
        fputs("OFTC supervisor: \(event)\n", stderr)
        fflush(stderr)
    }

    init(manager: NETunnelProviderManager, providerID: String,
         gateway: String, samlPort: UInt32,
         mode: ProviderStartEnvelope.ConnectMode, insecure: Bool,
         lease: SupervisorLease, loadPSK: @escaping () throws -> Data) {
        self.manager = manager
        self.providerID = providerID
        self.gateway = gateway
        self.samlPort = samlPort
        self.mode = mode
        self.insecure = insecure
        self.lease = lease
        self.loadPSK = loadPSK
        self.statusStore = SupervisorStatusStore(bundleID:
            String(providerID.dropLast(".provider".count)))
    }

    func run() {
        attachObserver()
        for number in [SIGINT, SIGTERM] {
            signal(number, SIG_IGN)
            let source = DispatchSource.makeSignalSource(signal: number, queue: .main)
            source.setEventHandler { [weak self] in self?.stop("Supervisor stopped", code: 0) }
            source.resume()
            signals.append(source)
        }
        let timer = DispatchSource.makeTimerSource(queue: .main)
        timer.schedule(deadline: .now() + .seconds(1), repeating: .seconds(1))
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            self.observe()
            self.timerTicks += 1
            if self.statusRefreshInFlight,
               let started = self.statusRefreshStartedAt,
               Date().timeIntervalSince(started) >= 10 {
                self.statusRefreshEpoch += 1 // Ignore a late callback.
                self.statusRefreshInFlight = false
                self.statusRefreshStartedAt = nil
                self.diagnostic("preference refresh timed out")
            }
            if self.timerTicks % 5 == 0 { self.refreshStatus() }
            if self.timerTicks % 30 == 0 {
                self.publish(self.publishedPhase)
                self.diagnostic("heartbeat status=\(self.manager.connection.status.rawValue) established=\(self.everConnected ? 1 : 0) current=\(self.connectedThisAttempt ? 1 : 0) refresh=\(self.statusRefreshInFlight ? 1 : 0) error_fetch=\(self.fetchingError ? 1 : 0)")
            }
        }
        self.timer = timer
        timer.resume()
        diagnostic("timer armed")
        beginAttempt()
    }

    private func attachObserver() {
        if let observer { NotificationCenter.default.removeObserver(observer) }
        // OperationQueue.main can deadlock with dispatchMain(): NE posts from
        // the main dispatch queue and waits for the operation queue to drain.
        observer = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange, object: manager.connection,
            queue: nil) { [weak self] _ in
                DispatchQueue.main.async { [weak self] in self?.observe() }
            }
    }

    private func refreshStatus() {
        guard !stopped, everConnected, connectedThisAttempt, !starting,
              !fetchingError, restartAfter == nil, !statusRefreshInFlight,
              manager.connection.status != .disconnected else { return }
        statusRefreshInFlight = true
        statusRefreshStartedAt = Date()
        statusRefreshEpoch += 1
        let epoch = statusRefreshEpoch
        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, error in
            DispatchQueue.main.async {
                guard let self, !self.stopped,
                      self.statusRefreshEpoch == epoch else { return }
                self.statusRefreshInFlight = false
                self.statusRefreshStartedAt = nil
                guard error == nil else {
                    self.diagnostic("preference refresh failed")
                    return
                }
                let matching = (managers ?? []).filter {
                    ($0.protocolConfiguration as? NETunnelProviderProtocol)?
                        .providerBundleIdentifier == self.providerID
                }
                guard matching.count == 1, let fresh = matching.first else {
                    self.stop("OFTC configuration changed during supervision", code: 1)
                    return
                }
                guard self.connectedThisAttempt, !self.starting,
                      !self.fetchingError, self.restartAfter == nil else { return }
                if self.timerTicks % 30 == 0 {
                    self.diagnostic("fresh status=\(fresh.connection.status.rawValue)")
                }
                if fresh.connection.status == .disconnected {
                    self.freshDisconnectedCount += 1
                    guard self.freshDisconnectedCount >= 2 else { return }
                    self.freshDisconnectedCount = 0
                    self.manager = fresh
                    self.attachObserver()
                    self.diagnostic("refreshed disconnected status")
                    self.observe()
                } else {
                    self.freshDisconnectedCount = 0
                }
            }
        }
    }

    private func beginAttempt() {
        guard !stopped, !lease.stopRequested,
              manager.connection.status == .disconnected else {
            stop("OFTC status changed before supervised start", code: 1); return
        }
        starting = true
        publish(.acquiring)
        diagnostic("begin attempt")
        sawConnecting = false
        connectedThisAttempt = false
        freshDisconnectedCount = 0
        if acquisitionDeadline == nil {
            acquisitionDeadline = Date().addingTimeInterval(390) // browser SSO + NE start
            unreachableBackoff = 5
        }
        startDeadline = acquisitionDeadline
        DispatchQueue.global(qos: .userInitiated).async {
            var psk = Data()
            var options: [String: NSObject]?
            var beforeBrowser = false
            do {
                psk = try self.loadPSK()
                if !self.lease.stopRequested {
                    options = try CandidateHostBridge.acquireOptions(
                        gateway: self.gateway, psk: psk, samlPort: self.samlPort,
                        insecure: self.insecure)
                    options?[ProviderStartEnvelope.modeKey] = try self.mode.encode() as NSData
                }
            } catch CandidateHostBridge.Failure.beforeBrowser {
                beforeBrowser = true
            } catch { }
            psk.resetBytes(in: 0..<psk.count)
            DispatchQueue.main.async {
                guard !self.stopped else { return }
                guard !self.lease.stopRequested else {
                    self.stop("Supervisor stopped", code: 0); return
                }
                guard let options else {
                    if beforeBrowser, !self.lease.stopRequested,
                       self.manager.connection.status == .disconnected,
                       let deadline = self.acquisitionDeadline, Date() < deadline {
                        self.starting = false
                        self.publish(.recovering)
                        self.restartAfter = Date().addingTimeInterval(self.unreachableBackoff)
                        self.unreachableBackoff = min(self.unreachableBackoff * 2, 30)
                        fputs("OFTC supervisor: SAML bootstrap unavailable; retrying before token use\n", stderr)
                        fflush(stderr)
                        return
                    }
                    self.stop("Fresh SAML acquisition failed; supervisor stopped", code: 1)
                    return
                }
                guard !self.lease.stopRequested else {
                    self.stop("Supervisor stopped", code: 0); return
                }
                self.manager.loadFromPreferences { error in
                    guard !self.stopped else { return }
                    guard error == nil, self.manager.isEnabled,
                          (self.manager.protocolConfiguration as? NETunnelProviderProtocol)?
                            .providerBundleIdentifier == self.providerID,
                          self.manager.connection.status == .disconnected,
                          !self.lease.stopRequested else {
                        self.stop("OFTC configuration or status changed before start", code: 1)
                        return
                    }
                    do {
                        self.diagnostic("start request entering")
                        self.publish(.connecting)
                        try CandidateHostBridge.start(self.manager.connection, options: options)
                        self.diagnostic("start request returned")
                        self.ownsConnection = true
                        self.startDeadline = Date().addingTimeInterval(90)
                        self.observe()
                    } catch {
                        self.stop("VPN start failed; no token retry", code: 1)
                    }
                }
            }
        }
    }

    private func observe() {
        guard !stopped else { return }
        if lease.stopRequested { stop("Supervisor stopped", code: 0); return }
        let status = manager.connection.status
        if status == .connected {
            fetchingError = false
            errorFetchDeadline = nil
            restartAfter = nil
            acquisitionDeadline = nil
            unreachableBackoff = 5
            if !connectedThisAttempt {
                diagnostic("VPN connected")
                connectedThisAttempt = true
                everConnected = true
                publish(.connected)
            }
            starting = false
            startDeadline = nil
            return
        }
        if status == .connecting || status == .reasserting { sawConnecting = true }
        if let deadline = startDeadline, Date() >= deadline {
            stop("VPN start deadline expired", code: 1); return
        }
        if let restartAfter, Date() >= restartAfter {
            self.restartAfter = nil
            beginAttempt()
            return
        }
        if fetchingError, let deadline = errorFetchDeadline, Date() >= deadline {
            fputs("OFTC supervisor: disconnect error fetch timed out\n", stderr)
            fflush(stderr)
            finishDisconnect(error: nil)
            return
        }
        if fetchingError { return }
        guard status == .disconnected, restartAfter == nil else { return }
        // A request can briefly remain disconnected before NE reports connecting.
        guard !starting || sawConnecting else { return }
        guard everConnected, connectedThisAttempt else {
            stop("VPN disconnected before establishment; no token retry", code: 1)
            return
        }
        connectedThisAttempt = false
        ownsConnection = false
        fetchingError = true
        publish(.recovering)
        diagnostic("VPN disconnected; fetching error")
        errorFetchDeadline = Date().addingTimeInterval(10)
        disconnectEpoch += 1
        let epoch = disconnectEpoch
        manager.connection.fetchLastDisconnectError { [weak self] error in
            DispatchQueue.main.async {
                guard let self, !self.stopped, self.fetchingError,
                      self.disconnectEpoch == epoch else { return }
                self.finishDisconnect(error: error as NSError?)
            }
        }
    }

    private func finishDisconnect(error: NSError?) {
        fetchingError = false
        errorFetchDeadline = nil
        if lease.stopRequested { stop("Supervisor stopped", code: 0); return }
        let now = Date()
        guard let error else {
            // A user stop through macOS can have no disconnect error. Never
            // spend a new SAML token when the cause is unknown.
            pauseAutomaticStart()
            stop("VPN disconnected without a recoverable error; staying down", code: 0)
            return
        }
        diagnostic("disconnect error domain=\(error.domain) code=\(error.code)")
        let allowed = policy.allowRecovery(after: error, now: now)
        guard allowed else {
            stop("VPN disconnected; automatic recovery unavailable", code: 1)
            return
        }
        restartAfter = now.addingTimeInterval(2)
        publish(.recovering)
        acquisitionDeadline = nil
        unreachableBackoff = 5
        fputs("OFTC supervisor: starting fresh SSO recovery\n", stderr)
        fflush(stderr)
    }

    private func pauseAutomaticStart() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        task.arguments = ["disable", "gui/\(getuid())/com.chris.openforticlient.oftc.agent"]
        task.standardOutput = FileHandle.nullDevice
        task.standardError = FileHandle.nullDevice
        do {
            try task.run()
            task.waitUntilExit()
            diagnostic(task.terminationStatus == 0
                ? "automatic start paused after unclassified disconnect"
                : "could not pause automatic start after unclassified disconnect")
        } catch {
            diagnostic("could not pause automatic start after unclassified disconnect")
        }
    }

    private func stop(_ message: String, code: Int32) {
        guard !stopped else { return }
        stopped = true
        publish(code == 0 ? .stopped : .failed)
        timer?.cancel()
        signals.forEach { $0.cancel() }
        if let observer { NotificationCenter.default.removeObserver(observer) }
        if ownsConnection && manager.connection.status != .disconnected {
            manager.connection.stopVPNTunnel()
        }
        lease.close()
        print(message)
        fflush(stdout)
        exit(code)
    }
}
