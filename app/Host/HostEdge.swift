import Darwin
import Foundation
import Network

// The Swift client of the host's local socket (docs/ui-edge.md). It is the only UI file
// that talks to the host. Nothing here blocks the caller: the socket is an NWConnection,
// the one child process runs on a background queue, and every callback is delivered on
// `deliveryQueue` (the main queue by default).

// MARK: - Wire types (core/ui-edge; the golden files pin them)

enum HostWire {
    /// Unknown enum values decode to the type's fallback, never an error, so a newer host
    /// within one protocol number cannot break this reader.
    static func decode<T: RawRepresentable>(_ decoder: Decoder, fallback: T) -> T where T.RawValue == String {
        guard let raw = try? decoder.singleValueContainer().decode(String.self) else { return fallback }
        return T(rawValue: raw) ?? fallback
    }

    static let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return decoder
    }()

    static func date(_ text: String?) -> Date? {
        guard let text else { return nil }
        return ISO8601DateFormatter().date(from: text)
    }
}

enum HostErrorCode: String, Decodable {
    case approvalRequired = "approval_required", pskUnavailable = "psk_unavailable"
    case notConfigured = "not_configured", alreadyConfigured = "already_configured"
    case migrationNeeded = "migration_needed", agentUnavailable = "agent_unavailable"
    case hostUnavailable = "host_unavailable", unsupportedSchema = "unsupported_schema"
    case tunnelsActive = "tunnels_active", busy, unknownOp = "unknown_op", badRequest = "bad_request"
    case invalidFile = "invalid_file", cancelled
    case internalFailure = "internal"
    /// `profiles[].error` only: why a connection failed or was lost (docs/ui-edge.md 4.5).
    case networkBlocked = "network_blocked", gatewayNotFound = "gateway_not_found"
    case gatewayNoAnswer = "gateway_no_answer", gatewayRefused = "gateway_refused"
    case signInRejected = "sign_in_rejected", connectionLost = "connection_lost"
    /// Never on the wire: a request the UI gave up waiting for.
    case timeout

    init(from decoder: Decoder) throws { self = HostWire.decode(decoder, fallback: .internalFailure) }
}

struct HostError: Error, Decodable, Equatable {
    var code: HostErrorCode
    var detail: String = ""
    var exit: Int = 1
    var profileId: String?

    static func local(_ code: HostErrorCode, _ detail: String) -> HostError {
        HostError(code: code, detail: detail, exit: code == .hostUnavailable ? 5 : 1, profileId: nil)
    }
}

enum HostConnectionState: String, Decodable {
    case connected, disconnected, connecting, disconnecting, signIn = "sign_in"
    case reconnecting, attention, setup
    init(from decoder: Decoder) throws { self = HostWire.decode(decoder, fallback: .attention) }
}

enum HostComponentState: String, Decodable {
    case checking, ready, missing, updateRequired = "update_required", approval, newer, unavailable
    init(from decoder: Decoder) throws { self = HostWire.decode(decoder, fallback: .unavailable) }
}

enum HostLoginState: String, Decodable {
    case enabled, disabled, requiresApproval = "requires_approval", notFound = "not_found"
    init(from decoder: Decoder) throws { self = HostWire.decode(decoder, fallback: .notFound) }
}

struct HostInfo: Decodable, Equatable {
    var version: String
    var build: String
    var providerBuild: String
}

struct HostComponent: Decodable, Equatable {
    var state: HostComponentState
    var installedBuild: String?
    var expectedBuild: String?
}

struct HostLogin: Decodable, Equatable {
    var menuItem: HostLoginState
    var agent: HostLoginState
    var hostAgent: HostLoginState
}

struct HostTraffic: Decodable, Equatable {
    var session: String
    var rxBytes: UInt64
    var txBytes: UInt64
    var rxRate: Double?
    var txRate: Double?
    var sampleSeq: UInt64
}

struct HostProfileError: Decodable, Equatable {
    var code: HostErrorCode
    var detail: String
}

struct HostProfile: Decodable, Equatable {
    var id: String
    var name: String
    var gateway: String
    var samlPort: Int
    var transport: String
    var autoStart: Bool
    var state: HostConnectionState
    var connectedSince: String?
    var traffic: HostTraffic?
    var error: HostProfileError?

    var connectedDate: Date? { HostWire.date(connectedSince) }
}

struct HostStatus: Decodable, Equatable {
    var schema: Int
    var generated: String
    var seq: UInt64
    var host: HostInfo
    var component: HostComponent
    var login: HostLogin
    var profiles: [HostProfile]
}

/// A `traffic` event: the newest sample of one profile.
struct HostTrafficEvent: Equatable {
    var profile: String
    var sample: HostTraffic
}

struct HostProgress: Equatable {
    var step: String
    var state: String
}

struct HostImportItem: Decodable, Equatable {
    var name: String
    var gateway: String
    var alreadyConfigured: Bool
}

struct HostImportPreview: Decodable, Equatable { var profiles: [HostImportItem] }
struct HostImportResult: Decodable, Equatable { var added: [String] }

/// An importable FortiClient profile (`list_sources`); never a PSK.
struct HostSource: Decodable, Equatable {
    var label: String
    var gateway: String
    var samlPort: Int
    var alreadyConfigured: Bool
}

struct HostSources: Decodable, Equatable { var sources: [HostSource] }
struct HostAddResult: Decodable, Equatable { var profileId: String }

struct HostUpdateOffer: Decodable, Equatable {
    var version: String
    var page: String
}

/// The `check_update` result: the host fetched the feed; `available` is nil when up to date or no
/// feed is configured.
struct HostUpdateResult: Decodable, Equatable { var available: HostUpdateOffer? }

enum HostSettingsPane: String { case extensions, loginItems = "login_items" }

private struct HostHello: Decodable { var protocolVersion: Int; var host: HostInfo
    enum CodingKeys: String, CodingKey { case protocolVersion = "protocol", host }
}

// MARK: - Framing

/// One decoded line from the host. A line that is none of these is `ignored`: unknown events
/// and fields never break a reader.
enum HostFrame: Equatable {
    case reply(id: UInt64, result: Data?, error: HostError?)
    case progress(id: UInt64, HostProgress)
    case status(HostStatus)
    case traffic(HostTrafficEvent)
    case ignored

    static let maxLine = 64 * 1024

    static func encode(id: UInt64, op: String, args: [String: Any] = [:]) -> Data {
        var object = args
        object["id"] = id
        object["op"] = op
        let body = (try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])) ?? Data()
        return body + Data("\n".utf8)
    }

    static func parse(_ line: Data) -> HostFrame {
        guard let object = (try? JSONSerialization.jsonObject(with: line)) as? [String: Any] else { return .ignored }
        let id = (object["id"] as? NSNumber)?.uint64Value
        switch object["event"] as? String {
        case "status"?:
            guard let status = object["status"], let data = try? JSONSerialization.data(withJSONObject: status),
                  let document = try? HostWire.decoder.decode(HostStatus.self, from: data) else { return .ignored }
            return .status(document)
        case "traffic"?:
            guard let profile = object["profile"] as? String,
                  let sample = try? HostWire.decoder.decode(HostTraffic.self, from: line) else { return .ignored }
            return .traffic(HostTrafficEvent(profile: profile, sample: sample))
        case "progress"?:
            guard let id, let step = object["step"] as? String, let state = object["state"] as? String else { return .ignored }
            return .progress(id: id, HostProgress(step: step, state: state))
        case .some: return .ignored
        case nil: break
        }
        guard let id, let ok = object["ok"] as? Bool else { return .ignored }
        if ok {
            let result = object["result"].flatMap { try? JSONSerialization.data(withJSONObject: $0, options: [.fragmentsAllowed]) }
            return .reply(id: id, result: result ?? Data("{}".utf8), error: nil)
        }
        let failure = (object["error"]).flatMap { try? JSONSerialization.data(withJSONObject: $0) }
            .flatMap { try? HostWire.decoder.decode(HostError.self, from: $0) }
        return .reply(id: id, result: nil, error: failure ?? .local(.internalFailure, "unreadable error"))
    }
}

/// Splits a byte stream into lines. A line longer than the cap makes `feed` return nil: the
/// caller closes, as the host does.
struct HostLineBuffer {
    private var bytes = Data()

    mutating func feed(_ chunk: Data) -> [Data]? {
        bytes.append(chunk)
        var lines: [Data] = []
        while let newline = bytes.firstIndex(of: 0x0A) {
            let line = bytes[bytes.startIndex..<newline]
            bytes.removeSubrange(bytes.startIndex...newline)
            if line.count > HostFrame.maxLine { return nil }
            if !line.isEmpty { lines.append(Data(line)) }
        }
        return bytes.count > HostFrame.maxLine ? nil : lines
    }
}

// MARK: - Transport and launching seams

protocol HostConnection: AnyObject {
    var onData: ((Data) -> Void)? { get set }
    /// Called once when the connection ends for any reason after `start`.
    var onClosed: (() -> Void)? { get set }
    /// `error` is nil when the socket is connected.
    func start(_ ready: @escaping (Error?) -> Void)
    func send(_ data: Data)
    func cancel()
}

final class UnixConnection: HostConnection {
    var onData: ((Data) -> Void)?
    var onClosed: (() -> Void)?
    private let connection: NWConnection
    private let queue: DispatchQueue
    private var reported = false
    private var closed = false

    init(path: String, queue: DispatchQueue) {
        connection = NWConnection(to: .unix(path: path), using: .tcp)
        self.queue = queue
    }

    func start(_ ready: @escaping (Error?) -> Void) {
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                self.reported = true
                ready(nil)
                self.receive()
            case .waiting(let error), .failed(let error):
                // A refused or missing socket makes NWConnection wait and retry; the
                // edge owns the retry policy, so this ends the attempt.
                if !self.reported { self.reported = true; ready(error) } else { self.finish() }
                self.cancel()
            case .cancelled:
                if !self.reported { self.reported = true; ready(NWError.posix(.ECANCELED)) }
                self.finish()
            default: break
            }
        }
        connection.start(queue: queue)
    }

    private func finish() {
        guard !closed else { return }
        closed = true
        onClosed?()
    }

    private func receive() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, complete, error in
            guard let self else { return }
            if let data, !data.isEmpty { self.onData?(data) }
            if complete || error != nil { self.cancel(); return }
            self.receive()
        }
    }

    func send(_ data: Data) {
        connection.send(content: data, completion: .contentProcessed { [weak self] error in
            if error != nil { self?.cancel() }
        })
    }

    func cancel() { connection.cancel() }
}

enum HostStartResult: Equatable { case started, needsApproval, failed }

/// How the UI starts or replaces the host when the socket is not there: direct mode, because
/// a client that needs a server cannot be the thing that starts it. Calls block, so the edge
/// runs them off its own queue.
protocol HostStarter {
    /// Starts the host service, registering it first when launchd does not know it.
    func start() -> HostStartResult
    /// Replaces a running host (`host restart`), after an upgrade left an older one running.
    func restart() -> Bool
}

/// `launchctl kickstart`, then `OFTCAgent host register` (registration and a kickstart, exit 4
/// when macOS wants the user's approval) and `OFTCAgent host restart`, each with a timeout.
struct LaunchctlStarter: HostStarter {
    let label: String
    let executable: URL?
    var launchctl = URL(fileURLWithPath: "/bin/launchctl")

    func start() -> HostStartResult {
        if Self.run(launchctl, ["kickstart", "gui/\(getuid())/\(label)"], timeout: 5) == 0 { return .started }
        guard let executable else { return .failed }
        switch Self.run(executable, ["host", "register"], timeout: 20) {
        case 0: return .started
        case 4: return .needsApproval
        default: return .failed
        }
    }

    func restart() -> Bool {
        guard let executable else { return false }
        return Self.run(executable, ["host", "restart"], timeout: 20) == 0
    }

    /// The exit status, or -1 when the child could not start or outlived `timeout`.
    static func run(_ executable: URL, _ arguments: [String], timeout: TimeInterval) -> Int32 {
        let process = Process()
        process.executableURL = executable
        process.arguments = arguments
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        let done = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in done.signal() }
        do { try process.run() } catch { return -1 }
        if done.wait(timeout: .now() + timeout) == .timedOut {
            process.terminate()
            return -1
        }
        return process.terminationStatus
    }
}

/// Stores a typed PSK: the one secret the UI handles never crosses the socket (docs/ui-edge.md 4.4).
/// It goes on the stdin pipe of the host's own `provision-psk --stdin <gateway>` verb, run as a
/// short-lived child of the app's executable, and the caller then sends `add_profile` (or runs
/// `component_update` again) with the key saved. Blocks: call it off the main thread.
enum HostPSK {
    static func store(_ psk: Data, gateway: String, executable: URL?, timeout: TimeInterval = 20) -> Bool {
        guard let executable, (1...1024).contains(psk.count), !psk.contains(0) else { return false }
        let process = Process()
        process.executableURL = executable
        process.arguments = ["provision-psk", "--stdin", gateway]
        let input = Pipe()
        process.standardInput = input
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        let done = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in done.signal() }
        guard (try? process.run()) != nil else { return false }
        input.fileHandleForWriting.write(psk)
        try? input.fileHandleForWriting.close()
        if done.wait(timeout: .now() + timeout) == .timedOut {
            process.terminate()
            return false
        }
        return process.terminationStatus == 0
    }
}

// MARK: - The client

enum HostUnavailable: Equatable {
    /// No server on the socket; the edge is starting it or retrying.
    case notRunning
    /// The service is registered but macOS is waiting for the user to allow it.
    case needsApproval
    /// An older host from before an upgrade is being replaced.
    case updating
    /// The host speaks no protocol this UI speaks.
    case unsupported(String)
}

enum HostAvailability: Equatable {
    case connecting
    case ready
    case unavailable(HostUnavailable)
}

final class HostEdge {
    struct Configuration {
        var socketPath: String
        var clientVersion: String
        var clientBuild: String
        var backoff: [TimeInterval] = [0.5, 1, 2, 5]
        var steadyRetry: TimeInterval = 30
        /// The least time between two attempts to start the service, however often the menu opens
        /// or a host answers and dies; only the user's own "Start service" skips it.
        var startFloor: TimeInterval = 30
        var requestTimeout: TimeInterval = 30
    }

    static let protocolRange = (min: 1, max: 1)

    /// `~/Library/Application Support/<bundle id>/host.sock`, the host's per-user directory.
    static func socketPath(bundleID: String, home: URL = FileManager.default.homeDirectoryForCurrentUser) -> String {
        home.appendingPathComponent("Library/Application Support/\(bundleID)/host.sock").path
    }

    /// Delivered on `deliveryQueue`.
    var onAvailability: ((HostAvailability) -> Void)?
    var onStatus: ((HostStatus) -> Void)?
    var onTraffic: ((HostTrafficEvent) -> Void)?

    private let queue = DispatchQueue(label: "oftc.host-edge")
    private let starterQueue = DispatchQueue(label: "oftc.host-edge.start")
    private let deliveryQueue: DispatchQueue
    private let configuration: Configuration
    private let starter: HostStarter
    private let makeConnection: (String, DispatchQueue) -> HostConnection

    // Everything below is confined to `queue`.
    private var connection: HostConnection?
    private var lines = HostLineBuffer()
    private var generation = 0
    private var nextID: UInt64 = 1
    private var pending: [UInt64: Pending] = [:]
    private var availability = HostAvailability.connecting
    private var attempt = 0
    private var lastStartAt: Date?
    private var forceStart = false
    /// `host register` said macOS holds the service for the user's approval: it is not run again
    /// until a host answers.
    private var approvalPending = false
    private var restartedForBuild = false
    private var active = true
    private var retryScheduled = false
    private var lastSeq: UInt64 = 0
    private(set) var lastStatus: HostStatus?

    private struct Pending {
        var progress: ((HostProgress) -> Void)?
        /// Runs on `queue` for the edge's own requests, on `deliveryQueue` for the caller's.
        var internalRequest = false
        var completion: (Result<Data, HostError>) -> Void
    }

    private func complete(_ waiting: Pending, _ result: Result<Data, HostError>) {
        if waiting.internalRequest { waiting.completion(result) } else { deliver { waiting.completion(result) } }
    }

    init(configuration: Configuration, starter: HostStarter,
         deliveryQueue: DispatchQueue = .main,
         makeConnection: @escaping (String, DispatchQueue) -> HostConnection = { UnixConnection(path: $0, queue: $1) }) {
        self.configuration = configuration
        self.starter = starter
        self.deliveryQueue = deliveryQueue
        self.makeConnection = makeConnection
    }

    // MARK: Public API (any thread)

    func start() { queue.async { self.connect() } }

    func stop() {
        queue.async {
            self.generation += 1
            self.retryScheduled = false
            self.connection?.cancel()
            self.connection = nil
            self.failPending(.local(.hostUnavailable, "stopped"))
        }
    }

    /// The menu is visible or a window is open. Retries run only while it is; coming back to
    /// the foreground tries once at once (also what a wake from sleep calls).
    func setActive(_ value: Bool) {
        queue.async {
            self.active = value
            if value { self.retryNow() }
        }
    }

    /// Tries to connect now (a window opened, a wake). `startService` is the user's own request to
    /// start the service and is the one thing that skips the floor between starts.
    func retryNow(startService: Bool = false) {
        queue.async {
            // An older host is being replaced; a connect now could only reach it again.
            guard self.availability != .unavailable(.updating), self.availability != .ready else { return }
            // Recorded even while a connect is in flight: that connect's failure consumes it,
            // so the user's request is never lost to a retry that happened to be mid-connect.
            if startService { self.forceStart = true }
            guard self.connection == nil, self.availability != .connecting else { return }
            self.attempt = 0
            self.connect()
        }
    }

    /// Asks for a fresh `status` document (after something the host does not watch, such as
    /// the setup window finishing).
    /// `completion` runs on the delivery queue after the fetched document has been delivered (or
    /// the fetch failed), so a caller can decide from what the host says now.
    func refresh(completion: (() -> Void)? = nil) {
        request("status", timeout: 10) { [weak self] result in
            if case .success(let data) = result, let status = try? HostWire.decoder.decode(HostStatus.self, from: data) {
                self?.queue.async {
                    self?.accept(status)
                    if let completion { self?.deliver(completion) }
                }
            } else if let completion { completion() }
        }
    }

    /// Sends one request. `completion` runs once on `deliveryQueue`: the reply's result, the
    /// host's typed error, `host_unavailable` when the connection is not ready or drops, or
    /// `timeout`. A request in flight when the connection drops is never retried here.
    func request(_ op: String, args: [String: Any] = [:], timeout: TimeInterval? = nil,
                 progress: ((HostProgress) -> Void)? = nil,
                 completion: @escaping (Result<Data, HostError>) -> Void) {
        queue.async {
            guard self.availability == .ready, let connection = self.connection else {
                self.deliver { completion(.failure(.local(.hostUnavailable, "OFTC's VPN service is not running"))) }
                return
            }
            let id = self.nextID
            self.nextID += 1
            self.pending[id] = Pending(progress: progress, completion: completion)
            connection.send(HostFrame.encode(id: id, op: op, args: args))
            let limit = timeout ?? self.configuration.requestTimeout
            self.queue.asyncAfter(deadline: .now() + limit) {
                guard let waiting = self.pending.removeValue(forKey: id) else { return }
                self.connection?.send(HostFrame.encode(id: self.nextID, op: "cancel", args: ["target": id]))
                self.nextID += 1
                self.complete(waiting, .failure(.local(.timeout, "no reply in \(Int(limit)) s")))
            }
        }
    }

    func request<T: Decodable>(_ op: String, args: [String: Any] = [:], timeout: TimeInterval? = nil,
                               as type: T.Type, completion: @escaping (Result<T, HostError>) -> Void) {
        request(op, args: args, timeout: timeout) { result in
            switch result {
            case .failure(let error): completion(.failure(error))
            case .success(let data):
                if let value = try? HostWire.decoder.decode(T.self, from: data) { completion(.success(value)) }
                else { completion(.failure(.local(.internalFailure, "unreadable reply"))) }
            }
        }
    }

    // MARK: Typed requests the windows use

    func listSources(_ completion: @escaping (Result<HostSources, HostError>) -> Void) {
        request("list_sources", timeout: 10, as: HostSources.self, completion: completion)
    }

    /// `add_profile`; `progress` carries the setup steps. The PSK is already saved (`HostPSK`) or
    /// comes from the named FortiClient profile inside the host.
    func addProfile(gateway: String, samlPort: Int, tcp: Bool, name: String?, fortiClientLabel: String?,
                    progress: @escaping (HostProgress) -> Void,
                    completion: @escaping (Result<HostAddResult, HostError>) -> Void) {
        var args: [String: Any] = ["gateway": gateway, "saml_port": samlPort, "transport": tcp ? "tcp" : "udp",
                                   "psk_source": fortiClientLabel == nil ? "saved" : "forticlient"]
        if let name { args["name"] = name }
        if let fortiClientLabel { args["label"] = fortiClientLabel }
        // Approval can take as long as the user does; the host's op ends when the request does.
        request("add_profile", args: args, timeout: 900, progress: progress) { result in
            switch result {
            case .failure(let error): completion(.failure(error))
            case .success(let data):
                if let value = try? HostWire.decoder.decode(HostAddResult.self, from: data) { completion(.success(value)) }
                else { completion(.failure(.local(.internalFailure, "unreadable reply"))) }
            }
        }
    }

    /// `component_update`: every profile's PSK, the system extension and each VPN entry, finished
    /// with no form. `psk_unavailable` carries the profile id that has no key.
    func componentUpdate(progress: @escaping (HostProgress) -> Void,
                         completion: @escaping (Result<Void, HostError>) -> Void) {
        request("component_update", timeout: 900, progress: progress) { result in
            completion(result.map { _ in () })
        }
    }

    func checkUpdate(_ completion: @escaping (Result<HostUpdateResult, HostError>) -> Void) {
        request("check_update", timeout: 30, as: HostUpdateResult.self, completion: completion)
    }

    func openSettings(_ pane: HostSettingsPane) {
        request("open_settings", args: ["pane": pane.rawValue], timeout: 10) { _ in }
    }

    // MARK: State machine (on `queue`)

    private func deliver(_ block: @escaping () -> Void) { deliveryQueue.async(execute: block) }

    private func setAvailability(_ next: HostAvailability) {
        guard next != availability else { return }
        availability = next
        deliver { self.onAvailability?(next) }
    }

    private func connect() {
        guard connection == nil else { return }
        generation += 1
        let mine = generation
        lines = HostLineBuffer()
        let created = makeConnection(configuration.socketPath, queue)
        connection = created
        created.onData = { [weak self] data in
            self?.queue.async { self?.receive(data, generation: mine) }
        }
        created.onClosed = { [weak self] in
            self?.queue.async { self?.closed(generation: mine) }
        }
        created.start { [weak self] error in
            self?.queue.async {
                guard let self, self.generation == mine else { return }
                if error == nil { self.sendHello() } else { self.connectFailed() }
            }
        }
    }

    private func sendHello() {
        let id = nextID
        nextID += 1
        pending[id] = Pending(progress: nil, internalRequest: true) { [weak self] result in
            self?.helloReplied(result)
        }
        let client: [String: Any] = ["kind": "ui", "version": configuration.clientVersion, "build": configuration.clientBuild]
        connection?.send(HostFrame.encode(id: id, op: "hello",
            args: ["protocol": [Self.protocolRange.min, Self.protocolRange.max], "client": client]))
        // One deadline for the exchange, as the host has.
        let mine = generation
        queue.asyncAfter(deadline: .now() + 10) {
            guard self.generation == mine, self.availability != .ready, self.connection != nil else { return }
            self.connection?.cancel()
        }
    }

    private func helloReplied(_ result: Result<Data, HostError>) {
        switch result {
        case .failure(let error) where error.code == .unsupportedSchema:
            // No retry: nothing changes until the app or the host is updated. A wake or a
            // window opening tries once more.
            setAvailability(.unavailable(.unsupported(error.detail)))
            connection?.cancel()
        case .failure:
            break // the connection is closing; `closed` takes it from here
        case .success(let data):
            guard let hello = try? HostWire.decoder.decode(HostHello.self, from: data) else { connection?.cancel(); return }
            if olderThanUI(hello.host.build), !restartedForBuild {
                // The UI started before the host service picked up the new bundle: ask for the
                // same restart the installer does, once, then reconnect to the new host.
                restartedForBuild = true
                setAvailability(.unavailable(.updating))
                connection?.cancel()
                starterQueue.async {
                    _ = self.starter.restart()
                    self.queue.async { self.attempt = 0; self.scheduleRetry(after: 0.5) }
                }
                return
            }
            attempt = 0
            approvalPending = false
            forceStart = false
            lastSeq = 0
            setAvailability(.ready)
            let topics: [String: Any] = ["topics": ["status", "traffic"]]
            let id = nextID
            nextID += 1
            pending[id] = Pending(progress: nil, internalRequest: true) { _ in }
            connection?.send(HostFrame.encode(id: id, op: "subscribe", args: topics))
        }
    }

    private func olderThanUI(_ hostBuild: String) -> Bool {
        let ours = configuration.clientBuild
        return !ours.isEmpty && !hostBuild.isEmpty && hostBuild.compare(ours, options: .numeric) == .orderedAscending
    }

    private func receive(_ data: Data, generation mine: Int) {
        guard generation == mine, connection != nil else { return }
        guard let batch = lines.feed(data) else { connection?.cancel(); return }
        for line in batch {
            switch HostFrame.parse(line) {
            case .reply(let id, let result, let error):
                guard let waiting = pending.removeValue(forKey: id) else { continue }
                complete(waiting, error.map { .failure($0) } ?? .success(result ?? Data("{}".utf8)))
            case .progress(let id, let progress):
                if let handler = pending[id]?.progress { deliver { handler(progress) } }
            case .status(let status): accept(status)
            case .traffic(let event): deliver { self.onTraffic?(event) }
            case .ignored: break
            }
        }
    }

    private func accept(_ status: HostStatus) {
        guard status.seq > lastSeq || lastStatus == nil else { return }
        lastSeq = status.seq
        lastStatus = status
        deliver { self.onStatus?(status) }
    }

    private func connectFailed() {
        connection?.cancel()
        connection = nil
        unreachable()
    }

    private func closed(generation mine: Int) {
        guard generation == mine, connection != nil else { return }
        connection = nil
        failPending(.local(.hostUnavailable, "the connection to OFTC's VPN service closed"))
        switch availability {
        case .unavailable(.unsupported), .unavailable(.updating):
            return // `unsupported` waits for a wake or a window; `updating` has its retry scheduled
        default: unreachable()
        }
    }

    private func failPending(_ error: HostError) {
        let waiting = pending
        pending = [:]
        for (_, entry) in waiting { complete(entry, .failure(error)) }
    }

    /// No server answered. Start it unless it was started (or is waiting for approval) lately,
    /// then retry with backoff.
    private func unreachable() {
        if availability != .unavailable(.needsApproval) { setAvailability(.unavailable(.notRunning)) }
        guard active else { return }
        let due = lastStartAt.map { Date().timeIntervalSince($0) >= configuration.startFloor } ?? true
        if !approvalPending && (due || forceStart) {
            forceStart = false
            lastStartAt = Date()
            starterQueue.async {
                let result = self.starter.start()
                self.queue.async {
                    switch result {
                    case .started: self.scheduleRetry(after: self.configuration.backoff.first ?? 0.5)
                    case .needsApproval:
                        self.approvalPending = true
                        self.setAvailability(.unavailable(.needsApproval))
                        self.scheduleRetry(after: self.nextDelay()) // the service starts itself once allowed
                    case .failed: self.scheduleRetry(after: self.nextDelay())
                    }
                }
            }
            return
        }
        scheduleRetry(after: nextDelay())
    }

    private func nextDelay() -> TimeInterval {
        defer { attempt += 1 }
        return attempt < configuration.backoff.count ? configuration.backoff[attempt] : configuration.steadyRetry
    }

    private func scheduleRetry(after delay: TimeInterval) {
        guard !retryScheduled else { return }
        retryScheduled = true
        queue.asyncAfter(deadline: .now() + delay) {
            self.retryScheduled = false
            guard self.connection == nil, self.active else { return }
            self.connect()
        }
    }
}
