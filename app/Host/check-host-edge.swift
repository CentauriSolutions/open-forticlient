import Darwin
import Foundation

// Offline check of HostEdge: the golden documents core/ui-edge pins (decoded here as the
// UI decodes them), the framing, and the client against a scripted host on a temporary
// unix socket. No real host, launchd, Network Extension or user directory is touched: the
// socket lives under /private/tmp and the "starter" is a double that counts its calls.

// A failed check removes this run's own scratch directory before it stops (a trap would skip the
// `defer` that normally does).
var scratch: String?

func failNow(_ message: String = "", line: UInt = #line) -> Never {
    FileHandle.standardError.write(Data("host-edge check failed (\(line)): \(message)\n".utf8))
    if let scratch { try? FileManager.default.removeItem(atPath: scratch) }
    exit(1)
}

func require(_ condition: @autoclosure () -> Bool, _ message: String = "", line: UInt = #line) {
    if !condition() { failNow(message, line: line) }
}

// MARK: Scripted host

final class FakeHost {
    let path: String
    private var listener: Int32 = -1
    private let lock = NSLock()
    private var clients: [Int32] = []
    private var log: [[String: Any]] = []
    private var accepted = 0
    var build = "24"
    var statusSeq: UInt64 = 5
    /// Replies for ops the standard script does not know: return a line, or nil to stay silent.
    var custom: (([String: Any]) -> [String]?)?
    var rejectHello = false
    /// Answers `hello`, then closes: a host that dies as soon as it is reached.
    var dropAfterHello = false

    init(directory: String) { path = directory + "/h.sock" }

    var requests: [[String: Any]] { lock.lock(); defer { lock.unlock() }; return log }
    var connections: Int { lock.lock(); defer { lock.unlock() }; return accepted }
    func ops(_ name: String) -> [[String: Any]] { requests.filter { $0["op"] as? String == name } }

    func start() {
        unlink(path)
        listener = socket(AF_UNIX, SOCK_STREAM, 0)
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        _ = withUnsafeMutablePointer(to: &address.sun_path) {
            $0.withMemoryRebound(to: CChar.self, capacity: 104) { strncpy($0, path, 103) }
        }
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(listener, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        require(bound == 0 && listen(listener, 8) == 0, "fake host could not listen")
        let fd = listener
        Thread.detachNewThread { [self] in
            while true {
                let client = accept(fd, nil, nil)
                if client < 0 { return }
                var on: Int32 = 1
                setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &on, 4)
                lock.lock(); clients.append(client); accepted += 1; lock.unlock()
                Thread.detachNewThread { self.serve(client) }
            }
        }
    }

    /// The host going away: the listener and every client close and the socket file goes.
    func stop() {
        lock.lock()
        let open = clients
        clients = []
        lock.unlock()
        if listener >= 0 { shutdown(listener, SHUT_RDWR); close(listener); listener = -1 }
        for client in open { shutdown(client, SHUT_RDWR); close(client) }
        unlink(path)
    }

    func write(_ line: String, to client: Int32) {
        let bytes = Array((line + "\n").utf8)
        _ = bytes.withUnsafeBytes { Darwin.send(client, $0.baseAddress, $0.count, 0) }
    }

    func broadcast(_ line: String) {
        lock.lock(); let open = clients; lock.unlock()
        for client in open { write(line, to: client) }
    }

    func statusLine(build: String? = nil) -> String {
        """
        {"event":"status","seq":\(statusSeq),"status":{"schema":1,"generated":"2026-11-04T12:00:00Z","seq":\(statusSeq),\
        "host":{"version":"0.9.0","build":"\(build ?? self.build)","provider_build":"24"},\
        "component":{"state":"ready","installed_build":"24","expected_build":"24"},\
        "login":{"menu_item":"enabled","agent":"enabled","host_agent":"enabled"},\
        "profiles":[{"id":"c2","name":"Office VPN","gateway":"vpn.example.com","saml_port":9443,"transport":"udp",\
        "auto_start":true,"state":"connected","ne_status":"connected","phase":"connected",\
        "connected_since":"2026-11-04T11:18:00Z","traffic":null,"error":null}]}}
        """
    }

    private func serve(_ client: Int32) {
        var pending = Data()
        var chunk = [UInt8](repeating: 0, count: 4096)
        while true {
            let count = read(client, &chunk, chunk.count)
            if count <= 0 { return }
            pending.append(contentsOf: chunk[0..<count])
            while let newline = pending.firstIndex(of: 0x0A) {
                let line = pending[pending.startIndex..<newline]
                pending.removeSubrange(pending.startIndex...newline)
                guard let message = (try? JSONSerialization.jsonObject(with: line)) as? [String: Any] else { continue }
                lock.lock(); log.append(message); lock.unlock()
                reply(to: message, client: client)
            }
        }
    }

    private func reply(to message: [String: Any], client: Int32) {
        let id = message["id"] as? Int ?? 0
        switch message["op"] as? String {
        case "hello"?:
            if rejectHello {
                write(#"{"id":\#(id),"ok":false,"error":{"code":"unsupported_schema","detail":"host speaks protocol 2","exit":5}}"#, to: client)
                shutdown(client, SHUT_RDWR)
            } else {
                write(#"{"id":\#(id),"ok":true,"result":{"protocol":1,"host":{"version":"0.9.0","build":"\#(build)","provider_build":"24"}}}"#, to: client)
                if dropAfterHello { shutdown(client, SHUT_RDWR) }
            }
        case "subscribe"?:
            write(#"{"id":\#(id),"ok":true,"result":{}}"#, to: client)
            write(statusLine(), to: client)
        default:
            for line in custom?(message) ?? [] { write(line, to: client) }
        }
    }
}

final class FakeStarter: HostStarter {
    private let lock = NSLock()
    private var starts = 0, restarts = 0
    var result = HostStartResult.started
    var onRestart: (() -> Void)?
    var startCount: Int { lock.lock(); defer { lock.unlock() }; return starts }
    var restartCount: Int { lock.lock(); defer { lock.unlock() }; return restarts }
    func start() -> HostStartResult { lock.lock(); starts += 1; lock.unlock(); return result }
    func restart() -> Bool { lock.lock(); restarts += 1; lock.unlock(); onRestart?(); return true }
}

// MARK: Check

@main enum HostEdgeCheck {
    static func wait(_ what: String, timeout: TimeInterval = 5, _ condition: () -> Bool) {
        let deadline = Date().addingTimeInterval(timeout)
        while !condition() && Date() < deadline { RunLoop.main.run(until: Date().addingTimeInterval(0.01)) }
        require(condition(), "timed out waiting for \(what)")
    }

    static func pause(_ seconds: TimeInterval) { RunLoop.main.run(until: Date().addingTimeInterval(seconds)) }

    static func main() throws {
        guard CommandLine.arguments.count == 2 else { fatalError("usage: host-edge-check <core/ui-edge/tests/golden>") }
        signal(SIGPIPE, SIG_IGN)
        try goldenDocuments(URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true))
        framing()
        let directory = "/private/tmp/oftc-he-\(UUID().uuidString.prefix(8))"
        try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
        scratch = directory
        defer { try? FileManager.default.removeItem(atPath: directory) }
        var count = 0
        for scenario in [handshakeAndRequests, unsupportedSchema, olderHostIsRestarted,
                         reconnectAfterTheHostRestarts, notRunningAndApproval, requestTimeout, inactiveMenuDoesNotRetry,
                         staleHostIsRestartedOnlyOnce, startsAreFloored, aHostThatDiesAtOnceIsNotStartedInALoop,
                         approvalPendingIsNotRegisteredAgain] {
            count += 1
            try FileManager.default.createDirectory(atPath: "\(directory)/\(count)", withIntermediateDirectories: true)
            scenario("\(directory)/\(count)")
        }
        print("host edge checks passed: golden documents, framing and \(count) scripted-host scenarios")
    }

    static func edge(_ host: FakeHost, starter: FakeStarter, build: String = "24", floor: TimeInterval = 60) -> HostEdge {
        HostEdge(configuration: .init(socketPath: host.path, clientVersion: "0.9.0", clientBuild: build,
                                      backoff: [0.05, 0.05, 0.1], steadyRetry: 0.1, startFloor: floor, requestTimeout: 5),
                 starter: starter)
    }

    // MARK: Golden documents (the files core/ui-edge pins)

    static func golden(_ directory: URL, _ name: String) throws -> Data {
        try Data(contentsOf: directory.appendingPathComponent(name))
    }

    static func goldenDocuments(_ dir: URL) throws {
        let status = try HostWire.decoder.decode(HostStatus.self,
            from: Data(contentsOf: dir.appendingPathComponent("status.json")))
        require(status.schema == 1 && status.seq == 1771 && status.host.build == "24")
        require(status.component.state == .ready && status.component.installedBuild == "24")
        require(status.login.menuItem == .enabled && status.login.hostAgent == .enabled)
        let first = status.profiles[0], second = status.profiles[1]
        require(first.id == "c2" && first.samlPort == 9443 && first.transport == "udp" && first.autoStart)
        require(first.state == .connected && first.connectedDate == Date(timeIntervalSince1970: 1_793_791_080))
        require(first.traffic == HostTraffic(session: "9f1c2e7a", rxBytes: 842_000_000, txBytes: 96_000_000,
                                                  rxRate: 1_200_000, txRate: 84_000, sampleSeq: 12))
        require(second.state == .signIn && second.traffic == nil && !second.autoStart)
        require(second.error == HostProfileError(code: .networkBlocked, detail: "The gateway did not answer over UDP or over TCP. This network may block UDP."))

        func frame(_ name: String) throws -> HostFrame { HostFrame.parse(try golden(dir, name)) }
        guard case .status(let event) = try frame("event_status.json") else { failNow("status event") }
        require(event.seq == 1772 && event.component.state == .checking && event.component.installedBuild == nil
                     && event.login.agent == .requiresApproval && event.login.hostAgent == .notFound && event.profiles.isEmpty)
        guard case .traffic(let traffic) = try frame("event_traffic.json") else { failNow("traffic event") }
        require(traffic.profile == "c2" && traffic.sample.rxRate == 1_100_000 && traffic.sample.txRate == nil
                     && traffic.sample.sampleSeq == 13)
        let progress = try frame("event_progress.json")
        require(progress == .progress(id: 9, HostProgress(step: "extension_approval", state: "waiting")))
        guard case .reply(1, let hello?, nil) = try frame("hello_reply.json") else { failNow("hello reply") }
        let host = try HostWire.decoder.decode(HostInfo.self, from: JSONSerialization.data(
            withJSONObject: (JSONSerialization.jsonObject(with: hello) as! [String: Any])["host"]!))
        require(host == HostInfo(version: "0.9.0", build: "24", providerBuild: "24"))
        guard case .reply(1, nil, let schema?) = try frame("error_unsupported_schema.json") else { failNow("schema error") }
        require(schema.code == .unsupportedSchema && schema.exit == 5)
        guard case .reply(10, nil, let configured?) = try frame("error_already_configured.json") else { failNow("configured") }
        require(configured.code == .alreadyConfigured && configured.profileId == "c2")
        guard case .reply(11, let preview?, nil) = try frame("import_preview_reply.json") else { failNow("preview") }
        let items = try HostWire.decoder.decode(HostImportPreview.self, from: preview).profiles
        require(items == [HostImportItem(name: "Office VPN", gateway: "vpn.example.com", alreadyConfigured: true)])

        // A newer host within one protocol number: unknown values and fields never break a reader.
        let future = Data(#"""
        {"event":"status","seq":9,"status":{"schema":1,"generated":"g","seq":9,"extra":1,
         "host":{"version":"1","build":"2","provider_build":"3"},
         "component":{"state":"quantum","installed_build":null,"expected_build":null},
         "login":{"menu_item":"limbo","agent":"enabled","host_agent":"enabled"},
         "profiles":[{"id":"x","name":"X","gateway":"g","saml_port":1,"transport":"udp","auto_start":false,
          "state":"levitating","new_field":true,"connected_since":null,"traffic":null,
          "error":{"code":"brand_new","detail":"d"}}]}}
        """#.utf8)
        guard case .status(let newer) = HostFrame.parse(future) else { failNow("future status") }
        require(newer.component.state == .unavailable && newer.login.menuItem == .notFound
                     && newer.profiles[0].state == .attention && newer.profiles[0].error?.code == .internalFailure)
        require(HostFrame.parse(Data(#"{"event":"surprise","x":1}"#.utf8)) == .ignored)
    }

    // MARK: Framing

    static func framing() {
        require(HostFrame.encode(id: 7, op: "connect", args: ["profile": "c2"])
            == Data(#"{"id":7,"op":"connect","profile":"c2"}"#.utf8 + [0x0A]))
        var buffer = HostLineBuffer()
        require(buffer.feed(Data(#"{"a":1}"#.utf8 + [0x0A] + #"{"b""#.utf8))?.count == 1)
        require(buffer.feed(Data(#":2}"#.utf8 + [0x0A, 0x0A]))?.map { String(decoding: $0, as: UTF8.self) } == [#"{"b":2}"#])
        var long = HostLineBuffer()
        require(long.feed(Data(repeating: 0x61, count: HostFrame.maxLine + 1)) == nil) // no newline in sight
        var long2 = HostLineBuffer()
        require(long2.feed(Data(repeating: 0x61, count: HostFrame.maxLine + 1) + [0x0A]) == nil)
        var edge = HostLineBuffer()
        require(edge.feed(Data(repeating: 0x61, count: HostFrame.maxLine) + [0x0A])?.count == 1)
    }

    // MARK: Scenarios against the scripted host

    /// hello, subscribe, the first status and traffic events, a reply, a typed error, and progress.
    static func handshakeAndRequests(_ directory: String) {
        let host = FakeHost(directory: directory)
        host.custom = { message in
            let id = message["id"] as! Int
            switch message["op"] as! String {
            case "connect":
                return [#"{"id":\#(id),"event":"progress","step":"keychain","state":"running"}"#,
                        #"{"id":\#(id),"ok":false,"error":{"code":"approval_required","detail":"x","exit":4}}"#]
            case "remove": return [#"{"id":\#(id),"ok":true,"result":{}}"#]
            case "import": return [#"{"id":\#(id),"ok":true,"result":{"added":["lab"]}}"#]
            default: return nil
            }
        }
        host.start(); defer { host.stop() }
        let starter = FakeStarter()
        let client = edge(host, starter: starter)
        var states: [HostAvailability] = [], statuses: [HostStatus] = [], samples: [HostTrafficEvent] = []
        client.onAvailability = { states.append($0) }
        client.onStatus = { statuses.append($0) }
        client.onTraffic = { samples.append($0) }
        client.start()
        wait("the first status") { !statuses.isEmpty }
        require(states == [.ready] && statuses[0].profiles[0].state == .connected)
        let hello = host.ops("hello")[0]
        require(hello["id"] as? Int == 1 && hello["protocol"] as? [Int] == [1, 1])
        let who = hello["client"] as? [String: String]
        require(who == ["kind": "ui", "version": "0.9.0", "build": "24"])
        require(host.ops("subscribe")[0]["topics"] as? [String] == ["status", "traffic"])
        require(starter.startCount == 0, "a host that is there is never started")

        host.broadcast(#"{"event":"traffic","profile":"c2","session":"9f1c","rx_bytes":5,"tx_bytes":6,"rx_rate":1.5,"tx_rate":null,"sample_seq":3}"#)
        wait("a traffic event") { !samples.isEmpty }
        require(samples[0].profile == "c2" && samples[0].sample.rxRate == 1.5)
        // An older status document (seq not above the last) is ignored.
        host.statusSeq = 3
        host.broadcast(host.statusLine())
        pause(0.2)
        require(statuses.count == 1)

        var progress: [HostProgress] = [], failure: HostError?
        client.request("connect", args: ["profile": "c2"], progress: { progress.append($0) }) { result in
            if case .failure(let error) = result { failure = error }
        }
        wait("the typed error") { failure != nil }
        require(failure?.code == .approvalRequired && failure?.exit == 4)
        require(progress == [HostProgress(step: "keychain", state: "running")])
        require(host.ops("connect")[0]["profile"] as? String == "c2")

        var removed = false
        client.request("remove", args: ["profile": "c2"]) { if case .success = $0 { removed = true } }
        wait("remove") { removed }
        var added: [String]?
        client.request("import", args: ["path": "/tmp/x.oftc"], as: HostImportResult.self) {
            if case .success(let value) = $0 { added = value.added }
        }
        wait("a typed result") { added != nil }
        require(added == ["lab"])
        // Ids are distinct and increase on one connection.
        let ids = host.requests.compactMap { $0["id"] as? Int }
        require(ids == Array(1...ids.count))
        client.stop()
    }

    /// An unsupported protocol is not retried: the UI says "Update OFTC" until a wake or a window.
    static func unsupportedSchema(_ directory: String) {
        let host = FakeHost(directory: directory)
        host.rejectHello = true
        host.start(); defer { host.stop() }
        let client = edge(host, starter: FakeStarter())
        var state: HostAvailability?
        client.onAvailability = { state = $0 }
        client.start()
        wait("unsupported") { state == .unavailable(.unsupported("host speaks protocol 2")) }
        pause(0.5)
        require(host.connections == 1, "no retry for an unsupported schema")
        var refused: HostError?
        client.request("status") { if case .failure(let error) = $0 { refused = error } }
        wait("the refused request") { refused != nil }
        require(refused?.code == .hostUnavailable && refused?.exit == 5)
        // A window opening tries once more (the host is still too new, so the state stays).
        client.retryNow()
        wait("one more attempt") { host.connections == 2 }
        client.stop()
    }

    /// A host older than the UI (an upgrade left it running) is restarted once, then used.
    static func olderHostIsRestarted(_ directory: String) {
        let host = FakeHost(directory: directory)
        host.build = "23"
        host.start(); defer { host.stop() }
        let starter = FakeStarter()
        starter.onRestart = { host.build = "24" } // the service comes back as the new build
        let client = edge(host, starter: starter)
        var states: [HostAvailability] = []
        client.onAvailability = { states.append($0) }
        client.start()
        wait("the restarted host") { states.last == .ready }
        require(states == [.unavailable(.updating), .ready])
        require(starter.restartCount == 1 && host.connections == 2)
        // A host that stays older is used rather than restarted in a loop.
        client.stop()
    }

    /// The host restarts under a connected UI: the request in flight fails, the old document stays,
    /// the service is started once, and the UI reconnects, says hello and subscribes again.
    static func reconnectAfterTheHostRestarts(_ directory: String) {
        let host = FakeHost(directory: directory)
        host.custom = { _ in nil } // `connect` is never answered
        host.start()
        let starter = FakeStarter()
        let client = edge(host, starter: starter)
        var states: [HostAvailability] = [], statuses: [HostStatus] = []
        client.onAvailability = { states.append($0) }
        client.onStatus = { statuses.append($0) }
        client.start()
        wait("ready") { states == [.ready] && statuses.count == 1 }
        var inFlight: HostError?
        client.request("connect", args: ["profile": "c2"]) { if case .failure(let e) = $0 { inFlight = e } }
        wait("the request to arrive") { !host.ops("connect").isEmpty }

        host.stop()
        wait("unavailable") { states.last == .unavailable(.notRunning) }
        wait("the in-flight failure") { inFlight != nil }
        require(inFlight?.code == .hostUnavailable, "a dropped request is not retried by the UI")
        require(host.ops("connect").count == 1)
        wait("the service start") { starter.startCount == 1 }
        pause(0.4) // several retries with nothing listening
        require(starter.startCount == 1, "the service is started once per outage")

        host.statusSeq = 1 // a new host numbers its documents from 1 again
        host.start(); defer { host.stop() }
        wait("ready again") { states.last == .ready && statuses.count == 2 }
        require(statuses[1].seq == 1)
        require(host.ops("hello").count == 2 && host.ops("subscribe").count == 2)
        require(starter.startCount == 1)
        client.stop()
    }

    /// No socket at all: the edge starts the service; one that needs approval says so.
    static func notRunningAndApproval(_ directory: String) {
        let host = FakeHost(directory: directory) // never started: no socket file
        let starter = FakeStarter()
        starter.result = .needsApproval
        let client = edge(host, starter: starter)
        var states: [HostAvailability] = []
        client.onAvailability = { states.append($0) }
        client.start()
        wait("approval") { states.last == .unavailable(.needsApproval) }
        require(states == [.unavailable(.notRunning), .unavailable(.needsApproval)])
        require(starter.startCount == 1)
        // The user approves; the service now answers; a window opening finds it.
        host.start(); defer { host.stop() }
        client.retryNow()
        wait("ready") { states.last == .ready }
        client.stop()
    }

    /// A request nobody answers ends with `timeout`, and the host is told to cancel it.
    static func requestTimeout(_ directory: String) {
        let host = FakeHost(directory: directory)
        host.custom = { _ in nil }
        host.start(); defer { host.stop() }
        let client = edge(host, starter: FakeStarter())
        var ready = false
        client.onAvailability = { ready = $0 == .ready }
        client.start()
        wait("ready") { ready }
        var failure: HostError?
        client.request("connect", args: ["profile": "c2"], timeout: 0.2) { if case .failure(let e) = $0 { failure = e } }
        wait("the timeout") { failure != nil }
        require(failure?.code == .timeout)
        wait("the cancel") { !host.ops("cancel").isEmpty }
        require(host.ops("cancel")[0]["target"] as? Int == host.ops("connect")[0]["id"] as? Int)
        client.stop()
    }

    /// While the menu is not visible and no window is open the edge neither starts nor retries.
    static func inactiveMenuDoesNotRetry(_ directory: String) {
        let host = FakeHost(directory: directory)
        let starter = FakeStarter()
        let client = edge(host, starter: starter)
        client.setActive(false)
        var states: [HostAvailability] = []
        client.onAvailability = { states.append($0) }
        client.start()
        wait("unavailable") { states == [.unavailable(.notRunning)] }
        pause(0.4)
        require(starter.startCount == 0 && host.connections == 0)
        host.start(); defer { host.stop() }
        client.setActive(true)
        wait("ready after the window opens") { states.last == .ready }
        client.stop()
    }

    /// A host that is still older after the restart is used, not restarted in a loop.
    static func staleHostIsRestartedOnlyOnce(_ directory: String) {
        let host = FakeHost(directory: directory)
        host.build = "23"
        host.start(); defer { host.stop() }
        let starter = FakeStarter() // `restart` changes nothing: the host stays build 23
        let client = edge(host, starter: starter)
        var states: [HostAvailability] = []
        client.onAvailability = { states.append($0) }
        client.start()
        wait("the old host to be used") { states.last == .ready }
        pause(0.3)
        require(starter.restartCount == 1 && host.connections == 2)
        client.stop()
    }

    /// Opening the menu while the host is down does not start the service each time; only the
    /// user's own "Start service" does.
    static func startsAreFloored(_ directory: String) {
        let host = FakeHost(directory: directory) // never started
        let starter = FakeStarter()
        let client = edge(host, starter: starter)
        client.start()
        wait("the first start") { starter.startCount == 1 }
        for _ in 0..<3 { client.retryNow(); client.setActive(true); pause(0.15) }
        require(starter.startCount == 1, "menu opens and wakes do not re-arm the start")
        client.retryNow(startService: true)
        wait("the user's start") { starter.startCount == 2 }
        client.stop()
    }

    /// A host that answers hello and dies each time is started once, not on every cycle.
    static func aHostThatDiesAtOnceIsNotStartedInALoop(_ directory: String) {
        let host = FakeHost(directory: directory)
        host.dropAfterHello = true
        host.start(); defer { host.stop() }
        let starter = FakeStarter()
        let client = edge(host, starter: starter)
        client.start()
        wait("several connections") { host.connections >= 4 }
        require(starter.startCount == 1, "started \(starter.startCount) times")
        client.stop()
    }

    /// While macOS waits for the user's approval the service is not registered again.
    static func approvalPendingIsNotRegisteredAgain(_ directory: String) {
        let host = FakeHost(directory: directory)
        let starter = FakeStarter()
        starter.result = .needsApproval
        let client = edge(host, starter: starter, floor: 0) // only the approval holds it back
        var state: HostAvailability?
        client.onAvailability = { state = $0 }
        client.start()
        wait("approval") { state == .unavailable(.needsApproval) }
        for _ in 0..<3 { client.retryNow(); client.retryNow(startService: true); pause(0.15) }
        require(starter.startCount == 1 && state == .unavailable(.needsApproval))
        client.stop()
    }
}
