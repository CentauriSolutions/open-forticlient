import Darwin
import Foundation
import NetworkExtension

@_silgen_name("oftc_provider_preflight") private func rustPreflight(
    _ gateway: UnsafePointer<UInt8>?, _ gatewayLength: Int,
    _ uid: UnsafePointer<UInt8>?, _ uidLength: Int,
    _ psk: UnsafePointer<UInt8>?, _ pskLength: Int) -> Int32

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let workQueue = DispatchQueue(label: "oftc.provider.session")
    // State below is confined to DispatchQueue.main. The opaque Rust handle
    // has one provider reference until all queued work and teardown finish.
    private var handle: OpaquePointer?
    private var pendingStart: ((Error?) -> Void)?
    private var stopCompletions: [() -> Void] = []
    private var running = false
    private var stopping = false
    private var settingsApplyPending = false
    private var shutdownStarted = false
    private var cleanupFinished = false
    private var preflightResult: Int32?
    private var livenessTimer: DispatchSourceTimer?
    private var livenessTickQueued = false
    private var livenessTickCount = 0
    private var rekeyProbePending = false
    private var traffic = TrafficCounters()

    private func failure(_ code: Int) -> NSError {
        NSError(domain: "OFTCProvider", code: code,
                userInfo: [NSLocalizedDescriptionKey: "OFTC provider stage \(code) failed"])
    }

    override func startTunnel(options: [String: NSObject]?,
                              completionHandler: @escaping (Error?) -> Void) {
        DispatchQueue.main.async {
            guard self.pendingStart == nil, self.handle == nil, !self.stopping else {
                completionHandler(self.failure(1))
                return
            }
            let mode: ProviderStartEnvelope.Mode
            do {
                mode = try ProviderStartEnvelope.consume(options,
                    now: UInt64(Date().timeIntervalSince1970))
            } catch {
                completionHandler(self.failure(2))
                return
            }
            self.pendingStart = completionHandler
            switch mode {
            case .preflight(var input):
                self.workQueue.async {
                    let status = input.gateway.withUnsafeBytes { g in
                        input.uid.withUnsafeBytes { uid in
                            input.psk.withUnsafeBytes { psk in
                                rustPreflight(g.bindMemory(to: UInt8.self).baseAddress, g.count,
                                              uid.bindMemory(to: UInt8.self).baseAddress, uid.count,
                                              psk.bindMemory(to: UInt8.self).baseAddress, psk.count)
                            }
                        }
                    }
                    input.clearSecrets()
                    DispatchQueue.main.async {
                        guard !self.stopping else { return }
                        // Diagnostic-only connection: no addresses, routes,
                        // DNS, or packetFlow are installed. The host reads the
                        // result through a provider message, then stops us.
                        self.preflightResult = status
                        self.pendingStart?(nil)
                        self.pendingStart = nil
                    }
                }
            case .live(var input, let mode):
                guard let handle = oftc_handle_new() else {
                    input.clearSecrets()
                    self.shutdown(self.failure(3))
                    return
                }
                self.handle = handle
                self.workQueue.async {
                    var rawMode = OftcConnectMode()
                    rawMode.transport = mode.transport
                    rawMode.outer_family = mode.outerFamily
                    rawMode.tcp_fallback = mode.tcpFallback
                    withUnsafeMutableBytes(of: &rawMode.idi_v4) { destination in
                        destination.copyBytes(from: mode.idiV4)
                    }
                    let status = input.gateway.withUnsafeBytes { g in
                        input.uid.withUnsafeBytes { uid in
                            input.psk.withUnsafeBytes { psk in
                                input.token.withUnsafeBytes { token in
                                    oftc_connect_mode(handle,
                                        g.bindMemory(to: UInt8.self).baseAddress, g.count,
                                        uid.bindMemory(to: UInt8.self).baseAddress, uid.count,
                                        psk.bindMemory(to: UInt8.self).baseAddress, psk.count,
                                        token.bindMemory(to: UInt8.self).baseAddress, token.count,
                                        &rawMode)
                                }
                            }
                        }
                    }
                    input.clearSecrets()
                    let settings = status == OFTC_OK ? try? FFISettings.read(handle) : nil
                    DispatchQueue.main.async {
                        guard !self.stopping else { return }
                        guard status == OFTC_OK, let settings else {
                            self.shutdown(self.failure(status == OFTC_OK ? 4 : 100 + Int(status)))
                            return
                        }
                        self.settingsApplyPending = true
                        self.setTunnelNetworkSettings(settings) { error in
                            DispatchQueue.main.async {
                                self.settingsApplyPending = false
                                if self.stopping {
                                    self.finishShutdown()
                                    return
                                }
                                if error != nil { self.shutdown(self.failure(5)); return }
                                self.running = true
                                self.traffic = TrafficCounters()
                                self.pendingStart?(nil)
                                self.pendingStart = nil
                                self.readNextBatch()
                                self.pollNext(handle)
                                self.startLivenessTimer(handle)
                            }
                        }
                    }
                }
            }
        }
    }

    private func readNextBatch() {
        guard running, !stopping, let handle else { return }
        packetFlow.readPackets { packets, protocols in
            DispatchQueue.main.async {
                guard self.running, !self.stopping else { return }
                self.sendBatch(packets, protocols, from: 0, handle: handle)
            }
        }
    }

    private func sendBatch(_ packets: [Data], _ protocols: [NSNumber],
                           from start: Int, handle: OpaquePointer) {
        guard running, !stopping else { return }
        let count = min(packets.count, protocols.count)
        if start >= count { readNextBatch(); return }
        // One packetFlow batch is retained at a time. Splitting it into work
        // slices prevents starving inbound ESP without inventing a NE batch cap.
        let end = min(start + 64, count)
        workQueue.async {
            var failed: Int32?
            var sentBytes = 0
            for index in start..<end where protocols[index].int32Value == AF_INET {
                let status = packets[index].withUnsafeBytes { bytes in
                    oftc_send_ip(handle, bytes.bindMemory(to: UInt8.self).baseAddress, bytes.count)
                }
                if status != OFTC_OK && status != OFTC_PACKET_DROPPED {
                    failed = status
                    break
                }
                if status == OFTC_OK { sentBytes += packets[index].count }
            }
            DispatchQueue.main.async {
                guard !self.stopping else { return }
                self.traffic.sent(sentBytes)
                if let failed { self.shutdown(self.failure(200 + Int(failed))) }
                else { self.sendBatch(packets, protocols, from: end, handle: handle) }
            }
        }
    }

    override func handleAppMessage(_ messageData: Data,
                                   completionHandler: ((Data?) -> Void)?) {
        DispatchQueue.main.async {
            if messageData == Data("oftc.traffic.v1".utf8) {
                guard self.running, !self.stopping else {
                    completionHandler?(nil)
                    return
                }
                completionHandler?(try? JSONEncoder().encode(self.traffic.snapshot()))
                return
            }
            if messageData == Data("oftc.rekey-counts.v1".utf8) {
                guard self.running, !self.stopping, let handle = self.handle else {
                    completionHandler?(nil)
                    return
                }
                self.workQueue.async {
                    var counts = OftcRekeyCounts()
                    let status = oftc_rekey_counts(handle, &counts)
                    DispatchQueue.main.async {
                        guard self.running, !self.stopping, status == OFTC_OK else {
                            completionHandler?(nil)
                            return
                        }
                        completionHandler?(Data("child_rekeys local=\(counts.local) peer=\(counts.peer) ike=\(counts.ike)".utf8))
                    }
                }
                return
            }
            if messageData == Data("oftc.rekey-child-once.v1".utf8)
                || messageData == Data("oftc.rekey-ike-once.v1".utf8) {
                let ike = messageData == Data("oftc.rekey-ike-once.v1".utf8)
                guard self.running, !self.stopping, !self.rekeyProbePending,
                      let handle = self.handle else {
                    completionHandler?(Data("rekey_unavailable".utf8))
                    return
                }
                self.rekeyProbePending = true
                self.workQueue.async {
                    let status = ike ? oftc_rekey_ike_once(handle) : oftc_rekey_child_once(handle)
                    DispatchQueue.main.async {
                        self.rekeyProbePending = false
                        if self.stopping {
                            completionHandler?(Data("rekey_stopped".utf8))
                        } else if status == OFTC_OK {
                            completionHandler?(Data("rekey_passed".utf8))
                        } else {
                            completionHandler?(Data("rekey_failed stage=\(status)".utf8))
                            self.shutdown(self.failure(500 + Int(status)))
                        }
                    }
                }
                return
            }
            guard messageData == Data("oftc.preflight-status.v1".utf8),
                  let result = self.preflightResult else {
                completionHandler?(nil)
                return
            }
            let text = result == 0 ? "preflight_passed responder_auth_and_eap_challenge" :
                "preflight_failed stage=\(result)"
            completionHandler?(Data(text.utf8))
        }
    }

    private func pollNext(_ handle: OpaquePointer) {
        guard running, !stopping else { return }
        workQueue.async {
            var bytes = [UInt8](repeating: 0, count: 65_535)
            var length = 0
            var event: UInt32 = 0
            let status = bytes.withUnsafeMutableBufferPointer {
                oftc_receive(handle, $0.baseAddress, $0.count, &length, &event)
            }
            DispatchQueue.main.async {
                guard self.running, !self.stopping else { return }
                if status == OFTC_OK && event == OFTC_EVENT_IP_PACKET {
                    guard (20...bytes.count).contains(length), bytes[0] >> 4 == 4 else {
                        self.shutdown(self.failure(6)); return
                    }
                    let accepted = self.packetFlow.writePackets(
                        [Data(bytes.prefix(length))], withProtocols: [NSNumber(value: AF_INET)])
                    if !accepted { self.shutdown(self.failure(7)); return }
                    self.traffic.received(length)
                } else if status == OFTC_OK &&
                    (event == OFTC_EVENT_PEER_DELETED_IKE ||
                     event == OFTC_EVENT_PEER_DELETED_CHILD) {
                    self.shutdown(self.failure(8)); return
                } else if status != OFTC_OK {
                    self.shutdown(self.failure(300 + Int(status))); return
                }
                self.pollNext(handle)
            }
        }
    }

    private func startLivenessTimer(_ handle: OpaquePointer) {
        guard livenessTimer == nil else { return }
        let timer = DispatchSource.makeTimerSource(queue: .main)
        timer.schedule(deadline: .now() + .seconds(5), repeating: .seconds(5),
                       leeway: .seconds(1))
        timer.setEventHandler { [weak self] in
            guard let self, self.running, !self.stopping,
                  self.handle == handle, !self.livenessTickQueued else { return }
            self.livenessTickQueued = true
            self.livenessTickCount += 1
            let refreshOuterMapping = self.livenessTickCount % 3 == 0
            self.workQueue.async {
                var status = oftc_tick_liveness(handle)
                if status == OFTC_OK && refreshOuterMapping {
                    // The keepalive refreshes NAT state without extending the
                    // authenticated DPD grace period.
                    status = oftc_send_nat_keepalive(handle)
                }
                DispatchQueue.main.async {
                    self.livenessTickQueued = false
                    guard self.running, !self.stopping, self.handle == handle else { return }
                    if status == OFTC_RECONNECT_NEEDED {
                        self.shutdown(self.failure(409))
                    } else if status != OFTC_OK {
                        self.shutdown(self.failure(400 + Int(status)))
                    }
                }
            }
        }
        livenessTimer = timer
        timer.resume()
    }

    override func stopTunnel(with reason: NEProviderStopReason,
                             completionHandler: @escaping () -> Void) {
        DispatchQueue.main.async {
            self.shutdown(self.failure(9), stopCompletion: completionHandler)
        }
    }

    private func shutdown(_ error: Error, stopCompletion: (() -> Void)? = nil) {
        if let stopCompletion {
            if cleanupFinished { stopCompletion() }
            else { stopCompletions.append(stopCompletion) }
        }
        if stopping { return }
        stopping = true
        running = false
        livenessTimer?.cancel()
        livenessTimer = nil
        shutdownError = error
        shutdownWasStarted = pendingStart == nil
        if let handle { _ = oftc_cancel(handle) }
        if settingsApplyPending { return }
        finishShutdown()
    }

    private var shutdownError: Error?
    private var shutdownWasStarted = false

    private func finishShutdown() {
        guard stopping, !shutdownStarted else { return }
        shutdownStarted = true
        let error = shutdownError ?? failure(9)
        let wasStarted = shutdownWasStarted
        let previous = handle
        workQueue.async {
            if let previous {
                var outcome: UInt32 = 0
                _ = oftc_teardown(previous, &outcome)
            }
            DispatchQueue.main.async {
                self.setTunnelNetworkSettings(nil) { _ in
                    DispatchQueue.main.async {
                        if let previous { oftc_handle_release(previous) }
                        self.handle = nil
                        self.cleanupFinished = true
                        self.pendingStart?(error)
                        self.pendingStart = nil
                        let completions = self.stopCompletions
                        self.stopCompletions.removeAll()
                        for completion in completions { completion() }
                        if wasStarted && completions.isEmpty { self.cancelTunnelWithError(error) }
                    }
                }
            }
        }
    }
}
