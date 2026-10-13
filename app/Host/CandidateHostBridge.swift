import Foundation
import NetworkExtension

private struct RustWireBuffer {
    var data: UnsafeMutablePointer<UInt8>?
    var count: Int
}

@_silgen_name("oftc_host_acquire")
private func rustAcquire(_ gateway: UnsafePointer<UInt8>?, _ gatewayLength: Int,
                         _ psk: UnsafePointer<UInt8>?, _ pskLength: Int,
                         _ samlPort: UInt32, _ insecure: UInt8,
                         _ output: UnsafeMutablePointer<RustWireBuffer>) -> Int32

@_silgen_name("oftc_host_free_wire")
private func rustFreeWire(_ data: UnsafeMutablePointer<UInt8>?, _ count: Int)

enum CandidateHostBridge {
    enum Failure: Error { case acquisition, beforeBrowser, invalidWire }

    // This method is also used by the delayed-SSO synthetic check. The clock
    // is sampled only after Rust returns the SAML callback and this method is
    // entered; a login lasting minutes cannot age out a fresh envelope.
    static func optionsFromWire(_ wire: Data, clock: () -> UInt64) throws -> [String: NSObject] {
        guard (12...4096).contains(wire.count) else { throw Failure.invalidWire }
        let now = clock()
        let payload = BootstrapWire.Payload(expiresAt: now + 60,
            sessionID: withUnsafeBytes(of: UUID().uuid) { Data($0) }, secret: wire)
        let envelope = try BootstrapWire.encode(payload, now: now)
        return [BootstrapWire.optionKey: envelope as NSData]
    }

    static func acquireOptions(gateway: String, psk: Data, samlPort: UInt32,
                               insecure: Bool) throws -> [String: NSObject] {
        var wire = RustWireBuffer(data: nil, count: 0)
        let gatewayBytes = Array(gateway.utf8)
        // rustAcquire can block for the entire browser SAML flow. Do not
        // evaluate Date() until after this call has returned successfully.
        let status = gatewayBytes.withUnsafeBufferPointer { host in
            psk.withUnsafeBytes { secret in
                rustAcquire(host.baseAddress, host.count,
                    secret.bindMemory(to: UInt8.self).baseAddress, secret.count,
                    samlPort, insecure ? 1 : 0, &wire)
            }
        }
        defer { rustFreeWire(wire.data, wire.count) }
        if status == 3 { throw Failure.beforeBrowser }
        guard status == 0, let data = wire.data,
              (12...4096).contains(wire.count) else { throw Failure.acquisition }
        var ownedCopy = Data(bytes: data, count: wire.count)
        defer { ownedCopy.resetBytes(in: 0..<ownedCopy.count) }
        return try optionsFromWire(ownedCopy,
            clock: { UInt64(Date().timeIntervalSince1970) })
    }

    static func start(_ connection: NEVPNConnection,
                      options: [String: NSObject]) throws {
        try connection.startVPNTunnel(options: options)
    }
}
