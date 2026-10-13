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

#if OFTC_SYNTHETIC
@_silgen_name("oftc_host_prepare_synthetic")
private func rustSynthetic(_ output: UnsafeMutablePointer<RustWireBuffer>) -> Int32
#endif

enum HostBridgeError: Error {
    case acquisitionFailed
    case invalidWire
}

enum HostBootstrapBridge {
    private static func wrap(_ wire: RustWireBuffer, now: UInt64) throws -> [String: NSObject] {
        guard let data = wire.data, (12...4096).contains(wire.count) else {
            throw HostBridgeError.invalidWire
        }
        // The Rust allocation is wiped after this copy. Foundation and
        // NetworkExtension may retain transient copies of the NSData value.
        let secret = Data(bytes: data, count: wire.count)
        let sessionID = withUnsafeBytes(of: UUID().uuid) { Data($0) }
        let payload = BootstrapWire.Payload(expiresAt: now + 60,
                                            sessionID: sessionID, secret: secret)
        return [BootstrapWire.optionKey: try BootstrapWire.encode(payload, now: now) as NSData]
    }

    static func acquireOptions(gateway: String, psk: Data, samlPort: UInt32,
                               insecure: Bool, now: UInt64) throws -> [String: NSObject] {
        var wire = RustWireBuffer(data: nil, count: 0)
        let gatewayBytes = Array(gateway.utf8)
        let status = gatewayBytes.withUnsafeBufferPointer { host in
            psk.withUnsafeBytes { secret in
                rustAcquire(host.baseAddress, host.count,
                            secret.bindMemory(to: UInt8.self).baseAddress, secret.count,
                            samlPort, insecure ? 1 : 0, &wire)
            }
        }
        defer { rustFreeWire(wire.data, wire.count) }
        guard status == 0 else { throw HostBridgeError.acquisitionFailed }
        return try wrap(wire, now: now)
    }

    #if OFTC_SYNTHETIC
    static func syntheticOptions(now: UInt64) throws -> [String: NSObject] {
        var wire = RustWireBuffer(data: nil, count: 0)
        let status = rustSynthetic(&wire)
        defer { rustFreeWire(wire.data, wire.count) }
        guard status == 0 else { throw HostBridgeError.acquisitionFailed }
        return try wrap(wire, now: now)
    }
    #endif

    // The signed IntegrationHost can call this after it loads its existing
    // NETunnelProviderManager. It is typechecked here, never invoked by tests.
    static func start(_ connection: NEVPNConnection,
                      options: [String: NSObject]) throws {
        try connection.startVPNTunnel(options: options)
    }
}
