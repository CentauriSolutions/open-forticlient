import Foundation
import NetworkExtension

// Compiled offline to check the actual host/provider API signatures. This
// prototype intentionally has no installed extension or network settings.
enum HostHandoff {
    static func start(_ connection: NEVPNConnection,
                      bootstrap: BootstrapWire.Payload,
                      now: UInt64) throws {
        let bytes = try BootstrapWire.encode(bootstrap, now: now)
        try connection.startVPNTunnel(options: [BootstrapWire.optionKey: bytes as NSData])
    }
}

final class OfflinePrototypeProvider: NEPacketTunnelProvider {
    override func startTunnel(options: [String: NSObject]?,
                              completionHandler: @escaping (Error?) -> Void) {
        // A real provider would move the payload immediately into the Rust IKE
        // engine, authenticate, set tunnel settings, then complete with nil.
        // Fail closed here: this class is only a compile-time interface probe.
        _ = try? BootstrapWire.fromStartOptions(options,
                                                 now: UInt64(Date().timeIntervalSince1970))
        completionHandler(NSError(domain: "OFTCOfflinePrototype", code: 1))
    }

    override func stopTunnel(with reason: NEProviderStopReason,
                             completionHandler: @escaping () -> Void) {
        completionHandler()
    }
}
