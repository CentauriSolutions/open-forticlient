import Darwin
import Foundation
import NetworkExtension

@_silgen_name("oftc_crypto_probe") private func cryptoProbe() -> Int32
@_silgen_name("oftc_packet_echo") private func packetEcho(
    _ input: UnsafePointer<UInt8>?, _ inputLength: Int,
    _ output: UnsafeMutablePointer<UInt8>?, _ capacity: Int,
    _ outputLength: UnsafeMutablePointer<Int>?) -> Int32

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private var running = false

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        do {
            try SyntheticStart.validate(options, now: UInt64(Date().timeIntervalSince1970))
        } catch {
            completionHandler(NSError(domain: "OFTCIntegration", code: 2,
                                      userInfo: [NSLocalizedDescriptionKey: "Missing or invalid synthetic start data"]))
            return
        }
        guard cryptoProbe() == 0 else {
            completionHandler(NSError(domain: "OFTCIntegration", code: 1,
                                      userInfo: [NSLocalizedDescriptionKey: "Rust/Swift bridge probe failed"]))
            return
        }
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "198.51.100.254")
        let ipv4 = NEIPv4Settings(addresses: ["192.0.2.2"], subnetMasks: ["255.255.255.255"])
        ipv4.includedRoutes = [NEIPv4Route(destinationAddress: "198.51.100.254",
                                           subnetMask: "255.255.255.255")]
        settings.ipv4Settings = ipv4
        let dns = NEDNSSettings(servers: ["192.0.2.53"])
        dns.matchDomains = ["integration.invalid"]
        dns.matchDomainsNoSearch = true
        settings.dnsSettings = dns
        settings.mtu = 1280
        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self else { completionHandler(error); return }
            if error == nil {
                self.running = true
                self.readNextBatch()
            }
            completionHandler(error)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        running = false
        setTunnelNetworkSettings(nil) { _ in completionHandler() }
    }

    private func readNextBatch() {
        guard running else { return }
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self, self.running else { return }
            for (packet, proto) in zip(packets, protocols) where proto.int32Value == AF_INET {
                var reply = [UInt8](repeating: 0, count: packet.count)
                var replyLength = 0
                let status = packet.withUnsafeBytes { input in
                    reply.withUnsafeMutableBufferPointer { output in
                        packetEcho(input.bindMemory(to: UInt8.self).baseAddress, packet.count,
                                   output.baseAddress, output.count, &replyLength)
                    }
                }
                if status == 0 {
                    let accepted = self.packetFlow.writePackets([Data(reply.prefix(replyLength))],
                                                                 withProtocols: [NSNumber(value: AF_INET)])
                    NSLog("Integration provider: Rust echo reply accepted=%d", accepted ? 1 : 0)
                }
            }
            self.readNextBatch()
        }
    }
}
