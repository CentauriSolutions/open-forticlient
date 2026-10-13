import Foundation
import NetworkExtension
import Darwin

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private var running = false
    private let probeAddress: [UInt8] = [198, 51, 100, 254]

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "198.51.100.254")
        let ipv4 = NEIPv4Settings(addresses: ["192.0.2.2"], subnetMasks: ["255.255.255.255"])
        ipv4.includedRoutes = [NEIPv4Route(destinationAddress: "198.51.100.254",
                                           subnetMask: "255.255.255.255")]
        settings.ipv4Settings = ipv4
        let dns = NEDNSSettings(servers: ["192.0.2.53"])
        dns.matchDomains = ["gate0.invalid"]
        dns.matchDomainsNoSearch = true
        settings.dnsSettings = dns
        settings.mtu = 1280
        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self else { completionHandler(error); return }
            if error == nil {
                self.running = true
                NSLog("Gate0 provider: test IP, host route, scoped DNS, and MTU applied")
                self.readNextBatch()
            }
            completionHandler(error)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        running = false
        setTunnelNetworkSettings(nil) { error in
            if let error { NSLog("Gate0 provider: settings cleanup error: %@", String(describing: error)) }
            else { NSLog("Gate0 provider: settings cleared") }
            completionHandler()
        }
    }

    private func readNextBatch() {
        guard running else { return }
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self, self.running else { return }
            for (packet, proto) in zip(packets, protocols) where proto.int32Value == AF_INET {
                guard let reply = self.echoReply(to: packet) else { continue }
                let accepted = self.packetFlow.writePackets([reply], withProtocols: [NSNumber(value: AF_INET)])
                NSLog("Gate0 provider: ICMP echo request read; reply write accepted=%d", accepted ? 1 : 0)
            }
            self.readNextBatch()
        }
    }

    // Respond only to an IPv4 ICMP echo sent to the reserved TEST-NET-2 host.
    // The probe never forwards a packet or opens an outer tunnel connection.
    private func echoReply(to packet: Data) -> Data? {
        var bytes = Array(packet)
        guard bytes.count >= 28, bytes[0] >> 4 == 4 else { return nil }
        let headerLength = Int(bytes[0] & 0x0f) * 4
        guard headerLength >= 20, bytes.count >= headerLength + 8,
              bytes[9] == 1, Array(bytes[16..<20]) == probeAddress,
              bytes[headerLength] == 8, bytes[headerLength + 1] == 0 else { return nil }
        let fragment = (UInt16(bytes[6]) << 8) | UInt16(bytes[7])
        guard fragment & 0x3fff == 0 else { return nil }
        let totalLength = Int(UInt16(bytes[2]) << 8 | UInt16(bytes[3]))
        guard totalLength >= headerLength + 8, totalLength <= bytes.count else { return nil }
        bytes = Array(bytes.prefix(totalLength))
        for index in 0..<4 { bytes.swapAt(12 + index, 16 + index) }
        bytes[8] = 64
        bytes[headerLength] = 0
        bytes[headerLength + 2] = 0
        bytes[headerLength + 3] = 0
        let icmpChecksum = checksum(bytes[headerLength..<totalLength])
        bytes[headerLength + 2] = UInt8(icmpChecksum >> 8)
        bytes[headerLength + 3] = UInt8(icmpChecksum & 0xff)
        bytes[10] = 0
        bytes[11] = 0
        let ipChecksum = checksum(bytes[0..<headerLength])
        bytes[10] = UInt8(ipChecksum >> 8)
        bytes[11] = UInt8(ipChecksum & 0xff)
        return Data(bytes)
    }

    private func checksum(_ bytes: ArraySlice<UInt8>) -> UInt16 {
        var sum: UInt32 = 0
        var index = bytes.startIndex
        while index < bytes.endIndex {
            let high = UInt32(bytes[index]) << 8
            index = bytes.index(after: index)
            let low = index < bytes.endIndex ? UInt32(bytes[index]) : 0
            if index < bytes.endIndex { index = bytes.index(after: index) }
            sum += high | low
        }
        while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16) }
        return ~UInt16(sum)
    }
}
