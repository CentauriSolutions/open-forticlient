import Foundation
import NetworkExtension

enum FFISettingsError: Error { case invalid }

enum FFISettings {
    private static func octets<T>(_ tuple: T, count: Int) -> [UInt8] {
        withUnsafeBytes(of: tuple) { Array($0.prefix(count)) }
    }

    private static func ipv4(_ bytes: [UInt8]) -> String {
        bytes.map(String.init).joined(separator: ".")
    }

    private static func outerEndpoint(_ raw: OftcSettings) throws -> String {
        let bytes = octets(raw.outer_remote, count: 16)
        switch raw.outer_remote_family {
        case 4 where bytes.suffix(12).allSatisfy({ $0 == 0 }):
            return ipv4(Array(bytes.prefix(4)))
        case 6:
            return stride(from: 0, to: 16, by: 2).map { index in
                String((UInt16(bytes[index]) << 8) | UInt16(bytes[index + 1]), radix: 16)
            }.joined(separator: ":")
        default:
            throw FFISettingsError.invalid
        }
    }

    static func read(_ handle: OpaquePointer) throws -> NEPacketTunnelNetworkSettings {
        var raw = OftcSettings()
        guard oftc_settings(handle, &raw) == OFTC_OK, raw.version == 2,
              raw.route_count > 0, raw.route_count <= 64,
              raw.dns_server_count <= 8, raw.dns_domain_count <= 32 else {
            throw FFISettingsError.invalid
        }
        var ranges = [AuthenticatedNetworkSettings.Range]()
        for index in 0..<Int(raw.route_count) {
            var route = OftcRoute()
            guard oftc_route(handle, index, &route) == OFTC_OK,
                  route.family == 4 else { throw FFISettingsError.invalid }
            ranges.append(.init(first: ipv4(octets(route.first, count: 4)),
                                last: ipv4(octets(route.last, count: 4))))
        }
        var servers = [String]()
        for index in 0..<Int(raw.dns_server_count) {
            var bytes = [UInt8](repeating: 0, count: 4)
            guard oftc_dns_server(handle, index, &bytes) == OFTC_OK else {
                throw FFISettingsError.invalid
            }
            servers.append(ipv4(bytes))
        }
        var domains = [String]()
        for index in 0..<Int(raw.dns_domain_count) {
            var needed = 0
            let status = oftc_dns_domain(handle, index, nil, 0, &needed)
            guard status == OFTC_BUFFER_TOO_SMALL, (1...253).contains(needed) else {
                throw FFISettingsError.invalid
            }
            var bytes = [UInt8](repeating: 0, count: needed)
            let copied = bytes.withUnsafeMutableBufferPointer {
                oftc_dns_domain(handle, index, $0.baseAddress, $0.count, &needed)
            }
            guard copied == OFTC_OK, needed == bytes.count,
                  let domain = String(bytes: bytes, encoding: .utf8) else {
                throw FFISettingsError.invalid
            }
            domains.append(domain)
        }
        let source = AuthenticatedNetworkSettings(
            assignedIPv4: ipv4(octets(raw.assigned_ipv4, count: 4)),
            netmask: ipv4(octets(raw.netmask, count: 4)),
            splitRoutes: ranges,
            dnsServers: servers,
            dnsDomains: domains,
            innerMTU: Int(raw.inner_mtu),
            outerEndpoint: try outerEndpoint(raw))
        return try SettingsMapper.make(source)
    }
}
