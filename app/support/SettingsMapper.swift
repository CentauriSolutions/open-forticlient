import Darwin
import Foundation
import NetworkExtension

// Plain, authenticated output from provider-live-engine::NetworkSettings.
// The outerEndpoint is the address of the connected transport socket, not a
// hostname that might resolve differently after the tunnel is installed.
struct AuthenticatedNetworkSettings {
    struct Range {
        let first: String
        let last: String
    }

    let assignedIPv4: String
    let netmask: String?
    let splitRoutes: [Range]
    let dnsServers: [String]
    let dnsDomains: [String]
    let innerMTU: Int
    let outerEndpoint: String
}

enum SettingsError: Error, Equatable {
    case invalidAddress
    case invalidMask
    case invalidRoute
    case invalidDNS
    case invalidMTU
    case recursiveEndpoint
}

enum SettingsMapper {
    private static let hostMask = "255.255.255.255"

    private static func ipv4(_ text: String) throws -> UInt32 {
        let parts = text.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { throw SettingsError.invalidAddress }
        var result: UInt32 = 0
        for part in parts {
            guard !part.isEmpty, part.count <= 3,
                  (part.count == 1 || part.first != "0"),
                  part.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }),
                  let octet = UInt8(part) else { throw SettingsError.invalidAddress }
            result = (result << 8) | UInt32(octet)
        }
        return result
    }

    private static func dotted(_ address: UInt32) -> String {
        "\(address >> 24).\((address >> 16) & 255).\((address >> 8) & 255).\(address & 255)"
    }

    private static func maskPrefix(_ mask: UInt32) -> Int? {
        let inverse = ~mask
        guard inverse & (inverse &+ 1) == 0 else { return nil }
        return mask.nonzeroBitCount
    }

    private static func route(_ range: AuthenticatedNetworkSettings.Range) throws -> NEIPv4Route {
        let first = try ipv4(range.first)
        let last = try ipv4(range.last)
        guard first <= last else { throw SettingsError.invalidRoute }
        let size = UInt64(last) - UInt64(first) + 1
        guard size & (size - 1) == 0,
              UInt64(first) & (size - 1) == 0 else { throw SettingsError.invalidRoute }
        let prefix = 32 - size.trailingZeroBitCount
        let mask: UInt32 = prefix == 0 ? 0 : UInt32.max << (32 - prefix)
        guard last == first | ~mask else { throw SettingsError.invalidRoute }
        return NEIPv4Route(destinationAddress: dotted(first), subnetMask: dotted(mask))
    }

    private static func validDomain(_ domain: String) -> Bool {
        guard !domain.isEmpty, domain.utf8.count <= 253,
              domain.utf8.allSatisfy({ $0 < 128 }) else { return false }
        return domain.split(separator: ".", omittingEmptySubsequences: false).allSatisfy { label in
            guard !label.isEmpty, label.utf8.count <= 63,
                  label.first != "-", label.last != "-" else { return false }
            return label.utf8.allSatisfy {
                ($0 >= 65 && $0 <= 90) || ($0 >= 97 && $0 <= 122)
                    || ($0 >= 48 && $0 <= 57) || $0 == 45
            }
        }
    }

    private static func validatedOuterEndpoint(_ text: String) throws -> (String, UInt32?) {
        if let ipv4 = try? ipv4(text) {
            guard ipv4 != 0, ipv4 < 0xe000_0000 else { throw SettingsError.invalidAddress }
            return (dotted(ipv4), ipv4)
        }
        var address = in6_addr()
        guard text.withCString({ inet_pton(AF_INET6, $0, &address) }) == 1 else {
            throw SettingsError.invalidAddress
        }
        let bytes = withUnsafeBytes(of: address) { Array($0) }
        guard bytes.contains(where: { $0 != 0 }), bytes[0] != 0xff else {
            throw SettingsError.invalidAddress
        }
        if bytes[0..<10].allSatisfy({ $0 == 0 }) && bytes[10] == 0xff && bytes[11] == 0xff {
            // An IPv4-mapped IPv6 socket still needs an IPv4 route exclusion.
            let peer = (UInt32(bytes[12]) << 24) | (UInt32(bytes[13]) << 16)
                | (UInt32(bytes[14]) << 8) | UInt32(bytes[15])
            guard peer != 0, peer < 0xe000_0000 else { throw SettingsError.invalidAddress }
            return (text, peer)
        }
        return (text, nil)
    }

    static func make(_ source: AuthenticatedNetworkSettings) throws -> NEPacketTunnelNetworkSettings {
        let assigned = try ipv4(source.assignedIPv4)
        guard assigned != 0, assigned < 0xe000_0000, assigned != UInt32.max else {
            throw SettingsError.invalidAddress
        }
        if let suppliedMask = source.netmask {
            guard let prefix = maskPrefix(try ipv4(suppliedMask)), prefix > 0 else {
                throw SettingsError.invalidMask
            }
        }
        guard (576...9000).contains(source.innerMTU) else { throw SettingsError.invalidMTU }
        guard !source.splitRoutes.isEmpty, source.splitRoutes.count <= 64 else {
            throw SettingsError.invalidRoute
        }
        let (outer, outerIPv4) = try validatedOuterEndpoint(source.outerEndpoint)
        guard outerIPv4 != assigned else { throw SettingsError.recursiveEndpoint }
        let included = try source.splitRoutes.map(route)

        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: outer)
        // /32 prevents the interface mask from creating an implicit on-link
        // route wider than the authenticated split routes. The supplied CP
        // netmask is checked above, but does not change routing policy.
        let interface = NEIPv4Settings(addresses: [dotted(assigned)], subnetMasks: [hostMask])
        interface.includedRoutes = included
        if let peer = outerIPv4 {
            interface.excludedRoutes = [NEIPv4Route(destinationAddress: dotted(peer), subnetMask: hostMask)]
        }
        settings.ipv4Settings = interface

        guard source.dnsServers.count <= 8, source.dnsDomains.count <= 32,
              source.dnsDomains.allSatisfy(validDomain) else { throw SettingsError.invalidDNS }
        if source.dnsServers.isEmpty {
            guard source.dnsDomains.isEmpty else { throw SettingsError.invalidDNS }
        } else {
            let servers = try source.dnsServers.map { address -> String in
                let value = try ipv4(address)
                guard value != 0, value < 0xe000_0000 else { throw SettingsError.invalidDNS }
                return dotted(value)
            }
            let dns = NEDNSSettings(servers: servers)
            if source.dnsDomains.isEmpty {
                // The authenticated gateway supplied servers without a split
                // DNS suffix. The empty match domain is the system resolver.
                dns.matchDomains = [""]
            } else {
                dns.matchDomains = source.dnsDomains
                dns.searchDomains = source.dnsDomains
                dns.matchDomainsNoSearch = true
            }
            settings.dnsSettings = dns
        }
        settings.mtu = NSNumber(value: source.innerMTU)
        return settings
    }
}
