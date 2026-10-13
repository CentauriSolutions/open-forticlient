import Foundation
import NetworkExtension

func sample() -> AuthenticatedNetworkSettings {
    AuthenticatedNetworkSettings(
        assignedIPv4: "10.20.0.42", netmask: nil,
        splitRoutes: [.init(first: "10.20.0.0", last: "10.20.0.255"),
                      .init(first: "10.2.3.4", last: "10.2.3.4")],
        dnsServers: [], dnsDomains: [], innerMTU: 1280,
        outerEndpoint: "203.0.113.7")
}

func expect(_ expected: SettingsError, _ source: AuthenticatedNetworkSettings) {
    do {
        _ = try SettingsMapper.make(source)
        fatalError("expected \(expected)")
    } catch let error as SettingsError {
        precondition(error == expected, "expected \(expected), got \(error)")
    } catch {
        fatalError("unexpected error \(error)")
    }
}

@main
enum Check {
    static func main() throws {
        let base = sample()
        let mapped = try SettingsMapper.make(base)
        precondition(mapped.tunnelRemoteAddress == "203.0.113.7")
        precondition(mapped.ipv4Settings?.addresses == ["10.20.0.42"])
        precondition(mapped.ipv4Settings?.subnetMasks == ["255.255.255.255"])
        precondition(mapped.ipv4Settings?.includedRoutes?.map(\.destinationAddress) ==
                     ["10.20.0.0", "10.2.3.4"])
        precondition(mapped.ipv4Settings?.includedRoutes?.map(\.destinationSubnetMask) ==
                     ["255.255.255.0", "255.255.255.255"])
        precondition(mapped.ipv4Settings?.excludedRoutes?.map(\.destinationAddress) == ["203.0.113.7"])
        precondition(mapped.ipv4Settings?.excludedRoutes?.map(\.destinationSubnetMask) == ["255.255.255.255"])
        precondition(mapped.dnsSettings == nil && mapped.mtu == 1280)

        let suppliedMask = AuthenticatedNetworkSettings(
            assignedIPv4: base.assignedIPv4, netmask: "255.255.255.0",
            splitRoutes: base.splitRoutes, dnsServers: ["10.20.0.53"],
            dnsDomains: ["internal.example"], innerMTU: base.innerMTU,
            outerEndpoint: base.outerEndpoint)
        let splitDNS = try SettingsMapper.make(suppliedMask)
        precondition(splitDNS.ipv4Settings?.subnetMasks == ["255.255.255.255"])
        precondition(splitDNS.dnsSettings?.servers == ["10.20.0.53"])
        precondition(splitDNS.dnsSettings?.matchDomains == ["internal.example"])
        precondition(splitDNS.dnsSettings?.searchDomains == ["internal.example"])
        precondition(splitDNS.dnsSettings?.matchDomainsNoSearch == true)

        let serverOnly = AuthenticatedNetworkSettings(
            assignedIPv4: base.assignedIPv4, netmask: nil,
            splitRoutes: base.splitRoutes, dnsServers: ["10.20.0.53"],
            dnsDomains: [], innerMTU: base.innerMTU,
            outerEndpoint: base.outerEndpoint)
        let globalDNS = try SettingsMapper.make(serverOnly)
        precondition(globalDNS.dnsSettings?.matchDomains == [""])

        let ipv6Outer = AuthenticatedNetworkSettings(
            assignedIPv4: base.assignedIPv4, netmask: nil,
            splitRoutes: base.splitRoutes, dnsServers: [], dnsDomains: [],
            innerMTU: base.innerMTU, outerEndpoint: "2001:db8::7")
        let overV6 = try SettingsMapper.make(ipv6Outer)
        precondition(overV6.tunnelRemoteAddress == "2001:db8::7")
        precondition(overV6.ipv4Settings?.excludedRoutes == nil)
        let mappedOuter = AuthenticatedNetworkSettings(
            assignedIPv4: base.assignedIPv4, netmask: nil,
            splitRoutes: base.splitRoutes, dnsServers: [], dnsDomains: [],
            innerMTU: base.innerMTU, outerEndpoint: "::ffff:203.0.113.7")
        let mappedV4 = try SettingsMapper.make(mappedOuter)
        precondition(mappedV4.ipv4Settings?.excludedRoutes?
            .first?.destinationAddress == "203.0.113.7")

        let defaultRoute = AuthenticatedNetworkSettings(
            assignedIPv4: base.assignedIPv4, netmask: nil,
            splitRoutes: [.init(first: "0.0.0.0", last: "255.255.255.255")],
            dnsServers: [], dnsDomains: [], innerMTU: base.innerMTU,
            outerEndpoint: base.outerEndpoint)
        let defaultMapped = try SettingsMapper.make(defaultRoute)
        precondition(defaultMapped.ipv4Settings?.includedRoutes?.first?.destinationSubnetMask == "0.0.0.0")
        precondition(defaultMapped.ipv4Settings?.excludedRoutes?.first?.destinationAddress == "203.0.113.7")

        expect(.invalidRoute, .init(assignedIPv4: base.assignedIPv4, netmask: nil,
                                    splitRoutes: [.init(first: "10.20.0.2", last: "10.20.0.255")],
                                    dnsServers: [], dnsDomains: [], innerMTU: 1280,
                                    outerEndpoint: base.outerEndpoint))
        expect(.invalidRoute, .init(assignedIPv4: base.assignedIPv4, netmask: nil,
                                    splitRoutes: [.init(first: "10.20.0.255", last: "10.20.0.0")],
                                    dnsServers: [], dnsDomains: [], innerMTU: 1280,
                                    outerEndpoint: base.outerEndpoint))
        expect(.invalidRoute, .init(assignedIPv4: base.assignedIPv4, netmask: nil,
                                    splitRoutes: [], dnsServers: [], dnsDomains: [], innerMTU: 1280,
                                    outerEndpoint: base.outerEndpoint))
        expect(.invalidMask, .init(assignedIPv4: base.assignedIPv4, netmask: "255.0.255.0",
                                   splitRoutes: base.splitRoutes, dnsServers: [], dnsDomains: [],
                                   innerMTU: 1280, outerEndpoint: base.outerEndpoint))
        expect(.invalidDNS, .init(assignedIPv4: base.assignedIPv4, netmask: nil,
                                  splitRoutes: base.splitRoutes, dnsServers: [],
                                  dnsDomains: ["internal.example"], innerMTU: 1280,
                                  outerEndpoint: base.outerEndpoint))
        expect(.invalidDNS, .init(assignedIPv4: base.assignedIPv4, netmask: nil,
                                  splitRoutes: base.splitRoutes, dnsServers: ["10.20.0.53"],
                                  dnsDomains: ["invalid..example"], innerMTU: 1280,
                                  outerEndpoint: base.outerEndpoint))
        expect(.invalidMTU, .init(assignedIPv4: base.assignedIPv4, netmask: nil,
                                  splitRoutes: base.splitRoutes, dnsServers: [], dnsDomains: [],
                                  innerMTU: 100, outerEndpoint: base.outerEndpoint))
        expect(.recursiveEndpoint, .init(assignedIPv4: base.assignedIPv4, netmask: nil,
                                         splitRoutes: base.splitRoutes, dnsServers: [], dnsDomains: [],
                                         innerMTU: 1280, outerEndpoint: base.assignedIPv4))
        expect(.invalidAddress, .init(assignedIPv4: base.assignedIPv4, netmask: nil,
                                      splitRoutes: base.splitRoutes, dnsServers: [], dnsDomains: [],
                                      innerMTU: 1280, outerEndpoint: "ff02::1"))
        print("provider settings: 15 synthetic cases passed")
    }
}
