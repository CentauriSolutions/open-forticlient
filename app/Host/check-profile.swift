import Foundation

@main
struct ProfileCheck {
    static func main() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("oftc-profile-check-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = try OFTCProfileStore(bundleID: "com.example.oftc", directory: directory)
        let profile = try OFTCProfile(gateway: "vpn.example.com", samlPort: 9443)
        try store.save(profile)
        let loaded = try store.load()
        precondition(loaded == profile)
        let attributes = try FileManager.default.attributesOfItem(atPath: store.url.path)
        precondition(attributes[.posixPermissions] as? NSNumber == 0o600)
        let tcp = try OFTCProfile(gateway: "vpn.example.com", samlPort: 9443,
                                  transport: .tcp)
        precondition(tcp.transport == .tcp)
        for gateway in ["", "/tmp/profile", "vpn.example.com:4443", "vpn..example.com"] {
            precondition((try? OFTCProfile(gateway: gateway, samlPort: 9443)) == nil)
        }
        precondition((try? OFTCProfile(gateway: "vpn.example.com", samlPort: 0)) == nil)
        try Data("{\"version\":2}".utf8).write(to: store.url, options: .atomic)
        precondition((try? store.load()) == nil)
        try FileManager.default.removeItem(at: store.url)
        try FileManager.default.createSymbolicLink(at: store.url,
            withDestinationURL: URL(fileURLWithPath: "/etc/hosts"))
        precondition((try? store.load()) == nil)
        print("OFTC profile store checks passed")
    }
}
