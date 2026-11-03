import Foundation

// This file contains only nonsecret connection preferences. The PSK remains in
// the OFTC Keychain item addressed by the exact gateway name.
struct OFTCProfile: Codable, Equatable {
    enum Transport: String, Codable { case udp, tcp }

    let version: Int
    let gateway: String
    let samlPort: UInt32
    let transport: Transport
    // Optional so profiles written before multi-profile support still decode.
    let name: String?
    // True for the profile that inherited the original unkeyed VPN entry.
    let adoptsUnkeyedVPNEntry: Bool?

    init(gateway: String, samlPort: UInt32, transport: Transport = .udp,
         name: String? = nil, adoptsUnkeyedVPNEntry: Bool? = nil) throws {
        version = 1
        self.gateway = gateway
        self.samlPort = samlPort
        self.transport = transport
        self.name = name
        self.adoptsUnkeyedVPNEntry = adoptsUnkeyedVPNEntry
        try validate()
    }

    var displayName: String { name ?? gateway }

    func with(name: String?, adoptsUnkeyedVPNEntry: Bool? = nil) throws -> OFTCProfile {
        try OFTCProfile(gateway: gateway, samlPort: samlPort, transport: transport,
                        name: name, adoptsUnkeyedVPNEntry: adoptsUnkeyedVPNEntry ?? self.adoptsUnkeyedVPNEntry)
    }

    func validate() throws {
        if let name, !(1...64).contains(name.utf8.count) ||
            name.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains) {
            throw OFTCProfileStore.Failure.invalid
        }
        guard version == 1, (1...65535).contains(samlPort),
              (1...253).contains(gateway.utf8.count),
              gateway.utf8.allSatisfy({ byte in
                  (48...57).contains(byte) || (65...90).contains(byte) ||
                  (97...122).contains(byte) || byte == 45 || byte == 46
              }), !gateway.hasPrefix("."), !gateway.hasSuffix("."),
              !gateway.contains("..") else { throw OFTCProfileStore.Failure.invalid }
    }
}

struct OFTCProfileStore {
    enum Failure: Error { case invalid, unavailable }

    let directory: URL

    init(bundleID: String, directory: URL? = nil) throws {
        guard !bundleID.isEmpty,
              bundleID.utf8.allSatisfy({ byte in
                  (48...57).contains(byte) || (65...90).contains(byte) ||
                  (97...122).contains(byte) || byte == 45 || byte == 46
              }) else { throw Failure.invalid }
        self.directory = directory ?? FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/\(bundleID)", isDirectory: true)
    }

    var url: URL { directory.appendingPathComponent("profile.json") }

    func save(_ profile: OFTCProfile) throws {
        try profile.validate()
        let data = try JSONEncoder().encode(profile)
        guard data.count <= 4096 else { throw Failure.invalid }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        let values = try directory.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
        guard values.isDirectory == true, values.isSymbolicLink != true else {
            throw Failure.unavailable
        }
        try FileManager.default.setAttributes([.posixPermissions: 0o700],
                                              ofItemAtPath: directory.path)
        try data.write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600],
                                              ofItemAtPath: url.path)
    }

    func load() throws -> OFTCProfile {
        let values = try url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey,
                                                     .fileSizeKey])
        guard values.isRegularFile == true, values.isSymbolicLink != true,
              let size = values.fileSize, (1...4096).contains(size) else {
            throw Failure.unavailable
        }
        let data = try Data(contentsOf: url)
        guard (1...4096).contains(data.count) else { throw Failure.invalid }
        let profile = try JSONDecoder().decode(OFTCProfile.self, from: data)
        try profile.validate()
        return profile
    }

    func remove() throws {
        let directoryValues = try directory.resourceValues(forKeys: [.isDirectoryKey,
                                                                    .isSymbolicLinkKey])
        let fileValues = try url.resourceValues(forKeys: [.isRegularFileKey,
                                                         .isSymbolicLinkKey])
        guard directoryValues.isDirectory == true,
              directoryValues.isSymbolicLink != true,
              fileValues.isRegularFile == true,
              fileValues.isSymbolicLink != true else { throw Failure.unavailable }
        try FileManager.default.removeItem(at: url)
    }
}
