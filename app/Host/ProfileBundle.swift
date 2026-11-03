import Foundation

// A shareable file holding one or more VPN profiles, including each PSK, so a
// colleague can import them. The PSK is not the authentication secret (SAML
// is), but the file is still configuration for a private gateway: share it
// with the people who need it.
struct OFTCProfileBundle: Codable, Equatable {
    static let format = "oftc-profiles"
    static let version = 1
    static let maxBytes = 64 * 1024
    static let maxProfiles = 16

    struct Item: Codable, Equatable {
        let name: String
        let gateway: String
        let samlPort: UInt32
        let transport: OFTCProfile.Transport
        let psk: String
    }

    enum Failure: Error, Equatable {
        case unreadable, wrongFormat, unsupportedVersion, tooLarge, empty, invalid(String)
    }

    let format: String
    let version: Int
    let profiles: [Item]

    init(profiles: [Item]) {
        format = Self.format
        version = Self.version
        self.profiles = profiles
    }

    func encoded() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(self) + Data("\n".utf8)
    }

    // Parses and validates untrusted file content. Nothing is stored here.
    static func decode(_ data: Data) throws -> [(profile: OFTCProfile, psk: Data)] {
        guard data.count <= maxBytes else { throw Failure.tooLarge }
        guard let bundle = try? JSONDecoder().decode(OFTCProfileBundle.self, from: data) else {
            throw Failure.unreadable
        }
        guard bundle.format == Self.format else { throw Failure.wrongFormat }
        guard bundle.version == Self.version else { throw Failure.unsupportedVersion }
        guard !bundle.profiles.isEmpty else { throw Failure.empty }
        guard bundle.profiles.count <= maxProfiles else { throw Failure.tooLarge }
        return try bundle.profiles.map { item in
            guard let profile = try? OFTCProfile(
                    gateway: item.gateway, samlPort: item.samlPort,
                    transport: item.transport, name: item.name) else {
                throw Failure.invalid(item.name)
            }
            let psk = Data(item.psk.utf8)
            guard (1...1024).contains(psk.count), !psk.contains(0) else {
                throw Failure.invalid(item.name)
            }
            return (profile, psk)
        }
    }
}

extension OFTCProfileBundle.Failure {
    var message: String {
        switch self {
        case .unreadable: return "That file isn't an OFTC profile file"
        case .wrongFormat: return "That file isn't an OFTC profile file"
        case .unsupportedVersion: return "That profile file is from a newer OFTC; update OFTC and try again"
        case .tooLarge: return "That profile file is too large"
        case .empty: return "That profile file contains no profiles"
        case .invalid(let name): return "The profile \"\(name)\" in that file has invalid settings"
        }
    }
}
