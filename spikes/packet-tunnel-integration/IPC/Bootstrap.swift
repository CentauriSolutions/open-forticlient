import Foundation

// The value is carried only in startVPNTunnel(options:), never in
// NETunnelProviderProtocol.providerConfiguration or saved preferences.
enum BootstrapWire {
    static let optionKey = "oftc.ephemeral-bootstrap.v1"
    static let maxSecretBytes = 4096
    static let maxLifetimeSeconds: UInt64 = 120
    private static let magic: [UInt8] = [0x4f, 0x46, 0x54, 0x43, 0x01]
    private static let headerBytes = 5 + 8 + 16 + 2

    enum Failure: Error {
        case missing, invalid, expired
    }

    struct Payload {
        let expiresAt: UInt64
        let sessionID: Data // 16 random bytes, generated separately for every start.
        let secret: Data // This development probe accepts only SYNTHETIC.
    }

    static func encode(_ payload: Payload, now: UInt64) throws -> Data {
        guard payload.sessionID.count == 16,
              (1...maxSecretBytes).contains(payload.secret.count),
              payload.expiresAt > now,
              payload.expiresAt - now <= maxLifetimeSeconds else { throw Failure.invalid }
        var bytes = magic
        for shift in stride(from: 56, through: 0, by: -8) {
            bytes.append(UInt8(truncatingIfNeeded: payload.expiresAt >> shift))
        }
        bytes.append(contentsOf: payload.sessionID)
        bytes.append(UInt8(payload.secret.count >> 8))
        bytes.append(UInt8(payload.secret.count & 0xff))
        bytes.append(contentsOf: payload.secret)
        return Data(bytes)
    }

    static func decode(_ data: Data, now: UInt64) throws -> Payload {
        let bytes = [UInt8](data)
        guard bytes.count >= headerBytes + 1,
              bytes.count <= headerBytes + maxSecretBytes,
              Array(bytes.prefix(5)) == magic else { throw Failure.invalid }
        var expiresAt: UInt64 = 0
        for byte in bytes[5..<13] { expiresAt = (expiresAt << 8) | UInt64(byte) }
        let size = Int(bytes[29]) << 8 | Int(bytes[30])
        guard (1...maxSecretBytes).contains(size), bytes.count == headerBytes + size else {
            throw Failure.invalid
        }
        guard expiresAt > now, expiresAt - now <= maxLifetimeSeconds else {
            throw Failure.expired
        }
        return Payload(expiresAt: expiresAt,
                       sessionID: Data(bytes[13..<29]),
                       secret: Data(bytes[headerBytes...]))
    }

    static func fromStartOptions(_ options: [String: NSObject]?, now: UInt64) throws -> Payload {
        guard let bytes = options?[optionKey] as? NSData else { throw Failure.missing }
        return try decode(bytes as Data, now: now)
    }
}

enum SyntheticStart {
    private static let marker = Data("SYNTHETIC".utf8)

    static func options(now: UInt64) throws -> [String: NSObject] {
        let sessionID = withUnsafeBytes(of: UUID().uuid) { Data($0) }
        let payload = BootstrapWire.Payload(expiresAt: now + 60,
                                            sessionID: sessionID,
                                            secret: marker)
        return [BootstrapWire.optionKey: try BootstrapWire.encode(payload, now: now) as NSData]
    }

    static func validate(_ options: [String: NSObject]?, now: UInt64) throws {
        let payload = try BootstrapWire.fromStartOptions(options, now: now)
        guard payload.secret == marker,
              payload.sessionID != Data(repeating: 0, count: 16) else {
            throw BootstrapWire.Failure.invalid
        }
    }
}
