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
        var secret: Data // Wipe the decoder-owned copy after provider handoff.
    }

    static func encode(_ payload: Payload, now: UInt64) throws -> Data {
        guard payload.sessionID.count == 16,
              (1...maxSecretBytes).contains(payload.secret.count),
              payload.expiresAt > now,
              payload.expiresAt - now <= maxLifetimeSeconds else { throw Failure.invalid }
        var header = magic
        for shift in stride(from: 56, through: 0, by: -8) {
            header.append(UInt8(truncatingIfNeeded: payload.expiresAt >> shift))
        }
        header.append(contentsOf: payload.sessionID)
        header.append(UInt8(payload.secret.count >> 8))
        header.append(UInt8(payload.secret.count & 0xff))
        var envelope = Data(header)
        envelope.append(payload.secret)
        return envelope
    }

    static func decode(_ data: Data, now: UInt64) throws -> Payload {
        guard data.count >= headerBytes + 1,
              data.count <= headerBytes + maxSecretBytes,
              data.prefix(5).elementsEqual(magic) else { throw Failure.invalid }
        var expiresAt: UInt64 = 0
        for byte in data[5..<13] { expiresAt = (expiresAt << 8) | UInt64(byte) }
        let size = Int(data[29]) << 8 | Int(data[30])
        guard (1...maxSecretBytes).contains(size), data.count == headerBytes + size else {
            throw Failure.invalid
        }
        guard expiresAt > now, expiresAt - now <= maxLifetimeSeconds else {
            throw Failure.expired
        }
        return Payload(expiresAt: expiresAt,
                       sessionID: data.subdata(in: 13..<29),
                       secret: data.subdata(in: headerBytes..<data.count))
    }

    static func fromStartOptions(_ options: [String: NSObject]?, now: UInt64) throws -> Payload {
        guard let bytes = options?[optionKey] as? NSData else { throw Failure.missing }
        return try decode(bytes as Data, now: now)
    }
}
