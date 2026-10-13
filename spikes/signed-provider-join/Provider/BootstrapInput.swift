import Foundation

// HBR1 is produced by host-bootstrap. Do not persist or print these bytes.
struct ProviderBootstrapInput {
    let gateway: Data
    let uid: Data
    var psk: Data
    var token: Data

    enum Failure: Error { case invalid }

    static func decode(_ wire: Data, tokenRequired: Bool = true) throws -> Self {
        guard wire.count >= 12, wire.count <= 4096,
              wire.prefix(4).elementsEqual([0x48, 0x42, 0x52, 0x31]) else {
            throw Failure.invalid
        }
        let lengths = stride(from: 4, to: 12, by: 2).map {
            Int(wire[$0]) << 8 | Int(wire[$0 + 1])
        }
        guard (1...253).contains(lengths[0]), lengths[1] == 32,
              (1...1024).contains(lengths[2]),
              (tokenRequired ? (1...1024).contains(lengths[3]) : lengths[3] == 0),
              12 + lengths.reduce(0, +) == wire.count else { throw Failure.invalid }
        var offset = 12
        let fields = lengths.map { length -> Data in
            defer { offset += length }
            return wire.subdata(in: offset..<(offset + length))
        }
        guard fields[1].allSatisfy({ (48...57).contains($0) || (65...70).contains($0)
              || (97...102).contains($0) }),
              !fields[2].contains(0), !fields[3].contains(0),
              let gateway = String(data: fields[0], encoding: .utf8),
              !gateway.contains("\0"), !gateway.isEmpty,
              String(data: fields[2], encoding: .utf8) != nil,
              String(data: fields[3], encoding: .utf8) != nil else { throw Failure.invalid }
        return Self(gateway: fields[0], uid: fields[1], psk: fields[2], token: fields[3])
    }

    // No token is acquired or serialized for the provider preflight.
    static func preflightWire(gateway: String, uid: String, psk: Data) throws -> Data {
        let fields = [Data(gateway.utf8), Data(uid.utf8), psk, Data()]
        let lengths = fields.map(\.count)
        guard (1...253).contains(lengths[0]), lengths[1] == 32,
              (1...1024).contains(lengths[2]),
              lengths.reduce(12, +) <= 4096 else { throw Failure.invalid }
        var header: [UInt8] = [0x48, 0x42, 0x52, 0x31]
        for length in lengths {
            header.append(UInt8(length >> 8))
            header.append(UInt8(length & 255))
        }
        var data = Data(header)
        for field in fields { data.append(field) }
        _ = try decode(data, tokenRequired: false)
        return data
    }

    mutating func clearSecrets() {
        psk.resetBytes(in: 0..<psk.count)
        token.resetBytes(in: 0..<token.count)
    }
}

enum ProviderStartEnvelope {
    static let liveKey = BootstrapWire.optionKey
    static let preflightKey = "oftc.ephemeral-preflight.v1"
    static let modeKey = "oftc.outer-mode.v1"
    private static let lock = NSLock()
    private static var usedIDs = [Data: UInt64]()

    struct ConnectMode {
        let transport: UInt32 // 1 UDP 4500, 2 TCP 4443
        let outerFamily: UInt32 // 4 or 6
        let idiV4: [UInt8]
        let tcpFallback: UInt32

        static let udpDefault = ConnectMode(transport: 1, outerFamily: 4,
                                            idiV4: [0, 0, 0, 0], tcpFallback: 1)

        func encode() throws -> Data {
            guard valid else { throw ProviderBootstrapInput.Failure.invalid }
            return Data([1, UInt8(transport), UInt8(outerFamily), UInt8(tcpFallback)] + idiV4)
        }

        static func decode(_ data: Data) throws -> Self {
            let bytes = [UInt8](data)
            guard bytes.count == 8, bytes[0] == 1 else {
                throw ProviderBootstrapInput.Failure.invalid
            }
            let mode = Self(transport: UInt32(bytes[1]), outerFamily: UInt32(bytes[2]),
                            idiV4: Array(bytes[4..<8]), tcpFallback: UInt32(bytes[3]))
            guard mode.valid else { throw ProviderBootstrapInput.Failure.invalid }
            return mode
        }

        private var valid: Bool {
            guard [1, 2].contains(transport), [4, 6].contains(outerFamily),
                  tcpFallback <= 1, !(transport == 2 && tcpFallback != 0),
                  idiV4.count == 4 else { return false }
            if outerFamily == 4 { return idiV4 == [0, 0, 0, 0] }
            return idiV4 != [0, 0, 0, 0] && idiV4[0] != 127 && idiV4[0] < 224
        }
    }

    enum Mode { case live(ProviderBootstrapInput, ConnectMode), preflight(ProviderBootstrapInput) }

    static func consume(_ options: [String: NSObject]?, now: UInt64) throws -> Mode {
        guard let options else { throw ProviderBootstrapInput.Failure.invalid }
        let hasLive = options[liveKey] != nil
        let preflight = options[preflightKey] != nil
        guard hasLive != preflight else { throw ProviderBootstrapInput.Failure.invalid }
        let key = preflight ? preflightKey : liveKey
        guard let data = options[key] as? NSData else { throw ProviderBootstrapInput.Failure.invalid }
        var payload = try BootstrapWire.decode(data as Data, now: now)
        defer { payload.secret.resetBytes(in: 0..<payload.secret.count) }
        guard payload.sessionID != Data(repeating: 0, count: 16) else {
            throw ProviderBootstrapInput.Failure.invalid
        }
        var input = try ProviderBootstrapInput.decode(payload.secret, tokenRequired: !preflight)
        var handedOff = false
        defer { if !handedOff { input.clearSecrets() } }
        guard !preflight || options[modeKey] == nil else {
            throw ProviderBootstrapInput.Failure.invalid
        }
        let connectMode: ConnectMode
        if let data = options[modeKey] as? NSData {
            connectMode = try ConnectMode.decode(data as Data)
        } else if options[modeKey] == nil {
            connectMode = .udpDefault
        } else {
            throw ProviderBootstrapInput.Failure.invalid
        }
        lock.lock()
        defer { lock.unlock() }
        usedIDs = usedIDs.filter { $0.value > now }
        guard usedIDs.count < 128, usedIDs[payload.sessionID] == nil else {
            throw ProviderBootstrapInput.Failure.invalid
        }
        usedIDs[payload.sessionID] = payload.expiresAt
        handedOff = true
        return preflight ? .preflight(input) : .live(input, connectMode)
    }
}
