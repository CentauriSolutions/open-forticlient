import Foundation

@main
enum Check {
    static func main() throws {
        let now: UInt64 = 1_700_000_000
        let options = try HostBootstrapBridge.syntheticOptions(now: now)
        let outer = try BootstrapWire.fromStartOptions(options, now: now)
        let inner = [UInt8](outer.secret)
        precondition(inner.count <= 4096 && Array(inner[..<4]) == Array("HBR1".utf8))
        let lengths = stride(from: 4, to: 12, by: 2).map {
            Int(inner[$0]) << 8 | Int(inner[$0 + 1])
        }
        precondition(lengths == [19, 16, 13, 15])
        precondition(12 + lengths.reduce(0, +) == inner.count)
        var offset = 12
        let fields = lengths.map { length -> String in
            defer { offset += length }
            return String(decoding: inner[offset..<offset + length], as: UTF8.self)
        }
        precondition(fields == ["integration.invalid", "SYNTHETICUID0123",
                                "SYNTHETIC-PSK", "SYNTHETIC-TOKEN"])
        precondition(outer.expiresAt == now + 60 && outer.sessionID.count == 16)
        print("host bootstrap: synthetic Rust -> Swift -> NetworkExtension options passed")
    }
}
