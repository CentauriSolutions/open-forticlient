import Foundation

func expectFailure(_ label: String, _ body: () throws -> Void) {
    do {
        try body()
        fatalError("unexpected success: \(label)")
    } catch BootstrapWire.Failure.invalid, BootstrapWire.Failure.expired,
            BootstrapWire.Failure.missing {
        // Expected.
    } catch {
        fatalError("unexpected error kind: \(label)")
    }
}

@main
enum Check {
    static func main() throws {
        let now: UInt64 = 1_700_000_000
        let payload = BootstrapWire.Payload(expiresAt: now + 60,
                                            sessionID: Data(0..<16),
                                            secret: Data([0x53, 0x59, 0x4e, 0x54, 0x48, 0x45, 0x54, 0x49, 0x43]))
        let wire = try BootstrapWire.encode(payload, now: now)
        let received = try BootstrapWire.fromStartOptions(
            [BootstrapWire.optionKey: wire as NSData], now: now)
        precondition(received.sessionID == payload.sessionID)
        precondition(received.secret == payload.secret)
        precondition(received.expiresAt == payload.expiresAt)

        expectFailure("nil options") { _ = try BootstrapWire.fromStartOptions(nil, now: now) }
        expectFailure("wrong key") { _ = try BootstrapWire.fromStartOptions(["other": wire as NSData], now: now) }
        expectFailure("expired") { _ = try BootstrapWire.decode(wire, now: now + 60) }
        expectFailure("future window") { _ = try BootstrapWire.decode(wire, now: now - 61) }
        expectFailure("truncated") { _ = try BootstrapWire.decode(Data(wire.dropLast()), now: now) }
        var corrupt = wire
        corrupt[0] = 0
        expectFailure("bad version") { _ = try BootstrapWire.decode(corrupt, now: now) }
        expectFailure("oversize") {
            let tooLarge = BootstrapWire.Payload(expiresAt: now + 30,
                                                 sessionID: Data(repeating: 1, count: 16),
                                                 secret: Data(repeating: 2, count: 4097))
            _ = try BootstrapWire.encode(tooLarge, now: now)
        }
        print("provider IPC synthetic codec: 8 checks passed")
    }
}
