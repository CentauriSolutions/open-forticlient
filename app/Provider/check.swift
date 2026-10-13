import Foundation

@main enum Check {
    static func main() throws {
        let now: UInt64 = 1_000
        let uid = "A".repeated(32)
        let preflight = try ProviderBootstrapInput.preflightWire(
            gateway: "integration.invalid", uid: uid, psk: Data("synthetic".utf8))
        let sample = try ProviderBootstrapInput.decode(preflight, tokenRequired: false)
        precondition(sample.token.isEmpty && sample.uid == Data(uid.utf8))
        let id = Data((1...16).map(UInt8.init))
        let payload = BootstrapWire.Payload(expiresAt: now + 60,
            sessionID: id, secret: preflight)
        let envelope = try BootstrapWire.encode(payload, now: now)
        let mode = try ProviderStartEnvelope.consume(
            [ProviderStartEnvelope.preflightKey: envelope as NSData], now: now)
        if case .preflight = mode {} else { fatalError("wrong mode") }
        let tcp6 = ProviderStartEnvelope.ConnectMode(transport: 2, outerFamily: 6,
            idiV4: [192, 0, 0, 2], tcpFallback: 0)
        let decodedTCP6 = try ProviderStartEnvelope.ConnectMode.decode(tcp6.encode())
        precondition(decodedTCP6.idiV4 == [192, 0, 0, 2])
        do {
            _ = try ProviderStartEnvelope.ConnectMode.decode(Data([1, 2, 6, 1, 192, 0, 0, 2]))
            fatalError("TCP mode accepted a second fallback")
        } catch ProviderBootstrapInput.Failure.invalid { }
        do {
            _ = try ProviderStartEnvelope.consume(
                [ProviderStartEnvelope.preflightKey: envelope as NSData], now: now)
            fatalError("replayed ID accepted")
        } catch ProviderBootstrapInput.Failure.invalid { }
        let later: UInt64 = 1_100
        let refreshed = try BootstrapWire.encode(.init(expiresAt: later + 60,
            sessionID: id, secret: preflight), now: later)
        let reusedAfterExpiry = try ProviderStartEnvelope.consume(
            [ProviderStartEnvelope.preflightKey: refreshed as NSData], now: later)
        if case .preflight = reusedAfterExpiry {} else { fatalError("expired replay entry stuck") }
        do {
            _ = try ProviderStartEnvelope.consume(
                [ProviderStartEnvelope.preflightKey: envelope as NSData,
                 ProviderStartEnvelope.liveKey: envelope as NSData], now: now)
            fatalError("ambiguous live/preflight options accepted")
        } catch ProviderBootstrapInput.Failure.invalid { }
        let liveFields = [Data("integration.invalid".utf8), Data(uid.utf8),
            Data("synthetic".utf8), Data("synthetic-token".utf8)]
        var raw: [UInt8] = [0x48, 0x42, 0x52, 0x31]
        for field in liveFields {
            raw.append(UInt8(field.count >> 8)); raw.append(UInt8(field.count & 255))
        }
        for field in liveFields { raw.append(contentsOf: field) }
        let live = try ProviderBootstrapInput.decode(Data(raw))
        precondition(live.token == Data("synthetic-token".utf8))
        // A browser flow that began at t=1000 and completed at t=1500 must
        // get an envelope valid after completion. No SAML/browser runs here.
        let afterSAML: UInt64 = 1_500
        let lateOptions = try CandidateHostBridge.optionsFromWire(Data(raw), clock: { afterSAML })
        _ = try BootstrapWire.fromStartOptions(lateOptions, now: afterSAML + 30)
        var tcp6Options = lateOptions
        tcp6Options[ProviderStartEnvelope.modeKey] = try tcp6.encode() as NSData
        let chosen = try ProviderStartEnvelope.consume(tcp6Options, now: afterSAML + 30)
        if case .live(_, let selected) = chosen {
            precondition(selected.transport == 2 && selected.outerFamily == 6 &&
                         selected.idiV4 == [192, 0, 0, 2] && selected.tcpFallback == 0)
        } else { fatalError("live transport mode lost") }
        do {
            _ = try BootstrapWire.fromStartOptions(lateOptions, now: afterSAML + 60)
            fatalError("expired delayed-login envelope accepted")
        } catch BootstrapWire.Failure.expired { }
        do {
            _ = try ProviderBootstrapInput.decode(Data(raw.dropLast()))
            fatalError("truncated HBR1 accepted")
        } catch ProviderBootstrapInput.Failure.invalid { }
        print("signed-provider bootstrap: synthetic checks passed")
    }
}

private extension String {
    func repeated(_ count: Int) -> String { String(repeating: self, count: count) }
}
