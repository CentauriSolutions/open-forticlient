import Foundation

// The Rust host (core/host/src/trust.rs) reads the pins and writes the request the
// certificate prompt child reads. Both directions are pinned against the shipped
// Swift type:
//  - the Rust-written requests decode with `GatewayTrust.PromptRequest`;
//  - the Swift-written fixtures under fixtures/swift/trust (the goldens the Rust tests
//    compare against) are exactly what `JSONEncoder` produces for the same values, so
//    a golden cannot drift from the encoder it claims to come from.
@main enum TrustCompatCheck {
    static func main() throws {
        guard CommandLine.arguments.count == 2 else { fatalError("usage: trust-compat-check <fixtures>") }
        let fixtures = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
        let pin = try String(contentsOf: fixtures.appendingPathComponent(
            "swift/trust/gateways/gw.example_9443.pem"), encoding: .utf8)
        let der = Data(base64Encoded: pin.split(whereSeparator: \.isNewline)
            .filter { !$0.hasPrefix("-----") }.joined())!
        precondition(GatewayCertificate(der: der)?.subject.contains("pin-test") == true)

        func read(_ path: String) throws -> Data {
            try Data(contentsOf: fixtures.appendingPathComponent(path))
        }
        func plist(_ data: Data) throws -> NSDictionary {
            try JSONSerialization.jsonObject(with: data) as! NSDictionary
        }
        let changedPrevious = Data(der + [0])
        for (name, previous) in [("review-request", nil), ("review-request-changed", changedPrevious)] as [(String, Data?)] {
            let rust = try JSONDecoder().decode(GatewayTrust.PromptRequest.self,
                                                from: read("rust/trust/\(name).json"))
            precondition(rust.profileName == "Example Office" && rust.host == "gw.example"
                && rust.port == 9443 && rust.certificate == der && rust.previous == previous, name)
            let encoded = try JSONEncoder().encode(GatewayTrust.PromptRequest(
                profileName: "Example Office", host: "gw.example", port: 9443,
                certificate: der, previous: previous))
            let golden = try plist(read("swift/trust/\(name).json"))
            let produced = try plist(encoded)
            precondition(produced == golden, "\(name).json is not what the Swift encoder writes")
        }
        print("Gateway trust requests agree between the Rust host and the Swift encoder")
    }
}
