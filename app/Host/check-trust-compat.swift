import Foundation

// The Rust host (core/host/src/trust.rs) writes the gateway pins and the request the
// certificate prompt child reads. This decodes what Rust writes with the shipped Swift
// readers: the pin file the Swift writer produced, which Rust reproduces byte for byte
// (a Rust test), and the Rust-written prompt requests.
@main enum TrustCompatCheck {
    static func main() throws {
        guard CommandLine.arguments.count == 2 else { fatalError("usage: trust-compat-check <fixtures>") }
        let fixtures = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
        let pins = fixtures.appendingPathComponent("swift/trust/gateways", isDirectory: true)
        let pinned = GatewayTrust.pinnedCertificate(host: "gw.example", port: 9443, directory: pins)!
        precondition(pinned.subject.contains("pin-test"))
        let file = try String(contentsOf: GatewayTrust.pinURL(
            host: "gw.example", port: 9443, directory: pins), encoding: .utf8)
        precondition(pinned.pem == file)

        func request(_ name: String) throws -> GatewayTrust.PromptRequest {
            try JSONDecoder().decode(GatewayTrust.PromptRequest.self, from: Data(contentsOf:
                fixtures.appendingPathComponent("rust/trust/\(name).json")))
        }
        let plain = try request("review-request")
        precondition(plain.profileName == "Example Office" && plain.host == "gw.example"
            && plain.port == 9443 && plain.certificate == pinned.der && plain.previous == nil)
        let changed = try request("review-request-changed")
        precondition(changed.certificate == pinned.der && changed.previous == Data(pinned.der + [0]))
        print("Rust-written gateway trust files decode with the Swift readers")
    }
}
