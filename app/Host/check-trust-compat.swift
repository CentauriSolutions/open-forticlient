import Foundation

// The Rust host (core/host/src/trust.rs) writes the request the certificate prompt child reads,
// with the certificate fields already parsed. The committed files under fixtures/rust/trust are
// what that writer produces (a Rust test compares them byte for byte); here the shipped Swift type
// must read them, and write back exactly the same fields, so neither side can drift alone.
@main enum TrustCompatCheck {
    static func main() throws {
        guard CommandLine.arguments.count == 2 else { fatalError("usage: trust-compat-check <fixtures>") }
        let fixtures = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
        func object(_ data: Data) throws -> NSDictionary {
            try JSONSerialization.jsonObject(with: data) as! NSDictionary
        }
        for (name, changed) in [("review-request", false), ("review-request-changed", true)] {
            let data = try Data(contentsOf: fixtures.appendingPathComponent("rust/trust/\(name).json"))
            let request = try JSONDecoder().decode(GatewayTrust.PromptRequest.self, from: data)
            precondition(request.profileName == "Example Office" && request.host == "gw.example"
                && request.port == 9443 && request.certificate.issuedTo == "gw.example"
                && request.certificate.issuedBy == "Example CA" && request.certificate.serial == "01AB"
                && request.certificate.sha256.split(separator: ":").count == 32
                && request.certificate.expires == "Jun 5 07:00:00 2056 GMT", name)
            precondition(request.changed == changed && request.previous?.serial == (changed ? "02" : nil), name)
            let produced = try object(JSONEncoder().encode(request))
            let golden = try object(data)
            precondition(produced == golden, "\(name).json is not what the Swift encoder writes")
        }
        print("Gateway trust requests agree between the Rust host and the Swift type")
    }
}
