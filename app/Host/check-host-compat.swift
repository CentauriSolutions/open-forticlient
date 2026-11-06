import Foundation

// The Rust host writes the profiles the Swift setup window (Onboarding) still reads. This
// decodes the Rust-written tree committed under core/host/tests/fixtures/rust with the
// shipped Swift reader; a Rust test keeps that tree equal to what the Rust writer produces.
// It goes with the reader when the setup window moves onto the host's `add_profile`.
@main enum HostCompatCheck {
    static func main() {
        guard CommandLine.arguments.count == 2 else { fatalError("usage: host-compat-check <fixtures/rust>") }
        let root = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
        let entries = OFTCProfileScope.entries(root: root)
        let summary = entries.map {
            "\($0.id)|\($0.name)|\($0.profile.gateway)|\($0.profile.samlPort)|\($0.profile.transport.rawValue)|\($0.profile.adoptsUnkeyedVPNEntry.map(String.init) ?? "-")"
        }
        precondition(summary == [
            "example-office|Example Office|vpn.example.com|9443|tcp|true",
            "lab|Lab|lab.example.com|8443|tcp|-",
            "office-hq-z-rich|Office \"HQ\" / Zürich — ☃|vpn2.example.com|9443|udp|-",
        ], "Swift decoded \(summary)")
        print("Rust-written profile registry decodes with the Swift profile reader (the setup window)")
    }
}
