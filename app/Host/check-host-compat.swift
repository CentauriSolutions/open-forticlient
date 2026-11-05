import Foundation

// The Rust host writes profiles and per-profile preferences that the Swift menu and
// the remaining Swift verbs still read. This decodes the Rust-written tree committed
// under core/host/tests/fixtures/rust with the shipped Swift readers; a Rust test
// keeps that tree equal to what the Rust writer produces.
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
        let migrated = entries[0]
        precondition(AgentIntent(bundleID: "com.example.oftc", directory: migrated.directory)
            .connectAtLogin(legacyEnabled: false))

        // The Rust-written supervisor files: a status record (read as the menu reads
        // it; a finished supervisor's record needs no lock) and the connect-at-login
        // choice. 815509075 on the 2001 clock is what the Rust writer was given.
        let supervisor = root.appendingPathComponent("supervisor", isDirectory: true)
        let status = SupervisorStatusStore(directory: supervisor)
            .read(now: Date(timeIntervalSinceReferenceDate: 815509080))
        precondition(status?.phase == .failed
            && status?.leaseID == "A4DF24C9-D3A9-4D2E-896A-95AC0C2B535A"
            && status?.processID == 4242
            && status?.updated == Date(timeIntervalSinceReferenceDate: 815509075),
            "Swift decoded \(String(describing: status))")
        precondition(AgentIntent(bundleID: "com.example.oftc", directory: supervisor)
            .preferences()?.connectAtLogin == true)
        print("Rust-written profile registry and supervisor files decode with the Swift readers")
    }
}
