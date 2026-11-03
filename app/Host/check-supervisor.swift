import Foundation
import NetworkExtension

@main enum SupervisorCheck {
    static func main() throws {
        let now = Date(timeIntervalSince1970: 1_000)
        var policy = ReconnectPolicy()
        let liveness = NSError(domain: "OFTCProvider", code: 409)
        precondition(!policy.allowRecovery(after: nil, now: now))
        precondition(!policy.allowRecovery(after: NSError(domain: "OFTCProvider", code: 102), now: now))
        precondition(!policy.allowRecovery(after: NSError(
            domain: NEVPNConnectionErrorDomain, code: 8), now: now))
        precondition(ReconnectPolicy.recoverable(NSError(domain: "OFTCProvider", code: 8)))
        for code in [301, 401, 501, 209, 309, 409, 509] {
            precondition(ReconnectPolicy.recoverable(NSError(domain: "OFTCProvider", code: code)))
        }
        for code in [201, 302, 403, 500, 601] {
            precondition(!ReconnectPolicy.recoverable(NSError(domain: "OFTCProvider", code: code)))
        }
        precondition(policy.allowRecovery(after: liveness, now: now))
        precondition(policy.allowRecovery(after: NSError(
            domain: NEVPNConnectionErrorDomain, code: 2), now: now.addingTimeInterval(1)))
        precondition(policy.allowRecovery(after: liveness, now: now.addingTimeInterval(2)))
        precondition(!policy.allowRecovery(after: liveness, now: now.addingTimeInterval(3)))
        precondition(policy.allowRecovery(after: liveness, now: now.addingTimeInterval(601)))
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("oftc-supervisor-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let lease = try SupervisorLease(directory: directory)
        let statusStore = SupervisorStatusStore(directory: directory)
        statusStore.publish(.acquiring, leaseID: lease.identifier)
        precondition(statusStore.read()?.phase == .acquiring)
        precondition(!lease.stopRequested)
        do {
            _ = try SupervisorLease(directory: directory)
            preconditionFailure("second supervisor acquired the same lock")
        } catch SupervisorLease.Failure.unavailable { }
        precondition(SupervisorLease.requestStop(directory: directory))
        precondition(lease.stopRequested)
        lease.close()
        precondition(statusStore.read() == nil) // No stale active state after exit.
        let replacement = try SupervisorLease(directory: directory)
        precondition(statusStore.read() == nil) // Old lease cannot describe a new process.
        statusStore.publish(.failed, leaseID: replacement.identifier)
        precondition(statusStore.read()?.phase == .failed)
        precondition(statusStore.read(now: Date().addingTimeInterval(301)) == nil)
        precondition(!replacement.stopRequested)
        replacement.close()
        let invalidState = directory.appendingPathComponent("supervisor.lock")
        try Data("broken".utf8).write(to: invalidState)
        precondition(!SupervisorLease.requestStop(directory: directory))
        try checkProfiles()
        try checkGatewayTrust()
        try checkProfileBundle()
        print("supervisor policy, stop lease, profile registry and SAML lock checks passed")
    }

    static func checkProfiles() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("oftc-registry-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: root) }
        precondition(OFTCProfileScope.slug("Office VPN") == "office-vpn")
        precondition(OFTCProfileScope.slug("  Warehouse!! ") == "warehouse")
        precondition(OFTCProfileScope.slug("✓✓") == "vpn")
        precondition(OFTCProfileScope.slug(String(repeating: "a", count: 80)).utf8.count == 32)
        precondition(OFTCProfileScope.uniqueID("c2", taken: ["c2"]) == "c2-2")
        precondition(OFTCProfileScope.isValidID("office-vpn"))
        for bad in ["", "Office", "-c2", "c2-", "a/b", "..", String(repeating: "a", count: 33)] {
            precondition(!OFTCProfileScope.isValidID(bad))
        }

        // The original single-profile layout migrates into profiles/<id>/ and
        // keeps its login preference.
        let legacy = try OFTCProfileStore(bundleID: "test.oftc", directory: root)
        try legacy.save(try OFTCProfile(gateway: "vpn.office.example", samlPort: 9443))
        try Data("{\"connectAtLogin\":true}".utf8)
            .write(to: root.appendingPathComponent("connection-preferences.json"))
        OFTCProfileScope.migrateLegacy(root: root) { $0 == "vpn.office.example" ? "Office VPN" : nil }
        var entries = OFTCProfileScope.entries(root: root)
        precondition(entries.count == 1 && entries[0].id == "office-vpn" && entries[0].name == "Office VPN")
        precondition(entries[0].profile.adoptsUnkeyedVPNEntry == true)
        precondition(!FileManager.default.fileExists(atPath: legacy.url.path))
        precondition(!FileManager.default.fileExists(atPath: root.appendingPathComponent("connection-preferences.json").path))
        precondition(AgentIntent(bundleID: "test.oftc", directory: entries[0].directory)
            .connectAtLogin(legacyEnabled: false))
        OFTCProfileScope.migrateLegacy(root: root) { _ in nil } // idempotent
        precondition(OFTCProfileScope.entries(root: root).count == 1)

        // Peers: independent identity, startup choice, stop request and status.
        let warehouse = try OFTCProfileScope.add(
            try OFTCProfile(gateway: "vpn.warehouse.example", samlPort: 9443, name: "Warehouse"), root: root)
        let again = try OFTCProfileScope.add(
            try OFTCProfile(gateway: "vpn.warehouse2.example", samlPort: 9443, name: "Warehouse"), root: root)
        precondition(warehouse.id == "warehouse" && again.id == "warehouse-2")
        entries = OFTCProfileScope.entries(root: root)
        precondition(entries.map(\.name) == ["Office VPN", "Warehouse", "Warehouse"])
        precondition(entries[0].profile.adoptsUnkeyedVPNEntry == true && warehouse.profile.adoptsUnkeyedVPNEntry == nil)
        precondition(!AgentIntent(bundleID: "test.oftc", directory: warehouse.directory)
            .connectAtLogin(legacyEnabled: false))
        let first = try SupervisorLease(directory: entries[0].directory)
        let second = try SupervisorLease(directory: warehouse.directory) // concurrent supervisors
        precondition(SupervisorLease.requestStop(directory: warehouse.directory))
        precondition(second.stopRequested && !first.stopRequested)
        first.close(); second.close()

        // Browser sign-ins queue behind each other across profiles.
        let held = SAMLAcquisitionLock(root: root, cancelled: { false })
        precondition(held != nil)
        var polls = 0
        let blocked = SAMLAcquisitionLock(root: root, cancelled: { polls += 1; return polls >= 2 },
                                          pollInterval: 0.01)
        precondition(blocked == nil && polls == 2)
        held?.release()
        precondition(SAMLAcquisitionLock(root: root, cancelled: { false }) != nil)
    }

    static func checkGatewayTrust() throws {
        let pem = """
-----BEGIN CERTIFICATE-----
MIICCjCCAbACCQCuByFg61aM6jAKBggqhkjOPQQDAjATMREwDwYDVQQDDAhwaW4t
dGVzdDAeFw0yNjExMDMxMjU0MDNaFw0zNjEwMzExMjU0MDNaMBMxETAPBgNVBAMM
CHBpbi10ZXN0MIIBSzCCAQMGByqGSM49AgEwgfcCAQEwLAYHKoZIzj0BAQIhAP//
//8AAAABAAAAAAAAAAAAAAAA////////////////MFsEIP////8AAAABAAAAAAAA
AAAAAAAA///////////////8BCBaxjXYqjqT57PrvVV2mIa8ZR0GsMxTsPY7zjw+
J9JgSwMVAMSdNgiG5wSTamZ44ROdJreBn36QBEEEaxfR8uEsQkf4vOblY6RA8ncD
fYEt6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9QIh
AP////8AAAAA//////////+85vqtpxeehPO5ysL8YyVRAgEBA0IABFnYWXJw2naj
VBZITMN0xV18IjUSSOC2/J7dcNmx6DudOa8ju1dT+vtA/jIhEQpPLAKHkm+abfFP
yh5hvl88r7AwCgYIKoZIzj0EAwIDSAAwRQIhALnJQmaWs4oZ9a3bxfw+YYIt8KQ+
JiXTJWiM0eCck27dAiBuHoTMMNAFsN+B5BHaiH7ZDKeDambYjrfbW17VzyobcQ==
-----END CERTIFICATE-----
"""
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("oftc-trust-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let certificate = GatewayCertificate(pem: pem)!
        precondition(certificate.pem.hasPrefix("-----BEGIN CERTIFICATE-----\n"))
        precondition(GatewayCertificate(pem: certificate.pem) == certificate)
        precondition(certificate.sha256.split(separator: ":").count == 32)
        precondition(certificate.subject.contains("pin-test"))
        let other = GatewayCertificate(der: certificate.der, subject: "other", issuer: "x",
                                       serial: "1", validity: "-")

        var prompts: [GatewayTrust.Review] = []
        func review(_ verdict: GatewayTrust.Verdict, _ answer: GatewayTrust.Decision)
            -> GatewayTrust.Outcome {
            GatewayTrust.review(host: "gw.example", port: 9443, directory: directory,
                                probe: { _, _ in verdict },
                                prompt: { prompts.append($0); return answer })
        }
        // Only an untrusted certificate asks; trusted or unreachable gateways never do.
        precondition(review(.systemTrusted, .trust) == .notACertificateProblem)
        precondition(review(.unreachable, .trust) == .notACertificateProblem)
        precondition(prompts.isEmpty)
        // No answer available (no GUI session) changes nothing.
        precondition(review(.untrusted(certificate), .unavailable) == .notACertificateProblem)
        precondition(GatewayTrust.pinnedCertificate(host: "gw.example", port: 9443, directory: directory) == nil)
        // Declining pins nothing and is reported.
        precondition(review(.untrusted(certificate), .decline) == .declined)
        precondition(GatewayTrust.pinnedCertificate(host: "gw.example", port: 9443, directory: directory) == nil)
        precondition(prompts.last?.reason == .untrusted)
        // Trusting pins exactly that certificate, owner-only.
        precondition(review(.untrusted(certificate), .trust) == .trusted(certificate))
        let pinFile = GatewayTrust.pinURL(host: "gw.example", port: 9443, directory: directory)
        precondition(GatewayTrust.pinnedCertificate(host: "gw.example", port: 9443, directory: directory) == certificate)
        let mode = (try FileManager.default.attributesOfItem(atPath: pinFile.path)[.posixPermissions] as? Int) ?? 0
        precondition(mode == 0o600)
        // The pinned certificate does not prompt again.
        let before = prompts.count
        precondition(review(.untrusted(certificate), .trust) == .notACertificateProblem)
        precondition(prompts.count == before)
        // A different certificate is a change, shown with the old fingerprint, and
        // declining keeps the old pin.
        let changed = GatewayCertificate(der: Data(certificate.der + [0]), subject: "x", issuer: "y",
                                         serial: "2", validity: "-")
        _ = other
        precondition(review(.untrusted(changed), .decline) == .declined)
        precondition(prompts.last?.reason == .changed(previous: certificate))
        precondition(GatewayTrust.pinnedCertificate(host: "gw.example", port: 9443, directory: directory) == certificate)
    }

    static func checkProfileBundle() throws {
        let items = [
            OFTCProfileBundle.Item(name: "Office VPN", gateway: "vpn.office.example", samlPort: 9443,
                                   transport: .udp, psk: "psk-one"),
            OFTCProfileBundle.Item(name: "Warehouse", gateway: "vpn.warehouse.example", samlPort: 9443,
                                   transport: .tcp, psk: "psk-two"),
        ]
        let data = try OFTCProfileBundle(profiles: items).encoded()
        let decoded = try OFTCProfileBundle.decode(data)
        precondition(decoded.map(\.profile.displayName) == ["Office VPN", "Warehouse"])
        precondition(decoded[1].profile.transport == .tcp && decoded[0].profile.samlPort == 9443)
        precondition(String(data: decoded[0].psk, encoding: .utf8) == "psk-one")

        func fails(_ data: Data, _ expected: OFTCProfileBundle.Failure) {
            do { _ = try OFTCProfileBundle.decode(data); preconditionFailure("accepted") }
            catch let failure as OFTCProfileBundle.Failure { precondition(failure == expected) }
            catch { preconditionFailure("unexpected error") }
        }
        func json(_ text: String) -> Data { Data(text.utf8) }
        fails(json("not json"), .unreadable)
        fails(json(#"{"format":"other","version":1,"profiles":[]}"#), .wrongFormat)
        fails(json(#"{"format":"oftc-profiles","version":2,"profiles":[]}"#), .unsupportedVersion)
        fails(json(#"{"format":"oftc-profiles","version":1,"profiles":[]}"#), .empty)
        fails(Data(count: OFTCProfileBundle.maxBytes + 1), .tooLarge)
        // Invalid gateway, empty PSK and NUL in a PSK are all rejected.
        let bad = { (gateway: String, psk: String) -> Data in
            let item = OFTCProfileBundle.Item(name: "X", gateway: gateway, samlPort: 9443, transport: .udp, psk: psk)
            return try! OFTCProfileBundle(profiles: [item]).encoded()
        }
        fails(bad("../etc", "psk"), .invalid("X"))
        fails(bad("vpn.example", ""), .invalid("X"))
        fails(bad("vpn.example", "a\u{0}b"), .invalid("X"))
    }
}
