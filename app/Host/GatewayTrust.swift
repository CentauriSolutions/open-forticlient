import CryptoKit
import Foundation
import Security

// A gateway certificate as shown to the user for a trust decision.
struct GatewayCertificate: Equatable {
    let der: Data
    let subject: String
    let issuer: String
    let serial: String
    let validity: String

    var sha256: String {
        SHA256.hash(data: der).map { String(format: "%02X", $0) }.joined(separator: ":")
    }

    init?(der: Data) {
        guard let certificate = SecCertificateCreateWithData(nil, der as CFData) else { return nil }
        self.der = der
        var fields: [String: String] = [:]
        if let text = GatewayCertificate.openssl(der) {
            for line in text.split(separator: "\n") {
                guard let equals = line.firstIndex(of: "=") else { continue }
                fields[String(line[..<equals]).lowercased()] =
                    String(line[line.index(after: equals)...]).trimmingCharacters(in: .whitespaces)
            }
        }
        let summary = SecCertificateCopySubjectSummary(certificate) as String? ?? "Unknown"
        subject = fields["subject"] ?? summary
        issuer = fields["issuer"] ?? "Unknown"
        serial = fields["serial"] ?? "Unknown"
        validity = [fields["notbefore"], fields["notafter"]].compactMap { $0 }.count == 2
            ? "\(fields["notbefore"]!) to \(fields["notafter"]!)" : "Unknown"
    }

    private static func openssl(_ der: Data) -> String? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        process.arguments = ["x509", "-inform", "DER", "-noout", "-subject", "-issuer",
                             "-serial", "-startdate", "-enddate"]
        let input = Pipe(), output = Pipe()
        process.standardInput = input
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        guard (try? process.run()) != nil else { return nil }
        input.fileHandleForWriting.write(der)
        try? input.fileHandleForWriting.close()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else { return nil }
        return String(data: data, encoding: .utf8)
    }
}

// What the certificate prompt shows. The decision logic (probing the gateway,
// the pinned certificates, when to ask) is Rust's: core/host/src/trust.rs. It runs
// the prompt as a child of this executable, `OFTCAgent review-certificate`, and
// passes the request below on stdin.
enum GatewayTrust {
    struct Review: Equatable {
        enum Reason: Equatable {
            case untrusted
            case changed(previous: GatewayCertificate)
        }
        let profileName: String
        let host: String
        let port: UInt32
        let certificate: GatewayCertificate
        let reason: Reason
    }

    enum Decision { case trust, decline }

    // What the prompt child reads on stdin. The Rust host writes this JSON
    // (core/host/src/trust.rs); check-trust-compat.swift pins both directions.
    struct PromptRequest: Codable {
        let profileName: String
        let host: String
        let port: UInt32
        let certificate: Data
        let previous: Data?
    }
}
