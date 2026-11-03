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

    var pem: String {
        let body = der.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
        return "-----BEGIN CERTIFICATE-----\n\(body)\n-----END CERTIFICATE-----\n"
    }

    init(der: Data, subject: String, issuer: String, serial: String, validity: String) {
        self.der = der
        self.subject = subject
        self.issuer = issuer
        self.serial = serial
        self.validity = validity
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

    init?(pem: String) {
        let lines = pem.split(whereSeparator: \.isNewline)
            .filter { !$0.hasPrefix("-----") }.joined()
        guard let data = Data(base64Encoded: lines) else { return nil }
        self.init(der: data)
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

// Trust-on-first-use for gateway certificates that macOS does not trust, such
// as a FortiGate's factory certificate. A decision is stored as a pinned
// certificate that the SAML bootstrap (app/bootstrap/tls.rs) checks by public
// key. Nothing is trusted without the user's explicit choice.
enum GatewayTrust {
    enum Verdict: Equatable {
        case systemTrusted
        case untrusted(GatewayCertificate)
        case unreachable
    }

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

    enum Decision { case trust, decline, unavailable }

    enum Outcome: Equatable {
        case notACertificateProblem
        case trusted(GatewayCertificate)
        case declined
    }

    static func pinDirectory() -> URL {
        let home = ProcessInfo.processInfo.environment["HOME"] ?? NSHomeDirectory()
        return URL(fileURLWithPath: home).appendingPathComponent(".config/oftc/gateways", isDirectory: true)
    }

    static func pinURL(host: String, port: UInt32, directory: URL) -> URL {
        directory.appendingPathComponent("\(host)_\(port).pem")
    }

    static func pinnedCertificate(host: String, port: UInt32, directory: URL) -> GatewayCertificate? {
        guard let text = try? String(contentsOf: pinURL(host: host, port: port, directory: directory),
                                     encoding: .utf8) else { return nil }
        return GatewayCertificate(pem: text)
    }

    static func pin(_ certificate: GatewayCertificate, host: String, port: UInt32,
                    directory: URL) throws {
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        try Data(certificate.pem.utf8).write(
            to: pinURL(host: host, port: port, directory: directory), options: .atomic)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600], ofItemAtPath: pinURL(host: host, port: port, directory: directory).path)
    }

    // Called after the SAML bootstrap failed before any browser sign-in. Only a
    // certificate that macOS and the pin both reject leads to a prompt.
    static func review(host: String, port: UInt32, profileName: String = "",
                       directory: URL = pinDirectory(),
                       probe: (String, UInt32) -> Verdict = probe,
                       prompt: (Review) -> Decision) -> Outcome {
        guard case .untrusted(let certificate) = probe(host, port) else {
            return .notACertificateProblem
        }
        let previous = pinnedCertificate(host: host, port: port, directory: directory)
        if previous?.sha256 == certificate.sha256 { return .notACertificateProblem }
        let reason: Review.Reason = previous.map { .changed(previous: $0) } ?? .untrusted
        switch prompt(Review(profileName: profileName, host: host, port: port,
                             certificate: certificate, reason: reason)) {
        case .unavailable:
            return .notACertificateProblem
        case .decline:
            return .declined
        case .trust:
            guard (try? pin(certificate, host: host, port: port, directory: directory)) != nil else {
                return .declined
            }
            return .trusted(certificate)
        }
    }

    // Captures the presented certificate and asks macOS whether it is trusted.
    // The connection is cancelled during the TLS challenge; no request is sent.
    static func probe(host: String, port: UInt32) -> Verdict {
        guard let url = URL(string: "https://\(host):\(port)/") else { return .unreachable }
        let delegate = ProbeDelegate()
        let session = URLSession(configuration: .ephemeral, delegate: delegate, delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        var request = URLRequest(url: url)
        request.timeoutInterval = 10
        let finished = DispatchSemaphore(value: 0)
        session.dataTask(with: request) { _, _, _ in finished.signal() }.resume()
        _ = finished.wait(timeout: .now() + 15)
        return delegate.verdict
    }

    private final class ProbeDelegate: NSObject, URLSessionDelegate {
        private let lock = NSLock()
        private var result: Verdict = .unreachable
        var verdict: Verdict { lock.lock(); defer { lock.unlock() }; return result }

        func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
            guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
                  let trust = challenge.protectionSpace.serverTrust else {
                completionHandler(.performDefaultHandling, nil); return
            }
            var verdict = Verdict.unreachable
            if SecTrustEvaluateWithError(trust, nil) {
                verdict = .systemTrusted
            } else if let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
                      let leaf = chain.first,
                      let certificate = GatewayCertificate(der: SecCertificateCopyData(leaf) as Data) {
                verdict = .untrusted(certificate)
            }
            lock.lock(); result = verdict; lock.unlock()
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}
