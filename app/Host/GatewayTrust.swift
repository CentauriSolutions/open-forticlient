import Foundation

// What the certificate prompt shows. The decision logic (probing the gateway, the pinned
// certificates, when to ask) and the parsing of the certificate are Rust's: core/host/src/trust.rs.
// It runs the prompt as a child of this executable, `OFTCAgent review-certificate`, and passes the
// request below on stdin with every field already parsed, so this side reads no certificate.
enum GatewayTrust {
    enum Decision { case trust, decline }

    /// One certificate as the host describes it for the prompt.
    struct Certificate: Codable, Equatable {
        let issuedTo: String
        let issuedBy: String
        let serial: String
        /// Upper-case hex pairs separated by colons.
        let sha256: String
        /// The `notAfter` text as openssl prints it, or `Unknown`.
        let expires: String
    }

    // What the prompt child reads on stdin. The Rust host writes this JSON
    // (core/host/src/trust.rs); check-trust-compat.swift pins both directions.
    struct PromptRequest: Codable, Equatable {
        let profileName: String
        let host: String
        let port: UInt32
        let certificate: Certificate
        /// Present when the gateway presented a different certificate than the one trusted before.
        let previous: Certificate?

        var changed: Bool { previous != nil }
    }
}
