import Foundation

// What the menu says when a request to the host fails. The host's typed error code picks the
// message (docs/ui-edge.md 4.7); no output text is matched. `timeout` is the UI's own.
enum MenuCommandFailure: Equatable {
    case approval, credentials, configuration, agent, migration, timeout
    case serviceUnavailable, unsupported, busy, tunnelsActive
    case failed(Int32)

    init(_ error: HostError) {
        switch error.code {
        case .approvalRequired: self = .approval
        case .pskUnavailable: self = .credentials
        case .notConfigured: self = .configuration
        case .migrationNeeded: self = .migration
        case .agentUnavailable: self = .agent
        case .hostUnavailable: self = .serviceUnavailable
        case .unsupportedSchema: self = .unsupported
        case .busy: self = .busy
        case .tunnelsActive: self = .tunnelsActive
        case .timeout: self = .timeout
        case .alreadyConfigured, .unknownOp, .badRequest, .invalidFile, .cancelled, .internalFailure,
             .networkBlocked, .gatewayNotFound, .gatewayNoAnswer, .gatewayRefused, .signInRejected,
             .connectionLost:
            self = .failed(Int32(error.exit))
        }
    }

    func message(action: String) -> String {
        switch self {
        case .approval:
            return "Allow OFTC in System Settings → General → Login Items & Extensions, then try again."
        case .credentials:
            return "The VPN key is unavailable. Open Settings → Set up OFTC… to check Keychain access."
        case .configuration:
            return "Finish setup in Settings → Set up OFTC…, then try Connect."
        case .agent:
            return "OFTC's background VPN agent did not become ready. Check Login Items & Extensions, then try again."
        case .migration:
            return "The previous OFTC agent needs attention. Disconnect OFTC, then try again."
        case .timeout:
            return "Preparing the VPN took too long. Check its connection status before trying again."
        case .serviceUnavailable:
            return "OFTC's VPN service is not running. Choose Start service, then try again."
        case .unsupported:
            return "Update OFTC to continue: this version cannot talk to its VPN service."
        case .busy:
            return "OFTC is finishing another change to this VPN. Try again in a moment."
        case .tunnelsActive:
            return "Disconnect your VPNs first, then try again."
        case .failed(let status):
            return "Could not \(action) (helper exit \(status)). Check VPN setup and try again."
        }
    }
}
