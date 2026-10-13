import Foundation
import NetworkExtension
import SystemExtensions

private let appID = Bundle.main.bundleIdentifier ?? ""
private let providerID = appID + ".provider"
private let probeName = "OFTC Gate 0 packet tunnel probe"

private func finish(_ message: String, code: Int32 = 0) -> Never {
    print(message)
    fflush(stdout)
    exit(code)
}

private func loadProbe(_ completion: @escaping (NETunnelProviderManager?) -> Void) {
    NETunnelProviderManager.loadAllFromPreferences { managers, error in
        if let error { finish("Failed to load VPN configurations: \(error)", code: 1) }
        let matches = (managers ?? []).filter {
            ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == providerID
        }
        if matches.count > 1 { finish("More than one Gate 0 configuration exists; refusing to guess", code: 1) }
        completion(matches.first)
    }
}

private final class ExtensionRequestDelegate: NSObject, OSSystemExtensionRequestDelegate {
    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        print("macOS approval required in System Settings for \(request.identifier)")
        fflush(stdout)
    }

    func request(_ request: OSSystemExtensionRequest,
                 actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension replacement: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        .replace
    }

    func request(_ request: OSSystemExtensionRequest,
                 didFinishWithResult result: OSSystemExtensionRequest.Result) {
        switch result {
        case .completed:
            finish("System extension request completed")
        case .willCompleteAfterReboot:
            finish("System extension request accepted; restart macOS before continuing", code: 3)
        @unknown default:
            finish("System extension request returned unknown result: \(result.rawValue)", code: 1)
        }
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        finish("System extension request failed: \(error)", code: 1)
    }
}

private let usage = "Usage: Gate0Host activate|deactivate|install-config|start|status|stop|remove-config"
guard let command = CommandLine.arguments.dropFirst().first,
      CommandLine.arguments.count == 2,
      !appID.isEmpty else { finish(usage, code: 2) }

switch command {
case "activate", "deactivate":
    let delegate = ExtensionRequestDelegate()
    let queue = DispatchQueue.main
    let request = command == "activate"
        ? OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: providerID, queue: queue)
        : OSSystemExtensionRequest.deactivationRequest(forExtensionWithIdentifier: providerID, queue: queue)
    request.delegate = delegate
    OSSystemExtensionManager.shared.submitRequest(request)
    withExtendedLifetime(delegate) { dispatchMain() }

case "install-config":
    loadProbe { existing in
        if existing != nil { finish("Gate 0 configuration already exists") }
        let manager = NETunnelProviderManager()
        let configuration = NETunnelProviderProtocol()
        configuration.providerBundleIdentifier = providerID
        configuration.serverAddress = "gate0.invalid" // Label only; the probe opens no network connection.
        manager.protocolConfiguration = configuration
        manager.localizedDescription = probeName
        manager.isEnabled = true
        manager.saveToPreferences { error in
            if let error { finish("Failed to save Gate 0 configuration: \(error)", code: 1) }
            finish("Gate 0 configuration saved")
        }
    }
    dispatchMain()

case "start":
    loadProbe { manager in
        guard let manager else { finish("No Gate 0 configuration; run install-config", code: 1) }
        manager.loadFromPreferences { error in
            if let error { finish("Failed to reload Gate 0 configuration: \(error)", code: 1) }
            do {
                try manager.connection.startVPNTunnel()
                finish("Tunnel start requested; use status to confirm it connected")
            } catch {
                finish("Tunnel start failed: \(error)", code: 1)
            }
        }
    }
    dispatchMain()

case "status":
    loadProbe { manager in
        guard let manager else { finish("Gate 0 configuration absent") }
        finish("Gate 0 VPN status: \(manager.connection.status.rawValue)")
    }
    dispatchMain()

case "stop":
    loadProbe { manager in
        guard let manager else { finish("Gate 0 configuration absent") }
        manager.connection.stopVPNTunnel()
        finish("Tunnel stop requested; use status and route/scutil checks to confirm cleanup")
    }
    dispatchMain()

case "remove-config":
    loadProbe { manager in
        guard let manager else { finish("Gate 0 configuration already absent") }
        manager.removeFromPreferences { error in
            if let error { finish("Failed to remove Gate 0 configuration: \(error)", code: 1) }
            finish("Gate 0 configuration removed")
        }
    }
    dispatchMain()

default:
    finish(usage, code: 2)
}
