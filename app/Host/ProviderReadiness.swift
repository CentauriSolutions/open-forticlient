import Foundation
import SystemExtensions

// Properties requests are read-only. Activation is performed only by the
// setup window after an explicit button press, with the VPN disconnected.
final class ProviderReadiness: NSObject, OSSystemExtensionRequestDelegate {
    private var request: OSSystemExtensionRequest?
    private var completion: ((VPNComponentState) -> Void)?
    private var expected = ""

    func check(identifier: String, expected: String, completion: @escaping (VPNComponentState) -> Void) {
        guard request == nil else { return }
        self.expected = expected
        self.completion = completion
        let request = OSSystemExtensionRequest.propertiesRequest(forExtensionWithIdentifier: identifier, queue: .main)
        self.request = request
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
        DispatchQueue.main.asyncAfter(deadline: .now() + 10) { [weak self, weak request] in
            guard let self, let request, self.request === request else { return }
            self.finish(.unavailable)
        }
    }

    private func finish(_ state: VPNComponentState) {
        let handler = completion
        completion = nil
        request = nil
        handler?(state)
    }

    func request(_ request: OSSystemExtensionRequest, foundProperties properties: [OSSystemExtensionProperties]) {
        guard self.request === request else { return }
        finish(.resolve(expected: expected, records: properties.map {
            .init(build: $0.bundleVersion, enabled: $0.isEnabled,
                  awaitingApproval: $0.isAwaitingUserApproval, uninstalling: $0.isUninstalling)
        }))
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        guard self.request === request else { return }
        let error = error as NSError
        finish(error.domain == OSSystemExtensionErrorDomain &&
               error.code == OSSystemExtensionError.Code.extensionNotFound.rawValue ? .missing : .unavailable)
    }
    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        guard self.request === request else { return }
        finish(.unavailable)
    }
    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {}
    func request(_ request: OSSystemExtensionRequest,
                 actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension replacement: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction { .cancel }
}
