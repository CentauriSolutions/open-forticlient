import AppKit
import Foundation

// The key prompt for a profile that has no saved PSK (the host's `psk_unavailable` names it). The
// text goes to HostPSK, which hands it to the host's own verb on a pipe; nothing here stores it.
enum OFTCKeyPrompt {
    /// The typed key, or nil when the user cancels or types nothing usable. The caller zeroes it.
    static func ask(name: String, gateway: String) -> Data? {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = "Enter the PSK for “\(name)”"
        alert.informativeText = "OFTC has no saved key for \(gateway). Your Keychain keeps the key you enter."
        let field = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 280, height: 24))
        alert.accessoryView = field
        alert.addButton(withTitle: "Continue")
        alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else { return nil }
        let psk = Data(field.stringValue.utf8)
        field.stringValue = ""
        guard (1...1024).contains(psk.count), !psk.contains(0) else { return nil }
        return psk
    }
}

// Finishes setup for profiles that already exist with the host's `component_update`, which checks
// every profile's key, activates the system extension and installs each VPN entry, and asks for
// nothing else. The op blocks until the user approves OFTC in System Settings; its `waiting`
// progress line, not a poll, says so, so a slow approval is a state and never a failure.
final class OFTCSetupRepair {
    enum Phase: Equatable { case idle, working, waiting, stillWaiting }

    private var sawApproval = false
    private var openedSettings = false
    private var running = false
    private(set) var phase = Phase.idle

    var onChange: (() -> Void)?
    var onFinish: ((SetupOutcome) -> Void)?
    var edge: () -> HostEdge? = { nil }

    var isRunning: Bool { phase == .working || phase == .waiting }
    var isWorking: Bool { phase == .working }

    var statusText: String? {
        switch phase {
        case .idle: return nil
        case .working: return SetupProgress.working
        case .waiting: return SetupProgress.waiting
        case .stillWaiting: return SetupProgress.stillWaiting
        }
    }

    func start() {
        guard !running, let edge = edge() else { return }
        running = true
        phase = .working
        sawApproval = false
        openedSettings = false
        edge.componentUpdate(progress: { [weak self] progress in self?.progressed(progress) }) { [weak self] result in
            guard let self else { return }
            self.running = false
            let outcome = SetupOutcome.resolve(result, sawApproval: self.sawApproval)
            self.phase = outcome == .waitingForApproval ? .stillWaiting : .idle
            self.onChange?()
            self.onFinish?(outcome)
        }
        onChange?()
    }

    // Bring System Settings forward again while waiting; no new request needed.
    func reopenSettings() { edge()?.openSettings(.extensions) }

    private func progressed(_ progress: HostProgress) {
        if progress.step == "extension_approval", progress.state == "waiting" {
            sawApproval = true
            phase = .waiting
            if !openedSettings {
                openedSettings = true
                reopenSettings()
            }
        } else if phase == .waiting {
            phase = .working   // approved; installing the VPN entries
        }
        onChange?()
    }
}
