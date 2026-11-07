import AppKit
import Foundation

// The add-a-VPN form. It collects a gateway, a name and a PSK and hands them to the host: the
// host's `list_sources` names the FortiClient profiles that can be imported, a typed PSK is saved by
// the host's own verb (HostPSK), and `add_profile` does the rest and reports its steps. This window
// reads no profile, Keychain item, system extension or VPN preference itself (docs/ui-edge.md).
// The installer can open this app, but setup always runs in the console user's session.
final class OFTCOnboarding: NSObject, NSWindowDelegate {
    private enum Source {
        case fortiClient(String, String, Int)
        case manual
    }

    private let edge: HostEdge
    private let executable: URL?
    private let onClose: (() -> Void)?
    private var sources = [Source.manual]
    private var adding = false
    private var waitingSince: Date?
    private let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 580, height: 427),
                                  styleMask: [.titled, .closable, .miniaturizable],
                                  backing: .buffered, defer: false)
    private let sourceMenu = NSPopUpButton()
    private let nameField = NSTextField()
    private let gatewayField = NSTextField()
    private let portField = NSTextField()
    private let transportMenu = NSPopUpButton()
    private let pskField = NSSecureTextField()
    private let statusLabel = NSTextField(labelWithString: "")
    private let setupButton = NSButton(title: "Add VPN", target: nil, action: nil)
    private let settingsButton = NSButton(title: "Open System Settings", target: nil, action: nil)

    init(edge: HostEdge, executable: URL? = Bundle.main.executableURL, onClose: (() -> Void)? = nil) {
        self.edge = edge
        self.executable = executable
        self.onClose = onClose
        super.init()
        sourceMenu.addItem(withTitle: "Enter settings manually")
        buildWindow()
        selectSource()
        loadSources()
    }

    func show() {
        NSApplication.shared.setActivationPolicy(.regular)
        window.center()
        window.makeKeyAndOrderFront(nil)
        NSApplication.shared.activate(ignoringOtherApps: true)
    }

    // FortiClient profiles the host can import, minus the ones OFTC already has.
    private func loadSources() {
        edge.listSources { [weak self] result in
            guard let self, case .success(let found) = result else { return }
            let fresh = found.sources.filter { !$0.alreadyConfigured }
            guard !fresh.isEmpty else { return }
            let selected = self.sourceMenu.indexOfSelectedItem
            self.sources = fresh.map { .fortiClient($0.label, $0.gateway, $0.samlPort) } + [.manual]
            self.sourceMenu.removeAllItems()
            self.sourceMenu.addItems(withTitles: fresh.map { "FortiClient: \($0.label)" } + ["Enter settings manually"])
            // The user may already be typing: only an untouched manual form moves to the first profile.
            if selected == 0, self.gatewayField.stringValue.isEmpty { self.sourceMenu.selectItem(at: 0) }
            else { self.sourceMenu.selectItem(at: self.sources.count - 1) }
            self.selectSource()
        }
    }

    private func buildWindow() {
        window.title = "Add a VPN to OFTC"
        window.isReleasedWhenClosed = false
        OFTCWindowPolicy.apply(to: window)
        window.delegate = self
        let content = NSView(frame: window.contentView!.bounds)
        window.contentView = content
        let title = NSTextField(labelWithString: "Add a VPN")
        title.font = .boldSystemFont(ofSize: 22)
        title.frame = NSRect(x: 28, y: 371, width: 520, height: 32)
        content.addSubview(title)
        let explanation = NSTextField(wrappingLabelWithString:
            "Choose a FortiClient profile or enter a gateway. Each VPN you add can be connected at the same time as the others. macOS may ask you to enable the OFTC Network Extension. Setup will not connect the VPN.")
        explanation.frame = NSRect(x: 28, y: 323, width: 524, height: 42)
        content.addSubview(explanation)

        func row(_ title: String, _ control: NSView, _ y: CGFloat) {
            let label = NSTextField(labelWithString: title)
            label.frame = NSRect(x: 28, y: y + 3, width: 128, height: 22)
            control.frame = NSRect(x: 164, y: y, width: 388, height: 26)
            content.addSubview(label)
            content.addSubview(control)
        }
        sourceMenu.target = self
        sourceMenu.action = #selector(sourceChanged)
        row("Source", sourceMenu, 284)
        nameField.placeholderString = "Shown in the OFTC menu"
        row("Name", nameField, 247)
        row("Gateway", gatewayField, 210)
        row("SAML port", portField, 173)
        transportMenu.addItems(withTitles: ["UDP (recommended)", "TCP"])
        row("Transport", transportMenu, 136)
        pskField.placeholderString = "Leave blank if a saved PSK is available"
        row("VPN PSK", pskField, 99)

        statusLabel.lineBreakMode = .byWordWrapping
        statusLabel.maximumNumberOfLines = 3
        statusLabel.frame = NSRect(x: 28, y: 42, width: 524, height: 52)
        content.addSubview(statusLabel)
        settingsButton.target = self
        settingsButton.action = #selector(openSettings)
        settingsButton.frame = NSRect(x: 290, y: 12, width: 151, height: 28)
        settingsButton.isHidden = true
        content.addSubview(settingsButton)
        setupButton.target = self
        setupButton.action = #selector(setUp)
        setupButton.frame = NSRect(x: 444, y: 12, width: 112, height: 28)
        content.addSubview(setupButton)
    }

    @objc private func sourceChanged() { selectSource() }

    private func selectSource() {
        guard sources.indices.contains(sourceMenu.indexOfSelectedItem) else { return }
        var name = ""
        var gateway = ""
        var port = 9443
        if case .fortiClient(let label, let host, let samlPort) = sources[sourceMenu.indexOfSelectedItem] {
            name = label
            gateway = host
            port = samlPort
        }
        nameField.stringValue = name
        gatewayField.stringValue = gateway
        portField.stringValue = String(port)
        transportMenu.selectItem(at: 0)
        pskField.stringValue = ""
        statusLabel.stringValue = "Enter a PSK only if one is not already saved or importable."
    }

    private func message(_ text: String, waiting: Bool = false) {
        statusLabel.stringValue = text
        setupButton.isEnabled = !waiting && !adding
        settingsButton.isHidden = !waiting
    }

    @objc private func setUp() {
        guard !adding else { return }
        let name = nameField.stringValue.trimmingCharacters(in: .whitespaces)
        let gateway = gatewayField.stringValue.trimmingCharacters(in: .whitespaces)
        guard sources.indices.contains(sourceMenu.indexOfSelectedItem), !gateway.isEmpty,
              !gateway.contains(" "), let port = Int(portField.stringValue), (1...65535).contains(port) else {
            message("Enter a valid name, gateway and SAML port (1–65535).")
            return
        }
        var psk = Data(pskField.stringValue.utf8)
        if !psk.isEmpty, !(1...1024).contains(psk.count) || psk.contains(0) {
            psk.resetBytes(in: 0..<psk.count)
            message("Enter a valid PSK of at most 1024 bytes.")
            return
        }
        var label: String?
        if case .fortiClient(let source, let host, _) = sources[sourceMenu.indexOfSelectedItem], host == gateway, psk.isEmpty {
            label = source
        }
        adding = true
        message("Saving the VPN…", waiting: true)
        settingsButton.isHidden = true
        let tcp = transportMenu.indexOfSelectedItem == 1
        pskField.stringValue = ""
        let typed = psk
        let executable = self.executable
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            // A typed PSK is stored by the host's verb before the host is asked to add the VPN.
            let stored = typed.isEmpty || HostPSK.store(typed, gateway: gateway, executable: executable)
            DispatchQueue.main.async {
                guard let self else { return }
                guard stored else {
                    self.adding = false
                    self.message("Could not save the PSK. Check Keychain access and try again.")
                    return
                }
                self.addProfile(gateway: gateway, port: port, tcp: tcp, name: name.isEmpty ? nil : name, label: label)
            }
        }
        psk.resetBytes(in: 0..<psk.count)
    }

    private func addProfile(gateway: String, port: Int, tcp: Bool, name: String?, label: String?) {
        edge.addProfile(gateway: gateway, samlPort: port, tcp: tcp, name: name, fortiClientLabel: label,
                        progress: { [weak self] in self?.progressed($0) }) { [weak self] result in
            guard let self else { return }
            self.adding = false
            self.waitingSince = nil
            switch result {
            case .success: self.complete(name: name ?? gateway)
            case .failure(let error): self.failed(error)
            }
        }
    }

    private func progressed(_ progress: HostProgress) {
        switch (progress.step, progress.state) {
        case ("extension_approval", "waiting"):
            // OFTC is listed under Extensions before it is enabled; if the sheet does not open, the
            // switch is behind the row's ⓘ button.
            waitingSince = waitingSince ?? Date()
            message("Click Open System Settings and turn on the switch next to OFTC in Network Extensions. If you only see a list, click ⓘ next to OFTC first. Setup continues once it is on.", waiting: true)
            DispatchQueue.main.asyncAfter(deadline: .now() + 90) { [weak self] in
                guard let self, let since = self.waitingSince, Date().timeIntervalSince(since) >= 89 else { return }
                self.message("Still waiting for macOS approval. Click Open System Settings and check that the switch next to OFTC is on. If it is already on, quit and reopen OFTC to retry.", waiting: true)
            }
        case ("extension_approval", "running"):
            message("Requesting macOS Network Extension approval…", waiting: true)
        case ("vpn_entry", _):
            waitingSince = nil
            message("Saving the VPN in System Settings…", waiting: true)
        default: break
        }
    }

    private func failed(_ error: HostError) {
        switch error.code {
        case .alreadyConfigured: message("That gateway is already set up in OFTC.")
        case .pskUnavailable: message("Enter the VPN PSK. The saved profile did not contain an importable key.")
        case .badRequest: message("Enter a valid name, gateway and SAML port (1–65535).")
        case .approvalRequired:
            message("Network Extension approval is still needed. Click Open System Settings, turn on OFTC, then choose Add VPN again.", waiting: true)
            setupButton.isEnabled = true
        default: message(MenuCommandFailure(error).message(action: "add the VPN"))
        }
    }

    @objc private func openSettings() { edge.openSettings(.extensions) }

    private func complete(name: String) {
        let version = edge.lastStatus?.host.version ?? "installed"
        message("\(name) added. OFTC \(version) is ready; use Connect in the OFTC menu bar.")
        setupButton.title = "Done"
        setupButton.isEnabled = true
        setupButton.action = #selector(done)
    }

    @objc private func done() { window.close() }

    func windowWillClose(_ notification: Notification) {
        if let onClose { onClose() }
        else { NSApplication.shared.terminate(nil) }
    }
}
