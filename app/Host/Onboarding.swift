import AppKit
import Foundation
import NetworkExtension
import Security
import ServiceManagement
import SystemExtensions

// The installer can open this app, but setup always runs in the console user's
// session. In particular, neither the profile nor its PSK belongs to root.
final class OFTCOnboarding: NSObject, OSSystemExtensionRequestDelegate, NSWindowDelegate {
    private enum Source {
        case development(OFTCProfile)
        case fortiClient(String, String, UInt32)
        case manual
    }

    private let appID: String
    private let onClose: (() -> Void)?
    private let providerID: String
    private let updating: Bool
    private var sources = [Source]()
    private var request: OSSystemExtensionRequest?
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
    private var createdEntry: OFTCProfileEntry?
    private let settingsButton = NSButton(title: "Open System Settings", target: nil, action: nil)

    init?(appID: String, updating: Bool = false, onClose: (() -> Void)? = nil) {
        guard !appID.isEmpty else { return nil }
        self.appID = appID
        self.onClose = onClose
        self.updating = updating
        providerID = appID + ".provider"
        super.init()
        buildSources()
        buildWindow()
        selectSource()
    }

    func show() {
        NSApplication.shared.setActivationPolicy(.regular)
        window.center()
        window.makeKeyAndOrderFront(nil)
        NSApplication.shared.activate(ignoringOtherApps: true)
    }

    private func buildSources() {
        let configured = Set(OFTCProfileScope.entries(root: OFTCProfileScope.defaultRoot(bundleID: appID))
            .map { $0.profile.gateway })
        if let profile = try? OFTCProfileStore(bundleID: "com.chris.openforticlient.gate0").load(),
           !configured.contains(profile.gateway) {
            sources.append(.development(profile))
            sourceMenu.addItem(withTitle: "OFTC development profile")
        }
        let plist = URL(fileURLWithPath: "/Library/Application Support/Fortinet/FortiClient/conf/vpn.plist")
        if let values = try? plist.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey]),
           values.isRegularFile == true, values.isSymbolicLink != true,
           let data = try? Data(contentsOf: plist), data.count <= 4_000_000,
           let root = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
           let profiles = root["Profiles"] as? [String: Any] {
            for name in profiles.keys.sorted() where !name.isEmpty && name.utf8.count <= 64 &&
                !name.contains(".") && !name.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains) {
                guard let entry = profiles[name] as? [String: Any],
                      let gateway = entry["Server"] as? String,
                      let rawPort = entry["IKESamlPort"] as? NSNumber ?? NSNumber(value: 9443) as NSNumber?,
                      let profile = try? OFTCProfile(gateway: gateway,
                                  samlPort: UInt32(truncating: rawPort)),
                      !configured.contains(profile.gateway) else { continue }
                sources.append(.fortiClient(name, profile.gateway, profile.samlPort))
                sourceMenu.addItem(withTitle: "FortiClient: \(name)")
            }
        }
        sources.append(.manual)
        sourceMenu.addItem(withTitle: "Enter settings manually")
    }

    private func buildWindow() {
        window.title = "Add a VPN to OFTC"
        window.isReleasedWhenClosed = false
        window.delegate = self
        let content = NSView(frame: window.contentView!.bounds)
        window.contentView = content
        let title = NSTextField(labelWithString: updating ? "Update your OFTC VPN" : "Add a VPN")
        title.font = .boldSystemFont(ofSize: 22)
        title.frame = NSRect(x: 28, y: 371, width: 520, height: 32)
        content.addSubview(title)
        let explanation = NSTextField(wrappingLabelWithString: updating
            ? "Your saved VPN settings and PSK are kept. Update the VPN component below and approve OFTC if macOS asks. You'll choose when to connect."
            : "Choose a FortiClient profile or enter a gateway. Each VPN you add can be connected at the same time as the others. macOS may ask you to enable the OFTC Network Extension. Setup will not connect the VPN.")
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
        if updating { setupButton.title = "Update VPN" }
        setupButton.frame = NSRect(x: 444, y: 12, width: 112, height: 28)
        content.addSubview(setupButton)
    }

    @objc private func sourceChanged() { selectSource() }

    private func selectSource() {
        guard sources.indices.contains(sourceMenu.indexOfSelectedItem) else { return }
        var profile: OFTCProfile?
        var name = ""
        switch sources[sourceMenu.indexOfSelectedItem] {
        case .development(let value):
            profile = value
            name = "Development"
        case .fortiClient(let label, let gateway, let port):
            profile = try? OFTCProfile(gateway: gateway, samlPort: port)
            name = label
        case .manual: break
        }
        nameField.stringValue = name
        gatewayField.stringValue = profile?.gateway ?? ""
        portField.stringValue = profile.map { String($0.samlPort) } ?? "9443"
        transportMenu.selectItem(at: profile?.transport == .tcp ? 1 : 0)
        pskField.stringValue = ""
        statusLabel.stringValue = "Enter a PSK only if one is not already saved or importable."
    }

    private func message(_ text: String, waiting: Bool = false) {
        statusLabel.stringValue = text
        setupButton.isEnabled = !waiting
        settingsButton.isHidden = !waiting
    }

    @objc private func setUp() {
        // Recheck at the point of mutation: another UI or CLI may have
        // connected since this window opened. Adding a VPN is safe beside live
        // tunnels, but replacing the provider under them is not.
        setupButton.isEnabled = false
        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, error in
            DispatchQueue.main.async {
                guard let self else { return }
                guard error == nil else {
                    self.message("Could not confirm your VPN state. Check VPN settings, then try again.")
                    return
                }
                let ours = (managers ?? []).filter {
                    ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == self.providerID
                }
                let live = ours.contains { $0.connection.status != .disconnected && $0.connection.status != .invalid }
                if self.updating && live {
                    self.message("Disconnect OFTC before updating its VPN component.")
                    return
                }
                self.performSetup()
            }
        }
    }

    private func performSetup() {
        let root = OFTCProfileScope.defaultRoot(bundleID: appID)
        let name = nameField.stringValue.trimmingCharacters(in: .whitespaces)
        guard sources.indices.contains(sourceMenu.indexOfSelectedItem),
              let port = UInt32(portField.stringValue),
              let profile = try? OFTCProfile(gateway: gatewayField.stringValue,
                  samlPort: port, transport: transportMenu.indexOfSelectedItem == 1 ? .tcp : .udp,
                  name: name.isEmpty ? nil : name) else {
            message("Enter a valid name, gateway and SAML port (1–65535).")
            return
        }
        let source = sources[sourceMenu.indexOfSelectedItem]
        if createdEntry == nil,
           OFTCProfileScope.entries(root: root).contains(where: { $0.profile.gateway == profile.gateway }) {
            message("That gateway is already set up in OFTC.")
            return
        }
        do {
            var psk = Data(pskField.stringValue.utf8)
            if psk.isEmpty, case .fortiClient(let label, let gateway, _) = source,
               gateway == profile.gateway {
                psk = (try? MigrationBridge.psk(profileName: label,
                                                 expectedGateway: gateway)) ?? Data()
            }
            defer { psk.resetBytes(in: 0..<psk.count) }
            if !psk.isEmpty {
                guard (1...1024).contains(psk.count), !psk.contains(0) else {
                    message("Enter a valid PSK of at most 1024 bytes.")
                    return
                }
                try savePSK(psk, gateway: profile.gateway)
                pskField.stringValue = ""
            } else if !hasPSK(gateway: profile.gateway) {
                message("Enter the VPN PSK. The saved profile did not contain an importable key.")
                return
            }
            if createdEntry == nil { createdEntry = try OFTCProfileScope.add(profile, root: root) }
        } catch {
            message("Could not save the profile or PSK. Check Keychain access and try again.")
            return
        }
        message("Requesting macOS Network Extension approval…", waiting: true)
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: providerID, queue: .main)
        request.delegate = self
        self.request = request
        OSSystemExtensionManager.shared.submitRequest(request)
        DispatchQueue.main.asyncAfter(deadline: .now() + 90) { [weak self, weak request] in
            guard let self, let request, self.request === request else { return }
            self.message("Still waiting for macOS approval. Click Open System Settings and check that the switch next to OFTC is on. If it is already on, quit and reopen OFTC to retry.", waiting: true)
        }
    }

    private func hasPSK(gateway: String) -> Bool {
        let query: [CFString: Any] = [kSecClass: kSecClassGenericPassword,
                                      kSecAttrService: appID + ".psk",
                                      kSecAttrAccount: gateway,
                                      kSecReturnData: true,
                                      kSecMatchLimit: kSecMatchLimitOne]
        var item: CFTypeRef?
        return SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess
    }

    private func savePSK(_ psk: Data, gateway: String) throws {
        let query: [CFString: Any] = [kSecClass: kSecClassGenericPassword,
                                      kSecAttrService: appID + ".psk",
                                      kSecAttrAccount: gateway]
        var item = query
        item[kSecValueData] = psk
        let result = SecItemAdd(item as CFDictionary, nil)
        let final = result == errSecDuplicateItem
            ? SecItemUpdate(query as CFDictionary, [kSecValueData: psk] as CFDictionary)
            : result
        guard final == errSecSuccess else { throw NSError(domain: NSOSStatusErrorDomain,
                                                         code: Int(final)) }
    }

    @objc private func openSettings() {
        // Undocumented route that macOS's own frameworks use for other
        // extension points. It presents the Network Extensions sheet with
        // OFTC's switch (observed on macOS 27.0.1). open() also succeeds when
        // Settings ignores the query, so the status text keeps the ⓘ path.
        if let url = URL(string: "x-apple.systempreferences:com.apple.ExtensionsPreferences?extensionPointIdentifier=com.apple.system_extension.network_extension.extension-point"),
           NSWorkspace.shared.open(url) { return }
        SMAppService.openSystemSettingsLoginItems()
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        // OFTC is listed under Extensions before it is enabled; if the sheet
        // does not open, the switch is behind the row's ⓘ button.
        message("Click Open System Settings and turn on the switch next to OFTC in Network Extensions. If you only see a list, click ⓘ next to OFTC first. Setup continues once it is on.", waiting: true)
    }

    func request(_ request: OSSystemExtensionRequest,
                 actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension replacement: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        VPNComponentState.canReplace(existing: existing.bundleVersion, replacement: replacement.bundleVersion)
            ? .replace : .cancel
    }

    func request(_ request: OSSystemExtensionRequest,
                 didFinishWithResult result: OSSystemExtensionRequest.Result) {
        self.request = nil
        if result == .willCompleteAfterReboot {
            message("macOS accepted OFTC, but a reboot is required. Reopen OFTC afterward to finish setup.")
            return
        }
        installVPNEntry()
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        self.request = nil
        let code = (error as NSError).code
        message("Network Extension approval failed (code \(code)). Check OFTC in System Settings, then try again.")
    }

    private func installVPNEntry() {
        guard let entry = createdEntry else {
            message("Could not find the new profile. Try setup again.")
            return
        }
        message("Saving the VPN in System Settings…", waiting: true)
        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, error in
            guard let self else { return }
            DispatchQueue.main.async {
                guard error == nil else {
                    self.message("Could not read VPN settings. Try setup again.")
                    return
                }
                let matching = OFTCProfileScope.manager(for: entry, in: managers ?? [], providerID: self.providerID)
                guard matching.count <= 1 else {
                    self.message("Multiple OFTC VPN entries exist for this profile. Remove the duplicate before retrying.")
                    return
                }
                if let existing = matching.first {
                    if existing.isEnabled {
                        self.complete()
                    } else {
                        existing.isEnabled = true
                        existing.saveToPreferences { error in
                            DispatchQueue.main.async {
                                if error == nil { self.complete() }
                                else { self.message("Could not enable OFTC VPN. Check Network Extensions approval and retry.") }
                            }
                        }
                    }
                    return
                }
                let manager = NETunnelProviderManager()
                let configuration = NETunnelProviderProtocol()
                configuration.providerBundleIdentifier = self.providerID
                configuration.serverAddress = "OFTC"
                configuration.providerConfiguration = [OFTCProfileScope.configurationKey: entry.id]
                manager.protocolConfiguration = configuration
                manager.localizedDescription = "OFTC VPN (\(entry.name))"
                manager.isEnabled = true
                manager.saveToPreferences { error in
                    DispatchQueue.main.async {
                        if error == nil { self.complete() }
                        else { self.message("Could not save OFTC VPN. Check Network Extensions approval and retry.") }
                    }
                }
            }
        }
    }

    private func complete() {
        let extensionPlist = Bundle.main.bundleURL.appendingPathComponent(
            "Contents/Library/SystemExtensions/\(providerID).systemextension/Contents/Info.plist")
        let metadata = NSDictionary(contentsOf: extensionPlist) as? [String: Any]
        let version = metadata?["CFBundleShortVersionString"] as? String ?? "installed"
        message("\(createdEntry?.name ?? "VPN") added. OFTC \(version) is ready; use Connect in the OFTC menu bar.")
        setupButton.title = "Done"
        setupButton.action = #selector(done)
    }

    @objc private func done() { window.close() }

    func windowWillClose(_ notification: Notification) {
        if let onClose { onClose() }
        else { NSApplication.shared.terminate(nil) }
    }
}
