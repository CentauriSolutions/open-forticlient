import AppKit
import Foundation
import Security
import ServiceManagement

enum OFTCSettingsLink {
    static func open() {
        // Undocumented route that macOS's own frameworks use for other
        // extension points. It presents the Network Extensions sheet with
        // OFTC's switch (observed on macOS 27.0.1). open() also succeeds when
        // Settings ignores the query, so the status text keeps the ⓘ path.
        if let url = URL(string: "x-apple.systempreferences:com.apple.ExtensionsPreferences?extensionPointIdentifier=com.apple.system_extension.network_extension.extension-point"),
           NSWorkspace.shared.open(url) { return }
        SMAppService.openSystemSettingsLoginItems()
    }
}

enum OFTCPSKStore {
    static func has(appID: String, gateway: String) -> Bool {
        let query: [CFString: Any] = [kSecClass: kSecClassGenericPassword,
                                      kSecAttrService: appID + ".psk",
                                      kSecAttrAccount: gateway,
                                      kSecReturnAttributes: true,
                                      kSecMatchLimit: kSecMatchLimitOne]
        // Attributes only: presence is checked without reading the secret.
        var item: CFTypeRef?
        return SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess
    }

    static func save(_ psk: Data, appID: String, gateway: String) throws {
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

    // Only for a profile that has no saved PSK; returns false if the user cancels.
    static func prompt(appID: String, name: String, gateway: String) -> Bool {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = "Enter the PSK for “\(name)”"
        alert.informativeText = "OFTC has no saved key for \(gateway). It is stored in your Keychain."
        let field = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 280, height: 24))
        alert.accessoryView = field
        alert.addButton(withTitle: "Continue")
        alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else { return false }
        var psk = Data(field.stringValue.utf8)
        defer { psk.resetBytes(in: 0..<psk.count) }
        guard (1...1024).contains(psk.count), !psk.contains(0),
              (try? save(psk, appID: appID, gateway: gateway)) != nil else { return false }
        return true
    }
}

// Finishes setup for profiles that already exist by running `oftc setup` (or
// `setup --from FILE`), which is idempotent: it activates the extension and
// installs each profile's VPN entry. The command blocks until the user approves
// OFTC in System Settings, so it gets a long timeout and a poll reports the
// waiting state instead of letting a slow approval look like a failure.
final class OFTCSetupRepair {
    enum Phase: Equatable { case idle, working, waiting, stillWaiting }

    private static let timeout: TimeInterval = 900
    private var runner: HostCLI?
    private var poll: Timer?
    private var started = Date()
    private var sawApproval = false
    private var openedSettings = false
    private(set) var phase = Phase.idle

    var onChange: (() -> Void)?
    var onFinish: ((SetupOutcome) -> Void)?
    /// The component state from the host's last document, and a request for a fresh one: the
    /// poll no longer asks the system itself.
    var component: () -> VPNComponentState = { .unavailable }
    var refresh: () -> Void = {}


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

    func start(arguments: [String]) {
        guard !isRunning else { return }
        phase = .working
        started = Date()
        sawApproval = false
        openedSettings = false
        let runner = HostCLI()
        self.runner = runner
        runner.run(executable: Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/oftc"),
                   arguments: ["--app", Bundle.main.bundlePath] + arguments,
                   home: FileManager.default.homeDirectoryForCurrentUser,
                   timeout: Self.timeout) { [weak self, weak runner] end in
            guard let self, let runner, self.runner === runner else { return }
            self.runner = nil
            self.poll?.invalidate()
            self.poll = nil
            let outcome = SetupOutcome.resolve(MenuCommandResult(end), sawApproval: self.sawApproval)
            self.phase = outcome == .waitingForApproval ? .stillWaiting : .idle
            self.onChange?()
            self.onFinish?(outcome)
        }
        poll = Timer.scheduledTimer(withTimeInterval: 3, repeats: true) { [weak self] _ in self?.tick() }
        if let poll { RunLoop.main.add(poll, forMode: .common) }
        onChange?()
    }

    // Bring System Settings forward again while waiting; no new request needed.
    func reopenSettings() { OFTCSettingsLink.open() }

    private func tick() {
        guard isRunning else { return }
        refresh()
        if SetupProgress.isWaitingForApproval(component: component(), elapsed: Date().timeIntervalSince(started)) {
            sawApproval = true
            phase = .waiting
            if !openedSettings {
                openedSettings = true
                OFTCSettingsLink.open()
            }
        } else if phase == .waiting {
            phase = .working   // approved; installing the VPN entries
        }
        onChange?()
    }
}
