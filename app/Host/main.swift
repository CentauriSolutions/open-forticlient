import Darwin
import AppKit
import Foundation
import NetworkExtension
import Security
import ServiceManagement
import SystemExtensions

private let appID = Bundle.main.bundleIdentifier ?? ""
private let providerID = appID + ".provider"
private let keychainService = appID + ".psk"
private var activeSupervisor: ReconnectSupervisor?

private func finish(_ message: String, code: Int32 = 0) -> Never {
    print(message)
    fflush(stdout)
    exit(code)
}

private func loadManager(_ completion: @escaping (NETunnelProviderManager?) -> Void) {
    NETunnelProviderManager.loadAllFromPreferences { managers, error in
        if error != nil { finish("Could not load VPN configuration", code: 1) }
        let matching = (managers ?? []).filter {
            ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == providerID
        }
        if matching.count > 1 { finish("Multiple OFTC configurations; refusing to guess", code: 1) }
        completion(matching.first)
    }
}

private enum PSKLookupError: Error { case unavailable }

private func lookupPSK(for gateway: String) throws -> Data {
    let query: [CFString: Any] = [
        kSecClass: kSecClassGenericPassword,
        kSecAttrService: keychainService,
        kSecAttrAccount: gateway,
        kSecReturnData: true,
        kSecMatchLimit: kSecMatchLimitOne,
    ]
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    guard status == errSecSuccess, let data = result as? Data,
          (1...1024).contains(data.count) else {
        throw PSKLookupError.unavailable
    }
    return data
}

private func storedPSK(for gateway: String) -> Data {
    guard let psk = try? lookupPSK(for: gateway) else {
        finish("PSK unavailable in OFTC Keychain service", code: 1)
    }
    return psk
}

private enum PSKPromptError: Error { case terminal, input, invalid }

private func readPSKFromTTY() throws -> Data {
    let fd = open("/dev/tty", O_RDWR)
    guard fd >= 0 else { throw PSKPromptError.terminal }
    defer { close(fd) }
    var original = termios()
    guard tcgetattr(fd, &original) == 0 else { throw PSKPromptError.terminal }
    var hidden = original
    hidden.c_lflag &= ~tcflag_t(ECHO)
    guard tcsetattr(fd, TCSANOW, &hidden) == 0 else { throw PSKPromptError.terminal }
    defer { _ = tcsetattr(fd, TCSANOW, &original) }
    let prompt = Array("OFTC PSK: ".utf8)
    _ = prompt.withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
    var bytes = [UInt8]()
    defer { _ = bytes.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) } }
    while bytes.count <= 1024 {
        var byte: UInt8 = 0
        guard read(fd, &byte, 1) == 1 else { throw PSKPromptError.input }
        if byte == 10 || byte == 13 { break }
        bytes.append(byte)
    }
    _ = write(fd, "\n", 1)
    guard (1...1024).contains(bytes.count), !bytes.contains(0),
          String(bytes: bytes, encoding: .utf8) != nil else { throw PSKPromptError.invalid }
    return Data(bytes)
}

private func savePSK(_ psk: Data, for gateway: String) {
    let selector: [CFString: Any] = [
        kSecClass: kSecClassGenericPassword,
        kSecAttrService: keychainService,
        kSecAttrAccount: gateway,
    ]
    var item = selector
    item[kSecValueData] = psk
    let status = SecItemAdd(item as CFDictionary, nil)
    if status == errSecDuplicateItem {
        let replacement: [CFString: Any] = [kSecValueData: psk]
        guard SecItemUpdate(selector as CFDictionary, replacement as CFDictionary) == errSecSuccess else {
            finish("Could not update OFTC Keychain PSK", code: 1)
        }
    } else if status != errSecSuccess {
        finish("Could not save OFTC Keychain PSK", code: 1)
    }
}

private func awaitPreflight(_ connection: NEVPNConnection, deadline: Date) {
    guard Date() < deadline else {
        connection.stopVPNTunnel()
        finish("Provider preflight did not report a stage before timeout", code: 1)
    }
    if connection.status == .connected,
       let session = connection as? NETunnelProviderSession {
        do {
            try session.sendProviderMessage(Data("oftc.preflight-status.v1".utf8)) { reply in
                if let reply, let stage = String(data: reply, encoding: .utf8) {
                    connection.stopVPNTunnel()
                    finish(stage, code: stage.hasPrefix("preflight_passed") ? 0 : 1)
                }
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.25) {
                    awaitPreflight(connection, deadline: deadline)
                }
            }
            return
        } catch { }
    }
    DispatchQueue.main.asyncAfter(deadline: .now() + 0.25) {
        awaitPreflight(connection, deadline: deadline)
    }
}

private func startWithManager(_ manager: NETunnelProviderManager,
                              options: [String: NSObject], preflight: Bool) {
    // Recheck after SAML too: another process may have changed the saved VPN
    // configuration or connection while the browser flow was in progress.
    manager.loadFromPreferences { error in
        guard error == nil, manager.isEnabled,
              (manager.protocolConfiguration as? NETunnelProviderProtocol)?
                  .providerBundleIdentifier == providerID,
              manager.connection.status == .disconnected else {
            finish("OFTC configuration or status changed before start", code: 1)
        }
        do {
            try CandidateHostBridge.start(manager.connection, options: options)
            if preflight {
                awaitPreflight(manager.connection, deadline: Date().addingTimeInterval(45))
            } else {
                finish("Live start requested; inspect status before any fresh-token retry")
            }
        } catch {
            finish("Start request failed; acquire a fresh token before another live attempt", code: 1)
        }
    }
}

private func start(_ options: [String: NSObject], preflight: Bool = false) {
    loadManager { manager in
        guard let manager else { finish("No OFTC configuration; run install-config", code: 1) }
        startWithManager(manager, options: options, preflight: preflight)
    }
    dispatchMain()
}

private func rekeyOnce(ike: Bool = false) {
    let kind = ike ? "IKE_SA" : "CHILD_SA"
    let message = ike ? "oftc.rekey-ike-once.v1" : "oftc.rekey-child-once.v1"
    loadManager { manager in
        guard let manager else { finish("No OFTC configuration", code: 1) }
        manager.loadFromPreferences { error in
            guard error == nil, manager.isEnabled,
                  (manager.protocolConfiguration as? NETunnelProviderProtocol)?
                    .providerBundleIdentifier == providerID,
                  manager.connection.status == .connected,
                  let session = manager.connection as? NETunnelProviderSession else {
                finish("OFTC VPN is not connected", code: 1)
            }
            var completed = false
            DispatchQueue.main.asyncAfter(deadline: .now() + 45) {
                guard !completed else { return }
                completed = true
                finish("\(kind) rekey probe timed out", code: 1)
            }
            do {
                try session.sendProviderMessage(Data(message.utf8)) { reply in
                    DispatchQueue.main.async {
                        guard !completed else { return }
                        completed = true
                        if reply == Data("rekey_passed".utf8) {
                            finish("\(kind) rekey probe passed")
                        }
                        if let reply,
                           let text = String(data: reply, encoding: .utf8),
                           text.hasPrefix("rekey_failed stage="),
                           let stage = Int32(text.dropFirst("rekey_failed stage=".count)),
                           (0...200).contains(stage) {
                            finish("\(kind) rekey probe failed (stage \(stage))", code: 1)
                        }
                        finish("\(kind) rekey probe failed", code: 1)
                    }
                }
            } catch { finish("Could not request \(kind) rekey probe", code: 1) }
        }
    }
    dispatchMain()
}

private func rekeyCounts() {
    loadManager { manager in
        guard let manager else { finish("No OFTC configuration", code: 1) }
        manager.loadFromPreferences { error in
            guard error == nil, manager.connection.status == .connected,
                  let session = manager.connection as? NETunnelProviderSession else {
                finish("OFTC VPN is not connected", code: 1)
            }
            var completed = false
            DispatchQueue.main.asyncAfter(deadline: .now() + 10) {
                guard !completed else { return }
                completed = true
                finish("CHILD_SA rekey counts unavailable", code: 1)
            }
            do {
                try session.sendProviderMessage(Data("oftc.rekey-counts.v1".utf8)) { reply in
                    DispatchQueue.main.async {
                        guard !completed else { return }
                        completed = true
                        guard let reply, let text = String(data: reply, encoding: .utf8),
                              text.hasPrefix("child_rekeys local=") else {
                            finish("CHILD_SA rekey counts unavailable", code: 1)
                        }
                        finish(text)
                    }
                }
            } catch { finish("Could not request CHILD_SA rekey counts", code: 1) }
        }
    }
    dispatchMain()
}

private final class ExtensionDelegate: NSObject, OSSystemExtensionRequestDelegate {
    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        print("macOS approval required for \(request.identifier)")
        print("In System Settings → General → Login Items & Extensions, click ⓘ next to OFTC under Extensions and turn on Network Extension.")
        fflush(stdout)
    }
    func request(_ request: OSSystemExtensionRequest,
                 actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension replacement: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        print("System extension replacement: \(existing.bundleShortVersion)/\(existing.bundleVersion) -> \(replacement.bundleShortVersion)/\(replacement.bundleVersion)")
        fflush(stdout)
        return .replace
    }
    func request(_ request: OSSystemExtensionRequest,
                 didFinishWithResult result: OSSystemExtensionRequest.Result) {
        if result == .willCompleteAfterReboot {
            finish("Extension replacement accepted; reboot required", code: 3)
        }
        finish("System extension request completed")
    }
    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        let nsError = error as NSError
        finish("System extension request failed: domain=\(nsError.domain) code=\(nsError.code)", code: 1)
    }
}

private func startMode(_ flags: [String]) -> (ProviderStartEnvelope.ConnectMode, Bool)? {
    var tcp = false
    var insecure = false
    var idiV4: [UInt8]?
    var index = 0
    while index < flags.count {
        switch flags[index] {
        case "--tcp" where !tcp:
            tcp = true
        case "--insecure-saml" where !insecure:
            insecure = true
        case "--ipv6-outer" where idiV4 == nil && index + 1 < flags.count:
            index += 1
            let parts = flags[index].split(separator: ".", omittingEmptySubsequences: false)
            guard parts.count == 4 else { return nil }
            var octets = [UInt8]()
            for part in parts {
                guard !part.isEmpty, part.count <= 3,
                      part.utf8.allSatisfy({ (48...57).contains($0) }),
                      let octet = UInt8(part) else { return nil }
                octets.append(octet)
            }
            idiV4 = octets
        default:
            return nil
        }
        index += 1
    }
    let mode = ProviderStartEnvelope.ConnectMode(
        transport: tcp ? 2 : 1, outerFamily: idiV4 == nil ? 4 : 6,
        idiV4: idiV4 ?? [0, 0, 0, 0], tcpFallback: tcp ? 0 : 1)
    guard (try? mode.encode()) != nil else { return nil }
    return (mode, insecure)
}

private func profileStore() -> OFTCProfileStore {
    guard let store = try? OFTCProfileStore(bundleID: appID) else {
        finish("Invalid OFTC app identity", code: 1)
    }
    return store
}

private func storedProfile() -> OFTCProfile {
    guard let profile = try? profileStore().load() else {
        finish("OFTC profile unavailable; run oftc setup", code: 1)
    }
    return profile
}

private func runLive(gateway: String, port: UInt32,
                     mode: ProviderStartEnvelope.ConnectMode,
                     insecure: Bool, supervised: Bool) -> Never {
    loadManager { manager in
        guard let manager else { finish("No OFTC configuration; run install-config", code: 1) }
        manager.loadFromPreferences { error in
            guard error == nil, manager.isEnabled,
                  (manager.protocolConfiguration as? NETunnelProviderProtocol)?
                    .providerBundleIdentifier == providerID,
                  manager.connection.status == .disconnected else {
                finish("OFTC configuration unavailable or VPN already active", code: 1)
            }
            if supervised {
                let lease: SupervisorLease
                do { lease = try SupervisorLease(bundleID: appID) }
                catch { finish("Another OFTC supervisor is active", code: 1) }
                let supervisor = ReconnectSupervisor(
                    manager: manager, providerID: providerID, gateway: gateway,
                    samlPort: port, mode: mode, insecure: insecure, lease: lease,
                    loadPSK: { try lookupPSK(for: gateway) })
                activeSupervisor = supervisor
                supervisor.run()
                return
            }
            var psk = storedPSK(for: gateway)
            defer { psk.resetBytes(in: 0..<psk.count) }
            var options: [String: NSObject]
            do {
                options = try CandidateHostBridge.acquireOptions(
                    gateway: gateway, psk: psk, samlPort: port,
                    insecure: insecure)
                options[ProviderStartEnvelope.modeKey] = try mode.encode() as NSData
            } catch { finish("SAML bootstrap failed", code: 1) }
            startWithManager(manager, options: options, preflight: false)
        }
    }
    dispatchMain()
}

private let usage = "Usage: OFTCAgent activate|deactivate|agent-status|register-agent|unregister-agent|install-config|save-profile <gateway> <saml-port> [--tcp]|import-profile <FortiClient-profile>|import-development-profile|show-profile|erase-profile|has-psk|start-profile [--tcp] [--ipv6-outer <CLAT-IPv4>] [--insecure-saml]|supervise-profile [--tcp] [--ipv6-outer <CLAT-IPv4>] [--insecure-saml]|provision-psk [gateway]|migrate-psk <FortiClient-profile> <gateway>|preflight <gateway> <32-hex-UID>|start-live <gateway> <saml-port> [--tcp] [--ipv6-outer <CLAT-IPv4>] [--insecure-saml]|supervise-live <gateway> <saml-port> [--tcp] [--ipv6-outer <CLAT-IPv4>] [--insecure-saml]|rekey-once|rekey-ike-once|rekey-counts|status|stop|remove-config"
let args = Array(CommandLine.arguments.dropFirst())
if args.isEmpty {
    OFTCMenuBar.run(appID: appID)
}
guard let command = args.first, !appID.isEmpty else { finish(usage, code: 2) }

switch command {
case "--after-install" where args.count == 1:
    OFTCMenuBar.run(appID: appID, afterInstall: true)

case "preview-menu" where args.count == 2:
    guard let state = MenuConnectionState(rawValue: args[1]) else { finish("Invalid preview state", code: 2) }
    OFTCMenuBar.run(appID: appID, preview: state)

case "render-menu-previews" where args.count == 2:
    do { try OFTCMenuBar.renderPreviews(to: URL(fileURLWithPath: args[1], isDirectory: true)) }
    catch { finish("Could not render menu previews: \(error)", code: 1) }

case "prepare-connect" where args.count == 1:
    do { try OFTCAgentService.prepareConnect() }
    catch { finish("Could not prepare an OFTC connection", code: 1) }
    finish("OFTC connection requested")

case "cancel-connect-request" where args.count == 1:
    AgentIntent(bundleID: appID).cancelRequest()
    finish("OFTC connection request cancelled")

case "unregister-menu-login" where args.count == 1:
    if SMAppService.mainApp.status == .enabled || SMAppService.mainApp.status == .requiresApproval {
        do { try SMAppService.mainApp.unregister() }
        catch { finish("Could not unregister the OFTC menu login item", code: 1) }
    }
    finish("OFTC menu login item unregistered")

case "quit-menu" where args.count == 1:
    DistributedNotificationCenter.default().postNotificationName(
        Notification.Name(appID + ".quit-menu"), object: nil, deliverImmediately: true)
    finish("OFTC menu quit requested")

case "agent-status" where args.count == 1:
    finish(OFTCAgentService.status)

case "login-settings" where args.count == 1:
    finish("Menu launch at login: \(SMAppService.mainApp.status == .enabled ? "enabled" : "disabled")\nVPN connect at login: \(OFTCAgentService.connectAtLogin ? "enabled" : "disabled")")

case "register-agent" where args.count == 1:
    do { try OFTCAgentService.register() }
    catch { finish("Could not register OFTC login agent: \(error.localizedDescription)", code: 1) }
    finish("OFTC login agent registered")

case "unregister-agent" where args.count == 1:
    do { try OFTCAgentService.unregister() }
    catch { finish("Could not unregister OFTC login agent: \(error.localizedDescription)", code: 1) }
    finish("OFTC login agent unregistered")

case "activate" where args.count == 1, "deactivate" where args.count == 1:
    let delegate = ExtensionDelegate()
    let request = command == "activate"
        ? OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: providerID, queue: .main)
        : OSSystemExtensionRequest.deactivationRequest(forExtensionWithIdentifier: providerID, queue: .main)
    request.delegate = delegate
    OSSystemExtensionManager.shared.submitRequest(request)
    withExtendedLifetime(delegate) { dispatchMain() }

case "install-config" where args.count == 1:
    loadManager { existing in
        if existing != nil { finish("OFTC configuration already exists") }
        let manager = NETunnelProviderManager()
        let configuration = NETunnelProviderProtocol()
        configuration.providerBundleIdentifier = providerID
        configuration.serverAddress = "OFTC" // Display label only, never a secret.
        manager.protocolConfiguration = configuration
        manager.localizedDescription = "OFTC VPN"
        manager.isEnabled = true
        manager.saveToPreferences { error in
            if error != nil { finish("Could not save OFTC configuration", code: 1) }
            finish("OFTC configuration saved")
        }
    }
    dispatchMain()

case "has-psk" where args.count == 1:
    let gateway = storedProfile().gateway
    guard var psk = try? lookupPSK(for: gateway) else {
        finish("OFTC PSK unavailable", code: 1)
    }
    psk.resetBytes(in: 0..<psk.count)
    finish("OFTC PSK available")

case "provision-psk" where args.count == 1 || args.count == 2:
    let gateway = args.count == 2 ? args[1] : storedProfile().gateway
    guard !gateway.isEmpty, gateway.utf8.count <= 253,
          !gateway.contains("/"), !gateway.contains(":") else {
        finish("Invalid gateway name", code: 2)
    }
    var psk: Data
    do { psk = try readPSKFromTTY() }
    catch { finish("Could not read a valid PSK from the terminal", code: 1) }
    savePSK(psk, for: gateway)
    psk.resetBytes(in: 0..<psk.count)
    finish("OFTC PSK stored in Keychain")

case "migrate-psk" where args.count == 3:
    // Explicit one-time path. Tunnel starts never consult FortiClient files.
    var psk: Data
    do { psk = try MigrationBridge.psk(profileName: args[1], expectedGateway: args[2]) }
    catch { finish("Could not obtain plaintext PSK for that profile and gateway", code: 1) }
    savePSK(psk, for: args[2])
    psk.resetBytes(in: 0..<psk.count)
    finish("Existing local profile PSK migrated into OFTC Keychain")

case "save-profile" where args.count == 3 || (args.count == 4 && args[3] == "--tcp"):
    guard let port = UInt32(args[2]),
          let profile = try? OFTCProfile(gateway: args[1], samlPort: port,
              transport: args.count == 4 ? .tcp : .udp) else { finish(usage, code: 2) }
    do { try profileStore().save(profile) }
    catch { finish("Could not save OFTC profile", code: 1) }
    finish("OFTC profile saved")

case "import-profile" where args.count == 2:
    // Only this explicit command loads FortiClient configuration. Normal
    // connection and recovery read the OFTC store and Keychain exclusively.
    var imported: MigrationBridge.ImportedProfile
    do { imported = try MigrationBridge.importProfile(name: args[1]) }
    catch { finish("Could not import FortiClient profile", code: 1) }
    defer { imported.psk.resetBytes(in: 0..<imported.psk.count) }
    let profile: OFTCProfile
    do { profile = try OFTCProfile(gateway: imported.gateway, samlPort: imported.samlPort) }
    catch { finish("Imported profile has invalid connection settings", code: 1) }
    savePSK(imported.psk, for: profile.gateway)
    do { try profileStore().save(profile) }
    catch { finish("PSK saved but OFTC profile could not be saved", code: 1) }
    finish("FortiClient profile imported into OFTC configuration and Keychain")

case "import-development-profile" where args.count == 1:
    // The old profile is nonsecret. Its Keychain PSK needs separate explicit
    // provisioning under the new signed identity.
    let destination = profileStore()
    guard (try? destination.load()) == nil else {
        finish("OFTC profile already exists; migration did not overwrite it", code: 1)
    }
    let profile: OFTCProfile
    do {
        profile = try OFTCProfileStore(bundleID: "com.chris.openforticlient.gate0").load()
        try destination.save(profile)
    } catch { finish("Could not import development profile", code: 1) }
    finish("Development profile copied; provision its PSK before connecting")

case "show-profile" where args.count == 1:
    let profile = storedProfile()
    finish("OFTC profile: gateway=\(profile.gateway) saml-port=\(profile.samlPort) transport=\(profile.transport.rawValue)")

case "erase-profile" where args.count == 1:
    loadManager { manager in
        if let manager, manager.connection.status != .disconnected,
           manager.connection.status != .invalid {
            finish("Disconnect OFTC before erasing its profile", code: 1)
        }
        let store = profileStore()
        guard let profile = try? store.load() else {
            if !FileManager.default.fileExists(atPath: store.url.path),
               (try? FileManager.default.destinationOfSymbolicLink(atPath: store.url.path)) == nil {
                finish("OFTC profile absent; nothing erased")
            }
            finish("OFTC profile invalid; nothing erased", code: 1)
        }
        let selector: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: keychainService,
            kSecAttrAccount: profile.gateway,
        ]
        let status = SecItemDelete(selector as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            finish("Could not erase OFTC Keychain PSK; profile left in place", code: 1)
        }
        do { try store.remove() }
        catch { finish("Keychain PSK erased, but profile file could not be removed", code: 1) }
        finish("OFTC profile and Keychain PSK erased")
    }
    dispatchMain()

case "preflight" where args.count == 3:
    let gateway = args[1]
    let uid = args[2]
    guard uid.utf8.count == 32, uid.utf8.allSatisfy({
        (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0)
    }) else {
        finish("Expected a 32-character hexadecimal UID", code: 2)
    }
    var psk = storedPSK(for: gateway)
    defer { psk.resetBytes(in: 0..<psk.count) }
    let wire: Data
    do { wire = try ProviderBootstrapInput.preflightWire(gateway: gateway, uid: uid, psk: psk) }
    catch { finish("Invalid preflight input", code: 2) }
    let now = UInt64(Date().timeIntervalSince1970)
    let payload = BootstrapWire.Payload(expiresAt: now + 60,
        sessionID: withUnsafeBytes(of: UUID().uuid) { Data($0) }, secret: wire)
    let envelope: Data
    do { envelope = try BootstrapWire.encode(payload, now: now) }
    catch { finish("Could not make preflight envelope", code: 2) }
    start([ProviderStartEnvelope.preflightKey: envelope as NSData], preflight: true)

case "start-live" where args.count >= 3:
    let gateway = args[1]
    guard let (mode, insecure) = startMode(Array(args.dropFirst(3))) else {
        finish(usage, code: 2)
    }
    guard let port = UInt32(args[2]), port > 0, port <= 65535,
          !gateway.isEmpty else { finish(usage, code: 2) }
    runLive(gateway: gateway, port: port, mode: mode,
            insecure: insecure, supervised: false)

case "supervise-live" where args.count >= 3:
    let gateway = args[1]
    guard let (mode, insecure) = startMode(Array(args.dropFirst(3))),
          let port = UInt32(args[2]), port > 0, port <= 65535,
          !gateway.isEmpty else { finish(usage, code: 2) }
    runLive(gateway: gateway, port: port, mode: mode,
            insecure: insecure, supervised: true)

case "start-profile", "supervise-profile":
    if command == "supervise-profile" {
        do { try OFTCAgentService.redirectSupervisorOutput() }
        catch { finish(error.localizedDescription, code: 1) }
        if ProcessInfo.processInfo.environment["OFTC_BUNDLED_AGENT"] == "1",
           !AgentIntent(bundleID: appID).shouldStart() {
            finish("OFTC automatic VPN connection is disabled")
        }
    }
    let profile = storedProfile()
    var flags = Array(args.dropFirst())
    if profile.transport == .tcp && !flags.contains("--tcp") {
        flags.insert("--tcp", at: 0)
    }
    guard let (mode, insecure) = startMode(flags) else { finish(usage, code: 2) }
    runLive(gateway: profile.gateway, port: profile.samlPort, mode: mode,
            insecure: insecure, supervised: command == "supervise-profile")

case "status" where args.count == 1:
    loadManager { manager in
        guard let manager else { finish("OFTC configuration absent") }
        let state: String
        switch manager.connection.status {
        case .invalid: state = "invalid"
        case .disconnected: state = "disconnected"
        case .connecting: state = "connecting"
        case .connected: state = "connected"
        case .reasserting: state = "reasserting"
        case .disconnecting: state = "disconnecting"
        @unknown default: state = "unknown"
        }
        finish("OFTC VPN status: \(state)")
    }
    dispatchMain()

case "rekey-once" where args.count == 1:
    rekeyOnce()
case "rekey-ike-once" where args.count == 1:
    rekeyOnce(ike: true)

case "rekey-counts" where args.count == 1:
    rekeyCounts()

case "stop" where args.count == 1:
    guard SupervisorLease.requestStop(bundleID: appID) else {
        finish("Could not signal OFTC supervisor; VPN left running", code: 1)
    }
    let intent = AgentIntent(bundleID: appID)
    do { try intent.setConnectAtLogin(false) }
    catch { finish("Could not disable automatic VPN connection", code: 1) }
    intent.cancelRequest()
    loadManager { manager in
        guard let manager else { finish("OFTC configuration absent") }
        manager.connection.stopVPNTunnel()
        finish("Stop requested")
    }
    dispatchMain()

case "remove-config" where args.count == 1:
    loadManager { manager in
        guard let manager else { finish("OFTC configuration absent") }
        manager.removeFromPreferences { error in
            if error != nil { finish("Could not remove OFTC configuration", code: 1) }
            finish("OFTC configuration removed")
        }
    }
    dispatchMain()

default:
    finish(usage, code: 2)
}
