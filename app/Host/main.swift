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
// Set from a leading `--profile <id>`. Without it, the only configured
// profile is used; several profiles require an explicit choice.
private var selectedProfile: String?
private let profileRoot = OFTCProfileScope.defaultRoot(bundleID: appID)

private func allEntries() -> [OFTCProfileEntry] { OFTCProfileScope.entries(root: profileRoot) }

private func requireEntry() -> OFTCProfileEntry {
    let entries = allEntries()
    if let id = selectedProfile {
        guard let entry = entries.first(where: { $0.id == id }) else {
            finish("OFTC profile unavailable: no profile named \(id); run oftc setup", code: 1)
        }
        return entry
    }
    if entries.count == 1 { return entries[0] }
    if entries.isEmpty { finish("OFTC profile unavailable; run oftc setup", code: 1) }
    finish("Several OFTC profiles are configured; choose one with --profile <id> (\(entries.map(\.id).joined(separator: ", ")))", code: 1)
}

private func belongs(_ manager: NETunnelProviderManager) -> Bool {
    OFTCProfileScope.matches(manager, providerID: providerID, entry: requireEntry())
}

private func finish(_ message: String, code: Int32 = 0) -> Never {
    print(message)
    fflush(stdout)
    exit(code)
}

private func loadManager(_ completion: @escaping (NETunnelProviderManager?) -> Void) {
    let entry = requireEntry()
    NETunnelProviderManager.loadAllFromPreferences { managers, error in
        if error != nil { finish("Could not load VPN configuration", code: 1) }
        let matching = OFTCProfileScope.manager(for: entry, in: managers ?? [], providerID: providerID)
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
              belongs(manager),
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
                  belongs(manager),
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

private func storedProfile() -> OFTCProfile { requireEntry().profile }

// Looks up the FortiClient name of a profile with this gateway, used to name
// the profile migrated from the original single-profile layout.
private func fortiClientName(forGateway gateway: String) -> String? {
    let plist = URL(fileURLWithPath: "/Library/Application Support/Fortinet/FortiClient/conf/vpn.plist")
    guard let data = try? Data(contentsOf: plist), data.count <= 4_000_000,
          let root = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
          let profiles = root["Profiles"] as? [String: Any] else { return nil }
    return profiles.keys.sorted().first {
        (profiles[$0] as? [String: Any])?["Server"] as? String == gateway
    }
}

private func runLive(gateway: String, port: UInt32,
                     mode: ProviderStartEnvelope.ConnectMode,
                     insecure: Bool, supervised: Bool) -> Never {
    loadManager { manager in
        guard let manager else { finish("No OFTC configuration; run install-config", code: 1) }
        manager.loadFromPreferences { error in
            guard error == nil, manager.isEnabled,
                  belongs(manager),
                  manager.connection.status == .disconnected else {
                finish("OFTC configuration unavailable or VPN already active", code: 1)
            }
            if supervised {
                let lease: SupervisorLease
                let entry = requireEntry()
                // Named on the browser's sign-in confirmation page.
                setenv("OFTC_PROFILE_NAME", entry.name, 1)
                setenv("OFTC_PROFILE_GATEWAY", gateway, 1)
                do { lease = try SupervisorLease(directory: entry.directory) }
                catch { finish("Another OFTC supervisor is active", code: 1) }
                let supervisor = ReconnectSupervisor(
                    manager: manager, providerID: providerID, gateway: gateway,
                    samlPort: port, mode: mode, insecure: insecure, lease: lease,
                    entry: entry,
                    loadPSK: { try lookupPSK(for: gateway) })
                supervisor.reviewCertificate = { host, port in
                    GatewayTrust.review(host: host, port: port, profileName: entry.name,
                                        prompt: GatewayTrustPrompt.present)
                }
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

// Runs as the login agent: starts a supervisor process for every profile whose
// connect-at-login choice (or a one-use request) says to connect. Supervisors
// serialize their own SAML sign-ins, so they can all start at once.
private func superviseAutostart() -> Never {
    do { try OFTCAgentService.redirectSupervisorOutput() }
    catch { finish(error.localizedDescription, code: 1) }
    var children: [Process] = []
    for entry in allEntries() where OFTCAgentService.intent(for: entry).shouldStart(
        legacyEnabled: entry.profile.adoptsUnkeyedVPNEntry == true) {
        guard let executable = Bundle.main.executableURL else { continue }
        let process = Process()
        process.executableURL = executable
        process.arguments = ["--profile", entry.id, "supervise-profile"]
        var environment = ProcessInfo.processInfo.environment
        environment.removeValue(forKey: "OFTC_BUNDLED_AGENT")
        process.environment = environment
        let logs = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Logs/OFTC", isDirectory: true)
        let logURL = logs.appendingPathComponent(entry.id + ".log")
        if let descriptor = Optional(open(logURL.path, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW, 0o600)),
           descriptor >= 0 {
            let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
            process.standardOutput = handle
            process.standardError = handle
        }
        process.standardInput = FileHandle.nullDevice
        do { try process.run(); children.append(process) }
        catch { print("Could not start supervisor for \(entry.id)") }
    }
    if children.isEmpty { finish("OFTC automatic VPN connection is disabled for every profile") }
    for process in children { process.waitUntilExit() }
    finish("OFTC supervisors exited")
}

private let usage = "Usage: OFTCAgent [--profile <id>] activate|deactivate|agent-status|register-agent|unregister-agent|install-config|list-profiles|check-update [url]|launcher-alias ensure|remove|export-profiles [id...]|import-profiles|save-profile <gateway> <saml-port> [--tcp] [--name <name>]|import-profile <FortiClient-profile>|show-profile|erase-profile|has-psk|set-autostart on|off|supervise-autostart|start-profile [--tcp] [--ipv6-outer <CLAT-IPv4>] [--insecure-saml]|supervise-profile [--tcp] [--ipv6-outer <CLAT-IPv4>] [--insecure-saml]|provision-psk [--stdin] [gateway]|migrate-psk <FortiClient-profile> <gateway>|preflight <gateway> <32-hex-UID>|start-live <gateway> <saml-port> [--tcp] [--ipv6-outer <CLAT-IPv4>] [--insecure-saml]|supervise-live <gateway> <saml-port> [--tcp] [--ipv6-outer <CLAT-IPv4>] [--insecure-saml]|rekey-once|rekey-ike-once|rekey-counts|status|stop|remove-config"
// The verbs below are implemented in Rust (liboftc_hostlib.a) and the rest here. Keep
// this list equal to the `rust` rows of `VERBS` in app/core/host/src/commands.rs; a
// Rust test compares them. Rust also handles a leading `--profile <id>` for them.
private let rustVerbs: Set<String> = ["list-profiles", "show-profile", "has-psk", "provision-psk", "save-profile", "export-profiles", "import-profiles", "import-profile", "migrate-psk"]

@_silgen_name("oftc_host_main")
private func oftcHostMain(_ argc: Int32, _ argv: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>,
                          _ bundleID: UnsafePointer<CChar>) -> Never

var args = Array(CommandLine.arguments.dropFirst())
if let verb = args.first == "--profile" && args.count >= 3 ? args[2] : args.first,
   rustVerbs.contains(verb) {
    appID.withCString { oftcHostMain(CommandLine.argc, CommandLine.unsafeArgv, $0) }
}
if args.first == "--profile" {
    guard args.count >= 3, OFTCProfileScope.isValidID(args[1]) else {
        finish("--profile needs a name of 1-32 lowercase letters, digits or hyphens", code: 2)
    }
    selectedProfile = args[1]
    args.removeFirst(2)
}
if args.first == "review-certificate" {
    GatewayTrustPrompt.runChild()
}
// Previews must not touch real profiles.
if !["preview-menu", "render-menu-previews"].contains(args.first ?? "") {
    OFTCProfileScope.migrateLegacy(root: profileRoot, nameForGateway: fortiClientName(forGateway:))
}
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
    var lines = ["Menu launch at login: \(SMAppService.mainApp.status == .enabled ? "enabled" : "disabled")"]
    for entry in allEntries() {
        lines.append("VPN connect at login (\(entry.id)): \(OFTCAgentService.connectAtLogin(entry) ? "enabled" : "disabled")")
    }
    finish(lines.joined(separator: "\n"))

case "set-autostart" where args.count == 2 && ["on", "off"].contains(args[1]):
    let entry = requireEntry()
    do { try OFTCAgentService.setConnectAtLogin(args[1] == "on", for: entry) }
    catch { finish("Could not change automatic connection: \(error.localizedDescription)", code: 1) }
    finish("Connect at login for \(entry.id): \(args[1])")

case "supervise-autostart" where args.count == 1:
    superviseAutostart()

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
    let entry = requireEntry()
    loadManager { existing in
        if existing != nil { finish("OFTC configuration already exists") }
        let manager = NETunnelProviderManager()
        let configuration = NETunnelProviderProtocol()
        configuration.providerBundleIdentifier = providerID
        configuration.serverAddress = "OFTC" // Display label only, never a secret.
        configuration.providerConfiguration = [OFTCProfileScope.configurationKey: entry.id]
        manager.protocolConfiguration = configuration
        manager.localizedDescription = "OFTC VPN (\(entry.name))"
        manager.isEnabled = true
        manager.saveToPreferences { error in
            if error != nil { finish("Could not save OFTC configuration", code: 1) }
            finish("OFTC configuration saved")
        }
    }
    dispatchMain()

case "launcher-alias" where args.count == 2 && ["ensure", "remove"].contains(args[1]):
    if args[1] == "ensure" { LauncherAlias.ensure() } else { LauncherAlias.remove() }
    finish("Launcher alias \(args[1] == "ensure" ? "checked" : "removed")")

case "check-update" where args.count <= 2:
    // Fetches the update feed (the configured one, or the URL given) and says
    // what it would offer. Nothing is downloaded or installed.
    let feed = args.count == 2 ? URL(string: args[1]) : UpdateFeed.configuredURL()
    guard let feed else { finish("No update feed is configured", code: 1) }
    let installed = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0"
    UpdateFeed.fetch(feed, current: installed) { result in
        switch result {
        case .success(let offer?): finish("Update available: \(offer.version) (\(offer.page.absoluteString)); installed \(installed)")
        case .success(nil): finish("Up to date: installed \(installed) is the latest")
        case .failure(let failure): finish("Could not check for updates (\(failure))", code: 1)
        }
    }
    dispatchMain()

case "erase-profile" where args.count == 1:
    // Without --profile this erases every profile, so uninstall can clean up.
    let targets = selectedProfile == nil ? allEntries() : [requireEntry()]
    if targets.isEmpty { finish("OFTC profile absent; nothing erased") }
    NETunnelProviderManager.loadAllFromPreferences { managers, error in
        if error != nil { finish("Could not load VPN configuration", code: 1) }
        for entry in targets {
            for manager in OFTCProfileScope.manager(for: entry, in: managers ?? [], providerID: providerID)
            where manager.connection.status != .disconnected && manager.connection.status != .invalid {
                finish("Disconnect \(entry.name) before erasing its profile", code: 1)
            }
        }
        func eraseData() {
            for entry in targets {
                let selector: [CFString: Any] = [
                    kSecClass: kSecClassGenericPassword,
                    kSecAttrService: keychainService,
                    kSecAttrAccount: entry.profile.gateway,
                ]
                let status = SecItemDelete(selector as CFDictionary)
                guard status == errSecSuccess || status == errSecItemNotFound else {
                    finish("Could not erase OFTC Keychain PSK for \(entry.name); profile left in place", code: 1)
                }
                // Its trusted gateway certificate goes too; a re-added VPN asks again.
                try? FileManager.default.removeItem(at: GatewayTrust.pinURL(
                    host: entry.profile.gateway, port: entry.profile.samlPort,
                    directory: GatewayTrust.pinDirectory()))
                do { try FileManager.default.removeItem(at: entry.directory) }
                catch { finish("Keychain PSK erased, but profile \(entry.name) could not be removed", code: 1) }
            }
            finish("OFTC profile, VPN entry and Keychain PSK erased")
        }
        // Each profile's macOS VPN entry goes with it, so none is left orphaned.
        func removeNext(_ remaining: [NETunnelProviderManager]) {
            guard let manager = remaining.first else { eraseData(); return }
            manager.removeFromPreferences { error in
                if error != nil { finish("Could not remove an OFTC VPN entry; profile left in place", code: 1) }
                removeNext(Array(remaining.dropFirst()))
            }
        }
        removeNext(targets.flatMap {
            OFTCProfileScope.manager(for: $0, in: managers ?? [], providerID: providerID)
        })
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
        // An agent plist from before multi-profile support runs this
        // command without a profile; it now means "start the autostart set".
        if selectedProfile == nil,
           ProcessInfo.processInfo.environment["OFTC_BUNDLED_AGENT"] == "1" {
            superviseAutostart()
        }
        do { try OFTCAgentService.redirectSupervisorOutput() }
        catch { finish(error.localizedDescription, code: 1) }
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
    // Stopping a tunnel leaves its connect-at-login choice alone; that is a
    // separate per-profile setting.
    guard SupervisorLease.requestStop(directory: requireEntry().directory) else {
        finish("Could not signal OFTC supervisor; VPN left running", code: 1)
    }
    loadManager { manager in
        guard let manager else { finish("OFTC configuration absent") }
        manager.connection.stopVPNTunnel()
        finish("Stop requested")
    }
    dispatchMain()

case "remove-config" where args.count == 1:
    // Removes every OFTC VPN entry, with or without a profile key.
    NETunnelProviderManager.loadAllFromPreferences { managers, error in
        if error != nil { finish("Could not load VPN configuration", code: 1) }
        let ours = (managers ?? []).filter {
            ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == providerID
        }
        if ours.isEmpty { finish("OFTC configuration absent") }
        var remaining = ours.count
        for manager in ours {
            manager.removeFromPreferences { error in
                if error != nil { finish("Could not remove OFTC configuration", code: 1) }
                remaining -= 1
                if remaining == 0 { finish("OFTC configuration removed") }
            }
        }
    }
    dispatchMain()

default:
    finish(usage, code: 2)
}
