import Darwin
import AppKit
import Foundation
import NetworkExtension
import Security

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
                     insecure: Bool) -> Never {
    loadManager { manager in
        guard let manager else { finish("No OFTC configuration; run install-config", code: 1) }
        manager.loadFromPreferences { error in
            guard error == nil, manager.isEnabled,
                  belongs(manager),
                  manager.connection.status == .disconnected else {
                finish("OFTC configuration unavailable or VPN already active", code: 1)
            }
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
        }
    }
    dispatchMain()
}

private let usage = "Usage: OFTCAgent [--profile <id>] activate|deactivate|agent-status|register-agent|unregister-agent|install-config|list-profiles|check-update [url]|launcher-alias ensure|remove|export-profiles [id...]|import-profiles|save-profile <gateway> <saml-port> [--tcp] [--name <name>]|import-profile <FortiClient-profile>|show-profile|erase-profile|has-psk|set-autostart on|off|supervise-autostart|start-profile [--tcp] [--ipv6-outer <CLAT-IPv4>] [--insecure-saml]|supervise-profile [--tcp] [--ipv6-outer <CLAT-IPv4>] [--insecure-saml]|provision-psk [--stdin] [gateway]|migrate-psk <FortiClient-profile> <gateway>|preflight <gateway> <32-hex-UID>|start-live <gateway> <saml-port> [--tcp] [--ipv6-outer <CLAT-IPv4>] [--insecure-saml]|supervise-live <gateway> <saml-port> [--tcp] [--ipv6-outer <CLAT-IPv4>] [--insecure-saml]|rekey-once|rekey-ike-once|rekey-counts|status|stop|remove-config"
// The verbs below are implemented in Rust (liboftc_hostlib.a) and the rest here. Keep
// this list equal to the `rust` rows of `VERBS` in app/core/host/src/commands.rs; a
// Rust test compares them. Rust also handles a leading `--profile <id>` for them.
private let rustVerbs: Set<String> = ["activate", "deactivate", "agent-status", "register-agent", "unregister-agent", "login-settings", "unregister-menu-login", "list-profiles", "show-profile", "has-psk", "provision-psk", "save-profile", "install-config", "erase-profile", "preflight", "start-live", "start-profile", "status", "rekey-once", "rekey-ike-once", "rekey-counts", "remove-config", "stop", "set-autostart", "supervise-autostart", "export-profiles", "import-profiles", "import-profile", "migrate-psk"]

@_silgen_name("oftc_host_main")
private func oftcHostMain(_ argc: Int32, _ argv: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>,
                          _ bundleID: UnsafePointer<CChar>) -> Never

// Hands `args` to the Rust host as if they had been the command line.
private func runRust(_ args: [String]) -> Never {
    var argv: [UnsafeMutablePointer<CChar>?] = (["OFTCAgent"] + args).map { strdup($0) } + [nil]
    return appID.withCString { oftcHostMain(Int32(args.count + 1), &argv, $0) }
}

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

case "quit-menu" where args.count == 1:
    DistributedNotificationCenter.default().postNotificationName(
        Notification.Name(appID + ".quit-menu"), object: nil, deliverImmediately: true)
    finish("OFTC menu quit requested")

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

case "supervise-live" where args.count >= 3:
    let gateway = args[1]
    guard let (mode, insecure) = startMode(Array(args.dropFirst(3))),
          let port = UInt32(args[2]), port > 0, port <= 65535,
          !gateway.isEmpty else { finish(usage, code: 2) }
    runLive(gateway: gateway, port: port, mode: mode, insecure: insecure)

case "supervise-profile":
    // An agent plist from before multi-profile support runs this
    // command without a profile; it now means "start the autostart set".
    if selectedProfile == nil,
       ProcessInfo.processInfo.environment["OFTC_BUNDLED_AGENT"] == "1" {
        runRust(["supervise-autostart"])
    }
    do { try OFTCAgentService.redirectSupervisorOutput() }
    catch { finish(error.localizedDescription, code: 1) }
    let profile = storedProfile()
    var flags = Array(args.dropFirst())
    if profile.transport == .tcp && !flags.contains("--tcp") {
        flags.insert("--tcp", at: 0)
    }
    guard let (mode, insecure) = startMode(flags) else { finish(usage, code: 2) }
    runLive(gateway: profile.gateway, port: profile.samlPort, mode: mode, insecure: insecure)

default:
    finish(usage, code: 2)
}
