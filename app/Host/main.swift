import AppKit
import Foundation

// The UI edge. Every host verb is Rust (liboftc_hostlib.a: core/host); only what needs
// AppKit or bookmarks stays here. The menu reads nothing from the host's files:
// it asks the host over its socket (HostEdge.swift). Keep `swift` rows of `VERBS` in
// core/host/src/commands.rs equal to the verbs below; a Rust test compares them.
private let appID = Bundle.main.bundleIdentifier ?? ""

@_silgen_name("oftc_host_main")
private func oftcHostMain(_ argc: Int32, _ argv: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>,
                          _ bundleID: UnsafePointer<CChar>) -> Never

private func finish(_ message: String, code: Int32 = 0) -> Never {
    print(message)
    fflush(stdout)
    exit(code)
}

let args = Array(CommandLine.arguments.dropFirst())
switch (args.first ?? "", args.count) {
case ("", _):
    OFTCMenuBar.run(appID: appID)
case ("--after-install", 1):
    OFTCMenuBar.run(appID: appID, afterInstall: true)
case ("preview-menu", 2):
    guard let state = MenuConnectionState(rawValue: args[1]) else { finish("Invalid preview state", code: 2) }
    OFTCMenuBar.run(appID: appID, preview: state)
case ("render-menu-previews", 2):
    do { try OFTCMenuBar.renderPreviews(to: URL(fileURLWithPath: args[1], isDirectory: true)) }
    catch { finish("Could not render menu previews: \(error)", code: 1) }
case ("review-certificate", 1):
    GatewayTrustPrompt.runChild()
case ("quit-menu", 1):
    DistributedNotificationCenter.default().postNotificationName(
        Notification.Name(appID + ".quit-menu"), object: nil, deliverImmediately: true)
    finish("OFTC menu quit requested")
case ("launcher-alias", 2) where ["ensure", "remove"].contains(args[1]):
    if args[1] == "ensure" { LauncherAlias.ensure() } else { LauncherAlias.remove() }
    finish("Launcher alias \(args[1] == "ensure" ? "checked" : "removed")")
default:
    // Everything else, including the usage text and `--profile`, is the Rust host's.
    var argv: [UnsafeMutablePointer<CChar>?] = CommandLine.arguments.map { strdup($0) } + [nil]
    appID.withCString { oftcHostMain(CommandLine.argc, &argv, $0) }
}
