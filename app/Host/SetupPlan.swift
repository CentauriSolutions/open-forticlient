import Foundation

// What "Set up…" (and "Update VPN component") does for a profile that is already
// on disk. Pure, so the decision table is pinned by check-setup-plan.swift.
// Issue 88: the form is only for a VPN that does not exist yet; everything else
// finishes with `oftc setup`, which is idempotent and asks for nothing.
enum SetupPlan: Equatable {
    case addForm                 // no profile yet: the Add a VPN form
    case repair                  // the host's component_update: keys, extension, VPN entries
    case waitForDisconnect       // the component must be replaced, but a tunnel is live
    case newerInstalled          // the installed component is newer than this app
    case nothingToDo
    case waitForHost             // the host is not answering: its document says nothing yet

    // While the host is down its document is empty, so "no profiles" would be a guess: an
    // upgrade's first launch has profiles on disk and a host still starting or awaiting approval.
    // Never choose from it; wait for the host (docs/ui-edge.md 7).
    static func decide(hostReady: Bool = true, profileCount: Int,
                       component: VPNComponentState, entriesMissing: Bool, anyActive: Bool) -> Self {
        if !hostReady { return .waitForHost }
        if component == .newer { return .newerInstalled }
        if profileCount == 0 { return .addForm }
        if component == .updateRequired && anyActive { return .waitForDisconnect }
        if component == .ready && !entriesMissing { return .nothingToDo }
        return .repair
    }

    // Repair once on launch so the user's only job is approving in System Settings.
    // Never for a login-item launch (nothing asked for it), and never again once
    // tried in this process, so a failure cannot loop.
    // The cheap guards come first so the caller can skip computing a plan on the many
    // checks that cannot lead to a repair.
    static func mayAutoRepair(component: VPNComponentState, automaticLaunch: Bool,
                              alreadyTried: Bool) -> Bool {
        component.needsSetup && !automaticLaunch && !alreadyTried
    }

    static func shouldAutoRepair(_ plan: Self, component: VPNComponentState,
                                 automaticLaunch: Bool, alreadyTried: Bool) -> Bool {
        mayAutoRepair(component: component, automaticLaunch: automaticLaunch, alreadyTried: alreadyTried)
            && plan == .repair
    }
}

/// What the setup button does and when the window carries on by itself, after the button was
/// pressed. Pure so the walkthrough in check-setup-plan.swift pins every transition.
enum SetupContinuation {
    enum Step: Equatable {
        case startService      // not running, or its approval is pending: start it / open Login Items
        case runUpdate         // the host's component_update
        case openForm          // no VPN yet: the Add a VPN form is next, not a component update
        case wait              // starting, updating or unsupported: nothing to press yet
    }

    static func step(service: ServiceState, plan: SetupPlan) -> Step {
        switch service {
        case .needsApproval, .notRunning: return .startService
        case .starting, .updating, .unsupported: return .wait
        case .ready:
            switch plan {
            case .addForm: return .openForm
            case .repair: return .runUpdate
            default: return .wait
            }
        }
    }

    /// What the window does by itself, without a click: only after the button was pressed, never
    /// while a run is going, only once the host answers; after a run that ended waiting for approval
    /// only once the component state has moved (so a refused approval cannot loop).
    static func automatic(intent: Bool, running: Bool, service: ServiceState, plan: SetupPlan,
                          phase: OFTCSetupRepair.Phase, component: VPNComponentState,
                          waitedAt: VPNComponentState?) -> Step? {
        guard intent, !running else { return nil }
        let next = step(service: service, plan: plan)
        guard next == .runUpdate || next == .openForm else { return nil }
        if next == .runUpdate, phase == .stillWaiting, component == waitedAt { return nil }
        return next
    }
}

/// How "Set up…" starts, from the plan: the entry points all end at the form or the one window.
enum SetupEntry: Equatable {
    case form, window, welcome, refresh

    static func route(_ plan: SetupPlan) -> Self {
        switch plan {
        case .addForm: return .form
        case .waitForHost, .repair: return .window       // the service is item 1; the window acts at once
        case .newerInstalled, .waitForDisconnect: return .welcome
        case .nothingToDo: return .refresh
        }
    }
}

/// Fetching the host's document while the window is visible: one request in flight, every
/// `interval` ticks, doubling (to a cap) after a failed or slow fetch and back to the base on success.
struct SetupPoller: Equatable {
    static let base = 2
    static let cap = 16
    private(set) var inFlight = false
    private(set) var interval = SetupPoller.base
    private var sinceLast = SetupPoller.base   // the first tick after opening fetches

    /// One tick of a one-second timer; true when a fetch should start now.
    mutating func tick(visible: Bool) -> Bool {
        guard visible else { sinceLast = interval; return false }   // reopening fetches at once
        guard !inFlight else { return false }
        sinceLast += 1
        guard sinceLast >= interval else { return false }
        sinceLast = 0
        inFlight = true
        return true
    }

    mutating func finished(ok: Bool) {
        inFlight = false
        interval = ok ? Self.base : min(interval * 2, Self.cap)
    }
}

enum SetupOutcome: Equatable {
    case done
    case waitingForApproval
    /// The host has no saved key for this profile (its id); ask for it, then run the update again.
    case needsKey(String?)
    case failure(MenuCommandFailure)

    // Approval is a state, not an error: a request that ends while macOS is still waiting for the
    // user must not become "took too long". The host's typed code says which: `approval_required`
    // is approval and `psk_unavailable` is the key, so no exit status is guessed at.
    static func resolve(_ result: Result<Void, HostError>, sawApproval: Bool) -> Self {
        switch result {
        case .success: return .done
        case .failure(let error) where error.code == .approvalRequired: return .waitingForApproval
        case .failure(let error) where error.code == .pskUnavailable: return .needsKey(error.profileId)
        case .failure(let error) where error.code == .timeout && sawApproval: return .waitingForApproval
        case .failure(let error): return .failure(MenuCommandFailure(error))
        }
    }
}

enum SetupProgress {
    // Approval is reported by the host's `waiting` progress line (OFTCSetupRepair).
    static let working = "Setting up OFTC…"
    static let waiting = "Waiting for approval in System Settings. Turn on OFTC under Network Extensions (click ⓘ next to OFTC if you only see a list); setup then finishes on its own."
    static let stillWaiting = "Still waiting for approval in System Settings. Once OFTC is on, setup continues by itself."
    static let serviceWaiting = "Waiting for you: turn on OFTC in Login Items & Extensions. This window continues by itself once it is on."
}

// The one guided setup window, from the host's document and the service's state alone
// (docs/ui-edge.md 4.5): a checklist of what is left (background service, network extension,
// VPN configurations n of m), what macOS will ask and in what order, and one button.
struct ComponentUpdatePresentation: Equatable {
    var title = "Finish setting up OFTC"
    /// The paragraph under the title: how many approvals to expect, and what each looks like.
    var intro = ""
    /// Nothing is left (a run just succeeded, or it was already so): the window shows only the result and a Done button.
    var finished = false
    /// Something is in progress, so the window shows a spinner and its button is disabled.
    var busy = false
    /// The checklist, one line per item, each starting with its mark (✓ done, … working, → waiting for you, ○ to do, ✗ blocked).
    var items: [String] = []
    /// How many macOS approvals are still to come.
    var approvals = 0
    var component: String
    var builds: String
    var login: [String]
    var status: String
    var button: String
    var canRun: Bool
    var showSettings: Bool
    /// The System Settings pane that holds the pending approval.
    var pane: HostSettingsPane

    /// `service`: the host's reachability (its LaunchAgent may still need approval, or not be running).
    /// `failure`: why the last run stopped (kept until the next click), shown in the window itself.
    init(status document: HostStatus?, phase: OFTCSetupRepair.Phase, anyActive: Bool, succeeded: Bool = false,
         service: ServiceState = .ready, failure: String? = nil) {
        let state = document.map { VPNComponentState($0.component.state) } ?? .unavailable
        let profiles = document?.profiles ?? []
        let missing = profiles.filter { $0.state == .setup }.count
        let serviceReady = service == .ready
        let loginPending = document.map { [$0.login.menuItem, $0.login.agent, $0.login.hostAgent].contains(.requiresApproval) } ?? false
        // The optional "OFTC at login" item never blocks the end; it is a line of its own.
        let optionalLogin = serviceReady && loginPending
            ? "Optional: allow OFTC at login in System Settings → Login Items & Extensions." : ""
        // Never "ready" with no VPN: with none, the next thing is the Add a VPN form.
        let allDone = serviceReady && state == .ready && missing == 0 && !profiles.isEmpty && document != nil
        if (succeeded && !profiles.isEmpty) || allDone {
            let build = document?.component.expectedBuild.map { "build \($0)" } ?? "the bundled build"
            finished = true
            title = "Your VPN is ready"
            intro = succeeded
                ? "The OFTC VPN component is now \(build). Your saved VPNs and PSKs were kept, and no sign-in was started. Choose Connect in OFTC when you want to use a VPN."
                : "The OFTC VPN component is \(build) and your saved VPNs are added to macOS. Choose Connect in OFTC when you want to use a VPN."
            if !optionalLogin.isEmpty { intro += "\n" + optionalLogin }
            component = ""; builds = ""; login = []; status = ""
            button = "Done"; canRun = false; showSettings = loginPending; pane = .loginItems
            return
        }
        builds = Self.builds(document?.component)
        login = Self.loginLines(document?.login)
        let running = phase == .working || phase == .waiting
        let waiting = phase == .waiting || phase == .stillWaiting
        // A profile in the host's `setup` state has no VPN entry (docs/ui-edge.md 4.5): the case
        // after an uninstall and reinstall, where the component is ready and only the entries are gone.
        let entriesMissing = missing > 0
        let blocked = anyActive && (state == .updateRequired || entriesMissing)
        let serviceApproval = service == .needsApproval
        busy = running || service == .starting || service == .updating
        showSettings = waiting || state == .approval || loginPending || serviceApproval
        pane = serviceApproval || (loginPending && !(waiting || state == .approval)) ? .loginItems : .extensions
        let needsForm = serviceReady && profiles.isEmpty

        // The checklist.
        let serviceLine: String
        switch service {
        case .ready: serviceLine = "✓  Background service: allowed and running"
        case .needsApproval: serviceLine = "→  Background service: turn on OFTC in Login Items & Extensions (System Settings opens for you)"
        case .starting, .updating: serviceLine = "…  Background service: starting"
        case .notRunning: serviceLine = "○  Background service: not running yet; it starts when you continue"
        case .unsupported: serviceLine = "✗  Background service: this OFTC is too old for it. Update OFTC."
        }
        let extensionLine: String
        switch state {
        case .ready: extensionLine = "✓  Network extension: \(document?.component.installedBuild.map { "build \($0)" } ?? "installed")"
        case .approval: extensionLine = "→  Network extension: turn on OFTC in System Settings → Network Extensions"
        case .newer: extensionLine = "✗  Network extension: a newer one is installed. Use the newer OFTC."
        case .checking: extensionLine = "…  Network extension: checking"
        case .updateRequired where running: extensionLine = "…  Network extension: updating"
        case .missing where running: extensionLine = "…  Network extension: installing"
        case .updateRequired: extensionLine = "○  Network extension: update from \(document?.component.installedBuild.map { "build \($0)" } ?? "the old build") to \(document?.component.expectedBuild.map { "build \($0)" } ?? "this app's build")"
        case .missing: extensionLine = "○  Network extension: not installed"
        case .unavailable: extensionLine = serviceReady ? "○  Network extension: state unknown; continuing checks it" : "○  Network extension: checked once the service runs"
        }
        let vpnLine: String
        if profiles.isEmpty { vpnLine = "○  VPN configurations: none yet; you add one next" }
        else if missing == 0 { vpnLine = "✓  VPN configurations: \(profiles.count) of \(profiles.count) added" }
        else if running && state == .ready { vpnLine = "…  VPN configurations: adding \(missing)" }
        else { vpnLine = "○  VPN configurations: \(profiles.count - missing) of \(profiles.count) added" }
        items = [serviceLine, extensionLine, vpnLine]
        component = items.joined(separator: "\n")

        // The approvals macOS will ask for, in order; nothing else is asked. The VPN-configurations
        // dialog comes whenever a VPN entry is yet to be saved: entries missing, or no VPN added yet.
        var asks: [String] = []
        if !serviceReady { asks.append("Allow OFTC's background service (System Settings → Login Items & Extensions)") }
        if state != .ready && state != .newer { asks.append("Allow the network extension (System Settings → Network Extensions; your password may be needed)") }
        if entriesMissing || profiles.isEmpty { asks.append("Allow VPN configurations (one macOS dialog: Allow\(profiles.isEmpty ? ", after you add your VPN here" : ""))") }
        approvals = asks.count
        let list = asks.enumerated().map { "\($0.offset + 1). \($0.element)" }.joined(separator: "\n")
        intro = asks.isEmpty
            ? "Nothing is left for macOS to ask. Your saved VPN settings and PSK are kept."
            : "Your saved VPN settings and PSK are kept, and no sign-in is started. macOS will ask you \(asks.count == 1 ? "once" : "\(asks.count) times"), in this order:\n\(list)"
        if !optionalLogin.isEmpty { intro += "\n" + optionalLogin }

        switch phase {
        case .working: status = SetupProgress.working
        case .waiting: status = SetupProgress.waiting
        case .stillWaiting: status = SetupProgress.stillWaiting
        case .idle:
            if let failure { status = failure }
            else if blocked { status = "Disconnect OFTC before finishing setup." }
            else if serviceApproval { status = SetupProgress.serviceWaiting }
            else if service == .starting || service == .updating { status = SetupProgress.working }
            else if state == .ready && entriesMissing {
                status = "Your saved VPNs will be added back to macOS. No sign-in is started."
            } else { status = "" }
        }
        switch phase {
        case .working: button = "Working…"
        case .waiting: button = "Waiting for you…"
        default:
            button = needsForm ? "Add a VPN" : serviceReady && state == .updateRequired && !entriesMissing ? "Update VPN component" : "Finish setup"
        }
        let serviceRunnable = service == .needsApproval || service == .notRunning
        canRun = (document != nil || serviceRunnable) && (phase == .idle || phase == .stillWaiting) && !blocked
            && state != .newer && state != .checking && (serviceReady || serviceRunnable)
            && (serviceRunnable || needsForm || state != .ready || entriesMissing)
    }

    static func builds(_ component: HostComponent?) -> String {
        let installed = component?.installedBuild.map { "build \($0)" } ?? "not installed"
        let bundled = component?.expectedBuild.map { "build \($0)" } ?? "unknown"
        return "Installed: \(installed). This app: \(bundled)."
    }

    static func loginLines(_ login: HostLogin?) -> [String] {
        guard let login else { return [] }
        return [("OFTC at login", login.menuItem), ("Login agent", login.agent), ("VPN service", login.hostAgent)]
            .map { "\($0.0): \(stateText($0.1))" }
    }

    static func stateText(_ state: HostLoginState) -> String {
        switch state {
        case .enabled: return "on"
        case .disabled: return "off"
        case .requiresApproval: return "needs approval in Login Items & Extensions"
        case .notFound: return "not set up"
        }
    }
}
