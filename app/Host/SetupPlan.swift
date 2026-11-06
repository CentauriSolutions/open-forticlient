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
    static let stillWaiting = "Still waiting for approval in System Settings. Once OFTC is on, choose Set up… again."
}

// What the component-update window shows, from the host's document alone (docs/ui-edge.md 4.5):
// the system extension and the three login items, and whether approval is what the user must do.
struct ComponentUpdatePresentation: Equatable {
    var component: String
    var builds: String
    var login: [String]
    var status: String
    var button: String
    var canRun: Bool
    var showSettings: Bool
    /// The System Settings pane that holds the pending approval.
    var pane: HostSettingsPane

    init(status document: HostStatus?, phase: OFTCSetupRepair.Phase, anyActive: Bool) {
        let state = document.map { VPNComponentState($0.component.state) } ?? .unavailable
        component = state.detail
        builds = Self.builds(document?.component)
        login = Self.loginLines(document?.login)
        let waiting = phase == .waiting || phase == .stillWaiting
        // A profile in the host's `setup` state has no VPN entry (docs/ui-edge.md 4.5): the case
        // after an uninstall and reinstall, where the component is ready and only the entries are gone.
        let entriesMissing = document?.profiles.contains { $0.state == .setup } ?? false
        let blocked = anyActive && (state == .updateRequired || entriesMissing)
        let loginPending = document.map { [$0.login.menuItem, $0.login.agent, $0.login.hostAgent].contains(.requiresApproval) } ?? false
        showSettings = waiting || state == .approval || loginPending
        pane = loginPending && !(waiting || state == .approval) ? .loginItems : .extensions
        switch phase {
        case .working: status = SetupProgress.working
        case .waiting: status = SetupProgress.waiting
        case .stillWaiting: status = SetupProgress.stillWaiting
        case .idle:
            if blocked { status = "Disconnect OFTC before finishing setup." }
            else if state == .ready && entriesMissing {
                status = "Your saved VPNs will be added back to macOS. No sign-in is started."
            } else { status = "" }
        }
        button = state == .updateRequired ? "Update VPN component" : "Finish setup"
        canRun = document != nil && (phase == .idle || phase == .stillWaiting) && !blocked
            && state != .newer && state != .checking && (state != .ready || entriesMissing)
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
