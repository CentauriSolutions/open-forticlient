import Foundation

// What "Set up…" (and "Update VPN component") does for a profile that is already
// on disk. Pure, so the decision table is pinned by check-setup-plan.swift.
// Issue 88: the form is only for a VPN that does not exist yet; everything else
// finishes with `oftc setup`, which is idempotent and asks for nothing.
enum SetupPlan: Equatable {
    case addForm                 // no profile yet: the Add a VPN form
    case askPSK([String])        // these profile ids have no saved PSK
    case repair                  // activate the extension, install the VPN entries
    case waitForDisconnect       // the component must be replaced, but a tunnel is live
    case newerInstalled          // the installed component is newer than this app
    case nothingToDo
    case waitForHost             // the host is not answering: its document says nothing yet

    // While the host is down its document is empty, so "no profiles" would be a guess: an
    // upgrade's first launch has profiles on disk and a host still starting or awaiting approval.
    // Never choose from it; wait for the host (docs/ui-edge.md 7).
    static func decide(hostReady: Bool = true, profileCount: Int, missingPSK: [String],
                       component: VPNComponentState, entriesMissing: Bool, anyActive: Bool) -> Self {
        if !hostReady { return .waitForHost }
        if component == .newer { return .newerInstalled }
        if profileCount == 0 { return .addForm }
        if !missingPSK.isEmpty { return .askPSK(missingPSK) }
        if component == .updateRequired && anyActive { return .waitForDisconnect }
        if component == .ready && !entriesMissing { return .nothingToDo }
        return .repair
    }

    // Repair once on launch so the user's only job is approving in System Settings.
    // Never for a login-item launch (nothing asked for it), and never again once
    // tried in this process, so a failure cannot loop.
    // The cheap guards come first so the caller can skip computing a plan (which
    // reads the Keychain) on the many checks that cannot lead to a repair.
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
    case failure(MenuCommandFailure)

    // Approval is a state, not an error: a command that ends while macOS is still
    // waiting for the user must not become "took too long".
    // Exit 4 is "needs the user" for approval and for an unavailable PSK alike (the same exit
    // table as the wire's); it is approval only when the component says so, or approval was seen
    // while waiting. Otherwise it is the missing key, which waiting would never fix.
    static func resolve(_ result: MenuCommandResult, sawApproval: Bool,
                        component: VPNComponentState = .unavailable) -> Self {
        switch result {
        case .success: return .done
        case .failure(.approval) where sawApproval || component.needsSetup: return .waitingForApproval
        case .failure(.approval): return .failure(.credentials)
        case .failure(.timeout) where sawApproval: return .waitingForApproval
        case .failure(let failure): return .failure(failure)
        }
    }
}

enum SetupProgress {
    // `oftc setup` blocks in activation until the user approves. Properties
    // report approval directly; if they do not, an extension still missing or
    // old after a few seconds of waiting means the same thing.
    static func isWaitingForApproval(component: VPNComponentState, elapsed: TimeInterval) -> Bool {
        switch component {
        case .approval: return true
        case .missing, .updateRequired: return elapsed >= 8
        default: return false
        }
    }

    static let working = "Setting up OFTC…"
    static let waiting = "Waiting for approval in System Settings. Turn on OFTC under Network Extensions (click ⓘ next to OFTC if you only see a list); setup then finishes on its own."
    static let stillWaiting = "Still waiting for approval in System Settings. Once OFTC is on, choose Set up… again."
}
