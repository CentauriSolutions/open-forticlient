import Foundation

// Pins the Issue 88 decision table: what "Set up…" / "Update VPN component"
// does for a profile that already exists. Pure logic; no extension, Keychain or
// VPN entry is touched.
@main enum SetupPlanCheck {
    static func main() {
        typealias C = VPNComponentState
        func plan(_ profiles: Int, psk missing: [String] = [], _ component: C,
                  entriesMissing: Bool = true, active: Bool = false) -> SetupPlan {
            SetupPlan.decide(profileCount: profiles, missingPSK: missing, component: component,
                             entriesMissing: entriesMissing, anyActive: active)
        }
        let rows: [(String, SetupPlan, SetupPlan)] = [
            ("no profile: the Add a VPN form", plan(0, .missing), .addForm),
            ("profile, extension missing, no VPN entry: repair, no form", plan(1, .missing), .repair),
            ("profile, extension approval pending: repair (waits for approval)", plan(1, .approval), .repair),
            ("profile, extension older, idle: Update VPN component repairs", plan(2, .updateRequired, entriesMissing: false), .repair),
            ("profile, extension older, tunnel live: wait for disconnect", plan(1, .updateRequired, entriesMissing: false, active: true), .waitForDisconnect),
            ("extension ready, VPN entry missing: repair", plan(1, .ready), .repair),
            ("extension ready, VPN entry present: nothing to do", plan(1, .ready, entriesMissing: false), .nothingToDo),
            ("profile without a PSK: ask for it, only for that profile", plan(2, psk: ["b"], .missing), .askPSK(["b"])),
            ("a missing PSK is asked before waiting on a live tunnel", plan(1, psk: ["a"], .updateRequired, active: true), .askPSK(["a"])),
            ("newer component: use the newer installer, even with no profile", plan(0, .newer), .newerInstalled),
            ("component state unknown still repairs (activation reports the truth)", plan(1, .unavailable), .repair),
        ]
        for (name, got, want) in rows { precondition(got == want, "\(name): \(got)") }

        // Auto repair at launch: only a plain repair, a component that needs it, a
        // user launch, and once.
        func auto(_ p: SetupPlan, _ c: C, automatic: Bool = false, tried: Bool = false) -> Bool {
            SetupPlan.shouldAutoRepair(p, component: c, automaticLaunch: automatic, alreadyTried: tried)
        }
        precondition(auto(.repair, .missing))
        precondition(auto(.repair, .updateRequired))
        precondition(auto(.repair, .approval))
        precondition(!auto(.repair, .ready), "a ready component needs no automatic activation")
        precondition(!auto(.repair, .unavailable), "unknown state must not trigger activation")
        precondition(!auto(.repair, .missing, automatic: true), "login-item launches never open System Settings")
        precondition(!auto(.repair, .missing, tried: true), "a failed repair must not loop")
        precondition(!auto(.askPSK(["a"]), .missing), "never guess a PSK")
        precondition(!auto(.waitForDisconnect, .updateRequired), "never replace the provider under a tunnel")

        // Approval is a state, never the "took too long" error.
        typealias O = SetupOutcome
        precondition(O.resolve(.success, sawApproval: false) == .done)
        precondition(O.resolve(.failure(.timeout), sawApproval: true) == .waitingForApproval)
        precondition(O.resolve(.failure(.approval), sawApproval: false) == .waitingForApproval)
        precondition(O.resolve(.failure(.timeout), sawApproval: false) == .failure(.timeout), "a real hang is still a failure")
        precondition(O.resolve(.failure(.failed(3)), sawApproval: true) == .failure(.failed(3)))

        // The waiting state: reported approval at once; a still-missing or old
        // extension only after a few seconds; never once ready or unknown.
        typealias P = SetupProgress
        precondition(P.isWaitingForApproval(component: .approval, elapsed: 0))
        precondition(!P.isWaitingForApproval(component: .missing, elapsed: 2))
        precondition(P.isWaitingForApproval(component: .missing, elapsed: 9))
        precondition(P.isWaitingForApproval(component: .updateRequired, elapsed: 9))
        precondition(!P.isWaitingForApproval(component: .ready, elapsed: 60), "ready means installing the VPN entry")
        precondition(!P.isWaitingForApproval(component: .unavailable, elapsed: 60))
        print("Setup plan, auto-repair, approval outcome and progress decisions passed (pure logic only).")
    }
}
