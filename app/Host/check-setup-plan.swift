import Foundation

// Pins the Issue 88 decision table: what "Set up…" / "Update VPN component"
// does for a profile that already exists, and what the component window shows. Pure logic; no
// extension, Keychain or VPN entry is touched.
@main enum SetupPlanCheck {
    static func main() {
        typealias C = VPNComponentState
        func plan(_ profiles: Int, _ component: C,
                  entriesMissing: Bool = true, active: Bool = false) -> SetupPlan {
            SetupPlan.decide(profileCount: profiles, component: component,
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
            ("newer component: use the newer installer, even with no profile", plan(0, .newer), .newerInstalled),
            ("component state unknown still repairs (activation reports the truth)", plan(1, .unavailable), .repair),
        ]
        // Host down: its document is empty, which is not "no profiles" (profiles on disk, host
        // not yet started or awaiting approval at an upgrade's first launch).
        precondition(SetupPlan.decide(hostReady: false, profileCount: 0, component: .checking,
                                      entriesMissing: false, anyActive: false) == .waitForHost,
                     "host down must not show the add form")
        for (name, got, want) in rows { precondition(got == want, "\(name): \(got)") }

        // Auto repair at launch: only a plain repair, a component that needs it, a
        // user launch, and once.
        func auto(_ p: SetupPlan, _ c: C, automatic: Bool = false, tried: Bool = false) -> Bool {
            SetupPlan.shouldAutoRepair(p, component: c, automaticLaunch: automatic, alreadyTried: tried)
        }
        precondition(auto(.repair, .missing))
        precondition(auto(.repair, .updateRequired))
        precondition(auto(.repair, .approval))
        precondition(!SetupPlan.mayAutoRepair(component: .ready, automaticLaunch: false, alreadyTried: false),
                     "the cheap guards must refuse before any plan is computed")
        precondition(!auto(.repair, .ready), "a ready component needs no automatic activation")
        precondition(!auto(.repair, .unavailable), "unknown state must not trigger activation")
        precondition(!auto(.repair, .missing, automatic: true), "login-item launches never open System Settings")
        precondition(!auto(.repair, .missing, tried: true), "a failed repair must not loop")
        precondition(!auto(.waitForDisconnect, .updateRequired), "never replace the provider under a tunnel")

        // Approval is a state, never the "took too long" error; the host's typed code says which
        // of approval and the missing key a request stopped at.
        typealias O = SetupOutcome
        func fail(_ code: HostErrorCode, id: String? = nil) -> Result<Void, HostError> {
            .failure(HostError(code: code, detail: "", exit: 1, profileId: id))
        }
        precondition(O.resolve(.success(()), sawApproval: false) == .done)
        precondition(O.resolve(fail(.approvalRequired), sawApproval: false) == .waitingForApproval)
        precondition(O.resolve(fail(.timeout), sawApproval: true) == .waitingForApproval)
        precondition(O.resolve(fail(.pskUnavailable, id: "lab"), sawApproval: true) == .needsKey("lab"),
                     "the missing key is asked for, never mistaken for approval")
        precondition(O.resolve(fail(.timeout), sawApproval: false) == .failure(.timeout), "a real hang is still a failure")
        precondition(O.resolve(fail(.tunnelsActive), sawApproval: true) == .failure(.tunnelsActive))

        // The waiting state: reported approval at once; a still-missing or old
        // extension only after a few seconds; never once ready or unknown.
        typealias P = SetupProgress
        precondition(P.isWaitingForApproval(component: .approval, elapsed: 0))
        precondition(!P.isWaitingForApproval(component: .missing, elapsed: 2))
        precondition(P.isWaitingForApproval(component: .missing, elapsed: 9))
        precondition(P.isWaitingForApproval(component: .updateRequired, elapsed: 9))
        precondition(!P.isWaitingForApproval(component: .ready, elapsed: 60), "ready means installing the VPN entry")
        precondition(!P.isWaitingForApproval(component: .unavailable, elapsed: 60))

        // The component window: what it offers follows the host's document alone.
        func document(_ state: HostComponentState, installed: String? = "35",
                      login: HostLoginState = .enabled) -> HostStatus {
            HostStatus(schema: 1, generated: "", seq: 1,
                       host: HostInfo(version: "1.0.14", build: "36", providerBuild: "36"),
                       component: HostComponent(state: state, installedBuild: installed, expectedBuild: "36"),
                       login: HostLogin(menuItem: login, agent: .enabled, hostAgent: .enabled), profiles: [])
        }
        typealias W = ComponentUpdatePresentation
        let idle = W(status: document(.updateRequired), phase: .idle, anyActive: false)
        precondition(idle.canRun && idle.button == "Update VPN component" && !idle.showSettings)
        precondition(idle.builds == "Installed: build 35. This app: build 36.")
        precondition(!W(status: document(.updateRequired), phase: .idle, anyActive: true).canRun, "never under a live tunnel")
        precondition(!W(status: document(.updateRequired), phase: .working, anyActive: false).canRun, "one run at a time")
        let waiting = W(status: document(.updateRequired), phase: .waiting, anyActive: false)
        precondition(waiting.showSettings && waiting.pane == .extensions && waiting.status == SetupProgress.waiting)
        precondition(W(status: document(.updateRequired), phase: .stillWaiting, anyActive: false).canRun, "run again after a wait")
        let login = W(status: document(.ready, login: .requiresApproval), phase: .idle, anyActive: false)
        precondition(login.showSettings && login.pane == .loginItems && !login.canRun)
        precondition(login.login[0] == "OFTC at login: needs approval in Login Items & Extensions")
        precondition(W(status: document(.missing, installed: nil), phase: .idle, anyActive: false).builds
                     == "Installed: not installed. This app: build 36.")
        precondition(!W(status: nil, phase: .idle, anyActive: false).canRun && W(status: nil, phase: .idle, anyActive: false).login.isEmpty)
        precondition(AboutDetails.line(appVersion: "1.0.14", appBuild: "36", status: document(.ready))
                     == "App 1.0.14 (36) · Service 1.0.14 (36) · provider build 36 · installed extension build 35")
        precondition(AboutDetails.line(appVersion: "1.0.14", appBuild: "36", status: nil)
                     == "App 1.0.14 (36) · OFTC’s VPN service is not running")
        print("Setup plan, auto-repair, approval outcome, progress and component window decisions passed (pure logic only).")
    }
}
