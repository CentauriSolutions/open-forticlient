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

        // The component window: what it offers follows the host's document alone.
        func document(_ state: HostComponentState, installed: String? = "35",
                      login: HostLoginState = .enabled, entryMissing: Bool = false, profiles count: Int = 1) -> HostStatus {
            let profile = HostProfile(id: "lab", name: "Lab", gateway: "vpn.example.com", samlPort: 9443,
                                      transport: "udp", autoStart: false,
                                      state: entryMissing ? .setup : .disconnected)
            return HostStatus(schema: 1, generated: "", seq: 1,
                       host: HostInfo(version: "1.0.14", build: "36", providerBuild: "36"),
                       component: HostComponent(state: state, installedBuild: installed, expectedBuild: "36"),
                       login: HostLogin(menuItem: login, agent: .enabled, hostAgent: .enabled), profiles: count == 0 ? [] : [profile])
        }
        typealias W = ComponentUpdatePresentation
        let idle = W(status: document(.updateRequired), phase: .idle, anyActive: false)
        precondition(idle.canRun && idle.button == "Update VPN component" && !idle.showSettings)
        precondition(idle.builds == "Installed: build 35. This app: build 36.")
        precondition(!W(status: document(.updateRequired), phase: .idle, anyActive: true).canRun, "never under a live tunnel")
        precondition(!W(status: document(.updateRequired), phase: .working, anyActive: false).canRun, "one run at a time")
        precondition(!W(status: document(.newer), phase: .idle, anyActive: false).canRun, "never replace a newer component")
        let waiting = W(status: document(.updateRequired), phase: .waiting, anyActive: false)
        precondition(waiting.showSettings && waiting.pane == .extensions && waiting.status == SetupProgress.waiting)
        precondition(W(status: document(.updateRequired), phase: .stillWaiting, anyActive: false).canRun, "run again after a wait")
        // Component ready, every VPN entry gone (uninstall, then reinstall): the plan is a repair
        // and the window must let it run, or Set up… and Close would loop for ever.
        let gone = W(status: document(.ready, installed: "36", entryMissing: true), phase: .idle, anyActive: false)
        precondition(plan(1, .ready) == .repair && gone.canRun && gone.button == "Finish setup")
        precondition(gone.status == "Your saved VPNs will be added back to macOS. No sign-in is started.")
        precondition(!W(status: document(.ready, entryMissing: true), phase: .idle, anyActive: true).canRun, "not beside a live tunnel")
        precondition(!W(status: document(.ready), phase: .idle, anyActive: false).canRun, "ready with nothing missing")
        precondition(!W(status: document(.newer, entryMissing: true), phase: .idle, anyActive: false).canRun)
        precondition(!W(status: document(.checking, entryMissing: true), phase: .idle, anyActive: false).canRun)
        let reinstall = WelcomePresentation(upgrade: false, configured: false, active: false, component: .ready, profilesExist: true)
        precondition(reinstall.action == .setup && reinstall.button == "Finish setup")
        precondition(WelcomePresentation(upgrade: false, configured: false, active: false, component: .ready).button == "Set up OFTC")
        // A run that succeeded: a result and one Done button, never the form with its button re-enabled.
        let done = W(status: document(.ready, installed: "36"), phase: .idle, anyActive: false, succeeded: true)
        precondition(done.finished && done.title == "Your VPN is ready" && done.button == "Done" && !done.canRun && !done.showSettings)
        precondition(done.intro == "The OFTC VPN component is now build 36. Your saved VPNs and PSKs were kept, and no sign-in was started. Choose Connect in OFTC when you want to use a VPN.")
        precondition(done.component.isEmpty && done.builds.isEmpty && done.login.isEmpty && done.status.isEmpty)
        precondition(!idle.finished && idle.title == "Finish setting up OFTC" && idle.intro.contains("saved VPN settings and PSK are kept"))
        // Closing the window: Welcome only when something is left to set up, judged from fresh status.
        typealias A = WelcomeAfterComponentWindow
        precondition(!A.shouldShow(fromSetup: true, succeeded: true, configured: false, component: .missing), "never after a success")
        precondition(!A.shouldShow(fromSetup: true, succeeded: false, configured: true, component: .ready), "a ready VPN has nothing to set up")
        precondition(A.shouldShow(fromSetup: true, succeeded: false, configured: false, component: .approval))
        precondition(!A.shouldShow(fromSetup: false, succeeded: false, configured: false, component: .missing), "the options menu just closes")

        // The walkthrough: every window state from "double-click install" to "ready", one row each.
        // Columns: service, component, a VPN entry missing, phase, then what the window shows (the
        // button, whether it can be pressed, whether something is in progress, the approvals still
        // to come, and the first character of each checklist line).
        struct Row { let name: String; let service: ServiceState; let component: HostComponentState
                     var entryMissing = true; var phase: OFTCSetupRepair.Phase = .idle; var active = false
                     let button: String; let canRun: Bool; let busy: Bool; let approvals: Int; let marks: String }
        let walk: [Row] = [
            .init(name: "reinstall: service needs approval, nothing else done", service: .needsApproval, component: .missing,
                  button: "Finish setup", canRun: true, busy: false, approvals: 3, marks: "→○○"),
            .init(name: "service not running yet (starts on click)", service: .notRunning, component: .missing,
                  button: "Finish setup", canRun: true, busy: false, approvals: 3, marks: "○○○"),
            .init(name: "service starting: working, nothing to press", service: .starting, component: .missing,
                  button: "Finish setup", canRun: false, busy: true, approvals: 3, marks: "…○○"),
            .init(name: "service ready, extension missing", service: .ready, component: .missing,
                  button: "Finish setup", canRun: true, busy: false, approvals: 2, marks: "✓○○"),
            .init(name: "click: working at once", service: .ready, component: .missing, phase: .working,
                  button: "Working…", canRun: false, busy: true, approvals: 2, marks: "✓…○"),
            .init(name: "macOS asks for the extension: waiting for you", service: .ready, component: .approval, phase: .waiting,
                  button: "Waiting for you…", canRun: false, busy: true, approvals: 2, marks: "✓→○"),
            .init(name: "request ended while waiting: runs again by itself", service: .ready, component: .approval, phase: .stillWaiting,
                  button: "Finish setup", canRun: true, busy: false, approvals: 2, marks: "✓→○"),
            .init(name: "extension approved, VPN entries being added", service: .ready, component: .ready, phase: .working,
                  button: "Working…", canRun: false, busy: true, approvals: 1, marks: "✓✓…"),
            .init(name: "update over an older install: one approval", service: .ready, component: .updateRequired, entryMissing: false,
                  button: "Update VPN component", canRun: true, busy: false, approvals: 1, marks: "✓○✓"),
            .init(name: "tunnel live during an update: blocked", service: .ready, component: .updateRequired, entryMissing: false, active: true,
                  button: "Update VPN component", canRun: false, busy: false, approvals: 1, marks: "✓○✓"),
            .init(name: "newer extension installed: blocked", service: .ready, component: .newer, entryMissing: false,
                  button: "Finish setup", canRun: false, busy: false, approvals: 0, marks: "✓✗✓"),
            .init(name: "old service too old: blocked", service: .unsupported, component: .missing,
                  button: "Finish setup", canRun: false, busy: false, approvals: 3, marks: "✗○○"),
        ]
        for row in walk {
            let got = W(status: document(row.component, installed: row.component == .missing ? nil : "35", entryMissing: row.entryMissing),
                        phase: row.phase, anyActive: row.active, service: row.service)
            let marks = String(got.items.compactMap(\.first))
            precondition(got.button == row.button && got.canRun == row.canRun && got.busy == row.busy
                         && got.approvals == row.approvals && marks == row.marks && !got.finished,
                         "\(row.name): \(got.button) \(got.canRun) \(got.busy) \(got.approvals) \(marks)")
        }
        // The end: everything done is the success state on its own, with one Done.
        let everything = W(status: document(.ready, installed: "36"), phase: .idle, anyActive: false)
        precondition(everything.finished && everything.button == "Done" && !everything.canRun && everything.approvals == 0)
        // Said in advance, in order, with how many.
        let fresh = W(status: document(.missing, installed: nil, entryMissing: true), phase: .idle, anyActive: false, service: .needsApproval)
        precondition(fresh.intro.contains("macOS will ask you 3 times, in this order:\n1. Allow OFTC's background service")
                     && fresh.intro.contains("\n2. Allow the network extension") && fresh.intro.contains("\n3. Allow VPN configurations"))
        precondition(fresh.showSettings && fresh.pane == .loginItems && fresh.status == SetupProgress.serviceWaiting)
        // More walkthrough rows: host down, unknown states, no VPN yet.
        let down = W(status: nil, phase: .idle, anyActive: false, service: .notRunning)
        precondition(down.canRun && down.items[0].hasPrefix("○") && down.items[1] == "○  Network extension: checked once the service runs"
                     && down.approvals == 3 && !down.finished, "host down: the button starts the service")
        for state in [HostComponentState.checking, .unavailable] {
            let unknown = W(status: document(state, entryMissing: false), phase: .idle, anyActive: false)
            precondition(!unknown.finished && unknown.canRun == (state != .checking), "\(state)")
        }
        let updating = W(status: document(.ready, entryMissing: false), phase: .idle, anyActive: false, service: .updating)
        precondition(updating.busy && !updating.canRun && !updating.finished && updating.items[0].hasPrefix("…"))
        // No VPN yet: never the ready state, never a component update; the form is next.
        let none = W(status: document(.ready, installed: "36", profiles: 0), phase: .idle, anyActive: false)
        precondition(!none.finished && none.button == "Add a VPN" && none.canRun && none.approvals == 1 && none.items[2].hasPrefix("○"))
        precondition(!W(status: document(.ready, installed: "36", profiles: 0), phase: .idle, anyActive: false, succeeded: true).finished,
                     "a run that succeeded with no VPN is not 'VPN ready'")
        let freshMac = W(status: document(.missing, installed: nil, profiles: 0), phase: .idle, anyActive: false, service: .needsApproval)
        precondition(freshMac.approvals == 3 && freshMac.intro.contains("3. Allow VPN configurations (one macOS dialog: Allow, after you add your VPN here)"))
        // The optional login item never blocks the end.
        let optional = W(status: document(.ready, installed: "36", login: .requiresApproval), phase: .idle, anyActive: false)
        precondition(optional.finished && optional.button == "Done" && optional.showSettings && optional.pane == .loginItems
                     && optional.intro.contains("Optional: allow OFTC at login") && optional.approvals == 0)
        // A failure stays in the window until the next click, with the next action.
        let failed = W(status: document(.missing, installed: nil), phase: .idle, anyActive: false,
                       failure: "Could not set up: timed out. Choose Finish setup to try again.")
        precondition(failed.status.hasPrefix("Could not set up") && failed.canRun && !failed.busy)
        precondition(W(status: document(.missing, installed: nil), phase: .working, anyActive: false, failure: "old").status == SetupProgress.working,
                     "a new run replaces the failure")

        // Every entry point ends at the form or the one window.
        typealias E = SetupEntry
        precondition(E.route(.addForm) == .form && E.route(.waitForHost) == .window && E.route(.repair) == .window
                     && E.route(.newerInstalled) == .welcome && E.route(.waitForDisconnect) == .welcome && E.route(.nothingToDo) == .refresh)
        // The window carries on by itself, but only after the button, and never in a loop.
        typealias K = SetupContinuation
        precondition(K.step(service: .needsApproval, plan: .waitForHost) == .startService && K.step(service: .notRunning, plan: .waitForHost) == .startService
                     && K.step(service: .ready, plan: .repair) == .runUpdate && K.step(service: .ready, plan: .addForm) == .openForm
                     && K.step(service: .starting, plan: .repair) == .wait && K.step(service: .unsupported, plan: .repair) == .wait
                     && K.step(service: .ready, plan: .nothingToDo) == .wait)
        func next(intent: Bool = true, running: Bool = false, service: ServiceState = .ready, plan: SetupPlan = .repair,
                  phase: OFTCSetupRepair.Phase = .idle, component: C = .missing, waitedAt: C? = nil) -> K.Step? {
            K.automatic(intent: intent, running: running, service: service, plan: plan, phase: phase, component: component, waitedAt: waitedAt)
        }
        precondition(next() == .runUpdate, "the service came up after the button: run the update")
        precondition(next(plan: .addForm) == .openForm, "a new user reaches the form once the service is on")
        precondition(next(intent: false) == nil && next(intent: false, plan: .addForm) == nil, "no click, no step")
        precondition(next(running: true) == nil && next(service: .needsApproval, plan: .waitForHost) == nil && next(plan: .nothingToDo) == nil)
        precondition(next(phase: .stillWaiting, component: .approval, waitedAt: .approval) == nil, "still not approved: do not loop")
        precondition(next(phase: .stillWaiting, component: .ready, waitedAt: .approval) == .runUpdate, "approved in System Settings: continue by itself")
        // Closing for the form opens neither Welcome nor anything else.
        precondition(!WelcomeAfterComponentWindow.shouldShow(fromSetup: true, succeeded: false, configured: false, component: .approval, handedOff: true))
        // Fetching the document while the window is visible: at once on opening, one in flight,
        // backing off after a failure, never while hidden.
        var poller = SetupPoller()
        precondition(poller.tick(visible: true) && poller.inFlight, "opening fetches at once")
        precondition(!poller.tick(visible: true) && !poller.tick(visible: true) && !poller.tick(visible: true), "one in flight at a time")
        poller.finished(ok: false)
        precondition(poller.interval == 4 && !poller.tick(visible: true) && !poller.tick(visible: true) && !poller.tick(visible: true)
                     && poller.tick(visible: true), "backs off after a failure")
        poller.finished(ok: true)
        precondition(poller.interval == SetupPoller.base)
        for _ in 0..<8 { _ = poller.tick(visible: true); poller.finished(ok: false) }
        precondition(poller.interval == SetupPoller.cap, "the back-off is capped")
        precondition(!poller.tick(visible: false) && poller.tick(visible: true), "hidden never fetches; reopening does at once")
        let login = W(status: document(.ready, login: .requiresApproval), phase: .idle, anyActive: false)
        precondition(login.showSettings && login.pane == .loginItems && !login.canRun && login.finished)
        precondition(W(status: document(.missing, login: .requiresApproval), phase: .idle, anyActive: false).login[0]
                     == "OFTC at login: needs approval in Login Items & Extensions")
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
