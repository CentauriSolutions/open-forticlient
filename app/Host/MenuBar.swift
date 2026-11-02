import AppKit
import Carbon
import Darwin
import Foundation
import NetworkExtension
import ServiceManagement

enum TunnelMenuIcon {
    private static var cache: [Int: NSImage] = [:]

    static func image(connected: Bool, attention: Bool = false) -> NSImage {
        let key = (connected ? 1 : 0) + (attention ? 2 : 0)
        if let cached = cache[key] { return cached }
        let size = NSSize(width: 22, height: 20)
        let image = NSImage(size: size)
        // A concrete alpha mask avoids deferred drawing in the system menu
        // bar's rendering context. Supply both standard and Retina pixels.
        for scale in [1, 2] {
            guard let bitmap = NSBitmapImageRep(bitmapDataPlanes: nil,
                pixelsWide: 22 * scale, pixelsHigh: 20 * scale,
                bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true,
                isPlanar: false, colorSpaceName: .deviceRGB,
                bytesPerRow: 0, bitsPerPixel: 0),
                let context = NSGraphicsContext(bitmapImageRep: bitmap) else { continue }
            bitmap.size = size
            NSGraphicsContext.saveGraphicsState()
            NSGraphicsContext.current = context
            context.cgContext.clear(CGRect(x: 0, y: 0, width: 22 * scale, height: 20 * scale))
            context.cgContext.scaleBy(x: CGFloat(scale), y: CGFloat(scale))
            paint(connected: connected, attention: attention)
            NSGraphicsContext.restoreGraphicsState()
            image.addRepresentation(bitmap)
        }
        image.isTemplate = true
        image.accessibilityDescription = "OFTC tunnel"
        cache[key] = image
        return image
    }

    private static func paint(connected: Bool, attention: Bool) {
        let opacity: CGFloat = connected ? 1 : 0.65
        NSColor.black.withAlphaComponent(opacity * 0.62).setStroke()
        let outer = NSBezierPath()
        outer.move(to: NSPoint(x: 2.8, y: 3.5))
        outer.curve(to: NSPoint(x: 11, y: 17),
            controlPoint1: NSPoint(x: 6.8, y: 3.5), controlPoint2: NSPoint(x: 4.8, y: 17))
        outer.curve(to: NSPoint(x: 19.2, y: 3.5),
            controlPoint1: NSPoint(x: 17.2, y: 17), controlPoint2: NSPoint(x: 15.2, y: 3.5))
        outer.lineWidth = 1.15
        outer.lineCapStyle = .round
        outer.stroke()
        NSColor.black.withAlphaComponent(opacity * 0.76).setStroke()
        let inner = NSBezierPath()
        inner.move(to: NSPoint(x: 6.6, y: 3.5))
        inner.curve(to: NSPoint(x: 11, y: 11.8),
            controlPoint1: NSPoint(x: 8.4, y: 5.3), controlPoint2: NSPoint(x: 7.4, y: 11.8))
        inner.curve(to: NSPoint(x: 15.4, y: 3.5),
            controlPoint1: NSPoint(x: 14.6, y: 11.8), controlPoint2: NSPoint(x: 13.6, y: 5.3))
        inner.lineWidth = 0.85
        inner.lineCapStyle = .round
        inner.stroke()
        NSColor.black.withAlphaComponent(opacity).setFill()
        for x: CGFloat in [0.9, 17.3] {
            NSBezierPath(ovalIn: NSRect(x: x, y: 1.6, width: 3.8, height: 3.8)).fill()
        }
        NSBezierPath(roundedRect: NSRect(x: 9.1, y: 3.2, width: 3.8, height: 5.5),
                     xRadius: 1.9, yRadius: 1.9).fill()
        if attention {
            NSColor.black.setFill()
            NSBezierPath(ovalIn: NSRect(x: 17, y: 12, width: 4, height: 4)).fill()
        }
    }
}

private final class MenuBackgroundView: NSView {
    override var isOpaque: Bool { true }
    override func draw(_ dirtyRect: NSRect) {
        NSColor.windowBackgroundColor.setFill()
        bounds.fill()
    }
}

final class OFTCMenuViewController: NSViewController {
    var onAction: (() -> Void)?
    var onDetails: (() -> Void)?
    var onSettings: ((NSButton) -> Void)?
    var onQuit: (() -> Void)?
    private let stateLabel = NSTextField(labelWithString: "Disconnected")
    private let descriptionLabel = NSTextField(wrappingLabelWithString: "Ready when you are.")
    private let actionButton = NSButton(title: "Connect", target: nil, action: nil)
    private let quitButton = NSButton(title: "Quit OFTC", target: nil, action: nil)
    private var values: [NSTextField] = []
    private let receivingHistory = RateSparklineView(receiving: true)
    private let sendingHistory = RateSparklineView(receiving: false)

    override func loadView() {
        view = MenuBackgroundView(frame: NSRect(x: 0, y: 0, width: 312, height: 430))
        let stack = NSStackView()
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 12
        stack.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(stack)
        NSLayoutConstraint.activate([
            view.widthAnchor.constraint(equalToConstant: 312),
            stack.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 18),
            stack.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -18),
            stack.topAnchor.constraint(equalTo: view.topAnchor, constant: 18),
            stack.bottomAnchor.constraint(equalTo: view.bottomAnchor, constant: -12),
        ])
        func add(_ child: NSView) {
            stack.addArrangedSubview(child)
            child.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true
        }
        let icon = NSImageView(image: NSImage(named: "OFTC") ??
            NSImage(contentsOf: Bundle.main.resourceURL!.appendingPathComponent("OFTC.icns")) ?? NSImage())
        icon.imageScaling = .scaleProportionallyUpOrDown
        icon.setAccessibilityLabel("OFTC app icon")
        icon.widthAnchor.constraint(equalToConstant: 36).isActive = true
        icon.heightAnchor.constraint(equalToConstant: 36).isActive = true
        let name = NSTextField(labelWithString: "OFTC")
        name.font = .systemFont(ofSize: 14, weight: .medium)
        let subtitle = NSTextField(labelWithString: "Open FortiClient")
        subtitle.font = .systemFont(ofSize: 11)
        subtitle.textColor = .secondaryLabelColor
        let names = NSStackView(views: [name, subtitle])
        names.orientation = .vertical
        names.alignment = .leading
        names.spacing = 0
        let vpn = NSTextField(labelWithString: "VPN")
        vpn.font = .systemFont(ofSize: 11)
        vpn.textColor = .secondaryLabelColor
        let spacer = NSView()
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        let header = NSStackView(views: [icon, names, spacer, vpn])
        header.spacing = 9
        add(header)

        stateLabel.font = .systemFont(ofSize: 20, weight: .medium)
        descriptionLabel.font = .systemFont(ofSize: 12)
        descriptionLabel.textColor = .secondaryLabelColor
        descriptionLabel.maximumNumberOfLines = 3
        let status = NSStackView(views: [stateLabel, descriptionLabel])
        status.orientation = .vertical
        status.alignment = .leading
        status.spacing = 3
        add(status)
        descriptionLabel.widthAnchor.constraint(equalTo: status.widthAnchor).isActive = true
        actionButton.target = self
        actionButton.action = #selector(performAction)
        actionButton.bezelStyle = .rounded
        actionButton.controlSize = .large
        add(actionButton)
        add(NSBox.separator())

        let statistics = NSStackView()
        statistics.orientation = .vertical
        statistics.alignment = .leading
        statistics.spacing = 7
        for label in ["Connected for", "↓ Receiving", "↑ Sending", "Received / sent"] {
            let name = NSTextField(labelWithString: label)
            name.font = .systemFont(ofSize: 13)
            name.textColor = .secondaryLabelColor
            let value = NSTextField(labelWithString: "—")
            value.font = .monospacedDigitSystemFont(ofSize: 13, weight: .regular)
            value.alignment = .right
            value.setContentCompressionResistancePriority(.required, for: .horizontal)
            if label == "↓ Receiving" || label == "↑ Sending" {
                value.widthAnchor.constraint(equalToConstant: 80).isActive = true
            }
            values.append(value)
            var rowViews: [NSView] = [name, NSView()]
            if label == "↓ Receiving" { rowViews.append(receivingHistory) }
            if label == "↑ Sending" { rowViews.append(sendingHistory) }
            rowViews.append(value)
            let row = NSStackView(views: rowViews)
            row.spacing = 7
            statistics.addArrangedSubview(row)
            row.widthAnchor.constraint(equalTo: statistics.widthAnchor).isActive = true
        }
        let caption = NSTextField(labelWithString: "VPN traffic · this connection · 60s trends")
        caption.font = .systemFont(ofSize: 11)
        caption.textColor = .secondaryLabelColor
        statistics.addArrangedSubview(caption)
        add(statistics)
        add(NSBox.separator())
        let details = link("Connection details", action: #selector(showDetails))
        let settings = link("Settings…", action: #selector(showSettings(_:)))
        let footer = NSStackView(views: [details, NSView(), settings])
        add(footer)
        quitButton.isBordered = false
        quitButton.font = .systemFont(ofSize: 12)
        quitButton.contentTintColor = .secondaryLabelColor
        quitButton.target = self
        quitButton.action = #selector(quit)
        add(quitButton)
    }

    private func link(_ title: String, action: Selector) -> NSButton {
        let button = NSButton(title: title, target: self, action: action)
        button.isBordered = false
        button.font = .systemFont(ofSize: 12)
        button.contentTintColor = .linkColor
        return button
    }

    func update(_ presentation: MenuPresentation) {
        _ = view
        stateLabel.stringValue = presentation.state.title
        descriptionLabel.stringValue = presentation.description
        actionButton.title = presentation.action
        actionButton.isEnabled = !presentation.busy && presentation.state != .disconnecting
        let stats = [presentation.duration, presentation.receiving, presentation.sending, presentation.totals]
        for (label, text) in zip(values, stats) { label.stringValue = text }
        receivingHistory.update(history: presentation.history, now: presentation.historyTime)
        sendingHistory.update(history: presentation.history, now: presentation.historyTime)
        quitButton.title = presentation.state.active ? "Disconnect and Quit OFTC" : "Quit OFTC"
        quitButton.isEnabled = !presentation.busy
        view.layoutSubtreeIfNeeded()
    }

    @objc private func performAction() { onAction?() }
    @objc private func showDetails() { onDetails?() }
    @objc private func showSettings(_ sender: NSButton) { onSettings?(sender) }
    @objc private func quit() { onQuit?() }
}

private extension NSBox {
    static func separator() -> NSBox {
        let box = NSBox()
        box.boxType = .separator
        return box
    }
}

// The menu observes state; only the existing CLI/supervisor starts or stops a
// tunnel. Preview mode never constructs a manager, reads a profile or Keychain,
// registers a login service, or invokes a connection command.
final class OFTCMenuBar: NSObject, NSApplicationDelegate, NSPopoverDelegate {
    private let appID: String
    private let preview: MenuConnectionState?
    private let content = OFTCMenuViewController()
    private let popover = NSPopover()
    private var item: NSStatusItem?
    private var timer: Timer?
    private var observers: [NSObjectProtocol] = []
    private var statusObservers: [NSObjectProtocol] = []
    private var statusObserverKey = ""
    private var menuLock: Int32 = -1
    private var manager: NETunnelProviderManager?
    private var profile: OFTCProfile?
    private var presentation = MenuPresentation()
    private var traffic = TrafficRates()
    private var trafficHistory = TrafficHistory()
    private var trafficEpoch = 0
    private var trafficPending = false
    private var trafficReceivedAt: Date?
    private var connectedDate: Date?
    private var refreshEpoch = 0
    private var refreshPending = false
    private var ticks = 0
    private static let safetyReloadTicks = 600
    private var errorMessage: String?
    private var statusError: String?
    private var stoppingSince: Date?
    private var command: MenuCommand?
    private var onboarding: OFTCOnboarding?
    private var quitAfterStop = false
    private let afterInstall: Bool
    private var automaticLaunch = false
    private var launchExperiencePending = true
    private var welcome: OFTCWelcome?
    private var controls: OFTCControlsWindow?
    private var applicationQuitItem: NSMenuItem?
    private var welcomeIsUpgrade = false
    private let componentProbe = ProviderReadiness()
    private var componentState = VPNComponentState.checking
    private var componentCheckPending = false
    private var experienceStore: LaunchExperienceStore {
        LaunchExperienceStore(directory: AgentIntent(bundleID: appID).directory)
    }
    private var hostBuild: String { Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "" }
    private var providerBuild: String {
        let url = Bundle.main.bundleURL.appendingPathComponent(
            "Contents/Library/SystemExtensions/\(appID).provider.systemextension/Contents/Info.plist")
        return (NSDictionary(contentsOf: url)?["CFBundleVersion"] as? String) ?? ""
    }

    init(appID: String, preview: MenuConnectionState? = nil, afterInstall: Bool = false) {
        self.appID = appID
        self.preview = preview
        self.afterInstall = afterInstall
    }

    static func run(appID: String, preview: MenuConnectionState? = nil, afterInstall: Bool = false) -> Never {
        let application = NSApplication.shared
        application.setActivationPolicy(.accessory)
        let controller = OFTCMenuBar(appID: appID, preview: preview, afterInstall: afterInstall)
        application.delegate = controller
        withExtendedLifetime(controller) { application.run() }
        exit(0)
    }

    func applicationWillFinishLaunching(_ notification: Notification) {
        captureLaunchReason()
    }

    private func captureLaunchReason() {
        let reason = NSAppleEventManager.shared().currentAppleEvent?
            .paramDescriptor(forKeyword: AEKeyword(keyAEPropData))?.enumCodeValue
        automaticLaunch = automaticLaunch || AppLaunchReason.isAutomatic(property: reason)
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        captureLaunchReason()
        if preview == nil, !acquireMenuLock() {
            if !automaticLaunch {
                DistributedNotificationCenter.default().postNotificationName(
                    Notification.Name(appID + ".show-menu"), object: nil, deliverImmediately: true)
            }
            NSApp.terminate(nil)
            return
        }
        item = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        item?.button?.target = self
        item?.button?.action = #selector(togglePopover)
        popover.behavior = .transient
        popover.delegate = self
        popover.contentViewController = content
        configureActions(content)
        installApplicationMenu()
        if let preview {
            presentation = .preview(preview)
            updateView()
            showPopover()
            return
        }
        // The cached manager is the source of truth: status changes are read
        // from it, and a full reload happens only when there is no manager
        // yet, on a configuration change, after wake, on user actions, and as
        // a rare safety net.
        syncStatusObservers()
        observers.append(NotificationCenter.default.addObserver(
            forName: .NEVPNConfigurationChange, object: nil, queue: .main) { [weak self] _ in
                self?.refresh()
            })
        observers.append(NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.didWakeNotification, object: nil, queue: .main) { [weak self] _ in
                self?.refresh()
            })
        for suffix in ["show-menu", "quit-menu"] {
            let token = DistributedNotificationCenter.default().addObserver(
                forName: Notification.Name(appID + "." + suffix), object: nil, queue: .main) { [weak self] _ in
                    if suffix == "quit-menu" { NSApp.terminate(nil) }
                    else { self?.showLaunchExperience() }
                }
            observers.append(token)
        }
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in self?.tick() }
        if let timer { RunLoop.main.add(timer, forMode: .common) }
        checkComponent()
        refresh()
    }

    // Status observers are scoped to the connections this menu actually shows,
    // one observer per connection, so more than one tunnel can be added to the
    // list later. Never observe with object: nil: every loadAllFromPreferences
    // then leaks about 3 mach ports in this process (Issue 038).
    private func syncStatusObservers() {
        let connections: [NEVPNConnection] = manager.map { [$0.connection] } ?? []
        let key = connections.map { String(UInt(bitPattern: ObjectIdentifier($0).hashValue)) }.joined(separator: ",")
        guard key != statusObserverKey else { return }
        statusObserverKey = key
        statusObservers.forEach { NotificationCenter.default.removeObserver($0) }
        statusObservers = []
        let handler: (Notification) -> Void = { [weak self] note in
            guard let self else { return }
            self.checkComponent()
            if let manager = self.manager, (note.object as AnyObject?) === manager.connection {
                self.reconcile()
            } else if self.manager == nil {
                self.refresh()
            }
        }
        for connection in connections {
            statusObservers.append(NotificationCenter.default.addObserver(
                forName: .NEVPNStatusDidChange, object: connection, queue: .main, using: handler))
        }
    }

    private func configureActions(_ controller: OFTCMenuViewController) {
        controller.onAction = { [weak self] in self?.performAction() }
        controller.onDetails = { [weak self] in self?.showDetails() }
        controller.onSettings = { [weak self] button in self?.showSettings(button) }
        controller.onQuit = { [weak self] in self?.quit() }
    }

    private func installApplicationMenu() {
        let main = NSMenu()
        let root = NSMenuItem()
        let application = NSMenu(title: "OFTC")
        let item = NSMenuItem(title: "Quit OFTC", action: #selector(quitFromApplicationMenu), keyEquivalent: "q")
        item.target = self
        application.addItem(item)
        applicationQuitItem = item
        root.submenu = application
        main.addItem(root)
        NSApp.mainMenu = main
    }

    @objc private func quitFromApplicationMenu() { quit() }

    private func restoreAccessoryPolicyIfNeeded() {
        if welcome?.window?.isVisible != true && controls?.window?.isVisible != true && onboarding == nil {
            NSApp.setActivationPolicy(.accessory)
        }
    }

    private func acquireMenuLock() -> Bool {
        let directory = AgentIntent(bundleID: appID).directory
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: 0o700])
        } catch { return false }
        menuLock = open(directory.appendingPathComponent("menu.lock").path,
                        O_RDWR | O_CREAT | O_NOFOLLOW, 0o600)
        return menuLock >= 0 && flock(menuLock, LOCK_EX | LOCK_NB) == 0
    }

    private func refresh() {
        guard !refreshPending else { return }
        refreshPending = true
        refreshEpoch += 1
        let epoch = refreshEpoch
        profile = try? OFTCProfileStore(bundleID: appID).load()
        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, error in
            DispatchQueue.main.async {
                guard let self, self.refreshEpoch == epoch else { return }
                self.refreshPending = false
                let matching = (managers ?? []).filter {
                    ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == self.appID + ".provider"
                }
                if error != nil || matching.count > 1 {
                    self.manager = nil
                    self.statusError = "Could not read a single OFTC VPN configuration. Check VPN settings."
                } else {
                    self.manager = matching.first
                    self.statusError = nil
                }
                self.syncStatusObservers()
                self.reconcile()
                self.finishInitialExperience()
            }
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 10) { [weak self] in
            guard let self, self.refreshPending, self.refreshEpoch == epoch else { return }
            self.refreshEpoch += 1
            self.refreshPending = false
            self.manager = nil
            self.statusError = "VPN status is unavailable. Open VPN settings and try again."
            self.resetTraffic()
            self.reconcile()
            self.finishInitialExperience()
        }
    }

    private func finishInitialExperience() {
        guard launchExperiencePending else { return }
        launchExperiencePending = false
        if !automaticLaunch { showLaunchExperience(forceWelcome: afterInstall) }
    }

    private func tick() {
        ticks += 1
        syncStatusObservers()
        if ticks % 5 == 0 {
            profile = try? OFTCProfileStore(bundleID: appID).load()
            if manager == nil || ticks % Self.safetyReloadTicks == 0 { refresh() }
        }
        reconcile()
        sampleTraffic()
    }

    private func reconcile() {
        let phase = SupervisorStatusStore(bundleID: appID).read()?.phase
        let status = manager?.connection.status
        if let stoppingSince {
            if (status == .disconnected || status == .invalid || manager == nil),
               phase == nil || phase == .stopped || phase == .failed {
                self.stoppingSince = nil
                if quitAfterStop { NSApp.terminate(nil); return }
            } else if Date().timeIntervalSince(stoppingSince) > 20 {
                self.stoppingSince = nil
                quitAfterStop = false
                errorMessage = "Could not confirm disconnection. Check VPN settings."
            }
        }
        var state = MenuConnectionState.resolve(status: status, configured: profile != nil && manager?.isEnabled == true,
                                               phase: phase, stopping: stoppingSince != nil)
        if !state.active && componentState.needsSetup { state = .setup }
        if statusError != nil || (errorMessage != nil && !state.active) { state = .attention }
        if connectedDate != manager?.connection.connectedDate || state != .connected {
            connectedDate = manager?.connection.connectedDate
            resetTraffic(clearHistory: true)
        }
        let now = TrafficHistoryClock.now
        trafficHistory.prune(now: now)
        presentation = MenuPresentation(state: state, description: state.detail)
        presentation.busy = command != nil || onboarding != nil || statusError != nil || (componentCheckPending && !state.active)
        if !state.active && profile != nil && componentState != .ready {
            presentation.description = componentState.detail
        }
        if state == .connected {
            presentation.description = profile?.gateway ?? "OFTC VPN"
            presentation.duration = TrafficFormat.duration(since: connectedDate)
            if let receivedAt = trafficReceivedAt, Date().timeIntervalSince(receivedAt) > 3 { resetTraffic() }
            presentation.receiving = TrafficFormat.rate(traffic.receiving)
            presentation.sending = TrafficFormat.rate(traffic.sending)
            presentation.history = trafficHistory.points
            presentation.historyTime = now
            if let sample = traffic.latest {
                presentation.totals = TrafficFormat.bytes(Double(sample.receivedBytes)) + " / " + TrafficFormat.bytes(Double(sample.sentBytes))
            } else { presentation.totals = "—" }
        }
        if let message = statusError ?? errorMessage { presentation.description = message }
        updateView()
        updateWelcome()
    }

    private func checkComponent() {
        guard preview == nil, !componentCheckPending else { return }
        componentCheckPending = true
        componentState = .checking
        componentProbe.check(identifier: appID + ".provider", expected: providerBuild) { [weak self] state in
            guard let self else { return }
            self.componentCheckPending = false
            self.componentState = state
            self.reconcile()
        }
        reconcile()
    }

    private func showLaunchExperience(forceWelcome: Bool = false) {
        guard preview == nil else { showPopover(); return }
        if let onboarding { onboarding.show(); return }
        if welcome != nil { updateWelcome(); welcome?.present(); return }
        if experienceStore.shouldWelcome(build: hostBuild, automatic: false, afterInstall: forceWelcome) {
            showWelcome()
        } else { showControlsWindow() }
    }

    private func updateWelcome() {
        welcome?.update(WelcomePresentation(upgrade: welcomeIsUpgrade,
            configured: profile != nil && manager?.isEnabled == true,
            active: presentation.state.active, component: componentState))
    }

    private func showWelcome() {
        if welcome == nil {
            welcomeIsUpgrade = profile != nil || experienceStore.acknowledgedBuild != nil
            let controller = OFTCWelcome()
            welcome = controller
            controller.onDismiss = { [weak self] in
                guard let self else { return }
                try? self.experienceStore.acknowledge(build: self.hostBuild)
                DispatchQueue.main.async { [weak self] in
                    self?.welcome = nil
                    self?.restoreAccessoryPolicyIfNeeded()
                }
            }
            controller.onAction = { [weak self] action in
                guard let self else { return }
                switch action {
                case .setup:
                    self.welcome?.window?.orderOut(nil)
                    self.showSetup()
                case .controls:
                    guard self.presentation.state.active || self.componentState == .ready else { return }
                    self.welcome?.close()
                    DispatchQueue.main.async { [weak self] in self?.showControlsWindow() }
                case .check: self.checkComponent(); self.refresh()
                case .wait: break
                }
            }
        }
        updateWelcome()
        popover.performClose(nil)
        controls?.window?.orderOut(nil)
        welcome?.present()
    }

    private func showControlsWindow() {
        if controls == nil {
            let controller = OFTCControlsWindow()
            configureActions(controller.content)
            controller.onClose = { [weak self] in
                DispatchQueue.main.async { [weak self] in self?.restoreAccessoryPolicyIfNeeded() }
            }
            controls = controller
        }
        popover.performClose(nil)
        controls?.update(presentation)
        controls?.present()
        if preview == nil { sampleTraffic() }
    }

    private func resetTraffic(clearHistory: Bool = false) {
        trafficEpoch += 1
        trafficPending = false
        trafficReceivedAt = nil
        if clearHistory {
            traffic.reset()
            trafficHistory.reset()
        } else {
            traffic.markUnavailable()
            trafficHistory.markUnavailable(at: TrafficHistoryClock.now)
        }
    }

    private func sampleTraffic() {
        guard !trafficPending, manager?.connection.status == .connected,
              let session = manager?.connection as? NETunnelProviderSession else { return }
        trafficPending = true
        trafficEpoch += 1
        let epoch = trafficEpoch
        let date = session.connectedDate
        do {
            try session.sendProviderMessage(Data("oftc.traffic.v1".utf8)) { [weak self] reply in
                DispatchQueue.main.async {
                    guard let self, self.trafficEpoch == epoch else { return }
                    self.trafficPending = false
                    guard self.manager?.connection.status == .connected,
                          self.manager?.connection.connectedDate == date,
                          let reply, reply.count <= 4096,
                          let sample = try? JSONDecoder().decode(TrafficSnapshot.self, from: reply), sample.valid else {
                        self.resetTraffic()
                        self.reconcile()
                        return
                    }
                    self.traffic.ingest(sample)
                    self.trafficHistory.record(sample, receiving: self.traffic.receiving,
                                               sending: self.traffic.sending, at: TrafficHistoryClock.now)
                    self.trafficReceivedAt = Date()
                    self.reconcile()
                }
            }
        } catch { resetTraffic() }
        DispatchQueue.main.asyncAfter(deadline: .now() + 3) { [weak self] in
            guard let self, self.trafficPending, self.trafficEpoch == epoch else { return }
            self.resetTraffic()
            self.reconcile()
        }
    }

    private func updateView() {
        content.update(presentation)
        controls?.update(presentation)
        popover.contentSize = content.view.fittingSize
        applicationQuitItem?.title = presentation.state.active ? "Disconnect and Quit OFTC" : "Quit OFTC"
        item?.button?.image = TunnelMenuIcon.image(connected: presentation.state == .connected,
                                                   attention: presentation.state == .attention)
        item?.button?.toolTip = "OFTC VPN: " + presentation.state.title
        item?.button?.setAccessibilityLabel("OFTC VPN: " + presentation.state.title)
    }

    @objc private func togglePopover() {
        if popover.isShown { popover.performClose(nil) }
        else { showPopover() }
    }

    private func showPopover() {
        guard let button = item?.button else { return }
        controls?.window?.orderOut(nil)
        if onboarding == nil && welcome?.window?.isVisible != true { NSApp.setActivationPolicy(.accessory) }
        NSApp.activate(ignoringOtherApps: true)
        popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
        if preview == nil { sampleTraffic() }
    }

    // Sampling continues while connected so reopening the popover shows a
    // useful recent history. The bounded buffer is kept only in memory.

    private func performAction() {
        if preview != nil {
            presentation = .preview(presentation.state.active ? .disconnected : .connected)
            updateView()
            return
        }
        if presentation.state == .setup { showSetup(); return }
        if !presentation.state.active && componentState != .ready { showWelcome(); return }
        guard command == nil else { return }
        let disconnect = presentation.state.active
        errorMessage = nil
        if disconnect { stoppingSince = Date() }
        runCommand(disconnect ? "disconnect" : "connect") { [weak self] result in
            guard let self else { return }
            if case .failure(let failure) = result {
                self.stoppingSince = nil
                self.quitAfterStop = false
                self.errorMessage = OFTCAgentService.status == "requires-approval"
                    ? "Allow OFTC in System Settings → Login Items & Extensions, then try again."
                    : failure.message(action: disconnect ? "disconnect" : "connect")
            }
            self.refresh()
            self.reconcile()
        }
    }

    private func runCommand(_ action: String, completion: @escaping (MenuCommandResult) -> Void) {
        let runner = MenuCommand()
        command = runner
        runner.start(executable: Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/oftc"),
                     arguments: ["--app", Bundle.main.bundlePath, action],
                     home: FileManager.default.homeDirectoryForCurrentUser) { [weak self, weak runner] result in
            guard let self, let runner, self.command === runner else { return }
            self.command = nil
            completion(result)
        }
        reconcile()
    }

    private func showSetup() {
        guard preview == nil else { return }
        guard !presentation.state.active else { showWelcome(); return }
        guard componentState != .newer else { showWelcome(); return }
        popover.performClose(nil)
        controls?.window?.orderOut(nil)
        welcome?.window?.orderOut(nil)
        if onboarding == nil {
            onboarding = OFTCOnboarding(appID: appID, updating: componentState == .updateRequired) { [weak self] in
                DispatchQueue.main.async { [weak self] in
                    guard let self else { return }
                    self.onboarding = nil
                    self.errorMessage = nil
                    self.checkComponent()
                    self.refresh()
                    self.showWelcome()
                }
            }
        }
        onboarding?.show()
        reconcile()
    }

    private func showDetails() {
        let alert = NSAlert()
        alert.messageText = "OFTC connection"
        let gateway = preview == nil ? profile?.gateway ?? "Not configured" : "vpn.example.com"
        let transport = preview == nil ? profile?.transport.rawValue.uppercased() ?? "—" : "UDP"
        alert.informativeText = "Status: \(presentation.state.title)\nGateway: \(gateway)\nTransport: IPsec over \(transport)\n\nTraffic counts inner IP bytes carried by OFTC. Totals reset on a new connection; rekeying preserves them."
        alert.addButton(withTitle: "Done")
        popover.performClose(nil)
        alert.runModal()
    }

    private func showSettings(_ sender: NSButton) {
        let menu = NSMenu()
        func add(_ title: String, action: Selector, checked: Bool? = nil) {
            let item = NSMenuItem(title: title, action: action, keyEquivalent: "")
            item.target = self
            if let checked { item.state = checked ? .on : .off }
            item.isEnabled = preview == nil && command == nil
            menu.addItem(item)
        }
        menu.autoenablesItems = false
        add("Launch OFTC at login", action: #selector(toggleMenuLogin),
            checked: preview == nil && SMAppService.mainApp.status == .enabled)
        add("Connect VPN at login", action: #selector(toggleVPNLogin),
            checked: preview == nil && OFTCAgentService.connectAtLogin)
        menu.addItem(.separator())
        add("Set up OFTC…", action: #selector(openSetup))
        add("Login Items & Extensions…", action: #selector(openLoginSettings))
        menu.popUp(positioning: nil, at: NSPoint(x: 0, y: sender.bounds.maxY), in: sender)
    }

    @objc private func toggleMenuLogin() {
        guard preview == nil else { return }
        do {
            if SMAppService.mainApp.status == .enabled { try SMAppService.mainApp.unregister() }
            else { try SMAppService.mainApp.register() }
            errorMessage = nil
        } catch { errorMessage = "Could not change login launch. Check Login Items & Extensions in System Settings." }
        reconcile()
    }
    @objc private func toggleVPNLogin() {
        guard preview == nil else { return }
        do { try OFTCAgentService.setConnectAtLogin(!OFTCAgentService.connectAtLogin); errorMessage = nil }
        catch { errorMessage = "Could not change automatic connection. Check Login Items & Extensions in System Settings." }
        reconcile()
    }
    @objc private func openSetup() { showSetup() }
    @objc private func openLoginSettings() { if preview == nil { SMAppService.openSystemSettingsLoginItems() } }

    private func quit() {
        if preview != nil { NSApp.terminate(nil); return }
        if presentation.state.active { quitAfterStop = true; performAction() }
        else { NSApp.terminate(nil) }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if !launchExperiencePending { showLaunchExperience() }
        return false
    }

    static func renderPreviews(to directory: URL) throws {
        _ = NSApplication.shared
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        for appearance in [NSAppearance.Name.aqua, .darkAqua] {
            for state in [MenuConnectionState.connected, .disconnected, .signingIn, .reconnecting, .attention, .setup] {
                var output: Data?
                NSAppearance(named: appearance)!.performAsCurrentDrawingAppearance {
                let controller = OFTCMenuViewController()
                controller.view.appearance = NSAppearance(named: appearance)
                controller.update(.preview(state))
                let view = controller.view
                let size = view.fittingSize
                let window = NSWindow(contentRect: NSRect(origin: .zero, size: size),
                                      styleMask: [.borderless], backing: .buffered, defer: false)
                window.isReleasedWhenClosed = false
                window.appearance = NSAppearance(named: appearance)
                window.contentViewController = controller
                window.setContentSize(size)
                view.layoutSubtreeIfNeeded()
                if let bitmap = view.bitmapImageRepForCachingDisplay(in: view.bounds) {
                    view.cacheDisplay(in: view.bounds, to: bitmap)
                    output = bitmap.representation(using: .png, properties: [:])
                }
                window.close()
                }
                guard let png = output else { throw NSError(domain: "OFTCPreview", code: 1) }
                let name = state.rawValue + (appearance == .darkAqua ? "-dark.png" : "-light.png")
                try png.write(to: directory.appendingPathComponent(name))
            }
        }
        print("Native offline menu previews rendered; no VPN or login services were accessed.")
        try OFTCWelcome.renderPreviews(to: directory)
    }
}
