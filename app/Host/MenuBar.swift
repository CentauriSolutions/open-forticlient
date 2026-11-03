import AppKit
import Carbon
import Darwin
import Foundation
import NetworkExtension
import ServiceManagement
import UniformTypeIdentifiers

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

// One profile's controls: state, start/stop, its own connect-at-login choice,
// and (while connected) its traffic.
private final class TunnelRowView: NSStackView {
    let tunnelID: String
    var onAction: ((String) -> Void)?
    var onAutoStart: ((String, Bool) -> Void)?
    var onRemove: ((String) -> Void)?
    private let moreButton = NSButton()
    private let dot = NSTextField(labelWithString: "●")
    private let nameLabel = NSTextField(labelWithString: "")
    private let stateLabel = NSTextField(labelWithString: "")
    private let detailLabel = NSTextField(wrappingLabelWithString: "")
    private let actionButton = NSButton(title: "Connect", target: nil, action: nil)
    private let autoStart = NSButton(checkboxWithTitle: "Connect at login", target: nil, action: nil)
    private let statistics = NSStackView()
    private var values: [NSTextField] = []
    private let receivingHistory = RateSparklineView(receiving: true)
    private let sendingHistory = RateSparklineView(receiving: false)

    init(id: String) {
        tunnelID = id
        super.init(frame: .zero)
        orientation = .vertical
        alignment = .leading
        spacing = 8
        func add(_ child: NSView) {
            addArrangedSubview(child)
            child.widthAnchor.constraint(equalTo: widthAnchor).isActive = true
        }
        dot.font = .systemFont(ofSize: 11)
        nameLabel.font = .systemFont(ofSize: 14, weight: .medium)
        nameLabel.lineBreakMode = .byTruncatingTail
        nameLabel.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        stateLabel.font = .systemFont(ofSize: 12)
        stateLabel.textColor = .secondaryLabelColor
        let spacer = NSView()
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        moreButton.image = NSImage(systemSymbolName: "ellipsis", accessibilityDescription: "More actions")
        moreButton.isBordered = false
        moreButton.contentTintColor = .secondaryLabelColor
        moreButton.target = self
        moreButton.action = #selector(showMore)
        moreButton.setAccessibilityLabel("More actions")
        let title = NSStackView(views: [dot, nameLabel, spacer, stateLabel, moreButton])
        title.spacing = 6
        add(title)
        detailLabel.font = .systemFont(ofSize: 11)
        detailLabel.textColor = .secondaryLabelColor
        detailLabel.maximumNumberOfLines = 3
        add(detailLabel)
        actionButton.target = self
        actionButton.action = #selector(performAction)
        actionButton.bezelStyle = .rounded
        autoStart.target = self
        autoStart.action = #selector(toggleAutoStart)
        autoStart.font = .systemFont(ofSize: 12)
        autoStart.setAccessibilityLabel("Connect this VPN at login")
        let controls = NSStackView(views: [actionButton, NSView(), autoStart])
        controls.spacing = 8
        add(controls)

        statistics.orientation = .vertical
        statistics.alignment = .leading
        statistics.spacing = 6
        for label in ["Connected for", "↓ Receiving", "↑ Sending", "Received / sent"] {
            let name = NSTextField(labelWithString: label)
            name.font = .systemFont(ofSize: 12)
            name.textColor = .secondaryLabelColor
            let value = NSTextField(labelWithString: "—")
            value.font = .monospacedDigitSystemFont(ofSize: 12, weight: .regular)
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
        caption.font = .systemFont(ofSize: 10)
        caption.textColor = .secondaryLabelColor
        statistics.addArrangedSubview(caption)
        add(statistics)
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    private func color(for state: MenuConnectionState) -> NSColor {
        switch state {
        case .connected: return .systemGreen
        case .connecting, .signingIn, .reconnecting, .disconnecting: return .systemOrange
        case .attention: return .systemRed
        default: return .tertiaryLabelColor
        }
    }

    func update(_ tunnel: TunnelPresentation) {
        nameLabel.stringValue = tunnel.name
        stateLabel.stringValue = tunnel.state.title
        dot.textColor = color(for: tunnel.state)
        detailLabel.stringValue = tunnel.description
        actionButton.title = tunnel.action
        actionButton.isEnabled = !tunnel.busy && tunnel.state != .disconnecting
        autoStart.state = tunnel.autoStart ? .on : .off
        autoStart.isEnabled = !tunnel.busy || tunnel.state.active
        setAccessibilityLabel("\(tunnel.name): \(tunnel.state.title)")
        statistics.isHidden = tunnel.state != .connected
        let stats = [tunnel.duration, tunnel.receiving, tunnel.sending, tunnel.totals]
        for (label, text) in zip(values, stats) { label.stringValue = text }
        receivingHistory.update(history: tunnel.history, now: tunnel.historyTime)
        sendingHistory.update(history: tunnel.history, now: tunnel.historyTime)
    }

    @objc private func showMore() {
        let menu = NSMenu()
        let remove = NSMenuItem(title: "Remove…", action: #selector(removeChosen), keyEquivalent: "")
        remove.target = self
        menu.addItem(remove)
        menu.popUp(positioning: nil, at: NSPoint(x: 0, y: moreButton.bounds.maxY + 4), in: moreButton)
    }
    @objc private func removeChosen() { onRemove?(tunnelID) }
    @objc private func performAction() { onAction?(tunnelID) }
    @objc private func toggleAutoStart() { onAutoStart?(tunnelID, autoStart.state == .on) }
}

final class OFTCMenuViewController: NSViewController {
    var onAction: ((String) -> Void)?
    var onAutoStart: ((String, Bool) -> Void)?
    var onRemove: ((String) -> Void)?
    var onAll: ((Bool) -> Void)?
    var onAddVPN: (() -> Void)?
    var onSettings: ((NSButton) -> Void)?
    var onQuit: (() -> Void)?
    private let noticeLabel = NSTextField(wrappingLabelWithString: "")
    private let rowsStack = NSStackView()
    private let emptyLabel = NSTextField(wrappingLabelWithString: "Add your VPN gateways, then connect any of them at the same time.")
    private let allControls = NSStackView()
    private let connectAll = NSButton(title: "Connect all", target: nil, action: nil)
    private let disconnectAll = NSButton(title: "Disconnect all", target: nil, action: nil)
    private let addButton = NSButton(title: "Add VPN…", target: nil, action: nil)
    private let quitButton = NSButton(title: "Quit OFTC", target: nil, action: nil)
    private var rows: [String: TunnelRowView] = [:]
    private var shownIDs: [String] = []

    override func loadView() {
        view = MenuBackgroundView(frame: NSRect(x: 0, y: 0, width: 312, height: 300))
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
        let vpn = NSTextField(labelWithString: "VPNs")
        vpn.font = .systemFont(ofSize: 11)
        vpn.textColor = .secondaryLabelColor
        let spacer = NSView()
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        let header = NSStackView(views: [icon, names, spacer, vpn])
        header.spacing = 9
        add(header)

        noticeLabel.font = .systemFont(ofSize: 12)
        noticeLabel.textColor = .systemRed
        noticeLabel.maximumNumberOfLines = 3
        add(noticeLabel)
        emptyLabel.font = .systemFont(ofSize: 12)
        emptyLabel.textColor = .secondaryLabelColor
        add(emptyLabel)
        rowsStack.orientation = .vertical
        rowsStack.alignment = .leading
        rowsStack.spacing = 12
        add(rowsStack)

        connectAll.target = self
        connectAll.action = #selector(connectAllTapped)
        disconnectAll.target = self
        disconnectAll.action = #selector(disconnectAllTapped)
        for button in [connectAll, disconnectAll] { button.bezelStyle = .rounded; button.controlSize = .small }
        allControls.setViews([connectAll, disconnectAll, NSView()], in: .leading)
        allControls.spacing = 8
        add(allControls)
        add(NSBox.separator())
        addButton.isBordered = false
        addButton.font = .systemFont(ofSize: 12)
        addButton.contentTintColor = .linkColor
        addButton.target = self
        addButton.action = #selector(addTapped)
        let settings = link("Settings…", action: #selector(showSettings(_:)))
        add(NSStackView(views: [addButton, NSView(), settings]))
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
        noticeLabel.stringValue = presentation.notice ?? ""
        noticeLabel.isHidden = presentation.notice == nil
        emptyLabel.isHidden = !presentation.tunnels.isEmpty
        let ids = presentation.tunnels.map(\.id)
        if ids != shownIDs {
            for old in rowsStack.arrangedSubviews { rowsStack.removeArrangedSubview(old); old.removeFromSuperview() }
            for (index, tunnel) in presentation.tunnels.enumerated() {
                let row = rows[tunnel.id] ?? {
                    let created = TunnelRowView(id: tunnel.id)
                    created.onAction = { [weak self] in self?.onAction?($0) }
                    created.onAutoStart = { [weak self] in self?.onAutoStart?($0, $1) }
                    created.onRemove = { [weak self] in self?.onRemove?($0) }
                    rows[tunnel.id] = created
                    return created
                }()
                if index > 0 {
                    let line = NSBox.separator()
                    rowsStack.addArrangedSubview(line)
                    line.widthAnchor.constraint(equalTo: rowsStack.widthAnchor).isActive = true
                }
                rowsStack.addArrangedSubview(row)
                row.widthAnchor.constraint(equalTo: rowsStack.widthAnchor).isActive = true
            }
            rows = rows.filter { ids.contains($0.key) }
            shownIDs = ids
        }
        for tunnel in presentation.tunnels { rows[tunnel.id]?.update(tunnel) }
        allControls.isHidden = presentation.tunnels.count < 2
        connectAll.isEnabled = !presentation.busy && presentation.tunnels.contains { !$0.state.active && $0.state != .setup }
        disconnectAll.isEnabled = !presentation.busy && presentation.anyActive
        addButton.isEnabled = !presentation.busy || presentation.anyActive
        quitButton.title = presentation.anyActive ? "Disconnect and Quit OFTC" : "Quit OFTC"
        quitButton.isEnabled = !presentation.busy
        view.layoutSubtreeIfNeeded()
    }

    @objc private func connectAllTapped() { onAll?(true) }
    @objc private func disconnectAllTapped() { onAll?(false) }
    @objc private func addTapped() { onAddVPN?() }
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

// Everything the menu tracks for one profile.
private final class TunnelRuntime {
    var entry: OFTCProfileEntry
    var manager: NETunnelProviderManager?
    var statusError: String?
    var errorMessage: String?
    var stoppingSince: Date?
    var command: MenuCommand?
    var autoStart = false
    var traffic = TrafficRates()
    var trafficHistory = TrafficHistory()
    var trafficEpoch = 0
    var trafficPending = false
    var trafficReceivedAt: Date?
    var connectedDate: Date?
    var state = MenuConnectionState.disconnected

    init(entry: OFTCProfileEntry) { self.entry = entry }

    func resetTraffic(clearHistory: Bool = false) {
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
}

// The menu observes state; only the existing CLI/supervisors start or stop a
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
    private var runtimes: [String: TunnelRuntime] = [:]
    private var order: [String] = []
    private var presentation = MenuPresentation()
    private var refreshEpoch = 0
    private var refreshPending = false
    private var ticks = 0
    private static let safetyReloadTicks = 600
    private var globalError: String?
    private var bulkCommand: MenuCommand?
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
    private var root: URL { OFTCProfileScope.defaultRoot(bundleID: appID) }
    private var experienceStore: LaunchExperienceStore {
        LaunchExperienceStore(directory: AgentIntent(bundleID: appID).directory)
    }
    private var hostBuild: String { Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "" }
    private var providerBuild: String {
        let url = Bundle.main.bundleURL.appendingPathComponent(
            "Contents/Library/SystemExtensions/\(appID).provider.systemextension/Contents/Info.plist")
        return (NSDictionary(contentsOf: url)?["CFBundleVersion"] as? String) ?? ""
    }
    private var orderedRuntimes: [TunnelRuntime] { order.compactMap { runtimes[$0] } }
    private var configured: Bool { runtimes.values.contains { $0.manager?.isEnabled == true } }

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
        // Each cached manager is the source of truth for its tunnel: status
        // changes are read from it, and a full reload happens only when a
        // profile has no manager yet, on a configuration change, after wake,
        // on user actions, and as a rare safety net.
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
    // one observer per connection. Never observe with object: nil: every
    // loadAllFromPreferences then leaks about 3 mach ports in this process
    // (Issue 038).
    private func syncStatusObservers() {
        let connections: [NEVPNConnection] = orderedRuntimes.compactMap { $0.manager?.connection }
        let key = connections.map { String(UInt(bitPattern: ObjectIdentifier($0).hashValue)) }.joined(separator: ",")
        guard key != statusObserverKey else { return }
        statusObserverKey = key
        statusObservers.forEach { NotificationCenter.default.removeObserver($0) }
        statusObservers = []
        let handler: (Notification) -> Void = { [weak self] note in
            guard let self else { return }
            self.checkComponent()
            if self.runtimes.values.contains(where: { $0.manager?.connection === (note.object as AnyObject?) }) {
                self.reconcile()
            } else if self.runtimes.values.contains(where: { $0.manager == nil }) {
                self.refresh()
            }
        }
        for connection in connections {
            statusObservers.append(NotificationCenter.default.addObserver(
                forName: .NEVPNStatusDidChange, object: connection, queue: .main, using: handler))
        }
    }

    private func configureActions(_ controller: OFTCMenuViewController) {
        controller.onAction = { [weak self] id in self?.performAction(id) }
        controller.onAutoStart = { [weak self] id, enabled in self?.setAutoStart(id, enabled) }
        controller.onRemove = { [weak self] id in self?.removeProfile(id) }
        controller.onAll = { [weak self] connect in self?.performAll(connect: connect) }
        controller.onAddVPN = { [weak self] in self?.showSetup() }
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

    // Reconciles the runtime set with the profiles on disk.
    private func syncProfiles() {
        let entries = OFTCProfileScope.entries(root: root)
        let ids = entries.map(\.id)
        for entry in entries {
            if let existing = runtimes[entry.id] { existing.entry = entry }
            else { runtimes[entry.id] = TunnelRuntime(entry: entry) }
        }
        for id in runtimes.keys where !ids.contains(id) { runtimes[id] = nil }
        order = ids
        for runtime in runtimes.values { runtime.autoStart = OFTCAgentService.connectAtLogin(runtime.entry) }
    }

    private func refresh() {
        guard !refreshPending else { return }
        refreshPending = true
        refreshEpoch += 1
        let epoch = refreshEpoch
        syncProfiles()
        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, error in
            DispatchQueue.main.async {
                guard let self, self.refreshEpoch == epoch else { return }
                self.refreshPending = false
                for runtime in self.runtimes.values {
                    let matching = OFTCProfileScope.manager(for: runtime.entry, in: managers ?? [],
                                                            providerID: self.appID + ".provider")
                    if error != nil || matching.count > 1 {
                        runtime.manager = nil
                        runtime.statusError = "Could not read a single VPN configuration for \(runtime.entry.name). Check VPN settings."
                    } else {
                        runtime.manager = matching.first
                        runtime.statusError = nil
                    }
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
            for runtime in self.runtimes.values {
                runtime.manager = nil
                runtime.statusError = "VPN status is unavailable. Open VPN settings and try again."
                runtime.resetTraffic()
            }
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
            let before = order
            syncProfiles()
            if before != order || runtimes.values.contains(where: { $0.manager == nil })
                || ticks % Self.safetyReloadTicks == 0 { refresh() }
        }
        reconcile()
        for runtime in orderedRuntimes { sampleTraffic(runtime) }
    }

    private func tunnelPresentation(_ runtime: TunnelRuntime) -> TunnelPresentation {
        let phase = SupervisorStatusStore(directory: runtime.entry.directory).read()?.phase
        let status = runtime.manager?.connection.status
        if let since = runtime.stoppingSince {
            if (status == .disconnected || status == .invalid || runtime.manager == nil),
               phase == nil || phase == .stopped || phase == .failed {
                runtime.stoppingSince = nil
            } else if Date().timeIntervalSince(since) > 20 {
                runtime.stoppingSince = nil
                quitAfterStop = false
                runtime.errorMessage = "Could not confirm disconnection. Check VPN settings."
            }
        }
        var state = MenuConnectionState.resolve(status: status, configured: runtime.manager?.isEnabled == true,
                                               phase: phase, stopping: runtime.stoppingSince != nil)
        if !state.active && componentState.needsSetup { state = .setup }
        if runtime.statusError != nil || (runtime.errorMessage != nil && !state.active) { state = .attention }
        runtime.state = state
        if runtime.connectedDate != runtime.manager?.connection.connectedDate || state != .connected {
            runtime.connectedDate = runtime.manager?.connection.connectedDate
            runtime.resetTraffic(clearHistory: true)
        }
        let now = TrafficHistoryClock.now
        runtime.trafficHistory.prune(now: now)
        var row = TunnelPresentation(id: runtime.entry.id, name: runtime.entry.name)
        row.state = state
        row.description = state.detail
        row.autoStart = runtime.autoStart
        row.busy = runtime.command != nil || bulkCommand != nil || onboarding != nil
            || runtime.statusError != nil || (componentCheckPending && !state.active)
        let gateway = runtime.entry.profile.gateway
        let transport = runtime.entry.profile.transport.rawValue.uppercased()
        if state == .disconnected { row.description = "\(gateway) · \(transport)" }
        if !state.active && state != .setup && componentState != .ready {
            row.description = componentState.detail
        }
        if state == .connected {
            row.description = "\(gateway) · \(transport)"
            row.duration = TrafficFormat.duration(since: runtime.connectedDate)
            if let receivedAt = runtime.trafficReceivedAt, Date().timeIntervalSince(receivedAt) > 3 {
                runtime.resetTraffic()
            }
            row.receiving = TrafficFormat.rate(runtime.traffic.receiving)
            row.sending = TrafficFormat.rate(runtime.traffic.sending)
            row.history = runtime.trafficHistory.points
            row.historyTime = now
            if let sample = runtime.traffic.latest {
                row.totals = TrafficFormat.bytes(Double(sample.receivedBytes)) + " / " + TrafficFormat.bytes(Double(sample.sentBytes))
            }
        }
        if let message = runtime.statusError ?? runtime.errorMessage { row.description = message }
        return row
    }

    private func reconcile() {
        var next = MenuPresentation()
        next.tunnels = orderedRuntimes.map(tunnelPresentation)
        next.busy = bulkCommand != nil || onboarding != nil
        next.notice = globalError
        presentation = next
        if quitAfterStop, !presentation.anyActive, runtimes.values.allSatisfy({ $0.stoppingSince == nil }) {
            NSApp.terminate(nil)
            return
        }
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
            configured: configured, active: presentation.anyActive, component: componentState))
    }

    private func showWelcome() {
        if welcome == nil {
            welcomeIsUpgrade = !runtimes.isEmpty || experienceStore.acknowledgedBuild != nil
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
                    guard self.presentation.anyActive || self.componentState == .ready else { return }
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
        if preview == nil { orderedRuntimes.forEach(sampleTraffic) }
    }

    private func sampleTraffic(_ runtime: TunnelRuntime) {
        guard !runtime.trafficPending, runtime.manager?.connection.status == .connected,
              let session = runtime.manager?.connection as? NETunnelProviderSession else { return }
        runtime.trafficPending = true
        runtime.trafficEpoch += 1
        let epoch = runtime.trafficEpoch
        let date = session.connectedDate
        do {
            try session.sendProviderMessage(Data("oftc.traffic.v1".utf8)) { [weak self, weak runtime] reply in
                DispatchQueue.main.async {
                    guard let self, let runtime, runtime.trafficEpoch == epoch else { return }
                    runtime.trafficPending = false
                    guard runtime.manager?.connection.status == .connected,
                          runtime.manager?.connection.connectedDate == date,
                          let reply, reply.count <= 4096,
                          let sample = try? JSONDecoder().decode(TrafficSnapshot.self, from: reply), sample.valid else {
                        runtime.resetTraffic()
                        self.reconcile()
                        return
                    }
                    runtime.traffic.ingest(sample)
                    runtime.trafficHistory.record(sample, receiving: runtime.traffic.receiving,
                                                  sending: runtime.traffic.sending, at: TrafficHistoryClock.now)
                    runtime.trafficReceivedAt = Date()
                    self.reconcile()
                }
            }
        } catch { runtime.resetTraffic() }
        DispatchQueue.main.asyncAfter(deadline: .now() + 3) { [weak self, weak runtime] in
            guard let self, let runtime, runtime.trafficPending, runtime.trafficEpoch == epoch else { return }
            runtime.resetTraffic()
            self.reconcile()
        }
    }

    private func updateView() {
        content.update(presentation)
        controls?.update(presentation)
        popover.contentSize = content.view.fittingSize
        applicationQuitItem?.title = presentation.anyActive ? "Disconnect and Quit OFTC" : "Quit OFTC"
        item?.button?.image = TunnelMenuIcon.image(connected: presentation.anyConnected,
                                                   attention: presentation.anyAttention)
        item?.button?.toolTip = "OFTC VPN: " + presentation.summary
        item?.button?.setAccessibilityLabel("OFTC VPN: " + presentation.summary)
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
        if preview == nil { orderedRuntimes.forEach(sampleTraffic) }
    }

    // Sampling continues while connected so reopening the popover shows a
    // useful recent history. The bounded buffer is kept only in memory.

    private func performAction(_ id: String) {
        if preview != nil {
            guard let index = presentation.tunnels.firstIndex(where: { $0.id == id }) else { return }
            presentation.tunnels[index].state = presentation.tunnels[index].state.active ? .disconnected : .connected
            updateView()
            return
        }
        guard let runtime = runtimes[id] else { return }
        if runtime.state == .setup { showSetup(); return }
        if !runtime.state.active && componentState != .ready { showWelcome(); return }
        guard runtime.command == nil, bulkCommand == nil else { return }
        let disconnect = runtime.state.active
        runtime.errorMessage = nil
        globalError = nil
        if disconnect { runtime.stoppingSince = Date() }
        runCommand([disconnect ? "disconnect" : "connect", id], for: runtime) { [weak self, weak runtime] result in
            guard let self, let runtime else { return }
            if case .failure(let failure) = result {
                runtime.stoppingSince = nil
                self.quitAfterStop = false
                runtime.errorMessage = failure.message(action: disconnect ? "disconnect" : "connect")
            }
            self.refresh()
            self.reconcile()
        }
    }

    private func performAll(connect: Bool) {
        guard preview == nil, bulkCommand == nil else { return }
        if connect && componentState != .ready { showWelcome(); return }
        globalError = nil
        if !connect { for runtime in runtimes.values where runtime.state.active { runtime.stoppingSince = Date() } }
        runCommand([connect ? "connect" : "disconnect"], for: nil) { [weak self] result in
            guard let self else { return }
            if case .failure(let failure) = result {
                for runtime in self.runtimes.values { runtime.stoppingSince = nil }
                self.quitAfterStop = false
                self.globalError = failure.message(action: connect ? "connect" : "disconnect")
            }
            self.refresh()
            self.reconcile()
        }
    }

    private func runCommand(_ arguments: [String], for runtime: TunnelRuntime?,
                            completion: @escaping (MenuCommandResult) -> Void) {
        let runner = MenuCommand()
        if let runtime { runtime.command = runner } else { bulkCommand = runner }
        runner.start(executable: Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/oftc"),
                     arguments: ["--app", Bundle.main.bundlePath] + arguments,
                     home: FileManager.default.homeDirectoryForCurrentUser) { [weak self, weak runner] result in
            guard let self, let runner else { return }
            if let runtime, runtime.command === runner { runtime.command = nil }
            else if self.bulkCommand === runner { self.bulkCommand = nil }
            else { return }
            completion(result)
        }
        reconcile()
    }

    private func removeProfile(_ id: String) {
        guard preview == nil, let runtime = runtimes[id],
              runtime.command == nil, bulkCommand == nil else { return }
        let name = runtime.entry.name
        popover.performClose(nil)
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "Remove “\(name)”?"
        alert.informativeText = (runtime.state.active ? "It will be disconnected first. " : "")
            + "This deletes its VPN entry, saved key and settings from this Mac. "
            + "To add it again later you’ll need a .oftc file or its gateway details, "
            + "so export your VPNs first if you want a copy."
        let remove = alert.addButton(withTitle: "Remove")
        remove.hasDestructiveAction = true
        alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        runtime.errorMessage = nil
        globalError = nil
        runtime.stoppingSince = runtime.state.active ? Date() : nil
        runCommand(["remove", id], for: runtime) { [weak self, weak runtime] result in
            guard let self else { return }
            if case .failure(let failure) = result, let runtime {
                runtime.stoppingSince = nil
                runtime.errorMessage = failure.message(action: "remove")
            }
            self.refresh()
            self.reconcile()
        }
    }

    private func setAutoStart(_ id: String, _ enabled: Bool) {
        guard preview == nil, let runtime = runtimes[id] else { return }
        do {
            try OFTCAgentService.setConnectAtLogin(enabled, for: runtime.entry)
            runtime.errorMessage = nil
        } catch {
            runtime.errorMessage = "Could not change automatic connection. Check Login Items & Extensions in System Settings."
        }
        runtime.autoStart = OFTCAgentService.connectAtLogin(runtime.entry)
        reconcile()
    }

    private func showSetup() {
        guard preview == nil else { return }
        guard componentState != .newer else { showWelcome(); return }
        // Adding a VPN is fine beside live tunnels; replacing the provider is not.
        guard !(presentation.anyActive && componentState == .updateRequired) else { showWelcome(); return }
        popover.performClose(nil)
        controls?.window?.orderOut(nil)
        welcome?.window?.orderOut(nil)
        if onboarding == nil {
            onboarding = OFTCOnboarding(appID: appID, updating: componentState == .updateRequired) { [weak self] in
                DispatchQueue.main.async { [weak self] in
                    guard let self else { return }
                    self.onboarding = nil
                    self.globalError = nil
                    self.checkComponent()
                    self.refresh()
                    self.showWelcome()
                }
            }
        }
        onboarding?.show()
        reconcile()
    }

    private func showSettings(_ sender: NSButton) {
        let menu = NSMenu()
        func add(_ title: String, action: Selector, checked: Bool? = nil) {
            let item = NSMenuItem(title: title, action: action, keyEquivalent: "")
            item.target = self
            if let checked { item.state = checked ? .on : .off }
            item.isEnabled = preview == nil && bulkCommand == nil
            menu.addItem(item)
        }
        menu.autoenablesItems = false
        add("Launch OFTC at login", action: #selector(toggleMenuLogin),
            checked: preview == nil && SMAppService.mainApp.status == .enabled)
        menu.addItem(.separator())
        add("Add VPN…", action: #selector(openSetup))
        add("Export VPNs…", action: #selector(exportVPNs))
        menu.items.last?.isEnabled = preview == nil && bulkCommand == nil && !runtimes.isEmpty
        add("Login Items & Extensions…", action: #selector(openLoginSettings))
        menu.popUp(positioning: nil, at: NSPoint(x: 0, y: sender.bounds.maxY), in: sender)
    }

    @objc private func toggleMenuLogin() {
        guard preview == nil else { return }
        do {
            if SMAppService.mainApp.status == .enabled { try SMAppService.mainApp.unregister() }
            else { try SMAppService.mainApp.register() }
            globalError = nil
        } catch { globalError = "Could not change login launch. Check Login Items & Extensions in System Settings." }
        reconcile()
    }
    @objc private func openSetup() { showSetup() }

    // MARK: Sharing profiles (.oftc files)

    private func present(_ title: String, _ text: String) {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = text
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }

    // Double-clicking a .oftc file in Finder, or dropping it on OFTC.
    func application(_ application: NSApplication, open urls: [URL]) {
        guard preview == nil, let url = urls.first(where: \.isFileURL) else { return }
        importProfiles(from: url)
    }

    private func importProfiles(from url: URL) {
        guard bulkCommand == nil else {
            present("OFTC is busy", "Try opening the file again in a moment.")
            return
        }
        popover.performClose(nil)
        let incoming: [(profile: OFTCProfile, psk: Data)]
        do {
            let data = try FileHandle(forReadingFrom: url).read(upToCount: OFTCProfileBundle.maxBytes + 1) ?? Data()
            incoming = try OFTCProfileBundle.decode(data)
        } catch let failure as OFTCProfileBundle.Failure {
            present("Can’t add these VPNs", failure.message + ".")
            return
        } catch {
            present("Can’t add these VPNs", "OFTC couldn’t read that file.")
            return
        }
        let configured = Set(OFTCProfileScope.entries(root: root).map(\.profile.gateway))
        let fresh = incoming.filter { !configured.contains($0.profile.gateway) }
        guard !fresh.isEmpty else {
            present("Already set up", "Every VPN in that file is already in OFTC.")
            return
        }
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = fresh.count == 1 ? "Add this VPN to OFTC?" : "Add these \(fresh.count) VPNs to OFTC?"
        alert.informativeText = fresh.map { "\($0.profile.displayName) — \($0.profile.gateway)" }
            .joined(separator: "\n")
            + (fresh.count < incoming.count ? "\n\nVPNs you already have are left as they are." : "")
            + "\n\nYou’ll sign in to each one with your own account when you connect."
        alert.addButton(withTitle: "Add")
        alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        globalError = nil
        runCommand(["setup", "--from", url.path], for: nil) { [weak self] result in
            guard let self else { return }
            if case .failure(let failure) = result {
                self.globalError = failure.message(action: "add")
            }
            self.checkComponent()
            self.refresh()
            self.reconcile()
            if case .success = result { self.showPopover() }
        }
    }

    @objc private func exportVPNs() {
        guard preview == nil, bulkCommand == nil, !runtimes.isEmpty else { return }
        popover.performClose(nil)
        NSApp.activate(ignoringOtherApps: true)
        let panel = NSSavePanel()
        panel.title = "Export VPNs"
        panel.message = "The file includes each VPN’s gateway and key. Share it only with people who need these VPNs."
        panel.nameFieldStringValue = "OFTC VPNs.oftc"
        panel.allowedContentTypes = [UTType(exportedAs: "com.chris.openforticlient.oftc.profiles", conformingTo: .data)]
        panel.canCreateDirectories = true
        guard panel.runModal() == .OK, let destination = panel.url else { return }
        // The CLI never overwrites; export to a fresh scratch file, then replace.
        let scratch = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let staged = scratch.appendingPathComponent("export.oftc")
        do {
            try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: 0o700])
        } catch { globalError = "Could not export VPNs."; reconcile(); return }
        globalError = nil
        runCommand(["export", "-o", staged.path], for: nil) { [weak self] result in
            guard let self else { return }
            defer { try? FileManager.default.removeItem(at: scratch) }
            switch result {
            case .failure(let failure):
                self.globalError = failure.message(action: "export")
            case .success:
                do {
                    if FileManager.default.fileExists(atPath: destination.path) {
                        try FileManager.default.removeItem(at: destination)
                    }
                    try FileManager.default.copyItem(at: staged, to: destination)
                    try FileManager.default.setAttributes([.posixPermissions: 0o600],
                                                          ofItemAtPath: destination.path)
                    NSWorkspace.shared.activateFileViewerSelecting([destination])
                } catch {
                    self.globalError = "Could not save the exported file."
                }
            }
            self.reconcile()
        }
    }
    @objc private func openLoginSettings() { if preview == nil { SMAppService.openSystemSettingsLoginItems() } }

    private func quit() {
        if preview != nil { NSApp.terminate(nil); return }
        if presentation.anyActive { quitAfterStop = true; performAll(connect: false) }
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
