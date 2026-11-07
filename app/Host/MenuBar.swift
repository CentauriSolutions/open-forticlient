import AppKit
import Carbon
import Darwin
import Foundation
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
    var onUpdateDownload: (() -> Void)?
    var onUpdateSkip: (() -> Void)?
    var onAll: ((Bool) -> Void)?
    var onAddVPN: (() -> Void)?
    var onSettings: ((NSButton) -> Void)?
    var onQuit: (() -> Void)?
    var onService: (() -> Void)?
    private let serviceLabel = NSTextField(wrappingLabelWithString: "")
    private let serviceButton = NSButton(title: "Start service", target: nil, action: nil)
    private let noticeLabel = NSTextField(wrappingLabelWithString: "")
    private let updateBanner = NSStackView()
    private let updateLabel = NSTextField(labelWithString: "")
    private let rowsStack = NSStackView()
    private let emptyLabel = NSTextField(wrappingLabelWithString: "Add your VPN gateways, then connect any of them at the same time.")
    private let allControls = NSStackView()
    private let connectAll = NSButton(title: "Connect all", target: nil, action: nil)
    private let disconnectAll = NSButton(title: "Disconnect all", target: nil, action: nil)
    private let addButton = NSButton(title: "Add VPN…", target: nil, action: nil)
    private let quitButton = NSButton(title: "Quit OFTC", target: nil, action: nil)
    private var serviceRow: NSStackView?
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

        updateLabel.font = .systemFont(ofSize: 12, weight: .medium)
        let download = NSButton(title: "Download", target: self, action: #selector(updateDownloadTapped))
        download.bezelStyle = .rounded
        download.controlSize = .small
        let skip = link("Skip this version", action: #selector(updateSkipTapped))
        skip.contentTintColor = .secondaryLabelColor
        let updateButtons = NSStackView(views: [download, skip, NSView()])
        updateButtons.spacing = 10
        updateBanner.orientation = .vertical
        updateBanner.alignment = .leading
        updateBanner.spacing = 6
        updateBanner.setViews([updateLabel, updateButtons], in: .leading)
        updateBanner.isHidden = true
        add(updateBanner)

        serviceLabel.font = .systemFont(ofSize: 12, weight: .medium)
        serviceLabel.maximumNumberOfLines = 3
        serviceButton.bezelStyle = .rounded
        serviceButton.controlSize = .small
        serviceButton.target = self
        serviceButton.action = #selector(serviceTapped)
        let service = NSStackView(views: [serviceLabel, serviceButton])
        service.orientation = .vertical
        service.alignment = .leading
        service.spacing = 6
        service.isHidden = true
        serviceRow = service
        add(service)

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
        updateLabel.stringValue = presentation.update.map { "Version \($0) is available" } ?? ""
        updateBanner.isHidden = presentation.update == nil
        noticeLabel.stringValue = presentation.notice ?? ""
        noticeLabel.isHidden = presentation.notice == nil
        serviceRow?.isHidden = presentation.service.message == nil
        serviceLabel.stringValue = presentation.service.message ?? ""
        serviceButton.title = presentation.service.button ?? ""
        serviceButton.isHidden = presentation.service.button == nil
        rowsStack.alphaValue = presentation.service == .ready ? 1 : 0.5 // the last document, greyed
        emptyLabel.isHidden = !presentation.tunnels.isEmpty || presentation.service != .ready
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
        connectAll.isEnabled = !presentation.busy && presentation.service == .ready && presentation.tunnels.contains { !$0.state.active && $0.state != .setup }
        disconnectAll.isEnabled = !presentation.busy && presentation.service == .ready && presentation.anyActive
        addButton.isEnabled = !presentation.busy || presentation.anyActive
        quitButton.title = presentation.anyActive && presentation.service == .ready ? "Disconnect and Quit OFTC" : "Quit OFTC"
        quitButton.isEnabled = !presentation.busy
        view.layoutSubtreeIfNeeded()
    }

    @objc private func updateDownloadTapped() { onUpdateDownload?() }
    @objc private func updateSkipTapped() { onUpdateSkip?() }
    @objc private func connectAllTapped() { onAll?(true) }
    @objc private func disconnectAllTapped() { onAll?(false) }
    @objc private func addTapped() { onAddVPN?() }
    @objc private func showSettings(_ sender: NSButton) { onSettings?(sender) }
    @objc private func quit() { onQuit?() }
    @objc private func serviceTapped() { onService?() }
}

private extension NSBox {
    static func separator() -> NSBox {
        let box = NSBox()
        box.boxType = .separator
        return box
    }
}

// Everything the menu tracks for one profile: the host's last word about it, plus the display
// state the menu keeps itself (a stop it just asked for, the last failure, the traffic ring).
private final class TunnelRuntime {
    var profile: HostProfile
    var errorMessage: String?
    var stoppingSince: Date?
    var busy = false
    var traffic = TunnelTraffic()
    var connectedSince: Date?
    var state = MenuConnectionState.disconnected

    init(profile: HostProfile) { self.profile = profile }
}

// The menu shows what the host says (HostEdge) and asks it to act; it reads no file and
// holds no Network Extension object. Preview mode never creates the edge, so it
// reaches no host and invokes nothing.
final class OFTCMenuBar: NSObject, NSApplicationDelegate, NSPopoverDelegate, NSMenuDelegate {
    private let appID: String
    private let preview: MenuConnectionState?
    private let content = OFTCMenuViewController()
    private let popover = NSPopover()
    private let popoverDismisser = OFTCPopoverDismisser()
    private var item: NSStatusItem?
    private var timer: Timer?
    private var observers: [NSObjectProtocol] = []
    private var menuLock: Int32 = -1
    private var edge: HostEdge?
    private var edgeActive = true
    private var service = ServiceState.starting
    private var loginMenuItem = HostLoginState.notFound
    private var runtimes: [String: TunnelRuntime] = [:]
    private var order: [String] = []
    private var presentation = MenuPresentation()
    private var globalError: String?
    private var bulkBusy = false
    private var onboarding: OFTCOnboarding?
    private var componentWindow: OFTCComponentUpdate?
    /// The last component update succeeded and its window has not been closed yet.
    private var componentRunSucceeded = false
    /// The user pressed the setup button: from then on the window carries on by itself as macOS
    /// finishes each approval, until the run succeeds, fails, or the window closes.
    private var setupIntent = false
    /// The component state when a run last ended still waiting for approval; a run starts again
    /// by itself only once that state has moved.
    private var stillWaitingState: VPNComponentState?
    private var setupPoller = SetupPoller()
    /// Why the last run stopped; shown in the window until the next click.
    private var setupFailure: String?
    /// The window closed to open the Add a VPN form.
    private var componentHandoff = false
    private var updateOffer: UpdateOffer?
    private var updateTimer: Timer?
    private var updateInFlight = false
    private var quitAfterStop = false
    private let afterInstall: Bool
    private var automaticLaunch = false
    private var launchExperiencePending = true
    private var welcome: OFTCWelcome?
    private var controls: OFTCControlsWindow?
    private var welcomeIsUpgrade = false
    private var componentState = VPNComponentState.checking
    private var supportDirectory: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/\(appID)", isDirectory: true)
    }
    private var autoRepairTried = false
    private lazy var repair: OFTCSetupRepair = {
        let repair = OFTCSetupRepair()
        repair.edge = { [weak self] in self?.edge }
        repair.onChange = { [weak self] in
            self?.reconcile()
            self?.updateComponentWindow()
        }
        repair.onFinish = { [weak self] in self?.setupFinished($0) }
        return repair
    }()
    private var updateStore: UpdateStore { UpdateStore(directory: experienceStore.directory) }
    private var experienceStore: LaunchExperienceStore { LaunchExperienceStore(directory: supportDirectory) }
    private var hostBuild: String { Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "" }
    private var orderedRuntimes: [TunnelRuntime] { order.compactMap { runtimes[$0] } }
    private var configured: Bool { runtimes.values.contains { $0.state != .setup } }

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
        if preview == nil {
            DispatchQueue.global(qos: .utility).async { LauncherAlias.ensure() }
            scheduleUpdateChecks()
        }
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
        item?.button?.action = #selector(statusItemClicked)
        item?.button?.sendAction(on: [.leftMouseUp, .rightMouseUp])
        popover.behavior = OFTCWindowPolicy.popoverBehavior
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
        startEdge()
        observers.append(NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.didWakeNotification, object: nil, queue: .main) { [weak self] _ in
                self?.edge?.retryNow()
                self?.edge?.refresh()
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
        // The first document normally ends the launch wait; this is the same ten-second bound
        // the menu always had when the system does not answer.
        DispatchQueue.main.asyncAfter(deadline: .now() + 10) { [weak self] in self?.finishInitialExperience() }
        reconcile()
    }

    private func startEdge() {
        let configuration = HostEdge.Configuration(
            socketPath: HostEdge.socketPath(bundleID: appID),
            clientVersion: Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0",
            clientBuild: hostBuild)
        let created = HostEdge(configuration: configuration,
                               starter: LaunchctlStarter(label: appID + ".host", executable: Bundle.main.executableURL))
        created.onAvailability = { [weak self] availability in
            guard let self else { return }
            self.service = ServiceState(availability)
            // A restarted host numbers its traffic samples from one again.
            if availability == .ready { for runtime in self.runtimes.values { runtime.traffic.hostReconnected() } }
            self.reconcile()
        }
        created.onStatus = { [weak self] status in self?.apply(status) }
        created.onTraffic = { [weak self] event in
            guard let self, let runtime = self.runtimes[event.profile] else { return }
            runtime.traffic.ingest(event.sample, at: TrafficHistoryClock.now)
            self.reconcile()
        }
        edge = created
        created.start()
    }

    // Reconciles the runtime set with the host's document.
    private func apply(_ status: HostStatus) {
        loginMenuItem = status.login.menuItem
        componentState = VPNComponentState(status.component.state)
        updateComponentWindow()
        for profile in status.profiles {
            if let existing = runtimes[profile.id] { existing.profile = profile }
            else { runtimes[profile.id] = TunnelRuntime(profile: profile) }
            if let sample = profile.traffic { runtimes[profile.id]?.traffic.ingest(sample, at: TrafficHistoryClock.now) }
        }
        let ids = status.profiles.map(\.id)
        for id in runtimes.keys where !ids.contains(id) { runtimes[id] = nil }
        order = ids
        reconcile()
        finishInitialExperience()
        autoRepairIfNeeded()
    }

    private func configureActions(_ controller: OFTCMenuViewController) {
        controller.onAction = { [weak self] id in self?.performAction(id) }
        controller.onAutoStart = { [weak self] id, enabled in self?.setAutoStart(id, enabled) }
        controller.onRemove = { [weak self] id in self?.removeProfile(id) }
        controller.onUpdateDownload = { [weak self] in self?.downloadUpdate() }
        controller.onUpdateSkip = { [weak self] in self?.skipUpdate() }
        controller.onAll = { [weak self] connect in self?.performAll(connect: connect) }
        controller.onAddVPN = { [weak self] in self?.showSetup() }
        controller.onSettings = { [weak self] button in self?.showSettings(button) }
        controller.onQuit = { [weak self] in self?.quit() }
        controller.onService = { [weak self] in self?.serviceAction() }
    }

    // The application menu, shown while a window is open, carries the same options as the gear
    // button, rebuilt each time it opens so its checkmarks are current.
    private func installApplicationMenu() {
        let main = NSMenu()
        let root = NSMenuItem()
        let application = NSMenu(title: "OFTC")
        application.delegate = self
        application.autoenablesItems = false
        root.submenu = application
        main.addItem(root)
        NSApp.mainMenu = main
        menuNeedsUpdate(application)
    }

    func menuNeedsUpdate(_ menu: NSMenu) {
        menu.removeAllItems()
        populateOptions(menu)
        menu.addItem(.separator())
        let stopsTunnels = presentation.anyActive && presentation.service == .ready
        let quit = NSMenuItem(title: stopsTunnels ? "Disconnect and Quit OFTC" : "Quit OFTC",
                              action: #selector(quitFromApplicationMenu), keyEquivalent: "q")
        quit.target = self
        menu.addItem(quit)
    }

    @objc private func quitFromApplicationMenu() { quit() }

    private func restoreAccessoryPolicyIfNeeded() {
        if welcome?.window?.isVisible != true && controls?.window?.isVisible != true && onboarding == nil
            && componentWindow == nil {
            NSApp.setActivationPolicy(.accessory)
        }
    }

    private func acquireMenuLock() -> Bool {
        let directory = supportDirectory
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: 0o700])
        } catch { return false }
        menuLock = open(directory.appendingPathComponent("menu.lock").path,
                        O_RDWR | O_CREAT | O_NOFOLLOW, 0o600)
        return menuLock >= 0 && flock(menuLock, LOCK_EX | LOCK_NB) == 0
    }

    private func finishInitialExperience() {
        guard launchExperiencePending, preview == nil else { return }
        launchExperiencePending = false
        if !automaticLaunch { showLaunchExperience(forceWelcome: afterInstall) }
    }

    // The edge retries only while something of the menu is on screen, except while the first
    // document is awaited: at login the menu and the host start together, and the status item
    // must not stay stale because the host was a second late.
    private func tick() {
        let visible = popover.isShown || controls?.window?.isVisible == true
            || welcome?.window?.isVisible == true || onboarding != nil || componentWindow != nil
            || launchExperiencePending
        if visible != edgeActive { edgeActive = visible; edge?.setActive(visible) }
        reconcile()
        continueSetup()
    }

    private func tunnelPresentation(_ runtime: TunnelRuntime) -> TunnelPresentation {
        let profile = runtime.profile
        let hostState = MenuConnectionState(profile.state)
        if let since = runtime.stoppingSince {
            // The host's document is the truth that ends the optimistic "Disconnecting".
            if [.disconnected, .setup, .attention].contains(hostState) {
                runtime.stoppingSince = nil
            } else if Date().timeIntervalSince(since) > 20 {
                runtime.stoppingSince = nil
                quitAfterStop = false
                runtime.errorMessage = "Could not confirm disconnection. Check VPN settings."
            }
        }
        var state = runtime.stoppingSince != nil ? MenuConnectionState.disconnecting : hostState
        if runtime.errorMessage != nil && !state.active { state = .attention }
        runtime.state = state
        let since = profile.connectedDate
        if runtime.connectedSince != since || state != .connected {
            runtime.connectedSince = since
            runtime.traffic.clear()
        }
        let now = TrafficHistoryClock.now
        runtime.traffic.pruneHistory(now: now)
        var row = TunnelPresentation(id: profile.id, name: profile.name)
        row.state = state
        row.description = state.detail
        row.autoStart = profile.autoStart
        row.busy = runtime.busy || bulkBusy || onboarding != nil || service != .ready || repair.isWorking
            || (componentState == .checking && !state.active)
        let place = "\(profile.gateway) · \(profile.transport.uppercased())"
        if state == .disconnected { row.description = place }
        if !state.active && state != .setup && componentState != .ready {
            row.description = componentState.detail
        }
        if state == .connected {
            row.description = place
            row.duration = TrafficFormat.duration(since: profile.connectedDate)
            if let receivedAt = runtime.traffic.receivedAt, Date().timeIntervalSince(receivedAt) > 3 {
                runtime.traffic.markStale(at: now)
            }
            row.receiving = TrafficFormat.rate(runtime.traffic.receiving)
            row.sending = TrafficFormat.rate(runtime.traffic.sending)
            row.history = runtime.traffic.history.points
            row.historyTime = now
            if let sample = runtime.traffic.latest {
                row.totals = TrafficFormat.bytes(Double(sample.rxBytes)) + " / " + TrafficFormat.bytes(Double(sample.txBytes))
            }
        }
        if state == .setup, let text = repair.statusText { row.description = text }
        // Why the last attempt failed, in the host's words (#104); a failed request of this
        // session's own, below, is newer and wins.
        if let reason = profile.error, !state.active { row.description = reason.detail }
        if let message = runtime.errorMessage { row.description = message }
        return row
    }

    private func reconcile() {
        var next = MenuPresentation()
        next.service = service
        next.tunnels = orderedRuntimes.map(tunnelPresentation)
        // The host being down greys the rows and the bulk buttons, not Add VPN: setup works without it.
        next.busy = bulkBusy || onboarding != nil || repair.isWorking
        next.notice = globalError
        next.update = updateOffer.flatMap { updateStore.shouldShow($0) ? $0.version : nil }
        presentation = next
        if quitAfterStop, !presentation.anyActive, runtimes.values.allSatisfy({ $0.stoppingSince == nil }) {
            NSApp.terminate(nil)
            return
        }
        updateView()
        updateWelcome()
    }

    // After something the host does not watch (the setup window, a wake): a fresh document.
    private func refresh() { edge?.refresh() }

    // What a failed request to the host means for the menu: a typed code picks the text.
    private func fail(_ error: HostError, action: String) -> String {
        MenuCommandFailure(error).message(action: action)
    }

    private func send(_ op: String, _ args: [String: Any] = [:], timeout: TimeInterval? = nil,
                      completion: @escaping (Result<Data, HostError>) -> Void) {
        guard let edge else { completion(.failure(.local(.hostUnavailable, "no host in preview"))); return }
        edge.request(op, args: args, timeout: timeout, completion: completion)
    }

    private func serviceAction() {
        if service == .needsApproval {
            if let url = URL(string: "x-apple.systempreferences:com.apple.LoginItems-Settings.extension") {
                NSWorkspace.shared.open(url)
            }
        }
        edge?.retryNow(startService: service == .notRunning)
    }

    private func showLaunchExperience(forceWelcome: Bool = false) {
        guard preview == nil else { showPopover(); return }
        if let onboarding { onboarding.show(); return }
        if let componentWindow { componentWindow.show(); return }
        if welcome != nil { updateWelcome(); welcome?.present(); return }
        if experienceStore.shouldWelcome(build: hostBuild, automatic: false, afterInstall: forceWelcome) {
            showWelcome()
        } else { showControlsWindow() }
    }

    private func updateWelcome() {
        welcome?.update(WelcomePresentation(upgrade: welcomeIsUpgrade,
            configured: configured, active: presentation.anyActive, component: componentState,
            profilesExist: !runtimes.isEmpty))
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
                    self.startSetup()
                case .controls:
                    guard self.presentation.anyActive || self.componentState == .ready else { return }
                    self.welcome?.close()
                    DispatchQueue.main.async { [weak self] in self?.showControlsWindow() }
                case .check: self.edge?.retryNow(); self.refresh()
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
    }

    private func updateView() {
        content.update(presentation)
        controls?.update(presentation)
        popover.contentSize = content.view.fittingSize
        item?.button?.image = TunnelMenuIcon.image(connected: presentation.anyConnected,
                                                   attention: presentation.anyAttention)
        item?.button?.toolTip = "OFTC VPN: " + presentation.summary
        item?.button?.setAccessibilityLabel("OFTC VPN: " + presentation.summary)
    }

    // Left click toggles the popover; right or control click opens the same options menu as the
    // gear button.
    @objc private func statusItemClicked() {
        let event = NSApp.currentEvent
        if event?.type == .rightMouseUp || event?.modifierFlags.contains(.control) == true {
            guard let button = item?.button else { return }
            popover.performClose(nil)
            let menu = NSMenu()
            populateOptions(menu)
            menu.popUp(positioning: nil, at: NSPoint(x: 0, y: button.bounds.maxY + 4), in: button)
        } else {
            togglePopover()
        }
    }

    func popoverDidClose(_ notification: Notification) { popoverDismisser.stop() }

    private func togglePopover() {
        if popover.isShown { popover.performClose(nil) }
        else { showPopover() }
    }

    private func showPopover() {
        guard let button = item?.button else { return }
        controls?.window?.orderOut(nil)
        if onboarding == nil && componentWindow == nil && welcome?.window?.isVisible != true {
            NSApp.setActivationPolicy(.accessory)
        }
        NSApp.activate(ignoringOtherApps: true)
        popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
        popoverDismisser.start(closing: popover)
        edge?.retryNow()
    }

    private func performAction(_ id: String) {
        if preview != nil {
            guard let index = presentation.tunnels.firstIndex(where: { $0.id == id }) else { return }
            presentation.tunnels[index].state = presentation.tunnels[index].state.active ? .disconnected : .connected
            updateView()
            return
        }
        guard let runtime = runtimes[id] else { return }
        if runtime.state == .setup { startSetup(); return }
        if !runtime.state.active && componentState != .ready { showWelcome(); return }
        guard !runtime.busy, !bulkBusy, service == .ready else { return }
        let disconnect = runtime.state.active
        runtime.errorMessage = nil
        globalError = nil
        if disconnect { runtime.stoppingSince = Date() }
        runtime.busy = true
        reconcile()
        send(disconnect ? "disconnect" : "connect", ["profile": id]) { [weak self, weak runtime] result in
            guard let self, let runtime else { return }
            runtime.busy = false
            if case .failure(let error) = result {
                runtime.stoppingSince = nil
                self.quitAfterStop = false
                runtime.errorMessage = self.fail(error, action: disconnect ? "disconnect" : "connect")
            }
            self.refresh()
            self.reconcile()
        }
    }

    private func performAll(connect: Bool) {
        guard preview == nil, !bulkBusy else { return }
        if service != .ready {
            // With the host down nothing can be stopped from here, and Quit must not hang.
            if quitAfterStop { NSApp.terminate(nil) }
            return
        }
        if connect && componentState != .ready { showWelcome(); return }
        globalError = nil
        if !connect { for runtime in runtimes.values where runtime.state.active { runtime.stoppingSince = Date() } }
        bulkBusy = true
        reconcile()
        send(connect ? "connect" : "disconnect") { [weak self] result in
            guard let self else { return }
            self.bulkBusy = false
            if case .failure(let error) = result {
                for runtime in self.runtimes.values { runtime.stoppingSince = nil }
                self.quitAfterStop = false
                self.globalError = self.fail(error, action: connect ? "connect" : "disconnect")
            }
            self.refresh()
            self.reconcile()
        }
    }

    private func removeProfile(_ id: String) {
        guard preview == nil, let runtime = runtimes[id], !runtime.busy, !bulkBusy, service == .ready else { return }
        let name = runtime.profile.name
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
        runtime.busy = true
        reconcile()
        // The host stops the profile, waits up to 20 s for its tunnel, then erases it.
        send("remove", ["profile": id], timeout: 60) { [weak self, weak runtime] result in
            guard let self else { return }
            runtime?.busy = false
            if case .failure(let error) = result, let runtime {
                runtime.stoppingSince = nil
                runtime.errorMessage = self.fail(error, action: "remove")
            }
            self.refresh()
            self.reconcile()
        }
    }

    private func setAutoStart(_ id: String, _ enabled: Bool) {
        guard preview == nil, let runtime = runtimes[id], service == .ready else { return }
        send("settings_set", ["key": "auto_start:" + id, "value": enabled]) { [weak self, weak runtime] result in
            guard let self, let runtime else { return }
            switch result {
            case .success: runtime.errorMessage = nil
            case .failure:
                runtime.errorMessage = "Could not change automatic connection. Check Login Items & Extensions in System Settings."
            }
            self.refresh() // the document carries the stored choice, success or not
            self.reconcile()
        }
    }

    // The Add VPN form: only for a VPN that does not exist yet. Finishing the profiles that do
    // exist is the component window (`showComponentUpdate`), which has no form.
    private func showSetup() {
        guard preview == nil, let edge else { return }
        guard componentState != .newer else { showWelcome(); return }
        // Adding a VPN is fine beside live tunnels; replacing the provider is not.
        guard !(presentation.anyActive && componentState == .updateRequired) else { showWelcome(); return }
        popover.performClose(nil)
        controls?.window?.orderOut(nil)
        welcome?.window?.orderOut(nil)
        if onboarding == nil {
            // The first profile turns "OFTC at login" on, once (the host decides; it only
            // does so when this setup left a profile behind, and never again after a choice).
            let firstSetup = runtimes.isEmpty
            onboarding = OFTCOnboarding(edge: edge) { [weak self] in
                DispatchQueue.main.async { [weak self] in
                    guard let self else { return }
                    self.onboarding = nil
                    self.globalError = nil
                    if firstSetup {
                        self.send("menu_login_default", ["first_setup": true]) { [weak self] _ in self?.refresh() }
                    }
                    self.edge?.retryNow()
                    self.refresh()
                    self.showWelcome()
                }
            }
        }
        onboarding?.show()
        reconcile()
    }

    // `fromSetup`: opened by the first-run or Set up… flow, which returns to Welcome when closed;
    // from the options menu it just closes.
    private func showComponentUpdate(fromSetup: Bool = false) {
        guard preview == nil else { return }
        popover.performClose(nil)
        controls?.window?.orderOut(nil)
        welcome?.window?.orderOut(nil)
        if componentWindow == nil {
            componentWindow = OFTCComponentUpdate(
                onRun: { [weak self] in self?.setupStep() },
                onSettings: { [weak self] pane in self?.edge?.openSettings(pane) },
                onClose: { [weak self] in
                    DispatchQueue.main.async { [weak self] in
                        guard let self else { return }
                        let succeeded = self.componentRunSucceeded
                        let handedOff = self.componentHandoff
                        self.componentHandoff = false
                        self.setupFailure = nil
                        self.setupIntent = false
                        self.componentWindow = nil
                        self.componentRunSucceeded = false
                        // Decide from the status the host reports now, not from what was captured
                        // before the run: only then is "Set up" never offered for a ready VPN.
                        let decide = { [weak self] in
                            guard let self else { return }
                            if WelcomeAfterComponentWindow.shouldShow(fromSetup: fromSetup, succeeded: succeeded,
                                                                      configured: self.configured, component: self.componentState,
                                                                      handedOff: handedOff) {
                                self.showWelcome()
                            } else { self.restoreAccessoryPolicyIfNeeded() }
                        }
                        if let edge = self.edge { edge.refresh(completion: { _ in decide() }) } else { decide() }
                    }
                })
        }
        updateComponentWindow()
        componentWindow?.show()
        // Reopening fetches at once (the poller does so after any hidden tick): the document shown is
        // the host's now, not the last one cached.
    }

    fileprivate func updateComponentWindow() {
        componentWindow?.update(ComponentUpdatePresentation(
            status: edge?.lastStatus, phase: repair.phase, anyActive: presentation.anyActive,
            succeeded: componentRunSucceeded, service: service, failure: setupFailure))
    }

    private func showSettings(_ sender: NSButton) {
        let menu = NSMenu()
        populateOptions(menu)
        menu.popUp(positioning: nil, at: NSPoint(x: 0, y: sender.bounds.maxY), in: sender)
    }

    private var appVersion: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0"
    }

    private var detailsLine: String {
        AboutDetails.line(appVersion: appVersion, appBuild: hostBuild, status: service == .ready ? edge?.lastStatus : nil)
    }

    // The one options menu: About with its Details line, then login, updates, adding and exporting
    // VPNs, the VPN component, and Login Items. The gear button, a right click on the status item
    // and the application menu all show it.
    private func populateOptions(_ menu: NSMenu) {
        let ready = preview == nil && !bulkBusy && service == .ready
        func add(_ title: String, action: Selector, checked: Bool? = nil, needsHost: Bool = true) {
            let item = NSMenuItem(title: title, action: action, keyEquivalent: "")
            item.target = self
            if let checked { item.state = checked ? .on : .off }
            item.isEnabled = needsHost ? ready : (preview == nil && !bulkBusy)
            menu.addItem(item)
        }
        menu.autoenablesItems = false
        add("About OFTC", action: #selector(showAbout), needsHost: false)
        let details = NSMenuItem(title: detailsLine, action: nil, keyEquivalent: "")
        details.isEnabled = false
        menu.addItem(details)
        menu.addItem(.separator())
        add("Launch OFTC at login", action: #selector(toggleMenuLogin),
            checked: preview == nil && loginMenuItem == .enabled)
        add("Check for Updates Automatically", action: #selector(toggleAutoUpdates),
            checked: preview == nil && updateStore.automatic, needsHost: false)
        add("Check for Updates Now…", action: #selector(checkUpdatesNow))
        menu.addItem(.separator())
        add("Add VPN…", action: #selector(openSetup), needsHost: false)
        add("Export VPNs…", action: #selector(exportVPNs))
        menu.items.last?.isEnabled = ready && !runtimes.isEmpty
        add("VPN Component…", action: #selector(openComponent), needsHost: false)
        add("Login Items & Extensions…", action: #selector(openLoginSettings))
    }

    @objc private func showAbout() {
        NSApp.activate(ignoringOtherApps: true)
        let credits = NSAttributedString(string: detailsLine, attributes: [
            .font: NSFont.systemFont(ofSize: 11), .foregroundColor: NSColor.secondaryLabelColor])
        NSApp.orderFrontStandardAboutPanel(options: [.credits: credits, .applicationName: "OFTC"])
    }

    @objc private func openComponent() { showComponentUpdate() }

    @objc private func toggleMenuLogin() {
        guard preview == nil else { return }
        send("settings_set", ["key": "menu_login", "value": loginMenuItem != .enabled]) { [weak self] result in
            guard let self else { return }
            switch result {
            case .success: self.globalError = nil
            case .failure:
                self.globalError = "Could not change login launch. Check Login Items & Extensions in System Settings."
            }
            self.refresh()
            self.reconcile()
        }
    }
    @objc private func openSetup() { showSetup() }

    // MARK: Updates

    private var installedCopy: Bool {
        Bundle.main.bundleURL.standardizedFileURL.path == LauncherAlias.installedApp.path
    }

    // The host fetches the feed (`check_update`); a build with no feed configured has nothing to
    // ask, and says so when the user asks.
    private var updatesConfigured: Bool {
        (Bundle.main.object(forInfoDictionaryKey: "OFTCUpdateFeedURL") as? String)?.hasPrefix("https://") == true
    }

    private func scheduleUpdateChecks() {
        guard installedCopy, updatesConfigured else { return }
        // Not at the instant of login; then hourly, but at most once a day.
        DispatchQueue.main.asyncAfter(deadline: .now() + 30) { [weak self] in self?.checkIfDue() }
        updateTimer = Timer.scheduledTimer(withTimeInterval: 3600, repeats: true) { [weak self] _ in
            self?.checkIfDue()
        }
    }

    private func checkIfDue() {
        guard preview == nil, updateStore.isDue() else { return }
        checkForUpdates(manual: false)
    }

    private func checkForUpdates(manual: Bool) {
        guard preview == nil, !updateInFlight else { return }
        guard updatesConfigured else {
            if manual { present("Updates aren’t set up", "This build has no update feed configured.") }
            return
        }
        guard let edge else { return }
        let current = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0"
        updateInFlight = true
        edge.checkUpdate { [weak self] result in
            guard let self else { return }
            self.updateInFlight = false
            switch result {
            case .success(let found):
                self.updateStore.markChecked()
                self.updateOffer = found.available.flatMap { UpdateOffer($0) }
                self.reconcile()
                if manual { self.reportManualCheck(self.updateOffer, current: current) }
            case .failure(let error):
                if manual {
                    let text = error.code == .hostUnavailable ? "OFTC’s VPN service is not running. Choose Start service, then try again."
                        : "Check your connection and try again."
                    self.present("Couldn’t check for updates", text)
                }
            }
        }
    }

    private func reportManualCheck(_ offer: UpdateOffer?, current: String) {
        guard let offer else {
            present("You’re up to date", "Open Forticlient \(current) is the latest version.")
            return
        }
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = "Version \(offer.version) is available"
        alert.informativeText = "You have \(current). Download opens the release page; install it like the first time. "
            + "Disconnect your VPNs first, because an update briefly stops them."
        alert.addButton(withTitle: "Download")
        alert.addButton(withTitle: "Later")
        if alert.runModal() == .alertFirstButtonReturn { NSWorkspace.shared.open(offer.page) }
    }

    private func downloadUpdate() {
        guard let offer = updateOffer else { return }
        popover.performClose(nil)
        NSWorkspace.shared.open(offer.page)
    }

    private func skipUpdate() {
        guard let offer = updateOffer else { return }
        updateStore.skip(offer.version)
        reconcile()
    }

    @objc private func toggleAutoUpdates() {
        let store = updateStore
        store.automatic = !store.automatic
    }

    @objc private func checkUpdatesNow() { checkForUpdates(manual: true) }

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

    // The host parses the file (it holds PSKs). This process only copies the user's file into a
    // private scratch directory first, so the same process as before is the one that reads from
    // wherever the user keeps it, and hands the host a path it can always open.
    private func scratchDirectory() throws -> URL {
        let scratch = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        return scratch
    }

    private func importProfiles(from url: URL) {
        guard !bulkBusy, !repair.isRunning, service == .ready else {
            present("OFTC is busy", "Try opening the file again in a moment.")
            return
        }
        popover.performClose(nil)
        let scratch: URL
        let staged: URL
        do {
            scratch = try scratchDirectory()
            staged = scratch.appendingPathComponent("import.oftc")
            try FileManager.default.copyItem(at: url, to: staged)
        } catch {
            present("Can’t add these VPNs", "OFTC couldn’t read that file.")
            return
        }
        bulkBusy = true
        reconcile()
        send("import_preview", ["path": staged.path]) { [weak self] result in
            guard let self else { return }
            self.bulkBusy = false
            self.reconcile()
            switch result {
            case .failure(let error):
                try? FileManager.default.removeItem(at: scratch)
                // `invalid_file` carries the reason in words ("That file isn't an OFTC profile file").
                let reason = error.code == .invalidFile ? error.detail : "OFTC couldn’t read that file"
                self.present("Can’t add these VPNs", reason.hasSuffix(".") ? reason : reason + ".")
            case .success(let data):
                guard let preview = try? HostWire.decoder.decode(HostImportPreview.self, from: data) else {
                    try? FileManager.default.removeItem(at: scratch)
                    self.present("Can’t add these VPNs", "OFTC couldn’t read that file.")
                    return
                }
                self.confirmImport(preview.profiles, staged: staged, scratch: scratch)
            }
        }
    }

    private func confirmImport(_ incoming: [HostImportItem], staged: URL, scratch: URL) {
        let fresh = incoming.filter { !$0.alreadyConfigured }
        guard !fresh.isEmpty else {
            try? FileManager.default.removeItem(at: scratch)
            present("Already set up", "Every VPN in that file is already in OFTC.")
            return
        }
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = fresh.count == 1 ? "Add this VPN to OFTC?" : "Add these \(fresh.count) VPNs to OFTC?"
        alert.informativeText = fresh.map { "\($0.name) — \($0.gateway)" }
            .joined(separator: "\n")
            + (fresh.count < incoming.count ? "\n\nVPNs you already have are left as they are." : "")
            + "\n\nYou’ll sign in to each one with your own account when you connect."
        alert.addButton(withTitle: "Add")
        alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else {
            try? FileManager.default.removeItem(at: scratch)
            return
        }
        globalError = nil
        bulkBusy = true
        reconcile()
        send("import", ["path": staged.path], timeout: 60) { [weak self] result in
            guard let self else { return }
            try? FileManager.default.removeItem(at: scratch)
            self.bulkBusy = false
            if case .failure(let error) = result {
                self.globalError = self.fail(error, action: "add")
            }
            self.refresh()
            self.reconcile()
            if case .success = result { self.showPopover() }
        }
    }

    @objc private func exportVPNs() {
        guard preview == nil, !bulkBusy, !runtimes.isEmpty, service == .ready else { return }
        popover.performClose(nil)
        NSApp.activate(ignoringOtherApps: true)
        let panel = NSSavePanel()
        panel.title = "Export VPNs"
        panel.message = "The file includes each VPN’s gateway and key. Share it only with people who need these VPNs."
        panel.nameFieldStringValue = "OFTC VPNs.oftc"
        panel.allowedContentTypes = [UTType(exportedAs: "com.chris.openforticlient.oftc.profiles", conformingTo: .data)]
        panel.canCreateDirectories = true
        guard panel.runModal() == .OK, let destination = panel.url else { return }
        // The host never overwrites; it exports to a fresh scratch file, then this replaces.
        let scratch: URL
        do { scratch = try scratchDirectory() } catch { globalError = "Could not export VPNs."; reconcile(); return }
        let staged = scratch.appendingPathComponent("export.oftc")
        globalError = nil
        bulkBusy = true
        reconcile()
        send("export", ["path": staged.path]) { [weak self] result in
            guard let self else { return }
            defer { try? FileManager.default.removeItem(at: scratch) }
            self.bulkBusy = false
            switch result {
            case .failure(let error):
                self.globalError = self.fail(error, action: "export")
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

    @objc private func openLoginSettings() {
        guard preview == nil else { return }
        send("open_settings", ["pane": "login_items"]) { _ in }
    }

    private func quit() {
        if preview != nil { NSApp.terminate(nil); return }
        // With the host down nothing can be stopped from here: the tunnels outlive the menu, so
        // quit rather than wait for a reply that cannot come.
        if presentation.anyActive && service == .ready { quitAfterStop = true; performAll(connect: false) }
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

// Issue 88: finishing setup for profiles that already exist, with no form.
//
// The decision reads the host's document (profile count, per-profile `setup` state, component
// state). The repair is the host's `component_update` (keys, system extension, each VPN entry);
// a profile with no saved key comes back as `psk_unavailable` with its id, the key is asked for
// here and stored by the host's own verb (HostPSK), and the repair runs again.
extension OFTCMenuBar {
    private func setupPlan() -> SetupPlan {
        let profiles = orderedRuntimes.map(\.profile)
        return SetupPlan.decide(
            hostReady: service == .ready,
            profileCount: profiles.count,
            component: componentState,
            entriesMissing: profiles.contains { $0.state == .setup },
            anyActive: presentation.anyActive)
    }

    fileprivate func startSetup() {
        guard preview == nil else { return }
        if repair.isRunning {
            // Never silent: bring the window that shows the progress back.
            showComponentUpdate(fromSetup: true)
            if repair.phase == .waiting { repair.reopenSettings() }
            return
        }
        switch SetupEntry.route(setupPlan()) {
        case .form: showSetup()
        case .window:
            // The service is the first item of the checklist: show it, and act on it now.
            showComponentUpdate(fromSetup: true)
            setupStep()
        case .welcome: showWelcome()
        case .refresh: refresh()
        }
    }

    fileprivate func runRepair() {
        globalError = nil
        componentRunSucceeded = false
        stillWaitingState = nil
        setupFailure = nil
        repair.start()
        updateComponentWindow()
    }

    /// The setup button: the step that is next. The service first (start it, or open Login Items
    /// for its approval), then the host's component update, or the Add a VPN form when there is no
    /// VPN yet; the window continues by itself.
    fileprivate func setupStep() {
        setupIntent = true
        setupFailure = nil
        perform(SetupContinuation.step(service: service, plan: setupPlan()))
        updateComponentWindow()
    }

    private func perform(_ step: SetupContinuation.Step) {
        switch step {
        case .startService: serviceAction()
        case .runUpdate: runRepair()
        case .openForm:
            // The form is the next window, not a component update: hand over, and Welcome stays shut.
            componentHandoff = true
            componentWindow?.close()
            showSetup()
        case .wait: break
        }
    }

    /// Once per second while the window is open: fetch the host's document (macOS finishing an
    /// approval is not an event the host reports) with one request in flight, back off when it is
    /// slow, refresh the checklist, and carry on by itself after the button.
    private func continueSetup() {
        let visible = componentWindow != nil && preview == nil
        if setupPoller.tick(visible: visible && service == .ready) {
            edge?.refresh { [weak self] ok in self?.setupPoller.finished(ok: ok) }
        }
        guard visible else { return }
        updateComponentWindow()
        if let step = SetupContinuation.automatic(
            intent: setupIntent, running: repair.isRunning, service: service, plan: setupPlan(),
            phase: repair.phase, component: componentState, waitedAt: stillWaitingState) {
            perform(step)
        }
    }

    fileprivate func autoRepairIfNeeded() {
        guard preview == nil, !repair.isRunning,
              SetupPlan.mayAutoRepair(component: componentState, automaticLaunch: automaticLaunch,
                                      alreadyTried: autoRepairTried),
              setupPlan() == .repair
        else { return }
        autoRepairTried = true
        showComponentUpdate(fromSetup: true)
        setupIntent = true
        runRepair()
    }

    fileprivate func setupFinished(_ outcome: SetupOutcome) {
        switch outcome {
        case .failure(let failure):
            globalError = failure.message(action: "set up")
            setupFailure = (globalError ?? "") + " Choose Finish setup to try again."
            setupIntent = false
        case .needsKey(let id): askForKey(profileID: id); setupIntent = false
        case .done: globalError = nil; componentRunSucceeded = componentWindow != nil; setupIntent = false
        case .waitingForApproval: globalError = nil; stillWaitingState = componentState
        }
        refresh()
        reconcile()
        updateComponentWindow()
    }

    private func askForKey(profileID: String?) {
        guard let id = profileID, let profile = runtimes[id]?.profile,
              var psk = OFTCKeyPrompt.ask(name: profile.name, gateway: profile.gateway) else {
            globalError = "Setup needs the VPN key. Choose Set up… to enter it."
            setupFailure = "Setup needs the VPN key. Choose Finish setup to enter it."
            updateComponentWindow()
            return
        }
        let executable = Bundle.main.executableURL
        let typed = psk
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let stored = HostPSK.store(typed, gateway: profile.gateway, executable: executable)
            DispatchQueue.main.async {
                guard let self else { return }
                if stored { self.runRepair() }
                else {
                    self.globalError = "Could not save the VPN key. Check Keychain access and try again."
                    self.setupFailure = "Could not save the VPN key. Check Keychain access, then choose Finish setup to try again."
                    self.reconcile()
                    self.updateComponentWindow()
                }
            }
        }
        psk.resetBytes(in: 0..<psk.count)
    }
}
