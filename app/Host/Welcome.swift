import AppKit

private final class WelcomeBackground: NSView {
    override var isOpaque: Bool { true }
    override func draw(_ dirtyRect: NSRect) {
        NSColor.windowBackgroundColor.setFill()
        bounds.fill()
    }
}

final class OFTCWelcome: NSWindowController, NSWindowDelegate {
    var onAction: ((WelcomePresentation.Action) -> Void)?
    var onDismiss: (() -> Void)?
    private let titleLabel = NSTextField(labelWithString: "")
    private let headingLabel = NSTextField(labelWithString: "")
    private let detailLabel = NSTextField(wrappingLabelWithString: "")
    private let actionButton = NSButton(title: "", target: nil, action: nil)
    private var action: WelcomePresentation.Action = .wait

    init() {
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 500, height: 430),
                              styleMask: [.titled, .closable], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        window.title = "OFTC"
        super.init(window: window)
        window.delegate = self
        let content = WelcomeBackground()
        window.contentView = content
        let stack = NSStackView()
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 18
        stack.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 28),
            stack.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -28),
            stack.topAnchor.constraint(equalTo: content.topAnchor, constant: 24),
            stack.bottomAnchor.constraint(equalTo: content.bottomAnchor, constant: -22),
        ])
        func add(_ view: NSView) {
            stack.addArrangedSubview(view)
            view.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true
        }
        let icon = NSImageView(image: NSImage(contentsOf: Bundle.main.resourceURL!
            .appendingPathComponent("OFTC.icns")) ?? NSImage())
        icon.imageScaling = .scaleProportionallyUpOrDown
        icon.widthAnchor.constraint(equalToConstant: 48).isActive = true
        icon.heightAnchor.constraint(equalToConstant: 48).isActive = true
        titleLabel.font = .systemFont(ofSize: 23, weight: .semibold)
        let subtitle = NSTextField(labelWithString: "VPN controls, always within reach.")
        subtitle.font = .systemFont(ofSize: 13)
        subtitle.textColor = .secondaryLabelColor
        let labels = NSStackView(views: [titleLabel, subtitle])
        labels.orientation = .vertical
        labels.alignment = .leading
        labels.spacing = 4
        let header = NSStackView(views: [icon, labels, NSView()])
        header.spacing = 14
        add(header)

        let tunnel = NSImageView(image: TunnelMenuIcon.image(connected: true))
        tunnel.setAccessibilityLabel("OFTC tunnel menu bar icon")
        tunnel.widthAnchor.constraint(equalToConstant: 24).isActive = true
        let location = NSTextField(wrappingLabelWithString:
            "Use this tunnel icon at the top of your screen for connection and traffic controls. Open OFTC from Applications for the same controls in a window.")
        location.font = .systemFont(ofSize: 13)
        let hint = NSStackView(views: [tunnel, location])
        hint.spacing = 14
        hint.edgeInsets = NSEdgeInsets(top: 14, left: 16, bottom: 14, right: 16)
        let box = NSBox()
        box.boxType = .custom
        box.borderColor = .separatorColor
        box.cornerRadius = 9
        box.contentViewMargins = .zero
        box.contentView = hint
        add(box)
        hint.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            hint.leadingAnchor.constraint(equalTo: box.leadingAnchor),
            hint.trailingAnchor.constraint(equalTo: box.trailingAnchor),
            hint.topAnchor.constraint(equalTo: box.topAnchor),
            hint.bottomAnchor.constraint(equalTo: box.bottomAnchor),
        ])

        headingLabel.font = .systemFont(ofSize: 16, weight: .semibold)
        detailLabel.font = .systemFont(ofSize: 13)
        detailLabel.textColor = .secondaryLabelColor
        let next = NSStackView(views: [headingLabel, detailLabel])
        next.orientation = .vertical
        next.alignment = .leading
        next.spacing = 7
        add(next)
        detailLabel.widthAnchor.constraint(equalTo: next.widthAnchor).isActive = true
        let note = NSTextField(wrappingLabelWithString:
            "You choose when to connect. Opening OFTC and completing setup won't start browser sign-in.")
        note.font = .systemFont(ofSize: 11)
        note.textColor = .secondaryLabelColor
        add(note)
        let later = NSButton(title: "Later", target: self, action: #selector(dismiss))
        later.bezelStyle = .rounded
        actionButton.target = self
        actionButton.action = #selector(performAction)
        actionButton.bezelStyle = .rounded
        actionButton.keyEquivalent = "\r"
        let buttons = NSStackView(views: [later, NSView(), actionButton])
        add(buttons)
        window.setContentSize(NSSize(width: 500, height: content.fittingSize.height))
        window.center()
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    func update(_ presentation: WelcomePresentation) {
        titleLabel.stringValue = presentation.title
        headingLabel.stringValue = presentation.heading
        detailLabel.stringValue = presentation.detail
        actionButton.title = presentation.button
        actionButton.isEnabled = presentation.action != .wait
        action = presentation.action
        window?.contentView?.layoutSubtreeIfNeeded()
        if let content = window?.contentView {
            window?.setContentSize(NSSize(width: 500, height: max(360, content.fittingSize.height)))
        }
    }

    func present() {
        NSApp.setActivationPolicy(.regular)
        showWindow(nil)
        window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    @objc private func performAction() { onAction?(action) }
    @objc private func dismiss() { close() }
    func windowWillClose(_ notification: Notification) { onDismiss?() }

    static func renderPreviews(to directory: URL) throws {
        let samples: [(String, WelcomePresentation)] = [
            ("fresh", .init(upgrade: false, configured: false, active: false, component: .missing)),
            ("upgrade", .init(upgrade: true, configured: true, active: false, component: .updateRequired)),
            ("ready", .init(upgrade: true, configured: true, active: false, component: .ready)),
            ("approval", .init(upgrade: true, configured: true, active: false, component: .approval)),
            ("active", .init(upgrade: true, configured: true, active: true, component: .updateRequired)),
            ("checking", .init(upgrade: true, configured: true, active: false, component: .checking)),
            ("unavailable", .init(upgrade: true, configured: true, active: false, component: .unavailable)),
            ("newer", .init(upgrade: true, configured: true, active: false, component: .newer)),
        ]
        for appearance in [NSAppearance.Name.aqua, .darkAqua] {
            for (name, presentation) in samples {
                var output: Data?
                NSAppearance(named: appearance)!.performAsCurrentDrawingAppearance {
                    let controller = OFTCWelcome()
                    controller.window?.appearance = NSAppearance(named: appearance)
                    controller.update(presentation)
                    if let view = controller.window?.contentView {
                        view.layoutSubtreeIfNeeded()
                        if let bitmap = view.bitmapImageRepForCachingDisplay(in: view.bounds) {
                            view.cacheDisplay(in: view.bounds, to: bitmap)
                            output = bitmap.representation(using: .png, properties: [:])
                        }
                    }
                    controller.close()
                }
                guard let output else { throw NSError(domain: "OFTCWelcomePreview", code: 1) }
                try output.write(to: directory.appendingPathComponent(
                    "welcome-" + name + (appearance == .darkAqua ? "-dark.png" : "-light.png")))
            }
        }
        print("Native offline welcome previews rendered from example states only.")
    }
}
