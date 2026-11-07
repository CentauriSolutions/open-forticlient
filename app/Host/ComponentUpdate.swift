import AppKit
import Foundation

// The VPN component window: a form-less view of what the host reports about the system extension
// and the login items, with one button that runs the host's `component_update` (through
// OFTCSetupRepair) and a link to the System Settings pane that holds a pending approval. It adds no
// VPN and touches no profile, so "Update VPN component" can never show the add-a-VPN form
// (docs/ui-edge.md, section 13.1).
final class OFTCComponentUpdate: NSObject, NSWindowDelegate {
    private let onClose: () -> Void
    private let onRun: () -> Void
    private let onSettings: (HostSettingsPane) -> Void
    private var presentation: ComponentUpdatePresentation?
    private let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 520, height: 340),
                                  styleMask: [.titled, .closable, .miniaturizable],
                                  backing: .buffered, defer: false)
    private let titleLabel = NSTextField(labelWithString: "")
    private let introLabel = NSTextField(wrappingLabelWithString: "")
    private let componentLabel = NSTextField(wrappingLabelWithString: "")
    private let buildsLabel = NSTextField(labelWithString: "")
    private let loginLabel = NSTextField(wrappingLabelWithString: "")
    private let statusLabel = NSTextField(wrappingLabelWithString: "")
    private let runButton = NSButton(title: "", target: nil, action: nil)
    private let settingsButton = NSButton(title: "Open System Settings", target: nil, action: nil)
    private let closeButton = NSButton(title: "Close", target: nil, action: nil)

    init(onRun: @escaping () -> Void, onSettings: @escaping (HostSettingsPane) -> Void,
         onClose: @escaping () -> Void) {
        self.onRun = onRun
        self.onSettings = onSettings
        self.onClose = onClose
        super.init()
        window.title = "OFTC VPN component"
        window.isReleasedWhenClosed = false
        window.delegate = self
        let title = titleLabel
        let explanation = introLabel
        title.font = .boldSystemFont(ofSize: 22)
        buildsLabel.textColor = .secondaryLabelColor
        loginLabel.textColor = .secondaryLabelColor
        statusLabel.maximumNumberOfLines = 4
        runButton.target = self
        runButton.action = #selector(run)
        runButton.keyEquivalent = "\r"
        settingsButton.target = self
        settingsButton.action = #selector(openSettings)
        closeButton.target = self
        closeButton.action = #selector(closeFromButton)
        let buttons = NSStackView(views: [settingsButton, NSView(), closeButton, runButton])
        let stack = NSStackView(views: [title, explanation, componentLabel, buildsLabel, loginLabel, statusLabel, buttons])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 12
        stack.translatesAutoresizingMaskIntoConstraints = false
        let content = NSView(frame: window.contentView!.bounds)
        window.contentView = content
        content.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 28),
            stack.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -28),
            stack.topAnchor.constraint(equalTo: content.topAnchor, constant: 24),
            stack.bottomAnchor.constraint(equalTo: content.bottomAnchor, constant: -20),
            buttons.widthAnchor.constraint(equalTo: stack.widthAnchor),
        ])
        for label in [explanation, componentLabel, loginLabel, statusLabel] {
            label.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true
        }
    }

    var isVisible: Bool { window.isVisible }

    func show() {
        NSApplication.shared.setActivationPolicy(.regular)
        window.center()
        window.makeKeyAndOrderFront(nil)
        NSApplication.shared.activate(ignoringOtherApps: true)
    }

    func close() { window.close() }

    func update(_ next: ComponentUpdatePresentation) {
        presentation = next
        titleLabel.stringValue = next.title
        introLabel.stringValue = next.intro
        for label in [componentLabel, buildsLabel, loginLabel, statusLabel] { label.isHidden = next.finished }
        // Finished: one primary button. The run button is gone, not merely disabled.
        runButton.isHidden = next.finished
        closeButton.title = next.finished ? "Done" : "Close"
        closeButton.keyEquivalent = next.finished ? "\r" : ""
        componentLabel.stringValue = next.component
        buildsLabel.stringValue = next.builds
        loginLabel.stringValue = next.login.joined(separator: "\n")
        statusLabel.stringValue = next.status
        runButton.title = next.button
        runButton.isEnabled = next.canRun
        settingsButton.isHidden = next.finished || !next.showSettings
    }

    @objc private func run() { onRun() }
    @objc private func openSettings() { onSettings(presentation?.pane ?? .extensions) }
    @objc private func closeFromButton() { window.close() }
    func windowWillClose(_ notification: Notification) { onClose() }
}
