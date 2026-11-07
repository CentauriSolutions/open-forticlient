import AppKit

// This second presentation uses the same view/controller and actions as the
// menu popover. It remains reachable from Applications or Spotlight when a
// status item is hidden, crowded out, or on another display.
final class OFTCControlsWindow: NSWindowController, NSWindowDelegate {
    let content = OFTCMenuViewController()
    var onClose: (() -> Void)?

    init() {
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 312, height: 430),
                              styleMask: [.titled, .closable, .miniaturizable],
                              backing: .buffered, defer: false)
        window.title = "OFTC VPN"
        window.isReleasedWhenClosed = false
        window.isMovableByWindowBackground = true
        OFTCWindowPolicy.apply(to: window)
        super.init(window: window)
        window.delegate = self
        window.contentViewController = content
        window.setContentSize(content.view.fittingSize)
        window.center()
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    func update(_ presentation: MenuPresentation) {
        content.update(presentation)
        window?.setContentSize(content.view.fittingSize)
    }

    func present() {
        NSApp.setActivationPolicy(.regular)
        showWindow(nil)
        window?.deminiaturize(nil)
        window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    func windowWillClose(_ notification: Notification) { onClose?() }
}
