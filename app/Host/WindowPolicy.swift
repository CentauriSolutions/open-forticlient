import AppKit

// How OFTC's surfaces behave when the user moves on. The menu-bar popover is transient and also
// closes when the app stops being active or a click lands anywhere outside it (a transient
// popover of an accessory app does not always see clicks in other apps). Every window is an
// ordinary window: normal level, never hidden or kept on top on deactivation, on one Space, so
// none floats over the app the user switched to. Pinned by check-window-policy.swift.
enum OFTCWindowPolicy {
    static let level = NSWindow.Level.normal
    static let popoverBehavior = NSPopover.Behavior.transient

    static func apply(to window: NSWindow) {
        window.level = level
        window.hidesOnDeactivate = false
        window.collectionBehavior = []
    }
}

/// Closes a popover on any click outside it and when the app resigns active; both end when the
/// popover closes, so nothing stays installed.
final class OFTCPopoverDismisser {
    private var monitor: Any?
    private var resign: NSObjectProtocol?

    func start(closing popover: NSPopover) {
        stop()
        monitor = NSEvent.addGlobalMonitorForEvents(matching: [.leftMouseDown, .rightMouseDown, .otherMouseDown]) { [weak popover] _ in
            popover?.performClose(nil)
        }
        resign = NotificationCenter.default.addObserver(
            forName: NSApplication.didResignActiveNotification, object: nil, queue: .main) { [weak popover] _ in
            popover?.performClose(nil)
        }
    }

    func stop() {
        if let monitor { NSEvent.removeMonitor(monitor) }
        if let resign { NotificationCenter.default.removeObserver(resign) }
        monitor = nil
        resign = nil
    }
}
