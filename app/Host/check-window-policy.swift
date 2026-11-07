import AppKit

// Pins how OFTC's surfaces behave when the user moves on (WindowPolicy.swift): the popover is
// transient and every window is ordinary, so nothing floats over the app switched to.
@main enum WindowPolicyCheck {
    static func main() {
        precondition(OFTCWindowPolicy.popoverBehavior == .transient)
        precondition(OFTCWindowPolicy.level == .normal)
        // A window that started out hostile ends up ordinary.
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 100, height: 100),
                              styleMask: [.titled, .closable], backing: .buffered, defer: true)
        window.level = .floating
        window.hidesOnDeactivate = true
        window.collectionBehavior = [.canJoinAllSpaces, .stationary]
        OFTCWindowPolicy.apply(to: window)
        precondition(window.level == .normal && !window.hidesOnDeactivate && window.collectionBehavior.isEmpty)
        print("Window policy checks passed: transient popover, normal-level windows.")
    }
}
