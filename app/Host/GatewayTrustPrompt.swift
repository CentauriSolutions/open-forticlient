import AppKit

// The popup for a gateway certificate macOS does not trust. "Don't Trust" is
// the default button and the fingerprint is visible without expanding anything.
// It runs in a short-lived child of this executable that the Rust supervisor starts:
// supervisors drain their main queue on a worker thread, where AppKit cannot build
// a window, and the child's top-level code runs on the real main thread.
enum GatewayTrustPrompt {
    // Child entry point: read the request from stdin, ask, exit 10 (trust),
    // 11 (decline) or 12 (nothing to show).
    static func runChild() -> Never {
        guard let request = try? JSONDecoder().decode(
                GatewayTrust.PromptRequest.self, from: FileHandle.standardInput.readDataToEndOfFile()) else { exit(12) }
        exit(run(request) == .trust ? 10 : 11)
    }

    // "Jun 5 07:00:00 2056 GMT" as a plain date; falls back to the raw text.
    static func expiry(_ raw: String) -> String {
        let parser = DateFormatter()
        parser.locale = Locale(identifier: "en_US_POSIX")
        parser.dateFormat = "MMM d HH:mm:ss yyyy 'GMT'"
        parser.timeZone = TimeZone(identifier: "GMT")
        guard let date = parser.date(from: raw.split(separator: " ").joined(separator: " ")) else { return raw }
        return date.formatted(date: .long, time: .omitted)
    }

    // 32 fingerprint bytes as two lines of 16, easy to compare by eye.
    static func fingerprintLines(_ certificate: GatewayTrust.Certificate) -> String {
        let bytes = certificate.sha256.split(separator: ":").map(String.init)
        return [bytes.prefix(16), bytes.dropFirst(16)].map { $0.joined(separator: " ") }.joined(separator: "\n")
    }

    private static func text(_ string: String, size: CGFloat = 12, secondary: Bool = false,
                             monospaced: Bool = false) -> NSTextField {
        let field = NSTextField(labelWithString: string)
        field.font = monospaced ? .monospacedSystemFont(ofSize: size, weight: .regular)
                                : .systemFont(ofSize: size)
        field.textColor = secondary ? .secondaryLabelColor : .labelColor
        field.isSelectable = true
        field.maximumNumberOfLines = 0
        return field
    }

    private static func fingerprint(_ caption: String, _ certificate: GatewayTrust.Certificate,
                                    secondary: Bool = false) -> NSStackView {
        let stack = NSStackView(views: [
            text(caption, size: 11, secondary: true),
            text(fingerprintLines(certificate), size: 11, secondary: secondary, monospaced: true),
        ])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 3
        return stack
    }

    // Keeps the details toggle alive for as long as the alert is.
    private final class DetailsToggle: NSObject {
        let button: NSButton
        let details: NSView
        let container: NSView
        let stack: NSStackView
        weak var alert: NSAlert?

        init(button: NSButton, details: NSView, container: NSView, stack: NSStackView) {
            self.button = button; self.details = details
            self.container = container; self.stack = stack
        }

        @objc func toggle(_ sender: Any?) {
            details.isHidden.toggle()
            button.image = NSImage(systemSymbolName: details.isHidden ? "chevron.right" : "chevron.down",
                                   accessibilityDescription: nil)
            stack.layoutSubtreeIfNeeded()
            container.setFrameSize(NSSize(width: container.frame.width, height: stack.fittingSize.height))
            alert?.layout()
        }
    }

    // Builds the alert; `retained` must outlive it.
    static func makeAlert(_ review: GatewayTrust.PromptRequest) -> (alert: NSAlert, retained: AnyObject) {
        let changed = review.changed
        let certificate = review.certificate
        let vpn = review.profileName.isEmpty ? "this VPN gateway" : "the “\(review.profileName)” VPN gateway"

        let alert = NSAlert()
        alert.messageText = changed ? "The certificate for \(vpn) changed" : "Trust \(vpn)?"
        alert.informativeText = changed
            ? "It no longer matches the one you trusted. That can mean the gateway was reconfigured, "
              + "or that someone is intercepting the connection."
            : "\(review.host) presented a certificate macOS doesn’t recognize. "
              + "That’s normal for a FortiGate’s built-in certificate."
        let symbol = changed ? "exclamationmark.shield" : "questionmark.circle"
        let configuration = NSImage.SymbolConfiguration(pointSize: 40, weight: .regular)
            .applying(.init(paletteColors: [changed ? .systemRed : .systemOrange]))
        alert.icon = NSImage(systemSymbolName: symbol, accessibilityDescription: nil)?
            .withSymbolConfiguration(configuration)

        var views: [NSView] = [fingerprint(changed ? "New SHA-256 fingerprint" : "SHA-256 fingerprint", certificate)]
        if let previous = review.previous {
            views.append(fingerprint("Previously trusted", previous, secondary: true))
        }

        let grid = NSGridView(views: [
            [text("Issued to", secondary: true), text(certificate.issuedTo)],
            [text("Issued by", secondary: true), text(certificate.issuedBy)],
            [text("Serial", secondary: true), text(certificate.serial)],
            [text("Expires", secondary: true), text(expiry(certificate.expires))],
        ])
        grid.columnSpacing = 14
        grid.rowSpacing = 3
        grid.column(at: 0).xPlacement = .leading
        grid.isHidden = true

        let button = NSButton(title: "Show certificate details", target: nil, action: nil)
        button.image = NSImage(systemSymbolName: "chevron.right", accessibilityDescription: nil)
        button.imagePosition = .imageLeading
        button.isBordered = false
        button.font = .systemFont(ofSize: 12)
        button.contentTintColor = .secondaryLabelColor
        views.append(button)
        views.append(grid)

        let stack = NSStackView(views: views)
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 10
        stack.translatesAutoresizingMaskIntoConstraints = false
        let container = NSView(frame: NSRect(x: 0, y: 0, width: 320, height: 10))
        container.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: container.leadingAnchor),
            stack.trailingAnchor.constraint(lessThanOrEqualTo: container.trailingAnchor),
            stack.topAnchor.constraint(equalTo: container.topAnchor),
            stack.bottomAnchor.constraint(equalTo: container.bottomAnchor),
        ])
        container.setFrameSize(NSSize(width: 320, height: stack.fittingSize.height))
        alert.accessoryView = container

        let toggle = DetailsToggle(button: button, details: grid, container: container, stack: stack)
        toggle.alert = alert
        button.target = toggle
        button.action = #selector(DetailsToggle.toggle(_:))

        alert.addButton(withTitle: "Don’t Trust")
        alert.addButton(withTitle: changed ? "Trust New" : "Trust")
        return (alert, toggle)
    }

    private static func run(_ review: GatewayTrust.PromptRequest) -> GatewayTrust.Decision {
        NSApplication.shared.setActivationPolicy(.accessory)
        let (alert, retained) = makeAlert(review)
        NSApp.activate(ignoringOtherApps: true)
        return withExtendedLifetime(retained) {
            alert.runModal() == .alertSecondButtonReturn ? .trust : .decline
        }
    }
}
