import AppKit

// The popup for a gateway certificate macOS does not trust. "Don't Trust" is
// the default button and the fingerprint is visible without expanding anything.
enum GatewayTrustPrompt {
    // The popup runs in a short-lived child of this executable. Supervisors
    // drain their main queue on a worker thread, where AppKit cannot build a
    // window; the child's top-level code runs on the real main thread.
    static func present(_ review: GatewayTrust.Review) -> GatewayTrust.Decision {
        guard CGSessionCopyCurrentDictionary() != nil,
              let executable = Bundle.main.executablePath else { return .unavailable }
        var previous: Data?
        if case .changed(let old) = review.reason { previous = old.der }
        guard let request = try? JSONEncoder().encode(GatewayTrust.PromptRequest(
            profileName: review.profileName, host: review.host, port: review.port,
            certificate: review.certificate.der, previous: previous)) else { return .unavailable }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = ["review-certificate"]
        let input = Pipe()
        process.standardInput = input
        process.standardOutput = FileHandle.nullDevice
        guard (try? process.run()) != nil else { return .unavailable }
        input.fileHandleForWriting.write(request)
        try? input.fileHandleForWriting.close()
        process.waitUntilExit()
        switch process.terminationStatus {
        case 10: return .trust
        case 11: return .decline
        default: return .unavailable
        }
    }

    // Child entry point: read the request from stdin, ask, exit 10 (trust),
    // 11 (decline) or 12 (nothing to show).
    static func runChild() -> Never {
        guard let request = try? JSONDecoder().decode(
                GatewayTrust.PromptRequest.self, from: FileHandle.standardInput.readDataToEndOfFile()),
              let certificate = GatewayCertificate(der: request.certificate) else { exit(12) }
        let reason: GatewayTrust.Review.Reason
        if let old = request.previous.flatMap({ GatewayCertificate(der: $0) }) {
            reason = .changed(previous: old)
        } else {
            reason = .untrusted
        }
        let decision = run(GatewayTrust.Review(
            profileName: request.profileName, host: request.host, port: request.port, certificate: certificate, reason: reason))
        exit(decision == .trust ? 10 : 11)
    }

    // The value of a distinguished-name field, e.g. a FortiGate's serial number
    // for CN.
    static func field(_ key: String, in name: String) -> String {
        let pattern = try? NSRegularExpression(pattern: "\\b\(key) ?= ?([^/,]+)")
        if let match = pattern?.firstMatch(in: name, range: NSRange(name.startIndex..., in: name)),
           let range = Range(match.range(at: 1), in: name) {
            return String(name[range]).trimmingCharacters(in: .whitespaces)
        }
        return name
    }

    // "Jun  5 07:00:00 2056 GMT" as a plain date; falls back to the raw text.
    static func expiry(_ validity: String) -> String {
        guard let range = validity.range(of: " to ") else { return validity }
        let raw = validity[range.upperBound...].split(separator: " ").joined(separator: " ")
        let parser = DateFormatter()
        parser.locale = Locale(identifier: "en_US_POSIX")
        parser.dateFormat = "MMM d HH:mm:ss yyyy 'GMT'"
        parser.timeZone = TimeZone(identifier: "GMT")
        guard let date = parser.date(from: raw) else { return raw }
        return date.formatted(date: .long, time: .omitted)
    }

    // 32 fingerprint bytes as two lines of 16, easy to compare by eye.
    static func fingerprintLines(_ certificate: GatewayCertificate) -> String {
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

    private static func fingerprint(_ caption: String, _ certificate: GatewayCertificate,
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
    static func makeAlert(_ review: GatewayTrust.Review) -> (alert: NSAlert, retained: AnyObject) {
        let changed: Bool
        if case .changed = review.reason { changed = true } else { changed = false }
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
        if case .changed(let previous) = review.reason {
            views.append(fingerprint("Previously trusted", previous, secondary: true))
        }

        let grid = NSGridView(views: [
            [text("Issued to", secondary: true), text(field("CN", in: certificate.subject))],
            [text("Issued by", secondary: true), text(field("CN", in: certificate.issuer))],
            [text("Serial", secondary: true), text(certificate.serial)],
            [text("Expires", secondary: true), text(expiry(certificate.validity))],
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

    private static func run(_ review: GatewayTrust.Review) -> GatewayTrust.Decision {
        NSApplication.shared.setActivationPolicy(.accessory)
        let (alert, retained) = makeAlert(review)
        NSApp.activate(ignoringOtherApps: true)
        return withExtendedLifetime(retained) {
            alert.runModal() == .alertSecondButtonReturn ? .trust : .decline
        }
    }
}
