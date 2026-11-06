import Foundation

// The host's typed error code, not its text, picks what the menu says.
@main enum MenuCommandCheck {
    static func main() {
        let table: [(HostErrorCode, MenuCommandFailure)] = [
            (.approvalRequired, .approval), (.pskUnavailable, .credentials), (.notConfigured, .configuration),
            (.migrationNeeded, .migration), (.agentUnavailable, .agent), (.hostUnavailable, .serviceUnavailable),
            (.unsupportedSchema, .unsupported), (.busy, .busy), (.tunnelsActive, .tunnelsActive),
            (.timeout, .timeout),
            // Everything else shows the generic text with the exit code the CLI would use.
            (.internalFailure, .failed(1)), (.badRequest, .failed(2)), (.invalidFile, .failed(3)),
        ]
        for (code, failure) in table {
            let error = HostError(code: code, detail: "", exit: code == .badRequest ? 2 : code == .invalidFile ? 3 : 1)
            precondition(MenuCommandFailure(error) == failure, "\(code)")
        }
        // The host's detail is for its log: it never reaches the screen, even from a code that
        // only maps to the generic message.
        let secret = "tokenid=PRIVATE_MARKER https://example.invalid/callback?secret=PRIVATE_MARKER"
        let failure = MenuCommandFailure(HostError(code: .internalFailure, detail: secret, exit: 8))
        precondition(failure == .failed(8))
        for item in table.map(\.1) + [failure] {
            precondition(!item.message(action: "connect").contains("PRIVATE_MARKER"))
        }
        precondition(failure.message(action: "connect") ==
                     "Could not connect (helper exit 8). Check VPN setup and try again.")
        // `oftc setup` runs as a process (HostCLI): only its exit status is read, 4 being approval.
        precondition(MenuCommandResult(.exited(0)) == .success)
        precondition(MenuCommandResult(.exited(4)) == .failure(.approval))
        precondition(MenuCommandResult(.exited(3)) == .failure(.failed(3)))
        precondition(MenuCommandResult(.timedOut) == .failure(.timeout))
        print("Menu failure message checks passed: the host's typed error codes choose the text.")
    }
}
