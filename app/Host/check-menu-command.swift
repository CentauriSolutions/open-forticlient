import Foundation

@main enum MenuCommandCheck {
    static func main() {
        let home = URL(fileURLWithPath: "/private/tmp/oftc-menu-home-fixture")
        func run(_ script: String, timeout: TimeInterval = 3) -> MenuCommandResult {
            let runner = MenuCommand()
            var result: MenuCommandResult?
            runner.start(executable: URL(fileURLWithPath: "/bin/sh"), arguments: ["-c", script],
                         home: home, timeout: timeout) { result = $0 }
            let deadline = Date().addingTimeInterval(5)
            while result == nil && Date() < deadline { RunLoop.current.run(until: Date().addingTimeInterval(0.01)) }
            precondition(result != nil, "Command completion must not block on pipes")
            withExtendedLifetime(runner) {}
            return result!
        }
        precondition(run("test \"$HOME\" = /private/tmp/oftc-menu-home-fixture") == .success)
        precondition(run("echo 'allow OFTC in System Settings' >&2; exit 1") == .failure(.approval))
        precondition(run("echo 'OFTC PSK is unavailable'; exit 1") == .failure(.credentials))
        precondition(run("echo 'OFTC VPN configuration is unavailable'; exit 1") == .failure(.configuration))
        precondition(run("echo 'an OFTC agent is loaded without a known registration' >&2; exit 1") == .failure(.migration))
        precondition(run("echo 'OFTC login agent registered but did not load' >&2; exit 1") == .failure(.agent))
        // Exercise both pipes beyond their storage limits without deadlock or
        // allowing arbitrary text (including fake secret markers) into UI.
        precondition(run("i=0; while test $i -lt 9000; do echo 'PRIVATE_MARKER' ; echo 'PRIVATE_MARKER' >&2; i=$((i+1)); done; exit 7") == .failure(.failed(7)))
        precondition(run("exec /bin/sleep 2", timeout: 0.05) == .failure(.timeout))
        precondition(run("( /bin/sleep 2 ) & exit 0", timeout: 0.5) == .success) // inherited pipe writers
        let secret = Data("tokenid=PRIVATE_MARKER https://example.invalid/callback?secret=PRIVATE_MARKER".utf8)
        let failure = MenuCommandFailure.classify(output: secret, status: 8)
        precondition(failure == .failed(8))
        precondition(!failure.message(action: "connect").contains("PRIVATE_MARKER"))
        print("Menu helper home, bounded pipes, safe failures and timeouts passed (isolated commands only).")
    }
}
