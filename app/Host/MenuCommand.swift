import Darwin
import Foundation

enum MenuCommandFailure: Equatable {
    case approval, credentials, configuration, agent, migration, timeout, launch
    case failed(Int32)

    static func classify(output: Data, status: Int32) -> Self {
        let text = String(decoding: output, as: UTF8.self).lowercased()
        if text.contains("requires-approval") || text.contains("allow oftc in system settings") {
            return .approval
        }
        if text.contains("psk is unavailable") || text.contains("psk unavailable") { return .credentials }
        if text.contains("profile unavailable") || text.contains("no oftc profile") ||
            text.contains("configuration is unavailable") { return .configuration }
        if text.contains("different app") || text.contains("without a known registration") ||
            text.contains("legacy login agent") { return .migration }
        if text.contains("login agent") || text.contains("bundled oftc agent") { return .agent }
        return .failed(status)
    }

    func message(action: String) -> String {
        switch self {
        case .approval:
            return "Allow OFTC in System Settings → General → Login Items & Extensions, then try again."
        case .credentials:
            return "The VPN key is unavailable. Open Settings → Set up OFTC… to check Keychain access."
        case .configuration:
            return "Finish setup in Settings → Set up OFTC…, then try Connect."
        case .agent:
            return "OFTC's background VPN agent did not become ready. Check Login Items & Extensions, then try again."
        case .migration:
            return "The previous OFTC agent needs attention. Disconnect OFTC, then try again."
        case .timeout:
            return "Preparing the VPN took too long. Check its connection status before trying again."
        case .launch:
            return "OFTC could not start its connection helper. Try reinstalling OFTC."
        case .failed(let status):
            return "Could not \(action) (helper exit \(status)). Check VPN setup and try again."
        }
    }
}

enum MenuCommandResult: Equatable {
    case success
    case failure(MenuCommandFailure)
}

// Drain both streams without blocking on inherited child pipe handles. Raw
// bytes stay bounded and in memory; only an allowlisted category leaves here.
private final class MenuCommandPipe {
    let pipe = Pipe()
    private let lock = NSLock()
    private var bytes = Data()
    private var closed = false
    private let limit = 16_384

    init() throws {
        let fd = pipe.fileHandleForReading.fileDescriptor
        let flags = fcntl(fd, F_GETFL)
        guard flags >= 0, fcntl(fd, F_SETFL, flags | O_NONBLOCK) >= 0 else {
            throw NSError(domain: "OFTCMenuCommand", code: 1)
        }
        pipe.fileHandleForReading.readabilityHandler = { [weak self] _ in self?.drain() }
    }

    private func drainLocked() {
        guard !closed else { return }
        var buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let count = buffer.withUnsafeMutableBytes {
                Darwin.read(pipe.fileHandleForReading.fileDescriptor, $0.baseAddress, $0.count)
            }
            guard count > 0 else { return }
            let accepted = min(count, max(0, limit - bytes.count))
            if accepted > 0 { bytes.append(contentsOf: buffer.prefix(accepted)) }
        }
    }

    private func drain() {
        lock.lock(); defer { lock.unlock() }
        drainLocked()
    }

    func finish() -> Data {
        pipe.fileHandleForReading.readabilityHandler = nil
        lock.lock(); defer { lock.unlock() }
        drainLocked()
        closed = true
        try? pipe.fileHandleForReading.close()
        try? pipe.fileHandleForWriting.close()
        return bytes
    }
}

final class MenuCommand {
    private let process = Process()
    private var stdout: MenuCommandPipe?
    private var stderr: MenuCommandPipe?
    private let lock = NSLock()
    private var completion: ((MenuCommandResult) -> Void)?
    private var finished = false
    private var requestedFailure: MenuCommandFailure?

    func start(executable: URL, arguments: [String], home: URL,
               timeout: TimeInterval = 30, completion: @escaping (MenuCommandResult) -> Void) {
        self.completion = completion
        process.executableURL = executable
        process.arguments = arguments
        var environment = ProcessInfo.processInfo.environment
        environment["HOME"] = home.path
        process.environment = environment
        process.standardInput = FileHandle.nullDevice
        do {
            stdout = try MenuCommandPipe()
            stderr = try MenuCommandPipe()
            process.standardOutput = stdout!.pipe
            process.standardError = stderr!.pipe
            process.terminationHandler = { [weak self] process in self?.finish(status: process.terminationStatus) }
            try process.run()
            try? stdout?.pipe.fileHandleForWriting.close()
            try? stderr?.pipe.fileHandleForWriting.close()
        } catch {
            finish(failure: .launch)
            return
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + timeout) { [weak self] in
            guard let self else { return }
            self.lock.lock()
            let pending = !self.finished
            if pending { self.requestedFailure = .timeout }
            self.lock.unlock()
            if pending {
                if self.process.isRunning { self.process.terminate() }
                self.finish(failure: .timeout)
            }
        }
    }

    private func finish(status: Int32 = 1, failure: MenuCommandFailure? = nil) {
        lock.lock()
        guard !finished else { lock.unlock(); return }
        finished = true
        let handler = completion
        let reason = failure ?? requestedFailure
        completion = nil
        lock.unlock()
        var output = stdout?.finish() ?? Data()
        output.append(stderr?.finish() ?? Data())
        let result: MenuCommandResult = reason.map { .failure($0) }
            ?? (status == 0 ? .success : .failure(.classify(output: output, status: status)))
        DispatchQueue.main.async { handler?(result) }
    }
}
