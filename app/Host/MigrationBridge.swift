import Foundation

private struct MigrationWireBuffer {
    var data: UnsafeMutablePointer<UInt8>?
    var count: Int
}

@_silgen_name("oftc_migrate_profile_psk")
private func rustMigrate(_ name: UnsafePointer<UInt8>?, _ nameLength: Int,
                         _ gateway: UnsafePointer<UInt8>?, _ gatewayLength: Int,
                         _ output: UnsafeMutablePointer<MigrationWireBuffer>) -> Int32

@_silgen_name("oftc_migrate_free")
private func rustMigrateFree(_ data: UnsafeMutablePointer<UInt8>?, _ count: Int)

enum MigrationBridge {
    enum Failure: Error { case unavailable }

    static func psk(profileName: String, expectedGateway: String) throws -> Data {
        var output = MigrationWireBuffer(data: nil, count: 0)
        let name = Array(profileName.utf8)
        let gateway = Array(expectedGateway.utf8)
        let status = name.withUnsafeBufferPointer { profile in
            gateway.withUnsafeBufferPointer { host in
                rustMigrate(profile.baseAddress, profile.count,
                            host.baseAddress, host.count, &output)
            }
        }
        defer { rustMigrateFree(output.data, output.count) }
        guard status == 0, let data = output.data,
              (1...1024).contains(output.count) else { throw Failure.unavailable }
        return Data(bytes: data, count: output.count)
    }
}
