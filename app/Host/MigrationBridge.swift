import Foundation

private struct MigrationWireBuffer {
    var data: UnsafeMutablePointer<UInt8>?
    var count: Int
}

private struct ImportWireBuffer {
    var gateway: MigrationWireBuffer
    var psk: MigrationWireBuffer
    var samlPort: UInt32
}

@_silgen_name("oftc_migrate_profile_psk")
private func rustMigrate(_ name: UnsafePointer<UInt8>?, _ nameLength: Int,
                         _ gateway: UnsafePointer<UInt8>?, _ gatewayLength: Int,
                         _ output: UnsafeMutablePointer<MigrationWireBuffer>) -> Int32

@_silgen_name("oftc_migrate_free")
private func rustMigrateFree(_ data: UnsafeMutablePointer<UInt8>?, _ count: Int)

@_silgen_name("oftc_import_profile")
private func rustImport(_ name: UnsafePointer<UInt8>?, _ nameLength: Int,
                        _ output: UnsafeMutablePointer<ImportWireBuffer>) -> Int32

@_silgen_name("oftc_import_free")
private func rustImportFree(_ output: UnsafeMutablePointer<ImportWireBuffer>)

enum MigrationBridge {
    enum Failure: Error { case unavailable }

    struct ImportedProfile {
        let gateway: String
        let samlPort: UInt32
        var psk: Data
    }

    static func importProfile(name: String) throws -> ImportedProfile {
        var output = ImportWireBuffer(
            gateway: MigrationWireBuffer(data: nil, count: 0),
            psk: MigrationWireBuffer(data: nil, count: 0), samlPort: 0)
        let nameBytes = Array(name.utf8)
        let status = nameBytes.withUnsafeBufferPointer {
            rustImport($0.baseAddress, $0.count, &output)
        }
        defer { rustImportFree(&output) }
        guard status == 0, let gatewayBytes = output.gateway.data,
              let pskBytes = output.psk.data,
              (1...253).contains(output.gateway.count),
              (1...1024).contains(output.psk.count),
              (1...65535).contains(output.samlPort),
              let gateway = String(bytes: UnsafeBufferPointer(start: gatewayBytes,
                                                              count: output.gateway.count),
                                   encoding: .utf8) else { throw Failure.unavailable }
        return ImportedProfile(gateway: gateway, samlPort: output.samlPort,
                               psk: Data(bytes: pskBytes, count: output.psk.count))
    }

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
