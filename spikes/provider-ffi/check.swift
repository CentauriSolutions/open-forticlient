import Foundation

// Compiled with -import-objc-header oftc_ffi.h. This is signature validation
// only; no handle or network request is created while typechecking.
func check(_ handle: OpaquePointer?) {
    var settings = OftcSettings()
    var route = OftcRoute()
    var domainLength = 0
    var event: UInt32 = 0
    var teardown: UInt32 = 0
    var ip = [UInt8](repeating: 0, count: 4096)
    var dns = [UInt8](repeating: 0, count: 4)
    let source = [UInt8](repeating: 0x41, count: 32)
    let gateway = Array("example.invalid".utf8)
    let secret = Array("synthetic".utf8)
    let retained = oftc_handle_retain(handle)
    _ = gateway.withUnsafeBufferPointer { g in
        source.withUnsafeBufferPointer { uid in
            secret.withUnsafeBufferPointer { psk in
                secret.withUnsafeBufferPointer { token in
                    oftc_connect(handle, g.baseAddress, g.count,
                                 uid.baseAddress, uid.count,
                                 psk.baseAddress, psk.count,
                                 token.baseAddress, token.count)
                }
            }
        }
    }
    _ = oftc_settings(handle, &settings)
    _ = oftc_route(handle, 0, &route)
    _ = oftc_dns_server(handle, 0, &dns)
    _ = dns.withUnsafeMutableBufferPointer { bytes in
        oftc_dns_domain(handle, 0, bytes.baseAddress, bytes.count, &domainLength)
    }
    _ = ip.withUnsafeBufferPointer { bytes in
        oftc_send_ip(handle, bytes.baseAddress, bytes.count)
    }
    _ = ip.withUnsafeMutableBufferPointer { bytes in
        oftc_receive(handle, bytes.baseAddress, bytes.count, &domainLength, &event)
    }
    _ = oftc_probe_liveness(handle)
    _ = oftc_cancel(handle)
    _ = oftc_teardown(handle, &teardown)
    oftc_handle_release(retained)
}
