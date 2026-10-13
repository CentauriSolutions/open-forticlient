import Darwin
import Foundation

@_silgen_name("oftc_crypto_probe") private func cryptoProbe() -> Int32
@_silgen_name("oftc_packet_echo") private func packetEcho(
    _ input: UnsafePointer<UInt8>?, _ inputLength: Int,
    _ output: UnsafeMutablePointer<UInt8>?, _ capacity: Int,
    _ outputLength: UnsafeMutablePointer<Int>?) -> Int32

func checksum(_ bytes: ArraySlice<UInt8>) -> UInt16 {
    var sum: UInt32 = 0
    var index = bytes.startIndex
    while index < bytes.endIndex {
        let high = UInt32(bytes[index]) << 8
        index = bytes.index(after: index)
        let low = index < bytes.endIndex ? UInt32(bytes[index]) : 0
        if index < bytes.endIndex { index = bytes.index(after: index) }
        sum += high | low
    }
    while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16) }
    return ~UInt16(sum)
}

precondition(cryptoProbe() == 0, "Rust to bundled Swift crypto bridge failed")
var request: [UInt8] = [
    0x45, 0, 0, 28, 0, 1, 0, 0, 64, 1, 0, 0,
    192, 0, 2, 2, 198, 51, 100, 254,
    8, 0, 0, 0, 0, 1, 0, 1,
]
let icmp = checksum(request[20..<28])
request[22] = UInt8(icmp >> 8)
request[23] = UInt8(icmp & 0xff)
let ip = checksum(request[0..<20])
request[10] = UInt8(ip >> 8)
request[11] = UInt8(ip & 0xff)

var reply = [UInt8](repeating: 0, count: request.count)
var count = 0
let status = request.withUnsafeBufferPointer { input in
    reply.withUnsafeMutableBufferPointer { output in
        packetEcho(input.baseAddress, input.count, output.baseAddress, output.count, &count)
    }
}
precondition(status == 0 && count == request.count, "Swift to Rust packet call failed")
precondition(Array(reply[12..<16]) == [198, 51, 100, 254]
             && Array(reply[16..<20]) == [192, 0, 2, 2]
             && reply[20] == 0, "Bad synthetic echo reply")
precondition(checksum(reply[0..<20]) == 0 && checksum(reply[20..<28]) == 0,
             "Bad synthetic reply checksum")
request[16] = 203
let ignored = request.withUnsafeBufferPointer { input in
    reply.withUnsafeMutableBufferPointer { output in
        packetEcho(input.baseAddress, input.count, output.baseAddress, output.count, &count)
    }
}
precondition(ignored == 1 && count == 0, "Non-probe address was accepted")
print("PASS: Swift -> Rust packet round trip and Rust -> Swift crypto bridge")
