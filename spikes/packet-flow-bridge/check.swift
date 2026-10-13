import Darwin
import Foundation

@_silgen_name("oftc_bridge_new_synthetic") private func bridgeNew(_ role: Int32) -> UnsafeMutableRawPointer?
@_silgen_name("oftc_bridge_free") private func bridgeFree(_ handle: UnsafeMutableRawPointer?)
@_silgen_name("oftc_bridge_send_ip") private func bridgeSend(
    _ handle: UnsafeMutableRawPointer?, _ input: UnsafePointer<UInt8>?, _ inputLength: Int,
    _ output: UnsafeMutablePointer<UInt8>?, _ capacity: Int,
    _ outputLength: UnsafeMutablePointer<Int>?) -> Int32
@_silgen_name("oftc_bridge_receive_udp") private func bridgeReceive(
    _ handle: UnsafeMutableRawPointer?, _ input: UnsafePointer<UInt8>?, _ inputLength: Int,
    _ output: UnsafeMutablePointer<UInt8>?, _ capacity: Int,
    _ outputLength: UnsafeMutablePointer<Int>?) -> Int32

enum BridgeResult: Equatable {
    case ip(Data)
    case ike(Data)
    case keepalive
}

final class BridgeSession {
    let handle: UnsafeMutableRawPointer

    init(role: Int32) {
        guard let handle = bridgeNew(role) else { fatalError("synthetic session installation failed") }
        self.handle = handle
    }

    deinit { bridgeFree(handle) }

    func sendIP(_ packet: Data) -> Data? {
        var output = [UInt8](repeating: 0, count: 2048)
        var used = -1
        let status = packet.withUnsafeBytes { input in
            output.withUnsafeMutableBufferPointer { bytes in
                bridgeSend(handle, input.bindMemory(to: UInt8.self).baseAddress, packet.count,
                           bytes.baseAddress, bytes.count, &used)
            }
        }
        guard status == 0 else {
            precondition(used == 0, "failed outbound call returned bytes")
            return nil
        }
        precondition(used > 0 && used <= output.count, "invalid outbound length")
        return Data(output.prefix(used))
    }

    func receiveUDP(_ payload: Data) -> BridgeResult? {
        var output = [UInt8](repeating: 0, count: max(1400, payload.count))
        var used = -1
        let status = payload.withUnsafeBytes { input in
            output.withUnsafeMutableBufferPointer { bytes in
                bridgeReceive(handle, input.bindMemory(to: UInt8.self).baseAddress, payload.count,
                              bytes.baseAddress, bytes.count, &used)
            }
        }
        precondition(used >= 0 && used <= output.count, "invalid inbound length")
        switch status {
        case 0: return .ip(Data(output.prefix(used)))
        case 1: return .ike(Data(output.prefix(used)))
        case 2:
            precondition(used == 0)
            return .keepalive
        default:
            precondition(used == 0, "failed inbound call returned bytes")
            return nil
        }
    }
}

// The same readPackets/writePackets shape as NEPacketTunnelFlow, held entirely
// in memory. A real provider would pass the ESP bytes to its UDP 4500 socket.
final class OfflinePacketFlow {
    private var pending: [(Data, NSNumber)] = []
    private(set) var delivered: [(Data, NSNumber)] = []

    func enqueue(_ packet: Data, protocolNumber: Int32) {
        pending.append((packet, NSNumber(value: protocolNumber)))
    }

    func readPackets(_ completion: ([Data], [NSNumber]) -> Void) {
        let batch = pending
        pending.removeAll()
        completion(batch.map(\.0), batch.map(\.1))
    }

    @discardableResult
    func writePackets(_ packets: [Data], withProtocols protocols: [NSNumber]) -> Bool {
        guard packets.count == protocols.count else { return false }
        delivered.append(contentsOf: zip(packets, protocols))
        return true
    }
}

final class PacketTunnelStyleAdapter {
    let flow: OfflinePacketFlow
    let session: BridgeSession

    init(flow: OfflinePacketFlow, session: BridgeSession) {
        self.flow = flow
        self.session = session
    }

    func pump(sendUDP: (Data) -> Void) {
        flow.readPackets { packets, protocols in
            for (packet, proto) in zip(packets, protocols) where proto.int32Value == AF_INET {
                if let wire = session.sendIP(packet) { sendUDP(wire) }
            }
        }
    }

    func receiveUDP(_ payload: Data) {
        guard let result = session.receiveUDP(payload) else { return }
        switch result {
        case .ip(let packet):
            precondition(flow.writePackets([packet], withProtocols: [NSNumber(value: AF_INET)]))
        case .ike:
            // Production adapter must forward this body to the active IKE SA.
            break
        case .keepalive:
            break
        }
    }
}

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

func packet(source: [UInt8], destination: [UInt8], reply: Bool = false) -> Data {
    precondition(source.count == 4 && destination.count == 4)
    var bytes = [UInt8](repeating: 0, count: 28)
    bytes[0] = 0x45
    bytes[2] = 0
    bytes[3] = 28
    bytes[8] = 64
    bytes[9] = 1 // ICMP
    bytes[12..<16] = source[...]
    bytes[16..<20] = destination[...]
    bytes[20] = reply ? 0 : 8
    bytes[24] = 0x12
    bytes[25] = 0x34
    bytes[26] = 0
    bytes[27] = 1
    let icmp = checksum(bytes[20..<28])
    bytes[22] = UInt8(icmp >> 8)
    bytes[23] = UInt8(icmp & 0xff)
    let ip = checksum(bytes[0..<20])
    bytes[10] = UInt8(ip >> 8)
    bytes[11] = UInt8(ip & 0xff)
    return Data(bytes)
}

let client = BridgeSession(role: 0)
let peer = BridgeSession(role: 1)
let flow = OfflinePacketFlow()
let adapter = PacketTunnelStyleAdapter(flow: flow, session: client)
let request = packet(source: [192, 0, 2, 2], destination: [198, 51, 100, 254])

// A mismatched IPv4 total length must fail before ESP sequence 1 is used.
var bad = request
bad[3] = 27
flow.enqueue(bad, protocolNumber: AF_INET)
var outbound: Data?
adapter.pump { outbound = $0 }
precondition(outbound == nil, "mis-sized IP packet reached ESP")

// Short caller storage is rejected before encryption and leaves length zero.
var tiny = [UInt8](repeating: 0, count: 1)
var tinyUsed = -1
let shortSend = request.withUnsafeBytes { input in
    tiny.withUnsafeMutableBufferPointer { output in
        bridgeSend(client.handle, input.bindMemory(to: UInt8.self).baseAddress, request.count,
                   output.baseAddress, output.count, &tinyUsed)
    }
}
precondition(shortSend == -2 && tinyUsed == 0, "short outbound buffer was not rejected")

flow.enqueue(request, protocolNumber: AF_INET)
adapter.pump { outbound = $0 }
guard let wire = outbound else { fatalError("valid packet did not produce ESP") }
precondition(wire.count >= 52 && Array(wire[0..<4]) == [0x22, 0x22, 0x22, 0x22])
precondition(Array(wire[4..<8]) == [0, 0, 0, 1], "bad packet consumed ESP sequence")
precondition(peer.receiveUDP(wire) == .ip(request), "peer did not authenticate outbound ESP")

let reply = packet(source: [198, 51, 100, 254], destination: [192, 0, 2, 2], reply: true)
guard let inboundWire = peer.sendIP(reply) else { fatalError("peer could not send ESP") }

// A short inbound buffer is rejected before ESP replay state changes.
var shortUsed = -1
let shortReceive = inboundWire.withUnsafeBytes { input in
    tiny.withUnsafeMutableBufferPointer { output in
        bridgeReceive(client.handle, input.bindMemory(to: UInt8.self).baseAddress,
                      inboundWire.count, output.baseAddress, output.count, &shortUsed)
    }
}
precondition(shortReceive == -2 && shortUsed == 0, "short inbound buffer was not rejected")

adapter.receiveUDP(inboundWire)
precondition(flow.delivered.count == 1, "authenticated packet was not written to packet flow")
precondition(flow.delivered[0].0 == reply && flow.delivered[0].1.int32Value == AF_INET)
precondition(client.receiveUDP(inboundWire) == nil, "replayed ESP was accepted")
precondition(client.receiveUDP(Data([0xff])) == .keepalive)

print("PASS: Swift packet-flow adapter -> Rust outbound ESP -> synthetic peer -> authenticated inbound IP")
print("PASS: malformed IP and short buffers fail before sequence/replay state changes")
