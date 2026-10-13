//! One bounded IPv4 ICMP echo for the first live ESP data-plane probe.
//! The target must be an explicitly chosen, known-safe internal host.
use std::net::Ipv4Addr;

const PAYLOAD: &[u8] = b"oftc-gate4-probe";

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in bytes.chunks(2) {
        sum += u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]) as u32;
    }
    while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16); }
    !(sum as u16)
}

pub fn echo_request(source: Ipv4Addr, target: Ipv4Addr, id: u16) -> Vec<u8> {
    let length = 20 + 8 + PAYLOAD.len();
    let mut packet = vec![0u8; length];
    packet[0] = 0x45; // IPv4, 20-byte header
    packet[2..4].copy_from_slice(&(length as u16).to_be_bytes());
    packet[8] = 64; // TTL
    packet[9] = 1; // ICMP
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&target.octets());
    let ip_sum = checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    packet[20] = 8; // Echo Request
    packet[24..26].copy_from_slice(&id.to_be_bytes());
    packet[26..28].copy_from_slice(&1u16.to_be_bytes());
    packet[28..].copy_from_slice(PAYLOAD);
    let icmp_sum = checksum(&packet[20..]);
    packet[22..24].copy_from_slice(&icmp_sum.to_be_bytes());
    packet
}

pub fn is_echo_reply(packet: &[u8], source: Ipv4Addr, target: Ipv4Addr, id: u16) -> bool {
    if packet.len() < 28 || packet[0] >> 4 != 4 { return false; }
    let header_len = (packet[0] & 0x0f) as usize * 4;
    if header_len < 20 || packet.len() < header_len + 8 + PAYLOAD.len()
        || u16::from_be_bytes([packet[2], packet[3]]) as usize != packet.len()
        || packet[9] != 1 || checksum(&packet[..header_len]) != 0
        || packet[12..16] != target.octets() || packet[16..20] != source.octets()
    { return false; }
    let icmp = &packet[header_len..];
    icmp.len() == 8 + PAYLOAD.len() && icmp[0] == 0 && icmp[1] == 0
        && checksum(icmp) == 0
        && icmp[4..6] == id.to_be_bytes()
        && icmp[6..8] == 1u16.to_be_bytes()
        && icmp[8..] == *PAYLOAD
}

pub fn is_icmp_error(packet: &[u8], destination: Ipv4Addr) -> bool {
    if packet.len() < 28 || packet[0] >> 4 != 4 { return false; }
    let header_len = (packet[0] & 0x0f) as usize * 4;
    header_len >= 20 && packet.len() >= header_len + 8
        && u16::from_be_bytes([packet[2], packet[3]]) as usize == packet.len()
        && packet[9] == 1 && checksum(&packet[..header_len]) == 0
        && packet[16..20] == destination.octets()
        && matches!(packet[header_len], 3 | 11)
        && checksum(&packet[header_len..]) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outbound_checksums_and_strict_reply_match() {
        let source = Ipv4Addr::new(192, 0, 2, 2);
        let target = Ipv4Addr::new(198, 51, 100, 254);
        let request = echo_request(source, target, 0x1234);
        assert_eq!(checksum(&request[..20]), 0);
        assert_eq!(checksum(&request[20..]), 0);
        let mut reply = request;
        reply[12..16].copy_from_slice(&target.octets());
        reply[16..20].copy_from_slice(&source.octets());
        reply[10..12].fill(0);
        let ip_sum = checksum(&reply[..20]);
        reply[10..12].copy_from_slice(&ip_sum.to_be_bytes());
        reply[20] = 0;
        reply[22..24].fill(0);
        let icmp_sum = checksum(&reply[20..]);
        reply[22..24].copy_from_slice(&icmp_sum.to_be_bytes());
        assert!(is_echo_reply(&reply, source, target, 0x1234));
        reply[28] ^= 1;
        assert!(!is_echo_reply(&reply, source, target, 0x1234));
        assert!(!is_icmp_error(&reply, source));
    }
}
