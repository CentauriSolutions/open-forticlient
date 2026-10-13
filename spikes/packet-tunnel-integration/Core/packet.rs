//! Synthetic IPv4 echo core for the extension packaging spike. No VPN logic.
use std::ffi::c_int;

unsafe extern "C" {
    fn oftc_swift_hmac(
        sha256: c_int,
        key: *const u8,
        key_len: usize,
        input: *const u8,
        input_len: usize,
        digest: *mut u8,
        digest_len: usize,
    ) -> c_int;
}

const PROBE_ADDRESS: [u8; 4] = [198, 51, 100, 254];
const HMAC_EXPECTED: [u8; 32] = [
    0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
    0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7,
];

/// Verifies that Rust can call the bundled Swift crypto bridge at runtime.
#[no_mangle]
pub extern "C" fn oftc_crypto_probe() -> c_int {
    let key = [0x0b_u8; 20];
    let message = b"Hi There";
    let mut digest = [0_u8; 32];
    let result = unsafe {
        oftc_swift_hmac(
            1,
            key.as_ptr(),
            key.len(),
            message.as_ptr(),
            message.len(),
            digest.as_mut_ptr(),
            digest.len(),
        )
    };
    if result == 0 && digest == HMAC_EXPECTED {
        0
    } else {
        -1
    }
}

/// Copies one well-formed IPv4 ICMP echo request into `output` as an echo reply.
/// 0 = reply, 1 = ignored packet, -1 = invalid ABI arguments. The caller owns
/// both buffers and provides non-overlapping storage; no pointer is retained.
#[no_mangle]
pub unsafe extern "C" fn oftc_packet_echo(
    input: *const u8,
    input_len: usize,
    output: *mut u8,
    output_cap: usize,
    output_len: *mut usize,
) -> c_int {
    if output_len.is_null() {
        return -1;
    }
    unsafe {
        *output_len = 0;
    }
    if input.is_null() || output.is_null() || input_len > 65_535 || output_cap < input_len {
        return -1;
    }
    let packet = unsafe { std::slice::from_raw_parts(input, input_len) };
    let Some(reply) = echo_reply(packet) else {
        return 1;
    };
    unsafe {
        std::ptr::copy_nonoverlapping(reply.as_ptr(), output, reply.len());
        *output_len = reply.len();
    }
    0
}

fn echo_reply(packet: &[u8]) -> Option<Vec<u8>> {
    if packet.len() < 28 || packet[0] >> 4 != 4 {
        return None;
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if !(20..=60).contains(&header_len)
        || packet.len() < header_len + 8
        || packet[9] != 1
        || packet[16..20] != PROBE_ADDRESS
        || packet[header_len] != 8
        || packet[header_len + 1] != 0
    {
        return None;
    }
    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    if fragment & 0x3fff != 0 {
        return None;
    }
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len < header_len + 8 || total_len > packet.len() {
        return None;
    }
    let mut reply = packet[..total_len].to_vec();
    for i in 0..4 {
        reply.swap(12 + i, 16 + i);
    }
    reply[8] = 64;
    reply[header_len] = 0;
    reply[header_len + 2..header_len + 4].fill(0);
    let icmp_checksum = checksum(&reply[header_len..]);
    reply[header_len + 2..header_len + 4].copy_from_slice(&icmp_checksum.to_be_bytes());
    reply[10..12].fill(0);
    let ip_checksum = checksum(&reply[..header_len]);
    reply[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
    Some(reply)
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for pair in bytes.chunks(2) {
        sum += u32::from(pair[0]) << 8 | u32::from(*pair.get(1).unwrap_or(&0));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
