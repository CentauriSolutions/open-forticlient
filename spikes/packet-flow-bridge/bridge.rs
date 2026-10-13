//! Offline PacketTunnel-style C ABI for the standalone ESP engine.
//! The only constructor installs public, synthetic CHILD_SA values.

#[path = "../engine-integration/engine.rs"]
mod engine;

use engine::esp::{Keys, SystemCrypto};
use engine::{AddressRange, AuthenticatedChildSa, Engine, EspSuite, Inbound, Outbound, TrafficSelector, Transport};
use std::net::{IpAddr, Ipv4Addr};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::sync::Mutex;

const MTU: usize = 1400;
const MAX_INPUT: usize = 65_575;
const OK: i32 = 0;
const IKE: i32 = 1;
const KEEPALIVE: i32 = 2;
const INVALID_ABI: i32 = -1;
const OUTPUT_TOO_SMALL: i32 = -2;
const REJECTED: i32 = -3;
const INTERNAL: i32 = -4;

pub struct Bridge {
    engine: Mutex<Engine<SystemCrypto>>,
}

fn range(first: [u8; 4], last: [u8; 4]) -> AddressRange {
    AddressRange {
        first: IpAddr::V4(Ipv4Addr::from(first)),
        last: IpAddr::V4(Ipv4Addr::from(last)),
    }
}

fn selector(addresses: AddressRange) -> TrafficSelector {
    TrafficSelector {
        addresses,
        protocol: 0,
        first_port: 0,
        last_port: u16::MAX,
    }
}

fn keys(seed: u8) -> Keys {
    Keys {
        encryption: [seed; 32],
        integrity: [seed.wrapping_add(1); 20],
    }
}

fn synthetic_handoff(peer: bool) -> AuthenticatedChildSa {
    let client = range([192, 0, 2, 2], [192, 0, 2, 2]);
    let remote = range([198, 51, 100, 254], [198, 51, 100, 254]);
    AuthenticatedChildSa {
        suite: EspSuite::Aes256CbcHmacSha1_96,
        esn: false,
        peer_inbound_spi: if peer { 0x1111_1111 } else { 0x2222_2222 },
        local_inbound_spi: if peer { 0x2222_2222 } else { 0x1111_1111 },
        outbound_keys: keys(if peer { 0x44 } else { 0x22 }),
        inbound_keys: keys(if peer { 0x22 } else { 0x44 }),
        assigned_ip: IpAddr::V4(Ipv4Addr::from(if peer {
            [198, 51, 100, 254]
        } else {
            [192, 0, 2, 2]
        })),
        local_selectors: vec![selector(if peer { remote } else { client })],
        remote_selectors: vec![selector(if peer { client } else { remote })],
        installed_routes: vec![if peer { client } else { remote }],
        inner_mtu: MTU,
        transport: Transport::Udp4500,
        max_tcp_record: engine::tcp_esp::DEFAULT_MAX_RECORD,
    }
}

/// Test-only constructor. Role 0 is the PacketTunnel client; role 1 is a
/// synthetic peer. The returned pointer is owned by the caller until free.
#[no_mangle]
pub extern "C" fn oftc_bridge_new_synthetic(role: i32) -> *mut Bridge {
    if role != 0 && role != 1 {
        return ptr::null_mut();
    }
    catch_unwind(|| {
        Engine::install(synthetic_handoff(role == 1), SystemCrypto)
            .map(|engine| Box::into_raw(Box::new(Bridge { engine: Mutex::new(engine) })))
            .unwrap_or(ptr::null_mut())
    })
    .unwrap_or(ptr::null_mut())
}

/// The caller must stop all calls before freeing, and must free exactly once.
#[no_mangle]
pub unsafe extern "C" fn oftc_bridge_free(session: *mut Bridge) {
    if !session.is_null() {
        unsafe { drop(Box::from_raw(session)) };
    }
}

fn esp_bound(ip_len: usize) -> Option<usize> {
    ip_len.checked_add(2)?.checked_add(15).map(|n| 36 + (n / 16) * 16)
}

/// 0 = bare UDP/4500 ESP payload; -1 = bad ABI; -2 = short output; -3 =
/// packet/policy/crypto rejection; -4 = internal failure. Output length is
/// reset to zero on every call with a non-null output_len. Buffers must not
/// overlap; neither pointer is retained. Caller serializes free with calls.
#[no_mangle]
pub unsafe extern "C" fn oftc_bridge_send_ip(
    session: *mut Bridge,
    input: *const u8,
    input_len: usize,
    output: *mut u8,
    output_cap: usize,
    output_len: *mut usize,
) -> i32 {
    if output_len.is_null() {
        return INVALID_ABI;
    }
    unsafe { *output_len = 0 };
    if session.is_null() || input.is_null() || output.is_null() || input_len == 0
        || input_len > MTU || output_cap > MAX_INPUT
    {
        return INVALID_ABI;
    }
    let Some(required) = esp_bound(input_len) else { return INVALID_ABI };
    if output_cap < required {
        return OUTPUT_TOO_SMALL;
    }
    catch_unwind(AssertUnwindSafe(|| {
        let packet = unsafe { std::slice::from_raw_parts(input, input_len) };
        let session = unsafe { &*session };
        let Ok(mut guard) = session.engine.lock() else { return INTERNAL };
        let Ok(Outbound::UdpPayload(wire)) = guard.send_ip(packet) else { return REJECTED };
        debug_assert!(wire.len() <= output_cap);
        unsafe {
            ptr::copy_nonoverlapping(wire.as_ptr(), output, wire.len());
            *output_len = wire.len();
        }
        OK
    }))
    .unwrap_or(INTERNAL)
}

/// 0 = authenticated IP, 1 = IKE body, 2 = NAT keepalive; negative statuses
/// match send_ip. For any call, output_cap must fit max(MTU, input_len), so a
/// successful ESP decrypt cannot consume replay state and then lose its IP
/// packet to a short output buffer. IKE bytes are returned to the caller.
#[no_mangle]
pub unsafe extern "C" fn oftc_bridge_receive_udp(
    session: *mut Bridge,
    input: *const u8,
    input_len: usize,
    output: *mut u8,
    output_cap: usize,
    output_len: *mut usize,
) -> i32 {
    if output_len.is_null() {
        return INVALID_ABI;
    }
    unsafe { *output_len = 0 };
    if session.is_null() || input.is_null() || output.is_null() || input_len == 0
        || input_len > MAX_INPUT || output_cap > MAX_INPUT
    {
        return INVALID_ABI;
    }
    if output_cap < MTU.max(input_len) {
        return OUTPUT_TOO_SMALL;
    }
    catch_unwind(AssertUnwindSafe(|| {
        let packet = unsafe { std::slice::from_raw_parts(input, input_len) };
        let session = unsafe { &*session };
        let Ok(mut guard) = session.engine.lock() else { return INTERNAL };
        let Ok(inbound) = guard.receive_udp(packet) else { return REJECTED };
        let (status, mut bytes) = match inbound {
            Inbound::Ip(bytes) => (OK, bytes),
            Inbound::Ike(bytes) => (IKE, bytes),
            Inbound::NatKeepalive => (KEEPALIVE, Vec::new()),
        };
        debug_assert!(bytes.len() <= output_cap);
        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), output, bytes.len());
            *output_len = bytes.len();
        }
        // The caller owns the returned plaintext buffer. Clear the temporary.
        bytes.fill(0);
        status
    }))
    .unwrap_or(INTERNAL)
}
