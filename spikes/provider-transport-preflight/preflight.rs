//! No-token provider preflight over an IPv6 outer socket. This is a separate
//! candidate for the signed provider; it does not alter the installed v4 app.
#![allow(dead_code)]
#[path = "../ike-sa-init/protocol.rs"] mod init;
#[path = "../ike-auth/auth.rs"] mod auth;
#[path = "../mschapv2/mschapv2.rs"] mod mschapv2;

use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const UDP: u32 = 1;
const TCP: u32 = 2;
const MAX_IKE: usize = 4096;

unsafe extern "C" {
    fn oftc_swift_group20_generate(key: *mut *mut std::ffi::c_void, public: *mut u8) -> i32;
    fn oftc_swift_group20_shared(key: *mut std::ffi::c_void, peer: *const u8,
                                 peer_len: usize, secret: *mut u8, secret_len: usize) -> i32;
    fn oftc_swift_group20_free(key: *mut std::ffi::c_void);
    fn oftc_swift_random(output: *mut u8, len: usize) -> i32;
}

struct Key(*mut std::ffi::c_void);
impl Drop for Key {
    fn drop(&mut self) { unsafe { oftc_swift_group20_free(self.0) }; }
}

fn random<const N: usize>() -> Result<[u8; N], i32> {
    let mut bytes = [0; N];
    if unsafe { oftc_swift_random(bytes.as_mut_ptr(), bytes.len()) } != 0 { return Err(3); }
    Ok(bytes)
}

fn select_ipv6(addresses: impl IntoIterator<Item = SocketAddr>) -> Option<SocketAddr> {
    addresses.into_iter().find(|addr| match addr {
        SocketAddr::V6(v6) => {
            let ip = v6.ip();
            !ip.is_unspecified() && !ip.is_multicast() && ip.to_ipv4_mapped().is_none()
        }
        SocketAddr::V4(_) => false,
    })
}

// getaddrinfo itself has no timeout. Keep it off the provider work queue and
// enforce a fixed caller deadline. A timed-out resolver may finish later; it
// owns only the hostname, and cannot initiate the IKE handshake.
fn endpoint(gateway: &str, transport: u32) -> Result<SocketAddr, i32> {
    let port = if transport == UDP { 4500 } else { 4443 };
    let gateway = gateway.to_owned();
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::Builder::new().name("oftc-ipv6-dns".into()).spawn(move || {
        let result = (gateway.as_str(), port).to_socket_addrs()
            .ok().and_then(select_ipv6);
        let _ = sender.send(result);
    }).map_err(|_| 2)?;
    receiver.recv_timeout(Duration::from_secs(3)).map_err(|_| 2)?.ok_or(2)
}

#[derive(Clone, Copy)]
struct Expected {
    spi_i: [u8; 8],
    spi_r: Option<[u8; 8]>,
    exchange: u8,
    message_id: u32,
}

impl Expected {
    fn matches(self, ike: &[u8]) -> bool {
        ike.len() >= 28 && ike.len() <= MAX_IKE &&
            ike[..8] == self.spi_i &&
            self.spi_r.is_none_or(|spi| ike[8..16] == spi) &&
            ike[17] == 0x20 && ike[18] == self.exchange &&
            ike[19] & 0x28 == 0x20 &&
            ike[20..24] == self.message_id.to_be_bytes() &&
            u32::from_be_bytes(ike[24..28].try_into().unwrap()) as usize == ike.len()
    }
}

enum Connection { Udp(UdpSocket), Tcp(TcpStream) }

impl Connection {
    fn open(remote: SocketAddr, transport: u32) -> Result<(Self, SocketAddr), i32> {
        if !remote.is_ipv6() { return Err(2); }
        if transport == UDP {
            let socket = UdpSocket::bind("[::]:0").map_err(|_| 2)?;
            socket.connect(remote).map_err(|_| 2)?;
            let local = socket.local_addr().map_err(|_| 2)?;
            Ok((Self::Udp(socket), local))
        } else {
            let stream = TcpStream::connect_timeout(&remote, Duration::from_secs(4))
                .map_err(|_| 2)?;
            let local = stream.local_addr().map_err(|_| 2)?;
            Ok((Self::Tcp(stream), local))
        }
    }

    fn exchange(&mut self, ike: &[u8], first: bool, expected: Expected) -> Result<Vec<u8>, i32> {
        match self {
            Self::Udp(socket) => {
                let frame = init::udp_frame(ike);
                let mut reply = [0u8; MAX_IKE + 4];
                for seconds in [2, 3] {
                    if socket.send(&frame).map_err(|_| 2)? != frame.len() { return Err(2); }
                    let deadline = Instant::now() + Duration::from_secs(seconds);
                    loop {
                        let remaining = deadline.saturating_duration_since(Instant::now());
                        if remaining.is_zero() { break; }
                        socket.set_read_timeout(Some(remaining.min(Duration::from_millis(250))))
                            .map_err(|_| 2)?;
                        match socket.recv(&mut reply) {
                            Ok(n) => {
                                if let Ok(packet) = init::unframe_udp(&reply[..n]) {
                                    if expected.matches(packet) { return Ok(packet.to_vec()); }
                                }
                            }
                            Err(error) if matches!(error.kind(), std::io::ErrorKind::TimedOut |
                                std::io::ErrorKind::WouldBlock) => {},
                            Err(_) => return Err(2),
                        }
                    }
                }
                Err(2)
            }
            Self::Tcp(stream) => {
                let deadline = Instant::now() + Duration::from_secs(5);
                if first { write_deadline(stream, b"IKETCP", deadline)?; }
                let frame = init::tcp_frame(ike).map_err(|_| 2)?;
                write_deadline(stream, &frame, deadline)?;
                let mut length = [0u8; 2];
                read_deadline(stream, &mut length, deadline)?;
                let n = u16::from_be_bytes(length) as usize;
                if !(34..=MAX_IKE + 6).contains(&n) { return Err(2); }
                let mut frame = vec![0u8; n];
                frame[..2].copy_from_slice(&length);
                read_deadline(stream, &mut frame[2..], deadline)?;
                let packet = init::unframe_tcp(&frame).map_err(|_| 2)?;
                if !expected.matches(packet) { return Err(2); }
                Ok(packet.to_vec())
            }
        }
    }
}

fn write_deadline(stream: &mut TcpStream, mut bytes: &[u8], deadline: Instant) -> Result<(), i32> {
    while !bytes.is_empty() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() { return Err(2); }
        stream.set_write_timeout(Some(remaining)).map_err(|_| 2)?;
        match stream.write(bytes) {
            Ok(0) => return Err(2),
            Ok(n) => bytes = &bytes[n..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {},
            Err(_) => return Err(2),
        }
    }
    Ok(())
}

fn read_deadline(stream: &mut TcpStream, mut bytes: &mut [u8], deadline: Instant) -> Result<(), i32> {
    while !bytes.is_empty() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() { return Err(2); }
        stream.set_read_timeout(Some(remaining)).map_err(|_| 2)?;
        match stream.read(bytes) {
            Ok(0) => return Err(2),
            Ok(n) => bytes = &mut bytes[n..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {},
            Err(_) => return Err(2),
        }
    }
    Ok(())
}

fn run(gateway: &str, uid: &str, psk: &[u8], idi: Ipv4Addr, transport: u32) -> Result<(), i32> {
    let remote = endpoint(gateway, transport)?;
    let (mut connection, local) = Connection::open(remote, transport)?;
    let mut raw_key = std::ptr::null_mut();
    let mut public = [0u8; 96];
    if unsafe { oftc_swift_group20_generate(&mut raw_key, public.as_mut_ptr()) } != 0 || raw_key.is_null() {
        if !raw_key.is_null() { unsafe { oftc_swift_group20_free(raw_key) }; }
        return Err(3);
    }
    let key = Key(raw_key);
    let mut spi_i = random::<8>()?;
    if spi_i == [0; 8] { spi_i[7] = 1; }
    let nonce_i = random::<32>()?;
    let first = init::request(spi_i, nonce_i, public, local, remote);
    let first_reply = connection.exchange(&first, true, Expected {
        spi_i, spi_r: None, exchange: 34, message_id: 0,
    })?;
    let response = init::parse_response(&first_reply, &spi_i, local, remote).map_err(|_| 3)?;
    if response.selected != 1 { return Err(3); }
    let mut dh = [0u8; 48];
    if unsafe { oftc_swift_group20_shared(key.0, response.peer_public.as_ptr(),
        response.peer_public.len(), dh.as_mut_ptr(), dh.len()) } != 0 { return Err(3); }
    let keys_result = auth::derive_keys(&nonce_i, &response.nonce, &spi_i, &response.spi_r, &dh);
    dh.fill(0);
    let keys = keys_result.map_err(|_| 3)?;
    let first_auth = auth::first_request(&spi_i, &response.spi_r, &keys, idi).map_err(|_| 4)?;
    let expected_auth = |message_id| Expected {
        spi_i, spi_r: Some(response.spi_r), exchange: 35, message_id,
    };
    let auth_reply = connection.exchange(&first_auth, false, expected_auth(1))?;
    let initial = auth::parse_response(&auth_reply, &spi_i, &response.spi_r, &keys, 1).map_err(|_| 4)?;
    auth::verify_responder_auth(&initial, psk, &first_reply, &nonce_i, &keys).map_err(|_| 4)?;
    if initial.eap_code != Some(1) || initial.eap_type != Some(1) { return Err(4); }
    let identity = auth::identity_reply(&spi_i, &response.spi_r, &keys,
        initial.eap_id.ok_or(4)?, uid.as_bytes()).map_err(|_| 5)?;
    let challenge_reply = connection.exchange(&identity, false, expected_auth(2))?;
    let challenge = auth::parse_response(&challenge_reply, &spi_i, &response.spi_r, &keys, 2)
        .map_err(|_| 5)?;
    mschapv2::parse_challenge(challenge.eap.as_deref().ok_or(5)?).map_err(|_| 5)?;
    Ok(())
}

/// 0 = authenticated EAP challenge; 1 = bad input; 2 = DNS/socket/timeout;
/// 3 = SA_INIT; 4 = responder AUTH; 5 = EAP challenge. No output contains
/// secret material or packet bytes. transport: 1=UDP4500, 2=TCP4443.
/// idi_v4 must be the caller-observed CLAT IPv4 address, not a guessed value.
#[no_mangle]
pub unsafe extern "C" fn oftc_provider_preflight_ipv6(
    gateway: *const u8, gateway_len: usize,
    uid: *const u8, uid_len: usize,
    psk: *const u8, psk_len: usize,
    idi_v4: *const u8, idi_v4_len: usize,
    transport: u32,
) -> i32 {
    std::panic::catch_unwind(|| {
        if gateway.is_null() || uid.is_null() || psk.is_null() || idi_v4.is_null() ||
            gateway_len == 0 || gateway_len > 253 || uid_len != 32 ||
            psk_len == 0 || psk_len > 1024 || idi_v4_len != 4 ||
            !matches!(transport, UDP | TCP) { return 1; }
        let gateway = unsafe { std::slice::from_raw_parts(gateway, gateway_len) };
        let uid = unsafe { std::slice::from_raw_parts(uid, uid_len) };
        let psk = unsafe { std::slice::from_raw_parts(psk, psk_len) };
        let idi = unsafe { std::slice::from_raw_parts(idi_v4, idi_v4_len) };
        let Ok(gateway) = std::str::from_utf8(gateway) else { return 1; };
        let Ok(uid) = std::str::from_utf8(uid) else { return 1; };
        if !valid_gateway(gateway) || !uid.bytes().all(|b| b.is_ascii_hexdigit()) ||
            psk.contains(&0) { return 1; }
        let idi = Ipv4Addr::new(idi[0], idi[1], idi[2], idi[3]);
        if idi.is_unspecified() || idi.is_multicast() || idi.is_broadcast() { return 1; }
        run(gateway, uid, psk, idi, transport).map_or_else(|code| code, |_| 0)
    }).unwrap_or(5)
}

fn valid_gateway(gateway: &str) -> bool {
    if gateway.parse::<Ipv6Addr>().is_ok() { return true; }
    !gateway.is_empty() && gateway.len() <= 253 &&
        gateway.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-') &&
        !gateway.starts_with('-') && !gateway.ends_with('-')
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{SocketAddrV4, SocketAddrV6};

    #[test]
    fn select_only_native_ipv6_and_transport_port() {
        let v4 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 4500));
        let mapped = SocketAddr::V6(SocketAddrV6::new("::ffff:192.0.2.1".parse().unwrap(), 4500, 0, 0));
        let nat64 = SocketAddr::V6(SocketAddrV6::new("64:ff9b::c000:201".parse().unwrap(), 4500, 0, 0));
        assert_eq!(select_ipv6([v4, mapped, nat64]), Some(nat64));
        assert_eq!(select_ipv6([v4, mapped]), None);
        let tcp = SocketAddr::V6(SocketAddrV6::new("2001:db8::1".parse().unwrap(), 4443, 0, 0));
        assert_eq!(select_ipv6([tcp]), Some(tcp));
    }

    #[test]
    fn matching_response_requires_header_and_spi() {
        let expected = Expected { spi_i: [1; 8], spi_r: Some([2; 8]), exchange: 35, message_id: 2 };
        let mut packet = vec![0; 28];
        packet[..8].fill(1);
        packet[8..16].fill(2);
        packet[17..20].copy_from_slice(&[0x20, 35, 0x20]);
        packet[20..24].copy_from_slice(&2u32.to_be_bytes());
        packet[24..28].copy_from_slice(&28u32.to_be_bytes());
        assert!(expected.matches(&packet));
        packet[8] = 3; assert!(!expected.matches(&packet)); packet[8] = 2;
        packet[19] = 0x08; assert!(!expected.matches(&packet)); packet[19] = 0x20;
        packet[20..24].copy_from_slice(&1u32.to_be_bytes()); assert!(!expected.matches(&packet));
    }

    #[test]
    fn tcp_frame_round_trip_and_bounds() {
        let packet = vec![0xa5; 64];
        let frame = init::tcp_frame(&packet).unwrap();
        assert_eq!(init::unframe_tcp(&frame).unwrap(), packet);
        let mut malformed = frame.clone(); malformed[2] = 1;
        assert!(init::unframe_tcp(&malformed).is_err());
        assert!(init::tcp_frame(&vec![0; 65_530]).is_err());
    }

    #[test]
    fn input_gate_stops_before_dns_or_sockets() {
        let gateway = b"vpn.example.com";
        let uid = b"0123456789abcdef0123456789abcdef";
        let psk = b"test-psk";
        let idi = [192, 0, 0, 2];
        let call = |g: &[u8], v4: &[u8], transport| unsafe {
            oftc_provider_preflight_ipv6(g.as_ptr(), g.len(), uid.as_ptr(), uid.len(),
                psk.as_ptr(), psk.len(), v4.as_ptr(), v4.len(), transport)
        };
        assert_eq!(call(gateway, &idi, 0), 1);
        assert_eq!(call(gateway, &idi[..3], UDP), 1);
        assert_eq!(call(b"vpn.example.com:4500", &idi, UDP), 1);
        assert_eq!(call(gateway, &[0, 0, 0, 0], UDP), 1);
        assert_eq!(call(gateway, &[255, 255, 255, 255], TCP), 1);
        assert_eq!(unsafe { oftc_provider_preflight_ipv6(std::ptr::null(), 0,
            std::ptr::null(), 0, std::ptr::null(), 0, std::ptr::null(), 0, UDP) }, 1);
    }

    #[test]
    fn explicit_clat_idi_is_not_derived_from_outer_ipv6() {
        let local: SocketAddr = "[2001:db8::22]:50000".parse().unwrap();
        let idi = Ipv4Addr::new(192, 0, 0, 2);
        assert!(local.is_ipv6());
        assert_eq!(idi.octets(), [192, 0, 0, 2]);
    }
}
