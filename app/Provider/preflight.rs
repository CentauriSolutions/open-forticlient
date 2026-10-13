//! Provider-process no-token preflight. It verifies SA_INIT, responder AUTH,
//! then the EAP-MSCHAPv2 challenge. No CHILD_SA, ESP, routes, or token.
#![allow(dead_code)]
#[path = "../core/ike-sa-init/protocol.rs"] mod init;
#[path = "../core/ike-auth/auth.rs"] mod auth;
#[path = "../core/mschapv2/mschapv2.rs"] mod mschapv2;

use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

unsafe extern "C" {
    fn oftc_swift_group20_generate(key: *mut *mut std::ffi::c_void, public: *mut u8) -> i32;
    fn oftc_swift_group20_shared(key: *mut std::ffi::c_void, peer: *const u8,
                                 peer_len: usize, secret: *mut u8, secret_len: usize) -> i32;
    fn oftc_swift_group20_free(key: *mut std::ffi::c_void);
    fn oftc_swift_random(output: *mut u8, len: usize) -> i32;
}

struct Key(*mut std::ffi::c_void);
impl Drop for Key { fn drop(&mut self) { unsafe { oftc_swift_group20_free(self.0) }; } }

fn random<const N: usize>() -> Result<[u8; N], i32> {
    let mut bytes = [0; N];
    if unsafe { oftc_swift_random(bytes.as_mut_ptr(), N) } != 0 { return Err(3); }
    Ok(bytes)
}

fn exchange(socket: &UdpSocket, ike: &[u8], id: u32) -> Result<Vec<u8>, i32> {
    let frame = init::udp_frame(ike);
    let mut reply = [0u8; 4096];
    for seconds in [2, 3] {
        if socket.send(&frame).map_err(|_| 2)? != frame.len() { return Err(2); }
        let deadline = Instant::now() + Duration::from_secs(seconds);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() { break; }
            socket.set_read_timeout(Some(left.min(Duration::from_millis(250)))).map_err(|_| 2)?;
            match socket.recv(&mut reply) {
                Ok(len) if len >= 32 && reply[..4] == [0; 4] => {
                    let response = init::unframe_udp(&reply[..len]).map_err(|_| 3)?;
                    if response[20..24] == id.to_be_bytes() { return Ok(response.to_vec()); }
                }
                Ok(_) => {},
                Err(error) if matches!(error.kind(), std::io::ErrorKind::TimedOut |
                    std::io::ErrorKind::WouldBlock) => {},
                Err(_) => return Err(2),
            }
        }
    }
    Err(2)
}

fn run(gateway: &str, uid: &str, psk: &[u8]) -> Result<(), i32> {
    let remote = (gateway, 4500).to_socket_addrs().map_err(|_| 2)?
        .find(SocketAddr::is_ipv4).ok_or(2)?;
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|_| 2)?;
    socket.connect(remote).map_err(|_| 2)?;
    let local = socket.local_addr().map_err(|_| 2)?;
    let IpAddr::V4(local_v4) = local.ip() else { return Err(2); };
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
    let first_reply = exchange(&socket, &first, 0)?;
    let response = init::parse_response(&first_reply, &spi_i, local, remote).map_err(|_| 3)?;
    if response.selected != 1 { return Err(3); }
    let mut dh = [0u8; 48];
    if unsafe { oftc_swift_group20_shared(key.0, response.peer_public.as_ptr(),
        response.peer_public.len(), dh.as_mut_ptr(), dh.len()) } != 0 { return Err(3); }
    let keys_result = auth::derive_keys(&nonce_i, &response.nonce, &spi_i, &response.spi_r, &dh);
    dh.fill(0);
    let keys = keys_result.map_err(|_| 3)?;
    let first_auth = auth::first_request(&spi_i, &response.spi_r, &keys, local_v4).map_err(|_| 4)?;
    let auth_reply = exchange(&socket, &first_auth, 1)?;
    let initial = auth::parse_response(&auth_reply, &spi_i, &response.spi_r, &keys, 1).map_err(|_| 4)?;
    auth::verify_responder_auth(&initial, psk, &first_reply, &nonce_i, &keys).map_err(|_| 4)?;
    if initial.eap_code != Some(1) || initial.eap_type != Some(1) { return Err(4); }
    let identity = auth::identity_reply(&spi_i, &response.spi_r, &keys,
        initial.eap_id.ok_or(4)?, uid.as_bytes()).map_err(|_| 5)?;
    let challenge_reply = exchange(&socket, &identity, 2)?;
    let challenge = auth::parse_response(&challenge_reply, &spi_i, &response.spi_r, &keys, 2)
        .map_err(|_| 5)?;
    mschapv2::parse_challenge(challenge.eap.as_deref().ok_or(5)?).map_err(|_| 5)?;
    Ok(())
}

/// 0 = authenticated EAP challenge received; 1 = invalid input;
/// 2 = socket/timeout; 3 = SA_INIT; 4 = responder AUTH; 5 = EAP challenge.
/// No diagnostic may include PSK or packet bytes.
#[no_mangle]
pub unsafe extern "C" fn oftc_provider_preflight(
    gateway: *const u8, gateway_len: usize,
    uid: *const u8, uid_len: usize,
    psk: *const u8, psk_len: usize,
) -> i32 {
    std::panic::catch_unwind(|| {
        if gateway.is_null() || uid.is_null() || psk.is_null() ||
            gateway_len == 0 || gateway_len > 253 || uid_len != 32 ||
            psk_len == 0 || psk_len > 1024 { return 1; }
        let gateway = unsafe { std::slice::from_raw_parts(gateway, gateway_len) };
        let uid = unsafe { std::slice::from_raw_parts(uid, uid_len) };
        let psk = unsafe { std::slice::from_raw_parts(psk, psk_len) };
        let Ok(gateway) = std::str::from_utf8(gateway) else { return 1; };
        let Ok(uid) = std::str::from_utf8(uid) else { return 1; };
        if !uid.bytes().all(|b| b.is_ascii_hexdigit()) || psk.contains(&0) { return 1; }
        run(gateway, uid, psk).map_or_else(|code| code, |_| 0)
    }).unwrap_or(5)
}

#[cfg(test)]
mod tests {
    #[test]
    fn bad_inputs_never_open_a_socket() {
        let status = unsafe { super::oftc_provider_preflight(
            std::ptr::null(), 0, std::ptr::null(), 0, std::ptr::null(), 0) };
        assert_eq!(status, 1);
    }
}
