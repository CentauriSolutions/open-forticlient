//! No-SSO IKE_AUTH probe. The default verifies responder PSK AUTH and stops.
//! --send-uid is an explicit, separately authorized EAP Identity experiment.
mod auth;
#[path = "../ike-sa-init/protocol.rs"]
mod init;
#[path = "../../client/src/profile.rs"]
mod profile;
#[path = "../../client/src/fctcrypt.rs"]
mod fctcrypt;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::Duration;

unsafe extern "C" {
    fn oftc_swift_group20_generate(key: *mut *mut std::ffi::c_void, public: *mut u8) -> i32;
    fn oftc_swift_group20_shared(
        key: *mut std::ffi::c_void, peer: *const u8, peer_len: usize,
        secret: *mut u8, secret_len: usize,
    ) -> i32;
    fn oftc_swift_group20_free(key: *mut std::ffi::c_void);
    fn oftc_swift_random(output: *mut u8, len: usize) -> i32;
}

struct Key(*mut std::ffi::c_void);
impl Drop for Key {
    fn drop(&mut self) { unsafe { oftc_swift_group20_free(self.0); } }
}

fn random<const N: usize>() -> Result<[u8; N], String> {
    let mut out = [0; N];
    if unsafe { oftc_swift_random(out.as_mut_ptr(), out.len()) } != 0 {
        return Err("secure random failed".into());
    }
    Ok(out)
}

fn new_key() -> Result<(Key, [u8; 96]), String> {
    let mut raw = std::ptr::null_mut();
    let mut public = [0; 96];
    if unsafe { oftc_swift_group20_generate(&mut raw, public.as_mut_ptr()) } != 0
        || raw.is_null() { return Err("P-384 generation failed".into()); }
    Ok((Key(raw), public))
}

fn shared(key: &Key, peer: &[u8; 96]) -> Result<[u8; 48], String> {
    let mut secret = [0; 48];
    if unsafe { oftc_swift_group20_shared(key.0, peer.as_ptr(), peer.len(),
                                            secret.as_mut_ptr(), secret.len()) } != 0 {
        return Err("responder P-384 point rejected".into());
    }
    Ok(secret)
}

fn endpoint(host: &str, port: u16) -> Result<SocketAddr, String> {
    (host, port).to_socket_addrs().map_err(|e| format!("resolve gateway: {e}"))?
        .find(SocketAddr::is_ipv4).ok_or("no IPv4 gateway address".into())
}

fn udp_exchange(sock: &UdpSocket, ike: &[u8], attempts: usize) -> Result<Vec<u8>, String> {
    let frame = init::udp_frame(ike);
    let mut buf = [0; 4096];
    for n in 0..attempts {
        sock.set_read_timeout(Some(Duration::from_millis(if n == 0 { 1500 } else { 2500 })))
            .map_err(|e| e.to_string())?;
        sock.send(&frame).map_err(|e| format!("UDP send: {e}"))?;
        match sock.recv(&mut buf) {
            Ok(len) => return init::unframe_udp(&buf[..len]).map(|x| x.to_vec()),
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut
                   || e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(format!("UDP receive: {e}")),
        }
    }
    Err("no UDP IKE response after bounded sends".into())
}

fn tcp_exchange(stream: &mut TcpStream, ike: &[u8], first: bool) -> Result<Vec<u8>, String> {
    stream.set_read_timeout(Some(Duration::from_secs(4))).map_err(|e| e.to_string())?;
    stream.set_write_timeout(Some(Duration::from_secs(4))).map_err(|e| e.to_string())?;
    if first { stream.write_all(b"IKETCP").map_err(|e| format!("TCP prefix: {e}"))?; }
    stream.write_all(&init::tcp_frame(ike)?).map_err(|e| format!("TCP write: {e}"))?;
    let mut len = [0; 2];
    stream.read_exact(&mut len).map_err(|e| format!("TCP frame header: {e}"))?;
    let n = u16::from_be_bytes(len) as usize;
    if !(34..=4096).contains(&n) { return Err("TCP IKE frame length out of bounds".into()); }
    let mut frame = vec![0; n];
    frame[..2].copy_from_slice(&len);
    stream.read_exact(&mut frame[2..]).map_err(|e| format!("TCP frame body: {e}"))?;
    init::unframe_tcp(&frame).map(|x| x.to_vec())
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let mut host = None;
    let mut transport = None;
    let mut send_uid = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--gateway" => host = args.next(),
            "--transport" => transport = args.next(),
            "--send-uid" => send_uid = true,
            _ => return Err("usage: probe --gateway HOST --transport udp|tcp [--send-uid]".into()),
        }
    }
    let host = host.ok_or("--gateway is required")?;
    let transport = transport.ok_or("--transport is required")?;
    if transport != "udp" && transport != "tcp" {
        return Err("--transport must be udp or tcp".into());
    }
    let remote = endpoint(&host, if transport == "udp" { 4500 } else { 4443 })?;
    let profile = profile::Profile::load("Office VPN")
        .map_err(|e| format!("load local profile: {e}"))?;
    if !profile.psk_is_plaintext {
        return Err("plaintext profile PSK unavailable".into());
    }
    if send_uid && (profile.uid.len() != 32 ||
                    !profile.uid.as_bytes().iter().all(u8::is_ascii_hexdigit)) {
        return Err("32-byte hex machine UID unavailable".into());
    }
    let (key, public) = new_key()?;
    let mut spi_i = random::<8>()?;
    if spi_i == [0; 8] { spi_i[7] = 1; }
    let nonce_i = random::<32>()?;

    if transport == "udp" {
        let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
        sock.connect(remote).map_err(|e| e.to_string())?;
        let local = sock.local_addr().map_err(|e| e.to_string())?;
        let first = init::request(spi_i, nonce_i, public, local, remote);
        let first_reply = udp_exchange(&sock, &first, 2)?;
        let init_response = init::parse_response(&first_reply, &spi_i, local, remote)?;
        if init_response.selected != 1 { return Err("unexpected IKE suite".into()); }
        let mut dh = shared(&key, &init_response.peer_public)?;
        let keys = auth::derive_keys(&nonce_i, &init_response.nonce, &spi_i,
                                     &init_response.spi_r, &dh)?;
        dh.fill(0);
        let ip = match local.ip() { std::net::IpAddr::V4(ip) => ip, _ => unreachable!() };
        let second = auth::first_request(&spi_i, &init_response.spi_r, &keys, ip)?;
        let reply = udp_exchange(&sock, &second, 2)?;
        let summary = auth::parse_response(&reply, &spi_i, &init_response.spi_r, &keys, 1)?;
        auth::verify_responder_auth(&summary, profile.psk.as_bytes(), &first_reply,
                                    &nonce_i, &keys)?;
        println!("transport=udp sa_init=accepted responder_psk_auth=verified eap_code={:?} eap_type={:?} notify_codes={:?}",
                 summary.eap_code, summary.eap_type, summary.notices);
        if send_uid {
            if summary.eap_code != Some(1) || summary.eap_type != Some(1) {
                return Err("verified responder did not request EAP Identity".into());
            }
            let identity = auth::identity_reply(&spi_i, &init_response.spi_r, &keys,
                                                 summary.eap_id.unwrap(), profile.uid.as_bytes())?;
            let method_reply = udp_exchange(&sock, &identity, 2)?;
            let method = auth::parse_response(&method_reply, &spi_i, &init_response.spi_r, &keys, 2)?;
            println!("transport=udp eap_after_identity_code={:?} eap_after_identity_type={:?} eap_vendor={:?} eap_vendor_type={:?} mschap_opcode={:?} challenge_size={:?} notify_codes={:?}",
                     method.eap_code, method.eap_type, method.eap_vendor,
                     method.eap_vendor_type, method.eap_mschap_opcode,
                     method.eap_mschap_challenge_size, method.notices);
        }
    } else {
        let mut stream = TcpStream::connect_timeout(&remote, Duration::from_secs(3))
            .map_err(|e| format!("TCP connect: {e}"))?;
        let local = stream.local_addr().map_err(|e| e.to_string())?;
        let first = init::request(spi_i, nonce_i, public, local, remote);
        let first_reply = tcp_exchange(&mut stream, &first, true)?;
        let init_response = init::parse_response(&first_reply, &spi_i, local, remote)?;
        if init_response.selected != 1 { return Err("unexpected IKE suite".into()); }
        let mut dh = shared(&key, &init_response.peer_public)?;
        let keys = auth::derive_keys(&nonce_i, &init_response.nonce, &spi_i,
                                     &init_response.spi_r, &dh)?;
        dh.fill(0);
        let ip = match local.ip() { std::net::IpAddr::V4(ip) => ip, _ => unreachable!() };
        let second = auth::first_request(&spi_i, &init_response.spi_r, &keys, ip)?;
        let reply = tcp_exchange(&mut stream, &second, false)?;
        let summary = auth::parse_response(&reply, &spi_i, &init_response.spi_r, &keys, 1)?;
        auth::verify_responder_auth(&summary, profile.psk.as_bytes(), &first_reply,
                                    &nonce_i, &keys)?;
        println!("transport=tcp sa_init=accepted responder_psk_auth=verified eap_code={:?} eap_type={:?} notify_codes={:?}",
                 summary.eap_code, summary.eap_type, summary.notices);
        if send_uid {
            if summary.eap_code != Some(1) || summary.eap_type != Some(1) {
                return Err("verified responder did not request EAP Identity".into());
            }
            let identity = auth::identity_reply(&spi_i, &init_response.spi_r, &keys,
                                                 summary.eap_id.unwrap(), profile.uid.as_bytes())?;
            let method_reply = tcp_exchange(&mut stream, &identity, false)?;
            let method = auth::parse_response(&method_reply, &spi_i, &init_response.spi_r, &keys, 2)?;
            println!("transport=tcp eap_after_identity_code={:?} eap_after_identity_type={:?} eap_vendor={:?} eap_vendor_type={:?} mschap_opcode={:?} challenge_size={:?} notify_codes={:?}",
                     method.eap_code, method.eap_type, method.eap_vendor,
                     method.eap_vendor_type, method.eap_mschap_opcode,
                     method.eap_mschap_challenge_size, method.notices);
        }
    }
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("IKE_AUTH probe: {e}");
        std::process::exit(1);
    }
}
