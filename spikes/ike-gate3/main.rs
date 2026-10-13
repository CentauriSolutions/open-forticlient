//! Bounded Gate 3 probe. A preflight reaches the EAP challenge without SSO.
//! --authenticate obtains one fresh SAML token in memory for one attempt.
//! --esp-target sends one direct protected ICMP echo after CHILD_SA validation.
#![allow(dead_code)] // Imported modules expose APIs beyond this narrow probe.
#[path = "../ike-auth/auth.rs"]
mod auth;
#[path = "../ike-sa-init/protocol.rs"]
mod init;
#[path = "../mschapv2/mschapv2.rs"]
mod mschapv2;
#[path = "../engine-integration/engine.rs"]
mod engine;
#[path = "../child-sa/child_sa.rs"]
mod child_sa;
mod icmp;
#[path = "../../client/src/profile.rs"]
mod profile;
#[path = "../../client/src/fctcrypt.rs"]
mod fctcrypt;
#[path = "../../client/src/saml.rs"]
mod saml;
#[path = "../../client/src/tls.rs"]
mod tls;
#[path = "../../client/src/log.rs"]
mod log;

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
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

fn random<const N: usize>() -> Result<[u8; N], String> {
    let mut bytes = [0; N];
    if unsafe { oftc_swift_random(bytes.as_mut_ptr(), bytes.len()) } != 0 {
        return Err("secure random failed".into());
    }
    Ok(bytes)
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

enum Connection {
    Udp(UdpSocket),
    Tcp(TcpStream),
}

impl Connection {
    fn open(host: &str, transport: &str) -> Result<(Self, SocketAddr, SocketAddr), String> {
        let port = if transport == "udp" { 4500 } else { 4443 };
        let remote = (host, port).to_socket_addrs().map_err(|e| format!("resolve gateway: {e}"))?
            .find(SocketAddr::is_ipv4).ok_or("no IPv4 gateway address")?;
        if transport == "udp" {
            let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
            sock.connect(remote).map_err(|e| e.to_string())?;
            let local = sock.local_addr().map_err(|e| e.to_string())?;
            Ok((Self::Udp(sock), local, remote))
        } else {
            let stream = TcpStream::connect_timeout(&remote, Duration::from_secs(4))
                .map_err(|e| format!("TCP connect: {e}"))?;
            let local = stream.local_addr().map_err(|e| e.to_string())?;
            Ok((Self::Tcp(stream), local, remote))
        }
    }

    fn exchange(&mut self, ike: &[u8], first: bool, expected_id: u32) -> Result<Vec<u8>, String> {
        match self {
            Self::Udp(sock) => {
                let frame = init::udp_frame(ike);
                let mut buf = [0; 4096];
                for attempt in 0..2 {
                    let timeout = if expected_id >= 3 {
                        Duration::from_secs(if attempt == 0 { 10 } else { 20 })
                    } else {
                        Duration::from_millis(if attempt == 0 { 1500 } else { 2500 })
                    };
                    sock.set_read_timeout(Some(timeout))
                        .map_err(|e| e.to_string())?;
                    sock.send(&frame).map_err(|e| format!("UDP send: {e}"))?;
                    for _ in 0..8 {
                        match sock.recv(&mut buf) {
                            Ok(len) => {
                                let packet = init::unframe_udp(&buf[..len])?;
                                if packet.len() >= 28 && packet[20..24] == expected_id.to_be_bytes() {
                                    return Ok(packet.to_vec());
                                }
                                // An old retransmitted reply is not this exchange.
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::TimedOut
                                   || e.kind() == std::io::ErrorKind::WouldBlock => break,
                            Err(e) => return Err(format!("UDP receive: {e}")),
                        }
                    }
                }
                Err(format!("no UDP response for IKE message {expected_id}"))
            }
            Self::Tcp(stream) => {
                stream.set_read_timeout(Some(Duration::from_secs(if expected_id >= 3 { 30 } else { 5 })))
                    .map_err(|e| e.to_string())?;
                stream.set_write_timeout(Some(Duration::from_secs(5))).map_err(|e| e.to_string())?;
                if first { stream.write_all(b"IKETCP").map_err(|e| format!("TCP prefix: {e}"))?; }
                stream.write_all(&init::tcp_frame(ike)?).map_err(|e| format!("TCP send: {e}"))?;
                let mut length = [0; 2];
                stream.read_exact(&mut length).map_err(|e| format!("TCP length: {e}"))?;
                let n = u16::from_be_bytes(length) as usize;
                if !(34..=4096).contains(&n) { return Err("TCP frame size out of bounds".into()); }
                let mut frame = vec![0; n];
                frame[..2].copy_from_slice(&length);
                stream.read_exact(&mut frame[2..]).map_err(|e| format!("TCP body: {e}"))?;
                let packet = init::unframe_tcp(&frame)?;
                if packet.len() < 28 || packet[20..24] != expected_id.to_be_bytes() {
                    return Err("unexpected TCP IKE message ID".into());
                }
                Ok(packet.to_vec())
            }
        }
    }
}

fn wipe_string(value: &mut String) {
    // The token is single use and must not linger in this process after EAP.
    for byte in unsafe { value.as_bytes_mut() } {
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

fn udp_esp_probe(connection: &mut Connection,
                 engine: &mut engine::Engine<engine::esp::SystemCrypto>,
                 assigned: Ipv4Addr, target: Ipv4Addr) -> Result<(), String> {
    let Connection::Udp(sock) = connection else {
        return Err("live ESP probe currently requires UDP transport".into());
    };
    let id = u16::from_be_bytes(random::<2>()?);
    let packet = icmp::echo_request(assigned, target, id);
    let outbound = engine.send_ip(&packet).map_err(|e| format!("ESP outbound: {e:?}"))?;
    let engine::Outbound::UdpPayload(wire) = outbound else {
        return Err("ESP engine selected unexpected transport".into());
    };
    sock.send(&wire).map_err(|e| format!("UDP ESP send: {e}"))?;
    println!("stage=esp_echo_sent");
    let deadline = Instant::now() + Duration::from_secs(12);
    let mut buf = [0u8; 4096];
    let mut other_ip = 0u32;
    let mut icmp_errors = 0u32;
    let mut ike = 0u32;
    let mut keepalives = 0u32;
    let mut rejected = 0u32;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() { break; }
        sock.set_read_timeout(Some(remaining))
            .map_err(|e| e.to_string())?;
        let len = match sock.recv(&mut buf) {
            Ok(len) => len,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut
                   || e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(format!("UDP ESP receive: {e}")),
        };
        match engine.receive_udp(&buf[..len]) {
            Ok(engine::Inbound::Ip(ip)) if icmp::is_echo_reply(&ip, assigned, target, id) => {
                println!("stage=esp_echo_reply_authenticated");
                return Ok(());
            }
            Ok(engine::Inbound::Ip(ip)) => {
                if icmp::is_icmp_error(&ip, assigned) { icmp_errors += 1; }
                else { other_ip += 1; }
            }
            Ok(engine::Inbound::Ike(_)) => ike += 1,
            Ok(engine::Inbound::NatKeepalive) => keepalives += 1,
            Err(_) => rejected += 1,
        }
    }
    Err(format!("no authenticated ICMP echo reply within 12 seconds; authenticated_icmp_errors={icmp_errors} other_authenticated_ip={other_ip} ike_frames={ike} keepalives={keepalives} rejected_frames={rejected}"))
}

fn attempt(profile: &profile::Profile, transport: &str,
           credentials: Option<&mut saml::Credentials>,
           esp_target: Option<Ipv4Addr>) -> Result<(), String> {
    let (mut connection, local, remote) = Connection::open(&profile.server, transport)?;
    let (key, public) = new_key()?;
    let mut spi_i = random::<8>()?;
    if spi_i == [0; 8] { spi_i[7] = 1; }
    let nonce_i = random::<32>()?;
    let first = init::request(spi_i, nonce_i, public, local, remote);
    let first_reply = connection.exchange(&first, true, 0)?;
    let init_response = init::parse_response(&first_reply, &spi_i, local, remote)?;
    if init_response.selected != 1 { return Err("gateway chose unexpected IKE suite".into()); }
    let mut dh = shared(&key, &init_response.peer_public)?;
    let keys = auth::derive_keys(&nonce_i, &init_response.nonce, &spi_i,
                                 &init_response.spi_r, &dh)?;
    dh.fill(0);
    let local_v4 = match local.ip() { std::net::IpAddr::V4(ip) => ip, _ => unreachable!() };
    let request = auth::first_request_with_child_spi(&spi_i, &init_response.spi_r,
                                                      &keys, local_v4)?;
    let first_auth_reply = connection.exchange(&request.packet, false, 1)?;
    let initial = auth::parse_response(&first_auth_reply, &spi_i, &init_response.spi_r, &keys, 1)?;
    auth::verify_responder_auth(&initial, profile.psk.as_bytes(), &first_reply, &nonce_i, &keys)?;
    if initial.eap_code != Some(1) || initial.eap_type != Some(1) {
        return Err(format!("verified responder did not request EAP Identity; notices={:?}", initial.notices));
    }
    let idr = initial.idr.as_deref().ok_or("missing authenticated IDr")?.to_vec();
    println!("transport={transport} stage=responder_auth_verified");

    let uid = profile.uid.as_str();
    if credentials.as_ref().is_some_and(|c| c.uid != uid) {
        return Err("SAML bootstrap UID differs from profile EAP identity".into());
    }
    let identity = auth::identity_reply(&spi_i, &init_response.spi_r, &keys,
                                        initial.eap_id.ok_or("missing EAP identifier")?,
                                        uid.as_bytes())?;
    let challenge_reply = connection.exchange(&identity, false, 2)?;
    let challenge_summary = auth::parse_response(&challenge_reply, &spi_i, &init_response.spi_r,
                                                  &keys, 2)?;
    let challenge = mschapv2::parse_challenge(challenge_summary.eap.as_deref()
        .ok_or("no EAP challenge after UID")?).map_err(|e| format!("EAP challenge: {e:?}"))?;
    println!("transport={transport} stage=mschapv2_challenge_received");
    let Some(credentials) = credentials else { return Ok(()); };
    if credentials.tokenid.is_empty() {
        return Err("SAML callback missing token".into());
    }
    // Fortinet's CONNECT supplies the bootstrap UID as its EAP username too.
    // The callback username is display metadata, not the EAP method identity.
    let prepared_result = mschapv2::respond(&challenge, uid, &credentials.tokenid);
    wipe_string(&mut credentials.tokenid);
    let prepared = prepared_result.map_err(|e| format!("MSCHAPv2 response build: {e:?}"))?;
    let response = auth::eap_reply(&spi_i, &init_response.spi_r, &keys, 3, &prepared.eap_response)?;
    let method_reply = connection.exchange(&response, false, 3)?;
    let method = auth::parse_response(&method_reply, &spi_i, &init_response.spi_r, &keys, 3)?;
    if method.eap_mschap_opcode == Some(4) {
        let failure = mschapv2::parse_failure(method.eap.as_deref().unwrap())
            .map_err(|e| format!("MSCHAPv2 failure malformed: {e:?}"))?;
        return Err(format!("MSCHAPv2 rejected: code={} retry_allowed={}",
                           failure.error_code, failure.retry_allowed));
    }
    if method.eap_code == Some(4) {
        return Err(format!("outer EAP Failure after MSCHAPv2 response; notices={:?}",
                           method.notices));
    }
    let verified = prepared.verify_success(method.eap.as_deref()
        .ok_or("missing inner MSCHAPv2 Success")?)
        .map_err(|e| format!("inner MSCHAPv2 Success: {e:?}"))?;
    println!("transport={transport} stage=mschapv2_server_verified");
    let ack = auth::eap_reply(&spi_i, &init_response.spi_r, &keys, 4, &verified.success_ack)?;
    let outer_reply = connection.exchange(&ack, false, 4)?;
    let outer = auth::parse_response(&outer_reply, &spi_i, &init_response.spi_r, &keys, 4)?;
    if outer.eap.as_deref().is_none_or(|e| e.len() != 4 || e[0] != 3) {
        return Err(format!("outer EAP Success absent; code={:?} notices={:?}",
                           outer.eap_code, outer.notices));
    }
    println!("transport={transport} stage=outer_eap_success");
    let final_request = auth::final_auth_request(&spi_i, &init_response.spi_r, &keys, 5,
                                                  verified.msk(), &first,
                                                  &init_response.nonce, &request.idi)?;
    let final_reply = connection.exchange(&final_request, false, 5)?;
    let final_summary = auth::parse_response(&final_reply, &spi_i, &init_response.spi_r, &keys, 5)?;
    if final_summary.auth.is_none() {
        return Err(format!("final IKE_AUTH omitted AUTH; notices={:?}", final_summary.notices));
    }
    auth::verify_final_auth(&final_summary, &idr, verified.msk(), &first_reply, &nonce_i, &keys)?;
    println!("transport={transport} stage=final_auth_verified child_sa={} selectors={} cp={} notices={:?}",
             final_summary.sa.is_some(),
             final_summary.tsi.is_some() && final_summary.tsr.is_some(),
             final_summary.cp.is_some(), final_summary.notices);
    let negotiated = child_sa::parse_final(
        final_summary.sa.as_deref().ok_or("final IKE_AUTH omitted CHILD_SA")?,
        final_summary.tsi.as_deref().ok_or("final IKE_AUTH omitted TSi")?,
        final_summary.tsr.as_deref().ok_or("final IKE_AUTH omitted TSr")?,
        final_summary.cp.as_deref().ok_or("final IKE_AUTH omitted CP")?,
        request.child_spi, &request.offered_tsi, &request.offered_tsr,
    ).map_err(|e| format!("CHILD_SA contract: {e:?}"))?;
    let (handoff, configuration) = child_sa::into_engine(
        negotiated, &keys.sk_d, &nonce_i, &init_response.nonce,
        |key, data| auth::prf_sha256(key, data).map_err(|_| child_sa::Error::Crypto),
        if transport == "udp" { engine::Transport::Udp4500 } else { engine::Transport::Tcp4443 },
        1280, 4096,
    ).map_err(|e| format!("CHILD_SA key derivation: {e:?}"))?;
    let mut engine = engine::Engine::install(handoff, engine::esp::SystemCrypto)
        .map_err(|e| format!("ESP engine install: {e:?}"))?;
    println!("transport={transport} stage=child_sa_handoff_validated routes={} dns_servers={} dns_domains={}",
             configuration.split_routes.len(), configuration.dns_servers.len(),
             configuration.dns_domains.len());
    if let Some(target) = esp_target {
        udp_esp_probe(&mut connection, &mut engine, configuration.assigned_ipv4, target)?;
    }
    Ok(())
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut transport = "udp";
    let mut authenticate = false;
    let mut insecure = false;
    let mut esp_target = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--transport" if i + 1 < args.len() => { i += 1; transport = &args[i]; }
            "--authenticate" => authenticate = true,
            "--insecure" => insecure = true,
            "--esp-target" if i + 1 < args.len() => {
                i += 1;
                esp_target = Some(args[i].parse::<Ipv4Addr>()
                    .map_err(|_| "--esp-target requires an IPv4 address")?);
            }
            _ => return Err("usage: gate3 [--transport udp|tcp] [--authenticate] [--esp-target IP] [--insecure]".into()),
        }
        i += 1;
    }
    if transport != "udp" && transport != "tcp" { return Err("transport must be udp or tcp".into()); }
    if esp_target.is_some() && (!authenticate || transport != "udp") {
        return Err("--esp-target requires --authenticate and UDP transport".into());
    }
    let profile = profile::Profile::load("Office VPN").map_err(|e| format!("load profile: {e}"))?;
    if !profile.psk_is_plaintext { return Err("plaintext profile PSK unavailable".into()); }
    attempt(&profile, transport, None, None)?;
    if !authenticate { return Ok(()); }
    println!("stage=preflight_passed starting_saml");
    let cfg = saml::SamlConfig {
        server: profile.server.clone(), saml_port: profile.saml_port,
        insecure, ..Default::default()
    };
    let mut creds = saml::obtain(&cfg).map_err(|e| format!("SAML: {e}"))?;
    let result = attempt(&profile, transport, Some(&mut creds), esp_target);
    wipe_string(&mut creds.tokenid);
    result
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Gate 3: {e}");
        std::process::exit(1);
    }
}
