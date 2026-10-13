//! IPv6-outer, no-SSO IKE preflight. The default stops after IKE_SA_INIT.
//! --idi-v4 opts into one initial IKE_AUTH and responder PSK AUTH check.
#[path = "../ike-sa-init/protocol.rs"]
mod init;
#[path = "../ike-auth/auth.rs"]
mod auth;
#[path = "../../client/src/profile.rs"]
mod profile;
#[path = "../../client/src/fctcrypt.rs"]
mod fctcrypt;

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
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
    fn drop(&mut self) { unsafe { oftc_swift_group20_free(self.0) }; }
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

fn select_ipv6(addresses: impl IntoIterator<Item = SocketAddr>) -> Result<SocketAddr, String> {
    addresses.into_iter().find(SocketAddr::is_ipv6)
        .ok_or_else(|| "resolver returned no IPv6 gateway address (native or DNS64)".into())
}

fn endpoint(host: &str, port: u16) -> Result<SocketAddr, String> {
    let addresses = (host, port).to_socket_addrs()
        .map_err(|e| format!("resolve gateway: {e}"))?;
    select_ipv6(addresses)
}

enum Connection {
    Udp(UdpSocket),
    Tcp(TcpStream),
}

impl Connection {
    fn open(remote: SocketAddr, transport: &str) -> Result<(Self, SocketAddr), String> {
        if !remote.is_ipv6() { return Err("IPv6 outer address required".into()); }
        if transport == "udp" {
            let sock = UdpSocket::bind("[::]:0").map_err(|e| format!("UDP bind: {e}"))?;
            sock.connect(remote).map_err(|e| format!("UDP connect: {e}"))?;
            let local = sock.local_addr().map_err(|e| e.to_string())?;
            Ok((Self::Udp(sock), local))
        } else {
            let stream = TcpStream::connect_timeout(&remote, Duration::from_secs(4))
                .map_err(|e| format!("TCP connect: {e}"))?;
            let local = stream.local_addr().map_err(|e| e.to_string())?;
            Ok((Self::Tcp(stream), local))
        }
    }

    fn exchange(&mut self, ike: &[u8], first: bool, id: u32) -> Result<Vec<u8>, String> {
        match self {
            Self::Udp(sock) => {
                let frame = init::udp_frame(ike);
                let mut buf = [0; 4096];
                for timeout in [Duration::from_millis(1500), Duration::from_millis(2500)] {
                    sock.set_read_timeout(Some(timeout)).map_err(|e| e.to_string())?;
                    sock.send(&frame).map_err(|e| format!("UDP send: {e}"))?;
                    for _ in 0..8 {
                        match sock.recv(&mut buf) {
                            Ok(len) => {
                                let packet = init::unframe_udp(&buf[..len])?;
                                if packet.len() >= 28 && packet[20..24] == id.to_be_bytes() {
                                    return Ok(packet.to_vec());
                                }
                                // Ignore a retransmitted reply to the previous request.
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::TimedOut
                                   || e.kind() == std::io::ErrorKind::WouldBlock => break,
                            Err(e) => return Err(format!("UDP receive: {e}")),
                        }
                    }
                }
                Err(format!("no UDP IKE response for message {id}"))
            }
            Self::Tcp(stream) => {
                stream.set_read_timeout(Some(Duration::from_secs(5))).map_err(|e| e.to_string())?;
                stream.set_write_timeout(Some(Duration::from_secs(5))).map_err(|e| e.to_string())?;
                if first { stream.write_all(b"IKETCP").map_err(|e| format!("TCP prefix: {e}"))?; }
                stream.write_all(&init::tcp_frame(ike)?).map_err(|e| format!("TCP send: {e}"))?;
                let mut length = [0; 2];
                stream.read_exact(&mut length).map_err(|e| format!("TCP length: {e}"))?;
                let n = u16::from_be_bytes(length) as usize;
                if !(34..=4096).contains(&n) { return Err("TCP IKE frame size out of bounds".into()); }
                let mut frame = vec![0; n];
                frame[..2].copy_from_slice(&length);
                stream.read_exact(&mut frame[2..]).map_err(|e| format!("TCP body: {e}"))?;
                let packet = init::unframe_tcp(&frame)?;
                if packet.len() < 28 || packet[20..24] != id.to_be_bytes() {
                    return Err("unexpected TCP IKE message ID".into());
                }
                Ok(packet.to_vec())
            }
        }
    }
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let mut host = None;
    let mut transport = "udp";
    let mut idi_v4 = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--gateway" => host = args.next(),
            "--transport" => {
                transport = match args.next().as_deref() {
                    Some("udp") => "udp",
                    Some("tcp") => "tcp",
                    _ => return Err("--transport must be udp or tcp".into()),
                };
            }
            "--idi-v4" => {
                idi_v4 = Some(args.next().ok_or("--idi-v4 requires an address")?
                    .parse::<Ipv4Addr>().map_err(|e| format!("invalid IDi IPv4 address: {e}"))?);
            }
            _ => return Err("usage: ipv6-outer --gateway HOST [--transport udp|tcp] [--idi-v4 ADDRESS]".into()),
        }
    }
    let host = host.ok_or("--gateway is required")?;
    let remote = endpoint(&host, if transport == "udp" { 4500 } else { 4443 })?;
    let (mut conn, local) = Connection::open(remote, transport)?;
    let (key, public) = new_key()?;
    let mut spi_i = random::<8>()?;
    if spi_i == [0; 8] { spi_i[7] = 1; }
    let ni = random::<32>()?;
    let request = init::request(spi_i, ni, public, local, remote);
    let reply = conn.exchange(&request, true, 0)?;
    let selected = init::parse_response(&reply, &spi_i, local, remote)?;
    if selected.selected != 1 { return Err("gateway selected unsupported IKE suite".into()); }
    let mut dh = shared(&key, &selected.peer_public)?;
    println!("transport={transport} outer_family=IPv6 sa_init=accepted suite=AES256-CBC/SHA256/ECP384 nat_source_match={:?} nat_dest_match={:?} notify_codes={:?}",
             selected.nat_source_match, selected.nat_dest_match, selected.notices);

    if let Some(idi) = idi_v4 {
        let profile = profile::Profile::load("Office VPN")
            .map_err(|e| format!("load local profile: {e}"))?;
        if !profile.psk_is_plaintext { return Err("plaintext profile PSK unavailable".into()); }
        let keys = auth::derive_keys(&ni, &selected.nonce, &spi_i, &selected.spi_r, &dh)?;
        dh.fill(0);
        let first_auth = auth::first_request(&spi_i, &selected.spi_r, &keys, idi)?;
        let auth_reply = conn.exchange(&first_auth, false, 1)?;
        let summary = auth::parse_response(&auth_reply, &spi_i, &selected.spi_r, &keys, 1)?;
        auth::verify_responder_auth(&summary, profile.psk.as_bytes(), &reply, &ni, &keys)?;
        println!("transport={transport} outer_family=IPv6 responder_psk_auth=verified eap_code={:?} eap_type={:?} notify_codes={:?}",
                 summary.eap_code, summary.eap_type, summary.notices);
    } else {
        dh.fill(0);
    }
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("IPv6 outer preflight: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv6Addr, SocketAddrV4, SocketAddrV6};

    fn v6(ip: &str, port: u16) -> SocketAddr {
        SocketAddr::V6(SocketAddrV6::new(ip.parse::<Ipv6Addr>().unwrap(), port, 0, 0))
    }

    #[test]
    fn resolver_selection_requires_v6_and_preserves_port() {
        let v4 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 4500));
        let dns64 = v6("64:ff9b::c000:201", 4500);
        assert_eq!(select_ipv6([v4, dns64]).unwrap(), dns64);
        assert!(select_ipv6([v4]).is_err());
        assert_eq!(select_ipv6([v6("2001:db8::2", 4443)]).unwrap().port(), 4443);
    }

    #[test]
    fn ipv6_nat_d_hashes_include_16_address_bytes_and_transport_port() {
        // Independent hashlib.sha1(SPIi || SPIr || IPv6 address || UDP/TCP port).
        let local = v6("2001:db8::1", 34567);
        let udp_peer = v6("64:ff9b::c000:201", 4500);
        let tcp_peer = v6("64:ff9b::c000:201", 4443);
        let request_udp = init::request([1, 2, 3, 4, 5, 6, 7, 8], [0x55; 32], [0x77; 96],
                                        local, udp_peer);
        let request_tcp = init::request([1, 2, 3, 4, 5, 6, 7, 8], [0x55; 32], [0x77; 96],
                                        local, tcp_peer);
        assert_eq!(&request_udp[268..288], &hex("90d45b6dbce7944c257e4c31ac4378a9f3d2ba56"));
        assert_eq!(&request_udp[296..316], &hex("f4627d8cb80e2bc2f5b5214fabe5f4c009ad04eb"));
        assert_eq!(&request_tcp[296..316], &hex("146c701e2c0c7c1c4ced7f01de8a5010aa7f6a6b"));
        assert_ne!(&request_udp[296..316], &request_tcp[296..316]);
    }

    #[test]
    fn synthetic_ipv6_reply_matches_nat_d_and_detects_translation() {
        let spi = [1, 2, 3, 4, 5, 6, 7, 8];
        let local = v6("2001:db8::1", 34567);
        let remote = v6("64:ff9b::c000:201", 4500);
        let mut reply = init::request(spi, [0x55; 32], [0x77; 96], remote, local);
        reply[8..16].copy_from_slice(&[9; 8]);
        reply[19] = 0x20; // response flag
        reply.drain(28 + 4 + 44..28 + 4 + 88); // keep proposal 1 only
        reply[30..32].copy_from_slice(&48u16.to_be_bytes());
        reply[32] = 0; // last proposal
        let length = reply.len() as u32;
        reply[24..28].copy_from_slice(&length.to_be_bytes());
        reply[224..244].copy_from_slice(&hex("0144b0d59cfa0691fcb5281f72edcc9d56178ae3"));
        reply[252..272].copy_from_slice(&hex("34b7d725510aa51c83e84b8a747224ee6b44f812"));
        let parsed = init::parse_response(&reply, &spi, local, remote).unwrap();
        assert_eq!(parsed.nat_source_match, Some(true));
        assert_eq!(parsed.nat_dest_match, Some(true));
        reply[224] ^= 1;
        let parsed = init::parse_response(&reply, &spi, local, remote).unwrap();
        assert_eq!(parsed.nat_source_match, Some(false));
        assert_eq!(parsed.nat_dest_match, Some(true));
    }

    fn hex(s: &str) -> Vec<u8> {
        s.as_bytes().chunks_exact(2).map(|b| {
            u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap()
        }).collect()
    }
}
