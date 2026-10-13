mod protocol;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::Duration;

unsafe extern "C" {
    fn oftc_swift_group20_generate(key: *mut *mut std::ffi::c_void, public: *mut u8) -> i32;
    fn oftc_swift_group20_shared(
        key: *mut std::ffi::c_void,
        peer: *const u8,
        peer_len: usize,
        secret: *mut u8,
        secret_len: usize,
    ) -> i32;
    fn oftc_swift_group20_free(key: *mut std::ffi::c_void);
    fn oftc_swift_random(output: *mut u8, len: usize) -> i32;
}

struct Key(*mut std::ffi::c_void);
impl Drop for Key {
    fn drop(&mut self) {
        unsafe {
            oftc_swift_group20_free(self.0);
        }
    }
}

fn random<const N: usize>() -> Result<[u8; N], String> {
    let mut out = [0u8; N];
    if unsafe { oftc_swift_random(out.as_mut_ptr(), N) } != 0 {
        return Err("system random generator failed".into());
    }
    Ok(out)
}

fn generate_key() -> Result<(Key, [u8; 96]), String> {
    let mut handle = std::ptr::null_mut();
    let mut public = [0u8; 96];
    if unsafe { oftc_swift_group20_generate(&mut handle, public.as_mut_ptr()) } != 0
        || handle.is_null()
    {
        return Err("CryptoKit P-384 key generation failed".into());
    }
    Ok((Key(handle), public))
}

fn confirm_peer_point(key: &Key, public: &[u8; 96]) -> Result<(), String> {
    let mut secret = [0u8; 48];
    let status = unsafe {
        oftc_swift_group20_shared(
            key.0,
            public.as_ptr(),
            public.len(),
            secret.as_mut_ptr(),
            secret.len(),
        )
    };
    secret.fill(0);
    if status == 0 {
        Ok(())
    } else {
        Err("responder P-384 point rejected".into())
    }
}

fn recv_udp(sock: &UdpSocket, ike: &[u8]) -> Result<Vec<u8>, String> {
    let frame = protocol::udp_frame(ike);
    let mut buf = [0u8; 4096];
    for timeout in [Duration::from_millis(1200), Duration::from_millis(2400)] {
        sock.set_read_timeout(Some(timeout))
            .map_err(|e| e.to_string())?;
        sock.send(&frame).map_err(|e| format!("UDP send: {e}"))?;
        match sock.recv(&mut buf) {
            Ok(n) => return protocol::unframe_udp(&buf[..n]).map(|p| p.to_vec()),
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue
            }
            Err(e) => return Err(format!("UDP receive: {e}")),
        }
    }
    Err("no IKE response after two identical UDP sends; transport may be blocked".into())
}

fn recv_tcp(stream: &mut TcpStream, ike: &[u8]) -> Result<Vec<u8>, String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(4)))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(4)))
        .map_err(|e| e.to_string())?;
    let frame = protocol::tcp_frame(ike)?;
    stream
        .write_all(b"IKETCP")
        .map_err(|e| format!("TCP prefix: {e}"))?;
    stream
        .write_all(&frame)
        .map_err(|e| format!("TCP frame: {e}"))?;
    let mut len_buf = [0u8; 2];
    stream
        .read_exact(&mut len_buf)
        .map_err(|e| format!("no TCP IKE frame: {e}"))?;
    let len = u16::from_be_bytes(len_buf) as usize;
    if !(32..=4096).contains(&len) {
        return Err(format!("TCP frame length {len} out of bounds"));
    }
    let mut frame = vec![0u8; len];
    frame[..2].copy_from_slice(&len_buf);
    stream
        .read_exact(&mut frame[2..])
        .map_err(|e| format!("partial TCP IKE frame: {e}"))?;
    protocol::unframe_tcp(&frame).map(|p| p.to_vec())
}

fn endpoint(host: &str, port: u16, family: &str) -> Result<SocketAddr, String> {
    let addresses = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("resolve gateway: {e}"))?;
    addresses
        .into_iter()
        .find(|a| match family {
            "v4" => a.is_ipv4(),
            "v6" => a.is_ipv6(),
            _ => true,
        })
        .ok_or_else(|| format!("no {family} gateway address"))
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let mut host = None;
    let mut transport = None;
    let mut family = "auto";
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--gateway" => host = args.next(),
            "--transport" => transport = args.next(),
            "--family" => {
                family = match args.next().as_deref() {
                    Some("v4") => "v4",
                    Some("v6") => "v6",
                    Some("auto") => "auto",
                    _ => return Err("--family must be auto, v4, or v6".into()),
                }
            }
            _ => {
                return Err(
                    "usage: probe --gateway HOST --transport udp|tcp [--family auto|v4|v6]".into(),
                )
            }
        }
    }
    let host = host.ok_or("--gateway is required")?;
    let transport = transport.ok_or("--transport is required")?;
    if transport != "udp" && transport != "tcp" {
        return Err("transport must be udp or tcp".into());
    }
    let port = if transport == "udp" { 4500 } else { 4443 };
    let remote = endpoint(&host, port, family)?;
    let (key, public) = generate_key()?;
    let mut spi = random::<8>()?;
    if spi == [0; 8] {
        spi[7] = 1;
    }
    let nonce = random::<32>()?;
    let (ike, reply, local) = if transport == "udp" {
        let bind = if remote.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind).map_err(|e| format!("UDP bind: {e}"))?;
        socket
            .connect(remote)
            .map_err(|e| format!("UDP connect: {e}"))?;
        let local = socket.local_addr().map_err(|e| e.to_string())?;
        let ike = protocol::request(spi, nonce, public, local, remote);
        let reply = recv_udp(&socket, &ike)?;
        (ike, reply, local)
    } else {
        let mut stream = TcpStream::connect_timeout(&remote, Duration::from_secs(3))
            .map_err(|e| format!("TCP connect: {e}"))?;
        let local = stream.local_addr().map_err(|e| e.to_string())?;
        let ike = protocol::request(spi, nonce, public, local, remote);
        let reply = recv_tcp(&mut stream, &ike)?;
        (ike, reply, local)
    };
    let parsed = protocol::parse_response(&reply, &spi, local, remote)?;
    confirm_peer_point(&key, &parsed.peer_public)?;
    println!("transport={transport} outer_family={} request_ike_bytes={} response_ike_bytes={} message_id=0 selected_proposal={} suite={} nonce_bytes={} nat_source_match={:?} nat_dest_match={:?} notices={:?}",
        if remote.is_ipv4() { "IPv4" } else { "IPv6" }, ike.len(), reply.len(), parsed.selected,
        if parsed.selected == 1 { "AES-256-CBC/PRF-SHA256/INTEG-SHA256/ECP-384" }
        else { "AES-256-CBC/PRF-SHA1/INTEG-SHA1/ECP-384" },
        parsed.nonce.len(), parsed.nat_source_match, parsed.nat_dest_match, parsed.notices);
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("SA_INIT probe: {e}");
        std::process::exit(1);
    }
}
