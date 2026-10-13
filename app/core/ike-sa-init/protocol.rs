//! Narrow, unauthenticated IKE_SA_INIT wire format for the observed gateway.
//! All integers in IKE and RFC 9329 frames are network byte order.
use std::net::{IpAddr, SocketAddr};

const SA: u8 = 33;
const KE: u8 = 34;
const NONCE: u8 = 40;
const NOTIFY: u8 = 41;
const VID: u8 = 43;
const NAT_SOURCE: u16 = 16388;
const NAT_DEST: u16 = 16389;
const VIDS: [[u8; 16]; 3] = [
    [
        0x4c, 0x53, 0x42, 0x7b, 0x6d, 0x46, 0x5d, 0x1b, 0x33, 0x7b, 0xb7, 0x55, 0xa3, 0x7a, 0x7f,
        0xef,
    ],
    [
        0xb4, 0xf0, 0x1c, 0xa9, 0x51, 0xe9, 0xda, 0x8d, 0x0b, 0xaf, 0xbb, 0xd3, 0x4a, 0xd3, 0x04,
        0x4e,
    ],
    [
        0xc1, 0xdc, 0x43, 0x50, 0x47, 0x6b, 0x98, 0xa4, 0x29, 0xb9, 0x17, 0x81, 0x91, 0x4c, 0xa4,
        0x3e,
    ],
];

unsafe extern "C" {
    fn CC_SHA1(data: *const std::ffi::c_void, len: u32, digest: *mut u8) -> *mut u8;
}

fn u16be(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}
fn u32be(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

fn payload(out: &mut Vec<u8>, next: u8, body: &[u8]) {
    out.push(next);
    out.push(0);
    out.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
    out.extend_from_slice(body);
}

fn transform(out: &mut Vec<u8>, more: bool, kind: u8, id: u16, aes_key: bool) {
    out.extend_from_slice(&[if more { 3 } else { 0 }, 0]);
    out.extend_from_slice(&(if aes_key { 12u16 } else { 8u16 }).to_be_bytes());
    out.extend_from_slice(&[kind, 0]);
    out.extend_from_slice(&id.to_be_bytes());
    if aes_key {
        out.extend_from_slice(&[0x80, 14, 1, 0]);
    } // TV key length 256
}

fn proposal(out: &mut Vec<u8>, number: u8, more: bool, prf: u16, integ: u16) {
    let start = out.len();
    out.extend_from_slice(&[if more { 2 } else { 0 }, 0, 0, 0, number, 1, 0, 4]);
    transform(out, true, 1, 12, true); // ENCR_AES_CBC, 256 bits
    transform(out, true, 2, prf, false);
    transform(out, true, 3, integ, false);
    transform(out, false, 4, 20, false); // ECP-384
    let len = (out.len() - start) as u16;
    out[start + 2..start + 4].copy_from_slice(&len.to_be_bytes());
}

fn nat_hash(spi_i: &[u8; 8], spi_r: &[u8; 8], addr: SocketAddr) -> [u8; 20] {
    let mut input = Vec::with_capacity(34);
    input.extend_from_slice(spi_i);
    input.extend_from_slice(spi_r);
    match addr.ip() {
        IpAddr::V4(ip) => input.extend_from_slice(&ip.octets()),
        IpAddr::V6(ip) => input.extend_from_slice(&ip.octets()),
    }
    input.extend_from_slice(&addr.port().to_be_bytes());
    let mut hash = [0u8; 20];
    // CommonCrypto consumes the bytes immediately; input remains alive here.
    unsafe {
        CC_SHA1(input.as_ptr().cast(), input.len() as u32, hash.as_mut_ptr());
    }
    hash
}

pub fn request(
    spi: [u8; 8],
    nonce: [u8; 32],
    public: [u8; 96],
    local: SocketAddr,
    remote: SocketAddr,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(376);
    out.extend_from_slice(&spi);
    out.extend_from_slice(&[0u8; 8]);
    out.extend_from_slice(&[SA, 0x20, 34, 0x08]); // IKEv2, SA_INIT, initiator
    out.extend_from_slice(&0u32.to_be_bytes()); // first request has message ID 0
    out.extend_from_slice(&0u32.to_be_bytes());
    let mut sa = Vec::new();
    proposal(&mut sa, 1, true, 5, 12); // SHA2-256 PRF and integrity
    proposal(&mut sa, 2, false, 2, 2); // SHA1 PRF and integrity
    payload(&mut out, KE, &sa);
    let mut ke = Vec::with_capacity(100);
    ke.extend_from_slice(&20u16.to_be_bytes());
    ke.extend_from_slice(&[0, 0]);
    ke.extend_from_slice(&public);
    payload(&mut out, NONCE, &ke);
    payload(&mut out, NOTIFY, &nonce);
    for (addr, next, typ) in [(local, NOTIFY, NAT_SOURCE), (remote, VID, NAT_DEST)] {
        let mut body = Vec::with_capacity(24);
        body.extend_from_slice(&[0, 0]); // protocol ID, SPI size
        body.extend_from_slice(&typ.to_be_bytes());
        body.extend_from_slice(&nat_hash(&spi, &[0u8; 8], addr));
        payload(&mut out, next, &body);
    }
    for (i, vid) in VIDS.iter().enumerate() {
        payload(&mut out, if i == 2 { 0 } else { VID }, vid);
    }
    let len = out.len() as u32;
    out[24..28].copy_from_slice(&len.to_be_bytes());
    out
}

pub fn udp_frame(ike: &[u8]) -> Vec<u8> {
    let mut out = vec![0; 4]; // UDP/4500 non-ESP marker
    out.extend_from_slice(ike);
    out
}

pub fn unframe_udp(frame: &[u8]) -> Result<&[u8], String> {
    if frame.len() < 32 || frame[..4] != [0; 4] {
        return Err("UDP reply lacks complete non-ESP-marked IKE packet".into());
    }
    Ok(&frame[4..])
}

pub fn tcp_frame(ike: &[u8]) -> Result<Vec<u8>, String> {
    let size = ike
        .len()
        .checked_add(6)
        .ok_or("TCP frame length overflow")?;
    let size = u16::try_from(size).map_err(|_| "TCP frame too long")?;
    let mut out = Vec::with_capacity(size as usize);
    out.extend_from_slice(&size.to_be_bytes()); // includes 2-byte length and marker
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(ike);
    Ok(out)
}

pub fn unframe_tcp(frame: &[u8]) -> Result<&[u8], String> {
    if frame.len() < 34 || u16be(frame) as usize != frame.len() || frame[2..6] != [0; 4] {
        return Err("invalid TCP IKE length or non-ESP marker".into());
    }
    Ok(&frame[6..])
}

pub struct Response {
    pub spi_r: [u8; 8],
    pub selected: u8,
    pub peer_public: [u8; 96],
    pub nonce: Vec<u8>,
    pub nat_source_match: Option<bool>,
    pub nat_dest_match: Option<bool>,
    pub notices: Vec<u16>,
}

impl std::fmt::Debug for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Response")
            .field("selected", &self.selected)
            .field("nonce_len", &self.nonce.len())
            .field("nat_source_match", &self.nat_source_match)
            .field("nat_dest_match", &self.nat_dest_match)
            .field("notices", &self.notices)
            .finish_non_exhaustive()
    }
}

fn parse_sa(body: &[u8]) -> Result<u8, String> {
    if body.len() < 8 {
        return Err("short SA proposal".into());
    }
    if body[0] != 0
        || u16be(&body[2..4]) as usize != body.len()
        || body[5] != 1
        || body[6] != 0
        || body[7] != 4
    {
        return Err("invalid selected IKE proposal structure".into());
    }
    let number = body[4];
    if number != 1 && number != 2 {
        return Err("unoffered proposal number".into());
    }
    let mut found = [None; 4];
    let mut offset = 8;
    for index in 0..4 {
        if body.len() - offset < 8 {
            return Err("truncated transform".into());
        }
        let t = &body[offset..];
        let len = u16be(&t[2..4]) as usize;
        if len < 8 || len > t.len() || t[0] != if index == 3 { 0 } else { 3 } {
            return Err("invalid transform length or chain".into());
        }
        let typ = t[4];
        if !(1..=4).contains(&typ) || found[(typ - 1) as usize].is_some() {
            return Err("duplicate or unexpected transform".into());
        }
        let id = u16be(&t[6..8]);
        if typ == 1 {
            if len != 12 || &t[8..12] != [0x80, 14, 1, 0] {
                return Err("AES-CBC key length not 256".into());
            }
        } else if len != 8 {
            return Err("unexpected transform attribute".into());
        }
        found[(typ - 1) as usize] = Some(id);
        offset += len;
    }
    if offset != body.len() {
        return Err("trailing transform bytes".into());
    }
    let expected = if number == 1 {
        [12, 5, 12, 20]
    } else {
        [12, 2, 2, 20]
    };
    if found != expected.map(Some) {
        return Err("selected suite was not offered".into());
    }
    Ok(number)
}

pub fn parse_response(
    ike: &[u8],
    spi_i: &[u8; 8],
    local: SocketAddr,
    remote: SocketAddr,
) -> Result<Response, String> {
    if ike.len() < 28 || ike.len() > 65529 {
        return Err("IKE header length out of bounds".into());
    }
    if &ike[..8] != spi_i
        || ike[17] >> 4 != 2
        || ike[18] != 34
        || ike[19] & 0x28 != 0x20
        || u32be(&ike[20..24]) != 0
        || u32be(&ike[24..28]) as usize != ike.len()
    {
        return Err("wrong SPI, exchange, response flag, message ID, or IKE length".into());
    }
    let spi_r: [u8; 8] = ike[8..16].try_into().unwrap();
    let mut typ = ike[16];
    let mut offset = 28;
    let mut selected = None;
    let mut peer_public = None;
    let mut nonce = None;
    let mut nat_source_match = None;
    let mut nat_dest_match = None;
    let mut notices = Vec::new();
    while typ != 0 {
        if ike.len() - offset < 4 {
            return Err("truncated payload header".into());
        }
        let next = ike[offset];
        let critical = ike[offset + 1] & 0x80 != 0;
        let len = u16be(&ike[offset + 2..offset + 4]) as usize;
        if len < 4 || len > ike.len() - offset {
            return Err("invalid payload length".into());
        }
        let body = &ike[offset + 4..offset + len];
        match typ {
            SA => {
                if selected.replace(parse_sa(body)?).is_some() {
                    return Err("duplicate SA".into());
                }
            }
            KE => {
                if body.len() != 100 || u16be(body) != 20 || body[2..4] != [0, 0] {
                    return Err("unexpected KE group or length".into());
                }
                let mut public = [0u8; 96];
                public.copy_from_slice(&body[4..]);
                if peer_public.replace(public).is_some() {
                    return Err("duplicate KE".into());
                }
            }
            NONCE => {
                if !(16..=256).contains(&body.len()) || nonce.replace(body.to_vec()).is_some() {
                    return Err("invalid or duplicate nonce".into());
                }
            }
            NOTIFY => {
                if body.len() < 4 {
                    return Err("short notify".into());
                }
                let spi_size = body[1] as usize;
                if body.len() < 4 + spi_size {
                    return Err("truncated notify SPI".into());
                }
                let code = u16be(&body[2..4]);
                let data = &body[4 + spi_size..];
                if code == NAT_SOURCE || code == NAT_DEST {
                    if body[0] != 0 || spi_size != 0 || data.len() != 20 {
                        return Err("invalid NAT-detection notify".into());
                    }
                    let match_addr = if code == NAT_SOURCE { remote } else { local };
                    let matched = data == nat_hash(spi_i, &spi_r, match_addr);
                    let slot = if code == NAT_SOURCE {
                        &mut nat_source_match
                    } else {
                        &mut nat_dest_match
                    };
                    if slot.replace(matched).is_some() {
                        return Err("duplicate NAT notify".into());
                    }
                } else {
                    notices.push(code);
                }
            }
            VID => {}
            _ if critical => return Err(format!("unsupported critical payload {typ}")),
            _ => {}
        }
        offset += len;
        typ = next;
    }
    if offset != ike.len() {
        return Err("trailing bytes after payload chain".into());
    }
    if selected.is_none() || peer_public.is_none() || nonce.is_none() {
        if let Some(code) = notices.iter().copied().find(|code| *code < 16384) {
            return Err(format!(
                "gateway IKE_SA_INIT notify {code} ({})",
                notify_name(code)
            ));
        }
        return Err("incomplete IKE_SA_INIT response".into());
    }
    if spi_r == [0; 8] {
        return Err("zero responder SPI".into());
    }
    Ok(Response {
        spi_r,
        selected: selected.unwrap(),
        peer_public: peer_public.unwrap(),
        nonce: nonce.unwrap(),
        nat_source_match,
        nat_dest_match,
        notices,
    })
}

fn notify_name(code: u16) -> &'static str {
    match code {
        14 => "NO_PROPOSAL_CHOSEN",
        17 => "INVALID_KE_PAYLOAD",
        16390 => "COOKIE",
        7 => "INVALID_SYNTAX",
        5 => "INVALID_MAJOR_VERSION",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};
    fn addr(a: [u8; 4], port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(a), port))
    }
    fn fixture() -> (Vec<u8>, [u8; 8], SocketAddr, SocketAddr) {
        let spi = [1, 2, 3, 4, 5, 6, 7, 8];
        let local = addr([192, 0, 2, 1], 4500);
        let remote = addr([198, 51, 100, 7], 4500);
        (
            request(spi, [0x55; 32], [0x77; 96], local, remote),
            spi,
            local,
            remote,
        )
    }
    fn response_suite(spi: [u8; 8], local: SocketAddr, remote: SocketAddr, suite: u8) -> Vec<u8> {
        let mut out = request(spi, [0x55; 32], [0x77; 96], remote, local);
        out[8..16].copy_from_slice(&[9; 8]);
        out[19] = 0x20;
        // Keep a single selected proposal; adjust SA length and IKE length.
        if suite == 1 {
            out.drain(28 + 4 + 44..28 + 4 + 88);
        } else {
            out.drain(28 + 4..28 + 4 + 44);
        }
        out[30..32].copy_from_slice(&48u16.to_be_bytes());
        out[28 + 4] = 0;
        let len = out.len() as u32;
        out[24..28].copy_from_slice(&len.to_be_bytes());
        // Recompute NAT notifies after responder SPI becomes nonzero.
        let start = 28 + 48 + 104 + 36;
        out[start + 8..start + 28].copy_from_slice(&nat_hash(&spi, &[9; 8], remote));
        out[start + 28 + 8..start + 56].copy_from_slice(&nat_hash(&spi, &[9; 8], local));
        out
    }
    fn response(spi: [u8; 8], local: SocketAddr, remote: SocketAddr) -> Vec<u8> {
        response_suite(spi, local, remote, 1)
    }
    #[test]
    fn exact_request_layout_and_framing() {
        let (ike, spi, local, remote) = fixture();
        assert_eq!(ike.len(), 376);
        assert_eq!(&ike[..8], &spi);
        assert_eq!(&ike[8..16], &[0; 8]);
        assert_eq!(&ike[16..28], &[33, 0x20, 34, 8, 0, 0, 0, 0, 0, 0, 1, 120]);
        assert_eq!(&ike[28..32], &[34, 0, 0, 92]);
        assert_eq!(&ike[32..40], &[2, 0, 0, 44, 1, 1, 0, 4]);
        assert_eq!(&ike[76..84], &[0, 0, 0, 44, 2, 1, 0, 4]);
        assert_eq!(&ike[120..128], &[40, 0, 0, 104, 0, 20, 0, 0]);
        assert_eq!(&ike[224..228], &[41, 0, 0, 36]);
        assert_eq!(&ike[260..268], &[41, 0, 0, 28, 0, 0, 0x40, 0x04]);
        assert_eq!(&ike[288..296], &[43, 0, 0, 28, 0, 0, 0x40, 0x05]);
        assert_eq!(&ike[296..316], &nat_hash(&spi, &[0; 8], remote));
        assert_eq!(&ike[316..320], &[43, 0, 0, 20]);
        assert_eq!(&ike[320..336], &VIDS[0]);
        assert_eq!(ike[356], 0); // last VID terminates chain
        let udp = udp_frame(&ike);
        assert_eq!(udp.len(), 380);
        assert_eq!(unframe_udp(&udp).unwrap(), ike);
        let tcp = tcp_frame(&ike).unwrap();
        assert_eq!(&tcp[..12], &[1, 126, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6]);
        assert_eq!(unframe_tcp(&tcp).unwrap(), ike);
        let mut bad = tcp.clone();
        bad[0] = 0;
        assert!(unframe_tcp(&bad).is_err());
        bad = tcp;
        bad[2] = 1;
        assert!(unframe_tcp(&bad).is_err());
        assert_eq!(local.port(), 4500);
    }
    #[test]
    fn nat_hash_matches_independent_sha1_vector() {
        assert_eq!(
            nat_hash(
                &[1, 2, 3, 4, 5, 6, 7, 8],
                &[0; 8],
                addr([192, 0, 2, 1], 4500)
            ),
            [
                0x70, 0x43, 0x3c, 0xeb, 0x72, 0xd8, 0x68, 0x3e, 0x19, 0x43, 0x7d, 0x7c, 0xba, 0xca,
                0x3f, 0x3f, 0xc2, 0xeb, 0x8e, 0x6f
            ]
        );
    }
    #[test]
    fn accepts_selected_suite_and_nat_hashes() {
        let (_, spi, local, remote) = fixture();
        let parsed = parse_response(&response(spi, local, remote), &spi, local, remote).unwrap();
        assert_eq!(parsed.selected, 1);
        assert_eq!(parsed.nonce, [0x55; 32]);
        assert_eq!(parsed.nat_source_match, Some(true));
        assert_eq!(parsed.nat_dest_match, Some(true));
    }
    #[test]
    fn accepts_sha1_fallback_only_when_offered_as_proposal_two() {
        let (_, spi, local, remote) = fixture();
        let p = response_suite(spi, local, remote, 2);
        assert_eq!(parse_response(&p, &spi, local, remote).unwrap().selected, 2);
    }
    #[test]
    fn rejects_wrong_id_lengths_and_unoffered_suite() {
        let (_, spi, local, remote) = fixture();
        let mut p = response(spi, local, remote);
        p[23] = 1;
        assert!(parse_response(&p, &spi, local, remote).is_err());
        p[23] = 0;
        p[27] = 1;
        assert!(parse_response(&p, &spi, local, remote).is_err());
        p[27] = p.len() as u8;
        p[36] = 3; // selected proposal number not offered
        assert!(parse_response(&p, &spi, local, remote).is_err());
        p[36] = 1;
        p[30..32].copy_from_slice(&0u16.to_be_bytes());
        assert!(parse_response(&p, &spi, local, remote).is_err());
    }
    #[test]
    fn reports_gateway_error_notify() {
        let (_, spi, _, _) = fixture();
        let mut p = Vec::new();
        p.extend_from_slice(&spi);
        p.extend_from_slice(&[0; 8]);
        p.extend_from_slice(&[NOTIFY, 0x20, 34, 0x20]);
        p.extend_from_slice(&[0; 4]);
        p.extend_from_slice(&36u32.to_be_bytes());
        p.extend_from_slice(&[0, 0, 0, 8, 0, 0, 0, 14]);
        let err = parse_response(
            &p,
            &spi,
            addr([192, 0, 2, 1], 4500),
            addr([198, 51, 100, 7], 4500),
        )
        .unwrap_err();
        assert!(err.contains("NO_PROPOSAL_CHOSEN"));
    }
}
