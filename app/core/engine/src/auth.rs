//! Narrow IKE_AUTH packet code. The caller verifies responder PSK AUTH before
//! opting into an EAP Identity reply. No SAML token or EAP secret is sent here.
use std::net::Ipv4Addr;

const SK: u8 = 46;
const IDI: u8 = 35;
const IDR: u8 = 36;
const AUTH: u8 = 39;
const NOTIFY: u8 = 41;
const EAP: u8 = 48;
const SA: u8 = 33;
const TSI: u8 = 44;
const TSR: u8 = 45;
const CP: u8 = 47;

fn hmac(key: &[u8], data: &[u8]) -> Result<[u8; 32], String> {
    Ok(oftc_crypto::hmac_sha256(key, data))
}

pub fn prf_sha256(key: &[u8], data: &[u8]) -> Result<[u8; 32], String> {
    hmac(key, data)
}

fn cbc(encrypt: bool, key: &[u8; 32], iv: &[u8; 16], input: &[u8]) -> Result<Vec<u8>, String> {
    if input.is_empty() || !input.len().is_multiple_of(16) {
        return Err("CBC input length is not block aligned".into());
    }
    let out = if encrypt {
        oftc_crypto::aes256_cbc_encrypt(key, iv, input)
    } else {
        oftc_crypto::aes256_cbc_decrypt(key, iv, input)
    };
    out.map_err(|_| "AES-256-CBC failed".into())
}

fn random<const N: usize>() -> Result<[u8; N], String> {
    oftc_crypto::random_array().map_err(|_| "secure random failed".into())
}

fn prf_plus(key: &[u8], seed: &[u8], needed: usize) -> Result<Vec<u8>, String> {
    if needed > 255 * 32 {
        return Err("PRF+ request exceeds limit".into());
    }
    let mut out = Vec::with_capacity(needed + 32);
    let mut prev = Vec::new();
    for n in 1..=needed.div_ceil(32) {
        let mut input = Vec::with_capacity(prev.len() + seed.len() + 1);
        input.extend_from_slice(&prev);
        input.extend_from_slice(seed);
        input.push(n as u8);
        prev = hmac(key, &input)?.to_vec();
        out.extend_from_slice(&prev);
    }
    out.truncate(needed);
    prev.fill(0);
    Ok(out)
}

pub struct Keys {
    pub sk_d: [u8; 32],
    pub sk_ai: [u8; 32],
    pub sk_ar: [u8; 32],
    pub sk_ei: [u8; 32],
    pub sk_er: [u8; 32],
    pub sk_pi: [u8; 32],
    pub sk_pr: [u8; 32],
}

impl Drop for Keys {
    fn drop(&mut self) {
        for key in [
            &mut self.sk_d,
            &mut self.sk_ai,
            &mut self.sk_ar,
            &mut self.sk_ei,
            &mut self.sk_er,
            &mut self.sk_pi,
            &mut self.sk_pr,
        ] {
            key.fill(0);
        }
    }
}

pub fn derive_keys(
    ni: &[u8],
    nr: &[u8],
    spi_i: &[u8; 8],
    spi_r: &[u8; 8],
    shared: &[u8; 48],
) -> Result<Keys, String> {
    if ni.len() < 16 || nr.len() < 16 {
        return Err("short SA_INIT nonce".into());
    }
    let mut nonces = Vec::with_capacity(ni.len() + nr.len());
    nonces.extend_from_slice(ni);
    nonces.extend_from_slice(nr);
    let mut skeyseed = hmac(&nonces, shared)?;
    nonces.fill(0);
    let result = derive_keys_from_skeyseed(&skeyseed, ni, nr, spi_i, spi_r);
    skeyseed.fill(0);
    result
}

pub fn derive_keys_from_skeyseed(
    skeyseed: &[u8; 32], ni: &[u8], nr: &[u8],
    spi_i: &[u8; 8], spi_r: &[u8; 8],
) -> Result<Keys, String> {
    if !(16..=256).contains(&ni.len()) || !(16..=256).contains(&nr.len())
        || *spi_i == [0; 8] || *spi_r == [0; 8] {
        return Err("invalid IKE key seed inputs".into());
    }
    let mut seed = Vec::with_capacity(ni.len() + nr.len() + 16);
    seed.extend_from_slice(ni);
    seed.extend_from_slice(nr);
    seed.extend_from_slice(spi_i);
    seed.extend_from_slice(spi_r);
    let mut material = prf_plus(skeyseed, &seed, 7 * 32)?;
    seed.fill(0);
    let take = |n: usize| -> [u8; 32] { material[n * 32..(n + 1) * 32].try_into().unwrap() };
    let keys = Keys {
        sk_d: take(0),
        sk_ai: take(1),
        sk_ar: take(2),
        sk_ei: take(3),
        sk_er: take(4),
        sk_pi: take(5),
        sk_pr: take(6),
    };
    material.fill(0);
    Ok(keys)
}

fn payload(out: &mut Vec<u8>, next: u8, body: &[u8]) {
    out.push(next);
    out.push(0);
    out.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
    out.extend_from_slice(body);
}

fn esp_offer(spi: [u8; 4]) -> Vec<u8> {
    let mut p = vec![0, 0, 0, 0, 1, 3, 4, 3]; // one ESP proposal, three transforms
    p.extend_from_slice(&spi);
    p.extend_from_slice(&[3, 0, 0, 12, 1, 0, 0, 12, 0x80, 14, 1, 0]); // AES-CBC-256
    p.extend_from_slice(&[3, 0, 0, 8, 3, 0, 0, 2]); // AUTH_HMAC_SHA1_96
    p.extend_from_slice(&[0, 0, 0, 8, 5, 0, 0, 0]); // mandatory ESN: no ESNs
    let len = p.len() as u16;
    p[2..4].copy_from_slice(&len.to_be_bytes());
    p
}

fn traffic_selector() -> [u8; 20] {
    [
        1, 0, 0, 0, 7, 0, 0, 16, 0, 0, 255, 255, 0, 0, 0, 0, 255, 255, 255, 255,
    ]
}

fn first_request_body(local: Ipv4Addr, child_spi: [u8; 4]) -> Vec<u8> {
    let mut inner = Vec::new();
    let mut idi = vec![1, 0, 0, 0]; // ID_IPV4_ADDR; never a SAML/EAP identity
    idi.extend_from_slice(&local.octets());
    payload(&mut inner, CP, &idi);
    let mut cp = vec![1, 0, 0, 0]; // CFG_REQUEST
    for attr in [1u16, 2, 3, 13, 25] {
        // address, netmask, DNS, split subnet, DNS domain
        cp.extend_from_slice(&attr.to_be_bytes());
        cp.extend_from_slice(&0u16.to_be_bytes());
    }
    payload(&mut inner, SA, &cp);
    payload(&mut inner, TSI, &esp_offer(child_spi));
    payload(&mut inner, TSR, &traffic_selector());
    payload(&mut inner, 0, &traffic_selector());
    inner
}

pub struct FirstRequest {
    pub packet: Vec<u8>,
    pub child_spi: [u8; 4],
    pub idi: Vec<u8>,
    pub offered_tsi: [u8; 20],
    pub offered_tsr: [u8; 20],
}

fn seal(
    spi_i: &[u8; 8],
    spi_r: &[u8; 8],
    msg_id: u32,
    response: bool,
    first_inner: u8,
    inner: &[u8],
    enc: &[u8; 32],
    auth: &[u8; 32],
    iv: [u8; 16],
) -> Result<Vec<u8>, String> {
    let mut plaintext = inner.to_vec();
    let pad = (16 - ((plaintext.len() + 1) % 16)) % 16;
    plaintext.extend(std::iter::repeat_n(0, pad));
    plaintext.push(pad as u8);
    let ciphertext = cbc(true, enc, &iv, &plaintext)?;
    plaintext.fill(0);
    let sk_len = 4 + iv.len() + ciphertext.len() + 16;
    let mut msg = Vec::with_capacity(28 + sk_len);
    msg.extend_from_slice(spi_i);
    msg.extend_from_slice(spi_r);
    msg.extend_from_slice(&[SK, 0x20, 35, if response { 0x20 } else { 0x08 }]);
    msg.extend_from_slice(&msg_id.to_be_bytes());
    msg.extend_from_slice(&((28 + sk_len) as u32).to_be_bytes());
    msg.extend_from_slice(&[first_inner, 0]);
    msg.extend_from_slice(&(sk_len as u16).to_be_bytes());
    msg.extend_from_slice(&iv);
    msg.extend_from_slice(&ciphertext);
    msg.extend_from_slice(&hmac(auth, &msg)?[..16]);
    Ok(msg)
}

pub fn first_request(
    spi_i: &[u8; 8],
    spi_r: &[u8; 8],
    keys: &Keys,
    local: Ipv4Addr,
) -> Result<Vec<u8>, String> {
    Ok(first_request_with_child_spi(spi_i, spi_r, keys, local)?.packet)
}

pub fn first_request_with_child_spi(
    spi_i: &[u8; 8],
    spi_r: &[u8; 8],
    keys: &Keys,
    local: Ipv4Addr,
) -> Result<FirstRequest, String> {
    let mut child_spi = random::<4>()?;
    if child_spi == [0; 4] {
        child_spi[3] = 1;
    }
    let body = first_request_body(local, child_spi);
    let packet = seal(
        spi_i,
        spi_r,
        1,
        false,
        IDI,
        &body,
        &keys.sk_ei,
        &keys.sk_ai,
        random::<16>()?,
    )?;
    let mut idi = vec![1, 0, 0, 0];
    idi.extend_from_slice(&local.octets());
    Ok(FirstRequest {
        packet,
        child_spi,
        idi,
        offered_tsi: traffic_selector(),
        offered_tsr: traffic_selector(),
    })
}

pub fn identity_reply(
    spi_i: &[u8; 8],
    spi_r: &[u8; 8],
    keys: &Keys,
    eap_id: u8,
    uid: &[u8],
) -> Result<Vec<u8>, String> {
    if uid.len() != 32 || !uid.iter().all(u8::is_ascii_hexdigit) {
        return Err("expected a 32-byte hex machine UID".into());
    }
    let mut eap = vec![2, eap_id]; // EAP Response, same identifier
    eap.extend_from_slice(&((5 + uid.len()) as u16).to_be_bytes());
    eap.push(1); // Identity
    eap.extend_from_slice(uid);
    eap_reply(spi_i, spi_r, keys, 2, &eap)
}

pub fn eap_reply(
    spi_i: &[u8; 8],
    spi_r: &[u8; 8],
    keys: &Keys,
    msg_id: u32,
    eap: &[u8],
) -> Result<Vec<u8>, String> {
    if eap.len() < 4
        || eap.len() > u16::MAX as usize
        || eap[0] != 2
        || u16::from_be_bytes([eap[2], eap[3]]) as usize != eap.len()
    {
        return Err("invalid EAP Response".into());
    }
    let mut inner = Vec::new();
    payload(&mut inner, 0, eap);
    let result = random::<16>().and_then(|iv| {
        seal(
            spi_i,
            spi_r,
            msg_id,
            false,
            EAP,
            &inner,
            &keys.sk_ei,
            &keys.sk_ai,
            iv,
        )
    });
    inner.fill(0);
    result
}

fn eap_auth(
    secret: &[u8],
    init_packet: &[u8],
    peer_nonce: &[u8],
    identity: &[u8],
    sk_p: &[u8; 32],
) -> Result<[u8; 32], String> {
    if secret.len() < 16 || init_packet.len() < 28 || peer_nonce.len() < 16 || identity.len() < 4 {
        return Err("invalid EAP AUTH inputs".into());
    }
    let mut signed = Vec::with_capacity(init_packet.len() + peer_nonce.len() + 32);
    signed.extend_from_slice(init_packet);
    signed.extend_from_slice(peer_nonce);
    signed.extend_from_slice(&hmac(sk_p, identity)?);
    let mut pad_key = hmac(secret, b"Key Pad for IKEv2")?;
    let result = hmac(&pad_key, &signed);
    pad_key.fill(0);
    signed.fill(0);
    result
}

pub fn final_auth_request(
    spi_i: &[u8; 8],
    spi_r: &[u8; 8],
    keys: &Keys,
    msg_id: u32,
    msk: &[u8],
    init_request: &[u8],
    nonce_r: &[u8],
    idi: &[u8],
) -> Result<Vec<u8>, String> {
    let mut auth_body = vec![2, 0, 0, 0]; // Shared Key Message Integrity Code
    auth_body.extend_from_slice(&eap_auth(msk, init_request, nonce_r, idi, &keys.sk_pi)?);
    let mut inner = Vec::new();
    payload(&mut inner, 0, &auth_body);
    auth_body.fill(0);
    let result = random::<16>().and_then(|iv| {
        seal(
            spi_i,
            spi_r,
            msg_id,
            false,
            AUTH,
            &inner,
            &keys.sk_ei,
            &keys.sk_ai,
            iv,
        )
    });
    inner.fill(0);
    result
}

pub fn verify_final_auth(
    summary: &ResponseSummary,
    idr: &[u8],
    msk: &[u8],
    init_reply: &[u8],
    nonce_i: &[u8],
    keys: &Keys,
) -> Result<(), String> {
    if summary
        .idr
        .as_deref()
        .is_some_and(|final_idr| final_idr != idr)
    {
        return Err("final responder IDr differs from authenticated IDr".into());
    }
    let auth = summary
        .auth
        .as_deref()
        .ok_or("missing responder final AUTH")?;
    if auth.len() != 36 || auth[..4] != [2, 0, 0, 0] {
        return Err("unexpected final responder AUTH method or length".into());
    }
    let mut expected = eap_auth(msk, init_reply, nonce_i, idr, &keys.sk_pr)?;
    let valid = equal_ct(&expected, &auth[4..]);
    expected.fill(0);
    if !valid {
        return Err("responder final EAP AUTH verification failed".into());
    }
    Ok(())
}

fn responder_auth(
    psk: &[u8],
    sa_init_reply: &[u8],
    ni: &[u8],
    idr: &[u8],
    sk_pr: &[u8; 32],
) -> Result<[u8; 32], String> {
    if psk.is_empty() || sa_init_reply.len() < 28 || ni.len() < 16 || idr.len() < 4 {
        return Err("invalid responder AUTH inputs".into());
    }
    let mut signed = Vec::with_capacity(sa_init_reply.len() + ni.len() + 32);
    signed.extend_from_slice(sa_init_reply); // no UDP non-ESP marker or TCP frame
    signed.extend_from_slice(ni);
    signed.extend_from_slice(&hmac(sk_pr, idr)?);
    let mut pad_key = hmac(psk, b"Key Pad for IKEv2")?;
    let result = hmac(&pad_key, &signed);
    pad_key.fill(0);
    signed.fill(0);
    result
}

fn equal_ct(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// May contain EAP material. Deliberately omit Debug to prevent accidental logging.
#[derive(PartialEq)]
pub struct ResponseSummary {
    pub idr: Option<Vec<u8>>,
    pub auth: Option<Vec<u8>>,
    pub eap_code: Option<u8>,
    pub eap_id: Option<u8>,
    pub eap_type: Option<u8>,
    pub eap_vendor: Option<u32>,
    pub eap_vendor_type: Option<u32>,
    pub eap_mschap_opcode: Option<u8>,
    pub eap_mschap_challenge_size: Option<u8>,
    pub eap: Option<Vec<u8>>,
    pub sa: Option<Vec<u8>>,
    pub tsi: Option<Vec<u8>>,
    pub tsr: Option<Vec<u8>>,
    pub cp: Option<Vec<u8>>,
    pub notices: Vec<u16>,
}

pub fn verify_responder_auth(
    summary: &ResponseSummary,
    psk: &[u8],
    sa_init_reply: &[u8],
    ni: &[u8],
    keys: &Keys,
) -> Result<(), String> {
    let idr = summary.idr.as_deref().ok_or("missing responder IDr")?;
    let auth = summary.auth.as_deref().ok_or("missing responder AUTH")?;
    if auth.len() != 36 || auth[..4] != [2, 0, 0, 0] {
        return Err("unexpected responder AUTH method or length".into());
    }
    let mut expected = responder_auth(psk, sa_init_reply, ni, idr, &keys.sk_pr)?;
    let valid = equal_ct(&expected, &auth[4..]);
    expected.fill(0);
    if !valid {
        return Err("responder PSK AUTH verification failed".into());
    }
    Ok(())
}

pub fn parse_response(
    packet: &[u8],
    spi_i: &[u8; 8],
    spi_r: &[u8; 8],
    keys: &Keys,
    msg_id: u32,
) -> Result<ResponseSummary, String> {
    if packet.len() < 28 + 4 + 16 + 16 + 16 || packet.len() > 4096 {
        return Err("IKE_AUTH response size out of bounds".into());
    }
    if packet.get(..8) != Some(spi_i)
        || packet.get(8..16) != Some(spi_r)
        || packet[16] != SK
        || packet[17] != 0x20
        || packet[18] != 35
        || packet[19] & 0x28 != 0x20
        || u32::from_be_bytes(packet[20..24].try_into().unwrap()) != msg_id
        || u32::from_be_bytes(packet[24..28].try_into().unwrap()) as usize != packet.len()
    {
        return Err("unexpected IKE_AUTH response header".into());
    }
    let sk_len = u16::from_be_bytes(packet[30..32].try_into().unwrap()) as usize;
    if sk_len != packet.len() - 28 || sk_len < 4 + 16 + 16 + 16 {
        return Err("invalid SK payload length".into());
    }
    let icv_at = packet.len() - 16;
    if !equal_ct(
        &hmac(&keys.sk_ar, &packet[..icv_at])?[..16],
        &packet[icv_at..],
    ) {
        return Err("IKE_AUTH integrity check failed".into());
    }
    let iv: [u8; 16] = packet[32..48].try_into().unwrap();
    let mut plaintext = cbc(false, &keys.sk_er, &iv, &packet[48..icv_at])?;
    let result = parse_inner(&plaintext, packet[28]);
    plaintext.fill(0);
    result
}

fn parse_inner(plaintext: &[u8], first_type: u8) -> Result<ResponseSummary, String> {
    let pad = *plaintext.last().ok_or("empty SK plaintext")? as usize;
    if pad + 1 > plaintext.len() {
        return Err("invalid IKE padding length".into());
    }
    let end = plaintext.len() - pad - 1;
    let mut offset = 0;
    let mut typ = first_type;
    let mut summary = ResponseSummary {
        idr: None,
        auth: None,
        eap_code: None,
        eap_id: None,
        eap_type: None,
        eap_vendor: None,
        eap_vendor_type: None,
        eap_mschap_opcode: None,
        eap_mschap_challenge_size: None,
        eap: None,
        sa: None,
        tsi: None,
        tsr: None,
        cp: None,
        notices: Vec::new(),
    };
    while typ != 0 {
        if end - offset < 4 {
            return Err("truncated inner payload".into());
        }
        let next = plaintext[offset];
        let critical = plaintext[offset + 1] & 0x80 != 0;
        let len = u16::from_be_bytes([plaintext[offset + 2], plaintext[offset + 3]]) as usize;
        if len < 4 || len > end - offset {
            return Err("invalid inner payload length".into());
        }
        let body = &plaintext[offset + 4..offset + len];
        match typ {
            IDR => {
                if body.len() < 4 || summary.idr.replace(body.to_vec()).is_some() {
                    return Err("bad/duplicate IDr".into());
                }
            }
            AUTH => {
                if body.len() < 4 || summary.auth.replace(body.to_vec()).is_some() {
                    return Err("bad/duplicate AUTH".into());
                }
            }
            NOTIFY => {
                if body.len() < 4 {
                    return Err("short notify".into());
                }
                summary.notices.push(u16::from_be_bytes([body[2], body[3]]));
            }
            SA => {
                if summary.sa.replace(body.to_vec()).is_some() {
                    return Err("duplicate SA".into());
                }
            }
            TSI => {
                if summary.tsi.replace(body.to_vec()).is_some() {
                    return Err("duplicate TSi".into());
                }
            }
            TSR => {
                if summary.tsr.replace(body.to_vec()).is_some() {
                    return Err("duplicate TSr".into());
                }
            }
            CP => {
                if summary.cp.replace(body.to_vec()).is_some() {
                    return Err("duplicate CP".into());
                }
            }
            EAP => {
                if body.len() < 4 || summary.eap_code.is_some() {
                    return Err("bad/duplicate EAP".into());
                }
                let length = u16::from_be_bytes([body[2], body[3]]) as usize;
                if length != body.len() {
                    return Err("invalid EAP length".into());
                }
                summary.eap = Some(body.to_vec());
                summary.eap_code = Some(body[0]);
                summary.eap_id = Some(body[1]);
                if body[0] == 1 {
                    if body.len() < 5 {
                        return Err("short EAP Request".into());
                    }
                    summary.eap_type = Some(body[4]);
                    if body[4] == 254 {
                        if body.len() < 12 {
                            return Err("short expanded EAP type".into());
                        }
                        summary.eap_vendor =
                            Some(u32::from_be_bytes([0, body[5], body[6], body[7]]));
                        summary.eap_vendor_type =
                            Some(u32::from_be_bytes(body[8..12].try_into().unwrap()));
                    } else if body[4] == 26 {
                        if body.len() < 9 {
                            return Err("short type-26 EAP request".into());
                        }
                        let ms_len = u16::from_be_bytes([body[7], body[8]]) as usize;
                        if ms_len != body.len() - 5 {
                            return Err("invalid type-26 inner length".into());
                        }
                        summary.eap_mschap_opcode = Some(body[5]);
                        if body[5] == 1 {
                            if body.len() < 10 || body.len() < 10 + body[9] as usize {
                                return Err("short MSCHAPv2 challenge".into());
                            }
                            summary.eap_mschap_challenge_size = Some(body[9]);
                        }
                    }
                }
            }
            _ if critical => {
                return Err(format!("unsupported critical inner payload {typ}"));
            }
            _ => {}
        }
        offset += len;
        typ = next;
    }
    if offset != end {
        return Err("trailing inner plaintext".into());
    }
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn derives_and_wraps_without_exposing_keys() {
        let keys = derive_keys(&[0x11; 32], &[0x22; 16], &[1; 8], &[2; 8], &[0x33; 48]).unwrap();
        let request = first_request(&[1; 8], &[2; 8], &keys, Ipv4Addr::new(192, 0, 2, 1)).unwrap();
        assert_eq!(request[16], SK);
        assert_eq!(request[18], 35);
        assert_eq!(request[19], 8);
        let mut inner = Vec::new();
        payload(&mut inner, EAP, &[2, 0, 0, 8, 2, 0, 0, 0]); // dummy AUTH
        payload(&mut inner, 0, &[1, 7, 0, 5, 1]); // EAP Request/Identity
        let reply = seal(
            &[1; 8],
            &[2; 8],
            1,
            true,
            AUTH,
            &inner,
            &keys.sk_er,
            &keys.sk_ar,
            [9; 16],
        )
        .unwrap();
        let parsed = parse_response(&reply, &[1; 8], &[2; 8], &keys, 1).unwrap();
        assert!(parsed.auth.is_some());
        assert_eq!(parsed.eap_type, Some(1));
        let mut tampered = reply;
        tampered[50] ^= 1;
        assert!(parse_response(&tampered, &[1; 8], &[2; 8], &keys, 1).is_err());
    }

    #[test]
    fn psk_auth_matches_independent_hmac_vector() {
        let idr = [
            2, 0, 0, 0, b'g', b'w', b'.', b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        ];
        let expected = responder_auth(b"test shared key", b"RESP", b"NN", &idr, &[0x11; 32]);
        assert!(expected.is_err()); // real SA_INIT and nonce length checks
        let mut packet = vec![0; 28];
        packet.extend_from_slice(b"RESP");
        let actual =
            responder_auth(b"test shared key", &packet, &[b'N'; 16], &idr, &[0x11; 32]).unwrap();
        // Independently generated with Python's hashlib/hmac for these bytes.
        assert_eq!(
            actual,
            [
                0x95, 0x4e, 0x22, 0x1d, 0x07, 0x1d, 0x6a, 0x48, 0xd6, 0xde, 0xbc, 0x64, 0x0c, 0xb8,
                0x5f, 0x6a, 0x9b, 0x78, 0xb4, 0x4e, 0xb0, 0x48, 0x77, 0x61, 0x70, 0x85, 0x81, 0x4b,
                0x99, 0xab, 0x5c, 0x3f,
            ]
        );
    }

    #[test]
    fn identity_reply_is_opt_in_and_contains_one_eap_response() {
        let keys = derive_keys(&[0x11; 32], &[0x22; 16], &[1; 8], &[2; 8], &[0x33; 48]).unwrap();
        assert!(identity_reply(&[1; 8], &[2; 8], &keys, 7, b"short").is_err());
        let uid = b"0123456789ABCDEF0123456789ABCDEF";
        let packet = identity_reply(&[1; 8], &[2; 8], &keys, 7, uid).unwrap();
        assert_eq!(packet[18], 35); // IKE_AUTH
        assert_eq!(packet[19], 8); // initiator request
        assert_eq!(&packet[20..24], &2u32.to_be_bytes());
        assert_eq!(packet[28], EAP);
        let iv: [u8; 16] = packet[32..48].try_into().unwrap();
        let plaintext = cbc(false, &keys.sk_ei, &iv, &packet[48..packet.len() - 16]).unwrap();
        assert_eq!(plaintext[0], 0); // sole inner payload
        assert_eq!(&plaintext[2..4], &41u16.to_be_bytes());
        assert_eq!(&plaintext[4..9], &[2, 7, 0, 37, 1]);
        assert_eq!(&plaintext[9..41], uid);
    }

    #[test]
    fn expanded_eap_vendor_is_reported() {
        let mut inner = Vec::new();
        payload(&mut inner, 0, &[1, 9, 0, 12, 254, 0, 0, 123, 0, 0, 0, 6]);
        inner.push(0); // no padding
        let parsed = parse_inner(&inner, EAP).unwrap();
        assert_eq!(parsed.eap_type, Some(254));
        assert_eq!(parsed.eap_vendor, Some(123));
        assert_eq!(parsed.eap_vendor_type, Some(6));
    }

    #[test]
    fn type_26_challenge_shape_is_reported_without_challenge_bytes() {
        let mut eap = vec![1, 4, 0, 26, 26, 1, 4, 0, 21, 16];
        eap.extend_from_slice(&[0x55; 16]);
        let mut inner = Vec::new();
        payload(&mut inner, 0, &eap);
        inner.push(0);
        let parsed = parse_inner(&inner, EAP).unwrap();
        assert_eq!(parsed.eap_mschap_opcode, Some(1));
        assert_eq!(parsed.eap_mschap_challenge_size, Some(16));
        assert_eq!(parsed.eap.as_deref(), Some(eap.as_slice()));
    }

    #[test]
    fn final_child_payload_bodies_survive_authenticated_decryption() {
        let keys = derive_keys(&[0x11; 32], &[0x22; 16], &[1; 8], &[2; 8], &[0x33; 48]).unwrap();
        let mut inner = Vec::new();
        let auth = [2, 0, 0, 0, 1, 2, 3, 4];
        let cp = [2, 0, 0, 0, 0, 1, 0, 4, 192, 0, 2, 42];
        let sa = [0, 0, 0, 12, 1, 3, 4, 0, 1, 2, 3, 4];
        let tsi = traffic_selector();
        let tsr = traffic_selector();
        payload(&mut inner, CP, &auth);
        payload(&mut inner, SA, &cp);
        payload(&mut inner, TSI, &sa);
        payload(&mut inner, TSR, &tsi);
        payload(&mut inner, 0, &tsr);
        let packet = seal(
            &[1; 8],
            &[2; 8],
            5,
            true,
            AUTH,
            &inner,
            &keys.sk_er,
            &keys.sk_ar,
            [9; 16],
        )
        .unwrap();
        let parsed = parse_response(&packet, &[1; 8], &[2; 8], &keys, 5).unwrap();
        assert_eq!(parsed.auth.as_deref(), Some(auth.as_slice()));
        assert_eq!(parsed.cp.as_deref(), Some(cp.as_slice()));
        assert_eq!(parsed.sa.as_deref(), Some(sa.as_slice()));
        assert_eq!(parsed.tsi.as_deref(), Some(tsi.as_slice()));
        assert_eq!(parsed.tsr.as_deref(), Some(tsr.as_slice()));
    }

    #[test]
    fn initial_child_request_puts_configuration_before_sa() {
        let inner = first_request_body(Ipv4Addr::new(192, 0, 2, 1), [1, 2, 3, 4]);
        let mut typ = IDI;
        let mut seen = Vec::new();
        let mut offset = 0;
        while typ != 0 {
            seen.push(typ);
            let next = inner[offset];
            let length = u16::from_be_bytes([inner[offset + 2], inner[offset + 3]]) as usize;
            offset += length;
            typ = next;
        }
        assert_eq!(seen, [IDI, CP, SA, TSI, TSR]);
        assert_eq!(offset, inner.len());
    }

    #[test]
    fn esp_offer_explicitly_selects_no_esn() {
        let offer = esp_offer([1, 2, 3, 4]);
        assert_eq!(offer[7], 3);
        assert_eq!(&offer[8..12], &[1, 2, 3, 4]);
        assert_eq!(&offer[offer.len() - 8..], &[0, 0, 0, 8, 5, 0, 0, 0]);
    }

    #[test]
    fn final_eap_auth_uses_msk_and_original_identity() {
        let keys = derive_keys(&[0x11; 32], &[0x22; 16], &[1; 8], &[2; 8], &[0x33; 48]).unwrap();
        let first =
            first_request_with_child_spi(&[1; 8], &[2; 8], &keys, Ipv4Addr::new(192, 0, 2, 1))
                .unwrap();
        assert_ne!(first.child_spi, [0; 4]);
        let init = [0x77; 28];
        let msk = [0x55; 64];
        let final_request = final_auth_request(
            &[1; 8],
            &[2; 8],
            &keys,
            4,
            &msk,
            &init,
            &[0x22; 16],
            &first.idi,
        )
        .unwrap();
        assert_eq!(&final_request[20..24], &4u32.to_be_bytes());
        assert_eq!(final_request[28], AUTH);
        let idr = [2, 0, 0, 0, b'g', b'w'];
        let mut body = vec![2, 0, 0, 0];
        body.extend_from_slice(&eap_auth(&msk, &init, &[0x11; 32], &idr, &keys.sk_pr).unwrap());
        let summary = ResponseSummary {
            idr: None,
            auth: Some(body),
            eap_code: None,
            eap_id: None,
            eap_type: None,
            eap_vendor: None,
            eap_vendor_type: None,
            eap_mschap_opcode: None,
            eap_mschap_challenge_size: None,
            eap: None,
            sa: None,
            tsi: None,
            tsr: None,
            cp: None,
            notices: Vec::new(),
        };
        verify_final_auth(&summary, &idr, &msk, &init, &[0x11; 32], &keys).unwrap();
        assert!(verify_final_auth(&summary, &idr, &[0x44; 64], &init, &[0x11; 32], &keys).is_err());
    }
}
