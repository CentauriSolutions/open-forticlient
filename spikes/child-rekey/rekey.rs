//! Offline IKEv2 CHILD_SA rekey primitives for the observed IPv4-inner profile.
//! Callers authenticate/decrypt CREATE_CHILD_SA with the established IKE SA
//! before passing its inner payloads here. This module never owns a socket.

const NOTIFY: u8 = 41;
const SA: u8 = 33;
const NONCE: u8 = 40;
const KE: u8 = 34;
const TSI: u8 = 44;
const TSR: u8 = 45;
const REKEY_SA: u16 = 16393;
const GROUP14: u16 = 14;
const MODP14_LEN: usize = oftc_modp14::PUBLIC_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidSpi,
    InvalidNonce,
    InvalidKe,
    InvalidPayload,
    InvalidSa,
    UnsupportedSuite,
    SelectorChanged,
    Crypto,
    CollisionTie,
    NoOldSa,
    DuplicateSpi,
    TooManySas,
    /// IKE integrity and message ID were verified by the caller. Only the
    /// Notify type is retained; optional responder data is never exported.
    PeerNotify(u16),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offer {
    /// SPI on which we receive ESP for the SA being replaced.
    pub old_inbound_spi: u32,
    /// SPI on which we will receive ESP for the proposed replacement.
    pub new_inbound_spi: u32,
    pub ni: [u8; 32],
    /// Fixed-width big-endian RFC 3526 group-14 public value.
    pub ke_i: [u8; MODP14_LEN],
    pub tsi: Vec<u8>,
    pub tsr: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accepted {
    pub peer_inbound_spi: u32,
    pub nr: Vec<u8>,
    pub ke_r: [u8; MODP14_LEN],
    pub tsi: Vec<u8>,
    pub tsr: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerOffer {
    /// SPI on which the peer receives ESP for the old pair (our outbound).
    pub old_peer_inbound_spi: u32,
    /// SPI on which the peer will receive ESP for the new pair.
    pub new_peer_inbound_spi: u32,
    pub ni: Vec<u8>,
    pub ke_i: [u8; MODP14_LEN],
    pub tsi: Vec<u8>,
    pub tsr: Vec<u8>,
}

/// Append one IKE generic payload. `next` is the next payload's type.
fn payload(out: &mut Vec<u8>, next: u8, body: &[u8]) -> Result<(), Error> {
    let len = body.len().checked_add(4).ok_or(Error::InvalidPayload)?;
    if len > u16::MAX as usize {
        return Err(Error::InvalidPayload);
    }
    out.extend_from_slice(&[next, 0]);
    out.extend_from_slice(&(len as u16).to_be_bytes());
    out.extend_from_slice(body);
    Ok(())
}

fn transform(last: u8, kind: u8, id: u16, attrs: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&[last, 0]);
    out.extend_from_slice(&((8 + attrs.len()) as u16).to_be_bytes());
    out.extend_from_slice(&[kind, 0]);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(attrs);
}

/// One ESP proposal: AES-256-CBC, HMAC-SHA1-96, MODP-2048 PFS, no ESN.
fn esp_proposal(spi: u32) -> Result<Vec<u8>, Error> {
    if spi <= 255 {
        return Err(Error::InvalidSpi);
    }
    let mut out = vec![0, 0, 0, 0, 1, 3, 4, 4];
    out.extend_from_slice(&spi.to_be_bytes());
    transform(3, 1, 12, &[0x80, 14, 1, 0], &mut out);
    transform(3, 3, 2, &[], &mut out);
    transform(3, 4, GROUP14, &[], &mut out);
    transform(0, 5, 0, &[], &mut out);
    let len = out.len() as u16;
    out[2..4].copy_from_slice(&len.to_be_bytes());
    Ok(out)
}

fn validate_selector(body: &[u8]) -> Result<(), Error> {
    if body.len() < 4 || body[0] == 0 || body[0] > 64 || body[1..4] != [0; 3] {
        return Err(Error::InvalidPayload);
    }
    if body.len() != 4 + body[0] as usize * 16 {
        return Err(Error::InvalidPayload);
    }
    for selector in body[4..].chunks_exact(16) {
        if selector[..8] != [7, 0, 0, 16, 0, 0, 255, 255] || selector[8..12] > selector[12..16] {
            return Err(Error::InvalidPayload);
        }
    }
    Ok(())
}

fn validate_ke(point: &[u8; MODP14_LEN]) -> Result<(), Error> {
    if !oftc_modp14::validate_public(point) {
        return Err(Error::InvalidKe);
    }
    Ok(())
}

/// Returns (first inner payload type, plaintext payload chain). The IKE caller
/// must seal it as exchange 36 with its next local message ID and retransmit
/// the identical sealed packet if needed.
pub fn encode_request(offer: &Offer) -> Result<(u8, Vec<u8>), Error> {
    if offer.old_inbound_spi == 0
        || offer.new_inbound_spi <= 255
        || offer.old_inbound_spi == offer.new_inbound_spi
    {
        return Err(Error::InvalidSpi);
    }
    validate_ke(&offer.ke_i)?;
    validate_selector(&offer.tsi)?;
    validate_selector(&offer.tsr)?;
    let mut notify = vec![3, 4]; // ESP, 4-byte SPI
    notify.extend_from_slice(&REKEY_SA.to_be_bytes());
    notify.extend_from_slice(&offer.old_inbound_spi.to_be_bytes());
    let mut ke = vec![0, GROUP14 as u8, 0, 0];
    ke.extend_from_slice(&offer.ke_i);
    let mut inner = Vec::with_capacity(512);
    payload(&mut inner, SA, &notify)?;
    payload(&mut inner, NONCE, &esp_proposal(offer.new_inbound_spi)?)?;
    payload(&mut inner, KE, &offer.ni)?;
    payload(&mut inner, TSI, &ke)?;
    payload(&mut inner, TSR, &offer.tsi)?;
    payload(&mut inner, 0, &offer.tsr)?;
    Ok((NOTIFY, inner))
}

/// Parses only the selected exact suite. Error notifications are returned as
/// errors; the caller keeps the old SA and decides whether to retry later.
fn selected_spi(body: &[u8]) -> Result<u32, Error> {
    if body.len() < 12
        || body[0] != 0
        || body[1] != 0
        || u16::from_be_bytes([body[2], body[3]]) as usize != body.len()
        || body[4..8] != [1, 3, 4, 4]
    {
        return Err(Error::InvalidSa);
    }
    let spi = u32::from_be_bytes(body[8..12].try_into().unwrap());
    if spi <= 255 {
        return Err(Error::InvalidSpi);
    }
    let mut off = 12;
    for (index, (kind, id, attrs)) in [
        (1, 12, &[0x80, 14, 1, 0][..]),
        (3, 2, &[][..]),
        (4, GROUP14, &[][..]),
        (5, 0, &[][..]),
    ]
    .iter()
    .enumerate()
    {
        if body.len() < off + 8 {
            return Err(Error::InvalidSa);
        }
        let len = u16::from_be_bytes([body[off + 2], body[off + 3]]) as usize;
        if len != 8 + attrs.len()
            || off + len > body.len()
            || body[off] != if index == 3 { 0 } else { 3 }
            || body[off + 1] != 0
            || body[off + 4] != *kind
            || body[off + 5] != 0
            || u16::from_be_bytes([body[off + 6], body[off + 7]]) != *id
            || &body[off + 8..off + len] != *attrs
        {
            return Err(Error::UnsupportedSuite);
        }
        off += len;
    }
    if off != body.len() {
        return Err(Error::InvalidSa);
    }
    Ok(spi)
}

fn next_body<'a>(data: &'a [u8], offset: &mut usize) -> Result<(u8, &'a [u8]), Error> {
    if data.len() < *offset + 4 {
        return Err(Error::InvalidPayload);
    }
    let next = data[*offset];
    let flags = data[*offset + 1];
    let len = u16::from_be_bytes([data[*offset + 2], data[*offset + 3]]) as usize;
    if flags != 0 || len < 4 || len > data.len() - *offset {
        return Err(Error::InvalidPayload);
    }
    let body = &data[*offset + 4..*offset + len];
    *offset += len;
    Ok((next, body))
}

/// Response body has already passed SK integrity and message-ID verification.
/// The exact TSi/TSr are retained for policy validation by the caller. This
/// spike accepts only unchanged selectors during rekey.
pub fn parse_response(first: u8, data: &[u8], offer: &Offer) -> Result<Accepted, Error> {
    if first == NOTIFY {
        let mut offset = 0;
        let (next, body) = next_body(data, &mut offset)?;
        if next != 0 || offset != data.len() || body.len() < 4
            || body.len() < 4 + body[1] as usize {
            return Err(Error::InvalidPayload);
        }
        return Err(Error::PeerNotify(u16::from_be_bytes([body[2], body[3]])));
    }
    if first != SA {
        return Err(Error::InvalidPayload);
    }
    let mut off = 0;
    let (next, sa) = next_body(data, &mut off)?;
    if next != NONCE {
        return Err(Error::InvalidPayload);
    }
    let spi = selected_spi(sa)?;
    // ESP SPIs are selected independently by each receiver. Equal numeric
    // values across the two directions are legal; compare only within the
    // receiver's own inbound namespace when installing a new SA.
    let (next, nr) = next_body(data, &mut off)?;
    if next != KE || !(16..=256).contains(&nr.len()) {
        return Err(Error::InvalidNonce);
    }
    let (next, ke) = next_body(data, &mut off)?;
    if next != TSI || ke.len() != 4 + MODP14_LEN || ke[..4] != [0, GROUP14 as u8, 0, 0] {
        return Err(Error::InvalidKe);
    }
    let ke_r: [u8; MODP14_LEN] = ke[4..].try_into().unwrap();
    validate_ke(&ke_r)?;
    let (next, tsi) = next_body(data, &mut off)?;
    if next != TSR {
        return Err(Error::InvalidPayload);
    }
    let (next, tsr) = next_body(data, &mut off)?;
    if next != 0 || off != data.len() {
        return Err(Error::InvalidPayload);
    }
    validate_selector(tsi)?;
    validate_selector(tsr)?;
    if tsi != offer.tsi || tsr != offer.tsr {
        return Err(Error::SelectorChanged);
    }
    Ok(Accepted {
        peer_inbound_spi: spi,
        nr: nr.to_vec(),
        ke_r,
        tsi: tsi.to_vec(),
        tsr: tsr.to_vec(),
    })
}

/// Parse one authenticated responder-initiated rekey request. Its REKEY_SA
/// notify names the old SPI on which that initiator receives ESP; the session
/// checks it against its active outbound SPI before accepting the request.
pub fn parse_peer_request(first: u8, data: &[u8],
                          tsi_expected: &[u8], tsr_expected: &[u8])
                          -> Result<PeerOffer, Error> {
    if first != NOTIFY { return Err(Error::InvalidPayload); }
    let mut off = 0;
    let (next, notify) = next_body(data, &mut off)?;
    if next != SA || notify.len() != 8 || notify[..4] != [3, 4, 0x40, 0x09] {
        return Err(Error::InvalidPayload);
    }
    let old_peer_inbound_spi = u32::from_be_bytes(notify[4..8].try_into().unwrap());
    if old_peer_inbound_spi == 0 { return Err(Error::InvalidSpi); }
    let (next, sa) = next_body(data, &mut off)?;
    if next != NONCE { return Err(Error::InvalidPayload); }
    let new_peer_inbound_spi = selected_spi(sa)?;
    let (next, ni) = next_body(data, &mut off)?;
    if next != KE || !(16..=256).contains(&ni.len()) { return Err(Error::InvalidNonce); }
    let (next, ke) = next_body(data, &mut off)?;
    if next != TSI || ke.len() != 4 + MODP14_LEN || ke[..4] != [0, GROUP14 as u8, 0, 0] {
        return Err(Error::InvalidKe);
    }
    let ke_i: [u8; MODP14_LEN] = ke[4..].try_into().unwrap();
    validate_ke(&ke_i)?;
    let (next, tsi) = next_body(data, &mut off)?;
    if next != TSR { return Err(Error::InvalidPayload); }
    let (next, tsr) = next_body(data, &mut off)?;
    if next != 0 || off != data.len() { return Err(Error::InvalidPayload); }
    validate_selector(tsi)?;
    validate_selector(tsr)?;
    if tsi != tsi_expected || tsr != tsr_expected {
        return Err(Error::SelectorChanged);
    }
    Ok(PeerOffer { old_peer_inbound_spi, new_peer_inbound_spi,
        ni: ni.to_vec(), ke_i, tsi: tsi.to_vec(), tsr: tsr.to_vec() })
}

/// A rekey response has no REKEY_SA notify. The caller commits new ESP state
/// before emitting this authenticated response and retains the old inbound SA.
pub fn encode_peer_response(peer: &PeerOffer, new_inbound_spi: u32,
                            nr: &[u8; 32], ke_r: &[u8; MODP14_LEN])
                            -> Result<(u8, Vec<u8>), Error> {
    if new_inbound_spi <= 255 { return Err(Error::InvalidSpi); }
    validate_ke(ke_r)?;
    let mut ke = vec![0, GROUP14 as u8, 0, 0];
    ke.extend_from_slice(ke_r);
    let mut inner = Vec::with_capacity(512);
    payload(&mut inner, NONCE, &esp_proposal(new_inbound_spi)?)?;
    payload(&mut inner, KE, nr)?;
    payload(&mut inner, TSI, &ke)?;
    payload(&mut inner, TSR, &peer.tsi)?;
    payload(&mut inner, 0, &peer.tsr)?;
    Ok((SA, inner))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EspKeys {
    pub outbound_encryption: [u8; 32],
    pub outbound_integrity: [u8; 20],
    pub inbound_encryption: [u8; 32],
    pub inbound_integrity: [u8; 20],
}

/// RFC 7296 §2.17: prf+(SK_d, fresh MODP-2048 shared secret | Ni | Nr).
/// `secret` must be a validated fixed-width big-endian DH result; a zero
/// secret is explicitly rejected.
pub fn derive_keymat<F>(
    sk_d: &[u8; 32],
    secret: &mut [u8],
    ni: &[u8],
    nr: &[u8],
    mut hmac_sha256: F,
) -> Result<EspKeys, Error>
where
    F: FnMut(&[u8], &[u8]) -> Result<[u8; 32], Error>,
{
    if !(16..=256).contains(&ni.len()) || !(16..=256).contains(&nr.len()) {
        secret.fill(0);
        return Err(Error::InvalidNonce);
    }
    if secret.iter().all(|b| *b == 0) {
        secret.fill(0);
        return Err(Error::InvalidKe);
    }
    let mut seed = Vec::with_capacity(secret.len() + ni.len() + nr.len());
    seed.extend_from_slice(secret);
    secret.fill(0);
    seed.extend_from_slice(ni);
    seed.extend_from_slice(nr);
    let mut material = [0u8; 104];
    let mut previous = [0u8; 32];
    let mut copied = 0;
    for counter in 1..=4u8 {
        let mut input = Vec::with_capacity(if counter == 1 { 0 } else { 32 } + seed.len() + 1);
        if counter != 1 {
            input.extend_from_slice(&previous);
        }
        input.extend_from_slice(&seed);
        input.push(counter);
        let next = hmac_sha256(sk_d, &input);
        input.fill(0);
        let next = match next {
            Ok(value) => value,
            Err(error) => {
                seed.fill(0);
                previous.fill(0);
                material.fill(0);
                return Err(error);
            }
        };
        previous.fill(0);
        previous = next;
        let count = (material.len() - copied).min(32);
        material[copied..copied + count].copy_from_slice(&previous[..count]);
        copied += count;
    }
    seed.fill(0);
    previous.fill(0);
    let keys = EspKeys {
        outbound_encryption: material[..32].try_into().unwrap(),
        outbound_integrity: material[32..52].try_into().unwrap(),
        inbound_encryption: material[52..84].try_into().unwrap(),
        inbound_integrity: material[84..104].try_into().unwrap(),
    };
    material.fill(0);
    Ok(keys)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpiPair {
    pub inbound: u32,
    pub outbound: u32,
}

/// The data plane must keep a separate anti-replay window for each inbound
/// SPI. A new outbound SA is selected only after the authenticated response;
/// old inbound SAs remain valid until authenticated DELETE or bounded expiry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaOverlap {
    pub active: SpiPair,
    pub old_inbound: Vec<u32>,
}

impl SaOverlap {
    pub fn new(active: SpiPair) -> Result<Self, Error> {
        if active.inbound == 0 || active.outbound == 0 {
            return Err(Error::InvalidSpi);
        }
        Ok(Self {
            active,
            old_inbound: Vec::new(),
        })
    }
    pub fn install(&mut self, replacement: SpiPair) -> Result<(), Error> {
        if replacement.inbound == 0
            || replacement.outbound == 0
            || self.accepts_inbound(replacement.inbound)
            || replacement.outbound == self.active.outbound
        {
            return Err(Error::DuplicateSpi);
        }
        if self.old_inbound.len() >= 2 {
            return Err(Error::TooManySas);
        }
        self.old_inbound.push(self.active.inbound);
        self.active = replacement;
        Ok(())
    }
    pub fn accepts_inbound(&self, spi: u32) -> bool {
        spi == self.active.inbound || self.old_inbound.contains(&spi)
    }
    pub fn delete_old(&mut self, spi: u32) -> Result<(), Error> {
        let index = self
            .old_inbound
            .iter()
            .position(|old| *old == spi)
            .ok_or(Error::NoOldSa)?;
        self.old_inbound.remove(index);
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Collision {
    DeleteOurNew,
    DeletePeerNew,
}

/// RFC 7296 §2.8.1: of the two new SA pairs, the pair containing the
/// lexicographically lowest of four nonces is redundant. Equal nonces are
/// treated as an error so the caller keeps both inbound SAs until resolved.
pub fn collision(
    our_ni: &[u8],
    our_nr: &[u8],
    peer_ni: &[u8],
    peer_nr: &[u8],
) -> Result<Collision, Error> {
    let nonces = [our_ni, our_nr, peer_ni, peer_nr];
    if nonces.iter().any(|n| !(16..=256).contains(&n.len())) {
        return Err(Error::InvalidNonce);
    }
    if nonces
        .iter()
        .enumerate()
        .any(|(i, n)| nonces[i + 1..].contains(n))
    {
        return Err(Error::CollisionTie);
    }
    let our_min = our_ni.min(our_nr);
    let peer_min = peer_ni.min(peer_nr);
    if our_min < peer_min {
        Ok(Collision::DeleteOurNew)
    } else {
        Ok(Collision::DeletePeerNew)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" {
        fn oftc_swift_hmac(
            sha256: i32,
            key: *const u8,
            key_len: usize,
            input: *const u8,
            input_len: usize,
            digest: *mut u8,
            digest_len: usize,
        ) -> i32;
    }

    fn prf(key: &[u8], input: &[u8]) -> Result<[u8; 32], Error> {
        let mut digest = [0u8; 32];
        let rc = unsafe {
            oftc_swift_hmac(
                1,
                key.as_ptr(),
                key.len(),
                input.as_ptr(),
                input.len(),
                digest.as_mut_ptr(),
                digest.len(),
            )
        };
        if rc != 0 {
            return Err(Error::Crypto);
        }
        Ok(digest)
    }

    fn selector() -> Vec<u8> {
        vec![
            1, 0, 0, 0, 7, 0, 0, 16, 0, 0, 255, 255, 10, 99, 0, 12, 10, 99, 0, 12,
        ]
    }

    fn public(n: u8) -> [u8; MODP14_LEN] {
        let mut value = [0; MODP14_LEN];
        value[MODP14_LEN - 1] = n;
        value
    }

    fn offer() -> Offer {
        Offer {
            old_inbound_spi: 0x01020304,
            new_inbound_spi: 0x05060708,
            ni: [0x22; 32],
            ke_i: public(3),
            tsi: selector(),
            tsr: selector(),
        }
    }

    fn response(offer: &Offer) -> Vec<u8> {
        let mut inner = Vec::new();
        let mut ke = vec![0, 14, 0, 0];
        ke.extend_from_slice(&public(4));
        payload(&mut inner, NONCE, &esp_proposal(0x11121314).unwrap()).unwrap();
        payload(&mut inner, KE, &[0x55; 32]).unwrap();
        payload(&mut inner, TSI, &ke).unwrap();
        payload(&mut inner, TSR, &offer.tsi).unwrap();
        payload(&mut inner, 0, &offer.tsr).unwrap();
        inner
    }

    #[test]
    fn request_encodes_rekey_notify_pfs_and_new_spi() {
        let o = offer();
        let (first, request) = encode_request(&o).unwrap();
        assert_eq!(first, NOTIFY);
        let mut at = 0;
        let (next, notify) = next_body(&request, &mut at).unwrap();
        assert_eq!(next, SA);
        assert_eq!(notify, &[3, 4, 0x40, 0x09, 1, 2, 3, 4]);
        let (next, sa) = next_body(&request, &mut at).unwrap();
        assert_eq!(next, NONCE);
        assert_eq!(selected_spi(sa), Ok(o.new_inbound_spi));
        let (next, ni) = next_body(&request, &mut at).unwrap();
        assert_eq!((next, ni), (KE, &o.ni[..]));
        let (next, ke) = next_body(&request, &mut at).unwrap();
        assert_eq!(next, TSI);
        assert_eq!(&ke[..4], &[0, 14, 0, 0]);
        assert_eq!(&ke[4..], &o.ke_i);
        let (next, tsi) = next_body(&request, &mut at).unwrap();
        assert_eq!((next, tsi), (TSR, &o.tsi[..]));
        let (next, tsr) = next_body(&request, &mut at).unwrap();
        assert_eq!((next, tsr), (0, &o.tsr[..]));
        assert_eq!(at, request.len());
    }

    #[test]
    fn authenticated_response_selects_exact_pfs_suite() {
        let o = offer();
        let accepted = parse_response(SA, &response(&o), &o).unwrap();
        assert_eq!(accepted.peer_inbound_spi, 0x11121314);
        assert_eq!(accepted.nr, [0x55; 32]);
        assert_eq!(accepted.ke_r, public(4));
    }

    #[test]
    fn authenticated_error_notify_exposes_only_its_type() {
        let mut inner = Vec::new();
        // NO_ADDITIONAL_SAS with opaque diagnostic data. The caller has
        // already authenticated and decrypted the CREATE_CHILD_SA response.
        payload(&mut inner, 0, &[0, 0, 0, 35, 0xaa, 0xbb]).unwrap();
        assert_eq!(parse_response(NOTIFY, &inner, &offer()),
                   Err(Error::PeerNotify(35)));
        inner[4 + 1] = 4; // SPI size exceeds the remaining body.
        assert_eq!(parse_response(NOTIFY, &inner[..7], &offer()),
                   Err(Error::InvalidPayload));
    }

    #[test]
    fn spi_values_may_match_across_directions() {
        let o = offer();
        let mut wire = response(&o);
        wire[4 + 8..4 + 12].copy_from_slice(&o.new_inbound_spi.to_be_bytes());
        assert_eq!(
            parse_response(SA, &wire, &o).unwrap().peer_inbound_spi,
            o.new_inbound_spi
        );
        assert!(SaOverlap::new(SpiPair {
            inbound: 1,
            outbound: 1
        })
        .is_ok());
    }

    #[test]
    fn response_rejects_missing_pfs_changed_selectors_and_truncation() {
        let o = offer();
        let valid = response(&o);
        let mut no_pfs = valid.clone();
        let group_offset = 4 + esp_proposal(0x11121314).unwrap().len() + 4 + 32 + 4;
        no_pfs[group_offset + 1] = 0;
        assert_eq!(parse_response(SA, &no_pfs, &o), Err(Error::InvalidKe));
        let mut changed = valid.clone();
        let n = changed.len();
        changed[n - 1] ^= 1;
        assert_eq!(
            parse_response(SA, &changed, &o),
            Err(Error::SelectorChanged)
        );
        assert_eq!(
            parse_response(SA, &valid[..valid.len() - 1], &o),
            Err(Error::InvalidPayload)
        );
        assert_eq!(
            parse_response(NOTIFY, &valid, &o),
            Err(Error::InvalidPayload)
        );
    }

    #[test]
    fn no_unsafe_spis_or_points() {
        let mut o = offer();
        o.old_inbound_spi = 0;
        assert_eq!(encode_request(&o), Err(Error::InvalidSpi));
        o = offer();
        o.new_inbound_spi = o.old_inbound_spi;
        assert_eq!(encode_request(&o), Err(Error::InvalidSpi));
        o = offer();
        o.new_inbound_spi = 255;
        assert_eq!(encode_request(&o), Err(Error::InvalidSpi));
        o = offer();
        o.ke_i.fill(0);
        assert_eq!(encode_request(&o), Err(Error::InvalidKe));
        o.ke_i[MODP14_LEN - 1] = 1;
        assert_eq!(encode_request(&o), Err(Error::InvalidKe));
        let mut bad_group = response(&offer());
        let group_offset = 4 + esp_proposal(0x11121314).unwrap().len() + 4 + 32 + 4;
        bad_group[group_offset + 1] = 20;
        assert_eq!(parse_response(SA, &bad_group, &offer()), Err(Error::InvalidKe));
    }

    #[test]
    fn pfs_keymat_matches_independent_python_hmac_vector() {
        // Vector computed separately with Python's hashlib/hmac; includes
        // a synthetic 48-byte secret before fresh CREATE_CHILD_SA nonces.
        let sk_d: [u8; 32] = std::array::from_fn(|n| n as u8);
        let mut secret: [u8; 48] = std::array::from_fn(|n| n as u8 + 1);
        let ni: [u8; 32] = std::array::from_fn(|n| n as u8 + 32);
        let nr: [u8; 32] = std::array::from_fn(|n| n as u8 + 64);
        let keys = derive_keymat(&sk_d, &mut secret, &ni, &nr, prf).unwrap();
        assert_eq!(secret, [0; 48]);
        let mut actual = Vec::new();
        actual.extend_from_slice(&keys.outbound_encryption);
        actual.extend_from_slice(&keys.outbound_integrity);
        actual.extend_from_slice(&keys.inbound_encryption);
        actual.extend_from_slice(&keys.inbound_integrity);
        let hex: String = actual.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "215a65a74894193e983f88722611b312904654ae0cfd2d33cb87bf584cc9709da5bd9c2cf63dac94eebd911c5dcf3aa22343b37f7f067b10317c35f285dda81511b16134782f12d8046c6aa9ca387fdb7c5afcaa23a7344fa872f9ea3b522717cbc2ee353317a5cf");
    }

    #[test]
    fn zero_pfs_secret_and_prf_failure_do_not_make_keys() {
        let mut secret = [0u8; 48];
        assert_eq!(
            derive_keymat(&[1; 32], &mut secret, &[2; 32], &[3; 32], prf),
            Err(Error::InvalidKe)
        );
        let mut secret = [5u8; 48];
        assert_eq!(
            derive_keymat(&[1; 32], &mut secret, &[2; 32], &[3; 32], |_, _| Err(
                Error::Crypto
            )),
            Err(Error::Crypto)
        );
        assert_eq!(secret, [0; 48]);
    }

    #[test]
    fn two_fresh_modp14_exchanges_agree_on_secret() {
        let mut a_seed = [0x35; 32];
        let mut b_seed = [0x79; 32];
        let (a, pa) = oftc_modp14::Secret::generate(&mut a_seed).unwrap();
        let (b, pb) = oftc_modp14::Secret::generate(&mut b_seed).unwrap();
        assert_eq!(a.shared(&pb), b.shared(&pa));
        assert_ne!(a.shared(&pb), Some([0; MODP14_LEN]));
    }

    #[test]
    fn failed_exchange_leaves_old_sa_and_success_overlaps_inbound() {
        let old = SpiPair {
            inbound: 1,
            outbound: 2,
        };
        let mut state = SaOverlap::new(old).unwrap();
        assert_eq!(
            parse_response(SA, &[], &offer()),
            Err(Error::InvalidPayload)
        );
        assert_eq!(state.active, old); // caller commits only after full validation
        state
            .install(SpiPair {
                inbound: 3,
                outbound: 4,
            })
            .unwrap();
        assert_eq!(state.active.outbound, 4);
        assert!(state.accepts_inbound(1));
        assert!(state.accepts_inbound(3));
        assert!(!state.accepts_inbound(2));
        state.delete_old(1).unwrap();
        assert!(!state.accepts_inbound(1));
        assert!(state.accepts_inbound(3));
    }

    #[test]
    fn collision_loser_is_pair_with_lowest_of_four_nonces() {
        assert_eq!(
            collision(&[1; 16], &[8; 16], &[2; 16], &[3; 16]),
            Ok(Collision::DeleteOurNew)
        );
        assert_eq!(
            collision(&[8; 16], &[2; 16], &[1; 16], &[3; 16]),
            Ok(Collision::DeletePeerNew)
        );
        assert_eq!(
            collision(&[1; 16], &[8; 16], &[1; 16], &[3; 16]),
            Err(Error::CollisionTie)
        );
    }

    #[test]
    fn peer_request_and_response_preserve_exact_selectors_and_pfs() {
        let mut request = offer();
        request.tsr[15] = 13;
        request.tsr[19] = 13;
        let (first, inner) = encode_request(&request).unwrap();
        let peer = parse_peer_request(first, &inner, &request.tsi, &request.tsr).unwrap();
        assert_eq!(peer.old_peer_inbound_spi, request.old_inbound_spi);
        assert_eq!(peer.new_peer_inbound_spi, request.new_inbound_spi);
        let (first, response) = encode_peer_response(&peer, 0x51525354,
            &[0x77; 32], &public(8)).unwrap();
        let selected = parse_response(first, &response, &request).unwrap();
        assert_eq!(selected.peer_inbound_spi, 0x51525354);
        assert_eq!(selected.nr, vec![0x77; 32]);
        assert_eq!(selected.ke_r, public(8));
        let mut changed = request.tsi.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert_eq!(parse_peer_request(NOTIFY, &inner, &changed, &request.tsr),
                   Err(Error::SelectorChanged));
        let mut bad = inner.clone();
        bad[6] = 0;
        assert!(parse_peer_request(NOTIFY, &bad, &request.tsi, &request.tsr).is_err());
    }
}
