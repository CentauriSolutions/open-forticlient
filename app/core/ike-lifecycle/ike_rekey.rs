//! Strict CREATE_CHILD_SA payloads for rekeying the observed IKE SA suite.
//! The lifecycle layer authenticates SK and the message ID before calling this.
use crate::auth::{self, Keys};

const SA: u8 = 33;
const KE: u8 = 34;
const NONCE: u8 = 40;
const GROUP20: u16 = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error { Invalid, UnsupportedSuite, Crypto }

pub struct Offer {
    pub spi_i: [u8; 8],
    pub ni: [u8; 32],
    pub ke_i: [u8; 96],
}

pub struct Accepted {
    pub spi_r: [u8; 8],
    pub nr: Vec<u8>,
    pub ke_r: [u8; 96],
}

fn payload(out: &mut Vec<u8>, next: u8, body: &[u8]) {
    out.extend_from_slice(&[next, 0]);
    out.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
    out.extend_from_slice(body);
}

fn proposal(spi: [u8; 8]) -> Vec<u8> {
    let mut sa = vec![0, 0, 0, 0, 1, 1, 8, 4];
    sa.extend_from_slice(&spi);
    sa.extend_from_slice(&[3, 0, 0, 12, 1, 0, 0, 12, 0x80, 14, 1, 0]);
    sa.extend_from_slice(&[3, 0, 0, 8, 2, 0, 0, 5]);
    sa.extend_from_slice(&[3, 0, 0, 8, 3, 0, 0, 12]);
    sa.extend_from_slice(&[0, 0, 0, 8, 4, 0, 0, 20]);
    let len = sa.len() as u16;
    sa[2..4].copy_from_slice(&len.to_be_bytes());
    sa
}

fn take<'a>(data: &'a [u8], offset: &mut usize) -> Result<(u8, &'a [u8]), Error> {
    let rest = data.get(*offset..).ok_or(Error::Invalid)?;
    if rest.len() < 4 || rest[1] != 0 { return Err(Error::Invalid); }
    let len = u16::from_be_bytes([rest[2], rest[3]]) as usize;
    if len < 4 || len > rest.len() { return Err(Error::Invalid); }
    *offset += len;
    Ok((rest[0], &rest[4..len]))
}

fn selected_spi(sa: &[u8]) -> Result<[u8; 8], Error> {
    if sa.len() != 52 || sa[..8] != [0, 0, 0, 52, 1, 1, 8, 4] {
        return Err(Error::UnsupportedSuite);
    }
    let mut spi = [0; 8];
    spi.copy_from_slice(&sa[8..16]);
    if spi == [0; 8] || sa[16..] != proposal(spi)[16..] {
        return Err(Error::UnsupportedSuite);
    }
    Ok(spi)
}

pub fn encode_request(offer: &Offer) -> Result<(u8, Vec<u8>), Error> {
    if offer.spi_i == [0; 8] || offer.ni == [0; 32] || offer.ke_i == [0; 96] {
        return Err(Error::Invalid);
    }
    let mut ke = vec![0, GROUP20 as u8, 0, 0];
    ke.extend_from_slice(&offer.ke_i);
    let mut inner = Vec::with_capacity(220);
    payload(&mut inner, NONCE, &proposal(offer.spi_i));
    payload(&mut inner, KE, &offer.ni);
    payload(&mut inner, 0, &ke);
    Ok((SA, inner))
}

pub fn parse_response(first: u8, data: &[u8], offer: &Offer) -> Result<Accepted, Error> {
    if first != SA { return Err(Error::Invalid); }
    let mut offset = 0;
    let (next, sa) = take(data, &mut offset)?;
    if next != NONCE { return Err(Error::Invalid); }
    let spi_r = selected_spi(sa)?;
    if spi_r == offer.spi_i { return Err(Error::Invalid); }
    let (next, nr) = take(data, &mut offset)?;
    if next != KE || !(16..=256).contains(&nr.len()) { return Err(Error::Invalid); }
    let (next, ke) = take(data, &mut offset)?;
    if next != 0 || offset != data.len() || ke.len() != 100
        || ke[..4] != [0, GROUP20 as u8, 0, 0] { return Err(Error::Invalid); }
    let mut ke_r = [0; 96];
    ke_r.copy_from_slice(&ke[4..]);
    if ke_r == [0; 96] { return Err(Error::Invalid); }
    Ok(Accepted { spi_r, nr: nr.to_vec(), ke_r })
}

/// RFC 7296 section 2.18. The caller wipes the ephemeral DH secret.
pub fn derive_keys(old_sk_d: &[u8; 32], shared: &[u8; 48],
                   offer: &Offer, accepted: &Accepted) -> Result<Keys, Error> {
    let mut seed = Vec::with_capacity(48 + 32 + accepted.nr.len());
    seed.extend_from_slice(shared);
    seed.extend_from_slice(&offer.ni);
    seed.extend_from_slice(&accepted.nr);
    let mut skeyseed = auth::prf_sha256(old_sk_d, &seed).map_err(|_| Error::Crypto)?;
    seed.fill(0);
    let result = auth::derive_keys_from_skeyseed(&skeyseed, &offer.ni, &accepted.nr,
                                                 &offer.spi_i, &accepted.spi_r)
        .map_err(|_| Error::Crypto);
    skeyseed.fill(0);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    fn offer() -> Offer { Offer { spi_i: [1; 8], ni: [2; 32], ke_i: [3; 96] } }
    #[test]
    fn strict_suite_and_payload_chain() {
        let mut peer = offer();
        peer.spi_i = [4; 8];
        peer.ni = [5; 32];
        peer.ke_i = [6; 96];
        let (first, data) = encode_request(&peer).unwrap();
        let accepted = parse_response(first, &data, &offer()).unwrap();
        assert_eq!(accepted.spi_r, [4; 8]);
        assert_eq!(accepted.nr, vec![5; 32]);
        for cut in 0..data.len() { assert!(parse_response(first, &data[..cut], &offer()).is_err()); }
        let mut changed = data.clone();
        changed[16 + 12 + 7] = 2; // PRF transform ID is pinned to SHA2-256.
        assert!(matches!(parse_response(first, &changed, &offer()),
                         Err(Error::UnsupportedSuite)));
    }

    #[test]
    fn renewed_keys_match_independent_hmac_sha256_vector() {
        let offer = Offer { spi_i: [11; 8], ni: [9; 32], ke_i: [3; 96] };
        let accepted = Accepted { spi_r: [12; 8], nr: vec![10; 32], ke_r: [4; 96] };
        let keys = derive_keys(&[7; 32], &[8; 48], &offer, &accepted).unwrap();
        let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(hex(&keys.sk_d),
            "3d679d127cd81339620f9b3deeae8b58093f341a34fc008ea5ed67b4b5a0da5b");
        assert_eq!(hex(&keys.sk_ai),
            "574bf9268b41d3bb7db045a74d3b20dcb6f84c6f1edb7747807ea9d07ec55148");
        assert_eq!(hex(&keys.sk_ei),
            "492b12da92a9df47fc7588bfcb09b950cc78141faae64d65246951a2f2ac372c");
    }
}
