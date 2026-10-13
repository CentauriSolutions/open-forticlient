//! Dependency-free EAP-MSCHAPv2 peer method for the standalone IKEv2 spike.
//! Cryptographic primitives come from macOS CommonCrypto, not local algorithms.
//! Never print an EAP response or the returned MSK: both carry credential material.

use std::ffi::c_void;
use std::ops::{Deref, DerefMut};

const EAP_REQUEST: u8 = 1;
const EAP_RESPONSE: u8 = 2;
const EAP_TYPE_MSCHAPV2: u8 = 26;
const OP_CHALLENGE: u8 = 1;
const OP_RESPONSE: u8 = 2;
const OP_SUCCESS: u8 = 3;
const OP_FAILURE: u8 = 4;

const AUTH_MAGIC1: &[u8] = b"Magic server to client signing constant";
const AUTH_MAGIC2: &[u8] = b"Pad to make it do more than one iteration";
const MPPE_MAGIC1: &[u8] = b"This is the MPPE Master Key";
const MPPE_MAGIC2: &[u8] =
    b"On the client side, this is the send key; on the server side, it is the receive key.";
const MPPE_MAGIC3: &[u8] =
    b"On the client side, this is the receive key; on the server side, it is the send key.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Truncated,
    InvalidLength,
    UnexpectedPacket,
    InvalidChallenge,
    InvalidUsername,
    InvalidPassword,
    InvalidSuccess,
    AuthenticatorMismatch,
    CryptoFailure,
    RandomFailure,
}

/// Small zero-on-drop wrapper for temporary secret buffers, including error paths.
struct Sensitive<const N: usize>([u8; N]);

impl<const N: usize> Deref for Sensitive<N> {
    type Target = [u8; N];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> DerefMut for Sensitive<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const N: usize> Drop for Sensitive<N> {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

/// The two EAP identifiers need not be equal. They must be copied independently.
#[derive(Debug, Clone, Copy)]
pub struct Challenge {
    pub eap_id: u8,
    pub mschap_id: u8,
    pub authenticator_challenge: [u8; 16],
}

/// Strictly decode a type-26 EAP Request/Challenge. The optional server name is
/// ignored. Data-link padding is deliberately rejected by this IKEv2 interface.
pub fn parse_challenge(eap: &[u8]) -> Result<Challenge, Error> {
    validate_header(eap, EAP_REQUEST, OP_CHALLENGE)?;
    if eap.len() < 26 || eap[9] != 16 {
        return Err(Error::InvalidChallenge);
    }
    let mut value = [0; 16];
    value.copy_from_slice(&eap[10..26]);
    Ok(Challenge {
        eap_id: eap[1],
        mschap_id: eap[6],
        authenticator_challenge: value,
    })
}

/// Non-secret failure metadata. The caller should end the attempt rather than
/// automatically retrying with a single-use SAML token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Failure {
    pub eap_id: u8,
    pub mschap_id: u8,
    pub error_code: u32,
    pub retry_allowed: bool,
}

impl Failure {
    /// Acknowledge a non-retryable method failure, if the IKE caller chooses
    /// to complete the EAP failure exchange rather than closing immediately.
    pub fn acknowledgement(&self) -> [u8; 6] {
        [
            EAP_RESPONSE,
            self.eap_id,
            0,
            6,
            EAP_TYPE_MSCHAPV2,
            OP_FAILURE,
        ]
    }
}

pub fn parse_failure(eap: &[u8]) -> Result<Failure, Error> {
    validate_header(eap, EAP_REQUEST, OP_FAILURE)?;
    let message = std::str::from_utf8(&eap[9..]).map_err(|_| Error::UnexpectedPacket)?;
    let mut error_code = None;
    let mut retry_allowed = None;
    let mut challenge_valid = false;
    for field in message.split_ascii_whitespace() {
        if let Some(value) = field.strip_prefix("E=") {
            error_code = value.parse::<u32>().ok();
        } else if let Some(value) = field.strip_prefix("R=") {
            retry_allowed = match value {
                "0" => Some(false),
                "1" => Some(true),
                _ => None,
            };
        } else if let Some(value) = field.strip_prefix("C=") {
            challenge_valid = value.len() == 32 && value.bytes().all(|b| b.is_ascii_hexdigit());
        }
    }
    if !challenge_valid {
        return Err(Error::UnexpectedPacket);
    }
    Ok(Failure {
        eap_id: eap[1],
        mschap_id: eap[6],
        error_code: error_code.ok_or(Error::UnexpectedPacket)?,
        retry_allowed: retry_allowed.ok_or(Error::UnexpectedPacket)?,
    })
}

/// An unsent EAP Response and the state needed to verify the server. The MSK
/// cannot be accessed until the server's inner authenticator response checks.
pub struct Prepared {
    pub eap_response: Vec<u8>,
    expected_authenticator: [u8; 20],
    msk: [u8; 64],
    mschap_id: u8,
}

impl std::fmt::Debug for Prepared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Prepared { credential_material: [redacted] }")
    }
}

impl Drop for Prepared {
    fn drop(&mut self) {
        wipe(&mut self.eap_response);
        wipe(&mut self.expected_authenticator);
        wipe(&mut self.msk);
    }
}

pub struct Verified {
    pub success_ack: [u8; 6],
    msk: [u8; 64],
}

impl Verified {
    /// MSK = peer send/server receive key (16) | peer receive/server send key
    /// (16) | zero pad (32).
    /// Use only after an outer EAP-Success; IKEv2 final AUTH consumes this MSK.
    pub fn msk(&self) -> &[u8; 64] {
        &self.msk
    }
}

impl std::fmt::Debug for Verified {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Verified { msk: [redacted] }")
    }
}

impl Drop for Verified {
    fn drop(&mut self) {
        wipe(&mut self.msk);
    }
}

/// Production entry point: generates a fresh 16-byte peer challenge with the
/// system CSPRNG. `password` is the single-use token on this gateway.
pub fn respond(challenge: &Challenge, username: &str, password: &str) -> Result<Prepared, Error> {
    let mut peer = [0; 16];
    let status = unsafe { getentropy(peer.as_mut_ptr().cast(), peer.len()) };
    if status != 0 {
        return Err(Error::RandomFailure);
    }
    let result = respond_with_peer_challenge(challenge, username, password, peer);
    wipe(&mut peer);
    result
}

/// Deterministic test and interoperability entry point. The caller must supply
/// a cryptographically random peer challenge in production.
pub fn respond_with_peer_challenge(
    challenge: &Challenge,
    username: &str,
    password: &str,
    peer: [u8; 16],
) -> Result<Prepared, Error> {
    let peer = Sensitive(peer);
    if username.is_empty()
        || username.len() > 256
        || !username.is_ascii()
        || username.as_bytes().contains(&0)
    {
        return Err(Error::InvalidUsername);
    }
    if password.encode_utf16().count() > 256 {
        return Err(Error::InvalidPassword);
    }
    let user_only = username.rsplit('\\').next().unwrap_or(username).as_bytes();
    let hash = Sensitive(nt_password_hash(password)?);
    let hash_hash = Sensitive(md4(&hash.0)?);
    let challenge_hash = Sensitive(sha1_parts(&[
        &peer[..],
        &challenge.authenticator_challenge,
        user_only,
    ])?);
    let mut nt_response = Sensitive([0; 24]);
    for i in 0..3 {
        let mut raw_key = Sensitive([0; 7]);
        let start = i * 7;
        for (j, byte) in raw_key.iter_mut().enumerate() {
            if start + j < hash.len() {
                *byte = hash[start + j];
            }
        }
        let key = Sensitive(expand_des_key(&raw_key));
        let encrypted = des_encrypt(&key, challenge_hash[..8].try_into().unwrap())?;
        nt_response[i * 8..(i + 1) * 8].copy_from_slice(&encrypted);
    }

    let auth_first = Sensitive(sha1_parts(&[
        &hash_hash[..],
        &nt_response[..],
        AUTH_MAGIC1,
    ])?);
    let expected_authenticator = Sensitive(sha1_parts(&[
        &auth_first[..],
        &challenge_hash[..8],
        AUTH_MAGIC2,
    ])?);
    let master_full = Sensitive(sha1_parts(&[
        &hash_hash[..],
        &nt_response[..],
        MPPE_MAGIC1,
    ])?);
    let mut msk = Sensitive([0; 64]);
    // EAP MSK ordering: server receive/peer send = Magic2, server send/peer
    // receive = Magic3, then 32 zero bytes. This matches strongSwan's EAP export.
    let receive = Sensitive(mppe_start_key(&master_full[..16], MPPE_MAGIC2)?);
    let send = Sensitive(mppe_start_key(&master_full[..16], MPPE_MAGIC3)?);
    msk[..16].copy_from_slice(&receive[..]);
    msk[16..32].copy_from_slice(&send[..]);

    let len = 59 + username.len(); // EAP header/type (5), MS fields (5), 49-byte value, name.
    let mut eap_response = Vec::with_capacity(len);
    eap_response.extend_from_slice(&[EAP_RESPONSE, challenge.eap_id]);
    eap_response.extend_from_slice(&(len as u16).to_be_bytes());
    eap_response.extend_from_slice(&[EAP_TYPE_MSCHAPV2, OP_RESPONSE, challenge.mschap_id]);
    eap_response.extend_from_slice(&((len - 5) as u16).to_be_bytes());
    eap_response.push(49);
    eap_response.extend_from_slice(&peer[..]);
    eap_response.extend_from_slice(&[0; 8]);
    eap_response.extend_from_slice(&nt_response[..]);
    eap_response.push(0);
    eap_response.extend_from_slice(username.as_bytes());

    Ok(Prepared {
        eap_response,
        expected_authenticator: expected_authenticator.0,
        msk: msk.0,
        mschap_id: challenge.mschap_id,
    })
}

impl Prepared {
    /// Consume this attempt only after validating the inner Success Request.
    /// On mismatch, no Success Response or MSK is exposed.
    pub fn verify_success(self, eap: &[u8]) -> Result<Verified, Error> {
        validate_header(eap, EAP_REQUEST, OP_SUCCESS)?;
        if eap[6] != self.mschap_id || eap.len() < 51 || &eap[9..11] != b"S=" {
            return Err(Error::InvalidSuccess);
        }
        if eap.len() > 51 && !eap[51..].starts_with(b" M=") {
            return Err(Error::InvalidSuccess);
        }
        let mut expected = [0; 40];
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        for (i, byte) in self.expected_authenticator.iter().enumerate() {
            expected[2 * i] = HEX[(byte >> 4) as usize];
            expected[2 * i + 1] = HEX[(byte & 15) as usize];
        }
        let matches = constant_time_equal(&eap[11..51], &expected);
        wipe(&mut expected);
        if !matches {
            return Err(Error::AuthenticatorMismatch);
        }
        Ok(Verified {
            success_ack: [EAP_RESPONSE, eap[1], 0, 6, EAP_TYPE_MSCHAPV2, OP_SUCCESS],
            msk: self.msk,
        })
    }
}

fn validate_header(eap: &[u8], code: u8, opcode: u8) -> Result<(), Error> {
    if eap.len() < 9 {
        return Err(Error::Truncated);
    }
    if eap.len() != u16::from_be_bytes([eap[2], eap[3]]) as usize
        || eap.len() - 5 != u16::from_be_bytes([eap[7], eap[8]]) as usize
    {
        return Err(Error::InvalidLength);
    }
    if eap[0] != code || eap[4] != EAP_TYPE_MSCHAPV2 || eap[5] != opcode {
        return Err(Error::UnexpectedPacket);
    }
    Ok(())
}

fn nt_password_hash(password: &str) -> Result<[u8; 16], Error> {
    let mut utf16le = Vec::with_capacity(password.len() * 2);
    for unit in password.encode_utf16() {
        utf16le.extend_from_slice(&unit.to_le_bytes());
    }
    let result = md4(&utf16le);
    wipe(&mut utf16le);
    result
}

fn md4(input: &[u8]) -> Result<[u8; 16], Error> {
    let mut digest = [0; 16];
    let output = unsafe {
        CC_MD4(
            input.as_ptr().cast(),
            input.len() as u32,
            digest.as_mut_ptr(),
        )
    };
    if output.is_null() {
        Err(Error::CryptoFailure)
    } else {
        Ok(digest)
    }
}

fn sha1_parts(parts: &[&[u8]]) -> Result<[u8; 20], Error> {
    let size: usize = parts.iter().map(|p| p.len()).sum();
    let mut data = Vec::with_capacity(size);
    for part in parts {
        data.extend_from_slice(part);
    }
    let mut digest = [0; 20];
    let output = unsafe { CC_SHA1(data.as_ptr().cast(), data.len() as u32, digest.as_mut_ptr()) };
    wipe(&mut data);
    if output.is_null() {
        Err(Error::CryptoFailure)
    } else {
        Ok(digest)
    }
}

fn expand_des_key(raw: &[u8; 7]) -> [u8; 8] {
    let mut key = [0; 8];
    key[0] = raw[0] & 0xfe;
    key[1] = (raw[0] << 7 | raw[1] >> 1) & 0xfe;
    key[2] = (raw[1] << 6 | raw[2] >> 2) & 0xfe;
    key[3] = (raw[2] << 5 | raw[3] >> 3) & 0xfe;
    key[4] = (raw[3] << 4 | raw[4] >> 4) & 0xfe;
    key[5] = (raw[4] << 3 | raw[5] >> 5) & 0xfe;
    key[6] = (raw[5] << 2 | raw[6] >> 6) & 0xfe;
    key[7] = (raw[6] << 1) & 0xfe;
    for byte in &mut key {
        *byte |= ((byte.count_ones() % 2) == 0) as u8;
    }
    key
}

fn des_encrypt(key: &[u8; 8], plaintext: &[u8; 8]) -> Result<[u8; 8], Error> {
    let mut ciphertext = [0; 8];
    let mut moved = 0usize;
    let status = unsafe {
        CCCrypt(
            0,
            1,
            2,
            key.as_ptr().cast(),
            8,
            std::ptr::null(),
            plaintext.as_ptr().cast(),
            8,
            ciphertext.as_mut_ptr().cast(),
            8,
            &mut moved,
        )
    };
    if status == 0 && moved == 8 {
        Ok(ciphertext)
    } else {
        Err(Error::CryptoFailure)
    }
}

fn mppe_start_key(master: &[u8], magic: &[u8]) -> Result<[u8; 16], Error> {
    let digest = Sensitive(sha1_parts(&[master, &[0; 40], magic, &[0xf2; 40]])?);
    let mut key = [0; 16];
    key.copy_from_slice(&digest[..16]);
    Ok(key)
}

fn constant_time_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

fn wipe(bytes: &mut [u8]) {
    for byte in bytes {
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

unsafe extern "C" {
    fn CC_MD4(input: *const c_void, len: u32, digest: *mut u8) -> *mut u8;
    fn CC_SHA1(input: *const c_void, len: u32, digest: *mut u8) -> *mut u8;
    fn CCCrypt(
        op: u32,
        alg: u32,
        options: u32,
        key: *const c_void,
        key_len: usize,
        iv: *const c_void,
        input: *const c_void,
        input_len: usize,
        output: *mut c_void,
        output_len: usize,
        moved: *mut usize,
    ) -> i32;
    fn getentropy(buffer: *mut c_void, size: usize) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    const AUTH_CHALLENGE: [u8; 16] = [
        0x5b, 0x5d, 0x7c, 0x7d, 0x7b, 0x3f, 0x2f, 0x3e, 0x3c, 0x2c, 0x60, 0x21, 0x32, 0x26, 0x26,
        0x28,
    ];
    const PEER: [u8; 16] = [
        0x21, 0x40, 0x23, 0x24, 0x25, 0x5e, 0x26, 0x2a, 0x28, 0x29, 0x5f, 0x2b, 0x3a, 0x33, 0x7c,
        0x7e,
    ];
    const NT_RESPONSE: [u8; 24] = [
        0x82, 0x30, 0x9e, 0xcd, 0x8d, 0x70, 0x8b, 0x5e, 0xa0, 0x8f, 0xaa, 0x39, 0x81, 0xcd, 0x83,
        0x54, 0x42, 0x33, 0x11, 0x4a, 0x3d, 0x85, 0xd6, 0xdf,
    ];

    fn challenge_packet() -> Vec<u8> {
        let mut eap = vec![1, 7, 0, 30, 26, 1, 9, 0, 25, 16];
        eap.extend_from_slice(&AUTH_CHALLENGE);
        eap.extend_from_slice(b"Name");
        eap
    }

    #[test]
    fn rfc2759_challenge_and_response() {
        let challenge = parse_challenge(&challenge_packet()).unwrap();
        assert_eq!(challenge.eap_id, 7);
        assert_eq!(challenge.mschap_id, 9);
        let prepared = respond_with_peer_challenge(&challenge, "User", "clientPass", PEER).unwrap();
        assert_eq!(
            &prepared.eap_response[..10],
            &[2, 7, 0, 63, 26, 2, 9, 0, 58, 49]
        );
        assert_eq!(&prepared.eap_response[10..26], &PEER);
        assert_eq!(&prepared.eap_response[26..34], &[0; 8]);
        assert_eq!(&prepared.eap_response[34..58], &NT_RESPONSE);
        assert_eq!(&prepared.eap_response[58..], b"\0User");
    }

    #[test]
    fn rfc2759_authenticator_and_rfc3079_msk() {
        let challenge = parse_challenge(&challenge_packet()).unwrap();
        let prepared = respond_with_peer_challenge(&challenge, "User", "clientPass", PEER).unwrap();
        let message = b"S=407A5589115FD0D6209F510FE9C04566932CDA56 M=OK";
        let mut success = vec![
            1,
            8,
            0,
            (9 + message.len()) as u8,
            26,
            3,
            9,
            0,
            (4 + message.len()) as u8,
        ];
        success.extend_from_slice(message);
        let verified = prepared.verify_success(&success).unwrap();
        assert_eq!(verified.success_ack, [2, 8, 0, 6, 26, 3]);
        assert_eq!(
            &verified.msk()[..16],
            &[
                0xd5, 0xf0, 0xe9, 0x52, 0x1e, 0x3e, 0xa9, 0x58, 0x96, 0x45, 0xe8, 0x60, 0x51, 0xc8,
                0x22, 0x26
            ]
        );
        assert_eq!(
            &verified.msk()[16..32],
            &[
                0x8b, 0x7c, 0xdc, 0x14, 0x9b, 0x99, 0x3a, 0x1b, 0xa1, 0x18, 0xcb, 0x15, 0x3f, 0x56,
                0xdc, 0xcb
            ]
        );
        assert_eq!(&verified.msk()[32..], &[0; 32]);
    }

    #[test]
    fn bad_authenticator_never_exposes_msk() {
        let challenge = parse_challenge(&challenge_packet()).unwrap();
        let prepared = respond_with_peer_challenge(&challenge, "User", "clientPass", PEER).unwrap();
        let message = b"S=0000000000000000000000000000000000000000";
        let mut success = vec![
            1,
            8,
            0,
            (9 + message.len()) as u8,
            26,
            3,
            9,
            0,
            (4 + message.len()) as u8,
        ];
        success.extend_from_slice(message);
        assert!(matches!(
            prepared.verify_success(&success),
            Err(Error::AuthenticatorMismatch)
        ));
    }

    #[test]
    fn bad_lengths_are_rejected() {
        let mut packet = challenge_packet();
        packet[8] = 24;
        assert!(matches!(
            parse_challenge(&packet),
            Err(Error::InvalidLength)
        ));
        packet = challenge_packet();
        packet[9] = 15;
        assert!(matches!(
            parse_challenge(&packet),
            Err(Error::InvalidChallenge)
        ));
        packet.pop();
        assert!(matches!(
            parse_challenge(&packet),
            Err(Error::InvalidLength)
        ));
    }

    #[test]
    fn rfc2759_des_key_parity() {
        assert_eq!(
            expand_des_key(&[0xfc, 0x15, 0x6a, 0xf7, 0xed, 0xcd, 0x6c]),
            [0xfd, 0x0b, 0x5b, 0x5e, 0x7f, 0x6e, 0x34, 0xd9]
        );
    }

    #[test]
    fn failure_metadata() {
        let msg = b"E=691 R=0 C=0123456789ABCDEF0123456789ABCDEF V=3";
        let mut eap = vec![
            1,
            8,
            0,
            (9 + msg.len()) as u8,
            26,
            4,
            9,
            0,
            (4 + msg.len()) as u8,
        ];
        eap.extend_from_slice(msg);
        assert_eq!(parse_failure(&eap).unwrap().error_code, 691);
        assert!(!parse_failure(&eap).unwrap().retry_allowed);
        assert_eq!(
            parse_failure(&eap).unwrap().acknowledgement(),
            [2, 8, 0, 6, 26, 4]
        );
    }

    #[test]
    fn domain_is_excluded_only_from_challenge_hash() {
        let challenge = parse_challenge(&challenge_packet()).unwrap();
        let prepared =
            respond_with_peer_challenge(&challenge, "DOMAIN\\User", "clientPass", PEER).unwrap();
        assert_eq!(&prepared.eap_response[34..58], &NT_RESPONSE);
        assert_eq!(&prepared.eap_response[59..], b"DOMAIN\\User");
    }
}
