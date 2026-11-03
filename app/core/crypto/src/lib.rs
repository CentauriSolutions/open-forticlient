//! Cryptographic primitives for the OFTC IKEv2/ESP engine.
//!
//! The suite is fixed by the gateway: group 20 (NIST P-384) key exchange,
//! AES-256-CBC without padding, HMAC-SHA1, and system randomness. Every
//! function here is deterministic except the ones that draw randomness, and
//! none holds state, so callers can wrap them behind their own traits.

use aes::cipher::{block_padding::NoPadding, BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use hmac::{Hmac, KeyInit, Mac};
use p384::{PublicKey, SecretKey};
use sha1::Sha1;
use sha2::Sha256;
use zeroize::Zeroizing;

/// Length of a group 20 public value on the wire: X || Y, each 48 bytes.
pub const GROUP20_PUBLIC_LEN: usize = 96;
/// Length of the group 20 shared secret: the X coordinate of the shared point.
pub const GROUP20_SECRET_LEN: usize = 48;
/// AES block and CBC IV length.
pub const BLOCK_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The system random number generator failed.
    Random,
    /// An input had the wrong length or was not a valid curve point.
    InvalidInput,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Error::Random => "system random number generator failed",
            Error::InvalidInput => "invalid cryptographic input",
        })
    }
}

impl std::error::Error for Error {}

/// Fill `buffer` from the operating system's random number generator.
pub fn fill_random(buffer: &mut [u8]) -> Result<(), Error> {
    getrandom::fill(buffer).map_err(|_| Error::Random)
}

/// Return `N` random bytes.
pub fn random_array<const N: usize>() -> Result<[u8; N], Error> {
    let mut bytes = [0; N];
    fill_random(&mut bytes)?;
    Ok(bytes)
}

/// One side of an ephemeral group 20 (secp384r1) key exchange.
pub struct Group20Key(SecretKey);

impl Group20Key {
    /// Generate a fresh key and return it with its 96-byte public value.
    pub fn generate() -> Result<(Self, [u8; GROUP20_PUBLIC_LEN]), Error> {
        let mut seed = Zeroizing::new([0u8; 48]);
        // A uniformly random 48-byte string is a valid scalar except with
        // negligible probability (below 2^-190); retry in that case.
        loop {
            fill_random(&mut *seed)?;
            if let Ok(secret) = SecretKey::from_bytes(&(*seed).into()) {
                let key = Self(secret);
                let public = key.public_value();
                return Ok((key, public));
            }
        }
    }

    /// Build a key from a known scalar. For known-answer tests only.
    #[cfg(test)]
    fn from_scalar(scalar: &[u8; 48]) -> Self {
        Self(SecretKey::from_bytes(&(*scalar).into()).expect("valid test scalar"))
    }

    /// The public value: the uncompressed point without its leading 0x04.
    pub fn public_value(&self) -> [u8; GROUP20_PUBLIC_LEN] {
        let point = p384::Sec1Point::from(self.0.public_key());
        let point = point.as_ref();
        debug_assert_eq!(point.len(), GROUP20_PUBLIC_LEN + 1);
        let mut out = [0; GROUP20_PUBLIC_LEN];
        out.copy_from_slice(&point[1..]);
        out
    }

    /// Compute the shared secret with the peer's 96-byte public value.
    /// Fails if the peer value is not a point on the curve.
    pub fn shared_secret(
        &self,
        peer: &[u8; GROUP20_PUBLIC_LEN],
    ) -> Result<Zeroizing<[u8; GROUP20_SECRET_LEN]>, Error> {
        let mut encoded = [0u8; GROUP20_PUBLIC_LEN + 1];
        encoded[0] = 4;
        encoded[1..].copy_from_slice(peer);
        let peer = PublicKey::from_sec1_bytes(&encoded).map_err(|_| Error::InvalidInput)?;
        let shared = self.0.diffie_hellman(&peer);
        let mut out = Zeroizing::new([0; GROUP20_SECRET_LEN]);
        out.copy_from_slice(shared.raw_secret_bytes());
        Ok(out)
    }
}

type CbcEncryptor = cbc::Encryptor<aes::Aes256>;
type CbcDecryptor = cbc::Decryptor<aes::Aes256>;

fn check_blocks(input: &[u8]) -> Result<(), Error> {
    if input.is_empty() || !input.len().is_multiple_of(BLOCK_LEN) {
        return Err(Error::InvalidInput);
    }
    Ok(())
}

/// AES-256-CBC encrypt `input` without padding. `input` must be a nonzero
/// multiple of the block length; the caller pads.
pub fn aes256_cbc_encrypt(
    key: &[u8; 32],
    iv: &[u8; BLOCK_LEN],
    input: &[u8],
) -> Result<Vec<u8>, Error> {
    check_blocks(input)?;
    let mut buffer = input.to_vec();
    CbcEncryptor::new(key.into(), iv.into())
        .encrypt_padded::<NoPadding>(&mut buffer, input.len())
        .map_err(|_| Error::InvalidInput)?;
    Ok(buffer)
}

/// AES-256-CBC decrypt `input` without removing padding.
pub fn aes256_cbc_decrypt(
    key: &[u8; 32],
    iv: &[u8; BLOCK_LEN],
    input: &[u8],
) -> Result<Vec<u8>, Error> {
    check_blocks(input)?;
    let mut buffer = input.to_vec();
    CbcDecryptor::new(key.into(), iv.into())
        .decrypt_padded::<NoPadding>(&mut buffer)
        .map_err(|_| Error::InvalidInput)?;
    Ok(buffer)
}

/// HMAC-SHA1 of `input` under `key` (any key length).
pub fn hmac_sha1(key: &[u8], input: &[u8]) -> [u8; 20] {
    let mut mac = <Hmac<Sha1> as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(input);
    mac.finalize().into_bytes().into()
}

/// HMAC-SHA256 of `input` under `key` (any key length).
pub fn hmac_sha256(key: &[u8], input: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(input);
    mac.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        let text: String = text.split_whitespace().collect();
        (0..text.len()).step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    fn array<const N: usize>(text: &str) -> [u8; N] {
        hex(text).try_into().unwrap()
    }

    // NIST SP 800-38A, F.2.5 / F.2.6, CBC-AES256.
    const CBC_KEY: &str = "603deb1015ca71be2b73aef0857d7781 1f352c073b6108d72d9810a30914dff4";
    const CBC_IV: &str = "000102030405060708090a0b0c0d0e0f";
    const CBC_PLAIN: &str = "6bc1bee22e409f96e93d7e117393172a ae2d8a571e03ac9c9eb76fac45af8e51
        30c81c46a35ce411e5fbc1191a0a52ef f69f2445df4f9b17ad2b417be66c3710";
    const CBC_CIPHER: &str = "f58c4c04d6e5f1ba779eabfb5f7bfbd6 9cfc4e967edb808d679f777bc6702c7d
        39f23369a9d9bacfa530e26304231461 b2eb05e2c39be9fcda6c19078c6a9d1b";

    #[test]
    fn aes256_cbc_matches_nist_vectors() {
        let key = array(CBC_KEY);
        let iv = array(CBC_IV);
        assert_eq!(aes256_cbc_encrypt(&key, &iv, &hex(CBC_PLAIN)).unwrap(), hex(CBC_CIPHER));
        assert_eq!(aes256_cbc_decrypt(&key, &iv, &hex(CBC_CIPHER)).unwrap(), hex(CBC_PLAIN));
    }

    #[test]
    fn aes256_cbc_rejects_empty_and_partial_blocks() {
        let key = [0; 32];
        let iv = [0; 16];
        for length in [0, 1, 15, 17, 31] {
            let input = vec![0; length];
            assert_eq!(aes256_cbc_encrypt(&key, &iv, &input), Err(Error::InvalidInput));
            assert_eq!(aes256_cbc_decrypt(&key, &iv, &input), Err(Error::InvalidInput));
        }
    }

    // RFC 2202 test cases 1, 2, 6 and 7 for HMAC-SHA-1.
    #[test]
    fn hmac_sha1_matches_rfc_2202() {
        assert_eq!(hmac_sha1(&[0x0b; 20], b"Hi There"),
            array::<20>("b617318655057264e28bc0b6fb378c8ef146be00"));
        assert_eq!(hmac_sha1(b"Jefe", b"what do ya want for nothing?"),
            array::<20>("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"));
        assert_eq!(hmac_sha1(&[0xaa; 80],
            b"Test Using Larger Than Block-Size Key - Hash Key First"),
            array::<20>("aa4ae5e15272d00e95705637ce8a3b55ed402112"));
        assert_eq!(hmac_sha1(&[0xaa; 80],
            b"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"),
            array::<20>("e8e99d0f45237d786d6bbaa7965c7808bbff1a91"));
    }

    // RFC 4231 test cases 1, 2 and 6 for HMAC-SHA-256.
    #[test]
    fn hmac_sha256_matches_rfc_4231() {
        assert_eq!(hmac_sha256(&[0x0b; 20], b"Hi There"),
            array::<32>("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));
        assert_eq!(hmac_sha256(b"Jefe", b"what do ya want for nothing?"),
            array::<32>("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
        assert_eq!(hmac_sha256(&[0xaa; 131],
            b"Test Using Larger Than Block-Size Key - Hash Key First"),
            array::<32>("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"));
    }

    // RFC 5903 section 8.2: 384-bit random ECP group. The shared secret is the
    // X coordinate of the common value (girx).
    const I: &str = "099f3c70 34d4a2c6 99884d73 a375a67f
        7624ef7c 6b3c0f16 0647b674 14dce655
        e35b5380 41e649ee 3faef896 783ab194";
    const GIX: &str = "667842d7 d180ac2c de6f74f3 7551f557
        55c7645c 20ef73e3 1634fe72 b4c55ee6
        de3ac808 acb4bdb4 c88732ae e95f41aa";
    const GIY: &str = "9482ed1f c0eeb9ca fc498462 5ccfc23f
        65032149 e0e144ad a0241815 35a0f38e
        eb9fcff3 c2c947da e69b4c63 4573a81c";
    const R: &str = "41cb0779 b4bdb85d 47846725 fbec3c94
        30fab46c c8dc5060 855cc9bd a0aa2942
        e0308312 916b8ed2 960e4bd5 5a7448fc";
    const GRX: &str = "e558dbef 53eecde3 d3fccfc1 aea08a89
        a987475d 12fd950d 83cfa417 32bc509d
        0d1ac43a 0336def9 6fda41d0 774a3571";
    const GRY: &str = "dcfbec7a acf31964 72169e83 8430367f
        66eebe3c 6e70c416 dd5f0c68 759dd1ff
        f83fa401 42209dff 5eaad96d b9e6386c";
    const SHARED: &str = "11187331 c279962d 93d60424 3fd592cb
        9d0a926f 422e4718 7521287e 7156c5c4
        d6031355 69b9e9d0 9cf5d4a2 70f59746";

    fn join(x: &str, y: &str) -> [u8; GROUP20_PUBLIC_LEN] {
        let mut out = [0; GROUP20_PUBLIC_LEN];
        out[..48].copy_from_slice(&hex(x));
        out[48..].copy_from_slice(&hex(y));
        out
    }

    #[test]
    fn group20_matches_rfc_5903_vectors() {
        let initiator = Group20Key::from_scalar(&array(I));
        let responder = Group20Key::from_scalar(&array(R));
        assert_eq!(initiator.public_value(), join(GIX, GIY));
        assert_eq!(responder.public_value(), join(GRX, GRY));
        let expected: [u8; 48] = array(SHARED);
        assert_eq!(*initiator.shared_secret(&join(GRX, GRY)).unwrap(), expected);
        assert_eq!(*responder.shared_secret(&join(GIX, GIY)).unwrap(), expected);
    }

    #[test]
    fn group20_generated_keys_agree() {
        let (a, a_public) = Group20Key::generate().unwrap();
        let (b, b_public) = Group20Key::generate().unwrap();
        assert_ne!(a_public, b_public);
        assert_eq!(*a.shared_secret(&b_public).unwrap(), *b.shared_secret(&a_public).unwrap());
    }

    #[test]
    fn group20_rejects_points_off_the_curve() {
        let (key, _) = Group20Key::generate().unwrap();
        assert_eq!(key.shared_secret(&[0; GROUP20_PUBLIC_LEN]).err(), Some(Error::InvalidInput));
        let mut bad = join(GIX, GIY);
        bad[95] ^= 1;
        assert_eq!(key.shared_secret(&bad).err(), Some(Error::InvalidInput));
    }

    #[test]
    fn random_values_differ() {
        assert_ne!(random_array::<32>().unwrap(), random_array::<32>().unwrap());
    }
}
