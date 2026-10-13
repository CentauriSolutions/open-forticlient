//! RFC 3526 group 14 for CHILD_SA PFS. The 2048-bit arithmetic uses
//! crypto-bigint's fixed-size, constant-time Montgomery exponentiation.
//! Randomness is supplied by the caller's SecRandomCopyBytes bridge.

use crypto_bigint::{
    modular::{FixedMontyForm, FixedMontyParams},
    Odd, U2048, U256,
};
use zeroize::Zeroize;

pub const PUBLIC_LEN: usize = 256;
pub const EXPONENT_LEN: usize = 32;

// RFC 3526 section 3, group 14. This is a public safe prime; generator is 2.
const PRIME: U2048 = U2048::from_be_hex(concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74",
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437",
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05",
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB",
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B",
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718",
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
));

fn params() -> FixedMontyParams<{ U2048::LIMBS }> {
    FixedMontyParams::new_vartime(Odd::new(PRIME).expect("RFC 3526 prime is odd"))
}

/// Reject zero, one, p-1, and out-of-range peer values before exponentiation.
pub fn validate_public(peer: &[u8; PUBLIC_LEN]) -> bool {
    let y = U2048::from_be_slice(peer);
    y >= U2048::from(2u8) && y <= PRIME.wrapping_sub(&U2048::from(2u8))
}

pub struct Secret {
    exponent: U256,
}

impl Drop for Secret {
    fn drop(&mut self) { self.exponent.zeroize(); }
}

impl Secret {
    /// Consume 256 bits of caller-supplied CSPRNG output and wipe the input.
    /// RFC 3526 recommends 220–320 bits of exponent entropy for this group.
    pub fn generate(random: &mut [u8; EXPONENT_LEN]) -> Option<(Self, [u8; PUBLIC_LEN])> {
        let exponent = U256::from_be_slice(random);
        random.zeroize();
        if exponent <= U256::ONE { return None; }
        let generator = FixedMontyForm::new(&U2048::from(2u8), &params());
        let public = generator.pow_bounded_exp(&exponent, 256).retrieve().to_be_bytes();
        Some((Self { exponent }, public.into()))
    }

    pub fn shared(&self, peer: &[u8; PUBLIC_LEN]) -> Option<[u8; PUBLIC_LEN]> {
        if !validate_public(peer) { return None; }
        let y = U2048::from_be_slice(peer);
        let peer_form = FixedMontyForm::new(&y, &params());
        let secret = peer_form.pow_bounded_exp(&self.exponent, 256).retrieve().to_be_bytes();
        if secret.iter().all(|byte| *byte == 0) { return None; }
        Some(secret.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(hex: &str) -> [u8; PUBLIC_LEN] {
        assert_eq!(hex.len(), PUBLIC_LEN * 2);
        let mut bytes = [0; PUBLIC_LEN];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap();
        }
        bytes
    }

    #[test]
    fn two_parties_agree_and_reject_invalid_peer_values() {
        let mut a_seed = [0x35; EXPONENT_LEN];
        let mut b_seed = [0x79; EXPONENT_LEN];
        let (a, a_public) = Secret::generate(&mut a_seed).unwrap();
        let (b, b_public) = Secret::generate(&mut b_seed).unwrap();
        assert_eq!(a_seed, [0; EXPONENT_LEN]);
        assert_eq!(b_seed, [0; EXPONENT_LEN]);
        assert!(validate_public(&a_public));
        assert!(validate_public(&b_public));
        // Independent Python pow(2, exponent, RFC 3526 p) and
        // pow(peer_public, exponent, p) vectors, fixed-width big-endian.
        assert_eq!(a_public, decode(concat!(
            "0b7cc9a1e67fb89e2e9e336b275cc3712e03bc142dd6a240f66f20ff5428f90d",
            "cc4e0e0e1ba57b56e83e7302ef9319723af393742872c72f75410004b1fbc8c8",
            "72e06b7c34e3c1d4878c3768323706f879661f593e0ea5b22ff2e75faa60dda0",
            "504dc774d3071eaea3287132c209b150247b9746f43368ab0396aa0dd3319cd2",
            "74b7729fec7cf838a6047fe53abad27bd8d39bb2c62021023b6bf76ce72b1d15",
            "a70f6bc6922bc61158352dfdf6e3ffd0b3057326643ca7ddb276688d291bd2b61",
            "c98cc16123da33cdc1661c668e7c55f9952384d7dda670b3ecc39b7ff0e8a945",
            "16762af96a6c4b924f82771ef56a61dd55100a0b23ea91c775baf47901aa528",
        )));
        assert_eq!(a.shared(&b_public), Some(decode(concat!(
            "148810b5faf02986b616c91ee3794a33fd46a9feda986546109a5d562cf2b86f4",
            "e749de349bbd11bf75e3238c5dcadefd2256f1726753154fe8fa6bc6dfbbfaa",
            "d3f02348c4a36ab257119168bb56332943bc701805335928840c5192ed86db6f5",
            "a82ca96d2a87f5a44085f82e998d9d7a7aabeb6244739ca27aafaae8284bca1",
            "092e92ef3278d9327d0a38edf518a8118f82b1850e5375e42588f289cd69a36",
            "5e2d8d9b6c5fea286ccab45e6dca41ea5882ae5f4a0af562199b15c913a1a1",
            "d40d1b7c2abe1523ca18c12223e7bb546728ecc903e55b0ecce04a71bfc1b5c",
            "48814c2e0e4edcff9e6195b65a8b3359a9e6916dd6d324e24b15eefd30346c2af5fb",
        ))));
        assert_eq!(a.shared(&b_public), b.shared(&a_public));
        assert_ne!(a.shared(&b_public), Some([0; PUBLIC_LEN]));
        assert!(!validate_public(&[0; PUBLIC_LEN]));
        let mut one = [0; PUBLIC_LEN]; one[PUBLIC_LEN - 1] = 1;
        assert!(!validate_public(&one));
        assert!(!validate_public(&PRIME.to_be_bytes().into()));
        let p_minus_one: [u8; PUBLIC_LEN] = PRIME.wrapping_sub(&U2048::ONE).to_be_bytes().into();
        assert!(!validate_public(&p_minus_one));
    }
}
