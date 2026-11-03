//! One fresh CREATE_CHILD_SA nonce, inbound SPI, and MODP-2048 private key.
//! Retain this object only until the response (or timeout); Drop wipes the key.
use crate::rekey::{self, Accepted, EspKeys, Offer};
use oftc_modp14::{Secret, EXPONENT_LEN, PUBLIC_LEN};

pub struct Ephemeral {
    pub offer: Offer,
    key: Secret,
}

impl Drop for Ephemeral {
    fn drop(&mut self) {
        self.offer.ni.fill(0);
    }
}

impl Ephemeral {
    pub fn new(old_inbound_spi: u32, tsi: Vec<u8>, tsr: Vec<u8>) -> Result<Self, rekey::Error> {
        if old_inbound_spi == 0 {
            return Err(rekey::Error::InvalidSpi);
        }
        let mut ni = [0u8; 32];
        if oftc_crypto::fill_random(&mut ni).is_err() {
            return Err(rekey::Error::Crypto);
        }
        let mut spi = [0u8; 4];
        let mut new_spi = 0;
        for _ in 0..8 {
            if oftc_crypto::fill_random(&mut spi).is_err() {
                ni.fill(0);
                return Err(rekey::Error::Crypto);
            }
            new_spi = u32::from_be_bytes(spi);
            if new_spi > 255 && new_spi != old_inbound_spi {
                break;
            }
        }
        if new_spi <= 255 || new_spi == old_inbound_spi {
            ni.fill(0);
            return Err(rekey::Error::InvalidSpi);
        }
        let mut exponent_seed = [0u8; EXPONENT_LEN];
        if oftc_crypto::fill_random(&mut exponent_seed).is_err() {
            exponent_seed.fill(0);
            ni.fill(0);
            return Err(rekey::Error::Crypto);
        }
        let (key, ke_i) = Secret::generate(&mut exponent_seed).ok_or(rekey::Error::Crypto)?;
        let result = Self {
            offer: Offer {
                old_inbound_spi,
                new_inbound_spi: new_spi,
                ni,
                ke_i,
                tsi,
                tsr,
            },
            key,
        };
        rekey::encode_request(&result.offer)?; // validate policy before exposure
        Ok(result)
    }

    /// Called only after the response has passed IKE SK, message ID, suite,
    /// nonce, MODP group-14 value, and traffic-selector checks.
    pub fn keymat(&self, accepted: &Accepted, sk_d: &[u8; 32]) -> Result<EspKeys, rekey::Error> {
        self.keymat_with_order(&accepted.ke_r, &self.offer.ni, &accepted.nr, sk_d)
    }

    /// For peer-initiated rekey, Ni belongs to the peer and our generated
    /// nonce is Nr. KEYMAT direction also reverses at the session boundary.
    pub fn keymat_as_responder(&self, peer_nonce: &[u8], peer_ke: &[u8; PUBLIC_LEN],
                               sk_d: &[u8; 32]) -> Result<EspKeys, rekey::Error> {
        self.keymat_with_order(peer_ke, peer_nonce, &self.offer.ni, sk_d)
    }

    fn keymat_with_order(&self, peer_ke: &[u8; PUBLIC_LEN], ni: &[u8], nr: &[u8],
                         sk_d: &[u8; 32]) -> Result<EspKeys, rekey::Error> {
        let mut secret = self.key.shared(peer_ke).ok_or(rekey::Error::InvalidKe)?;
        rekey::derive_keymat(
            sk_d,
            &mut secret,
            ni,
            nr,
            |key, input| Ok(oftc_crypto::hmac_sha256(key, input)),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn selector() -> Vec<u8> {
        vec![
            1, 0, 0, 0, 7, 0, 0, 16, 0, 0, 255, 255, 10, 99, 0, 12, 10, 99, 0, 12,
        ]
    }

    #[test]
    fn generates_distinct_nonce_spi_and_dh_keymat() {
        let first = Ephemeral::new(7, selector(), selector()).unwrap();
        let second = Ephemeral::new(9, selector(), selector()).unwrap();
        assert_ne!(first.offer.ni, second.offer.ni);
        assert_ne!(first.offer.new_inbound_spi, second.offer.new_inbound_spi);
        let accepted_a = Accepted {
            peer_inbound_spi: second.offer.new_inbound_spi,
            nr: second.offer.ni.to_vec(),
            ke_r: second.offer.ke_i,
            tsi: selector(),
            tsr: selector(),
        };
        let accepted_b = Accepted {
            peer_inbound_spi: first.offer.new_inbound_spi,
            nr: first.offer.ni.to_vec(),
            ke_r: first.offer.ke_i,
            tsi: selector(),
            tsr: selector(),
        };
        // Direction reverses for a responder: use equal nonce order to prove
        // that two independent ephemeral DH keys produce the same KEYMAT.
        let a = first.keymat(&accepted_a, &[0x77; 32]).unwrap();
        let mut secret = second.key.shared(&accepted_b.ke_r).unwrap();
        let b = rekey::derive_keymat(
            &[0x77; 32],
            &mut secret,
            &first.offer.ni,
            &second.offer.ni,
            |key, input| Ok(oftc_crypto::hmac_sha256(key, input)),
        )
        .unwrap();
        assert_eq!(a, b);
    }
}
