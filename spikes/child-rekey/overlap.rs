//! Inbound ESP overlap with one independent anti-replay window per SPI.
//! The IKE caller authenticates the rekey response before installing a new SA.
use crate::esp::{self, Crypto, InboundSa, Keys};

pub struct InboundOverlap<C: Crypto> {
    active_spi: u32,
    active: InboundSa<C>,
    old: Vec<(u32, InboundSa<C>)>,
}

impl<C: Crypto> InboundOverlap<C> {
    pub fn new(spi: u32, keys: Keys, crypto: C) -> Result<Self, esp::Error> {
        let active = InboundSa::new(spi, keys, crypto)?;
        Ok(Self {
            active_spi: spi,
            active,
            old: Vec::new(),
        })
    }

    /// Install new inbound SA after the authenticated CREATE_CHILD_SA reply.
    /// The previous inbound SA remains able to decrypt packets during grace.
    pub fn install(&mut self, spi: u32, keys: Keys, crypto: C) -> Result<(), esp::Error> {
        if spi == self.active_spi
            || self.old.iter().any(|(old, _)| *old == spi)
            || self.old.len() >= 2
        {
            return Err(esp::Error::InvalidSa);
        }
        let replacement = InboundSa::new(spi, keys, crypto)?;
        let old = std::mem::replace(&mut self.active, replacement);
        self.old.push((self.active_spi, old));
        self.active_spi = spi;
        Ok(())
    }

    pub fn open(&mut self, packet: &[u8]) -> Result<Vec<u8>, esp::Error> {
        if packet.len() < 4 {
            return Err(esp::Error::InvalidPacket);
        }
        let spi = u32::from_be_bytes(packet[..4].try_into().unwrap());
        if spi == self.active_spi {
            return self.active.open(packet);
        }
        let (_, sa) = self
            .old
            .iter_mut()
            .find(|(old, _)| *old == spi)
            .ok_or(esp::Error::InvalidSa)?;
        sa.open(packet)
    }

    /// Invoke only after an authenticated DELETE or bounded old-SA expiry.
    pub fn delete_old(&mut self, spi: u32) -> Result<(), esp::Error> {
        let index = self
            .old
            .iter()
            .position(|(old, _)| *old == spi)
            .ok_or(esp::Error::InvalidSa)?;
        self.old.remove(index);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::esp::{OutboundSa, SystemCrypto};

    fn keys(seed: u8) -> Keys {
        Keys {
            encryption: [seed; 32],
            integrity: [seed.wrapping_add(1); 20],
        }
    }

    fn ip() -> [u8; 20] {
        [
            0x45, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0, 10, 0, 8, 1, 10, 99, 0, 12,
        ]
    }

    #[test]
    fn authenticates_both_spis_with_independent_replay_windows() {
        let crypto = SystemCrypto;
        let mut old_sender = OutboundSa::new(1, keys(0x11), crypto).unwrap();
        let mut inbound = InboundOverlap::new(1, keys(0x11), crypto).unwrap();
        let first_old = old_sender.seal(&ip()).unwrap();
        assert_eq!(inbound.open(&first_old).unwrap(), ip());
        inbound.install(3, keys(0x33), crypto).unwrap();
        let mut new_sender = OutboundSa::new(3, keys(0x33), crypto).unwrap();
        let first_new = new_sender.seal(&ip()).unwrap(); // sequence 1 on both SPIs
        let second_old = old_sender.seal(&ip()).unwrap();
        assert_eq!(inbound.open(&first_new).unwrap(), ip());
        assert_eq!(inbound.open(&second_old).unwrap(), ip());
        assert_eq!(inbound.open(&first_new), Err(esp::Error::Replay));
        assert_eq!(inbound.open(&first_old), Err(esp::Error::Replay));
        inbound.delete_old(1).unwrap();
        assert_eq!(inbound.open(&second_old), Err(esp::Error::InvalidSa));
        assert_eq!(
            inbound.open(&new_sender.seal(&ip()).unwrap()).unwrap(),
            ip()
        );
    }

    #[test]
    fn wrong_key_and_duplicate_spi_preserve_existing_sa() {
        let crypto = SystemCrypto;
        let mut inbound = InboundOverlap::new(1, keys(1), crypto).unwrap();
        assert_eq!(
            inbound.install(1, keys(2), crypto),
            Err(esp::Error::InvalidSa)
        );
        let mut sender = OutboundSa::new(1, keys(1), crypto).unwrap();
        assert_eq!(inbound.open(&sender.seal(&ip()).unwrap()).unwrap(), ip());
        inbound.install(3, keys(3), crypto).unwrap();
        let mut wrong = OutboundSa::new(3, keys(4), crypto).unwrap();
        assert_eq!(
            inbound.open(&wrong.seal(&ip()).unwrap()),
            Err(esp::Error::AuthenticationFailed)
        );
        let mut correct = OutboundSa::new(3, keys(3), crypto).unwrap();
        assert_eq!(inbound.open(&correct.seal(&ip()).unwrap()).unwrap(), ip());
    }
}
