//! Offline ESP tunnel-mode packet codec for one non-ESN AES-256-CBC/HMAC-SHA1-96 CHILD_SA.
//! No network or packet-tunnel I/O. Keys and SPIs must come from an authenticated CHILD_SA.

const BLOCK: usize = 16;
const ICV: usize = 12;
const MAX_IP: usize = 40 + 65535; // IPv6 without jumbograms; covers IPv4 too.
const MAX_ESP: usize = 8 + BLOCK + (MAX_IP + 2).div_ceil(BLOCK) * BLOCK + ICV;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidSa,
    InvalidPacket,
    AuthenticationFailed,
    Replay,
    SequenceExhausted,
    CryptoFailure,
}

/// Directional key material. The IKE core owns derivation and negotiated-transform checks.
pub struct Keys {
    pub encryption: [u8; 32],
    pub integrity: [u8; 20],
}

impl Drop for Keys {
    fn drop(&mut self) {
        self.encryption.fill(0);
        self.integrity.fill(0);
    }
}

/// Implementations must use unpredictable IVs and vetted AES/HMAC primitives.
pub trait Crypto {
    fn random_iv(&self) -> Result<[u8; BLOCK], Error>;
    fn cbc(
        &self,
        encrypt: bool,
        key: &[u8; 32],
        iv: &[u8; BLOCK],
        input: &[u8],
    ) -> Result<Vec<u8>, Error>;
    fn hmac_sha1(&self, key: &[u8; 20], input: &[u8]) -> Result<[u8; 20], Error>;
}

#[derive(Clone, Copy, Default)]
pub struct SystemCrypto;

impl Crypto for SystemCrypto {
    fn random_iv(&self) -> Result<[u8; BLOCK], Error> {
        oftc_crypto::random_array().map_err(|_| Error::CryptoFailure)
    }

    fn cbc(
        &self,
        encrypt: bool,
        key: &[u8; 32],
        iv: &[u8; BLOCK],
        input: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if input.is_empty() || !input.len().is_multiple_of(BLOCK) {
            return Err(Error::InvalidPacket);
        }
        let output = if encrypt {
            oftc_crypto::aes256_cbc_encrypt(key, iv, input)
        } else {
            oftc_crypto::aes256_cbc_decrypt(key, iv, input)
        };
        output.map_err(|_| Error::CryptoFailure)
    }

    fn hmac_sha1(&self, key: &[u8; 20], input: &[u8]) -> Result<[u8; 20], Error> {
        Ok(oftc_crypto::hmac_sha1(key, input))
    }
}

fn ip_next_header(packet: &[u8]) -> Result<u8, Error> {
    match packet.first().map(|b| b >> 4) {
        Some(4) if packet.len() >= 20 => {
            let header = usize::from(packet[0] & 0x0f) * 4;
            let declared = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
            if header < 20 || header > packet.len() || declared != packet.len() || declared < header
            {
                return Err(Error::InvalidPacket);
            }
            Ok(4)
        }
        Some(6) if packet.len() >= 40 => {
            let payload = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
            if packet.len() != 40 + payload {
                return Err(Error::InvalidPacket);
            }
            Ok(41)
        }
        _ => Err(Error::InvalidPacket),
    }
}

pub struct OutboundSa<C: Crypto> {
    spi: u32,
    next_sequence: u32,
    keys: Keys,
    crypto: C,
}

impl<C: Crypto> OutboundSa<C> {
    pub fn new(spi: u32, keys: Keys, crypto: C) -> Result<Self, Error> {
        if spi == 0 {
            return Err(Error::InvalidSa);
        }
        Ok(Self {
            spi,
            next_sequence: 1,
            keys,
            crypto,
        })
    }

    pub fn next_sequence(&self) -> Option<u32> {
        (self.next_sequence != 0).then_some(self.next_sequence)
    }

    /// Returns the bare ESP packet; UDP/4500 uses it unchanged as its payload.
    pub fn seal(&mut self, ip_packet: &[u8]) -> Result<Vec<u8>, Error> {
        let next_header = ip_next_header(ip_packet)?;
        if ip_packet.len() > MAX_IP {
            return Err(Error::InvalidPacket);
        }
        let sequence = self.next_sequence().ok_or(Error::SequenceExhausted)?;
        let iv = self.crypto.random_iv()?;
        let padding = (BLOCK - (ip_packet.len() + 2) % BLOCK) % BLOCK;
        let mut plain = Vec::with_capacity(ip_packet.len() + padding + 2);
        plain.extend_from_slice(ip_packet);
        for n in 1..=padding {
            plain.push(n as u8);
        }
        plain.push(padding as u8);
        plain.push(next_header);
        let plaintext_len = plain.len();
        let cipher_result = self.crypto.cbc(true, &self.keys.encryption, &iv, &plain);
        plain.fill(0);
        let cipher = cipher_result?;
        if cipher.len() != plaintext_len {
            return Err(Error::CryptoFailure);
        }
        let mut packet = Vec::with_capacity(8 + BLOCK + cipher.len() + ICV);
        packet.extend_from_slice(&self.spi.to_be_bytes());
        packet.extend_from_slice(&sequence.to_be_bytes());
        packet.extend_from_slice(&iv);
        packet.extend_from_slice(&cipher);
        let mut digest = self.crypto.hmac_sha1(&self.keys.integrity, &packet)?;
        packet.extend_from_slice(&digest[..ICV]);
        digest.fill(0);
        self.next_sequence = sequence.wrapping_add(1); // zero is exhausted; no reuse.
        Ok(packet)
    }
}

#[derive(Default)]
struct ReplayWindow {
    highest: u32,
    seen: u64,
}

impl ReplayWindow {
    fn eligible(&self, sequence: u32) -> bool {
        if sequence == 0 {
            return false;
        }
        if sequence > self.highest {
            return true;
        }
        let age = self.highest - sequence;
        age < 64 && (self.seen & (1u64 << age)) == 0
    }

    fn accept(&mut self, sequence: u32) {
        if sequence > self.highest {
            let advance = sequence - self.highest;
            self.seen = if advance >= 64 {
                1
            } else {
                (self.seen << advance) | 1
            };
            self.highest = sequence;
        } else {
            self.seen |= 1u64 << (self.highest - sequence);
        }
    }
}

pub struct InboundSa<C: Crypto> {
    spi: u32,
    keys: Keys,
    replay: ReplayWindow,
    crypto: C,
}

impl<C: Crypto> InboundSa<C> {
    pub fn new(spi: u32, keys: Keys, crypto: C) -> Result<Self, Error> {
        if spi == 0 {
            return Err(Error::InvalidSa);
        }
        Ok(Self {
            spi,
            keys,
            replay: ReplayWindow::default(),
            crypto,
        })
    }

    pub fn open(&mut self, packet: &[u8]) -> Result<Vec<u8>, Error> {
        if packet.len() < 8 + BLOCK + BLOCK + ICV
            || packet.len() > MAX_ESP
            || !(packet.len() - 8 - BLOCK - ICV).is_multiple_of(BLOCK)
        {
            return Err(Error::InvalidPacket);
        }
        let spi = u32::from_be_bytes(packet[..4].try_into().unwrap());
        if spi != self.spi {
            return Err(Error::InvalidSa);
        }
        let sequence = u32::from_be_bytes(packet[4..8].try_into().unwrap());
        if !self.replay.eligible(sequence) {
            return Err(Error::Replay);
        }
        let authenticated_len = packet.len() - ICV;
        let mut digest = self
            .crypto
            .hmac_sha1(&self.keys.integrity, &packet[..authenticated_len])?;
        let mut difference = 0u8;
        for n in 0..ICV {
            difference |= digest[n] ^ packet[authenticated_len + n];
        }
        digest.fill(0);
        if difference != 0 {
            return Err(Error::AuthenticationFailed);
        }
        // No decryption or replay-state mutation occurs until the ICV passes.
        let iv: &[u8; BLOCK] = packet[8..8 + BLOCK].try_into().unwrap();
        let mut plain = self.crypto.cbc(
            false,
            &self.keys.encryption,
            iv,
            &packet[8 + BLOCK..authenticated_len],
        )?;
        if plain.len() < BLOCK || !plain.len().is_multiple_of(BLOCK) {
            plain.fill(0);
            return Err(Error::CryptoFailure);
        }
        let decoded = (|| {
            let len = plain.len();
            let padding = usize::from(plain[len - 2]);
            if padding + 2 > len {
                return Err(Error::InvalidPacket);
            }
            for n in 0..padding {
                if plain[len - 2 - padding + n] != (n + 1) as u8 {
                    return Err(Error::InvalidPacket);
                }
            }
            let ip = &plain[..len - padding - 2];
            if ip_next_header(ip)? != plain[len - 1] {
                return Err(Error::InvalidPacket);
            }
            Ok(ip.to_vec())
        })();
        plain.fill(0);
        let ip = decoded?;
        self.replay.accept(sequence);
        Ok(ip)
    }
}

/// RFC 3948 UDP/4500 payload classification; the UDP header is owned by transport.
#[derive(Debug, PartialEq, Eq)]
pub enum Udp4500<'a> {
    Esp(&'a [u8]),
    Ike(&'a [u8]),
    NatKeepalive,
}

pub fn classify_udp4500(payload: &[u8]) -> Result<Udp4500<'_>, Error> {
    if payload == [0xff] {
        return Ok(Udp4500::NatKeepalive);
    }
    if payload.len() < 4 {
        return Err(Error::InvalidPacket);
    }
    if payload[..4] == [0; 4] {
        if payload.len() < 4 + 28 {
            return Err(Error::InvalidPacket);
        }
        return Ok(Udp4500::Ike(&payload[4..]));
    }
    if payload.len() < 8 + BLOCK + BLOCK + ICV {
        return Err(Error::InvalidPacket);
    }
    Ok(Udp4500::Esp(payload))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    const IP4: &str = "450000140001000040008eb2c0000201c6336402";
    // Independent Python hashlib.hmac + OpenSSL AES-256-CBC, with fixed public
    // keys/IV. This covers SPI, sequence, IV, padding, next-header, CBC, ICV.
    const ESP: &str = "1234567800000001000102030405060708090a0b0c0d0e0f\
        6bea9ec5f6e8b20f790a0158cfda621a3ad10dcc40cf729666add564bd60181b\
        ec595fbfdb8f4f95d549f3ed";

    fn hex(s: &str) -> Vec<u8> {
        let compact: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        compact
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    fn keys() -> Keys {
        let mut encryption = [0; 32];
        for (n, b) in encryption.iter_mut().enumerate() {
            *b = n as u8;
        }
        let mut integrity = [0; 20];
        for (n, b) in integrity.iter_mut().enumerate() {
            *b = 0xa0 + n as u8;
        }
        Keys {
            encryption,
            integrity,
        }
    }

    #[derive(Clone)]
    struct FixedIv;
    impl Crypto for FixedIv {
        fn random_iv(&self) -> Result<[u8; 16], Error> {
            Ok(std::array::from_fn(|n| n as u8))
        }
        fn cbc(
            &self,
            encrypt: bool,
            key: &[u8; 32],
            iv: &[u8; 16],
            input: &[u8],
        ) -> Result<Vec<u8>, Error> {
            SystemCrypto.cbc(encrypt, key, iv, input)
        }
        fn hmac_sha1(&self, key: &[u8; 20], input: &[u8]) -> Result<[u8; 20], Error> {
            SystemCrypto.hmac_sha1(key, input)
        }
    }

    #[test]
    fn independent_esp_vector_and_udp_demux() {
        let ip = hex(IP4);
        let mut tx = OutboundSa::new(0x12345678, keys(), FixedIv).unwrap();
        let packet = tx.seal(&ip).unwrap();
        assert_eq!(packet, hex(ESP));
        assert_eq!(tx.next_sequence(), Some(2));
        assert_eq!(
            classify_udp4500(&packet),
            Ok(Udp4500::Esp(packet.as_slice()))
        );
        let mut rx = InboundSa::new(0x12345678, keys(), SystemCrypto).unwrap();
        assert_eq!(rx.open(&hex(ESP)), Ok(ip));
        assert_eq!(rx.open(&hex(ESP)), Err(Error::Replay));
        assert_eq!(classify_udp4500(&[0xff]), Ok(Udp4500::NatKeepalive));
        let mut ike = vec![0; 32];
        ike[4] = 1;
        assert_eq!(classify_udp4500(&ike), Ok(Udp4500::Ike(&ike[4..])));
        assert_eq!(classify_udp4500(&[0, 0, 0, 0]), Err(Error::InvalidPacket));
        assert_eq!(classify_udp4500(&[1, 2, 3]), Err(Error::InvalidPacket));
    }

    #[derive(Clone)]
    struct CountingCrypto {
        decryptions: Arc<AtomicUsize>,
    }
    impl Crypto for CountingCrypto {
        fn random_iv(&self) -> Result<[u8; 16], Error> {
            SystemCrypto.random_iv()
        }
        fn cbc(
            &self,
            encrypt: bool,
            key: &[u8; 32],
            iv: &[u8; 16],
            input: &[u8],
        ) -> Result<Vec<u8>, Error> {
            if !encrypt {
                self.decryptions.fetch_add(1, Ordering::SeqCst);
            }
            SystemCrypto.cbc(encrypt, key, iv, input)
        }
        fn hmac_sha1(&self, key: &[u8; 20], input: &[u8]) -> Result<[u8; 20], Error> {
            SystemCrypto.hmac_sha1(key, input)
        }
    }

    #[test]
    fn malformed_packets_never_decrypt_before_integrity() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut rx = InboundSa::new(
            0x12345678,
            keys(),
            CountingCrypto {
                decryptions: calls.clone(),
            },
        )
        .unwrap();
        let valid = hex(ESP);
        for at in [8, 24, valid.len() - 1] {
            let mut bad = valid.clone();
            bad[at] ^= 1;
            assert_eq!(rx.open(&bad), Err(Error::AuthenticationFailed));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(rx.open(&valid), Ok(hex(IP4)));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        for size in [0, 1, 8, 39, valid.len() - 1] {
            assert_eq!(rx.open(&valid[..size]), Err(Error::InvalidPacket));
        }
        let mut wrong_spi = valid.clone();
        wrong_spi[0] ^= 1;
        assert_eq!(rx.open(&wrong_spi), Err(Error::InvalidSa));
        let mut zero_seq = valid.clone();
        zero_seq[4..8].fill(0);
        assert_eq!(rx.open(&zero_seq), Err(Error::Replay));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    fn packet_from_plain(plain: &[u8]) -> Vec<u8> {
        let iv: [u8; 16] = hex(ESP)[8..24].try_into().unwrap();
        let cipher = SystemCrypto
            .cbc(true, &keys().encryption, &iv, plain)
            .unwrap();
        let mut packet = hex(ESP)[..24].to_vec();
        packet.extend_from_slice(&cipher);
        let digest = SystemCrypto.hmac_sha1(&keys().integrity, &packet).unwrap();
        packet.extend_from_slice(&digest[..ICV]);
        packet
    }

    #[test]
    fn authenticated_bad_trailer_and_ip_do_not_commit_replay() {
        let mut rx = InboundSa::new(0x12345678, keys(), SystemCrypto).unwrap();
        let mut plain = hex(IP4);
        plain.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 10, 4]);
        plain[29] = 0; // invalid final padding byte, with a valid ICV
        assert_eq!(
            rx.open(&packet_from_plain(&plain)),
            Err(Error::InvalidPacket)
        );
        plain[29] = 10;
        plain[31] = 41; // IPv6 next-header for an IPv4 packet
        assert_eq!(
            rx.open(&packet_from_plain(&plain)),
            Err(Error::InvalidPacket)
        );
        plain[31] = 4;
        plain[2] = 0;
        plain[3] = 21; // bad inner IPv4 length
        assert_eq!(
            rx.open(&packet_from_plain(&plain)),
            Err(Error::InvalidPacket)
        );
        assert_eq!(rx.open(&hex(ESP)), Ok(hex(IP4)));
    }

    #[test]
    fn replay_window_out_of_order_and_exhaustion() {
        let ip = hex(IP4);
        let mut tx = OutboundSa::new(0x12345678, keys(), FixedIv).unwrap();
        let mut rx = InboundSa::new(0x12345678, keys(), SystemCrypto).unwrap();
        tx.next_sequence = 100;
        let p100 = tx.seal(&ip).unwrap();
        tx.next_sequence = 1000;
        let mut bad_high = tx.seal(&ip).unwrap();
        *bad_high.last_mut().unwrap() ^= 1;
        assert_eq!(rx.open(&bad_high), Err(Error::AuthenticationFailed));
        assert_eq!(rx.open(&p100), Ok(ip.clone()));
        tx.next_sequence = 99;
        let p99 = tx.seal(&ip).unwrap();
        assert_eq!(rx.open(&p99), Ok(ip.clone()));
        assert_eq!(rx.open(&p99), Err(Error::Replay));
        tx.next_sequence = 36;
        assert_eq!(rx.open(&tx.seal(&ip).unwrap()), Err(Error::Replay)); // age 64
        tx.next_sequence = 37;
        assert_eq!(rx.open(&tx.seal(&ip).unwrap()), Ok(ip.clone())); // age 63
        tx.next_sequence = u32::MAX;
        assert_eq!(tx.seal(&ip).unwrap()[4..8], u32::MAX.to_be_bytes());
        assert_eq!(tx.next_sequence(), None);
        assert_eq!(tx.seal(&ip), Err(Error::SequenceExhausted));
    }

    #[test]
    fn ip_versions_sizes_and_sa_spi() {
        assert!(OutboundSa::new(0, keys(), SystemCrypto).is_err());
        assert!(InboundSa::new(0, keys(), SystemCrypto).is_err());
        let mut tx = OutboundSa::new(1, keys(), SystemCrypto).unwrap();
        let mut v6 = vec![0; 40];
        v6[0] = 0x60;
        let mut rx = InboundSa::new(1, keys(), SystemCrypto).unwrap();
        assert_eq!(rx.open(&tx.seal(&v6).unwrap()), Ok(v6.clone()));
        v6[5] = 1;
        assert_eq!(tx.seal(&v6), Err(Error::InvalidPacket));
        let mut v4 = hex(IP4);
        v4[0] = 0x44;
        assert_eq!(tx.seal(&v4), Err(Error::InvalidPacket));
        let mut v4 = hex(IP4);
        v4[2] = 0;
        v4[3] = 19;
        assert_eq!(tx.seal(&v4), Err(Error::InvalidPacket));
    }

    #[derive(Clone)]
    struct FailAt(&'static str);
    impl Crypto for FailAt {
        fn random_iv(&self) -> Result<[u8; 16], Error> {
            if self.0 == "random" {
                Err(Error::CryptoFailure)
            } else {
                FixedIv.random_iv()
            }
        }
        fn cbc(
            &self,
            encrypt: bool,
            key: &[u8; 32],
            iv: &[u8; 16],
            input: &[u8],
        ) -> Result<Vec<u8>, Error> {
            if self.0 == "cbc" {
                Err(Error::CryptoFailure)
            } else {
                SystemCrypto.cbc(encrypt, key, iv, input)
            }
        }
        fn hmac_sha1(&self, key: &[u8; 20], input: &[u8]) -> Result<[u8; 20], Error> {
            if self.0 == "hmac" {
                Err(Error::CryptoFailure)
            } else {
                SystemCrypto.hmac_sha1(key, input)
            }
        }
    }

    #[test]
    fn cryptographic_failure_does_not_consume_sequence() {
        for stage in ["random", "cbc", "hmac"] {
            let mut tx = OutboundSa::new(0x12345678, keys(), FailAt(stage)).unwrap();
            assert_eq!(tx.seal(&hex(IP4)), Err(Error::CryptoFailure));
            assert_eq!(tx.next_sequence(), Some(1));
        }
    }
}
