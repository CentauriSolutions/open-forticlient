//! Decrypt FortiClient `Enc …` strings (vpn.plist `AuthInfo`, iked.conf psk).
//!
//! Reverse-engineered from iked (`_enc_dec_str` → `_fcrypt_init`/`_derive_key`/
//! `_encr_data`), see docs/fct-enc-crypto.md. The scheme is device-INDEPENDENT:
//! a key hardcoded in the binary, so this works on any machine with no root,
//! no Keychain, no per-device material. That lets us recover the plaintext
//! pre-shared key straight from the installed profile.
//!
//! Format: `Enc <hex>` where the bytes are `[salt][magic(2)][ciphertext][mac(10)]`:
//!   - `D   = PBKDF2-HMAC-SHA1(KEY, salt, 1000, 2*aeslen+2)`
//!   - AES key = `D[0..aeslen]`, HMAC key = `D[aeslen..2*aeslen]`, magic = `D[2*aeslen..+2]`
//!   - cipher  = AES-CTR (LE 64-bit counter from 1), MAC = `HMAC-SHA1(hmackey, ct)[..10]`
//!   - `cat` (from the key length) fixes the sizes; the hardcoded KEY is 38 bytes → cat 2
//!     → 12-byte salt, AES-192. We shell `openssl` for AES-ECB (as tls.rs does).

use std::process::{Command, Stdio};

/// The key baked into FortiClient's binaries (iked `__cstring` @0x1004bc6d8).
const KEY: &[u8] = b"fc_1A2Brown3Fox4Jumped5Over6A7Lazy8Dog";
const ITERS: u32 = 1000;

/// Decrypt an `Enc <hex>` string to its plaintext, or None if it is not an
/// `Enc ` value, is malformed, or the MAC/magic check fails.
pub fn decrypt_enc(s: &str) -> Option<String> {
    let hex = s.strip_prefix("Enc ")?;
    let blob = hex_decode(hex.trim())?;

    // sizes from `cat`, derived from the (fixed) key length — see _fcrypt_init.
    let cat = cat_for(KEY.len())?;
    let saltlen = (4 + 4 * cat) as usize;
    let aeslen = (8 + 8 * cat) as usize; // AES key bytes: 16/24/32
    let dklen = 2 * aeslen + 2;
    if blob.len() < saltlen + 2 + 10 {
        return None;
    }
    let salt = &blob[..saltlen];
    let magic = &blob[saltlen..saltlen + 2];
    let ct = &blob[saltlen + 2..blob.len() - 10];
    let mac = &blob[blob.len() - 10..];

    let d = pbkdf2_sha1(KEY, salt, ITERS, dklen);
    let aes_key = &d[..aeslen];
    let hmac_key = &d[aeslen..2 * aeslen];
    let derived_magic = &d[2 * aeslen..2 * aeslen + 2];

    // Integrity: the derived magic and the HMAC must match before we trust it.
    if derived_magic != magic {
        return None;
    }
    if &hmac_sha1(hmac_key, ct)[..10] != mac {
        return None;
    }

    // AES-CTR: keystream = AES-ECB(key, counter_block) for counter = 1,2,3,…
    // counter block = u64 LE counter || 8 zero bytes.
    let nblocks = ct.len().div_ceil(16);
    let mut counters = Vec::with_capacity(nblocks * 16);
    for i in 1..=nblocks as u64 {
        counters.extend_from_slice(&i.to_le_bytes());
        counters.extend_from_slice(&[0u8; 8]);
    }
    let keystream = openssl_aes_ecb_encrypt(aes_key, &counters)?;
    let pt: Vec<u8> = ct.iter().zip(&keystream).map(|(c, k)| c ^ k).collect();
    String::from_utf8(pt).ok()
}

/// `cat` selects the salt/key sizes, keyed off the password length (see the
/// thresholds in iked's `_do_encrypt_decrypt_buffer`).
fn cat_for(keylen: usize) -> Option<u32> {
    match keylen {
        0..=7 => None,
        8..=31 => Some(1),
        32..=47 => Some(2),
        48..=128 => Some(3),
        _ => None,
    }
}

// ───────────────────────── AES via openssl ──────────────────────────────────

fn openssl_aes_ecb_encrypt(key: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    use std::io::Write;
    let cipher = format!("-aes-{}-ecb", key.len() * 8);
    let mut child = Command::new("openssl")
        .args(["enc", "-e", &cipher, "-K", &hex_encode(key), "-nopad"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    child.stdin.take()?.write_all(data).ok()?;
    let out = child.wait_with_output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(out.stdout)
}

// ───────────────────────── SHA-1 / HMAC / PBKDF2 ─────────────────────────────

fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let ml = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&ml.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 80];
        for (i, word) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let tmp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    let mut out = [0u8; 20];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

fn hmac_sha1(key: &[u8], msg: &[u8]) -> [u8; 20] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..20].copy_from_slice(&sha1(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Vec::with_capacity(64 + msg.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(msg);
    let ih = sha1(&inner);
    let mut outer = Vec::with_capacity(84);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&ih);
    sha1(&outer)
}

fn pbkdf2_sha1(pw: &[u8], salt: &[u8], iters: u32, dklen: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(dklen);
    let mut block = 1u32;
    while out.len() < dklen {
        // U1 = HMAC(pw, salt || INT_32_BE(block))
        let mut salted = salt.to_vec();
        salted.extend_from_slice(&block.to_be_bytes());
        let mut u = hmac_sha1(pw, &salted);
        let mut t = u;
        for _ in 1..iters {
            u = hmac_sha1(pw, &u);
            for i in 0..20 {
                t[i] ^= u[i];
            }
        }
        out.extend_from_slice(&t);
        block += 1;
    }
    out.truncate(dklen);
    out
}

// ───────────────────────── hex helpers ──────────────────────────────────────

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha1_rfc() {
        assert_eq!(
            hex_encode(&sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex_encode(&sha1(b"")),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
    }

    #[test]
    fn hmac_sha1_rfc2202() {
        // RFC 2202 test case 2
        assert_eq!(
            hex_encode(&hmac_sha1(b"Jefe", b"what do ya want for nothing?")),
            "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
        );
    }

    #[test]
    fn pbkdf2_sha1_rfc6070() {
        // RFC 6070: P="password", S="salt", c=1, dkLen=20
        assert_eq!(
            hex_encode(&pbkdf2_sha1(b"password", b"salt", 1, 20)),
            "0c60c80f961f0e71f3a9b524af6012062fe037a6"
        );
        // c=2
        assert_eq!(
            hex_encode(&pbkdf2_sha1(b"password", b"salt", 2, 20)),
            "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"
        );
    }
}
