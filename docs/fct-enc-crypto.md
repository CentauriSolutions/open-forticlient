# FortiClient `Enc ` string crypto (reverse engineering)

Historical Fortinet-backed analysis; the current client is described in
[architecture.md](architecture.md). The referenced controller source is in Git
commit `b9ade25`.

Goal: decrypt vpn.plist `AuthInfo` (and the `psk "Enc …"` in iked.conf) locally,
so `oftc` can obtain the plaintext pre-shared key without an operator pasting it.

**Status: DONE.** Fully reverse-engineered, validated against a known plaintext
(the decrypted `AuthInfo` matches the real PSK, and the derived magic + HMAC both
check out), and implemented in `app/migration/fctcrypt.rs` (`decrypt_enc`). Current
OFTC uses it only for an explicit one-time profile import into Keychain.

## The big result: it is device-independent

The `Enc ` scheme uses a **hardcoded key baked into the binary**, not `local.key`,
not the machine UID, not the Keychain:

```
fc_1A2Brown3Fox4Jumped5Over6A7Lazy8Dog
```

(iked `__TEXT,__cstring` @ `0x1004bc6d8`, immediately after the `"Enc "` literal
@ `0x1004bc6d3`.) So the same plaintext encrypts to the same `Enc …` on every
machine, and decryption needs **no root, no Keychain prompt, no per-device key**.
`ipsec/private/local.key` (root-only) is the IKE **cert** key, unrelated.

## Call graph (in iked; the same code is in fctctld)

```
_enc_dec_str(in, out)
  strncmp(in, "Enc ")                     # detect the prefix
  _hex2bin(hexpart) -> blob               # the part after "Enc " is hex
  _decrypt_buffer(blob, key="fc_1A2Brown…3Fox4Jumped5Over6A7Lazy8Dog")
    -> _do_encrypt_decrypt_buffer(..., decrypt=1)
         parse container (below)
         _fcrypt_init(cat, key, keylen=38, salt, ctx)
             _derive_key(key, keylen, salt, dklen, iters=0x3e8=1000, out)  # PBKDF2-HMAC-SHA1
             _aes_set_encrypt_key(derived, keybits, ctx+0x20)              # AES
             _hmac_sha1_begin/_key(derived_tail, ctx+0x128)               # MAC key
         _fcrypt_decrypt(ct, len, ctx)
             _hmac_sha1_data(ct)           # MAC covers the ciphertext
             _encr_data(ct, len, ctx)      # AES-CTR: AES_ECB(counter)⊕data
         _fcrypt_end(ctx) -> 10-byte HMAC-SHA1 tag
```

Primitives are standard (confirmed by the symbol stubs): `_derive_key` loops
HMAC-SHA1 1000× with a big-endian block counter (textbook **PBKDF2-HMAC-SHA1**),
`_encr_data` increments a 16-byte counter and `_aes_encrypt_block`s it then XORs
(**AES-CTR**), and the tag is **HMAC-SHA1 truncated to 10 bytes**.

## Container layout (what the blob is) — the byte order is salt-first

```
[salt][2-byte magic][ciphertext][10-byte HMAC-SHA1]
```

(The encrypt path writes the PRNG salt at the front, then the 2-byte magic, then
the ciphertext, then the 10-byte tag.) `magic` is *derived* from PBKDF2(key,salt)
and re-checked on decrypt, so it is not a fixed constant. `ct` length == plaintext
length (CTR is a stream). For our 43-byte PSK the 68-byte `AuthInfo` blob is
`salt(12) + magic(2) + ct(43) + mac(10) = 67`… note the ciphertext is actually 44
here because the stored plaintext is 44 bytes; the first 43 are the PSK.

## Exact parameters (validated)

`cat` is chosen from the key length (iked `_do_encrypt_decrypt_buffer`): keylen
`<8`→error, `8..31`→1, `32..47`→2, `48..128`→3. The hardcoded KEY is 38 bytes →
**cat = 2**, giving:

| quantity | formula (cat) | cat=2 value |
|---|---|---|
| salt length | `4 + 4·cat` | 12 bytes |
| AES key bytes | `8 + 8·cat` | 24 → **AES-192** |
| derived length | `2·aeslen + 2` | 50 bytes |

`D = PBKDF2-HMAC-SHA1(KEY, salt, iters=1000, dkLen=50)`, then:

- AES key   = `D[0 .. 24]`
- HMAC key  = `D[24 .. 48]`
- magic     = `D[48 .. 50]`  (must equal the blob's 2 magic bytes)
- cipher    = **AES-192-CTR**, 16-byte counter block = `u64_LE(counter) ‖ 8 zero`,
  counter starts at 0 and is **incremented before each block** (so blocks use
  counter = 1, 2, 3, …), keystream ⊕ ciphertext.
- MAC       = `HMAC-SHA1(HMAC_key, ciphertext)[0 .. 10]` (verified on decrypt).

Addresses (thinned x86_64 iked, all resolvable by name in `otool -tV`):
`_enc_dec_str`, `_do_encrypt_decrypt_buffer`, `_fcrypt_init`, `_derive_key`,
`_encr_data`, `_fcrypt_end`.

## Implementation

`b9ade25:client/src/fctcrypt.rs` implements SHA-1 / HMAC-SHA1 / PBKDF2-HMAC-SHA1 in pure
Rust (RFC test vectors in-module) and shells `openssl enc -aes-192-ecb` for the
CTR keystream (consistent with `tls.rs`). `profile.rs` calls `decrypt_enc` on the
profile's `AuthInfo` whenever no `$FORTIGATE_PSK`/`.env`/`~/.config/oftc/psk`
override is set, so a configured machine needs **zero** PSK setup. The override
path remains as an escape hatch.
