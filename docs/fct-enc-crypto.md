# FortiClient `Enc ` string crypto (reverse engineering)

Goal: decrypt vpn.plist `AuthInfo` (and the `psk "Enc …"` in iked.conf) locally,
so `oftc` can obtain the plaintext pre-shared key without an operator pasting it.

**Status: algorithm identified; NOT yet reproduced bit-exactly.** Two
known-plaintext validation sweeps did not converge, so the exact byte layout in
`_derive_key`/`_fcrypt_init` still needs register-level tracing before a working
implementation.

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

## Container layout (what the 68-byte `AuthInfo` blob is)

```
[2-byte magic][salt][ciphertext][10-byte HMAC-SHA1]
```

- `magic` is *derived* from PBKDF2(key, salt) and re-checked on decrypt (format/
  integrity gate), so it is not a fixed constant.
- `ct` length == plaintext length (CTR is a stream), so for our 43-byte PSK:
  `2 + salt(13) + ct(43) + 10 = 68`.
- The AES key, the CTR counter seed, the HMAC key, and the magic are all carved
  out of the PBKDF2 output (`_derive_key` → one buffer, sliced in `_fcrypt_init`).

## What still needs pinning (the open RE)

Two sweeps over `{saltlen, AES-128/256, derive-offset, counter-start/endianness,
pre-increment}` vs the known plaintext did **not** match, so at least one of these
differs from the textbook guess and must be read from the asm exactly:

1. `_derive_key` dklen and whether the salt is passed verbatim or formatted.
2. The slice offsets in `_fcrypt_init` (AES key vs CTR seed vs HMAC key vs magic)
   and the AES key size (the `8 + 8·cat` / `4 + 4·cat` sizing from `cat`).
3. The exact CTR counter init + increment (the code forces a regen on the first
   byte via `ctx+0x1c8 = 0x10`, incrementing the low 8 bytes little-endian).

Addresses (thinned x86_64 iked): `_enc_dec_str`, `_do_encrypt_decrypt_buffer`,
`_fcrypt_init`, `_derive_key`, `_encr_data`, `_fcrypt_end` — all resolvable by
name in `otool -tV`.

## Implementation note (when reproduced)

Decryption is `PBKDF2-HMAC-SHA1 → AES-CTR ⊕ → verify HMAC-SHA1/10`. A std-only
build has none of these; options are the RustCrypto crates (`pbkdf2`, `hmac`,
`sha1`, `aes`, `ctr`) — clean but breaks the zero-dependency goal — or shelling
to `openssl`. Wire the result into `oftc install`: decrypt `AuthInfo` once, write
the plaintext to `~/.config/oftc/psk` (0600). Fragile across FortiClient releases
(the salt/KDF/key could change), so keep the `$FORTIGATE_PSK` path as a fallback.
