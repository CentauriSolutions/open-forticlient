#ifndef OFTC_SPIKE_CRYPTO_H
#define OFTC_SPIKE_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

// Group 20 public value is X || Y (48 bytes each); shared value is X (48 bytes).
// The opaque key is process-local and must be released with oftc_group20_free.
int oftc_group20_generate(void **key_out, uint8_t public_out[96]);
int oftc_group20_shared(void *key, const uint8_t *peer, size_t peer_len,
                        uint8_t *secret_out, size_t secret_len);
void oftc_group20_free(void *key);

// Input must already include IKE/ESP padding and be a multiple of 16 bytes.
// No PKCS#7 padding is added or removed. encrypt=1; decrypt=0.
int oftc_aes256_cbc(int encrypt, const uint8_t *key, size_t key_len,
                    const uint8_t *iv, size_t iv_len, const uint8_t *input,
                    size_t input_len, uint8_t *output, size_t output_len);

// digest_len is 20 for SHA-1 and 32 for SHA-256. The caller decides any
// protocol-specific truncation after validating the full digest.
int oftc_hmac(int sha256, const uint8_t *key, size_t key_len,
              const uint8_t *input, size_t input_len, uint8_t *digest,
              size_t digest_len);
int oftc_random(uint8_t *output, size_t output_len);

#endif
