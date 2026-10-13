#include "crypto.h"

#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonHMAC.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <string.h>

enum { EC_BYTES = 48, EC_PUBLIC_BYTES = 1 + 2 * EC_BYTES };

static CFDictionaryRef ec_attributes(CFTypeRef key_class) {
    const void *keys[] = {kSecAttrKeyType, kSecAttrKeyClass};
    const void *values[] = {kSecAttrKeyTypeECSECPrimeRandom, key_class};
    return CFDictionaryCreate(kCFAllocatorDefault, keys, values, 2,
                              &kCFTypeDictionaryKeyCallBacks,
                              &kCFTypeDictionaryValueCallBacks);
}

static int export_group20_public(SecKeyRef key, uint8_t output[96]) {
    int result = -2;
    CFErrorRef error = NULL;
    SecKeyRef public_key = SecKeyCopyPublicKey(key);
    if (!public_key) return result;
    CFDataRef bytes = SecKeyCopyExternalRepresentation(public_key, &error);
    if (bytes && CFDataGetLength(bytes) == EC_PUBLIC_BYTES &&
        CFDataGetBytePtr(bytes)[0] == 4) {
        memcpy(output, CFDataGetBytePtr(bytes) + 1, 96);
        result = 0;
    }
    if (bytes) CFRelease(bytes);
    if (error) CFRelease(error);
    CFRelease(public_key);
    return result;
}

int oftc_group20_generate(void **key_out, uint8_t public_out[96]) {
    if (!key_out || !public_out) return -1;
    *key_out = NULL;
    int bits = 384;
    CFNumberRef size = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &bits);
    if (!size) return -2;
    const void *keys[] = {kSecAttrKeyType, kSecAttrKeySizeInBits};
    const void *values[] = {kSecAttrKeyTypeECSECPrimeRandom, size};
    CFDictionaryRef attributes = CFDictionaryCreate(
        kCFAllocatorDefault, keys, values, 2, &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    CFRelease(size);
    if (!attributes) return -2;
    CFErrorRef error = NULL;
    SecKeyRef key = SecKeyCreateRandomKey(attributes, &error);
    CFRelease(attributes);
    if (error) CFRelease(error);
    if (!key) return -2;
    int result = export_group20_public(key, public_out);
    if (result == 0) *key_out = key;
    else CFRelease(key);
    return result;
}

int oftc_group20_shared(void *key, const uint8_t *peer, size_t peer_len,
                        uint8_t *secret_out, size_t secret_len) {
    if (!key || !peer || !secret_out || peer_len != 96 || secret_len != 48)
        return -1;
    uint8_t x963[EC_PUBLIC_BYTES];
    x963[0] = 4;
    memcpy(x963 + 1, peer, 96);
    CFDataRef bytes = CFDataCreate(kCFAllocatorDefault, x963, sizeof(x963));
    CFDictionaryRef attrs = ec_attributes(kSecAttrKeyClassPublic);
    if (!bytes || !attrs) {
        if (bytes) CFRelease(bytes);
        if (attrs) CFRelease(attrs);
        return -2;
    }
    CFErrorRef error = NULL;
    SecKeyRef peer_key = SecKeyCreateWithData(bytes, attrs, &error);
    CFRelease(bytes);
    CFRelease(attrs);
    if (error) { CFRelease(error); error = NULL; }
    if (!peer_key) return -2;
    CFDictionaryRef parameters = CFDictionaryCreate(
        kCFAllocatorDefault, NULL, NULL, 0, &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    CFDataRef secret = parameters ? SecKeyCopyKeyExchangeResult(
        (SecKeyRef)key, kSecKeyAlgorithmECDHKeyExchangeStandard, peer_key,
        parameters, &error) : NULL;
    if (parameters) CFRelease(parameters);
    int result = -2;
    if (secret && CFDataGetLength(secret) == EC_BYTES) {
        memcpy(secret_out, CFDataGetBytePtr(secret), EC_BYTES);
        result = 0;
    }
    if (secret) CFRelease(secret);
    if (error) CFRelease(error);
    CFRelease(peer_key);
    return result;
}

void oftc_group20_free(void *key) {
    if (key) CFRelease((SecKeyRef)key);
}

int oftc_aes256_cbc(int encrypt, const uint8_t *key, size_t key_len,
                    const uint8_t *iv, size_t iv_len, const uint8_t *input,
                    size_t input_len, uint8_t *output, size_t output_len) {
    if ((encrypt != 0 && encrypt != 1) || !key || !iv || !input || !output ||
        key_len != kCCKeySizeAES256 || iv_len != kCCBlockSizeAES128 ||
        input_len == 0 || input_len % kCCBlockSizeAES128 != 0 ||
        output_len < input_len) return -1;
    size_t moved = 0;
    CCCryptorStatus status = CCCrypt(
        encrypt ? kCCEncrypt : kCCDecrypt, kCCAlgorithmAES, 0, key, key_len,
        iv, input, input_len, output, output_len, &moved);
    return status == kCCSuccess && moved == input_len ? 0 : -2;
}

int oftc_hmac(int sha256, const uint8_t *key, size_t key_len,
              const uint8_t *input, size_t input_len, uint8_t *digest,
              size_t digest_len) {
    if ((sha256 != 0 && sha256 != 1) || !key || !input || !digest ||
        digest_len != (size_t)(sha256 ? CC_SHA256_DIGEST_LENGTH :
                                        CC_SHA1_DIGEST_LENGTH)) return -1;
    CCHmac(sha256 ? kCCHmacAlgSHA256 : kCCHmacAlgSHA1, key, key_len, input,
           input_len, digest);
    return 0;
}

int oftc_random(uint8_t *output, size_t output_len) {
    if (!output || output_len == 0) return -1;
    return SecRandomCopyBytes(kSecRandomDefault, output_len, output) ==
                   errSecSuccess ? 0 : -2;
}
