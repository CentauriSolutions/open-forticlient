#include "crypto.h"

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdio.h>
#include <string.h>

static int nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex(const char *source, uint8_t *dest, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        int hi = nibble(source[2 * i]), lo = nibble(source[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        dest[i] = (uint8_t)((hi << 4) | lo);
    }
    return source[2 * length] == '\0' ? 0 : -1;
}

static int equal_hex(const uint8_t *actual, const char *expected, size_t length) {
    uint8_t bytes[128];
    return length <= sizeof(bytes) && hex(expected, bytes, length) == 0 &&
           memcmp(actual, bytes, length) == 0;
}

static int test_cbc(void) {
    uint8_t key[32], iv[16], plain[64], want[64], encrypted[64], decrypted[64];
    if (hex("603deb1015ca71be2b73aef0857d7781"
            "1f352c073b6108d72d9810a30914dff4", key, sizeof(key)) ||
        hex("000102030405060708090a0b0c0d0e0f", iv, sizeof(iv)) ||
        hex("6bc1bee22e409f96e93d7e117393172a"
            "ae2d8a571e03ac9c9eb76fac45af8e51"
            "30c81c46a35ce411e5fbc1191a0a52ef"
            "f69f2445df4f9b17ad2b417be66c3710", plain, sizeof(plain)) ||
        hex("f58c4c04d6e5f1ba779eabfb5f7bfbd6"
            "9cfc4e967edb808d679f777bc6702c7d"
            "39f23369a9d9bacfa530e26304231461"
            "b2eb05e2c39be9fcda6c19078c6a9d1b", want, sizeof(want))) return -1;
    if (oftc_aes256_cbc(1, key, 32, iv, 16, plain, 64, encrypted, 64) ||
        memcmp(encrypted, want, 64) ||
        oftc_aes256_cbc(0, key, 32, iv, 16, encrypted, 64, decrypted, 64) ||
        memcmp(decrypted, plain, 64)) return -1;
    // A caller cannot accidentally request PKCS#7 padding or a short buffer.
    if (oftc_aes256_cbc(1, key, 32, iv, 16, plain, 63, encrypted, 64) != -1 ||
        oftc_aes256_cbc(1, key, 32, iv, 16, plain, 64, encrypted, 63) != -1 ||
        oftc_aes256_cbc(1, key, 31, iv, 16, plain, 64, encrypted, 64) != -1)
        return -1;
    return 0;
}

static int test_hmac(void) {
    uint8_t key[20], sha1[20], sha256[32];
    memset(key, 0x0b, sizeof(key));
    const uint8_t message[] = "Hi There";
    if (oftc_hmac(0, key, sizeof(key), message, 8, sha1, sizeof(sha1)) ||
        !equal_hex(sha1, "b617318655057264e28bc0b6fb378c8ef146be00", 20) ||
        oftc_hmac(1, key, sizeof(key), message, 8, sha256, sizeof(sha256)) ||
        !equal_hex(sha256,
                   "b0344c61d8db38535ca8afceaf0bf12b"
                   "881dc200c9833da726e9376c2e32cff7", 32)) return -1;
    if (oftc_hmac(1, key, 20, message, 8, sha256, 20) != -1 ||
        oftc_hmac(2, key, 20, message, 8, sha256, 32) != -1)
        return -1;
    return 0;
}

static int test_random(void) {
    uint8_t a[32] = {0}, b[32] = {0}, zero[32] = {0};
    if (oftc_random(a, sizeof(a)) || oftc_random(b, sizeof(b)) ||
        memcmp(a, b, sizeof(a)) == 0 || memcmp(a, zero, sizeof(a)) == 0 ||
        oftc_random(NULL, sizeof(a)) != -1 || oftc_random(a, 0) != -1)
        return -1;
    return 0;
}

// RFC 5903 section 8.2: construct Apple's 04 || X || Y || K private format
// from the published group-20 public point and private scalar.
static SecKeyRef rfc_private_key(const uint8_t public_xy[96],
                                 const uint8_t scalar[48]) {
    uint8_t x963[145];
    x963[0] = 4;
    memcpy(x963 + 1, public_xy, 96);
    memcpy(x963 + 97, scalar, 48);
    CFDataRef bytes = CFDataCreate(kCFAllocatorDefault, x963, sizeof(x963));
    const void *keys[] = {kSecAttrKeyType, kSecAttrKeyClass};
    const void *values[] = {kSecAttrKeyTypeECSECPrimeRandom,
                            kSecAttrKeyClassPrivate};
    CFDictionaryRef attrs = CFDictionaryCreate(
        kCFAllocatorDefault, keys, values, 2, &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    if (!bytes || !attrs) {
        if (bytes) CFRelease(bytes);
        if (attrs) CFRelease(attrs);
        return NULL;
    }
    CFErrorRef error = NULL;
    SecKeyRef key = SecKeyCreateWithData(bytes, attrs, &error);
    CFRelease(bytes);
    CFRelease(attrs);
    if (error) {
        CFShow(error);
        CFRelease(error);
    }
    return key;
}

static int test_group20_vector(void) {
    uint8_t initiator[96], responder[96], private_scalar[48], want[48];
    if (hex("667842d7d180ac2cde6f74f37551f55755c7645c20ef73e31634fe72b4c55ee6"
            "de3ac808acb4bdb4c88732aee95f41aa"
            "9482ed1fc0eeb9cafc4984625ccfc23f65032149e0e144ada024181535a0f38e"
            "eb9fcff3c2c947dae69b4c634573a81c", initiator, 96) ||
        hex("e558dbef53eecde3d3fccfc1aea08a89a987475d12fd950d83cfa41732bc509d"
            "0d1ac43a0336def96fda41d0774a3571"
            "dcfbec7aacf3196472169e838430367f66eebe3c6e70c416dd5f0c68759dd1ff"
            "f83fa40142209dff5eaad96db9e6386c", responder, 96) ||
        hex("099f3c7034d4a2c699884d73a375a67f7624ef7c6b3c0f160647b67414dce655"
            "e35b538041e649ee3faef896783ab194", private_scalar, 48) ||
        hex("11187331c279962d93d604243fd592cb9d0a926f422e47187521287e7156c5c4"
            "d603135569b9e9d09cf5d4a270f59746", want, 48)) return -1;
    SecKeyRef rfc_key = rfc_private_key(initiator, private_scalar);
    if (!rfc_key) {
        fprintf(stderr, "RFC private key import failed\n");
        return -1;
    }
    uint8_t secret[48];
    int result = oftc_group20_shared(rfc_key, responder, 96, secret, 48);
    if (result || memcmp(secret, want, 48)) {
        fprintf(stderr, "RFC shared secret mismatch or API status %d\n", result);
        result = -1;
    }
    uint8_t malformed[96] = {0};
    if (oftc_group20_shared(rfc_key, responder, 95, secret, 48) != -1 ||
        oftc_group20_shared(rfc_key, responder, 96, secret, 47) != -1 ||
        oftc_group20_shared(rfc_key, malformed, 96, secret, 48) != -2)
        { fprintf(stderr, "Group-20 invalid-input handling failed\n"); result = -1; }
    CFRelease(rfc_key);
    return result;
}

static int test_group20_ephemeral(void) {
    void *a = NULL, *b = NULL;
    uint8_t pub_a[96] = {0}, pub_b[96] = {0}, ab[48] = {0}, ba[48] = {0};
    int result = 0;
    int ga = oftc_group20_generate(&a, pub_a);
    int gb = oftc_group20_generate(&b, pub_b);
    int sab = ga || gb ? -9 : oftc_group20_shared(a, pub_b, 96, ab, 48);
    int sba = ga || gb ? -9 : oftc_group20_shared(b, pub_a, 96, ba, 48);
    if (ga || gb || sab || sba || memcmp(ab, ba, 48)) {
        fprintf(stderr, "Ephemeral group-20 exchange failed (%d %d %d %d)\n",
                ga, gb, sab, sba);
        result = -1;
    }
    oftc_group20_free(a);
    oftc_group20_free(b);
    return result;
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--ephemeral") == 0) {
        int result = test_group20_ephemeral();
        if (result) fprintf(stderr, "FAIL: Security ephemeral key generation\n");
        else puts("PASS: Security ephemeral key generation");
        return result ? 1 : 0;
    }
    if (argc != 1) return 2;
    const struct { const char *name; int (*run)(void); } cases[] = {
        {"RFC 5903 group-20 ECDH and wire encoding", test_group20_vector},
        {"NIST SP 800-38A AES-256-CBC without padding", test_cbc},
        {"RFC 2202/4231 HMAC-SHA1/SHA256", test_hmac},
        {"Security framework random bytes", test_random},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        if (cases[i].run()) {
            fprintf(stderr, "FAIL: %s\n", cases[i].name);
            return 1;
        }
        printf("PASS: %s\n", cases[i].name);
    }
    return 0;
}
