# Gate 1 crypto/build-cost probe

Run on macOS with Xcode Command Line Tools and Rust:

```sh
sh spikes/crypto/run.sh
```

This probes only public test data. It makes no VPN, SSO, gateway, or system
extension call. Outputs are ignored by this directory's `.gitignore`.

The C adapter is a comparison probe: Security for P-384 ECDH and random bytes,
CommonCrypto for AES-CBC and HMAC. The complete Rust FFI route uses **one Swift
adapter**: CryptoKit for P-384, CommonCrypto for AES-CBC and HMAC, and Security
for random bytes. `rust-test.rs` links only that Swift adapter. No crate is
added to `client/`.

Vectors: [RFC 5903 §8.2](https://datatracker.ietf.org/doc/html/rfc5903#section-8.2)
(group-20 public X||Y and shared X), [NIST SP 800-38A §F.2.5–6](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38a.pdf)
(AES-256-CBC), [RFC 2202 §3](https://datatracker.ietf.org/doc/html/rfc2202#section-3)
(HMAC-SHA1), and [RFC 4231 §4.2](https://datatracker.ietf.org/doc/html/rfc4231#section-4.2)
(HMAC-SHA256). The tests also reject malformed EC points, non-block CBC input,
short output buffers, and invalid lengths. CBC passes option `0` to CCCrypt,
so the caller must construct and validate IKE/ESP padding itself.

On this Mac, `SecKeyCreateWithData` correctly imports the RFC P-384 private
key and `SecKeyCopyKeyExchangeResult` returns the expected 48-byte X value.
However, `SecKeyCreateRandomKey` returns `NSOSStatusErrorDomain/-50` ("failed
to generate CDSA key") for both P-256 and P-384 ephemeral keys in this
execution environment. Reproduce the adapter failure with:

```sh
cd spikes/crypto
./crypto-test --ephemeral
```

The passing CryptoKit P-384 test includes ephemeral generation, matching
bidirectional shared secrets, and bad-point rejection. The Rust caller proves
that a narrow Swift C ABI can provide the observed suite to a Rust engine. The
Swift bridge adds a local `libcrypto_swift.dylib`; packaging/signing and a
stable ABI still need validation before use in an app or system extension.

## Build cost on the test Mac

macOS 27 arm64, Xcode clang/Swift, Rust 1.98.1, `-O`/`-O2`, macOS 11 minimum.
These are single local wall-clock samples, not stable performance benchmarks.
The script always recompiles; its second run is a **warm full rebuild**, not a
no-op incremental build.

| Probe artifact | Warm compile/link | File size |
| --- | ---: | ---: |
| C vector executable | 0.18 s | 52,600 B |
| Swift standalone executable | 1.60 s | 159,480 B |
| Complete Swift bridge dylib | 0.42 s | 88,376 B |
| Rust FFI caller (Swift bridge only; stripped) | 0.10 s | 342,464 B |

Full `run.sh`, including all builds and tests, took 3.27 s with a fresh Swift
module cache and 2.38 s with that cache warm. The combined Rust caller plus
local Swift dylib is 430,840 B before app packaging. The unchanged `client/`
crate, built into a separate temporary target directory, took 0.56 s for a
clean debug build and 0.02 s for a Cargo no-op build. A Rust-only edit can
therefore use its existing Cargo loop while the native bridge artifact is
reused; changes to the bridge require its separate compile and link step.

The C vector executable is a successful limited route, but Security's
ephemeral key-generation failure prevents recommending an all-C/Security
adapter here. One Swift adapter covers the observed suite with no third-party
crypto crates. The underscored `@_cdecl` export, library load path, signing,
minimum macOS version, and secret-copy/zeroization behavior need a production
review. No finding here establishes gateway acceptance or full IKE/ESP safety.

No protocol layer is present: PRF+, IKE AUTH, integrity-before-decryption,
protocol padding, ESP anti-replay, and rekey remain implementation work.
