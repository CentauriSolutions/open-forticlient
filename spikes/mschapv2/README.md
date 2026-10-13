# EAP-MSCHAPv2 peer module (offline Gate 3 component)

`mschapv2.rs` implements the observed type-26/opcode-1 method without a crate
dependency. It uses macOS CommonCrypto for MD4, SHA-1, and DES-ECB, and
`getentropy` for the 16-byte peer challenge. The Rust code implements packet
layout, DES key parity, and RFC key derivation. No SSO, gateway, VPN, or token
is used by its tests.

Run `sh spikes/mschapv2/run.sh`. Seven tests pass, including RFC 2759's
`User`/`clientPass` challenge, NT response, authenticator response, and DES
key, plus RFC 3079's MPPE send-key vector. Malformed lengths, a wrong
authenticator response, failure metadata, and domain stripping are covered.

## Gate 3 handoff

Include `#[path = "../mschapv2/mschapv2.rs"] mod mschapv2;` from the IKE_AUTH
probe (adjust relative path), then:

1. After decrypting and integrity-checking the gateway's EAP Challenge, call
   `parse_challenge(eap_bytes) -> Challenge`.
2. Call `respond(&challenge, bootstrap_uid, tokenid) -> Prepared`. Send
   `prepared.eap_response` as the next encrypted EAP payload. `respond()`
   creates a fresh random peer challenge. **Use the same bootstrap UID that
   was sent as EAP Identity.** Existing Fortinet CONNECT passes that UID as
   its EAP username with tokenid as password; the SAML callback `username`
   is a separate value and is not passed to `iked` through CONNECT.
3. On a gateway inner EAP-MSCHAPv2 Success Request, call
   `prepared.verify_success(eap_bytes) -> Verified`. This checks the 40-digit
   server authenticator in constant time and the MSCHAP ID. On failure it
   exposes neither acknowledgement nor MSK. On success, send
   `verified.success_ack` (6 bytes) as the encrypted EAP Success Response.
4. Wait for the outer EAP Success, then pass the complete `verified.msk()`
   (64 bytes) into IKEv2's final AUTH computation. Its layout is peer
   send/server receive key (16) | peer receive/server send key (16) |
   zero padding (32). Do not log it.
5. If the gateway sends an inner Failure Request, `parse_failure()` returns
   only the E/R fields and `Failure::acknowledgement()` can finish a
   non-retryable method failure. Do not silently retry with a single-use token.

The `tokenid` argument is the **exact decoded callback text**, passed as
`&str`; the module converts it to UTF-16LE (without a terminator) for the NT
password hash. It accepts at most 256 UTF-16 code units. The UID/Name must be
nonempty ASCII of at most 256 bytes. The caller owns its token string and must
wipe it; `Prepared` and `Verified` redact `Debug` and wipe internal credential
material on drop. The EAP response itself contains an NT response and must not
be logged or persisted. The module does not handle retries, IKE transcript
authentication, outer EAP Success, or client AUTH. Those remain with the
IKE_AUTH state machine.

## Build impact

On this arm64 Mac, an optimized `rustc --crate-type rlib` build took **0.18 s**
and produced an approximately **115 KB** rlib. A stripped release harness that retains
all public method paths grew from **432,784** to **450,720 bytes** (+17,936
bytes) compared with a tiny `std::env::args` baseline. This is an estimate
of incremental method code, not a measurement of the final `oftc` binary.
No new runtime dylib or package dependency was introduced.

Sources: [RFC 2759 sections 4, 8, 9](https://www.rfc-editor.org/rfc/rfc2759.html),
[RFC 3079 sections 3.3-3.5](https://www.rfc-editor.org/rfc/rfc3079.html),
[Microsoft EAP-MSCHAPv2 wire syntax](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-chap/6cdfa42c-173a-4780-80e1-8872abdeaa30),
[Microsoft MSK derivation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-chap/5a860bf5-2aeb-485b-82ee-fac1e8e6b76f),
and [strongSwan's EAP-MSCHAPv2 MSK export](https://github.com/strongswan/strongswan/blob/master/src/libcharon/plugins/eap_mschapv2/eap_mschapv2.c).
