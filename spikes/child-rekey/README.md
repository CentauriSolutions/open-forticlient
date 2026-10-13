# CHILD_SA rekey spike (offline)

Run `sh spikes/child-rekey/run.sh`. Twenty-one tests pass, including the imported
ESP tests. This spike makes no network connection and handles no SAML token.

## What the spike proves

- `rekey.rs` encodes the authenticated **inner** `CREATE_CHILD_SA` request as
  `N(REKEY_SA, ESP, old inbound SPI), SA(new inbound SPI, AES-256-CBC,
  HMAC-SHA1-96, group 14, no ESN), Ni, KEi, TSi, TSr`. It strictly parses the
  corresponding response and rejects missing PFS, changed selectors,
  malformed payloads, and unexpected suite changes. The ESP registry rejects
  reuse of a local inbound SPI and keeps 0–255 reserved; matching numeric
  values across directions are legal under RFC 4303 §2.1.
- `ephemeral.rs` generates a fresh 32-byte nonce, ESP SPI, and RFC 3526
  group-14 MODP key pair using SecRandomCopyBytes and the fixed-width
  `spikes/modp14` crate. The private exponent is wiped on drop. An
  independent Python modular-exponentiation vector verifies public and shared
  values, and two independently generated key pairs agree on a shared secret.
- Key derivation includes the **fresh** 256-byte MODP secret before Ni and Nr in
  `prf+(SK_d, g^ir | Ni | Nr)`. A fixed 104-byte key-material vector matches
  independent Python `hmac` output. The ephemeral secret and intermediate
  buffers are cleared on success or error.
- `overlap.rs` authenticates old and new inbound ESP SPIs concurrently with
  distinct anti-replay windows. Old inbound ESP stops only after an explicit
  authenticated DELETE or bounded expiry. A failed response/installation
  leaves the old outbound/inbound pair intact.
- Simultaneous rekey resolution chooses the new SA pair containing the lowest
  of four nonces for deletion, using octetwise comparison. A nonce tie is
  flagged instead of deleting either SA blindly.

The current local rekey offer is IPv4 inner traffic with AES-256-CBC,
HMAC-SHA1-96, no ESN, and MODP-2048/group 14 PFS. The initial CHILD_SA from
IKE_AUTH uses the IKE_SA_INIT nonces and no new DH secret; this module is only
for **subsequent** CHILD_SA rekeys.

## Concrete integration sequence

1. Schedule a jittered soft lifetime sufficiently before the hard lifetime or
   ESP sequence exhaustion. The current client must fail closed at the hard
   limit if rekey cannot finish. Keep one request outstanding per IKE SA unless
   the peer negotiated a larger message window.
2. Create `Ephemeral`, encode the request, then seal it as IKE exchange type
   `CREATE_CHILD_SA` (36) under the established IKE keys and next local
   message ID. Cache the sealed request for byte-identical retransmission.
   UDP/4500 and TCP/4443 use the same inner exchange with their existing outer
   framing.
3. Verify responder SPI, SK integrity, response flag, exchange type, and
   message ID **before** passing the decrypted inner payloads to
   `parse_response`. Reject a missing/invalid group-14 KE and failed public-value
   validation. Derive new ESP keys, install the new inbound SA and independent
   replay window, then atomically select the new outbound SA and sequence 1.
   Keep the old inbound SA available during the response/DELETE handover.
4. Send an authenticated INFORMATIONAL DELETE naming the **old local inbound
   ESP SPI**, retrying according to the existing IKE lifecycle. The peer's
   DELETE uses its inbound SPI. Do not remove old inbound state until the
   exchange completes or a bounded grace expires. Handle an authenticated
   peer-initiated rekey with the same overlap and nonce-collision rules.
5. On a failed rekey, retain the old pair while it is valid; retry with bounded
   backoff or reconnect before the hard lifetime. `NO_PROPOSAL_CHOSEN`,
   `INVALID_KE_PAYLOAD`, `TEMPORARY_FAILURE`, and `CHILD_SA_NOT_FOUND` require
   distinct handling. If an SA expires, close the IKE SA and affected CHILD_SAs
   instead of continuing to encrypt on expired keys.

## Remaining blockers before leaving a live tunnel up

- The provider-owned engine now shares one IKE message window across
  INFORMATIONAL and CREATE_CHILD_SA, handles local and peer-initiated rekey,
  and retains old inbound ESP replay state during DELETE. The signed v7 probe
  failed without exposing its stage. A signed/notarized v8 candidate now
  reports fixed nonsecret rekey stages 120–132. Its one approved live IPv4 UDP
  attempt established a tunnel but the gateway returned authenticated stage
  122 (`NO_PROPOSAL_CHOSEN`) for the local rekey offer. No post-rekey packet
  was sent. Read-only gateway phase-2 settings show `pfs enable`, an
  `aes256-sha1` proposal, and DH groups 5 and 14, with no group 20. The local
  group-20-only offer therefore has no matching PFS transform. The operator
  chose to keep the gateway unchanged. A signed/notarized v9 candidate now
  offers group 14 for local and peer-initiated rekey. The group-14 arithmetic,
  protocol, provider, FFI, and bundle checks passed offline. One approved v9
  IPv4 UDP gate then established the tunnel, completed a local CHILD_SA rekey,
  and received one encrypted ICMP reply through the new SA path. The gate
  stopped/removed OFTC and confirmed route/DNS restoration.
- Source after the frozen v7 probe snapshot uses provisional 20–22-minute
  CHILD soft rekey, 35-minute CHILD hard reconnect, and 55-minute IKE hard
  reconnect. Gateway lifetimes have not been observed; tune these after the
  live contract is known.
- The live gateway rejected v8's group-20 PFS rekey proposal with
  `NO_PROPOSAL_CHOSEN`; its phase-2 policy lists groups 5 and 14. The v9
  group-14 candidate passed one local rekey and post-rekey encrypted ICMP
  exchange. The strict parser accepted the gateway's selected suite and
  unchanged TSi/TSr in that run; sustained use, peer-initiated rekey, and
  adverse network conditions remain untested live.
- Simultaneous local/peer rekey currently requests a bounded reconnect. Full
  four-nonce winner selection needs three-SA overlap and deletion of the losing
  pair. Test crossed DELETE, packet loss, and peer `CHILD_SA_NOT_FOUND`.

Protocol basis: [RFC 7296 sections 1.3.3, 2.8, 2.8.1, 2.17, and
2.25.1](https://www.rfc-editor.org/rfc/rfc7296.html) and [RFC 4303 §2.1](https://www.rfc-editor.org/rfc/rfc4303.html). In particular, RFC 7296
requires the `REKEY_SA` SPI to be the exchange initiator's inbound ESP SPI,
allows inbound packets on both overlapping SAs, and specifies nonce-based
collision cleanup. The local integration does not yet establish that the
current FortiGate accepts a rekey or supports sustained operation through its
configured lifetimes.
