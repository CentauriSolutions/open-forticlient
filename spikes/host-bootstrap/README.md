# In-memory host SAML bootstrap spike

`lib.rs` imports the existing `client/src/saml.rs` and profile type. The live
entry takes a gateway and plaintext PSK already held in process memory,
constructs a transient `Profile` value, obtains one SAML callback through the
existing browser flow, and returns the exact gateway, SAML UID, PSK, and
single-use token as one length-prefixed buffer. It does **not** call
`Profile::load`; this bridge does not read FortiClient files, environment PSK
overrides, or a Keychain item. It uses the UID returned by `saml::obtain`,
which must be the IKE EAP identity; the callback display username is not sent.

The Swift `HostBootstrapBridge` copies that buffer into the existing
`BootstrapWire` envelope with a fresh 16-byte start ID and 60-second expiry.
Its `start(_:options:)` method typechecks the real
`NEVPNConnection.startVPNTunnel(options:)` signature. No value goes into
`NETunnelProviderProtocol.providerConfiguration`, argv, an environment
variable, a log, or a file.

## Offline verification

```sh
zsh spikes/host-bootstrap/run.sh
```

This runs 16 Rust tests, compiles the bridge as a synthetic-only dynamic
library, typechecks Swift against NetworkExtension, and verifies a synthetic
Rust buffer carried through Swift to the `startVPNTunnel` options dictionary.
The synthetic path contains literal `SYNTHETIC` values. It never invokes the
live SAML entry, opens a browser, reads a real profile, starts a tunnel, or
sends any packet. The signed IntegrationHost bundle is unchanged.

## Wire and ownership

The inner buffer is `HBR1` followed by four big-endian 16-bit lengths and the
UTF-8 bytes for gateway, UID, PSK, and token in that order. Total length is at
most 4096 bytes; gateway, UID, PSK, and token have individual limits of 253,
128, 1024, and 1024 bytes. The Rust allocation has exact length. Rust
volatile-wipes the PSK and token strings after encoding and wipes the returned
allocation when Swift calls `oftc_host_free_wire`. On failure it returns only a
generic status; the output pointer remains null.

The Swift `Data`/`NSData` copies required by NetworkExtension cannot be
guaranteed zeroized. Keep the options in memory only until the one start call,
never print an options dictionary, and do not attach it to saved preferences.
The provider must validate the outer envelope, decode the inner lengths
exactly, move the token to its Rust session, and reject duplicate or stale
start IDs. The current signed provider only recognizes its synthetic marker;
this spike is not yet a live host/provider connection.

## Integration path

1. Obtain gateway and PSK in host memory, then call `acquireOptions` away from
   the main UI thread. Its real entry blocks while the user completes SSO.
   Call `start(manager.connection, options:)` once with the resulting options.
   A failed start needs a fresh token; never replay the same envelope.
2. For a short interoperability spike, the existing `Profile` type can supply
   gateway, SAML port, and plaintext PSK. Its loader currently consults
   FortiClient files and may consult an environment variable or `.env` for the
   PSK. Keep that legacy loader outside the signed host path.
3. For standalone `oftc`, own the profile schema and store the PSK in the
   Keychain. Read it only for an explicit start, hand it to this bridge in
   memory, then release the host-side value promptly. Replace the legacy
   `saml.rs` TLS/bootstrap shell calls with a small native implementation
   before considering the host independent of FortiClient. Review transient
   Foundation/NetworkExtension copies during signed integration.
