# Offline IKEv2 lifecycle codec

`sh spikes/ike-lifecycle/run.sh` compiles the existing Swift crypto bridge and
the Rust test module. It makes **no network request**, reads no profile or
credential, and does not install routes or SAs. The tests use synthetic keys
and SPIs.

`lifecycle.rs` uses the importing crate's `auth::Keys` and HMAC-SHA256 helpers,
plus the same Swift AES-256-CBC and secure-random bridge. `test.rs` supplies
that crate-level `auth` module for the standalone tests. It supports a narrow
IKEv2 `INFORMATIONAL` exchange after final IKE_AUTH has succeeded:

| Operation | Initiator request | Valid responder response |
| --- | --- | --- |
| Liveness / DPD | Authenticated, encrypted empty SK | Authenticated, encrypted empty SK |
| Delete one ESP CHILD_SA | Delete payload with **our inbound** ESP SPI | Empty SK, or Delete with **peer inbound** ESP SPI |
| Delete IKE_SA | Delete payload with protocol ID 1, SPI size/count zero | Empty SK |

Responder-initiated empty DPD and ESP/IKE delete requests are also parsed. A
valid new request returns an encrypted response and an event for the caller to
apply. A byte-identical retransmission returns the cached response without
repeating the event. The codec accepts one CHILD_SA SPI pair; it rejects an
unknown delete SPI rather than tearing down a different SA.
If both peers independently delete that same CHILD_SA at once, the reply to
the crossed peer request is empty, as required by RFC 7296 §1.4.1. The pending
local delete still accepts an authenticated empty reply.

## Integration

After final IKE_AUTH, create `Lifecycle` with the authenticated initiator and
responder IKE SPIs, owned `Keys`, the next **unused** initiator request
message ID, responder request message ID (normally zero), and the installed
CHILD_SA SPI pair. Keep one instance for the life of the IKE SA. For an
initiator request, `start()` returns raw IKE bytes to frame for UDP/4500 or
RFC 9329 TCP; retransmit `pending_packet()` **verbatim** on a timeout. Call
`complete()` only on a received, unframed IKE response. Message IDs advance
only after a matching, authenticated response. Route removal, ESP key disposal,
timers, and socket closure remain the provider's responsibility. On provider
shutdown, delete the CHILD_SA and then the IKE_SA while the transport remains
available; if an exchange times out, handle the uncertainty explicitly before
discarding local state.

`handle_peer_request()` accepts responder-initiated IKE packets and returns a
response to send plus a `PeerEvent` for local SA cleanup. It tracks the
responder's message ID independently. Its cached response permits the last
request's retransmission, including after IKE_SA delete. The caller must
dispatch any IKE response to `complete()` and any responder request to
`handle_peer_request()` based on the authenticated header.

## Graceful liveness policy

`liveness.rs` adds a nonblocking `Liveness` timer policy around the codec.
Start it with a monotonic clock after final IKE_AUTH and call `tick()` from the
provider event loop. The default policy starts a DPD after 20 seconds without
authenticated inbound traffic, resends the **same sealed packet** every five
seconds, preserves the CHILD_SA through at least 60 seconds of probe grace,
and requests reconnect after 120 seconds without a DPD answer even if ESP has
continued. An authenticated ESP packet or peer IKE request extends the silence
grace; untrusted, malformed, or replayed packets must not call `observed_rx()`.
The matching authenticated DPD response must go through `complete_dpd()`;
that is the only path that clears the pending IKE request and advances its
message ID. Late responses recover the session; duplicate or forged responses
do not advance it. `Reconnect` is a request to the provider, not an automatic
SA disposal action. The provider must avoid installing stale routes and must
stop using that IKE SA before reconnecting.

The current `provider-live-engine/session.rs` still calls a synchronous
five-second `probe_liveness()` and invalidates ESP on that first timeout.
Integration must replace that behavior with event-loop `tick()` and packet
dispatch, not run both mechanisms. It must preserve packetFlow delivery while
the DPD is pending and use the existing socket for retransmissions. No live
gateway or screen-lock behavior has been validated for this policy.

The codec does not implement CREATE_CHILD_SA, rekey, multiple CHILD_SAs,
fragmentation, arbitrary INFORMATIONAL notifications, or NAT keepalives. The
liveness policy supplies timer decisions but no socket I/O or general IKE
retransmit engine. It does not itself prove gateway interoperability;
the tests validate synthetic encrypted and authenticated packets, including
malformed headers, wrong IDs/SPIs, tampering, and duplicate requests.

CHILD_SA rekey is a separate substantial gate: the current one-CHILD_SA engine
needs overlapping old/new ESP receive SAs and an atomic outbound switch;
CREATE_CHILD_SA needs fresh nonces, the negotiated PFS exchange, `REKEY_SA`
notification and traffic selectors, authenticated response validation, new
KEYMAT, and cleanup of the old SA after its grace period. IKE_SA rekey and
simultaneous rekey collision handling remain additional work. Until those
land, a long-running provider must reconnect before either SA lifetime or
ESP sequence exhaustion, with route and packetFlow continuity explicitly
tested.

Format and SPI direction follow [RFC 7296, sections 1.4 and 3.11](https://www.rfc-editor.org/rfc/rfc7296.html).
