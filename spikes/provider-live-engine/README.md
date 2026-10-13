# Provider-owned live session spike

`session.rs` turns the Gate 3 handshake into a provider-owned `Session`.
The caller supplies the gateway name, machine UID, plaintext PSK, and one fresh
SAML `tokenid` as `ConnectInput` in process memory. This layer does not load a
FortiClient profile, open a browser, or retrieve a token. `Session::connect`
consumes the input, verifies responder PSK AUTH and EAP-MSCHAPv2 server Success,
checks outer EAP Success and final AUTH, validates the CHILD_SA and its selected
routes, and retains the connected outer socket with the installed ESP engine.
It also retains the authenticated IKE keys, SPIs, next request ID, and CHILD_SA
SPI pair for lifecycle exchanges. `Session::connect` prefers IPv4 UDP 4500 and
switches once to TCP 4443 only when UDP SA_INIT times out or its socket fails.
The TCP attempt starts a fresh IKE SPI, DH key, and NAT-detection hashes before
EAP; an authenticated failure never retries the single-use token.
`Session::connect_with_options` also permits an explicit transport and native
IPv6 outer socket. IPv6 requires a caller-observed CLAT IPv4 address for the
FortiGate IDi payload. A bounded DNS worker selects the requested address
family; TCP connects are bounded to four seconds.

The signed v6 provider completed one protected packetFlow ICMP round trip on
IPv4 UDP, IPv4 TCP, native IPv6 UDP, and native IPv6 TCP. Current source after
the frozen v7 rekey-probe build also integrates local and peer-initiated
`CREATE_CHILD_SA`, old/new inbound ESP replay windows, authenticated old-SPI
DELETE, and one shared IKE request window. An explicit
`Session::rekey_child_once()` is available for a bounded live gateway probe.
FortiGate's accepted rekey suite and selector representation remain unobserved. A
signed/notarized v8 diagnostic candidate reports fixed nonsecret rekey stages
through the provider and host. Its one approved IPv4 UDP live attempt returned
authenticated `NO_PROPOSAL_CHOSEN` for the local CHILD rekey request; it sent
no post-rekey packet and restored signed v7. The gateway phase-2 policy allows
PFS groups 5 and 14. The operator kept that policy unchanged; signed/notarized
v9 now offers group 14 for local and peer-initiated rekey. V9 passed offline
checks and one authorized IPv4 UDP gate: local CHILD rekey succeeded, one
post-rekey ICMP echo received a reply, and cleanup restored route/DNS.

The returned `NetworkSettings` contains the actual resolved outer gateway IP
address, assigned inner IPv4 address, optional netmask, split routes, DNS
servers/domains, and a conservative 1280-byte inner
MTU. A missing interface mask defaults to `/32`; it does not broaden the
assigned interface subnet. The provider should install routes and DNS only
after `connect` succeeds and should remove them when the session ends.
`Session::send_ip` enforces the authenticated selectors/routes and sends ESP
on the retained socket. For TCP, IKE and ESP share one RFC 9329 stream with one
`IKETCP` prefix, bounded record framing, and partial reads preserved between
polls. `Session::send_nat_keepalive` emits the correct UDP or TCP keepalive
when the provider schedules it. `Session::receive` verifies and answers
responder-initiated IKE INFORMATIONAL DPD and CHILD/IKE DELETE; it returns the
peer event after sending the authenticated response. It also returns
authenticated inner IP, a NAT keepalive, a rejected datagram, or a normal
250 ms timeout. Unauthenticated, malformed, unsupported, or late duplicate
IKE packets are rejected without deleting an established ESP SA; only a
verified peer DELETE disables the affected data path. No SPI, key, MSK, PSK, or token
is returned to Swift. The caller must serialize calls on a session; the
`Cancellation` handle may be shared with another thread.

`Cancellation::cancel` interrupts response waits, idle receives, and TCP
control writes within the 250 ms polling slice; the DNS caller has a
three-second deadline even when its worker remains blocked, while TCP connect
and a synchronous crypto call cannot be interrupted mid-call. Error values contain only a stage, not packet bytes or
secrets. The token is wiped immediately after constructing the EAP response;
the input PSK and any remaining token are wiped on drop. Existing IKE and ESP
types wipe their key material on drop.

`Session::probe_liveness` sends one authenticated empty INFORMATIONAL request,
retransmitting the identical sealed packet once, and requires an authenticated
empty response. It queues up to 32 authenticated IP packets that arrive during
the bounded wait, dropping excess data packets while still waiting for control.
A verified peer CHILD/IKE DELETE interrupts the probe instead of being reported
as liveness success. A failed probe disables ESP and requires reconnect.
`Session::disconnect` consumes the session, sends an authenticated CHILD_SA
DELETE followed by IKE_SA DELETE, and waits up to 5 seconds for each
acknowledgement. It returns `Clean` only after both responses verify. Its other
results distinguish a peer-initiated delete, pending control exchange, or an
unconfirmed CHILD/IKE delete; in every case the socket and local keys are
dropped. Provider cancellation skips blocked network DELETE work so local
packet-tunnel cleanup can finish promptly.
If the gateway did not acknowledge a delete, its SA may remain until expiry.

`Session::tick_liveness` starts a jittered local CHILD rekey after 20–22 minutes,
requires a fresh CHILD or reconnect by 35 minutes, starts local IKE SA renewal
at 20 hours, and requires renewal or reconnect by 23 hours. The recorded
FortiGate configuration has a 24-hour IKE and 12-hour CHILD lifetime; actual
gateway enforcement remains unmeasured. The local IKE renewal uses fresh
P-384 DH and inherits the existing CHILD SA without fresh SAML. An unanswered
or malformed rekey fails closed;
a simultaneous local/peer rekey also requests reconnect until three-SA
nonce-collision cleanup is implemented. A peer-initiated replacement retains
the old inbound SA for an authenticated DELETE, with a 60-second deadline.

## Offline verification

```sh
sh spikes/provider-live-engine/run.sh
```

This compiles the Swift crypto bridge and Rust session into a temporary build
directory, then runs the imported protocol/ESP tests and provider API tests.
The loopback socket test is ignored by default because the sandbox denies
socket creation; where local networking is permitted, run:

```sh
${TMPDIR:-/private/tmp}/oftc-provider-live-engine/provider-live-engine-test \
  --ignored --exact tests::retained_socket_sends_and_receives_synthetic_esp
```

The loopback tests use synthetic keys to reject forged matching-ID IKE replies
until an authenticated response arrives; keep valid ESP working after late
IKE_AUTH and bad-MAC INFORMATIONAL packets; answer peer DPD; complete an
initiator DPD probe despite queue pressure; interrupt DPD on a verified peer
CHILD DELETE; verify authenticated CHILD and IKE DELETE on `disconnect`; and
send and receive authenticated ESP over a retained TCP stream when a reply is
split across two reads.
It does not contact a VPN gateway. The IKE connect path has not yet been
retested through this new owner against a real gateway; Gate 3 and the direct
UDP ESP probe verified the underlying protocol sequence in the separate
runner.

## Remaining gates

- Extend the successful one-shot signed-provider local rekey to sustained use
  and peer-initiated rekey. The current parser accepts only unchanged selectors.
- Resolve simultaneous local/peer rekey using the four-nonce rule and bounded
  three-SA overlap. Until then, collision reconnects rather than risking the
  wrong outbound SA.
- Validate live IKE renewal and the gateway's actual lifetime policy, then
  adjust the local deadlines if needed. Validate sleep, wake, roam, stalls,
  and sustained tunnel use.
