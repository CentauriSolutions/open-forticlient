# TCP ESP live-proof runner (offline preparation)

This isolated Gate 5 runner joins the existing IKEv2/SAML, authenticated
CHILD_SA, ESP engine, RFC 9329 framing, and strict ICMP probe code without
modifying the UDP Gate 3 runner. `sh spikes/tcp-live-probe/run.sh` compiles and
runs 63 local tests only. It leaves a runnable binary under
`/private/tmp/oftc-tcp-live-probe/`; the build script never contacts the VPN
or opens SSO. This test isolates TCP fallback; it does not change the intended
UDP-first transport policy.

The preflight-only command `tcp-live-probe` uses TCP 4443 to reach an EAP
challenge without consuming a SAML token. A separately authorized live test
would run `tcp-live-probe --authenticate --esp-target 10.20.0.1`, where the
target is the operator's stated internal FortiGate ICMP address. It first
performs a fresh TCP preflight, then one SAML authentication and one protected
ICMP echo on the *same established TCP stream* as the authenticated IKE SA.
The ESP record has a two-byte RFC 9329 length and nonzero SPI, with no IKE
marker or second `IKETCP` prefix. A reply counts only after ESP integrity,
replay, selector, IP/ICMP checksum, address, ID, sequence, and payload checks.
It installs no route, DNS setting, or packet tunnel.

The test is bounded to one outbound echo and a 12-second response wait.
Diagnostics are redacted stages and counts; credentials, keys, and raw packet
bytes are not logged. The build and tests alone do not establish gateway TCP
ESP support. Full packet-tunnel flow, network transitions, and lock/wake
recovery remain separate work.

## Authenticated TCP result, 2026-10-07

After the operator explicitly authorized one fresh token and one echo, the
runner reached the EAP challenge in its no-SSO preflight, then completed
EAP-MSCHAPv2, final responder AUTH, and CHILD_SA validation on a new TCP 4443
connection. It sent one RFC 9329 ESP record on that same IKE TCP stream and
authenticated the matching ICMP echo reply from `10.20.0.1`:

```
transport=tcp stage=child_sa_handoff_validated routes=1 dns_servers=0 dns_domains=0
transport=tcp stage=esp_echo_sent
transport=tcp stage=esp_echo_reply_authenticated
```

The process exited successfully and installed no route, DNS setting, or
packet tunnel. The direct TCP fallback data-plane subgate passed on this IPv4
network. The signed provider integration and IPv6-only/NAT64 path remain.
