# Authenticated IKEv2 Gate 3 probe

This narrow executable joins the SA_INIT, encrypted IKE_AUTH, and EAP-MSCHAPv2
spikes. It uses the installed `Office VPN` profile and `oftc`'s existing SAML flow.
It targets the profile's configured gateway over IPv4. UDP 4500 is the default;
TCP 4443 is an explicit fallback choice. It does not install routes or create a
packet tunnel. It sends ESP only with the explicit `--esp-target` option.

Build without network access:

```sh
sh spikes/ike-gate3/run.sh
```

Run `spikes/ike-gate3/gate3` to make a bounded **no-SSO preflight**. It verifies
the gateway PSK AUTH, sends the configured machine UID as EAP Identity, parses
the MSCHAPv2 Challenge, and stops. `--transport tcp` selects TCP. The default
UDP path must be tried first on a network that permits it.

`--authenticate` repeats that preflight, then opens the browser for SSO and
uses **one fresh, single-use** callback token for one new IKE SA. The SAML
bootstrap UID is both the EAP Identity and MSCHAPv2 Name, matching the working
Fortinet CONNECT path. The callback username is display metadata.
The probe verifies inner MSCHAPv2 Success, outer EAP Success, and the final
IKE AUTH, then validates the negotiated CHILD_SA, selectors, configuration,
and derived ESP keys against the offline packet engine. By default, it does
not send ESP.
The token stays in process memory and is erased immediately after
constructing the MSCHAPv2 response. Packet bytes, token, PSK, MSK, and SAML
login URL are not logged. If the gateway certificate is not trusted or pinned,
use the existing `oftc trust` flow; `--insecure` is an explicit local test
override.

The runner does not automatically try a second token or switch transport after
an authentication rejection. Record the **last printed stage**, non-secret
notify or MSCHAPv2 error code, and corresponding gateway IKE/FNBAM diagnostic
before deciding on another attempt. An authenticated and validated CHILD_SA
would pass Gate 3; protected traffic remains Gate 4.
Token-bearing IKE responses have a bounded 30-second read window (two UDP
sends of the same request, or one TCP request) to accommodate gateway identity
lookup without consuming a second token.

## Direct UDP ESP subgate

`--authenticate --esp-target 10.20.0.1` makes one additional, bounded test after
the authenticated CHILD_SA is validated. It constructs one ICMP echo request
from the gateway-assigned inner IPv4 address to the operator-approved firewall
address, encrypts it as ESP, and sends the bare ESP packet on the existing UDP
4500 socket. It waits up to 12 seconds for an authenticated, matching ICMP echo
reply. The engine enforces the returned split route and traffic selectors before
sending. This option requires UDP and a fresh SAML token; it does not install a
route, DNS setting, or packet tunnel. Success would establish the direct UDP
data-plane subgate, not the full Gate 4 packet-tunnel result.

## Preflight result, 2026-10-07

After the CP-before-SA ordering fix and a request for split-subnet attribute
13, one no-SSO preflight on each transport passed on the current IPv4 network.
The ESP offer now explicitly includes the mandatory no-ESN transform;
subsequent UDP and TCP preflights still reached the same challenge:

| Outer transport | Verified responder | Last stage |
| --- | --- | --- |
| UDP 4500 | PSK AUTH verified | MSCHAPv2 Challenge received |
| TCP 4443 | PSK AUTH verified | MSCHAPv2 Challenge received |

Each preflight used a fresh IKE SA and the configured machine UID; neither
opened SSO, used a token, sent a method response, established a CHILD_SA, or
sent ESP. These results confirm that the revised initial IKE_AUTH request
still reaches the expected method on both paths. The authenticated attempt
and gateway contract remain the next Gate 3 boundary.

Automatic approval review rejected the first request to run `--authenticate`
before starting the process because sending a single-use SAML credential to
this gateway needs explicit destination-specific authorization. No browser
opened and no token was obtained or sent. A later explicit authorization
allowed the single attempt below; there was no indirect retry path.

## Authenticated UDP result, 2026-10-07

After the operator explicitly authorized one token-bearing attempt, the
browser SSO returned one fresh token and the UDP runner completed:

| Stage | Result |
| --- | --- |
| Responder PSK AUTH | verified |
| EAP-MSCHAPv2 Challenge and inner server Success | received and verified |
| Outer EAP Success | received |
| Final responder AUTH | verified with the EAP MSK |
| CHILD_SA | SAr2, TSi, TSr, and CP present; selected ESP suite, SPIs, selector narrowing, assigned IPv4 address, route policy, and directional KEYMAT passed the typed engine handoff |

The authenticated response carried one split route, no DNS servers or domains,
and notify code 61689 (meaning not yet classified). No token, PSK, MSK, SPI,
address, route value, or decrypted packet was logged. The runner closed after
validating the handoff; it installed no tunnel setting and sent no ESP. This
passes Gate 3 on UDP only. Protected traffic and TCP authentication remain
untested at that point.

## Direct UDP ESP result, 2026-10-07

With a second, separately authorized fresh SAML token, the runner repeated
the authenticated UDP exchange and sent exactly one encrypted ICMP echo to
the operator-approved firewall address `10.20.0.1`. The ESP engine accepted
the gateway-assigned source, returned split route, and negotiated traffic
selectors before sending. It then authenticated a matching ICMP echo reply on
the same UDP 4500 socket within the bounded wait:

```
transport=udp stage=child_sa_handoff_validated routes=1 dns_servers=0 dns_domains=0
stage=esp_echo_sent
stage=esp_echo_reply_authenticated
```

The run exited successfully. No token, key, SPI, assigned address, decrypted
packet, or raw capture was logged. This passes the direct UDP ESP subgate. It
does not prove that macOS `packetFlow`, route/DNS settings, or teardown can
carry the same session; those remain Gate 4 work.
