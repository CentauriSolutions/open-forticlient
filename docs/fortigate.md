# FortiGate requirements

For the gateway admin: what OFTC needs from a FortiGate. Examples use reserved names
(`vpn.example.com`, `203.0.113.10`).

## What the client uses

- **IKEv2 dial-up IPsec** (a `phase1-interface` of type dynamic) with **EAP** and
  **SAML** sign-in. The user signs in in their browser; the client does not handle
  passwords.
- The **SAML port** the gateway listens on for the browser handoff (9443 in the
  examples). Users enter it in setup; it must be reachable from their network.
- The IPsec pre-shared key for that phase1 (distributed to users out of band).

## Transport: allow TCP fallback

OFTC tries **UDP 4500** first and, if that fails, **TCP on the gateway's `ike-tcp-port`**
(4443 by default in these docs). Networks that block UDP 4500 (coworking Wi-Fi, some
hotels) cannot connect unless the phase1 allows TCP, so enable the fallback:

```text
config vpn ipsec phase1-interface
    edit "<dial-up phase1 name>"
        set transport udp-fallback-tcp     # FortiOS 7.4.x
        # set transport auto               # FortiOS 7.6
    next
end
```

As observed on FortiOS 7.4.11 and 7.6.6: on 7.4.x the CLI offers `udp`,
`udp-fallback-tcp` and `tcp`, so use `udp-fallback-tcp`; on 7.6 the value is `auto`.
Options differ on other minors: check with `set transport ?` on your version. Also
confirm `ike-tcp-port` is what you expect and that a local-in policy lets that TCP port
reach the gateway's own address (see the lab observations: it may be needed).

Editing a phase1 can briefly reset tunnels that use it; make the change in a quiet
window.

## Observed in our lab

Plain observations, not a diagnosis of FortiOS; your gateway may differ.

- On a 7.4.11 gateway with `ike-tcp-port` 4443 and `transport` set to
  `udp-fallback-tcp` (and again with `tcp`), `diagnose sys tcpsock` showed `iked`
  listening on TCP 4500 and 11443. TCP connects to 4443 and to 4500 from outside got no
  SYN-ACK and were dropped by the implicit local-in policy, even though `iked` was
  listening. `diagnose debug flow` showed `iprope_in_check() check failed on policy 0,
  drop`: that line is the signature of this problem. Restarting the daemon changed
  nothing.
- After adding an explicit local-in policy on the client-facing interface allowing the
  IKE TCP port (a custom TCP service for 4500, action accept, source and destination
  all, schedule always), TCP connects to both 4500 and 4443 were accepted from outside,
  and the client connected through its UDP-to-TCP fallback from a network that blocks
  UDP 4500. We do not know why 4443 also opened.
- On a later run on the same gateway, deleting that policy again left TCP 4443 and 4500
  answering from outside, so the policy was not the only thing that decided it. We have not
  found what else did.
- A 7.6.6 gateway with `transport auto` accepted the client's TCP connects to 4443 and
  4500 with no extra policy.

All we conclude: TCP fallback is a gateway requirement. On the observed 7.4.11 gateway
an explicit local-in policy for the IKE TCP port made TCP reachable at first, but later
observations show it is not the only factor; on 7.6.6 with `transport auto` it was not
needed. Test from a network that blocks UDP rather than assuming either way. If your users connect from known networks, you can scope the policy's source to them; a
dial-up gateway that serves users anywhere normally allows any source and relies on the
phase1's authentication (PSK, EAP with SAML, an authorised user group) and DPD. Do not trust the configuration alone: verify with a TCP
connect to `<ike-tcp-port>` from outside the gateway's network.

## Verify from the gateway

With a client connecting from `<client-ip>`:

```text
diagnose sniffer packet any 'host <client-ip> and (udp port 500 or udp port 4500 or tcp port <ike-tcp-port>)' 4 0 l
```

You should see UDP 500/4500 traffic and, for a client on a UDP-blocking network, a TCP
handshake on `<ike-tcp-port>`. TCP SYNs with no SYN-ACK mean the connection is being
dropped or nothing is listening. To see which, trace the flow:

```text
diagnose debug flow filter addr <client-ip>
diagnose debug flow filter dport <ike-tcp-port>
diagnose debug flow filter proto 6
diagnose debug flow show function-name enable
diagnose debug flow trace start 20
diagnose debug enable
```

A drop with `iprope_in_check() check failed on policy 0, drop` means local-in policy is
refusing the port; with `diagnose sys tcpsock` also showing no listener on it, the
transport setting is not applied. Turn the trace off afterwards with
`diagnose debug disable` and `diagnose debug flow trace stop`.
