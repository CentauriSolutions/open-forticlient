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
confirm `ike-tcp-port` is what you expect and that the port is allowed to reach the
gateway's own address (local-in).

Editing a phase1 can briefly reset tunnels that use it; make the change in a quiet
window.

## Verify from the gateway

With a client connecting from `<client-ip>`:

```text
diagnose sniffer packet any 'host <client-ip> and (udp port 500 or udp port 4500 or tcp port <ike-tcp-port>)' 4 0 l
```

You should see UDP 500/4500 traffic and, for a client on a UDP-blocking network, a TCP
handshake on `<ike-tcp-port>`. TCP SYNs with no SYN-ACK, together with a local-in drop in
`diagnose debug flow`, mean the TCP listener is not active (the transport setting above
is not applied, or the port is blocked).
