# Gateway requirements

What the OFTC client expects from a FortiGate. How to configure the gateway is the gateway
admin's business and is not covered here; see Fortinet's documentation. Examples use
reserved names (`vpn.example.com`, `203.0.113.10`).

## What the client uses

- **IKEv2 dial-up IPsec** with **EAP** and **SAML** sign-in. The user signs in in their
  browser; the client never handles a password.
- The **SAML port** the gateway listens on for the browser handoff (9443 in the examples).
  Users enter it in setup, and it must be reachable from their network.
- The IPsec **pre-shared key** for that dial-up phase1, which the user gets out of band.

## Transport

OFTC tries **UDP 4500** first and, if the gateway does not answer, **TCP on the gateway's
IKE TCP port**. On a network that blocks UDP (coworking Wi-Fi, some hotels) the connection
works only if the gateway also answers on that TCP port.

If neither answers, OFTC reports `network_blocked` ("The gateway did not answer over UDP or
over TCP. This network may block UDP."). That message means the client reached no transport;
it does not say which side is at fault, so check from a second network before blaming the
first one.
