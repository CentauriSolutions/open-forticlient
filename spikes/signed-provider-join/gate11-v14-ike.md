# Issue 13: v14 IKE SA renewal gate

The signed and stapled version 14 candidate is uninstalled at
`/private/tmp/oftc-v14-ike-final/IntegrationHost.app`. Apple accepted
notarization submission `77a7bc64-3bb0-444d-9023-4571aa809b82`. The signed
archive is `/private/tmp/oftc-v14-ike-final/IntegrationHost-v14-notary.zip`,
SHA-256 `2af1d67ae54fe972e6807c52080021bff7cce5771501f23803a7689612451a92`.
Ticket validation, deep signature verification, and Gatekeeper assessment passed.

| Component | SHA-256 |
| --- | --- |
| Host executable | `9e7dce0472be846fa031cd03c0c4ab687cfd46f837c39ea553c301f2b95119bc` |
| Provider executable | `1755eb7e33f41ad054152cfde648a4580de0ebbf5648435c3e15ec6a26515889` |
| Provider engine | `27071fcc776860b3569d6a4af7db019d436848095aeb36152ec144a7b31d4c9c` |

V14 adds local IKE SA renewal with fresh P-384 DH, old-`SK_d` key derivation,
old IKE DELETE retransmission, inherited ESP CHILD SA, reset message IDs, and
an explicit `rekey-ike-once` probe. The 55-minute local disconnect is removed.
Configured gateway phase 1 lifetime is 24 hours; local renewal starts at 20
hours with a 23-hour fail-closed bound. The actual gateway policy and live
renewal response remain unverified. The protocol suite passed 96 offline
tests, including an independent HMAC key vector, authenticated old/new IKE
windows, and strict malformed-response parsing. The provider ABI passed 12
tests and Swift typecheck; the signed bundle passed its offline checks.

Run the [pinned gate script](gate11-v14-ike.sh) only after the v13 short recovery
diagnostic and after the target route has returned to `en0`. Its read-only
`--check` verifies the installed v13 baseline, exact v14 artifact, stored
profile/Keychain item, inactive VPN/agent, route, and Tailscale state.
`--install` holds v13 for rollback and activates only v14. Use `--start renewal`
for one stored-profile browser SSO connection and protected reply from
`10.20.0.1`; then use `--probe` to invoke `rekey-ike-once` once and require a
post-renewal protected reply. The same probe performs a CHILD rekey through the
new IKE SA and requires another protected reply before `--stop-run`. The script
records only nonsecret status,
route, count, and fixed stage codes. Cleanup removes OFTC's agent and VPN
configuration and verifies baseline route and DNS.

Use a separate `--start lifecycle` connection for the uninterrupted 55-minute
run. `--stop-run` requires at least 55 minutes after established traffic and
another protected reply, independently of the Wi-Fi loss run. This checks that
the former local cutoff is absent; it does not validate the 20-hour timer.
`--finish` requires both successful runs, leaves v14 installed and disconnected,
and retains exact v13 for rollback. The live IKE renewal and 55-minute runs
remain pending.
