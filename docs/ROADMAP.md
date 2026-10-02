# Roadmap & implementation strategies

Ordered cheapest-to-most-work. §0 and §A may make a full client unnecessary; do
them first.

## §0 — Zero-code: suppress the client's lock-disconnect (investigate first)

The teardown is gated by a flag (`-[LegacyIpsecBridge setDisconnectOnSleep:]`,
function `_ipsec_system_sleep`, log `System sleep disconnect enabled`). If that
flag is driven by a readable/writable preference or EMS/sysconf key, flipping it
is the entire fix — no client needed.

**Next steps**

1. Disassemble `_ipsec_system_sleep` and the writer of `disconnectOnSleep`; find
   whether it reads a plist key, an env var, an EMS policy, or is hard-coded.
2. Grep `conf/fctsysconf.plist`, `conf/vpn.plist`, `data/` for the key; try
   toggling in a copy and relaunching FortiTray.
3. If hard-coded `true` with no knob, §0 is out — move to §A/§C.

Also re-confirm the community workaround (downgrade to `7.4.1.1716`, which has no
lock-disconnect code path) as a stopgap, weighing the security tradeoff of
pinning an old build.

## §A — Server-side: enable IKEv2 session resumption (operator has FortiGate admin)

Makes a dropped tunnel *resumable* without a fresh SAML login. Requires FortiOS
**7.4.4+**.

```
config vpn ipsec phase1-interface
    edit "<dialup-forticlient-phase1>"
        set client-resume enable
        set client-resume-interval 7200      # seconds, 120–172800
    next
end
```

**Caveat / must-test:** per Fortinet's own note, FortiClient only *acts on* resume
on a network change or wake-from-sleep, and the macOS client still issues an
explicit disconnect on **lock**. So §A most reliably helps the sleep/roam case; it
may not by itself stop the lock-triggered drop unless §0's client behavior is also
addressed. Worth testing the combination:

- enable `client-resume` server-side, **and**
- a profile that permits keep-running (so the client takes the
  `tunnelConnectWithoutReauth` branch instead of the disconnect branch).

Test matrix: {client-resume off/on} × {keep-running off/on} × {lock, display-sleep,
real-sleep, wifi-roam} → record which combinations survive without a SAML prompt.

## §B — strongSwan + a thin SAML shim (open stack, uncertain acceptance)

Use the existing `tools/saml_catch.py` flow to obtain `username`+`tokenid`, then
feed them to **strongSwan** as `eap` credentials with `remote auth = psk`,
`local { round = 2, auth = eap, eap_id = <username> }` and the token as the EAP
secret. This is the known strongSwan↔FortiGate IKEv2 recipe.

**Risk:** strongSwan will not emit the Fortinet vendor IDs or the
`FORTICLIENT_CONNECT` (0xF100) notify. If the gateway requires those for the free
tier, IKE_AUTH is rejected. Unknown until tested — see `ike-dialect.md`. If it
works, this is the cleanest fully-open result. If not, go to §C.

Also: strongSwan would own sleep/wake itself, so we get the "don't disconnect on
lock" property for free, and its MOBIKE / `client-resume` interop can be tested
independently.

## §C — Reuse Fortinet's own `iked`, replace only FortiTray (highest fidelity)

The daemon `iked` already speaks the exact dialect (vendor IDs, notifies, EAP,
license blob). The bug lives in **FortiTray**, not `iked`. So: keep `iked`, write
a small controller that does what FortiTray does **minus the lock teardown**.

**What the controller must do**

1. Run the SAML flow (`tools/saml_catch.py` logic) → `username`, `tokenid`.
2. Produce/point to an `iked.conf` (copy the one `fctctld` already generates at
   `…/ipsec/iked.conf`; it is world-readable and complete).
3. Start `iked` (or let `fctctld`/launchd start it) and deliver the EAP
   identity+OTP over its control socket `…/ipsec/fctvpnctrl_woker.sock`
   (see `ikectl`, `fct_tunnel_ctl` for the message format).
4. Program routes/DNS — either via the existing PrivilegedHelper XPC, or our own
   root helper calling `route`/`scutil`.
5. **Register nothing for screen-lock.** Optionally register for real-sleep only,
   and on wake rely on `client-resume` (§A) to resume.

**Unknowns to resolve**

- The control-socket protocol to `iked` (reverse `ikectl` / the
  `fctvpnctrl_woker.sock` consumer in `fctctld`).
- How the EAP OTP is injected at runtime vs. via config.
- Whether running `iked` outside Fortinet's launchd context trips entitlement /
  code-signing / SIP requirements (it's a signed root daemon). May need to keep
  using Fortinet's launchd job and only replace the tray.

**Why this is attractive:** it inherits licensing (`FORTICLIENT_CONNECT`), the
vendor IDs, and `client-resume` for free, and the only new code is a few hundred
lines of orchestration. It is also the least "novel protocol" risk.

## Recommended sequence

1. **§0 investigation** (hours) — may end the project immediately.
2. **§A** (operator has admin; minutes to configure) + measure the test matrix.
3. If a client is still needed: **§C** (reuse `iked`) as the primary path, with
   **§B** (strongSwan) as the fully-open fallback, decided by whether the gateway
   accepts a non-FortiClient IKE_AUTH.

## Cross-cutting open questions

- Does this gateway's free tier require `FORTICLIENT_CONNECT`? (gates §B vs §C)
- Which EAP method does the token use? (capture a live EAP exchange)
- Exact 2 binary vendor IDs. (capture live, or pull from `iked` `__const`)
- `fctvpnctrl_woker.sock` message schema. (reverse `ikectl`)
- Can `iked` be driven outside Fortinet's launchd/entitlement context?
