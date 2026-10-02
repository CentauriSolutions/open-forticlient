# Roadmap & implementation strategies

Ordered cheapest-to-most-work. §0 and §A may make a full client unnecessary; do
them first.

## §0 — Zero-code: suppress the client's lock-disconnect (RESOLVED: no local knob)

**Outcome (Issue 1, done).** The teardown *is* gated by a flag, but it is not a
local preference. `AppDelegate.systemWillSleep(_:)` skips the entire stop block
iff `VpnManager.enableClientResumption` is true, and that field is set only from
the **gateway-advertised** `allowClientResumption` option
(`ipsecFgtOptions(…ClientResumption:)` → `enableClientResumption = (arg != 0)`),
otherwise initialized to 0. There is no `fctsysconf.plist`/`vpn.plist`/`data/`
key and no env var to flip. See FINDINGS §1/§6.

So §0 collapses into **§A**: the only lever that flips the client's own flag is
the gateway telling it resumption is allowed. Two fallbacks remain if the gateway
won't advertise it to this free client:

- **Stopgap:** downgrade to `7.4.1.1716`, which has no lock-disconnect code path
  (Issue 9) — independent of the gateway, at the cost of pinning an old build.
- **Real fix:** §C — replace the component that issues the lock-time
  `DISCONNECT`, so lock survival no longer depends on Fortinet (Issue 6).

## §A — Server-side: enable IKEv2 session resumption (operator has FortiGate admin)

Makes a dropped tunnel *resumable* without a fresh SAML login. Requires FortiOS
**7.4.4+**.

> **Tested 2026-10-02 — NO-GO (Issue 2).** Admin enabled `client-resume` and
> reconnected; `fctctld` logged `Enable Client Resumption: 0` (the gateway did not
> advertise it to this free client), and the next lock still tore the tunnel down.
> Server-side alone does not fix the lock drop here. Primary fix is now §C.
> (Re-test only if the gateway turns out to be < 7.4.4 or the wrong phase1 was
> edited — either would flip the logged value to non-zero.)

```
config vpn ipsec phase1-interface
    edit "<dialup-forticlient-phase1>"
        set client-resume enable
        set client-resume-interval 7200      # seconds, 120–172800
    next
end
```

**What we now know (and the real risk).** Disassembly proves the *client half*:
if the gateway advertises `allowClientResumption`, FortiTray sets
`enableClientResumption = true` and `systemWillSleep` skips the lock teardown
entirely (FINDINGS §1). So if the FortiGate advertises resume to this client, the
lock drop stops with **zero client code**. The unproven link — and the likely
home of the known "free client" defect — is whether the gateway advertises
`allowClientResumption=1` to a **free/unregistered** FortiClient at all. There is
no way to force the flag locally (it is private state, reset to 0, written only
from the gateway option), so this can only be settled by testing on the gateway.

**Precise pass/fail signal (no guessing).** After `set client-resume enable` and
a reconnect, lock the screen and read
`~/Library/Application Support/Fortinet/FortiClient/Logs/fortitray.log`:
- **Fix took** if, after `AppDelegate … System is going to sleep`, there is **no**
  `Stop current VPN` / `checkAndStopVPN` and the tunnel stays up (no SAML on
  return).
- **Bug persists** if `Stop current VPN` still follows the sleep line — meaning
  the gateway did not advertise resume to this client, and §A cannot fix it.

Test matrix: {client-resume off/on} × {keep-running off/on} × {lock,
display-sleep, real-sleep, wifi-roam} → record which survive without a SAML
prompt, and in each case whether `fortitray.log` shows the stop. If the "on" rows
still stop on lock, go to §C.

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

Two shapes (full build plan + phases in Issue 6; a Phase-0 check of whether
`fctctld` accepts a non-FortiTray peer decides between them):
- **§C-a interposer** — relay `/var/run/fctvpnctrl.sock` and flip the one
  `allowClientResumption` byte in the daemon→tray options message (and/or drop the
  lock-time `DISCONNECT`); FortiTray then sets `enableClientResumption=true` and
  skips the teardown itself. Smallest change; keeps all of Fortinet's stack.
- **§C-b replacement** — stop FortiTray; our controller runs SAML, sends
  `CONNECT`, answers the OTP prompt, consumes `STATUS`, and never sends
  `DISCONNECT` on lock. More code, no socket-interposition dependency.

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

1. **§A** (operator has admin; minutes to configure) — enable `client-resume` and
   read the pass/fail signal above. If the lock drop stops, we are done with zero
   client code. (§0 is resolved: there is no local knob; §A is the only lever.)
2. If §A does not stop the lock drop (the likely outcome if the free tier is not
   advertised resume), **§C** (reuse `iked`, replace the tray) is the primary fix
   — now substantially de-risked: the control protocol is mapped
   ([`control-socket.md`](control-socket.md)), the vendor IDs are recovered, and
   `iked` has no blocking entitlements (Issue 10). It guarantees lock survival
   because *our* controller decides whether to send `DISCONNECT`.
3. **§B** (strongSwan) stays the fully-open alternative, gated on whether the
   gateway accepts a non-FortiClient IKE_AUTH without `FORTICLIENT_CONNECT`
   (Issue 3).
4. **Stopgap in parallel:** 7.4.1 downgrade (Issue 9) if an immediate,
   gateway-independent reprieve is needed while §C is built.

## Cross-cutting open questions

- Does this gateway advertise `allowClientResumption` to the free client? (the
  §A make-or-break — testable now, Issue 2.)
- Does this gateway's free tier require `FORTICLIENT_CONNECT`? (gates §B vs §C,
  Issue 3.)
- Which EAP method does the token use? (capture a live EAP exchange — Issue 8.
  Likely GTC; the token is fed as an OTP via `fct_eap_peer_set_otp`.)
- ~~Exact binary vendor IDs~~ — **recovered** (ike-dialect.md).
- ~~`fctvpnctrl_woker.sock` message schema~~ — **recovered** (control-socket.md).
- ~~Can `iked` run outside Fortinet's launchd/entitlement context~~ — **answered**
  (Issue 10): minimal entitlements; reuse the launchd job, replace the tray.
