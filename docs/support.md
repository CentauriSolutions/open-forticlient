# Support: what to send when something fails

Send the smallest set that shows the failure, and read it before sending. **Never send**
a PSK, a `.oftc` export (it contains each PSK), a SAML callback URL or `tokenid`, a
packet capture, or a Keychain item. Remove gateway names you are not allowed to share.

Say first: the OFTC version (`oftc --version`), the macOS version (`sw_vers`), whether
this was a fresh install or an update (and from which version), and what you clicked
or ran when it failed.

## 1. State

```sh
oftc --version
oftc status                    # each VPN's state, the agent, login settings
oftc profiles                  # names and ids, no secrets
systemextensionsctl list       # is the OFTC provider "activated enabled"? which version?
```

`systemextensionsctl list` shows the provider version and build next to its state. A
provider that is `activated waiting for user` needs approval in *System Settings →
General → Login Items & Extensions*; `terminated waiting to uninstall on reboot` needs a
restart.

## 2. Supervisor logs

Each VPN's supervisor writes `~/Library/Logs/OFTC/<profile id>.log`; the login agent and
the resident host service write `agent.log` in the same folder. Send the last lines
around the failure, for example:

```sh
tail -n 80 ~/Library/Logs/OFTC/<profile id>.log
```

Each supervisor line starts `OFTC supervisor:`. The files hold no PSKs or tokens, but
check them for gateway names before sending.

## 3. System log (provider and system extension)

The provider (`OFTCTunnel`) is a system extension; macOS records its lifecycle,
approval and tunnel start/stop in the unified log under the system processes that
manage it. Capture a window around the failure, no wider than needed:

```sh
log show --last 15m --info \
  --predicate 'process == "OFTCTunnel" OR process == "OFTCAgent" OR process == "sysextd" OR process == "nesessionmanager" OR process == "neagent"' \
  > oftc-log.txt
```

Read `oftc-log.txt` before sending it. Which lines appear depends on the failure; a
log with no `OFTCTunnel` lines is itself useful (the provider never started).

## 4. Installer log (install or update failed)

Installer failures are summarised generically in its window. The cause is in the
installer log:

```sh
grep -E "OFTC|openforticlient" /var/log/install.log | tail -n 60
```

Send only the lines about the OFTC package (a preinstall refusal says `OFTC is running`
or `An OFTC VPN is active`; a code-signature or extension problem names the bundle).

## Common causes

| You see | Usually |
| --- | --- |
| Installer: "Disconnect OFTC before updating" | An OFTC VPN is connected or reconnecting. Disconnect every VPN, quit OFTC, retry. |
| Setup never completes, extension error code 8 | The installed app bundle's signature is broken (a hand-merged copy). Reinstall the package over it. |
| Connects, then asks to sign in again | Expected after any drop: every reconnect needs a fresh browser sign-in. |
| A VPN stays "Set up your VPN" | Its gateway or PSK is missing; add it with **Add VPN…** or open the team's `.oftc` file. |
