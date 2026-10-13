# Operating OFTC

These commands target the signed OFTC app. The current default path is
`/Applications/OFTC development probe.app`; use `--app /absolute/path/App.app`
for a development build. The bundle and path are temporary v15 identities,
pending distributable packaging.

## One-time setup

Install a signed and notarized app before activation. Then:

```sh
oftc activate
oftc import-profile "Office VPN"   # or save-profile GATEWAY SAML_PORT + provision-psk GATEWAY
oftc install-config
oftc show-profile
oftc install-agent             # stages a disabled per-user job
```

Import is the only normal setup step that needs a FortiClient profile. It
copies the PSK to an OFTC Keychain item and saves a nonsecret OFTC profile.
`install-agent` does not connect. The app must remain at the path recorded by
the agent.

## Connect, inspect, stop

```sh
oftc start-agent
oftc status
oftc rekey-counts
oftc stop-agent
```

`start-agent` starts the supervised connection and enables starts at future
GUI logins. Browser SSO may appear when the existing provider session cannot
complete authentication silently. `stop-agent` disables future login starts
and stops the VPN. `oftc connect` runs the same supervisor in the foreground;
`oftc disconnect` stops a managed connection and disables its agent.

Logs are under `~/Library/Logs/open-forticlient/standalone.log`. They include
nonsecret state transitions and recovery reasons. If a connection fails, check
`oftc status`, the macOS VPN configuration and extension state, route and DNS,
then the relevant log window. Avoid sharing raw SAML callbacks or packet
captures. For local build checks, use the commands in the [README](../README.md);
an offline build does not validate live VPN behavior.

## Remove or change the app

```sh
oftc uninstall-agent
oftc remove-config
```

`uninstall-agent` stops the connection and removes the per-user job. It leaves
the app, OFTC profile, Keychain PSK, and log in place. To change the app path,
stop and uninstall the agent, install the new signed app, then install and
start the agent for that path. Follow the [rollout gates](initial-rollout-gaps.md)
before replacing an existing client for general use.
