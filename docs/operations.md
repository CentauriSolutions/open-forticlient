# Operating OFTC

The release package installs `/Applications/OFTC.app`, `/usr/local/bin/oftc`,
and `man oftc`. Build 19 is the current pilot package. Local upgrade,
profile/PSK preservation, extension activation, and a short live IPv4 UDP
connection passed. Recovery and longer sessions on this package remain open;
see the [build 19 record](evidence/v19-packaged-pilot.md).

For colleagues testing the package, use the shorter [pilot guide](pilot-validation.md)
and its [local report script](../scripts/collect-pilot-report.zsh).

## Install and set up

After installing the package, run:

```sh
oftc setup
```

It offers any local OFTC development or FortiClient profile as a starting
point and asks for missing settings or a PSK. Approve the OFTC Network
Extension if macOS requests it. Setup prepares the VPN without connecting;
rerun `oftc setup` if approval interrupted it. See `man oftc` for explicit
setup options.

For the current development installation only, first run
`app/migrate-development.sh --plan` and then `--apply` after installing the
release package. The script stops the old agent and VPN while retaining its
app, profile, and Keychain item for rollback. Then run `oftc setup` and choose
the development profile.

## Connect and inspect

```sh
oftc connect
oftc status
oftc disconnect
```

`connect` starts a supervised connection and enables starts at future GUI
logins. Browser SSO may appear. The supervisor retries recoverable drops.
`disconnect` stops the VPN and disables those future starts, so a deliberate
stop stays down until `oftc connect`. `status` shows VPN and agent state,
nonsecret profile settings, and CHILD SA rekey counts when connected. Agent
logs are in `~/Library/Logs/OFTC/agent.log`. Do not share raw SAML callbacks,
PSKs, or packet captures.

## Update or uninstall

Disconnect before installing an update; the package refuses to replace a
running app. Run `oftc connect` after the update if you want the VPN and login
starts enabled again.

```sh
oftc disconnect
# install the verified replacement package
oftc connect
```

`oftc uninstall` stops the agent and VPN, removes OFTC's VPN configuration,
requests system extension deactivation, then invokes the package removal
helper with administrator access. It retains the OFTC profile, Keychain PSK,
and logs. Use `oftc uninstall --erase-profile` to erase that profile and its
PSK as well. If macOS defers extension removal, complete its approval or
reboot and rerun uninstall; the helper refuses to remove an active extension.

The older Fortinet-backed controller remains available from Git history, not
from the active source tree. See [initial rollout gaps](initial-rollout-gaps.md)
for deployment limits and [Issue 17](../Issues/017-package-distributable-macos-client.md)
for release validation status.
