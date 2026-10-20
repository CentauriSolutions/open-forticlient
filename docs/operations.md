# Operating OFTC

The release package installs `/Applications/OFTC.app`, `/usr/local/bin/oftc`,
and `man oftc`. Host build 26 adds independent controls, concrete menu icon masks, and
clearer update and connection handling to OFTC 1.0.5, using provider build 23.
The [build 26 record](evidence/v26-menu-visibility-and-upgrade-recovery.md) separates
offline checks, package trust, installation, and live validation.

For colleagues testing the package, use the shorter [pilot guide](pilot-validation.md)
and its [local report script](../scripts/collect-pilot-report.zsh).

## Install and set up

Installer opens OFTC's welcome window. If it does not appear, open **OFTC**
from Applications. The window explains where the tunnel icon lives and
offers setup, a VPN component update, or **Open VPN controls**, according to
the current setup. New users can select an existing FortiClient profile or
enter their VPN settings and PSK. Approve the OFTC Network Extension and VPN
configuration if macOS requests them. Setup prepares the VPN without connecting.

An update keeps the existing OFTC profile and Keychain PSK. The app checks the
enabled provider against the bundled version with a read-only properties
request. If the provider needs an update, follow **Update VPN component** or
**Continue setup**, then return to **Open VPN controls**. A saved profile alone
does not establish that the provider update is complete. OFTC does not replace
a connected provider or downgrade a newer provider from this setup flow.

Intentional app opening reveals the welcome window for an unacknowledged
build, or a compact controls window after acknowledgement. Automatic login/service
launch stays quiet; acknowledging a welcome does not enable VPN connection
at login. Choosing **Later** leaves setup available from the menu. Closing
the controls window leaves the menu app running; reopening OFTC brings it back.

Terminal setup remains available with `oftc setup`; see `man oftc` for explicit
setup options.

## Connect and inspect

Open OFTC to keep its tunnel icon in the menu bar. Click the icon, then
**Connect**. Browser SSO may appear; the popover shows sign-in, connection,
and recovery progress. Opening OFTC from Applications also reveals controls
when its menu icon is inaccessible. **Disconnect** also cancels recovery and disables
automatic VPN connection at login. The menu bar stays available to reconnect.

The upper icon arches use fine lines. The tunnel is grey when disconnected.
While connected, the popover shows connection duration, receive/send rates,
and received/sent totals. Receiving and sending include sparklines of the
last 60 seconds, with separate scales available in their tooltips. These
count inner IP traffic carried by OFTC,
excluding IPsec overhead and traffic outside the tunnel. Totals reset on a
new connection, not on rekey. Rates are sampled once per second while
connected, including while the popover is closed. The bounded history stays
only in memory and resets on a new connection. Missing samples leave gaps
in the traces; a missing current rate is unavailable rather than zero. Last
reported totals survive sampling gaps within the same connection.

In **Settings**, **Launch OFTC at login** controls only the menu bar app.
**Connect VPN at login** separately controls automatic VPN connection.
Enabling either setting does not connect immediately. New installations
leave automatic VPN connection off; an existing registered VPN agent keeps
its prior login behavior until changed or explicitly disconnected.
The helper uses the GUI user's home directory and presents only fixed error
categories and exit status, never raw command output. If the first connection
fails before browser sign-in, record the displayed error before trying the CLI.
**Set up OFTC…** reopens guided setup. **Disconnect and Quit OFTC** stops
an active connection before closing the menu app.

The same connection controls are available from the terminal:

```sh
oftc connect
oftc status
oftc disconnect
```

`connect` starts a supervised connection using the saved connect-at-login
preference and registers the agent bundled in `OFTC.app`. On the first connection
after an upgrade, it removes the old per-user LaunchAgent plist. Browser SSO
may appear. The supervisor retries recoverable drops.
`disconnect` stops the VPN, disables automatic VPN connection, and unregisters
the bundled agent, so a deliberate stop stays down until Connect is requested.
It leaves the menu app running. `status` shows VPN and agent state, both login settings,
nonsecret profile settings, and CHILD SA rekey counts when connected. Agent
logs are in `~/Library/Logs/OFTC/agent.log`. Do not share raw SAML callbacks,
PSKs, or packet captures.

## Update or uninstall

Disconnect OFTC before installing an update. Graphical Installer blocks an
active or recovering VPN, then uses its native app-closing declaration for
an idle running app. The final preinstall guard still requires the host to
have exited; command-line and managed installs must quit it first. Installer's
welcome and completion pages explain the controls and preserve saved settings.
Actual native app closing remains a pilot validation step for build 26.

`oftc disconnect` stops the VPN and its background agent; it leaves the app
open. Open **OFTC** from Applications for its controls and choose **Quit OFTC**.
For an older version with inaccessible controls, quit **OFTCAgent** in Activity
Monitor after disconnecting. Do not kill **OFTCTunnel**: it is the system-managed
VPN component. Reopen OFTC after updating and connect when ready.

If Installer reports a failure, view its log and find the OFTC package error.
The build 24 preinstall script reports either `OFTC is running` or
`OFTC VPN is active` when it refuses an update for those reasons. The generic
failure summary alone does not establish the cause. Share only the relevant
package error lines for diagnosis, rather than VPN logs or credentials.

Installing a new app can leave the older provider activated. After an update,
with OFTC disconnected, use **Settings → Set up OFTC…** to request approval
for the bundled provider before reconnecting. If traffic statistics remain
unavailable after an upgrade, check that the new provider is activated rather
than only installed inside the app.

```sh
oftc disconnect
# quit OFTC from its menu bar
# install the verified replacement package
oftc connect
```

`oftc uninstall` stops the agent and VPN, closes the menu app, unregisters its
login launch, removes OFTC's VPN configuration,
requests system extension deactivation, then invokes the package removal
helper with administrator access. It retains the OFTC profile, Keychain PSK,
and logs. Use `oftc uninstall --erase-profile` to erase that profile and its
PSK as well. If macOS defers extension removal, complete its approval or
reboot and rerun uninstall; the helper refuses to remove an active extension.

The older Fortinet-backed controller remains available from Git history, not
from the active source tree. See [initial rollout gaps](initial-rollout-gaps.md)
for deployment limits and [Issue 17](../Issues/017-package-distributable-macos-client.md)
for release validation status.
