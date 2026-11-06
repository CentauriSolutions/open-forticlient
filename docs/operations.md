# Operating OFTC

The release package installs `/Applications/Open Forticlient.app` (OFTC for short;
releases before 1.2 used `OFTC.app`, which an upgrade removes), `/usr/local/bin/oftc`,
and `man oftc`. Offline build checks, Developer ID signing, notarization,
installation, extension activation, and live traffic are separate claims; this
guide says which one each step relies on.

## Install and set up

Installer opens OFTC's welcome window. If it does not appear, open **OFTC**
from Applications. The window explains where the tunnel icon lives and
offers setup, a VPN component update, or **Open VPN controls**, according to
the current setup. New users can select an existing FortiClient profile or
enter their VPN settings and PSK. Approve the OFTC Network Extension and VPN
configuration if macOS requests them. Approval is the **Network Extension**
switch behind the ⓘ button on OFTC's row under Login Items & Extensions →
Extensions; the row is listed before the switch is on. While approval is
pending, setup's **Open System Settings** button opens the Network Extensions
sheet that contains this switch. It uses an undocumented System Settings URL
and falls back to the supported Login Items opener. Setup prepares the VPN
without connecting.

An update keeps the existing OFTC profile and Keychain PSK. The app checks the
enabled provider against the bundled version with a read-only properties
request. If the provider needs an update, follow **Update VPN component** or
**Continue setup**, then return to **Open VPN controls**. A saved profile alone
does not establish that the provider update is complete. OFTC does not replace
a connected provider or downgrade a newer provider from this setup flow.

For a VPN that is already saved, **Set up…**, **Continue setup** and **Update VPN
component** show no form: OFTC activates the component and finishes each VPN's
entry itself, and shows "Waiting for approval in System Settings" until you turn
OFTC on. It asks for a PSK only if that VPN has none saved. When OFTC starts and
saved VPNs exist but the component is not ready, it does this once on its own
(never for a login-item launch).

Intentional app opening reveals the welcome window for an unacknowledged
build, or a compact controls window after acknowledgement. Automatic login/service
launch stays quiet; acknowledging a welcome does not enable VPN connection
at login. Choosing **Later** leaves setup available from the menu. Closing
the controls window leaves the menu app running; reopening OFTC brings it back.

Terminal setup remains available with `oftc setup`; see `man oftc` for explicit
setup options.

### Share profiles with a colleague

```sh
oftc export -o vpns.oftc            # every profile, in one file
oftc export office-vpn warehouse -o vpns.oftc
```

In the app, **Settings → Export VPNs…** saves the same `.oftc` file from a
Save dialog.

Your colleague installs OFTC and either double-clicks the `.oftc` file (OFTC
lists the VPNs and asks before adding them) or runs
`oftc setup --from vpns.oftc`. Either way it adds
each profile, stores its PSK in their Keychain, activates the extension, and
installs the VPN entries; they then `oftc connect`. A gateway they already have
is skipped, never changed. The file holds each profile's PSK. SAML is the real
sign-in, so the PSK is not treated as a secret, but it is still configuration
for a private gateway: share it only with the people who need it. Export
creates the file with owner-only permissions and will not overwrite one.

### Tray icon and updates

- **After install:** an interactive install opens the app, so the tray icon
  appears straight away. On a fresh install the app also turns on
  **Settings → Launch OFTC at login**, so the icon is there after every login.
  An upgrade keeps whatever you had, and turning it off stays off. Managed and
  headless installs (no Installer window) finish without opening a GUI.
- **Update notice:** the app checks a release feed at most once a day and shows
  "Version X is available" in the popover with **Download** (opens the release
  page; you install the new package the same way as the first time) and **Skip
  this version**. **Settings** has **Check for Updates Automatically** and
  **Check for Updates Now…**. It never downloads or installs anything itself:
  an update briefly stops the VPNs and may need system extension approval, so it
  stays a deliberate step.
- **Feed:** a GitHub "latest release" document (`tag_name`, `html_url`,
  `draft`, `prerelease`), https only; prereleases and drafts are never offered.
  Set it at build time with `OFTCUpdateFeedURL` in `app/Host/Info.plist`. The OFTC
  service fetches it (`check_update`); the per-user `updateFeedURL` default of earlier
  builds is no longer read. Empty means no checks. For a GitHub repository it is
  `https://api.github.com/repos/OWNER/REPO/releases/latest`. Check a feed with
  `"/Applications/Open Forticlient.app/Contents/MacOS/OFTCAgent" check-update <url>`.

### Remove a VPN

Click the **…** on a VPN's row and choose **Remove…**, or run
`oftc remove warehouse`. OFTC disconnects it, then deletes its VPN entry, saved
PSK, settings, connect-at-login choice and trusted gateway certificate. Other
VPNs keep running. Export first (`oftc export`, or **Settings → Export VPNs…**)
if you want a copy to import later.

## Connect and inspect

Open OFTC to keep its tunnel icon in the menu bar. Click the icon to see
every configured VPN. Each has its own row with its state, **Connect** or
**Disconnect**, and its own **Connect at login** checkbox. Any number of VPNs
can be connected at the same time; **Connect all** and **Disconnect all**
appear when there is more than one. Browser SSO may appear, one VPN at a time;
each row shows sign-in, connection, and recovery progress. Opening OFTC from
Applications also reveals controls when its menu icon is inaccessible.
**Disconnect** cancels recovery for that VPN only and leaves its Connect at
login choice alone. The menu bar stays available to reconnect. Use
**Settings → Add VPN…** to add another gateway.

Concurrent VPNs are separate tunnels: macOS chooses between them by the most
specific route, so two gateways that push the same prefix are ambiguous.
OFTC does not yet detect overlapping routes or conflicting DNS between
profiles; see #40.

The upper icon arches use fine lines. The tunnel is grey when disconnected.
While connected, each connected VPN's row shows its connection duration,
receive/send rates, and received/sent totals. Receiving and sending include sparklines of the
last 60 seconds, with separate scales available in their tooltips. These
count inner IP traffic carried by OFTC,
excluding IPsec overhead and traffic outside the tunnel. Totals reset on a
new connection, not on rekey. Rates are sampled once per second while
connected, including while the popover is closed. The bounded history stays
only in memory and resets on a new connection. Missing samples leave gaps
in the traces; a missing current rate is unavailable rather than zero. Last
reported totals survive sampling gaps within the same connection.

In **Settings**, **Launch OFTC at login** controls only the menu bar app.
Each VPN's **Connect at login** checkbox separately controls whether the
bundled agent connects it when you log in. Enabling either setting does not
connect immediately. New VPNs start with automatic connection off; the VPN
migrated from a single-profile install keeps its prior login behavior.
The helper uses the GUI user's home directory and presents only fixed error
categories and exit status, never raw command output. If the first connection
fails before browser sign-in, record the displayed error before trying the CLI.
**Add VPN…** opens guided setup for another gateway. **Disconnect and Quit
OFTC** stops every active connection before closing the menu app.

The same connection controls are available from the terminal:

```sh
oftc setup --import "Warehouse"   # add another VPN
oftc profiles
oftc connect                     # every profile, or: oftc connect warehouse
oftc status
oftc autostart warehouse on
oftc disconnect                  # every profile, or: oftc disconnect warehouse
```

`connect` starts one supervised connection per profile; each supervisor runs
independently and retries recoverable drops. Browser SSO may appear, one
profile at a time. On the first connection after an upgrade, it removes the
old per-user LaunchAgent plist. `disconnect` stops the named VPNs and leaves
their connect-at-login choices alone, so a deliberate stop stays down until
Connect is requested. `autostart` registers the bundled agent, which starts a
supervisor for each profile with connect-at-login on. It leaves the menu app
running. `status` shows each profile's state, the agent, login settings, and
CHILD SA rekey counts when connected. Supervisor logs are in
`~/Library/Logs/OFTC/<profile>.log`; each line the supervisor writes there starts
`OFTC supervisor:`. A supervisor ends cleanly on SIGINT or SIGTERM, and when the
gateway's certificate is not trusted it asks once in a window (decline stops it). Do not share raw SAML callbacks, PSKs, or
packet captures.

A profile is identified by a short id, such as `office-vpn`, made from its name.
A profile created before multi-profile support is migrated automatically the
first time the new app runs: its settings move into
`profiles/<id>/` and its existing VPN entry and login choice are kept.

## Update or uninstall

Disconnect OFTC before installing an update. Graphical Installer blocks an
active or recovering VPN, then uses its native app-closing declaration for
an idle running app. The final preinstall guard still requires the host to
have exited; command-line and managed installs must quit it first. Installer's
welcome and completion pages explain the controls and preserve saved settings.
Actual native app closing has not been validated with the real Installer; it is on the live checklist in [releasing.md](releasing.md).

`oftc disconnect` stops every VPN; it leaves the app open. Open **OFTC** from Applications for its controls and choose **Quit OFTC**.
For an older version with inaccessible controls, quit **OFTCAgent** in Activity
Monitor after disconnecting. Do not kill **OFTCTunnel**: it is the system-managed
VPN component. Reopen OFTC after updating and connect when ready.

If Installer reports a failure, view its log and find the OFTC package error.
The package's preinstall script reports either `OFTC is running` or
`An OFTC VPN is active` (any profile) when it refuses an update for those reasons. The generic
failure summary alone does not establish the cause. Share only the relevant
package error lines for diagnosis, rather than VPN logs or credentials.

Installing a new app can leave the older provider activated. After an update,
with OFTC disconnected, use **Settings → Add VPN…** to request approval
for the bundled provider before reconnecting. If traffic statistics remain
unavailable after an upgrade, check that the new provider is activated rather
than only installed inside the app.

```sh
oftc disconnect
# quit OFTC from its menu bar
# install the verified replacement package
oftc connect
```

### The host service

The app bundles a second launch agent, `com.chris.openforticlient.oftc.host`, in
`Contents/Library/LaunchAgents/`. It runs `OFTCAgent host serve`, the long-lived
process that serves the UI's local socket (`docs/ui-edge.md`). It starts at login,
is restarted if it exits with a failure (`KeepAlive` `SuccessfulExit` false; exit 0 on
SIGTERM or when another host already serves does not respawn it), and sets `AbandonProcessGroup`. Supervisors it
starts lead their own process groups, so restarting or killing the host leaves
their tunnels up (not yet verified live); the Network Extension owns packet flow either way.

- It is a separate Login Items entry from the login agent
  (`com.chris.openforticlient.oftc.agent`): macOS may list two items for OFTC.
  `agent-status` and `register-agent` cover the login agent only. The menu app
  registers the host service itself, by the hidden verb `OFTCAgent host register`, the first
  time it finds nothing to start (macOS may ask the user to allow it in Login Items; exit 4).
  The hidden `unregister-host` verb removes its registration, and `oftc uninstall` calls it so
  no Login Items entry is left behind.
- The package's postinstall runs
  `launchctl kickstart -k gui/<uid>/com.chris.openforticlient.oftc.host` for the
  logged-in user, so an upgrade replaces the running host with the new bundle's
  executable. It fails harmlessly if the service was never registered.
- By hand: `launchctl kickstart -k gui/$(id -u)/com.chris.openforticlient.oftc.host`
  (or `OFTCAgent host restart`). Its output is not yet written to a log file.
- The login agent's `launchctl disable` after an unexplained drop never touches
  the host service's label.

`oftc uninstall` stops the agent and VPN, unregisters the host service and the login
agent, closes the menu app, unregisters its login launch, removes OFTC's VPN configuration,
requests system extension deactivation, then invokes the package removal
helper with administrator access. It retains the OFTC profile, Keychain PSK,
and logs. Use `oftc uninstall --erase-profile` to erase that profile and its
PSK as well. If macOS defers extension removal, complete its approval or
reboot and rerun uninstall; the helper refuses to remove an active extension.

The older Fortinet-backed controller remains available from Git history (the
`legacy-controller` tag), not from the active source tree. See #17 for release
validation status. When something fails, [support.md](support.md) lists what to send.
