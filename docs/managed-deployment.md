# Managed Mac extension approval

For a user-approved MDM deployment, configure a **System Extensions** payload
(`com.apple.system-extension-policy`) with `AllowedSystemExtensions` mapping
Team ID `HU2S8957ZY` to the single bundle ID
`com.chris.openforticlient.oftc.provider`. Do not allow the whole Team ID for
this pilot. Install the profile before OFTC so the app's activation request can
complete without a manual Network Extensions toggle. The user still needs to
choose a VPN profile and connect. Apple documents the
[payload settings](https://developer.apple.com/documentation/devicemanagement/systemextensions)
and the [Team ID to bundle ID mapping](https://developer.apple.com/documentation/devicemanagement/systemextensions/allowedsystemextensions-data.dictionary).

## What stays a user prompt

Even with that profile, a user still sees a few prompts, and they cannot be removed by
this payload:

- the installer's administrator authentication (and, for the Installer app, its "run a
  program to determine if the software can be installed" check);
- macOS's "Add VPN Configurations" prompt the first time OFTC creates a VPN entry. Its
  default button is **Don't Allow**; the user must choose **Allow**.

Without the profile, add the Network Extensions approval in System Settings and its
authentication. A managed VPN payload could pre-create the entries, but then MDM owns the
configurations and OFTC's own profiles no longer control them, so this project does not
recommend it.
