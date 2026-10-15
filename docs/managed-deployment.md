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
