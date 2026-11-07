# Setup walkthrough

One window ("Set up OFTC", `app/Host/ComponentUpdate.swift`) carries a profile that exists on disk to
"everything ready". Its states are the rows of the walkthrough table in
`app/Host/check-setup-plan.swift`; the transitions are `SetupContinuation` in `SetupPlan.swift`.

## Approvals macOS asks for

| Mac | Approvals, in order |
| --- | --- |
| Fresh Mac (no profile) | 1. Background service (Login Items & Extensions). 2. Network extension (Network Extensions; password may be needed). 3. Add VPN configurations (one dialog). A fourth, "OFTC at login", is offered once with the first profile and can be declined. |
| Reinstalling Mac (profiles on disk) | The same list, minus whatever macOS kept: usually the service again (the uninstall removed it), the extension if it was removed, and the VPN configurations dialog if their entries are gone. Up to 3, and the window says how many before anything starts. |

They cannot be merged: each is a different OS authorization (a LaunchAgent, a system extension and a
NEVPNManager save). What the app controls is the order and that none is asked twice: the extension is
replaced only when it is not already current, and VPN entries are saved once, after the extension.

## Dead ends and silent clicks this replaces

| Before | Now |
| --- | --- |
| "Set up OFTC" with the service unapproved only opened System Settings; no window, no state | The window opens with the service as item 1, opens Login Items, and continues by itself once it is on |
| The button did nothing visible while the service started | Spinner and "Working…" at once; the button is disabled while anything is in progress |
| After approving in System Settings nothing refreshed; the user clicked again | The window fetches the host's document each two seconds after the button, and starts the next step itself |
| A run that ended while waiting needed another "Set up…" click | It starts again by itself when the component state moves, and not before (no loop) |
| "Set up…" while a run was in progress returned silently | It brings the window forward |
| Closing after success reopened Welcome | Done closes; Welcome is only shown when something is still left (#124) |

## Known limits

An old extension that macOS has queued for removal on reboot makes `component_update` fail with a
generic "reboot required" error; the document has no state for it, so the window cannot say more.
That is a host-protocol change and is left for its own issue.
