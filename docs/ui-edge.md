# The Swift UI edge

Status: proposal for Issue 47, revision 2 (socket API). Nothing in the shipping
UI changes with this document. All examples use `vpn.example.com` and
`203.0.113.0/24`.

The UI stays native AppKit, written in Swift, behind one narrow edge. The Rust
host owns profiles, Keychain, the supervisor, the CLI, SystemExtensions,
`SMAppService` for the agent, and every write to the NetworkExtension
preferences (Issue 46, process model A). The Swift UI reads state and requests
actions; it never owns either. Revision 2 makes the edge a **local socket API
served by a long-lived Rust host process**, so the host's and the UI's process
lifecycles are independent.

Decisions already taken by the user: Swift UI stays; the UI reads no files and
takes no locks; the UI talks to the host only through the socket; the CLI is a
client of the same API and keeps a direct fallback; the host is a separate launch
agent; a typed PSK goes to a stdin child; **the host serves traffic from the first
release, so the UI has no NetworkExtension dependency at all and does not speak
`oftc.traffic.v1`**; About is the standard macOS panel plus a short "Details" line
(a custom panel may be revisited later).

## 1. What the Swift UI may depend on

| # | Dependency | Use |
| --- | --- | --- |
| 1 | The host socket (sections 3 to 6), spoken only by `HostEdge.swift` | every fact shown, every action requested |
| 2 | Foundation, AppKit, `Network` (for the unix-domain connection), `UserDefaults`, the UI's own `Application Support/<bundle id>/ui/` directory | views, UI-private state (welcome acknowledgement, update skip, `menu.lock`) |

The UI does **not** read `supervisor-status.json`, `profile.json`, `profiles/`,
lock files or the C snapshot (`oftc_host_snapshot_json`); it links no Rust symbol.
Today `SupervisorStatusStore.read` takes a `flock` on `supervisor.lock` and calls
`kill(pid, 0)`; Rust already does that in `core/host/src/status.rs`
(`StatusStore::read`), and the socket's answer is the `phase` field.

The Swift UI must not: read Keychain, import `Security`, `CryptoKit`,
`SystemExtensions` or `ServiceManagement`, call
`NETunnelProviderManager.loadAllFromPreferences` or `saveToPreferences`, open a
socket or `URLSession` anywhere except `HostEdge.swift`, parse `profile.json`,
`.oftc` bundles, FortiClient plists or provider messages other than
`oftc.traffic.v1`, or reference an engine or provider symbol.

All of dependency 1 and 2 enters through **`HostEdge.swift`** (new): a
non-blocking client with Codable `HostStatus`, `HostProfile`, `HostError`,
`HostEdge.request(...)` and a `HostEdge.events` callback. Views and view models
import none of `Network`, `Process` or `NetworkExtension`.

## 2. Which process serves the socket

Today nothing long-lived serves anything. The login agent
(`com.chris.openforticlient.oftc.agent`, `OFTCAgent supervise-autostart`,
`RunAtLoad` true, `KeepAlive` false) starts a supervisor per connect-at-login
profile and exits. Supervisors are separate short-lived processes, one per
profile. The menu app is entitled but runs only while the user has it open.
Candidates:

| Candidate | Lifecycle | Verdict |
| --- | --- | --- |
| **A. The existing login agent, made resident** | starts at login, but its plist is `KeepAlive` false and the supervisor calls `launchctl disable` on that label after an unexplained drop so a bad session is not reconnected at the next login (`agent.rs`, `Launchctl::disable`). Disabling the agent would also take the socket down | rejected: the socket would die exactly when the user most needs status |
| **B. The menu app** | exists only while the UI runs; the CLI and the next UI launch would have no server; couples the lifecycles the user wants decoupled | rejected as the server (it stays a client) |
| **C. A supervisor** | one per profile, exits when its tunnel ends | rejected: many, short-lived |
| **D. A new second launch agent, `...oftc.host`, running `OFTCAgent host serve`** | resident from login (`RunAtLoad`), restarted on crash (`KeepAlive`), registered with `SMAppService.agent(plistName:)` like the existing one, same entitled main executable so it may use NetworkExtension and SystemExtensions | **recommended** |

Design of D:

- New bundled plist `Contents/Library/LaunchAgents/com.chris.openforticlient.oftc.host.plist`:
  `BundleProgram` `Contents/MacOS/OFTCAgent`, arguments `host serve`, `RunAtLoad`
  true, `KeepAlive` true, `ProcessType` `Interactive`, `AbandonProcessGroup` true
  (see the risk in section 15: supervisors it starts must outlive it). A hidden
  verb pair `host serve` / `host restart` follows the existing `hidden(...)`
  rows in `commands.rs`, so the usage text stays byte for byte.
- It is registered by the same `register-agent` path (`agent.rs` already wraps
  `SMAppService.agent`), by `oftc setup`, the installer's postinstall, or the UI's
  first run. macOS asks the user to allow background items once; the exact
  prompt count for two agents in one app is **not verified**.
- `launchd` socket activation (a `Sockets` key) was considered and dropped: the
  plist is bundled and static, so it cannot name a per-user path, and
  `SecureSocketWithKey` hands the path over through the environment, which a UI
  process cannot read portably. The agent binds the socket itself.
- Upgrade: the installer replaces the bundle and runs
  `launchctl kickstart -k gui/<uid>/com.chris.openforticlient.oftc.host` (or the
  `host restart` verb); the UI notices a lower `host.build` than its own at the
  hello (section 6) and asks for the same restart.
- The agent stays out of the tunnels' way: the provider extension owns packet
  flow, supervisors own reconnect. Stopping or crashing the host never stops a
  tunnel.
- When the user has not approved or registered the agent, the socket does not
  exist; section 7 covers what the UI does.

## 3. Socket location and permissions

- Path: `~/Library/Application Support/<bundle id>/host.sock`. That directory
  is the host's existing per-user directory, created `0700` by `make_private_dir`
  (`lease.rs`). The socket is created `0600`. `sun_path` allows 104 bytes; the
  suffix is about 68 bytes, leaving about 29 characters for the user name, so the
  server checks the length at startup and refuses to start with
  `host_unavailable: path too long` rather than truncating. (Bundle id of a
  development variant counts too.)
- Unix-domain only; no TCP or UDP listener, ever. Nothing is exposed to the
  network.
- Single instance: the server takes an exclusive `flock` on `host.lock` in the
  same directory. Holding the lock, it removes a leftover `host.sock` and binds a
  new one; without the lock it exits 0. Because only the lock holder unlinks, a
  stale socket after a crash or reboot is replaced and a live server is never
  displaced. A client `connect` that fails with `ECONNREFUSED` or `ENOENT`
  means "not running".
- Peer check on every accepted connection: `getsockopt(SOL_LOCAL, LOCAL_PEERCRED)`
  and require `cr_uid` equal to the server's uid; otherwise close without a
  reply. This lives in the `os` module (the only `unsafe` in `core/host`).
  Same-uid code can already run `oftc` and the Keychain ACLs apply regardless,
  so the check is defence against other local users and a mis-set directory
  mode, not against the user's own malware. A code-signature check of the peer
  (`LOCAL_PEERPID` and `SecCodeCheckValidity`) is possible and **not**
  recommended: it breaks development builds and the CLI and adds a `Security`
  dependency to the host for a threat the Keychain ACL already covers.
- No secret ever crosses the socket: no PSK, SAML token, cookie, private key.
  Verbs that need a typed PSK are section 4.4.

## 4. Wire protocol

### 4.1 Framing

Newline-delimited JSON (NDJSON), UTF-8, one object per line, at most 64 KiB per
line (longer: the receiver closes). One connection carries many requests; each
request has a client-chosen integer `id` and every reply, progress and result
echoes it. Events have no `id`. The server answers requests on a connection in
order of completion, not of arrival; a client matches by `id`.

### 4.2 Handshake and versioning

First line from the client:
`{"id":1,"op":"hello","protocol":[1,1],"client":{"kind":"ui","version":"0.9.0","build":"24"}}`
where `protocol` is `[min, max]` supported. Reply:
`{"id":1,"ok":true,"result":{"protocol":1,"host":{"version":"0.9.0","build":"24","provider_build":"24"}}}`.
The server picks the highest protocol both support. No overlap:
`{"ok":false,"error":{"code":"unsupported_schema","exit":5,...}}` and the server
closes. Any other op before `hello` is rejected the same way. Within one
protocol number, changes are additive: unknown fields and unknown ops are
ignored by the receiver (unknown ops get `unknown_op`), and unknown enum values map
to `attention` for `state` and to "unavailable" elsewhere. A breaking change
bumps the number, and the host supports the current and previous number for one
release.

### 4.3 Operations

| `op` | Arguments | Result |
| --- | --- | --- |
| `hello` | section 4.2 | host block |
| `status` | | the status document (4.5) |
| `subscribe` | `topics`: any of `status`, `traffic` | `{}`, then events |
| `unsubscribe` | | `{}` |
| `connect`, `disconnect` | `profile` (optional: all) | `{}` once the host has started or stopped; later phase in events |
| `remove` | `profile` | `{}` |
| `export` | `profiles` (optional), `path` | `{}`; the host writes the file, mode `0600`, refusing to overwrite (the UI keeps its scratch-then-copy step) |
| `import_preview` | `path` | contents, `already_configured` per item, **no PSK** |
| `import` | `path` | `{ "added": [ids] }` |
| `add_profile` | `gateway`, `saml_port`, `transport`, `name`, `psk_source` | progress then result (4.6). `psk_source` is `"saved"`, `"forticlient"` plus `label`, or `"stdin_job"` (4.4) |
| `list_sources` | | importable FortiClient profiles: `label`, `gateway`, `saml_port`, `already_configured`; never a PSK |
| `component_update` | | progress then result; `tunnels_active` if any profile is up |
| `settings_set` | `key`: `menu_login`, `auto_start:<id>`, `auto_update`; `value` | `{}` |
| `check_update` | | `{ "available": { "version", "page" } \| null }`; the host fetches |
| `open_settings` | `pane`: `extensions` or `login_items` | `{}` |
| `cancel` | `target`: an earlier request `id` | `{}` |

Not on the socket: `activate`, `install-config`, `supervise-*`, `rekey-*`,
`uninstall`, `erase-profile`. The host composes them inside the ops above.

### 4.4 Secrets

The one secret the UI handles is a PSK the user types into the add form. It does
not go on the socket. Recommended: the UI runs the existing direct verb
(`provision-psk --stdin`, already in the Rust verb table) as a short-lived child
with the PSK on a pipe to stdin, then sends `add_profile` with
`"psk_source":"saved"`. That is the only use of `Process` besides `host restart`,
and both are in `HostEdge.swift`. The alternative, passing a one-shot pipe file
descriptor with `SCM_RIGHTS` over the socket, keeps one transport but needs
`sendmsg` control-message code in Swift that `Network` cannot do. The
FortiClient-import path never exposes the PSK to the UI at all: the host reads
it from the FortiClient profile (`migrate-psk` exists). `.oftc` imports pass a
path; the host parses the file.

### 4.5 Status document

Stable, versioned, nonsecret. No PSK, token, certificate, cookie or file path
that includes a user name. The same document is the `result` of `status` and the
payload of `status` events.

```json
{
  "schema": 1,
  "generated": "2026-11-04T12:00:00Z",
  "seq": 1771,
  "host": { "version": "0.9.0", "build": "24", "provider_build": "24" },
  "component": { "state": "ready", "installed_build": "24", "expected_build": "24" },
  "login": { "menu_item": "enabled", "agent": "enabled", "host_agent": "enabled" },
  "profiles": [
    {
      "id": "c2", "name": "Office VPN", "gateway": "vpn.example.com",
      "saml_port": 9443, "transport": "udp", "auto_start": true,
      "state": "connected", "ne_status": "connected", "phase": "connected",
      "connected_since": "2026-11-04T11:18:00Z",
      "traffic": { "session": "9f1c", "rx_bytes": 842000000, "tx_bytes": 96000000,
                   "rx_rate": 1200000.0, "tx_rate": 84000.0, "sample_seq": 1771 },
      "error": null
    }
  ]
}
```

| Field | Type | Values and rules |
| --- | --- | --- |
| `schema` | int | equals the negotiated `protocol` |
| `seq` | int | increases on every change; a reconnecting client ignores older |
| `host.version`, `host.build`, `host.provider_build` | string | marketing version, `CFBundleVersion`, bundled provider build. Feeds About. |
| `component.state` | enum | `checking`, `ready`, `missing`, `update_required`, `approval`, `newer`, `unavailable` (`VPNComponentState.resolve`, computed in Rust) |
| `component.installed_build`, `expected_build` | string or null | for the "Details" line and the update view |
| `login.*` | enum | `enabled`, `disabled`, `requires_approval`, `not_found` |
| `profiles[].id` | string | 1 to 32 of `[a-z0-9-]` |
| `profiles[].state` | enum | `connected`, `disconnected`, `connecting`, `disconnecting`, `sign_in`, `reconnecting`, `attention`, `setup` (`MenuConnectionState.resolve`, computed in Rust from NE status, supervisor phase, a stopping flag and the component state). The UI maps it to localised text and does not recompute it. |
| `profiles[].ne_status` | enum or null | raw NE status, for support output |
| `profiles[].phase` | enum or null | `acquiring`, `connecting`, `connected`, `recovering`, `failed`, `stopped`; null without a live supervisor (the liveness rules of `StatusStore::read`) |
| `profiles[].traffic` | object or null | present while connected and sampled. Rates are bytes per second derived in Rust; null while a sample is unavailable. `session` changes on a new provider connection; totals survive a rekey. |
| `profiles[].error` | object or null | `{ "code", "detail" }`, codes in 4.7 |

The profile fields (`id`, `name`, `gateway`, `saml_port`, `transport`,
`auto_start`, `phase`) are exactly what `core/host/src/snapshot.rs` already
computes; section 8 says how it is reused.

### 4.6 Events and progress

Events, server to client, only after `subscribe`:

```json
{"event":"status","seq":1772,"status":{ ... the status document ... }}
{"event":"traffic","profile":"c2","session":"9f1c","rx_bytes":842100000,"tx_bytes":96050000,"rx_rate":1100000.0,"tx_rate":80000.0,"sample_seq":1772}
```

`status` is sent when the document changes, debounced to at most one per 100 ms;
`traffic` once per second per connected profile, and only while some client
subscribes to `traffic`, so an idle host does no sampling. A new subscriber gets
the current `status` immediately. The UI therefore never polls. Progress for a
long op shares the request id:

```json
{"id":9,"event":"progress","step":"extension_approval","state":"waiting"}
{"id":9,"ok":true,"result":{"profile_id":"c2"}}
```

`step` is an enum (`keychain`, `profile`, `extension_approval`, `vpn_entry`,
`sign_in`, ...); the UI owns the wording. `waiting` means "needs the user" and is
not a failure. Closing the connection does not cancel an op; the host's ops are
idempotent (`install-config`, `remove` of an absent profile) so finishing is
safe, and `cancel` is explicit.

### 4.7 Errors and exit codes

Failure reply: `{"id":N,"ok":false,"error":{"code":"...","detail":"...","exit":4}}`.
The CLI, as a client, exits with `exit` and with `--json` prints the object
unchanged: `0` ok, `2` usage, `3` configuration, `4` needs user action, `5` host
unavailable or protocol mismatch, `6` busy, `1` anything else. `code` is the
stable part and replaces the substring match in `MenuCommandFailure.classify`:

| `code` | exit | Replaces |
| --- | ---: | --- |
| `approval_required` | 4 | "requires-approval", "allow oftc in system settings" |
| `psk_unavailable` | 4 | "psk is unavailable" |
| `not_configured` | 3 | "profile unavailable", "no oftc profile" |
| `already_configured` | 3 | new; carries `profile_id` |
| `migration_needed` | 3 | "different app", "legacy login agent" |
| `agent_unavailable` | 5 | "login agent", "bundled oftc agent" |
| `host_unavailable` | 5 | new; client-side when the socket cannot be reached |
| `unsupported_schema` | 5 | new |
| `tunnels_active` | 3 | new |
| `busy` | 6 | new; another op holds that profile's lock |
| `unknown_op` | 2 | new |
| `internal` | 1 | everything else; `detail` is for the log, never shown verbatim |

`timeout` and `launch` stay UI-side. The user-facing messages stay in Swift and
`en.lproj`.

## 5. CLI and traffic

### 5.1 The CLI is a client

`oftc status --json`, `oftc profiles --json`, `oftc --version --json`, `connect`,
`disconnect`, `remove`, `export` and `check-update --json` connect to the socket,
send one request and print the reply. `--json` prints the protocol's object, with
the same error codes and exit codes as 4.7. Without `--json` the human text is
unchanged. `oftc` **falls back to running the verb directly** through the host
executable when the socket is unavailable, as it does today, because a client
that needs a server cannot be the thing that starts and registers the server:
`setup`, `register-agent`, `host restart`, `uninstall` and `status` on a Mac whose
agent is not approved must still work. In direct mode the document comes from the
same Rust functions, so the output is the same.

### 5.2 Traffic

The host owns the provider message. It subscribes to NE status through
`VpnControl::subscribe`, and while at least one client subscribes to `traffic` it
sends `oftc.traffic.v1` once per second per connected profile (the message and its
reply stay byte compatible, so mixed host and provider builds keep working),
derives rates, and emits the `traffic` events of 4.6. The UI never imports
`NetworkExtension`. The UI keeps the 120-sample history ring and the sparklines;
they are display state.

## 6. Mixed versions

| Case | Behaviour |
| --- | --- |
| old UI, new host | the old UI has no socket client and keeps using the files and the C snapshot, which the new host does not remove until the UI migration (PR 10) lands; after that the bundle ships one UI, so the case is a UI left running across an upgrade. The `hello` from an old client does not exist, so the server sees no `hello` and closes; the old UI shows its existing unavailable state until relaunched. Not silently wrong. |
| new UI, old host (UI launched before the host agent restarted) | `hello` reports `host.build` lower than the UI's: the UI shows "OFTC is finishing an update", runs `host restart` (direct), reconnects. If the old host predates the socket, the connect fails and the UI shows `host_unavailable` and starts the agent (7). |
| protocol N UI, N+1 host | the host supports N and N+1 for one release; negotiated to N. |
| protocol N+1 UI, N host | negotiated to N if the UI supports N, else `unsupported_schema`: "Update OFTC", actions disabled. |
| bundle replaced while the host runs | the running host keeps its old inode; the installer's `kickstart -k` and the UI's restart prompt replace it. Supervisors are not children of it (section 15). |

## 7. When the host is not running

`HostEdge` is a small state machine on its own serial queue:
`connecting` to `ready` or `unavailable(reason)`. Every socket call is
non-blocking (`NWConnection` over `NWEndpoint.unix(path:)` with callbacks), the
reconnect timer runs off the main thread, and the main thread only receives
finished `HostStatus` values. No view waits on the socket.

1. Connect fails with `ENOENT` or `ECONNREFUSED`: state `unavailable`. The UI
   shows a single row, "OFTC's VPN service is not running", with the previous
   profiles greyed rather than removed (the last document is kept, marked stale),
   and every action disabled except "Start service".
2. It tries once to start the host: run `launchctl kickstart gui/<uid>/<host label>`
   (a short child inside `HostEdge`, with a timeout), then retries the connect
   with backoff 0.5 s, 1 s, 2 s, 5 s, then every 30 s. It stops retrying while the
   menu is not visible and no window is open, and retries once on window open
   and on wake.
3. If kickstart reports the service is not registered or needs approval, the
   state is `unavailable(approval)`: the row links to Login Items & Extensions
   (`open_settings` is a socket op, so for this case the UI runs the direct
   `register-agent` / settings verb) and the Welcome flow's existing wording.
4. A request in flight when the connection drops fails with `host_unavailable`
   (exit 5 for the CLI); the UI does not retry a non-idempotent op itself. On
   reconnect it re-sends `hello` and `subscribe` and takes the fresh document.
5. `Quit` still disconnects tunnels first: with the host down it cannot, and
   says so instead of hanging (the existing `quitAfterStop` timeout applies).

## 8. How it composes with the merged host code

`core/host` already provides what the server serves; the server adds transport,
protocol and the live parts. Nothing below changes a format that a Swift reader
or an old supervisor uses.

| Existing (`origin/main`) | Used for |
| --- | --- |
| `registry.rs`, `profile.rs` | profile list and fields in the status document |
| `snapshot.rs` (`json`: id, name, gateway, port, transport, `phase`, `connectAtLogin`) | **the source of the profile fields.** The server calls the same function (or its typed inner form) and the `ui-edge` crate maps it to schema 1. The camelCase C snapshot (`oftc_host_snapshot_json`, `oftc_host_free`) stays until the UI migration lands, then is deleted with its Swift caller. |
| `status.rs` (`StatusStore::read`: age, lock probe, pid check) | `phase` and its liveness rules, unchanged |
| `lease.rs` (supervisor lease, stop request, SAML lock, `make_private_dir`, `write_private`) | the host's directory handling reused for `host.lock` and the socket directory; the same `flock` discipline |
| `intent.rs` | `auto_start`, `settings_set auto_start:<id>` |
| `agent.rs` (`SMAppService.agent`, `Launchctl`) | registering the host agent; `kickstart` joins `enable`/`disable` on the `Launchctl` trait so it is faked in tests |
| `commands.rs` (`run(args, env, backends, io) -> i32`, `Out`, golden verb table, `VERBS`) | verbs the server runs: the socket ops call the same internal functions the verbs call, returning typed results; the verb printers format those results, so text and JSON cannot drift. `host serve` and `host restart` are added as `hidden(...)` rows so the usage text stays byte for byte. |
| `vpn.rs`, `oftc_apple::manager::{VpnControl, VpnEntry, Subscription}` | NE status read and subscribe, `send` of `oftc.traffic.v1`, start and stop |
| `supervisor.rs`, `start.rs` | `connect`, `disconnect`; unchanged |
| `trust.rs` | the certificate prompt keeps its child-process edge (exit 10, 11, 12) |
| `out.rs` (`Out`, `Capture`) | the server captures verb output the same way the tests do |
| `hostlib` (`oftc_host_main`) | `host serve` is one more branch of it; Swift `main` still only forwards argv |

New code: one module tree `core/host/src/serve/` (listener and peer check,
framing, protocol, session, state resolution), the `os` module's
`peer_uid` (the only new `unsafe`, quarantined), and a new crate
`app/core/ui-edge` holding the wire types, golden JSON files and the
exit-code table shared by server, CLI client and tests (Swift decodes the same
documents; the golden files are also decoded by a Swift check, so the two
languages share one pinned contract).

## 9. Concurrency and ownership

| Thing | Owner | UI rule |
| --- | --- | --- |
| Profile files, Keychain items, NE preferences, extension activation | Rust host | never touch |
| `supervisor.lock`, supervisor status record, stop request, SAML browser lock | Rust host | never open; read `phase` |
| `host.lock`, `host.sock`, the socket directory | host agent | never open the lock; connect to the socket only |
| Per-profile operation lock (`connect`, `disconnect`, `remove`, `add_profile`, `component_update`) | Rust host | a second op gets `busy`; the UI also disables the row while its own request runs |
| `menu.lock`, welcome acknowledgement, update-skip record, `ui/` directory | Swift UI | single UI instance; nothing else reads them |
| Status | the host's one in-memory document, rebuilt on change | read-only copies over the socket |

Ops are idempotent where they can be. The server runs each op on a worker and
never holds a global lock across an op, so a slow sign-in blocks only its
profile. The UI keeps its optimistic `stoppingSince` display state; the host's
status is the truth that clears it.

## 10. Enforcement

`app/ui-files.txt` lists the UI Swift files (an explicit list; moving files to a
directory would collide with other in-flight ports). `app/check-ui-edge.sh`,
called from `build.sh` before compiling, fails when a listed file other than
`HostEdge.swift` matches any of:

```
import (Security|CryptoKit|SystemExtensions|ServiceManagement|NetworkExtension|Network)
SecItem|kSec|Keychain|NETunnelProviderManager|saveToPreferences|loadAllFromPreferences
SMAppService|OSSystemExtension|URLSession|NWConnection|socket\(|connect\(|profile\.json|supervisor\.lock|supervisor-status|oftc_(ffi|engine|provider|host)
```

`HostEdge.swift` may use `Network` and `Process`, and none of `NetworkExtension`,
`Security`, `CryptoKit` or `SystemExtensions`. The check is a
**ratchet**: current violations are recorded in `app/ui-edge-baseline.txt` (file,
pattern, count), the check fails on any new match or any count above baseline,
and CI fails if the baseline file grows in a PR. Lines for deleted files are
ignored. A fixture covers the script. The baseline reaches empty with PR 15.

## 11. Audit of the current UI files

Line counts are today's. "Violation" means a dependency outside section 1.

| File | Lines | What it is | Violations | Verdict |
| --- | ---: | --- | --- | --- |
| `MenuBar.swift` | 1321 | status item, popover, menu, controller. Also: reads `NETunnelProviderManager`, `SupervisorStatusStore`, `OFTCProfileScope`, `OFTCAgentService`, `SMAppService`, `LauncherAlias`, `UpdateFeed` (network), `OFTCProfileBundle.decode` (PSKs), export file I/O, `quitAfterStop` logic | NE read and `sendProviderMessage`, SMAppService x4, profile directory and supervisor file reads, bundle decode, URLSession via `UpdateFeed`, file writes outside `ui/` | **Shrink** to views, view model, status-item and dialogs over `HostEdge`. The runtime/NE half (about 450 lines: `TunnelRuntime`, `refresh`, `syncProfiles`, `syncStatusObservers`, `sampleTraffic`, `tunnelPresentation`'s resolve) becomes `HostStatus` mapping fed by the socket's `subscribe` stream. |
| `MenuModel.swift` | 170 | `MenuConnectionState` and `resolve(status:phase:)`, `TrafficFormat`, view-model structs, preview data | `resolve` imports NE status types | **Keep, shrink**: `resolve` is deleted (Rust computes `state`; its test cases move to `cargo test`); titles, details, formatting and view models stay because they carry the localised text. |
| `MenuCommand.swift` | 154 | process runner with bounded pipes and timeout; error classify by substring | classify scrapes text | **Shrink to almost nothing**: the socket replaces the process runner. Keep one small `Process` helper inside `HostEdge.swift` for the two direct-mode cases (typed PSK on stdin, `host restart`), with its timeout; delete `classify`. |
| `ControlsWindow.swift` | 40 | window around the same view controller | none | **Keep.** |
| `RateSparklineView.swift` | 57 | custom `draw`, accessibility | none | **Keep.** Spike section 9 shows a Rust port draws identically and costs more. |
| `TrafficHistory.swift` | 104 | rate ring (120 samples, 60 s, gaps) and `RateSparkline` geometry | none (pure) | **Keep.** Pure display state; moving it would put 60 points per profile per second on the edge. Input becomes rates from the status JSON. |
| `Welcome.swift` | 172 | welcome window presentation, preview rendering | none | **Keep.** |
| `LaunchExperience.swift` | 154 | `VPNComponentState.resolve` (SystemExtensions records), `WelcomePresentation`, `LaunchExperienceStore`, `MenuLoginDefaultStore`, `AppLaunchReason` | `resolve` encodes provider-readiness rules | **Split.** `VPNComponentState.resolve` and `canReplace` go to Rust (`component.state`, check cases move to `cargo test`). The rest stays: UI-private files in `ui/`. |
| `Onboarding.swift` | 364 | add form and the whole setup transaction | `Security` (`SecItem*`), `NETunnelProviderManager` save/enable, `OSSystemExtensionRequest` and delegate, `SMAppService` link, `MigrationBridge.psk`, FortiClient plist parse, `OFTCProfileScope.add`, gateway uniqueness check | **Shrink hard** to about 150 lines: form, `--list-sources`, run `setup --json-progress`, render steps. All of `setUp`, `performSetup`, `savePSK`, `hasPSK`, `installVPNEntry`, `complete` and the delegate leave. |
| `UpdateCheck.swift` | 138 | `AppVersion`, feed parse, `URLSession` fetch, `UpdateStore` | network and parse | **Port** `AppVersion`, `UpdateFeed`, fetch to Rust (`check-update --json`); `UpdateStore` (skip, last checked, automatic) stays UI-private. |
| `GatewayTrustPrompt.swift` | 213 | alert in a child process: stdin JSON in, exit 10, 11 or 12 out | uses `GatewayCertificate(der:)` (Security) to format fingerprint and names | **Keep, shrink.** Already a clean edge. The host passes pre-parsed fields (subject, issuer, SHA-256, validity) and the child does no certificate parsing. Exit codes and `review-certificate` argv stay. |
| `check-menu*.swift`, `check-experience.swift` | 276 | offline checks of the above | n/a | **Move with the subject.** Cases for `resolve`, `VPNComponentState` become Rust tests; cases for formatting, history, command runner stay Swift. A case that duplicates another is dropped (AGENTS.md). |

Files the UI uses today that are **not UI** and belong to Issue 46:
`ProfileScope`, `OFTCProfile`, `ProfileBundle`, `AgentService`, `AgentIntent`,
`SupervisorStatus`, `ProviderReadiness`, `LauncherAlias`, `GatewayTrust`,
`MigrationBridge`, `ReconnectSupervisor`. After the edge lands the UI imports
none of them.

Expected Swift UI size after the edge: roughly 1,800 to 2,000 lines from
about 2,900 (an estimate from the splits above, not a measurement).

## 12. Parity study (spike not merged)

The throwaway spike (Rust and Swift builds, `compare.sh`) is not merged, per the
spike-hygiene rule; this section records its results.

Question: can Rust with `objc2-app-kit` match native for the status item with a
template image, a menu, and a small controls window? The spike builds the same
surface twice and renders both headlessly (`cacheDisplay` into a bitmap, light
and dark appearance): a controls window with a bold label, a label, a
custom-drawn accessible sparkline view, a checkbox and a button in an
`NSStackView`; a template status-item icon (the real OFTC icon path); an
`NSMenu` with target/action items (About, Quit) attached to an `NSStatusItem`.

| Measure | Result |
| --- | --- |
| Pixels, controls window light and dark | **byte-identical PNGs** between the Rust and Swift builds (321x272); both contain drawn content (checked by counting non-transparent pixels, after a first run in which both were blank because the harness did not size the view) |
| Pixels, template icon | byte-identical (44x40) when rendered through `NSImageView` headlessly; see the limits below |
| Builds | compiles offline with exact-pinned `objc2 0.6.5`, `objc2-app-kit 0.3.2`, `objc2-foundation 0.3.2`, `block2 0.6.2`; needed `default-features = false` plus a hand-picked feature list (about 30 names) because the default pulls `objc2-core-text`, absent from the offline cache |
| Runs | the interactive build ran 3 s, created the status item and window, no panic |
| Lines of code | 182 Rust vs 112 Swift for the same surface (1.6x) |
| `unsafe` | 17 of 182 lines mention it (some are the `#[unsafe(method)]` attributes of `define_class!`): the `NSView` subclass, accessibility setters, `NSButton`/`NSMenuItem` constructors that take a target, `NSWindow` init. Counted by `grep -c unsafe`, not audited line by line |
| Accessibility | role, label and element flags on the drawn view are settable from Rust; **not verified** with VoiceOver |
| Localisation | not tested; `NSLocalizedString`/`.strings` work the same underneath but Rust has no `genstrings` equivalent, so strings would be hand-extracted |

**Not verified:** the live menu bar (I could not screenshot the display, so the
icon was never seen in a real status bar; the Swift code deliberately uses
bitmap representations "to avoid deferred drawing in the menu bar's rendering
context" and my Rust icon uses a drawing handler, so the headless result does
not transfer), `NSPopover` (not built), the full 1,300-line `MenuBar.swift`
behaviour, dark-mode status bar tinting, VoiceOver, localisation, resize and
Auto Layout edge cases. The Rust side compiled and rendered; it was not
exercised interactively by a person.

**Verdict.** Rust can reach pixel parity because both call the same AppKit.
It does not reach parity on cost: more lines, `unsafe` at the widget boundary
(contradicting spike-hygiene rule 5 unless wrapped in a module whose size would
rival the Swift it replaces), a hand-maintained feature list, no tooling for
strings, and `define_class!` boilerplate for every delegate and view subclass.
Nothing observed is a benefit that Swift lacks. **The UI stays Swift behind the
edge**, as the plan's default said. The study does not argue for Option B.

## 13. Known UI defects: design

### 10.1 "Update VPN component" shows the add-a-VPN form

Cause (read from the code): `OFTCOnboarding(updating: true)` only changes the
title, the explanation and the button label. `buildWindow` always builds the
name, gateway, port, transport and PSK rows, `buildSources` always appends
"Enter settings manually", and `setUp` always runs `performSetup`, which
validates the form and rejects with "That gateway is already set up in OFTC"
because `createdEntry == nil` and the gateway exists. The update path goes
through the add path.

Fix: a separate, form-less **component update** view (same window chrome, no
fields): installed build, bundled build, one explanatory paragraph, one
"Update" button, a progress line, and the "Open System Settings" button while
approval is pending. It sends the `component_update` request and renders its `progress` events
(`extension_approval`, `done`). The host refuses with `tunnels_active` if any
profile is connected (the UI also disables the button, as today). No profile,
PSK or Keychain access is involved, so the existing profiles are untouched by
construction. `showSetup()` routes by `component.state`: `update_required` opens
the update view; `missing` and `approval` open the add view; a gateway that
already exists returns `already_configured` with the profile id and the UI says
so and offers to select it. Welcome's `.setup` action uses the same routing.

### 10.2 No menu-bar access to version info or options

Today a click opens the popover and the options sit behind its gear button; the
app has no visible main menu (accessory policy) and no About item. Design for
later work: add **About OFTC** (`NSApp.orderFrontStandardAboutPanel`, plus a short "Details" line reading
`Extension build X, provider build Y` from `host.build`, `component.installed_build`
and `host.provider_build`) and the
existing options (login, updates, add, export, Login Items & Extensions) to one
shared `NSMenu`, used both by the gear button and by right-click or ctrl-click on
the status item, and mirrored in the application menu shown while a window
is open. The edge already carries the version fields; nothing else is needed
from the host. Ships after the adapter, independent of the Rust work.

## 14. PR stack

Sizes are estimates in changed lines. "#46" means a piece already on `origin/main`
(`core/host`, `hostlib`, `core/apple`; the supervisor port #95 is merged).

| # | PR | Size | Needs | Parallel with |
| --- | --- | ---: | --- | --- |
| 1 | `docs: UI edge contract` (this file; plan and architecture links; spike stays on a branch) | ~700 doc | none | 2, 3 |
| 2 | `build: ratchet check for the UI edge` (`ui-files.txt`, script, baseline, fixture, `build.sh` call) | ~200 | 1 | 3 |
| 3 | `feat(ui-edge): wire types` (`core/ui-edge`: requests, events, status document, error and exit tables, golden JSON, ignore-unknown and `hello` tests) | ~600 Rust | 1 | 2 |
| 4 | `feat(host): serve skeleton` (`serve/`: the hidden `host serve` and `host restart` verb rows, so no later PR edits the verb table for them; lock, stale socket, 0700 dir and 0600 socket, `peer_uid`, NDJSON framing, `hello`, `status` and `profiles` from `snapshot`/`status`/`registry`; fake-transport tests) | ~900 Rust | 3; #46 registry, snapshot, status, lease | 2 |
| 5 | `feat(host): subscribe, state resolution, traffic` (compose `VpnControl` subscription with phase: port of `MenuConnectionState.resolve` and `VPNComponentState` with their check cases moved to `cargo test`; debounce; the host sends `oftc.traffic.v1` once per second per connected profile and derives rates, a Rust port of `TrafficRates`/`TrafficSnapshot` validation and its Swift cases; `traffic` events only with a subscriber) | ~1000 Rust | 4; #46 vpn, apple manager | 6, 7, 8 |
| 6 | `feat(host): verbs over the socket` (connect, disconnect, remove, export, import preview and import, settings, check-update, open-settings, cancel; typed results shared with the verb printers; `busy`; error and exit codes; golden verb table kept green) | ~1000 Rust | 4; #46 commands, start, supervisor, bundle, intent | 5, 7, 8 |
| 7 | `feat(cli): socket client` (`status`, `profiles`, `--version`, `--json`, exit mapping, direct fallback) | ~500 Rust | 3, 4 | 5, 6, 8 |
| 8 | `build: host launch agent` (plist, `Launchctl::kickstart`, register path, postinstall kickstart, signing and `build.sh` edits, `docs/operations.md`) | ~350 | 4; #46 agent | 5, 6, 7 |
| 9 | `feat(ui): HostEdge` (Network client, hello, subscribe, backoff and kickstart, typed errors, stale-state handling; Swift check decoding the golden files) | ~550 Swift | 3, 4, 5, 8 | 6, 7 |
| 10 | `refactor(ui): MenuBar and MenuModel on HostEdge` (delete `classify`, `SupervisorStatus`, `ProfileScope`, `OFTCProfile` readers, the C snapshot caller and its FFI, and every `NetworkExtension` use: `TunnelRuntime`'s manager, status observers, `sampleTraffic`, `TrafficSnapshot` decoding; baseline lowered) | about -1000 Swift | 9, 6 | |
| 11 | `feat(host): add_profile, list_sources, component_update` (progress events, `psk_source`, `tunnels_active`, idempotent `install-config`) | ~700 Rust | 6; #46 sysext, keychain, bundle | 10 |
| 12 | `fix(ui): component update view; Onboarding shrinks onto add_profile` (defect 1) | about -250 Swift | 10, 11 | 13, 14 |
| 13 | `feat(ui): About and shared options menu` (defect 2, with the "Details" line) | ~150 Swift | 10 | 12, 14 |
| 14 | `refactor: update check to the host; GatewayTrustPrompt takes pre-parsed fields` | about -150 Swift, ~200 Rust | 6; #46 trust | 12, 13 |
| 15 | `build: empty the ratchet baseline` (remove `ui-edge-baseline.txt` and its allowances once PRs 10, 12, 13, 14 have burned it down) | ~100 | 10, 12, 13, 14 | |

Critical path: 3, 4, 5, 9, 10 (PR 9 needs PR 5 so `HostEdge` can subscribe to `traffic` from the start; no UI file ever imports `NetworkExtension`). PRs 1 to 3 need nothing from #46. The remaining
#46 work that matters is deleting the Swift readers that `MenuBar.swift` and
`Onboarding.swift` still call (`ProfileScope`, `OFTCProfile`, `SupervisorStatus`,
`AgentService`, `ProviderReadiness`): they must be deleted in PR 10 and PR 12, not
earlier, or the UI target breaks; no #46 PR should delete them first. PRs 5, 6
and 11 touch `commands.rs` and its golden table with #46 follow-ups; land them in
order and rebase, no parallel edits to that file.

## 15. Risks

- **Supervisors must outlive the host.** A resident agent that starts
  supervisors makes them its children; `launchctl kickstart -k` or a crash would
  kill the process group and drop every VPN, which today's one-shot agent never
  risks. Mitigation: spawn them detached in their own session
  (`spawn_supervisor` in `agent.rs` today does not `setsid`; verify) and set
  `AbandonProcessGroup`. **Not verified**; it needs a live test with a connected
  tunnel and a host restart, run by the user (Issue 48 style), before PR 8
  merges.
- **A second Login Items entry** and its approval prompt; behaviour of two
  agents in one app is not verified. If the cost is unacceptable, fall back to
  option A with the `launchctl disable` behaviour moved off the shared label.
- **A new always-on process** in a security tool: mitigated by owner-only
  socket, peer uid check, no secrets, no network listener, caps on line length and
  connections (16), and `deny(unsafe_code)` outside `os`.
- **Socket path length** (104 bytes) for long user names; fail closed with
  `host_unavailable`.
- **Debounce and backpressure**: a slow UI must not grow the server's queue;
  each connection keeps only the latest `status` document and drops intermediate
  `traffic` events.
- **Schema drift** and the mixed-version matrix (section 6); a baseline silently
  raised (CI guard); logic moved to Rust (`resolve`) needs its Swift cases ported
  one for one, then deduped.
- **Approval waits are unbounded**; `waiting` is normal, and the existing 90 s
  hint stays UI text.
- **Host sampling cost**: one provider message per second per connected profile,
  only while a client subscribes to `traffic`. An idle host sends none.

## 16. Evidence levels

Reached by this proposal: **design and spike only.** The spike was built with
the Rust toolchain and `swiftc` on the development Mac (macOS 27.0.1), rendered
headlessly and compared byte for byte, and ran interactively for a few seconds.
The host-code composition in section 8 was read from `origin/main` source, not
run. Not reached and not verified: any change to the shipping UI, an offline app
build, signing, notarization, installation, launch-agent registration or its
approval prompt count, supervisor survival across a host restart, extension
activation, live traffic. No host serves the socket yet and no code for it
exists.
