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
| **D. A new second launch agent, `...oftc.host`, running `OFTCAgent host serve`** | resident from login (`RunAtLoad`), restarted after a failed exit (`KeepAlive` with `SuccessfulExit` false), registered with `SMAppService.agent(plistName:)` like the existing one, same entitled main executable so it may use NetworkExtension and SystemExtensions | **recommended** |

Design of D:

- New bundled plist `Contents/Library/LaunchAgents/com.chris.openforticlient.oftc.host.plist`:
  `BundleProgram` `Contents/MacOS/OFTCAgent`, arguments `host serve`, `RunAtLoad`
  true, `KeepAlive` `{SuccessfulExit: false}`, `ProcessType` `Interactive`, `AbandonProcessGroup` true
  (see the risk in section 15: supervisors it starts must outlive it). A hidden
  verb pair `host serve` / `host restart` follows the existing `hidden(...)`
  rows in `commands.rs`, so the usage text stays byte for byte (a test now pins
  the text). `host serve` arms SIGINT and SIGTERM and serves until one arrives;
  `host restart` is `launchctl kickstart -k` of the host label, so the
  `Launchctl::kickstart` seam lands with the verb in PR 2, not PR 5; with the
  service not registered it reports that and exits 1. PR 5 adds the plist
  (`app/Host/HostAgent.plist`, bundled as `<bundle id>.host.plist`) and
  `agent::{host_item, host_status, register_host, unregister_host}`; wiring them to
  a verb and to `oftc setup` is left to the verb owners (`commands.rs`), and the
  plist's `OFTC_BUNDLED_AGENT=1` is there so `host serve` can send its output to
  `agent.log` through `redirect_output` once it calls it (it does not yet, so
  launchd discards the host's output).
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
  (`lease.rs`). The socket is created `0600`. A directory that already exists with group or other bits is put back to `0700`
  if it is ours and refused if it is not; a symlink in its place is refused, never
  followed (`lstat`). The socket is created with the process umask and restricted to
  `0600` right after `bind`; the window between the two exposes nothing because
  the directory is already closed to everyone else (no `umask` call: it is
  process-wide and would need another `unsafe`). `sun_path` holds 104 bytes including its
  NUL, so the path may be at most 103 bytes; the suffix is about 68 bytes, leaving
  about 29 characters for the user name, so the server checks the length before it
  creates anything and refuses to start (`host serve` prints
  `host_unavailable: path too long` and exits 1) rather than truncating. (Bundle id of a
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
  and require `cr_uid` equal to the server's uid; otherwise, and when the system
  will not say, close without a reply. This lives in the `os` module (the only `unsafe` in `core/host`).
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
line (longer: the receiver closes). A line that is not a JSON object with an unsigned integer `id` and
a string `op` cannot be answered, so the server closes the connection without a
reply; so it does when `hello` has not completed within 10 s of connecting (one deadline for the whole exchange, so a client sending a byte at a time is cut off too), when a write is not
accepted for 5 s, and for a 17th simultaneous connection. Blank lines are
skipped. One connection carries many requests; each
request has a client-chosen integer `id` and every reply, progress and result
echoes it. Events have no `id`. The server answers requests on a connection in
order of completion, not of arrival; a client matches by `id`.

### 4.2 Handshake and versioning

First line from the client:
`{"id":1,"op":"hello","protocol":[1,1],"client":{"kind":"ui","version":"0.9.0","build":"24"}}`
where `protocol` is `[min, max]` supported. Reply:
`{"id":1,"ok":true,"result":{"protocol":1,"host":{"version":"0.9.0","build":"24","provider_build":"24"}}}`.
The server picks the highest protocol both support. No overlap, a range
with `min` above `max`, or no `protocol` at all:
`{"ok":false,"error":{"code":"unsupported_schema","exit":5,...}}` and the server
closes. Any other op before `hello` is rejected the same way. A second `hello` on
an open connection is answered again with the same result. Within one
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
| `profiles` | | `{ "profiles": [ { id, name, gateway, saml_port, transport, auto_start } ] }`: the settings only, nothing live (what `oftc profiles --json` prints; this table lacked it) |
| `subscribe` | `topics`: any of `status`, `traffic` | `{}`, then events. It replaces the connection's topic set; unknown topic names are ignored; each `subscribe` is owed the current `status` again. Without `topics` the reply is `unknown_op` (there is no usage code) |
| `unsubscribe` | | `{}` |
| `connect`, `disconnect` | `profile` (optional: all) | `{}` once the host has started a supervisor (`connect`: one per profile that is down and has no supervisor yet; one already connecting or connected is left alone) or asked the supervisor and tunnel to stop (`disconnect`); later phase in events. A failure is also shown in that profile's `error` until the next such op on it starts. Without `profile`, every profile is tried and the first failure is the reply |
| `remove` | `profile` | `{}`: stops the profile, waits up to 20 s for its tunnel, then erases it, its VPN entry and PSK (`tunnels_active` if the tunnel stays up and nothing is removed). A profile that is not there is already removed, so the reply is `{}` |
| `export` | `profiles` (optional), `path` (absolute) | `{}`; the host writes the file, mode `0600`, never over an existing file or through a symlink (the UI keeps its scratch-then-copy step). The bundle holds PSKs; the reply does not |
| `import_preview` | `path` (absolute) | `{ "profiles": [ { name, gateway, saml_port, transport, already_configured } ] }`, **no PSK** |
| `import` | `path` (absolute) | `{ "added": [ids] }`; a gateway that already has a profile is skipped, so repeating it adds nothing |
| `add_profile` | `gateway`, `saml_port`, `transport`, `name`, `psk_source`, `label` | progress then `{ "profile_id" }` (4.6). `psk_source` is `"saved"` (the PSK was stored first by the stdin child, 4.4) or `"forticlient"` plus `label`; the earlier draft's `"stdin_job"` is gone, it duplicated `saved` |
| `list_sources` | | `{ "sources": [ { label, gateway, saml_port, already_configured } ] }`: importable FortiClient profiles, never a PSK |
| `component_update` | | progress then `{}`: finishes setup for the profiles that exist (PSKs, system extension, VPN entries); `tunnels_active` if any profile is up, `psk_unavailable` with `profile_id` if one has no saved PSK |
| `settings_set` | `key`: `menu_login`, `auto_start:<id>`, `auto_update`; `value`: a boolean | `{}` |
| `check_update` | | `{ "available": { "version", "page" } \| null }`; the host fetches |
| `open_settings` | `pane`: `extensions` or `login_items` | `{}` |
| `cancel` | `target`: an earlier request `id` of this connection | `{}`; see 4.6 |

PR 2 serves `hello`, `status`, `profiles`, `subscribe` and `unsubscribe`; PR 3 serves
the rest. Arguments that are missing or of the wrong type are `bad_request`.

Details PR 3 settled where this document was silent:

- `add_profile` runs the steps of `oftc setup` in this order: `keychain` (the PSK must be
  in the Keychain; with `forticlient` it is copied there inside the host), `profile`,
  `extension_approval` (nothing is asked of the system when the extension is already current, but the step is still reported), `vpn_entry`.
  It is **resumable**: a gateway whose profile exists but has no VPN entry yet (an earlier
  call stopped at the extension step) is finished by the next call, and only a gateway
  that is fully set up answers `already_configured` with `profile_id`. Two calls for one
  gateway, or an `import` that includes it, are `busy`; so is a `remove` of that gateway's
  profile: `add_profile`, `import` and `remove` each take the `gateway:<host>` and the
  `profile:<id>` key, so none can race another into a VPN entry with no profile.
  Profile creation itself is serialised, since ids are chosen from the profiles that
  exist. `import` and `import_preview` read only regular files.
- `settings_set auto_update` is stored by the host in `host-settings.json` in its own
  directory. Nothing reads it back over the socket yet (`UpdateStore` stays UI-private,
  4.5 has no field for it); the UI keeps its own value as the source of truth until a
  field is added.
- `check_update` needs an HTTP fetch, which the host did not have. It runs
  `/usr/bin/curl` (https only, 15 s, 256 KiB) against the feed in `OFTCUpdateFeedURL` of
  the app's Info.plist, the same child-process edge as the certificate check, and ports
  the Swift `UpdateFeed` and `AppVersion` rules. No feed configured is `available: null`.
  The per-user `defaults write ... updateFeedURL` override of the Swift code is not
  ported (the host reads no `UserDefaults`). This lives in `serve/ops_update.rs`, so PR 7
  has no `update.rs` to add.
- `migration_needed` is not produced by any op: the "different app" and "legacy login
  agent" checks are in the CLI's `run_connect` (PR 4's client), not in the host.
- `approval_required` comes from `settings_set` (a login item left pending), and from
  `add_profile` and `component_update` when the extension request itself reports it;
  the usual wait for approval is a `waiting` progress line, not an error.

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
  "host": { "version": "0.9.0", "build": "24", "provider_build": "50" },
  "component": { "state": "ready", "installed_build": "50", "expected_build": "50" },
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
| `seq` | int | starts at 1 when the host first builds the document and increases by one on every change of the document, **not** counting `profiles[].traffic` (a change of `generated` alone is not a change). A reconnecting client ignores older. |
| `host.version`, `host.build`, `host.provider_build` | string | marketing version, `CFBundleVersion`, bundled provider build. Feeds About. |
| `component.state` | enum | `checking` until the first answer of the read-only system extension request (`properties`, 10 s timeout, repeated at most every 30 s), then `ready`, `missing`, `update_required`, `approval`, `newer` or `unavailable` (`VPNComponentState.resolve`, computed in Rust). `expected_build` is `host.provider_build` (the bundled provider's `CFBundleVersion`, which differs from the host's `build`); an unreadable bundle gives `null` and `unavailable`. |
| `component.installed_build`, `expected_build` | string or null | for the "Details" line and the update view |
| `login.*` | enum | `enabled`, `disabled` (`SMAppService` `notRegistered`), `requires_approval`, `not_found` (also an unknown status); read at most every 10 s |
| `profiles[].id` | string | 1 to 32 of `[a-z0-9-]` |
| `profiles[].state` | enum | `connected`, `disconnected`, `connecting`, `disconnecting`, `sign_in`, `reconnecting`, `attention`, `setup` (`MenuConnectionState.resolve`, computed in Rust from NE status, supervisor phase, a stopping flag and the component state). The UI maps it to localised text and does not recompute it. |
| `profiles[].ne_status` | enum or null | raw NE status, for support output |
| `profiles[].phase` | enum or null | `acquiring`, `connecting`, `connected`, `recovering`, `failed`, `stopped`; null without a live supervisor (the liveness rules of `StatusStore::read`) |
| `profiles[].connected_since` | string or null | when this host first saw the profile connected (`NEVPNConnection.connectedDate` is not on the `VpnControl` seam), so `null` for a tunnel already up when the host started and for a profile that is not connected. A follow-up may add the date to `VpnControl`. |
| `profiles[].traffic` | object or null | the newest sample while the profile is connected and some client subscribes to `traffic` (an idle host does not sample, so `null` otherwise). Rates are bytes per second derived in Rust; null until two samples of one session are 5 s or less apart, and after a missed sample (the totals stay). `session` is the first 8 hex digits, lower case, of the provider's session UUID and changes on a new provider connection; totals survive a rekey. `sample_seq` is one counter for the host, increasing with every sample of any profile. |
| `profiles[].error` | object or null | `{ "code", "detail" }`, codes in 4.7: the failure of the last `connect` or `disconnect` of that profile. Cleared when the next `connect`, `disconnect` or `remove` of that profile starts. When no op failure is held and `phase` is `failed`, it is the supervisor's recorded provider failure with a plain reason (`core/host/src/reason.rs`): `detail` is then a short English message with no host, address or secret, and the code is one of the connection reasons in 4.7. |

The profile fields (`id`, `name`, `gateway`, `saml_port`, `transport`,
`auto_start`, `phase`) are exactly what `core/host/src/snapshot.rs` already
computes; section 8 says how it is reused.

### 4.6 Events and progress

Events, server to client, only after `subscribe`:

```json
{"event":"status","seq":1772,"status":{ ... the status document ... }}
{"event":"traffic","profile":"c2","session":"9f1c","rx_bytes":842100000,"tx_bytes":96050000,"rx_rate":1100000.0,"tx_rate":80000.0,"sample_seq":1772}
```

`status` is sent when the document changes, debounced to at most one per 100 ms
per connection; a new sample alone does not change the document, so traffic does
not produce `status` events (the `traffic` inside a `status` event is the newest
sample at that moment). `traffic` is sent once per second per connected profile,
and only while some client subscribes to `traffic`, so an idle host does no
sampling; the host measures profiles one after another, each with a 3 s reply
timeout. A new subscriber gets the current `status` immediately, after the
`subscribe` reply, and no old samples. The UI therefore never polls. Progress for a
long op shares the request id:

```json
{"id":9,"event":"progress","step":"extension_approval","state":"waiting"}
{"id":9,"ok":true,"result":{"profile_id":"c2"}}
```

`step` is an enum (`keychain`, `profile`, `extension_approval`, `vpn_entry`; an
unknown one decodes as `other`), and `state` is `running`, `waiting` or `done`: each step
of `add_profile` and `component_update` says `running`, may say `waiting`, and ends
`done` (there is no step named `done`; the final reply is the end of the op, and a
step is always reported, including `extension_approval` when the system extension is already current, which then goes straight from `running` to `done`). The UI owns the wording. `waiting` means
"needs the user" and is not a failure. `sign_in` is not a step of any op: signing in
belongs to the supervisor and shows in `state` and `phase`. Closing the connection sets
the cancel flag of every op it still has running, so an op nobody is waiting for stops
at its next step; the ops are idempotent (`install-config`, `remove` of an absent
profile) and resumable, so stopping half way is safe. A connection runs at most 8 ops at
once; a ninth is `busy`.

`cancel` sets the target's flag, which an op looks at between steps, and answers the
target at once with `cancelled` (exit 1). The op itself runs on to its next step
boundary, so a cancelled `add_profile` can leave a profile with no VPN entry, which the
next `add_profile` finishes (resumable, not rolled back). The target's own answer, when it ends, is
dropped. The system extension request cannot be withdrawn, so a `cancel` during
`waiting` leaves that request open: the op stops when it ends, and its profile key stays
`busy` until then. A `cancel` for an id that is not running (never started, or ended)
is a success. A request `id` still running on the connection cannot be reused
(`bad_request`).

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
| `bad_request` | 2 | new (PR 3): arguments missing or malformed, a relative path, an export over an existing file, an unknown setting |
| `invalid_file` | 3 | new (PR 3): a `.oftc` file that cannot be read or decoded, including one from a newer OFTC |
| `cancelled` | 1 | new (PR 3): the client sent `cancel` |
| `network_blocked` | 1 | `profiles[].error` only: the UDP attempt got no answer and the TCP 4443 fallback was refused or unanswered (provider code 201, the log line `OFTC provider stage 201 failed`) |
| `gateway_not_found` | 1 | `profiles[].error` only: the gateway name did not resolve (200) |
| `gateway_no_answer` | 1 | `profiles[].error` only: no answer in time (202) |
| `gateway_refused` | 1 | `profiles[].error` only: IKE_SA_INIT, the pre-shared key check or CHILD_SA was refused (203, 204, 209 to 212) |
| `sign_in_rejected` | 1 | `profiles[].error` only: EAP or the final AUTH was rejected, e.g. an expired sign-in (205 to 208) |
| `connection_lost` | 1 | `profiles[].error` only: an established tunnel dropped and the three automatic recoveries in ten minutes are used up |
| `internal` | 1 | everything else; `detail` is for the log, never shown verbatim |

`already_configured` carries `profile_id` beside `detail`. The verbs and the ops return
the same typed failure (`typed::Failure`): a verb prints its text and its own exit code,
the socket sends its code, so no code is recovered from text.

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
| old UI, new host | the old UI has no socket client and keeps using the files and the C snapshot, which the new host does not remove until the UI migration (PR 6) lands; after that the bundle ships one UI, so the case is a UI left running across an upgrade. The `hello` from an old client does not exist, so the server sees no `hello` and closes; the old UI shows its existing unavailable state until relaunched. Not silently wrong. |
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

PR 6 settled, where this section was silent:

- Nothing registered the host service (PR 5 only bundled it), so a hidden verb
  `host register` (`agent::register_host`, then a kickstart; exit 4 when macOS holds it for
  approval) is what `HostEdge` runs, directly, when `launchctl kickstart` finds no service.
  Approval shows as `unavailable(approval)` with a row linking to Login Items; it is not retried
  into a loop. `oftc setup` does not register the service yet.
- #105's first-run repair (`SetupPlan`, `SetupRepair`) stays, reading the host's document (profile
  count, per-profile `setup` state, component state) instead of the system. PR 6 still did two
  things itself (the Keychain presence check and prompt for a PSK, and `oftc setup` run by
  `HostCLI`) because no op finished every existing profile; PR 7 made `component_update` do that
  and removed both (see "PR 7 settled"). The `.oftc` import uses the `import` op, not the CLI.
- The UI starts the host once per outage (kickstart, then register), not on every retry; a
  window opening or a wake starts the count again. An unsupported protocol is not retried.
- `HostEdge` ignores a `status` whose `seq` is not above the last one of that connection and
  accepts the first after a reconnect, since a restarted host counts from 1.
- The `.oftc` import and export keep the old file hand-offs: the menu app copies the user's
  file into a private scratch directory and gives the host that path (and the host exports
  to a scratch path the menu copies out), so the same process as before touches the user's folders.

PR 7 settled, where the earlier text was silent:

- `component_update` is the one op that finishes every existing profile. After the tunnel check it
  runs three reported steps: `keychain` (every profile's PSK is saved; the first profile without one
  fails the op with `psk_unavailable` and its `profile_id`, before the system is asked for anything),
  `extension_approval`, then `vpn_entry` (a VPN entry for each profile that lacks one, as
  `add_profile` makes it). The UI asks for the missing PSK, stores it with the host's own
  `provision-psk --stdin` verb (section 4.4, `HostPSK` in `HostEdge.swift`, the only other `Process`
  use besides the `host` verbs) and runs the op again. `oftc setup` is no longer run by the UI, and
  the UI's Keychain presence check is gone.
- The form-less component view (`ComponentUpdate.swift`) shows `component.state`, the installed and
  bundled builds and the three `login.*` states from the document, runs `component_update`, and
  opens the pane that holds a pending approval with `open_settings`. `startSetup` routes by
  `SetupPlan`: no profile opens the add form (`Onboarding.swift`, which uses `list_sources`,
  `provision-psk --stdin` and `add_profile`); a profile that needs finishing opens the component view;
  the silent first-launch repair runs the same op and updates that view when it is open.
- The options menu (`OFTCMenuBar.populateOptions`) is shown by the gear button, a right or control
  click on the status item, and the application menu while a window is open. It leads with About OFTC
  and a disabled Details line, `AboutDetails.line`: app version and build (the UI's own), the host's
  version, build and provider build, and the installed extension build, all from the document
  (#89). `VPN Component…` opens the component view at any time, so the extension and login item
  states are visible without `systemextensionsctl`.
- The update check is the host's `check_update`; `UpdateCheck.swift` is deleted. The UI keeps its own
  record (`UpdateStore`: automatic, last checked, skipped version, in `ui/`) and only asks when the
  bundle's `OFTCUpdateFeedURL` is set, so a build with no feed still says so. `check-update [url]` is
  now a Rust verb (same texts) for checking a feed by hand.
- The certificate prompt child reads a request with every field parsed by the host
  (`trust::CertificateView`: common names, serial, SHA-256, `notAfter`); `GatewayCertificate`
  (`Security`, `CryptoKit`, openssl) is gone from Swift. This changes only what the prompt shows, not
  when it is shown: #97 (a prompt for a publicly trusted certificate after an outage) is a verdict
  problem in the evaluator and stays open until it is reproduced live.
- Deleted as dead after `Onboarding.swift` stopped reading profiles: `ProfileScope`, `OFTCProfile`,
  `MigrationBridge` and the Swift checks of them. `oftc_migrate_profile_psk` in `hostlib` has no
  Swift caller left.
- The baseline is empty; `ui-files.txt` lists `ComponentUpdate.swift` and `GatewayTrust.swift` (now
  plain request types) and exempts only `main.swift` and `LauncherAlias.swift`.

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
ignored. A fixture covers the script. The baseline reached empty with PR 7 and stays empty: any new match in a listed file fails the check.

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

Interim (issue 88, before the edge carries `component_update`): the Swift UI
already routes by `SetupPlan` (`app/Host/SetupPlan.swift`). A profile that exists
but is not finished (extension missing, older or awaiting approval, or no VPN
entry) is finished by running `oftc setup` with no form; the form is only for a
VPN that does not exist. Waiting for approval is a state with the Settings deep
link, not an error. PR 7 replaced this with the update view above (`ComponentUpdate.swift`).

### 10.2 No menu-bar access to version info or options

Today a click opens the popover and the options sit behind its gear button; the
app has no visible main menu (accessory policy) and no About item. Design for
later work: add **About OFTC** (`NSApp.orderFrontStandardAboutPanel`, plus a short "Details" line reading
`Extension build X, provider build Y` from `component.installed_build`
and `host.provider_build`; `host.build` is the host's own and is never compared with the extension) and the
existing options (login, updates, add, export, Login Items & Extensions) to one
shared `NSMenu`, used both by the gear button and by right-click or ctrl-click on
the status item, and mirrored in the application menu shown while a window
is open. The edge already carries the version fields; nothing else is needed
from the host. Ships after the adapter, independent of the Rust work.

## 14. PR stack

Seven PRs, cut at logical boundaries. Sizes are estimates in changed lines. All of
#46 is on `main` (4f16573: `core/host`, `hostlib`, `core/apple`, the supervisor
port), so no PR waits on it.

| # | PR | Size | Needs |
| --- | --- | ---: | --- |
| 1 | `docs: UI edge contract` (this file) | ~700 doc | none |
| 2 | **The host serves status** (the PR text lists what differed from this row): `core/ui-edge` wire types and golden JSON; `core/host/src/serve/` skeleton (lock, socket, peer check, framing, `hello`); `status` and `profiles`; `subscribe`; state resolution (port of `MenuConnectionState.resolve` and `VPNComponentState`, their Swift cases moved to `cargo test`); host traffic sampling (`oftc.traffic.v1` once a second per connected profile, only with a `traffic` subscriber, plus a Rust port of `TrafficRates` and snapshot validation); the hidden `host serve` and `host restart` verb rows | ~2500 Rust, mostly tables and tests | 1 |
| 3 | **Verbs and setup over the socket**: typed results shared with the verb printers, `busy`, error and exit codes, `connect`, `disconnect`, `remove`, `export`, `import_preview`, `import`, `settings_set`, `check_update`, `open_settings`, `cancel`, `add_profile`, `list_sources`, `component_update` with progress events | ~1700 Rust | 2 |
| 4 | **CLI becomes a socket client** with the direct fallback: `status`, `profiles`, `--version`, `--json`, exit mapping | ~500 Rust | 2 |
| 5 | **Host launch agent**: plist, register path, detached supervisor spawn, postinstall `kickstart -k`, signing, operations doc | ~350 | 2 |
| 6 | **`HostEdge.swift` and the ratchet**: the Swift client; `ui-files.txt`, `check-ui-edge.sh`, baseline and fixture, introduced here; `MenuBar`/`MenuModel` migrate onto it; the Swift readers, the C snapshot FFI and every `NetworkExtension` use are deleted | about +750, -1800 Swift and script | 2, 3, 5 |
| 7 | **UI features on the new edge**: component-update view and Onboarding shrink onto `add_profile` (defect 1); About and shared options menu with the "Details" line (defect 2); update check to the host and the trust prompt taking pre-parsed fields; the ratchet baseline emptied | about -550 Swift, ~200 Rust | 3, 6 |

Parallel: 2 first. Then 3, 4 and 5 run in parallel; 3 and 4 share no files, and 5
touches only the plist, scripts and `agent.rs`. 6 needs 2, 3 and 5. 7 needs 3 and 6.
Serial spine: 2, 3 (or 5), 6, 7.

### Files each PR touches

| # | Files |
| --- | --- |
| 1 | `docs/ui-edge.md` |
| 2 | new `app/core/ui-edge/**`; new `app/core/host/src/serve/**`; `host/src/lib.rs`; `host/src/os.rs` (`peer_uid`, the only new `unsafe`); `host/src/vpn.rs` (`owns_key`); `host/src/commands.rs` (two hidden verb rows, the golden table and a pin on the usage text); `host/src/snapshot.rs` (a typed `facts`, the JSON unchanged); `host/src/agent.rs` (`Launchctl::kickstart`, the host label and plist name); `host/src/lease.rs` (`open_lock_file` visible to `serve`); `docs/host-verbs.md`; `docs/ui-edge.md`; `host/Cargo.toml`; `app/Cargo.toml`, `app/Cargo.lock` |
| 3 | `serve/ops*.rs`; `host/src/{commands,start,bundle,intent,supervisor,sysext,keychain}.rs` (shared typed internals; no new verb rows); `docs/host-verbs.md` |
| 4 | `client/src/**`; `client/Cargo.toml`; `client/man/oftc.1`; `client/README.md` |
| 5 | new `app/Host/*.host.plist`; `host/src/agent.rs` (register path, detached spawn); `app/build.sh`; `app/sign-developer-id.sh`; `app/package-scripts/postinstall`; `docs/operations.md` |
| 6 | new `app/Host/HostEdge.swift`; a Swift check that decodes the golden files; new `app/ui-files.txt`, `app/check-ui-edge.sh`, `app/ui-edge-baseline.txt`, fixture; `app/build.sh`; `MenuBar.swift`, `MenuModel.swift`, `MenuCommand.swift`, `main.swift`, `check-menu*.swift`, `check-experience.swift`; deletes `ProfileScope`, `OFTCProfile`, `SupervisorStatus`, the `AgentService` readers; `core/hostlib/src/lib.rs` and `host/src/snapshot.rs` (the FFI) |
| 7 | `Onboarding.swift`, `Welcome.swift`, `LaunchExperience.swift`, `UpdateCheck.swift` (deleted), `GatewayTrustPrompt.swift`, `MenuBar.swift` (menu section), `en.lproj`; `host/src/trust.rs` (the update check itself landed in PR 3, `serve/ops_update.rs`); `app/ui-edge-baseline.txt`, `app/ui-files.txt` |

### Serial constraints

- `commands.rs` and its pinned usage text and golden table: PR 2 adds the two
  hidden rows; PR 3 changes the file for typed internals and adds no verb rows;
  7 edits it last for the update check. 2 before 3 before 7. PR 4 and PR 5 do not
  touch it.
- `app/build.sh`: PR 5, then PR 6 (the ratchet call and the Swift compile list).
  They are sequential by dependency (6 needs 5), so no conflict.
- `MenuBar.swift`: only PR 6 and PR 7 edit it, and 7 needs 6.
- The Swift readers (`ProfileScope`, `OFTCProfile`, `SupervisorStatus`,
  `AgentService`, `ProviderReadiness`) must stay until PR 6 removes their last
  callers; no other PR deletes them. The camelCase C snapshot FFI
  (`oftc_host_snapshot_json`) stays until PR 6.
- **Live-run items stay attached to PR 5** (see section 15): supervisors
  surviving a host restart, and the Login Items prompt count with two agents.
  Neither is verified.

## 15. Risks

- **Supervisors must outlive the host.** A resident agent that starts
  supervisors makes them its children; `launchctl kickstart -k` or a crash would
  kill the process group and drop every VPN, which today's one-shot agent never
  risks. Mitigation: spawn them in their own process group (`spawn_supervisor`
  in `agent.rs` did not detach; PR 5 sets `process_group(0)`, pinned by a test that
  the child leads its own group, not a `setsid`: that needs an `unsafe` `pre_exec`
  and a launchd job has no controlling terminal) and set `AbandonProcessGroup`.
  **Not verified live**; it needs a connected tunnel and a host restart, run by the
  user on a signed build (steps in the PR 5 description) before PR 5 merges.
- **A second Login Items entry** and its approval prompt; behaviour of two
  agents in one app is not verified. If the cost is unacceptable, fall back to
  option A with the `launchctl disable` behaviour moved off the shared label.
- **A host whose loops die.** A connection that panics is closed and its slot and
  subscriptions released; if the status refresh or the traffic sampler ends while
  the host is running, `host serve` stops, prints `host_unavailable: internal failure`
  and exits 1, so `KeepAlive` restarts it rather than serving stale documents.
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

PR 2 adds the server and its wire types. It is covered offline by cargo tests with
doubles (no real Network Extension, Keychain, launchd or user directory) and by an
offline app build. Nothing is registered, signed, installed or run on a signed
build, so the peer check against the kernel in a signed app, the real
NetworkExtension notifications and provider replies, and the host across an
upgrade are not verified. The rest of this section describes the proposal as first
written.

Reached by this proposal: **design and spike only.** The spike was built with
the Rust toolchain and `swiftc` on the development Mac (macOS 27.0.1), rendered
headlessly and compared byte for byte, and ran interactively for a few seconds.
The host-code composition in section 8 was read from `origin/main` source, not
run. Not reached and not verified: any change to the shipping UI, an offline app
build, signing, notarization, installation, launch-agent registration or its
approval prompt count, supervisor survival across a host restart, extension
activation, live traffic. No host serves the socket yet and no code for it
exists.
