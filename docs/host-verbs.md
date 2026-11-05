# Host verbs

The entitled `OFTCAgent` executable answers a fixed set of verbs. `oftc`, the menu
and the install scripts run them and parse what they print, so the verb names, their
arity, their output and their exit codes are a protocol: change them additively
only. This page lists what is implemented in Rust (`app/core/host`, reached through
`oftc_host_main` in `app/core/hostlib`); the golden table in
`app/core/host/src/commands.rs` pins every line below, and a Rust test keeps the
usage text and the verbs `Host/main.swift` keeps equal to the verb table there.

`OFTCAgent [--profile <id>] <verb> ...` The leading `--profile` selects a profile by
id (1 to 32 of `a-z`, `0-9`, `-`, not starting or ending with `-`). Without it a verb
that needs a profile uses the only one; with several it exits 1 and lists the ids.
A malformed `--profile` exits 2 with
`--profile needs a name of 1-32 lowercase letters, digits or hyphens`. A command
line the verb does not accept prints the usage text and exits 2. Output goes to
stdout, errors included, as the Swift host did. A closed stdout (`| head -1`) does
not abort the command; its exit code is the command's own.

Before a Rust verb runs, a single-profile layout from an older version
(`<root>/profile.json`) is moved into `<root>/profiles/<id>/` and named after the
FortiClient profile for the same gateway, or the gateway itself.

## Verbs in Rust

| Verb | Success | Failure |
| --- | --- | --- |
| `activate`, `deactivate` | Submits the system extension request for `<bundle id>.provider` and narrates it as it happens: `macOS approval required for <id>` plus the System Settings hint, `System extension replacement: <short>/<build> -> <short>/<build>` (always accepted); ends with `System extension request completed`, exit 0 | `Extension replacement accepted; reboot required`, exit 3; `System extension request failed: domain=<d> code=<c>`, exit 1 (a request the system never answers, or a failed callback, prints the error text instead of domain and code) |
| `agent-status` | `not-registered`, `enabled`, `requires-approval`, `not-found` or `unknown`; exit 0 | |
| `register-agent` | `OFTC login agent registered`; exit 0 | `Could not register OFTC login agent: <reason>`, exit 1; the reason is the system's description, or `OFTC login agent is <status>` when approval is pending, the status is unknown or registration did not leave it enabled, or `... is disabled` when `launchctl enable` failed |
| `unregister-agent` | `OFTC login agent unregistered` (also when nothing is registered); exit 0 | `Could not unregister OFTC login agent: <reason>`, exit 1 |
| `unregister-menu-login` | `OFTC menu login item unregistered`; exit 0 | `Could not unregister the OFTC menu login item`; exit 1 |
| `login-settings` | `Menu launch at login: enabled\|disabled`, then `VPN connect at login (<id>): enabled\|disabled` per profile; exit 0 | |
| `list-profiles` | one line per profile, `id`, name, gateway, port, transport separated by tabs, ordered by name; an empty line when there are none; exit 0 | |
| `show-profile` | `OFTC profile <id> (<name>): gateway=<g> saml-port=<p> transport=<udp\|tcp>`; exit 0 | `OFTC profile unavailable; run oftc setup` (none), `OFTC profile unavailable: no profile named <id>; run oftc setup` (unknown `--profile`), `Several OFTC profiles are configured; choose one with --profile <id> (<ids>)`; exit 1 |
| `has-psk` | `OFTC PSK available`; exit 0 | `OFTC PSK unavailable`; exit 1 (or the profile errors above) |
| `provision-psk [--stdin] [gateway]` | `OFTC PSK stored in Keychain`; exit 0 | `Invalid gateway name` (empty, over 253 bytes, contains `/` or `:`) exit 2; `Could not read a valid PSK from the terminal` / `...from standard input` exit 1; `Could not save OFTC Keychain PSK` exit 1 |
| `save-profile <gateway> <saml-port> [--tcp] [--name <name>]` | `OFTC profile saved: id=<id>`; exit 0 | usage, exit 2, for settings the profile rules refuse; `OFTC already has a profile for <gateway>`; `Could not save OFTC profile (a profile with that id may already exist)`; exit 1 |
| `install-config` | `OFTC configuration saved`, or `OFTC configuration already exists` (idempotent); exit 0 | `Could not save OFTC configuration`, `Could not load VPN configuration`, `Multiple OFTC configurations; refusing to guess`; exit 1 |
| `status` | `OFTC VPN status: <invalid\|disconnected\|connecting\|connected\|reasserting\|disconnecting>`, or `OFTC configuration absent`; exit 0 | the load errors above; exit 1 |
| `remove-config` | `OFTC configuration removed` or `OFTC configuration absent` (every entry of this app, any profile key; needs no profile); exit 0 | `Could not remove OFTC configuration`; exit 1 |
| `erase-profile` | `OFTC profile, VPN entry and Keychain PSK erased` (the selected profile, or every profile without `--profile`), or `OFTC profile absent; nothing erased`; exit 0 | `Disconnect <name> before erasing its profile`, `Could not remove an OFTC VPN entry; profile left in place`, `Could not erase OFTC Keychain PSK for <name>; profile left in place`, `Keychain PSK erased, but profile <name> could not be removed`; exit 1 |
| `rekey-once`, `rekey-ike-once` | `CHILD_SA rekey probe passed` / `IKE_SA rekey probe passed`; exit 0 | `... rekey probe failed (stage <0-200>)`, `... failed`, `... timed out` (45 s), `Could not request ... rekey probe`, `No OFTC configuration`, `OFTC VPN is not connected`; exit 1 |
| `rekey-counts` | the provider's `child_rekeys local=...` line; exit 0 | `CHILD_SA rekey counts unavailable` (10 s), `Could not request CHILD_SA rekey counts`, `OFTC VPN is not connected`; exit 1 |
| `preflight <gateway> <32-hex-UID>` | the provider's stage line when it starts with `preflight_passed`; the tunnel is stopped; exit 0 | any other stage line, `Provider preflight did not report a stage before timeout` (45 s), `PSK unavailable in OFTC Keychain service`, `No OFTC configuration; run install-config`, `OFTC configuration or status changed before start`, `Start request failed; ...`; exit 1. `Expected a 32-character hexadecimal UID`, `Invalid preflight input`, `Could not make preflight envelope`; exit 2 |
| `start-live <gateway> <saml-port> [--tcp] [--ipv6-outer <CLAT-IPv4>] [--insecure-saml]` | `Live start requested; inspect status before any fresh-token retry`; exit 0 | `SAML bootstrap failed`, `OFTC configuration unavailable or VPN already active`, `PSK unavailable in OFTC Keychain service`, `No OFTC configuration; run install-config`, `OFTC configuration or status changed before start`, `Start request failed; acquire a fresh token before another live attempt`; exit 1. Usage, exit 2, for a port outside 1-65535, an empty gateway, or flags the provider would refuse |
| `start-profile [flags]` | as `start-live`, with the selected profile's gateway, port and transport (`--tcp` is implied by a TCP profile); usage (exit 2) is checked after the profile is found | as `start-live`, plus the profile errors |
| `stop` | `Stop requested` after asking the supervisor to stand down (its lease id is copied from `supervisor.lock` to `supervisor.stop`) and stopping the tunnel; `OFTC configuration absent` (exit 0) when the profile has no VPN entry | `Could not signal OFTC supervisor; VPN left running` (the lock holds something that is not a lease id, or the request cannot be written; the tunnel is not touched), `Could not load VPN configuration`, `Multiple OFTC configurations; refusing to guess`, or the profile errors above; exit 1 |
| `set-autostart on\|off` | `Connect at login for <id>: on\|off`; exit 0. `on` also registers the login agent without starting a sign-in (see below) | `Could not change automatic connection: <reason>`, exit 1: the preference or request file could not be written, or registration failed (`OFTC login agent is requires-approval`, `... is disabled`, the system's description); on a failed registration the previous choice is restored |
| `supervise-autostart` | run by the login agent: starts `OFTCAgent --profile <id> supervise-profile` for each profile that should connect, waits for them, prints `OFTC supervisors exited`; exit 0. With none: `OFTC automatic VPN connection is disabled for every profile`, exit 0. `Could not start supervisor for <id>` is printed for one that would not start | `Could not open the OFTC supervisor log`, exit 1 (under launchd only) |
| `export-profiles [id...]` | the `.oftc` bundle of the named profiles (all when none) on stdout, PSKs included; exit 0 | `OFTC profile unavailable: no profile named <id>`, `No OFTC profiles to export`, `PSK unavailable for <name>; nothing exported` (nothing is written); exit 1 |
| `import-profiles` | reads a bundle from stdin (at most 64 KiB, 16 profiles); one line per profile, `Imported <name>: id=<id>` or `Skipped <name>: already configured` (a gateway that has a profile keeps it and its PSK); exit 0 | the bundle's message (`That file isn't an OFTC profile file`, `...from a newer OFTC; update OFTC and try again`, `...is too large`, `...contains no profiles`, `The profile "<name>" in that file has invalid settings`), `Could not save the profile "<name>"`; exit 1 |
| `import-profile <FortiClient-profile>` | `FortiClient profile imported into OFTC configuration and Keychain: id=<id>`; exit 0 | `Could not import FortiClient profile`, `Imported profile has invalid connection settings`, `OFTC already has a profile for <gateway>`, `Could not save OFTC profile (a profile with that id may already exist)`, `Could not save OFTC Keychain PSK`; exit 1 |
| `migrate-psk <FortiClient-profile> <gateway>` | `Existing local profile PSK migrated into OFTC Keychain`; exit 0 | `Could not obtain plaintext PSK for that profile and gateway`, `Could not save OFTC Keychain PSK`; exit 1 |

`start-live` and `start-profile` sign in once through the browser and start once;
they never retry. The envelope's expiry is read from the clock after the sign-in
returns, so a long login cannot age it out. A `supervise-profile` with no `--profile`
and `OFTC_BUNDLED_AGENT=1`, as an agent plist from before multi-profile support runs
it, is handed to `supervise-autostart`.

## The reconnect supervisor

`supervise-live <gateway> <saml-port> [flags]` and `supervise-profile [flags]` (the
profile's own gateway, port and transport) take the profile's supervisor lease, sign
in through the browser, start the tunnel once and keep it up. Before the lease they
make `start-live`'s checks: `No OFTC configuration; run install-config`, `OFTC
configuration unavailable or VPN already active`; a held lease is `Another OFTC
supervisor is active`; all exit 1. It prints one line when it stops and exits with
its code (`app/core/host/src/supervisor.rs`):

| Exit 0 | Exit 1 |
| --- | --- |
| `Supervisor stopped` (a `stop` request, SIGINT or SIGTERM); `VPN disconnected without a recoverable error; staying down` (also runs `launchctl disable` on the login agent) | `Gateway certificate not trusted; supervisor stopped`, `Fresh SAML acquisition failed; supervisor stopped`, `OFTC status changed before supervised start`, `OFTC configuration or status changed before start`, `OFTC configuration changed during supervision`, `VPN start failed; no token retry`, `VPN start deadline expired`, `VPN disconnected before establishment; no token retry`, `VPN disconnected; automatic recovery unavailable` |

A token is single-use, so only a gateway that was unreachable *before* the browser
opened is retried without the user (waits of 5, 10, 20, then 30 s, or 1 s after the
user just trusted its certificate, until 390 s after the first attempt). A drop of an
established tunnel is recovered with a fresh sign-in after 2 s when its error is one of
the provider's established-SA codes or an `NEVPNConnectionError` overslept, no network,
unrecoverable network change, server not responding, dead or disconnected, at most
three times in ten minutes. An untrusted gateway certificate is shown by the Swift
prompt (`OFTCAgent review-certificate`), once, only after such an unreachable result.
Diagnostics go to stderr as `OFTC supervisor: <event>`.

Differences from the Swift supervisor (each deliberate):

- The sign-in, the preference reload and the disconnect-error fetch block the
  supervisor's own thread instead of running on queues; the sign-in polls for a stop
  request and SIGINT/SIGTERM every 100 ms and abandons the browser wait, and the
  loop notices a stop or signal within one second otherwise (up to 10 s while it waits
  for the disconnect error, which has that timeout). Swift exited from the main queue.
- Deadlines (390 s, 90 s, 2 s, 1 s…30 s) use the monotonic clock; Swift used wall-clock
  `Date`, so a Mac that slept through a deadline expired it on wake and now does not
  (whether the monotonic clock counts sleep is the platform's).
- The "preference refresh timed out" diagnostic is gone: the reload carries its own
  timeout. The heartbeat diagnostic prints status words, not raw numbers.
- A missing or unusable PSK is the same failure as a failed sign-in (Swift's
  catch-all did the same).
- The disconnect error is read through the host's wrapper, so any failure to fetch
  it, not only a timeout, counts as "no error".

The certificate check no longer uses `URLSession`: it reads the chain from
`/usr/bin/openssl s_client` and asks `SecTrust` (`trust.rs`), so a system proxy is not
followed; the gateway's verdict must be compared live (see the PR for #46).

`oftc` parses `id=` from the `save-profile` line with `rsplit_once("id=")` and the
`list-profiles` tab-separated fields; the menu classifies failures by the substrings
`PSK unavailable`, `profile unavailable` and `configuration is unavailable`.

`provision-psk` reads the PSK with echo off from `/dev/tty`, or, with `--stdin`, the
first line of standard input. Either way it must be 1 to 1024 bytes of UTF-8 without
NUL. `--stdin` lets a caller with no terminal (the setup window) supply the PSK
without handling the Keychain itself.

`login-settings` and `unregister-menu-login` are not in the usage text (they never
were); the verb table marks them hidden so the text stays byte-for-byte.
`set-autostart on` with the agent not yet enabled leaves a one-use
`agent-request.json` (`connect: false`, valid for 60 s) so that registering the agent
does not itself open a browser; the next `supervise-autostart` consumes it. A fresh
request decides, whatever it says; otherwise the profile's choice does. A request
that cannot be decoded is left in place and ignored. Under launchd
(`OFTC_BUNDLED_AGENT=1`) `supervise-autostart` first sends its own output to
`~/Library/Logs/OFTC/agent.log`, and each supervisor it starts writes to
`<id>.log` there (appended, mode 0600, never through a symlink); a direct run keeps
its terminal.

A profile's connect-at-login is its `connection-preferences.json`; with no such file,
a profile that adopted the original layout inherits an enabled agent. A file that
exists but cannot be decoded counts as off.

## Differences from the Swift verbs

- Activation events print from the main queue while the verb waits; the order of the
  lines is unchanged.
- `provision-psk --stdin` is new (additive), and the usage text lists it.
- A failed Keychain update reports `Could not save OFTC Keychain PSK`; Swift said
  `Could not update OFTC Keychain PSK` for that one case. Both exit 1.
- Profile names are checked against Unicode general categories Cc and Cf, the set
  Foundation's `controlCharacters` has, so zero-width and soft-hyphen characters are
  refused as before.
- Profile order for names is by Unicode lower-case, not locale collation (order is
  not persisted).
- A generated profile id that collides more than 998 times keeps counting
  (`name-1000`) within 32 characters; Swift appended four random hex digits, which
  could exceed 32 characters.
- `start-live`/`start-profile` name the tunnel on the browser's sign-in page (the
  supervised verbs always did; these did not).
- `rekey-*`, `preflight` and the status polling use a timeout on each provider
  message (45 s, 45 s, 10 s; 10 s per preflight request inside its 45 s window);
  Swift waited on the callback with its own timer.
- `import-profile` checks for an existing profile for the gateway, and for a taken
  `--profile` id, before it writes the Keychain. Swift overwrote the existing
  profile's PSK and then refused.
- When `import-profiles` or `import-profile` cannot write the Keychain it stops with
  `Could not save OFTC Keychain PSK`; `import-profiles` first prints the lines for
  the profiles it had already imported (Swift printed only the failure).

The bundle format (`app/core/host/src/bundle.rs`) is byte-identical to what
`ProfileBundle.swift` writes; `tests/fixtures/swift/bundle.oftc` is its output. The
menu still reads bundles with the Swift decoder until its UI moves.

- `set-autostart` reports a write failure with the operating system's error text
  (`Permission denied (os error 13)`); Swift printed Foundation's description. The
  agent log directory failing to be created reports `Could not open the OFTC
  supervisor log`, where Swift printed Foundation's description.
- `OFTC_BUNDLED_AGENT` is read once at start, into the host's environment, instead of
  by each function.

Files shared with older builds (a supervisor started by an old build keeps running
while a new `stop` or menu reads its files): `supervisor.lock` (a `flock` on the file,
which holds the lease id: 36 uppercase hex-and-hyphen characters, no newline),
`supervisor.stop` (the same text), `supervisor-status.json` (`updated` counts seconds
from 2001-01-01 UTC, not 1970), `connection-preferences.json`, `agent-request.json`
and `<root>/saml.lock`. Swift-written copies are checked in under
`app/core/host/tests/fixtures/swift/supervisor`; the Rust-written status and
preference files under `fixtures/rust/supervisor` are decoded by the Swift readers in
`build.sh`.

## Reading the host's files from the menu

`oftc_host_snapshot_json(bundle_id)` in `liboftc_host.a` returns every profile with its
supervisor phase and connect-at-login choice as JSON, for the menu to read in process
(free the string with `oftc_host_free`). The shape is documented in
`app/core/host/src/snapshot.rs`. Nothing in the menu calls it yet.

## Still in Swift

`Host/main.swift` keeps only what needs AppKit, bookmarks or `URLSession`: the menu (no
arguments, `--after-install`, `preview-menu`, `render-menu-previews`, `quit-menu`),
`review-certificate` (the certificate prompt the supervisor starts), `launcher-alias`
and `check-update`. Everything else, including a bad command line, is Rust's.
