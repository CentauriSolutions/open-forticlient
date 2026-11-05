# Host verbs

The entitled `OFTCAgent` executable answers a fixed set of verbs. `oftc`, the menu
and the install scripts run them and parse what they print, so the verb names, their
arity, their output and their exit codes are a protocol: change them additively
only. This page lists what is implemented in Rust (`app/core/host`, reached through
`oftc_host_main` in `app/core/hostlib`); the golden table in
`app/core/host/src/commands.rs` pins every line below, and a Rust test keeps the
usage text and the Swift stub's verb list equal to the verb table there.

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
| `export-profiles [id...]` | the `.oftc` bundle of the named profiles (all when none) on stdout, PSKs included; exit 0 | `OFTC profile unavailable: no profile named <id>`, `No OFTC profiles to export`, `PSK unavailable for <name>; nothing exported` (nothing is written); exit 1 |
| `import-profiles` | reads a bundle from stdin (at most 64 KiB, 16 profiles); one line per profile, `Imported <name>: id=<id>` or `Skipped <name>: already configured` (a gateway that has a profile keeps it and its PSK); exit 0 | the bundle's message (`That file isn't an OFTC profile file`, `...from a newer OFTC; update OFTC and try again`, `...is too large`, `...contains no profiles`, `The profile "<name>" in that file has invalid settings`), `Could not save the profile "<name>"`; exit 1 |
| `import-profile <FortiClient-profile>` | `FortiClient profile imported into OFTC configuration and Keychain: id=<id>`; exit 0 | `Could not import FortiClient profile`, `Imported profile has invalid connection settings`, `OFTC already has a profile for <gateway>`, `Could not save OFTC profile (a profile with that id may already exist)`, `Could not save OFTC Keychain PSK`; exit 1 |
| `migrate-psk <FortiClient-profile> <gateway>` | `Existing local profile PSK migrated into OFTC Keychain`; exit 0 | `Could not obtain plaintext PSK for that profile and gateway`, `Could not save OFTC Keychain PSK`; exit 1 |

`start-live` and `start-profile` sign in once through the browser and start once;
they never retry. The envelope's expiry is read from the clock after the sign-in
returns, so a long login cannot age it out. `supervise-live` and `supervise-profile`
are still Swift.

`oftc` parses `id=` from the `save-profile` line with `rsplit_once("id=")` and the
`list-profiles` tab-separated fields; the menu classifies failures by the substrings
`PSK unavailable`, `profile unavailable` and `configuration is unavailable`.

`provision-psk` reads the PSK with echo off from `/dev/tty`, or, with `--stdin`, the
first line of standard input. Either way it must be 1 to 1024 bytes of UTF-8 without
NUL. `--stdin` lets a caller with no terminal (the setup window) supply the PSK
without handling the Keychain itself.

## Differences from the Swift verbs

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

## Still in Swift

Every other verb in the usage text (`OFTCAgent` with a verb not listed above), and
the menu with no arguments, are unchanged. This page grows as verbs move.
