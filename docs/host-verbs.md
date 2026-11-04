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

## Still in Swift

Every other verb in the usage text (`OFTCAgent` with a verb not listed above), and
the menu with no arguments, are unchanged. This page grows as verbs move.
