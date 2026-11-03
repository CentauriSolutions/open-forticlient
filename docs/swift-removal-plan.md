# Swift removal plan

Goal: minimise Swift in OFTC, and where it stays, keep it behind a narrow,
documented edge. Tracked as Issues 41 to 50.

## Decisions already made

1. **Keep NetworkExtension.** The provider stays a `NEPacketTunnelProvider`
   system extension. Dropping it for a root `utun` daemon is a separate project
   (it trades away the entitlement and approval friction for owning routes, DNS
   cleanup and gateway pinning) and is out of scope. The `Tunnel` trait (Issue 41)
   keeps that door open without building it.
2. **Add a `Tunnel` trait** between the engine and the OS packet interface.
3. **UI stays native.** Native look comes from using AppKit, not from the language.
   AppKit through `objc2` renders the same widgets, so the decision is about
   maintainability. Default: UI stays Swift behind a clean edge unless Issue 47
   shows Rust reaches parity at acceptable cost.
4. **The live gate replaces the installed provider** on the development Mac
   (same bundle id), with a written rollback (Issue 48).
5. **A project-wide simplification pass follows** (Issue 50), and every lane
   carries spike hygiene rules (below) so that pass has less to remove.

## Target end state

| Piece | Language | Notes |
| --- | --- | --- |
| Engine (IKE, EAP, ESP, transport) | Rust | unchanged except crypto backend |
| Crypto (P-384, AES-CBC, HMAC, RNG) | Rust | Issue 42; no `libcrypto_swift.dylib` |
| Provider executable (`OFTCTunnel`) | Rust | Issues 43, 44; engine linked statically, no C ABI |
| Host logic (profiles, Keychain, supervisor, NE manager, SystemExtensions, SMAppService) | Rust | Issues 45, 46 |
| `oftc` CLI | Rust | unchanged role |
| UI (menu bar, popover, welcome, onboarding, trust prompt, sparkline) | Swift unless Issue 47 says otherwise | thin main executable plus UI only |

Process model (default, from Issue 45): `OFTCAgent` remains the bundle's main
executable, so restricted entitlements stay where they are today. It becomes a
~30-line Swift `main` that links a Rust host static library, the pattern
`liboftc_migration.a` already uses. With arguments it calls
`oftc_host_main(argc, argv)`. With none it starts the Swift UI. The alternative
(a Rust main executable that loads the Swift UI) is chosen only if the Issue 45
entitlement test favours it.

## The UI edge

Swift UI may depend on exactly three things, all documented in `docs/ui-edge.md`
(Issue 47):

1. The `oftc` CLI commands the menu already invokes.
2. The nonsecret supervisor status record and profile registry JSON.
3. NetworkExtension status notifications plus the versioned provider message
   (`oftc.traffic.v1`), which stays byte-compatible so mixed host/provider builds
   keep working.

Swift UI code must not read Keychain items, open sockets, parse provider
internals, or call engine functions.

## Dependency graph

```
   Issue 40 (concurrent tunnels is committed; its open route and DNS
   policy tasks touch SettingsMapper and the host, so land or park them first)
                              |
                        Issue 41  seams + workspace          (serial)
        ______________________|______________________________________
       |          |            |             |            |
   Issue 42   Issue 43     Issue 44      Issue 45     Issue 47
   crypto     provider     NE backend    manager      UI edge +
              logic        + hello ext   bindings     parity study
                 \            |             |
                  \           |        Issue 46 host logic
                   \__________|          (mock VpnControl; no wait on 45)
                              |
                        Issue 48  live gate                  (serial, user-attended)
                              |
                        Issue 49  integrate, delete Swift
                              |
                        Issue 50  project-wide simplification
```

Lanes 42 to 47 run in parallel, each in its own git worktree off the Issue 41
commit. Only the live gate (Issue 48) is serial, because one system extension per
bundle id can be active and approval needs the user.

## Merge order

42, then 43 and 44 together (they meet at the `Tunnel` trait), then 45 and 46,
then 47's edge doc. 48 validates the merged provider before 49 deletes Swift.
Merge as each passes its own offline gate; do not hold lanes for each other.

## Spike hygiene (applies to Issues 42 to 47)

Exploratory work leaves residue. These rules keep it from reaching `main`:

1. **Spike code is labelled.** Throwaway code lives under `spikes/<issue-id>/`,
   outside every build input and `build.sh` step. Nothing merges from there;
   anything kept is re-homed in its permanent location with tests.
2. **Replace, do not add.** Each merged change deletes what it supersedes (Swift
   file, `extern` block, C ABI function, `build.sh` step, doc paragraph) in the
   same commit. Record the net line count in the issue.
3. **No speculative trait surface.** Every trait method has a production caller,
   is exercised by the mock, and is implemented by one real backend. No generics,
   feature flags or methods added for a `utun` backend that does not exist.
4. **No new escape hatches.** No new `#![allow(dead_code)]`, `#[path = "..."] mod`
   includes, `cfg` switches, environment-variable toggles or old/new runtime
   switches. Cutover is by branch, not flag.
5. **Unsafe is quarantined.** All `objc2`, `block2` and C FFI `unsafe` for a
   framework sits in one module with a safe wrapper API. Code outside it has no
   `unsafe` for that framework.
6. **Behaviour does not change.** Provider messages, `profile.json`, the status
   record, `.oftc` export format, exit codes and Keychain item names stay
   identical. Each lane adds a compatibility test for what it touches.
7. **Tests move with code.** Each ported `check-*.swift` becomes a `cargo test`
   with the same cases; the issue lists the mapping and the Swift check is deleted
   with its subject.
8. **Residue report.** At the end of a lane, write in the issue: scaffolding still
   present, anything that looked clever but should be simpler, anything you
   would cut. Issue 50 starts from these reports.

## Evidence levels

Per `AGENTS.md`, these are separate claims and each issue records which it
reached: offline build, unit/mock tests, Developer ID signing, notarization,
installation, extension activation, live traffic. Lanes 42 to 47 claim at most
offline build plus tests. Only Issue 48 claims activation and live traffic.

## Risks

- **Class registration.** `NEProviderClasses` names the principal class; a Rust
  `objc2` class must be registered under a plain Objective-C name before
  `startSystemExtensionMode`. Issue 44 answers this first.
- **Entitlement placement.** Which executable may call `NETunnelProviderManager`
  and `OSSystemExtensionManager` under its provisioning profile. Issue 45 tests
  this; it decides the process model.
- **Missing crates.** `objc2-network-extension`, `objc2-system-extensions`,
  `objc2-service-management` and `p384` are not in the offline cargo cache.
  Hand-write the small binding slice or vendor the crates; Issue 41 decides once.
- **Concurrent edits.** Issue 40's remaining route-overlap and DNS policy work
  touches `SettingsMapper` and the host. Land it, or decide to port it later,
  before Issue 41 so the parallel lanes do not rebase over it.
