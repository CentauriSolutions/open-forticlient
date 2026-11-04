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

Process model (Issue 45): the recommended and adopted choice is **Option A**: a
thin Swift `main` plus one Rust staticlib inside the entitled `OFTCAgent`. The
maintainer started its implementation. The alternatives, named once: **Option B**
is a Rust `main` executable that loads the Swift UI as a dylib; **Option C** is
Rust host logic in a nested entitled helper under `Contents/Helpers`.

Under Option A, `OFTCAgent` remains the bundle's main executable, so the
restricted entitlements, which are bound to `Contents/MacOS/OFTCAgent` when the
bundle is signed, stay where they are today. It becomes a ~30-line Swift `main`
that links one Rust host static library, the pattern `liboftc_migration.a`
already uses. With arguments it calls `oftc_host_main(argc, argv)`. With none it
starts the Swift UI. In-process libraries inherit the process's entitlements, so
this needs no signing change.

Consequences:

- Rust owns every write to the NetworkExtension preferences (create, enable,
  remove); the Swift UI only reads them. UI-side enable and create paths move
  behind an idempotent `install-config` verb.
- The host libraries (migration, host, later engine) go into a single staticlib
  crate: one panic and allocator state and a smaller binary. The Issue 46 change
  that introduces it owns the `build.sh` and signing-script edits.
- Option B adds a signed artifact; revisit it only if Issue 47 chooses a Rust UI.
  Option C is ruled out by the placement test below.

Entitlement-placement test (run on the development Mac, signed with the existing
Developer ID identity and host profile, not notarized, nothing installed or
activated; full result in
<https://github.com/CentauriSolutions/open-forticlient/issues/45#issuecomment-6618560555>).
A probe called `NETunnelProviderManager.loadAllFromPreferences`:

| Run | Placement and signing | Result |
| --- | --- | --- |
| T1 | Probe as `Contents/MacOS/OFTCAgent`, profile embedded | Runs; sees the app's own 2 entries. |
| T2 | Nested helper, same entitlements, no profile of its own | Killed at launch (exit 137), reproducibly. |
| T3 | Probe with no entitlements (today's `oftc` helper) | Runs, no error; sees 6 entries instead of 2. |

- A nested entitled helper without its own profile is killed, so Option C is
  ruled out as tested. The kill cause is inferred from T1 against T2, not read
  from a log.
- An unentitled binary can call `loadAllFromPreferences` but sees a different
  scope. Issue 46 must not rely on that scoping (writes were not tested).

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
   with its subject. A moved or ported test that duplicates the coverage of another is dropped, not
   carried over; see "Every test earns its place" in `AGENTS.md`.
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
- **Entitlement placement.** Answered by the Issue 45 test (above): a nested
  helper claiming the entitlements without its own profile is killed, so the
  entitled calls stay in the main executable (Option A).
- **Missing crates.** `objc2-network-extension`, `objc2-system-extensions`,
  `objc2-service-management` and `p384` are not in the offline cargo cache.
  Hand-write the small binding slice or vendor the crates; Issue 41 decides once.
- **Concurrent edits.** Issue 40's remaining route-overlap and DNS policy work
  touches `SettingsMapper` and the host. Land it, or decide to port it later,
  before Issue 41 so the parallel lanes do not rebase over it.
