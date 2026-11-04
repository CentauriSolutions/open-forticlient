# Documentation

## Current client

- [Architecture](architecture.md): active source and runtime boundaries.
- [Operations](operations.md): setup, connection, stop, and diagnostics.
- [Host verbs](host-verbs.md): the `OFTCAgent` verbs implemented in Rust and their output and exit codes.
- [Roadmap](ROADMAP.md): distribution and rollout work.
- [Releasing](releasing.md): CI, and building, signing and publishing a release.
- [Swift removal plan](swift-removal-plan.md): Issues 41 to 50, seams, lanes, and hygiene rules.

## Historical research

[Findings](FINDINGS.md), [daemon replacement](daemon-replacement.md),
[control socket](control-socket.md), [SAML binding](saml-ipsec-protocol.md),
[IKE dialect](ike-dialect.md), and [profile encryption](fct-enc-crypto.md)
record the investigation. Older sections may cite the original roadmap stages. The old source and full research plan are under the `legacy-controller` tag; use `git show legacy-controller:<path>` to inspect them.
