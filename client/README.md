# `oftc` CLI

This crate builds the standalone OFTC command-line interface. It invokes the
signed macOS app and manages its per-user LaunchAgent. It contains no
Fortinet-backed VPN engine. `oftc standalone ...` remains an alias while v15
installations transition; the direct form is preferred.

```sh
cargo test --offline --manifest-path client/Cargo.toml
cargo build --offline --release --manifest-path client/Cargo.toml
client/target/release/oftc help
```

See [operations](../docs/operations.md) for setup and daily commands and
[architecture](../docs/architecture.md) for the app/provider boundary. The
default app path and LaunchAgent label retain their validated v15 names until
the distributable identity and migration are implemented.
