# `oftc` CLI

This crate builds the public CLI for the signed OFTC macOS app. Its five
operational commands are `setup`, `connect`, `disconnect`, `status`, and
`uninstall`; `help` and `man oftc` describe the complete interface. The CLI
does not contain a VPN engine. The signed app's host executable retains
internal commands for setup, diagnostics, and release testing.

`oftc profiles` and the `--json` forms (`profiles`, `status`, `--version`) are clients of
the host's local socket (`~/Library/Application Support/<bundle id>/host.sock`, protocol
in [the UI edge design](../docs/ui-edge.md)); the wire types come from
`app/core/ui-edge`. When the host is not running or its agent is not approved,
`profiles` and `status` run the host executable directly, as every other command does;
`--json` has no direct form and exits 5 (`host_unavailable`). `setup`, `register-agent`
and `uninstall` never use the socket.

```sh
cargo test --offline --locked --manifest-path client/Cargo.toml
cargo build --offline --locked --release --manifest-path client/Cargo.toml
client/target/release/oftc help
```

See [operations](../docs/operations.md) for the install and user workflow,
[the man page](man/oftc.1) for arguments, and
[architecture](../docs/architecture.md) for component boundaries.
