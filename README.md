# dwara

A high-performance API gateway written in Rust.

Status: pre-alpha. The workspace scaffolds the gateway; proxying arrives in M1.

## Quickstart

Requires Rust 1.94 (pinned in `rust-toolchain.toml`).

```sh
cargo run -p dwara-bin
```

Starts a hello listener on `http://127.0.0.1:8080` (proxying arrives in
M1):

```sh
curl http://127.0.0.1:8080
# dwara
```

Stop it with Ctrl-C.

## Crates

| Crate | Role |
| --- | --- |
| `dwara-core` | Config model, routing types, swappable trait definitions |
| `dwara-bin` | Gateway server binary |
| `dwara-admin` | Admin / management-plane API |
| `dwara-cli` | Operator command-line client |

## License

Apache-2.0
