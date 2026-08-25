# dwara

A high-performance API gateway written in Rust.

Status: pre-alpha. The workspace scaffolds the gateway; proxying arrives in M1.

## Quickstart

Requires Rust 1.94 (pinned in `rust-toolchain.toml`).

The binary requires a config file at startup: it exits with code 1,
printing every validation issue, if the config is missing or invalid. A
sample config ships in the `dwara-bin` crate, so from the repo root:

```sh
DWARA_CONFIG=crates/dwara-bin/dwara.yaml cargo run -p dwara-bin
```

Starts a hello listener on `http://127.0.0.1:8080` (proxying arrives in
M1):

```sh
curl http://127.0.0.1:8080
# dwara
```

Stop it with Ctrl-C.

Environment variables (all optional):

- `DWARA_CONFIG`: path to the gateway YAML config, default `./dwara.yaml`.
- `DWARA_BIND`: listen address, default `127.0.0.1:8080`.
- `DWARA_SHUTDOWN_TIMEOUT_SECS`: graceful-drain budget on
  SIGTERM/SIGINT, default 10.

## Configuration

Gateway configuration is a YAML file parsed strictly by `dwara-core`
(`parse_gateway`): unknown fields are rejected, and errors carry the
path of the offending node. A minimal valid configuration:

```yaml
listeners:
  - name: main
    address: 0.0.0.0
    port: 8080
routes:
  - name: all
    service: echo
    match:
      path:
        type: prefix
        value: /
    action:
      type: proxy
services:
  - name: echo
    upstream: echo-upstream
upstreams:
  - name: echo-upstream
    endpoints:
      - address: 127.0.0.1
        port: 9000
```

More examples live in `crates/dwara-core/tests/fixtures/` (minimal and
full). A machine-readable `json_schema()` export exists
programmatically; it is the intended canonical reference once the
schema stabilizes. The schema still churns during M1.

Config passes through a fixed pipeline before the gateway serves it:

- **Parse** (strict): unknown fields rejected, errors carry the path of
  the offending node.
- **Validate** (semantic): duplicate names, unknown upstream/service/
  policy references, listener address+port conflicts, empty or invalid
  credentials and endpoint weights are checked, and every issue is
  reported at once rather than one per attempt.
- **Compile**: route paths are built into lookup structures. This is
  where schema-valid config can still fail (an invalid regex or
  conflicting path template names the route and pattern at fault).
- **Publish** (atomic): a config that fails anywhere above never
  replaces the running one; the gateway keeps serving the previous
  snapshot, and each successful publish gets a new generation id.

Route paths match one of three ways: `exact` (a full template, path
parameters like `/users/{id}` supported), `regex`, or `prefix`. Lookup
precedence is exact, then regex (first declared pattern wins), then
longest prefix.

### TLS

Listeners are `http` (cleartext) or `https` (TLS). An `https` listener
requires a `tls` block with one of two modes.

**Terminate** (default): dwara ends TLS at the edge (rustls, aws-lc-rs
provider; TLS 1.2 and 1.3 with rustls's default cipher policy). ALPN
advertises `h2` and `http/1.1`, so both HTTP/2 and HTTP/1.1 work over
one listener. Multiple certificates are selected by SNI: entries in
`certificates` are matched (exact, case-insensitive) against the
client's server name; the single `cert_file`/`key_file` pair is the
fallback for unmatched or absent SNI, and with no single pair the first
`certificates` entry is the fallback. A single pair alone (no
`certificates`) is the simplest form; a `certificates`-only config is
also valid.

```yaml
listeners:
  - name: edge
    address: 0.0.0.0
    port: 443
    protocol: https
    tls:
      mode: terminate
      cert_file: /etc/dwara/certs/default.crt.pem   # fallback pair
      key_file: /etc/dwara/certs/default.key.pem
      certificates:
        - server_names: [a.example.com]
          cert_file: /etc/dwara/certs/a.crt.pem
          key_file: /etc/dwara/certs/a.key.pem
        - server_names: [b.example.com]
          cert_file: /etc/dwara/certs/b.crt.pem
          key_file: /etc/dwara/certs/b.key.pem
```

**Passthrough**: dwara never decrypts. The ClientHello is peeked (not
consumed), the SNI server name is matched exactly (case-insensitive)
against `sni_routes`, and the raw TLS bytes are spliced bidirectionally
to the upstream. A non-TLS client, a ClientHello with no SNI, or an
unmatched name has its connection closed. Certificate fields are
rejected in this mode; `sni_routes` are rejected in terminate mode.

```yaml
listeners:
  - name: edge
    address: 0.0.0.0
    port: 443
    protocol: https
    tls:
      mode: passthrough
      sni_routes:
        - server_names: [back.example.com]
          upstream: backends
upstreams:
  - name: backends
    endpoints:
      - address: 10.0.0.5
        port: 8443
```

v1 limitation: a passthrough route forwards to the FIRST endpoint of
its upstream; load balancing across endpoints arrives later in M1.

Cleartext `http` listeners accept HTTP/1.1 and h2c (HTTP/2 prior
knowledge) — the connection preface is sniffed, no upgrade or ALPN
needed.

## Operations

Reload: the config file is watched (the file's directory, so atomic
write-temp-plus-rename replacement is observed; events are debounced)
and `SIGHUP` also triggers a reload. A reload re-reads the file,
validates, and publishes a new generation atomically. A rejected
reload (unreadable, parse, or validation failure) logs every issue and
keeps serving the running generation — the process never exits on a
bad reload. If the file watch cannot start, SIGHUP reload still works.

Certificates hot-reload on terminate listeners: the cert/key files are
watched (same directory-watch pattern as the config), and a change
rebuilds the TLS configuration and swaps it in live — no connections
are dropped. New handshakes use the new material; handshakes and
sessions already in flight keep what they negotiated. A config reload
also refreshes TLS material. A failed TLS reload (e.g. an unreadable
PEM) is logged and keeps the previous certificates. Limitations: the
listener bind set (listeners, addresses, ports) is fixed at startup —
adding or removing listeners or changing address/port takes effect on
restart; only route/config changes and certificate material reload
live. Passthrough splices are also not drained on graceful shutdown;
they run until the process exits.

Shutdown: `SIGTERM`/`SIGINT` stop accepting, drain live connections
(including ones still in the kernel accept backlog) within
`DWARA_SHUTDOWN_TIMEOUT_SECS`, then exit 0. Connections still draining
past the budget are force-closed.

## Crates

| Crate | Role |
| --- | --- |
| `dwara-core` | Config model, routing types, swappable trait definitions |
| `dwara-bin` | Gateway server binary |
| `dwara-admin` | Admin / management-plane API |
| `dwara-cli` | Operator command-line client |

## Extension points

State-holding subsystems are defined as swappable traits in
`dwara-core::extensions`: `RateLimiter`, `ConfigSource`, `CacheStore`,
`AnalyticsSink`, and `SecretSource`. Each trait's rustdoc states its
contract (purpose, semantics, failure model). Local in-memory, file, and
environment-variable implementations ship today; alternative backends
plug in by implementing the same traits.

## Development

CI runs on pushes and pull requests to `main` (when Rust sources,
manifests, toolchain files, or the workflow itself change). Blocking
gates: `cargo fmt --check`, clippy with `-D warnings`, build, tests,
and [cargo-deny](https://github.com/EmbarkStudios/cargo-deny) checks
(advisories, licenses, bans — policy in `deny.toml`). A CycloneDX SBOM
is generated and uploaded as an artifact on each run.

Run the same checks locally:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
```

## License

Apache-2.0
