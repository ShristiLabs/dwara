# Install options in detail

## Prerequisites

- Docker (Path A) or Rust with the repo's pinned toolchain (Path C -
  `rust-toolchain.toml` selects it automatically).
- `curl` and, for TLS verification against the quickstart, `openssl` (the
  `gen-certs.sh` script uses it).

## Path A - Docker quickstart, details

Repo layout that matters:

```
quickstart/
├── gen-certs.sh          # one-shot cert generation -> ./certs
├── certs/                # created by gen-certs.sh (server, client CA, client cert)
├── upstream/             # static demo pages for the nginx upstream
└── oss/                  # OSS single-node topology
    ├── docker-compose.yml
    ├── dwara.yaml        # the feature-tour config (~1100 commented lines)
    └── data/             # SQLite state + analytics DBs (bind-mounted)
```

Environment the compose file sets:

| Variable | Value | Why |
| --- | --- | --- |
| `DWARA_CONFIG` | `/etc/dwara/dwara.yaml` | Points the gateway at its config (default is `./dwara.yaml` in cwd). |
| `DWARA_STATE_DB` | `/var/lib/dwara/state.db` | SQLite state store: consumer quota counters, MCP sessions. Omit it and quotas log a warning per request and are not enforced. |

Notes:

- The image is built from `Dockerfile.scratch` (static musl binary on
  `FROM scratch`); `Dockerfile.distroless` bakes in the nonroot user
  instead. The compose service runs as UID 65532.
- On Linux, `./data` must be writable by UID 65532:
  `sudo chown -R 65532:65532 data` - otherwise the SQLite stores cannot
  create their files.
- The sibling `quickstart/enterprise/` runs the CP/DP split topology
  (controller + two edges) - only relevant with an enterprise build.

## Path B - minimal config, details

See [../assets/minimal-dwara.yaml](../assets/minimal-dwara.yaml). Shape:

- one `listeners` entry: `name`, `address`, `port`, `protocol: http|https`
  (`https` additionally requires `tls:` with `cert_file`/`key_file`, and
  optionally `client_ca_file` for client-cert auth);
- one `routes` entry with `match.path.type: exact` and
  `action.type: respond` (gateway-served; no upstream dialed);
- a `services` entry and an `upstreams` entry (schema-required even when the
  action never dials them - keep a placeholder endpoint).

Run with any binary: `DWARA_CONFIG=./dwara.yaml ./dwara`. Reload later by
re-saving the file (watch) or `kill -HUP <pid>`; the gateway re-runs the
full Parse -> Validate -> Compile -> Publish pipeline and keeps the previous
config serving if the new one fails.

## Path C - cargo build, details

```sh
cargo build --release              # OSS edition (default)
cargo build --release --features ent   # Enterprise edition (license-gated)
```

Only three cargo features exist in the workspace: `ent` (enterprise),
`loom` (model-checked test builds), and `cel-jit` (faster CEL evaluation;
interpreter fallback). Everything else compiles into the OSS build
unconditionally.

Workspace binaries: `dwara` (gateway), `dwara-cli` (operator CLI),
`dwara-loadgen` (benchmark rig; supports `--echo` for an in-process
upstream so no backend is needed to load-test).

Container images: `Dockerfile.scratch`, `Dockerfile.distroless` (OSS);
`Dockerfile.ent`, `Dockerfile.release-*` (release pipelines).

## Which entry port to use

- HTTPS listener `:8443` with `--cacert certs/server.crt` - the realistic
  path (matches production: TLS termination at the edge).
- HTTP listener `:8080` - fine for local iteration and health checks; do not
  expose plaintext listeners publicly.
- Admin `:2019` - always with the client certificate; see the
  `dwara-operations` skill for the endpoint surface.
