# CLI

`dwara-cli` is the operator command line for working with configs
without standing up a gateway.

## `run`

```sh
dwara-cli run [ARGS]...
```

Runs the gateway server. The CLI spawns the `dwara` binary (which must
be on `PATH`) with the given arguments passed through verbatim; the
environment (`DWARA_CONFIG`, etc.) passes through, and the binary's
exit status is propagated.

## `validate`

```sh
dwara-cli validate path/to/dwara.yaml
```

Runs the same parse → validate → compile pipeline the gateway runs at
startup and on reload, without starting a server. Prints **every**
issue found (never stops at the first). Exit 0 on success (prints the
route count), exit 1 on any issue.

## `fmt`

```sh
dwara-cli fmt path/to/dwara.yaml
```

Normalizes a config file in place: parses it, then re-serializes with
stable field order and defaulted-empty collections omitted. The output
is guaranteed to parse back to the same typed value. Prints nothing on
success; exit 1 on failure.

## `diff`

```sh
dwara-cli diff a.yaml b.yaml
```

Compiles both configs and prints route/upstream/consumer deltas:

```
+ route new-api
- route old-api
~ upstream backend
```

`+`/`-`/`~` mean added / removed / same-name-but-changed (compared by a
hash of the normalized serialization, so reordering keys in the source
file never shows up as a change). Exit 1 if either side is invalid.

## `lint`

```sh
dwara-cli lint path/to/dwara.yaml
```

Advisory checks beyond validation — config that compiles and routes
traffic but likely doesn't do what the author meant:

| Rule | Flags |
| --- | --- |
| `prefix-duplicate` | two prefix routes with an identical pattern (the later one can never win) |
| `regex-shadowed-by-exact` | an exact route that fully matches a regex route's pattern |
| `consumer-unused` | referenced by no authorization rule and bound to no JWT provider |
| `policy-unused` | attached to nothing (no consumer, route, service, listener, or global) |
| `upstream-unreferenced` | targeted by no service |
| `config/version` | config `version` is older or newer than the current schema version |

Exit codes: `0` clean, `2` warnings found, `1` the file didn't even
parse/validate (fix that first — linting an invalid config would just
be noise).

## `migrate`

```sh
dwara-cli migrate path/to/dwara.yaml
dwara-cli migrate path/to/dwara.yaml --in-place
```

Upgrades a config to the current schema version: parses the config,
sets its `version` field to `CURRENT_CONFIG_VERSION`, and
re-serializes. Without `--in-place`, the migrated config is printed to
stdout; with `--in-place`, it is written back to the file. Migration
notes are printed to stderr. Exit 0 on success, 1 on parse/serialize
failure.

## `explain`

```sh
dwara-cli explain --config path/to/dwara.yaml --method GET --path /api/v1/users
dwara-cli explain --config dwara.yaml --method POST --path /orders --header "Authorization: Bearer token"
dwara-cli explain --config dwara.yaml --method GET --path /api/users --consumer alice
```

Renders a human-readable explanation of what the gateway would do for
a request matching the given method, path, headers, and consumer:
route matching, authorization, rate limiting, transforms, upstream
selection, and caching. Reuses the same pure decision logic the
gateway runs at request time, so the explanation is always consistent
with the gateway's actual behavior. Exit 0 on success, 2 on config
parse/compile error.

## `schema`

```sh
dwara-cli schema
```

Prints the [JSON Schema](https://json-schema.org/) (a standard for describing a JSON document's shape) of the gateway config to stdout (deterministic
for a given build). This is what generates the committed
`config-reference.json` — see
[Generating the config schema reference](./deployment#generating-the-config-schema-reference).

## `upgrade`

```sh
dwara-cli upgrade
dwara-cli upgrade --pid 12345
dwara-cli upgrade --pid-file /run/dwara.pid
```

Sends `SIGUSR2` (a Unix signal that triggers a zero-downtime upgrade) to a running gateway to trigger a zero-downtime binary
upgrade. The PID is read from `--pid`, else the PID file (`--pid-file`
or the `DWARA_PID_FILE` env var). The gateway must have been started
with `DWARA_PID_FILE` set (or the PID supplied explicitly). See
[Zero-downtime upgrade](./zero-downtime-upgrade) for the hand-off
sequence and the `DWARA_UPGRADE_*` env vars.

## `import`

```sh
dwara-cli import nginx  nginx.conf  --output dwara.yaml
dwara-cli import kong   kong.yaml   --output dwara.yaml
dwara-cli import envoy  envoy.yaml  --output dwara.yaml
dwara-cli import openapi petstore.yaml --output dwara.yaml
dwara-cli import openapi petstore.yaml --output dwara.yaml --mock
```

Scaffolds a Dwara config from an existing NGINX, Kong, or Envoy
config, or from an OpenAPI 3.x spec. With `--mock`, the OpenAPI import
reads response examples and generates mock route actions instead of
proxy actions, producing a fully functional mock API without any
backend. Unsupported constructs are appended as YAML-comment warnings.
See [Config import](./config-import) and
[OpenAPI import and mock mode](./openapi-import).

## `tf`

```sh
dwara-cli tf export --admin http://127.0.0.1:2019 --out-state dwara.tfstate --out-hcl dwara.tf
dwara-cli tf plan   --admin http://127.0.0.1:2019 --state dwara.tfstate
dwara-cli tf apply  --admin http://127.0.0.1:2019 --state dwara.tfstate
```

Terraform-compatible state export/plan/apply over the admin API. See
[Terraform state tool](./terraform-state).

## `plugin new`

```sh
dwara-cli plugin new my-plugin
```

Scaffolds a ready-to-build proxy-wasm plugin crate. See
[Plugin SDK](./plugin-sdk).

## `k8s conformance-report`

```sh
dwara-cli k8s conformance-report
```

Emits the upstream Gateway API conformance report YAML. Feature-gated:
requires building `dwara-cli` with the `k8s` feature
(`cargo build -p dwara-cli --bin dwara-cli`); the
published OSS binaries do not include it. See
[Kubernetes Gateway API](./kubernetes-gateway-api).

## `status`

```sh
dwara-cli status
dwara-cli status --admin http://127.0.0.1:2019
```

Prints a one-shot snapshot of the running gateway: version, uptime,
readiness, config generation and hash, per-upstream endpoint health,
circuit-breaker states, active request count, and cache stats. The
admin URL defaults to `DWARA_ADMIN` or `http://127.0.0.1:2019`.

## `top`

```sh
dwara-cli top
dwara-cli top --interval 2000
```

A live, refreshing view of upstream load-balancer state: algorithm,
scheme, connections opened, requests sent, breaker state, and
per-endpoint health and inflight counts. Refreshes every second
(override with `--interval <ms>`) until interrupted with Ctrl-C.

## `completions`

```sh
dwara-cli completions bash > /etc/bash_completion.d/dwara
dwara-cli completions zsh  > ~/.zfunc/_dwara-cli
dwara-cli completions fish > ~/.config/fish/completions/dwara-cli.fish
dwara-cli completions powershell | Out-File dwara-cli.ps1
```

Generates a shell completion script for the `dwara-cli` command model.
Supported shells: bash, zsh, fish, PowerShell.

## `dwara-loadgen`

`dwara-loadgen` is a separate benchmarking binary shipped alongside
the CLI. It drives concurrent load at a target across HTTP/1.1,
HTTP/2 (h2c), and HTTP/3 (QUIC), and optionally runs an
in-process echo upstream:

```sh
dwara-loadgen --url http://127.0.0.1:8080/v1/ --connections 10 \
  --duration 30 --rate 500
dwara-loadgen --echo 9000 --echo-only        # just the echo upstream
dwara-loadgen --url http://127.0.0.1:8080/ --protocol h2 \
  --workload pool-reuse --json               # h2 pool-reuse, JSON output
```

`--protocol h3` uses the HTTP/3 transport compiled into the default build
(`cargo build -p dwara-cli --bin dwara-loadgen`) and
rejects `--echo` (no in-process QUIC echo — point it at a real h3
listener); `--insecure` skips certificate verification for loopback
targets. The three `--workload` shapes are `throughput` (default,
back-to-back requests on an owned connection), `pool-reuse` (a shared
pooled client exercising connection/stream reuse), and `streaming`
(chunked echo the client drains fully). With `--json`, a
machine-parseable `JSON:` line is emitted alongside the `RESULT:` line
for the regression gate (`scripts/bench-regression.py`).

| Flag | Default | Description |
| --- | --- | --- |
| `--url` | `http://127.0.0.1:18080/` | Target URL. |
| `--protocol` | `h1` | Wire protocol: `h1`, `h2` (h2c), or `h3`. |
| `--workload` | `throughput` | Macro workload: `throughput`, `pool-reuse`, or `streaming`. |
| `--connections` | `10` | Concurrent worker connections. |
| `--duration` | `10` | Run length in seconds. |
| `--rate` | `0` (unbounded) | Target requests/second across all connections. |
| `--echo <port>` | off | Also serve a minimal HTTP/1.1 echo upstream on this port. |
| `--echo-only` | off | Serve only the echo upstream (requires `--echo`). |
| `--echo-body` | `128` | Echo response body size in bytes (throughput/pool-reuse). |
| `--stream-chunks` | `8` | Chunks the streaming echo emits per response (streaming + `--echo`). |
| `--stream-chunk-bytes` | `1024` | Bytes per streaming chunk (streaming + `--echo`). |
| `--stream-chunk-delay-ms` | `0` | Delay between streaming chunks in ms (streaming + `--echo`). |
| `--timeout-ms` | `10000` | Per-request timeout. |
| `--json` | off | Emit a machine-parseable `JSON:` line (for the regression gate). |
| `--insecure` | off | (h3 only) Skip server certificate verification; loopback targets only. |

## Runnable demo

Run config validation against a live gateway: [`demos/09-operations/`](https://github.com/shristilabs/dwara/tree/main/demos/09-operations)
in the repository (test script: `test-03-cli-validate.sh`). The demo
image ships only the gateway binary, so the script documents
`dwara-cli validate` and proves the config through the gateway's
startup validation; the README covers running the CLI on the host.
