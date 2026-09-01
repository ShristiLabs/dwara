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

Exit codes: `0` clean, `2` warnings found, `1` the file didn't even
parse/validate (fix that first — linting an invalid config would just
be noise).

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
```

Scaffolds a Dwara config from an existing NGINX, Kong, or Envoy
config, or from an OpenAPI 3.x spec. Unsupported constructs are
appended as YAML-comment warnings. See
[Config import](./config-import) and
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
(`cargo build -p dwara-cli --features k8s --bin dwara-cli`); the
published OSS binaries do not include it. See
[Kubernetes Gateway API](./kubernetes-gateway-api).

## `dwara-loadgen`

`dwara-loadgen` is a separate benchmarking binary shipped alongside
the CLI. It drives concurrent load at a target and optionally runs an
in-process echo upstream:

```sh
dwara-loadgen --url http://127.0.0.1:8080/v1/ --connections 10 \
  --duration 30 --rate 500
dwara-loadgen --echo 9000 --echo-only        # just the echo upstream
```

| Flag | Default | Description |
| --- | --- | --- |
| `--url` | `http://127.0.0.1:18080/` | Target URL. |
| `--connections` | `10` | Concurrent worker connections. |
| `--duration` | `10` | Run length in seconds. |
| `--rate` | `0` (unbounded) | Target requests/second across all connections. |
| `--echo <port>` | off | Also serve a minimal HTTP/1.1 echo upstream on this port. |
| `--echo-only` | off | Serve only the echo upstream (requires `--echo`). |
| `--echo-body` | `128` | Echo response body size in bytes. |
| `--timeout-ms` | `10000` | Per-request timeout. |
