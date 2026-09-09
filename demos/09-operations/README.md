# Category 09: Operations & Config Management

Demonstrates the operator-facing surface of the dwara gateway: hot
config reload, the mTLS-only admin API, config validation, secret
references resolved from the environment, OTLP telemetry export, the
embedded web console, replay debugging, zero-downtime binary upgrade,
Terraform-compatible state management, config import from NGINX,
Kubernetes Gateway API manifests, and agent-operable (MCP) admin
endpoints.

## What this demo runs

Four containers on a single docker bridge network (`ops-net`):

| Service | Image | Role |
|---------|-------|------|
| `dwara` | `dwara:demo` | The gateway (HTTP on :8080, admin API on :2019) |
| `echo`  | `dwara-demo/echo` | Reflects the request as JSON |
| `static` | `dwara-demo/static` | Serves demo HTML + JSON files |
| `otel-collector` | `otel/opentelemetry-collector:0.96.0` | OTLP receiver for test-04 (no host ports) |

The gateway runs as the nonroot UID `65532:65532` (scratch has no
users, so the UID is injected via `user:`). The config is mounted
read-only at `/etc/dwara/dwara.yaml`; the shared certs are mounted at
`/etc/dwara/certs`; a local `./data` directory backs the SQLite state
DB so consumer/credential seeding survives restarts.

The gateway container exports OTLP telemetry to the collector
(`DWARA_OTLP_ENDPOINT=http://otel-collector:4318`, metrics interval
shortened to 2s via `DWARA_OTLP_METRICS_INTERVAL_SECS`). The
collector is pinned to 0.96.0 — the last release line shipping the
`logging` exporter under that name (newer releases renamed it to
`debug`).

## Layout

```
09-operations/
  docker-compose.yml      # the four-service compose (gateway, echo, static, otel-collector)
  dwara.yaml              # gateway config (listeners, routes, admin, secrets)
  data/                   # SQLite state DB + demo data files (see below)
  test-01-hot-reload.sh   # hot config reload on file change
  test-02-admin-api.sh    # mTLS admin API (/health, /config, /stats)
  test-03-cli-validate.sh # config validation
  test-04-otlp-export.sh  # OTLP trace + metrics export to the collector
  test-05-synthetic-monitoring.sh # synthetic route probes (documented limitation)
  test-06-web-console.sh  # embedded web console on the admin listener
  test-07-replay-debugging.sh     # record routing, replay offline, diff configs
  test-08-secrets.sh      # ${ENV_NAME} secret references
  test-09-zero-downtime-upgrade.sh # SO_REUSEPORT binary hand-off (host-based)
  test-10-terraform-state.sh       # dwara-cli tf export/plan (host-based)
  test-11-config-import.sh         # dwara-cli import nginx
  test-12-kubernetes-gateway-api.sh # Gateway API manifests + conformance report
  test-13-agent-operable-admin.sh  # MCP admin endpoints (/mcp/sessions,/mcp/tools,/mcp/calls)
  README.md               # this file
```

Demo data files under `data/`:

| File | Used by | What it is |
|------|---------|------------|
| `otel-collector.yaml` | test-04 | Collector config: OTLP/http receiver + logging exporter (detailed) |
| `upgrade-demo.yaml` | test-09 | Host gateway config for the upgrade hand-off (:18099) |
| `tf-demo.yaml` | test-10 | Host gateway config with a loopback dev admin (:20190) |
| `nginx-demo.conf` | test-11 | Sample NGINX config (upstream + 3 locations) |
| `gateway.yaml` | test-12 | GatewayClass + Gateway manifests (Gateway API v1) |
| `httproute.yaml` | test-12 | HTTPRoute manifest (PathPrefix rules + backendRefs) |
| `state.db*` | compose | SQLite state DB (gitignored, created on first run) |

## Running

```sh
docker compose up -d
./test-01-hot-reload.sh
./test-02-admin-api.sh
./test-03-cli-validate.sh
./test-04-otlp-export.sh
./test-05-synthetic-monitoring.sh
./test-06-web-console.sh
./test-07-replay-debugging.sh
./test-08-secrets.sh
./test-09-zero-downtime-upgrade.sh   # host-based: uses target/debug/dwara
./test-10-terraform-state.sh         # host-based: uses target/debug/{dwara,dwara-cli}
./test-11-config-import.sh           # host-based: uses target/debug/dwara-cli
./test-12-kubernetes-gateway-api.sh  # manifest + conformance-report (cluster-free half)
./test-13-agent-operable-admin.sh
docker compose down
```

Tests 07, 09, 10, 11, and 12 use the prebuilt HOST binaries
`target/debug/dwara` and `target/debug/dwara-cli` (the scratch image
ships only the server binary — see test-03's note). Each skips with a
message when a binary is missing; build them with
`cargo build -p dwara-bin -p dwara-cli`.

## Config summary (`dwara.yaml`)

- **Listener:** one plaintext HTTP listener on `0.0.0.0:8080`.
- **Upstreams:**
  - `echo-upstream` — `round_robin`, one endpoint (`echo:8080`).
  - `static-upstream` — `round_robin`, one endpoint (`static:80`).
- **Services:** `echo-service` (upstream: `echo-upstream`),
  `static-service` (upstream: `static-upstream`).
- **Routes:**
  - `echo-route` — prefix `/v1/echo/`, proxy to `echo-service`,
    `strip_prefix`.
  - `static-route` — exact `/`, proxy to `static-service`.
  - `healthz` — exact `/healthz`, direct-respond `200 "ok"`.
- **Auth:** no route requires authentication (`auth_required` omitted).
- **Admin API:** `bind: 0.0.0.0:2019`, mTLS with the shared server
  cert/key and client CA. Endpoints: `GET /health`, `GET /config`,
  `PATCH /config`, `GET /stats`.
- **Secrets:** the `ops-consumer`'s `api_key.key` is `${DEMO_SECRET}`,
  resolved from the container environment (see below).

## Hot reload (test-01)

The gateway watches its config file (`DWARA_CONFIG`) and atomically
re-reads, validates, and re-publishes the snapshot on change (DW-006).
In-flight requests keep their old generation; new requests pick up the
new one without ever interrupting accept. `SIGHUP` also triggers a
reload. The test touches the host-side `dwara.yaml` (updating its mtime
to nudge the file watcher) and verifies the gateway keeps responding.
To exercise a real content reload, edit `./dwara.yaml` on the host and
save.

## Admin API (test-02)

The admin API binds `0.0.0.0:2019` and requires a client certificate
chained to the client CA — mTLS is its only authentication. Every call
uses the shared client cert + key and trusts the server cert via
`--cacert`:

```sh
curl --cert ../_shared/certs/client.crt \
     --key  ../_shared/certs/client.key \
     --cacert ../_shared/certs/server.crt \
     https://localhost:2019/health
```

Endpoints exercised:
- `GET /health` — liveness (200).
- `GET /config` — the active config snapshot as JSON (200).
- `GET /stats` — runtime statistics (200).

A call without a client cert fails the TLS handshake (mTLS enforced).

## Config validation (test-03)

The operator CLI (`dwara-cli`) has a `validate <file>` subcommand that
parses, validates, and dry-run compiles a config, printing every issue
and exiting 1 on any (0 on success, printing the route count).

**Important:** the scratch image (`dwara:demo`, `FROM scratch`) ships
ONLY the gateway server binary at `/usr/local/bin/dwara`. It does NOT
include `dwara-cli`, and the `dwara` server binary has no `validate`
subcommand — it is the server, not the CLI. So
`docker exec dwara /usr/local/bin/dwara validate ...` is not a valid
invocation in this image.

The authoritative validation path in this demo is the gateway's
startup validation: the server reads `DWARA_CONFIG`, validates it, and
refuses to start (exit 1) on any issue, printing every problem. A
running gateway therefore proves the config validated. To run the
standalone CLI validator, build/install `dwara-cli` on the host:

```sh
cargo run -q -p dwara-cli --bin dwara-cli -- validate ./dwara.yaml
```

## Secrets (test-08)

The gateway supports `${ENV_NAME}` secret references (DW-045) on
secret-bearing config fields (e.g. `consumers[].credentials[].api_key.key`,
HMAC secrets, webhook header values). References resolve at
config-compile time — cold start and every hot reload re-read the
environment.

This demo sets `DEMO_SECRET` in the container environment (see
`docker-compose.yml`) and references it as `${DEMO_SECRET}` in the
`ops-consumer`'s `api_key` credential:

```yaml
consumers:
  - name: ops-consumer
    type: user
    credentials:
      - type: api_key
        key: ${DEMO_SECRET}
```

Behavior:
- **Unset/empty fails closed.** If `DEMO_SECRET` is unset or empty, the
  gateway refuses to start, naming the field. There is no default-value
  syntax: the grammar is strictly `${ENV_NAME}` (the env-var name is
  `[A-Za-z_][A-Za-z0-9_]*`; `file:` and `redacted` prefixes are
  reserved). A form like `${DEMO_SECRET:default-value}` is NOT a valid
  reference (the colon is not part of a legal env-var name) and would
  fail validation.
- **File secrets.** `${file:/path/to/secret}` reads a file at resolution
  time (the Docker/Kubernetes mounted-secret and systemd
  `LoadCredential` shape); one trailing newline is trimmed.
- **Redaction.** The resolved value is never echoed. The admin
  `GET /config` endpoint redacts inline secrets and `${...}` references
  alike (DW-045): a `${redacted:sha256:<8hex>}` placeholder appears in
  their place, so a GET-then-PATCH round trip cannot leak the secret.

Because the gateway is running, the `${DEMO_SECRET}` reference resolved
successfully. The test verifies the gateway is up, the `DEMO_SECRET`
env var is set in the container, and the admin `/config` endpoint does
not echo the resolved value.

## OTLP export (test-04)

The gateway pushes telemetry over the OpenTelemetry Protocol: setting
`DWARA_OTLP_ENDPOINT` to a base http URL arms both exporters — the
trace exporter (the DW-021 span tree: root `request` span plus
authn/authz/ratelimit/admission/upstream_pick/upstream_attempt phase
spans) appends `/v1/traces`, and a periodic metrics exporter appends
`/v1/metrics` (interval override `DWARA_OTLP_METRICS_INTERVAL_SECS`,
default 15s; this demo sets 2s). Unset, the exporters are inert. On
SIGTERM the gateway flushes a final metrics export and drains the
trace batch inside the graceful-shutdown budget.

The compose stack runs an `otel/opentelemetry-collector` container
whose `fixtures/otel-collector.yaml` receives OTLP/http on :4318 and logs
everything at detailed verbosity — `docker compose logs
otel-collector` shows the `service.name: Str(dwara)` resource
attribute, span names, and the gateway's metric families (e.g.
`requests_total`; the exporter ships the same families the `/metrics`
endpoint serves) verbatim. The test generates traffic through the
gateway and asserts exactly that. Both the Prometheus `/metrics`
endpoint and OTLP export run simultaneously; use whichever fits.

## Synthetic monitoring (test-05, documented limitation)

Synthetic monitoring (DW-071) runs built-in probes per route — a
periodic request through the route's matched path that records
latency and status, feeds results into analytics, and fires
edge-triggered webhook alerts (`probe_alert` / `probe_recovered`,
once per state transition, not per failure).

**Current state:** the probe engine (`crates/dwara-core/src/synthetic/`
— `ProbeSpec`, `ProbeRunner` with failure thresholds and edge-triggered
alerting) is complete and test-covered as a library surface, but it is
not yet wired into the gateway binary: the config schema has no
top-level `synthetic:` block, so the guide's probes config cannot be
applied yet. The test pins that state: `/metrics` (the surface probe
results would feed) is live, and `dwara-cli validate` on a config
carrying the guide's `synthetic:` block fails with `unknown field
'synthetic'`. Once the config block lands, the test should apply
probes (e.g. `route_name: healthz`, `interval_ms: 1000`), wait past
the interval, and assert the synthetic probe metrics plus a
`probe_alert` webhook on the `webhook-receiver` image. To exercise
the engine today: `cargo test -p dwara-core synthetic`.

## Web console (test-06)

The web console (DW-117/DW-118) is a single-page app embedded in the
gateway binary at compile time (`include_str!`/`include_bytes!` — no
runtime file dependency) and served from the **admin listener** at
`/console/` before the admin API dispatch. It inherits the admin
listener's mTLS authentication: there is no separate login or token —
the TLS handshake is the authentication. From a browser, install the
shared client certificate
(`demos/_shared/certs/client.crt` + `client.key`) and open
`https://localhost:2019/console/`.

Served paths: `/console` (and `/console/`, `/console/index.html`)
return the SPA shell; `/console/style.css` and `/console/app.js`
return the embedded assets; any other `/console/*` path answers 404
`console_not_found`. The SPA fetches `/health`, `/stats`,
`/config_dump`, and `/analytics/*` endpoints same-origin. In the OSS
build the console is read-only (inspect routes, services, upstreams,
health, metrics); CRUD, fleet views, the config editor, and the
workspace switcher are the enterprise v2 console
(`cargo build --features ent` + a valid license). On a developer
machine `DWARA_ADMIN_DEV=1` (loopback-only plaintext admin) also
serves the console in plaintext.

## Replay debugging (test-07)

Replay time-travel debugging (DW-102) answers "why did this request
go there?" offline: run the gateway's decision path (routing, authz,
rate limits, transforms, upstream pick) for recorded requests against
a candidate config and diff it against the baseline config the
requests were captured under — no live traffic, no upstreams touched.
Exit 0 = no decision differences, 1 = diffs found (a CI gate for
config changes), 2 = load error.

The CLI flow is `dwara-cli replay --recording <file.json> --config
<candidate.yaml>`; a recording is `{baseline_config: "<YAML string>",
requests: [{method, path, headers, auth_identity, timestamp_ms}]}`
(exported from the analytics store or authored from captured
traffic). The test sends a few requests through the live compose
gateway, builds a recording with the demo config as the baseline,
then replays it against the identical config (exit 0, "no decision
differences") and against a diverging candidate where the echo-route
prefix moved (exit 1, a per-request diff naming the path and the
changed stage). Because replay compiles both configs, the demo's
`${DEMO_SECRET}` reference must resolve — the test exports it exactly
as the compose file does.

## Zero-downtime upgrade (test-09, host-based)

The gateway swaps its binary under load with zero failed requests
(DW-049): every listening socket is bound with `SO_REUSEPORT`, and on
`SIGUSR2` the old process spawns a new copy of the binary
(`DWARA_UPGRADE_BINARY` or the current executable) with the
environment inherited. The new process binds the same port alongside
the old, signals `READY` over a Unix domain socket
(`/tmp/dwara-upgrade-<oldpid>.sock`), and the old process then runs
the SIGTERM drain sequence and exits 0. If the new process never
signals READY within `DWARA_UPGRADE_READY_TIMEOUT_SECS` (default
30s), the old process keeps running — a failed upgrade never takes
the gateway down.

The operator trigger is `dwara-cli upgrade --pid-file <path>` (or
`kill -USR2`); start the gateway with `DWARA_PID_FILE` set so the CLI
can find it (the new process overwrites the file after READY). This
demo is host-based (two OS processes cannot share one container): it
starts instance A from `fixtures/upgrade-demo.yaml` on `127.0.0.1:18099`,
hammers `/healthz` in a loop, triggers the upgrade, and asserts the
log trail (`upgrade_initiated` → `upgrade_child_spawned` →
`upgrade_ready`), the old PID's exit, the new PID in the PID file,
and zero failed requests. The listener bind set is fixed at startup —
an upgrade inherits the same listeners; changing binds still requires
a full restart.

## Terraform state (test-10, host-based)

`dwara-cli tf` brings a running gateway's config under
Infrastructure-as-Code management without a Terraform binary or gRPC
plugin (DW-065):

- `tf export --admin URL --out-state F --out-hcl F` — GET `/config`
  from the admin API and write a tfstate JSON (state format version
  4) plus HCL; entities map to `dwara_listener`, `dwara_route`,
  `dwara_service`, `dwara_upstream`, `dwara_consumer` resources.
- `tf plan --admin URL --state F` — diff local state vs the running
  gateway; exit 0 clean / 1 drift.
- `tf apply --admin URL --state F [--config F]` — push the desired
  config via `PATCH /config`.

The tool's HTTP client is plaintext `http://` only — its primary
target is the dev admin (`DWARA_ADMIN_DEV=1`, loopback-only
plaintext; the mTLS admin is a documented follow-up via the reserved
`--ca`/`--client-cert`/`--client-key` flags). Since the compose
gateway's admin binds `0.0.0.0:2019` with mTLS and dev mode refuses
non-loopback binds, the test runs a small host gateway from
`fixtures/tf-demo.yaml` (listener `127.0.0.1:18080`, dev admin
`127.0.0.1:20190`), exports its config, verifies the tfstate/HCL name
the known `echo-route`, plans clean (exit 0), then injects drift via
`PATCH /config` and verifies the plan catches it (exit 1).

## Config import (test-11)

`dwara-cli import nginx <config> --output <file>` scaffolds a Dwara
config from an existing NGINX config (DW-065): `server` blocks
(listen/server_name), `location` blocks with `proxy_pass` (match
modifiers `=` exact, none prefix, `~`/`~*` regex), and `upstream`
blocks with `server` endpoints. An NGINX `upstream backend` becomes
dwara `backend-upstream` + `backend-service`; a literal
`proxy_pass http://host:port` synthesizes `route-N-upstream`/
`route-N-service`. Unsupported constructs (`rewrite`, `auth_basic`,
`limit_req`, `if`, `try_files`, ...) are appended as YAML-comment
warnings, and the generated config always passes
`dwara-cli validate`.

The test imports `fixtures/nginx-demo.conf` (an upstream with two
endpoints plus three locations, one carrying an unsupported
`rewrite`) and asserts the generated routes (`route-0` prefix
`/api/` → `backend-service`, `route-1` exact `/exact` → synthesized
service), both upstream endpoints, the warnings block, and
validation. The same CLI imports Kong (`import kong`), Envoy
(`import envoy`), and OpenAPI 3.x (`import openapi`) configs.

## Kubernetes Gateway API (test-12, documented limitation)

Dwara implements a Gateway API controller (DW-064) that reconciles
Gateway API v1 resources (GatewayClass, Gateway, HTTPRoute) and
standard Ingress into its config model: the controller watches the
Kubernetes API server, translates watched resources into a Dwara
config YAML, and writes it to a file the gateway hot-reloads.
Supported: HTTP/HTTPS/TLS protocols, Terminate/Passthrough/Reencrypt
TLS modes, Exact/PathPrefix/RegularExpression path matches, header
and query matches, RequestRedirect/RequestHeaderModifier/
ResponseHeaderModifier/URLRewrite filters, GatewayClass/Gateway/
HTTPRoute status conditions, and Ingress (prefix/exact/
ImplementationSpecific, host routing, TLS terminate, defaultBackend,
IngressClass filtering).

**Limitation:** this category runs on docker compose, so the
controller's watch/reconcile loop has no cluster to run against. The
demo ships `fixtures/gateway.yaml` (GatewayClass with
`controllerName: shristilabs.com/dwara` + a Gateway with an HTTP
listener) and `fixtures/httproute.yaml` (parentRef + PathPrefix rules +
Service backendRefs) shaped to the translator's structs, and the test
verifies both plus the cluster-free CLI half:
`dwara-cli k8s conformance-report` generates the upstream Gateway API
conformance report YAML from the features the translator actually
supports. To run against a cluster: deploy
`deploy/k8s/base/` (raw manifests, or a Kustomize overlay / the Helm
chart — two containers per pod — the `dwara-k8s-controller` writing the
generated config to a shared volume, and the `dwara` gateway
hot-reloading it), then `kubectl apply -f fixtures/gateway.yaml -f
fixtures/httproute.yaml`. The translator is pinned cluster-free by
`cargo test -p dwara-core --test k8s_conformance` and
`--test k8s_controller`.

## Agent-operable admin (test-13)

Dwara ships agent-operable administration over MCP (Model Context
Protocol): a typed tool surface over the admin data model
(`list_routes`, `get_route`, `create_route`, `update_route`,
`delete_route`, `list_services`, `get_stats`, `get_health`,
`get_config`, `purge_cache`) with per-agent permissions
(read/write/admin RBAC) and JSON Schema argument validation
(`crates/dwara-core/src/mcp`).

The MCP **server** is a compile-time library capability with no
transport mounted yet — there is no `tools/call` endpoint on the
admin listener; an embedding constructs the `McpServer`, connects a
transport, and supplies a `ToolHandler`. That half is a documented
limitation (the test prints it; exercise the engine with
`cargo test -p dwara-core --features mcp mcp`).

What IS live on the admin listener (DW-087) and asserted by the test,
over the same mTLS every admin call needs:

- `GET /mcp/sessions` — list active MCP sessions from the state store
  (the demo runs with `DWARA_STATE_DB` set, so this is 200).
- `DELETE /mcp/sessions/:id` — idempotent session teardown (200).
- `GET /mcp/tools` — list configured MCP tools from the snapshot's
  `ai.mcp` block (`{"tools": []}` here — the demo configures none).
- `GET /mcp/calls?from_ms&to_ms` — MCP tool call analytics; without
  an analytics store the documented 404 `analytics_not_configured`
  envelope is the expected shape.

## Shared infrastructure

This demo reuses the shared certs and helper script under
`demos/_shared/`:

- `demos/_shared/certs/` — `server.crt`, `server.key`, `client-ca.crt`,
  `client.crt`, `client.key` (generated by the quickstart `gen-certs.sh`).
- `demos/_shared/helpers.sh` — `assert_status`, `assert_contains`,
  `assert_not_contains`, `wait_for`, `http_status`, `http_body`,
  `print_summary`.
