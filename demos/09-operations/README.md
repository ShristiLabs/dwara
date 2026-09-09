# Category 09: Operations & Config Management

Demonstrates the operator-facing surface of the dwara gateway: hot
config reload, the mTLS-only admin API, config validation, and secret
references resolved from the environment.

## What this demo runs

Three containers on a single docker bridge network (`ops-net`):

| Service | Image | Role |
|---------|-------|------|
| `dwara` | `dwara:demo` | The gateway (HTTP on :8080, admin API on :2019) |
| `echo`  | `dwara-demo/echo` | Reflects the request as JSON |
| `static` | `dwara-demo/static` | Serves demo HTML + JSON files |

The gateway runs as the nonroot UID `65532:65532` (scratch has no
users, so the UID is injected via `user:`). The config is mounted
read-only at `/etc/dwara/dwara.yaml`; the shared certs are mounted at
`/etc/dwara/certs`; a local `./data` directory backs the SQLite state
DB so consumer/credential seeding survives restarts.

## Layout

```
09-operations/
  docker-compose.yml      # the three-service compose
  dwara.yaml              # gateway config (listeners, routes, admin, secrets)
  data/                   # SQLite state DB (created on first run)
  test-01-hot-reload.sh   # hot config reload on file change
  test-02-admin-api.sh    # mTLS admin API (/health, /config, /stats)
  test-03-cli-validate.sh # config validation
  test-08-secrets.sh      # ${ENV_NAME} secret references
  README.md               # this file
```

## Running

```sh
docker compose up -d
./test-01-hot-reload.sh
./test-02-admin-api.sh
./test-03-cli-validate.sh
./test-08-secrets.sh
docker compose down
```

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

## Shared infrastructure

This demo reuses the shared certs and helper script under
`demos/_shared/`:

- `demos/_shared/certs/` — `server.crt`, `server.key`, `client-ca.crt`,
  `client.crt`, `client.key` (generated by the quickstart `gen-certs.sh`).
- `demos/_shared/helpers.sh` — `assert_status`, `assert_contains`,
  `assert_not_contains`, `wait_for`, `http_status`, `http_body`,
  `print_summary`.
