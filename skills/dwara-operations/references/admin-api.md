# Admin API reference

Enabled by the `admin:` block; mTLS mandatory. Default bind
`127.0.0.1:2019`. Endpoints exist under both `/v1/` and legacy bare paths.
`GET /v1/openapi.json` is the machine-readable spec of the surface itself.

## Auth

- Client certificate chaining to `admin.tls.client_ca_file` (all three TLS
  files required - no plaintext admin listener).
- Optional `api_tokens.tokens[]`: `token_hash` = SHA-256 hex of the bearer
  token, `role: admin|readonly`; sent as `Authorization: Bearer`.
- Optional `rbac.bindings[]`: `cert_fingerprint` (SHA-256 of cert DER, 64
  lowercase hex) -> role; fail-closed when configured.
- Optional `audit.enabled: true` -> append-only log of every mutation
  (target `dwara::admin::audit`).

## Config

| Call | Behavior |
| --- | --- |
| `GET /config` | Normalized YAML, secrets redacted to `${redacted:sha256:<8hex>}`. Response headers `x-dwara-config-generation`, `x-dwara-config-hash`. |
| `PATCH /config` | **Full-document YAML replacement** (no partial merge). Pipeline dry-run first: invalid -> `400` listing every issue; valid -> atomic write + publish. >4 MiB body -> `413`. Patching a redacted placeholder verbatim -> `400`. |

Safe edit pattern: fetch the source file (not the redacted echo), edit,
`dwara-cli validate`, then PATCH the whole document.

## Runtime

| Call | Returns |
| --- | --- |
| `GET /health` | Readiness, config generation, per-upstream/endpoint health |
| `GET /runtime_info` | Version, uptime, generation, config hash, readiness |
| `GET /stats` (+`?format=prometheus`) | Schema version, breaker states, `active_requests`; Prometheus dump |
| `GET /clusters` | Envoy-style cluster dump |
| `GET /config_dump` | Full config as redacted JSON |
| `POST /cache/purge` | Body `{"route": name}` \| `{"all": true}` \| `{"tag": t}` \| `{"url": u, "prefix": bool}` |

## Entity CRUD (optimistic concurrency)

`GET|POST|PUT|DELETE` on `/routes`, `/services`, `/upstreams`,
`/consumers`, `/policies` (and `/{name}` / `/{name}` subpaths):

- Duplicates -> `409`; missing -> `404`.
- Every GET returns an `ETag`; mutations may send `If-Match` ->
  `412` on mismatch (someone changed it first). Omitting `If-Match` =
  last-write-wins.
- Listeners are NOT CRUD-managed (file/PATCH only).

## Consumers and credentials lifecycle

| Call | Purpose |
| --- | --- |
| `GET /consumers/{name}/credentials` | List credentials with lifecycle stamps |
| `POST /consumers/{name}/credentials` | Issue a key (16..=512 bytes) - dual-validity window with the old key |
| `POST /credentials/{id}/retire` | Retire now (empty body) or schedule `{"at_ms": ...}` (only earlier than current); enforcement is lazy |

## Analytics endpoints (404 when analytics unconfigured)

`GET /analytics/dashboard` (granularity 0..3, group_by), `GET
/analytics/top?kind=consumers|routes|slowest|error_prone|rate_limited`,
`POST /analytics/query` (closed JSON grammar - no raw SQL), `GET|POST
/analytics/exports` + `POST /analytics/exports/run`, `GET /analytics/live`,
`GET /analytics/forecast`, `GET /analytics/anomalies`.

## Quotas

`GET /quotas/usage` ->
`{now_epoch_s, consumers: [{consumer, synced, budgets: [{budget, limit,
used, remaining, window_start_epoch_s, reset_epoch_s}]}]}`. Requires
`DWARA_STATE_DB` (else `404 state_store_not_configured`). Bad consumer name
-> `400 quota_bad_consumer`.

## AI surface (see dwara-ai-gateway skill)

`GET /ai/credential-pools[?provider=]` (quarantine status, no secrets),
`POST /analytics/spend`, `POST /analytics/prompt-logs`,
`POST /analytics/governance-audit`, `GET|DELETE /mcp/sessions[/:id]`,
`GET /mcp/tools`, `GET /mcp/calls`, `PUT|GET|DELETE
/experiments/prompt-overrides`, `POST /experiments/feedback`,
`POST /experiments/verdict`.

## CLI wrappers

`dwara-cli status [--admin URL]` (one-shot snapshot; `DWARA_ADMIN` env,
default `http://127.0.0.1:2019`), `dwara-cli top [--interval ms]` (live
LB/breaker view), `dwara-cli tf *` (Terraform-shaped state operations - see
dwara-migration skill).

## curl recipes (mTLS)

```sh
ADMIN=https://127.0.0.1:2019
CERTS=(--cert client.crt --key client.key --cacert server.crt)

curl "${CERTS[@]}" $ADMIN/health
curl "${CERTS[@]}" $ADMIN/stats?format=prometheus | grep breaker_state
curl "${CERTS[@]}" -X POST $ADMIN/cache/purge \
     -H 'Content-Type: application/json' -d '{"route": "api-v1"}'

# ETag-guarded route update
ETAG=$(curl "${CERTS[@]}" -sD - -o /dev/null $ADMIN/routes/api-v1 | awk -F'"' '/^etag:/i{print $2}')
curl "${CERTS[@]}" -X PUT $ADMIN/routes/api-v1 -H "If-Match: $ETAG" \
     -H 'Content-Type: application/yaml' --data-binary @route.yaml
```

Note: `dwara-cli status/top` default to plaintext `http://` because
`DWARA_ADMIN_DEV` gateways are loopback-dev; against a production admin
endpoint set `DWARA_ADMIN=https://...` and ensure the CLI build's TLS
options apply (mTLS flags are the documented follow-up - prefer curl for
cert-authenticated calls today).
