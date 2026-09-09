# Admin API

The admin API is a separate, small operator surface. It is
**default-off**: no `admin` block in the config means no admin listener
starts at all.

## When to use this

Use the admin API for live inspection and patching of a running gateway
without a restart — rotating credentials, purging cache, checking
health, and patching config in a managed deployment. It is default-off
and [mutual TLS](https://en.wikipedia.org/wiki/Mutual_authentication) (mTLS) (both sides present certificates) only, so enable it only on
hosts where an operator can present a signed client certificate.

```yaml
admin:
  bind: 127.0.0.1:2019     # default; loopback-only out of the box
  tls:
    cert_file: /etc/dwara/admin.crt.pem
    key_file: /etc/dwara/admin.key.pem
    client_ca_file: /etc/dwara/admin-clients.ca.pem
```

## Authentication

The admin listener always terminates TLS and **requires** a client
certificate (an X.509 certificate the operator presents to prove identity) chaining to `client_ca_file`. All three TLS files are
mandatory; a config with an `admin` block missing `client_ca_file` is
rejected rather than silently serving no-auth TLS.

By default (no `rbac` or `api_tokens` blocks), possession of a valid
client certificate is the authorization — the v1 behavior. For larger
deployments that need finer-grained access control, RBAC and API tokens
are opt-in additions to the mTLS foundation.

A sketch of the certificate setup:

```sh
# CA for admin clients
openssl req -x509 -newkey rsa:2048 -nodes -keyout admin-clients.ca.key \
  -out admin-clients.ca.pem -days 3650 -subj "/CN=dwara-admin-clients"
# server certificate the admin listener presents
openssl req -x509 -newkey rsa:2048 -nodes -keyout admin.key.pem \
  -out admin.crt.pem -days 365 -subj "/CN=dwara-admin"
# one client certificate per operator
openssl req -newkey rsa:2048 -nodes -keyout operator.key \
  -out operator.csr -subj "/CN=operator"
openssl x509 -req -in operator.csr -CA admin-clients.ca.pem \
  -CAkey admin-clients.ca.key -CAcreateserial -out operator.crt -days 365
```

```sh
curl --cert operator.crt --key operator.key https://127.0.0.1:2019/config
```

A connection without a client certificate (or one signed by the wrong
CA) fails the TLS handshake before any HTTP is exchanged.

## RBAC: role-based access control

When the `rbac` block is present, the gateway maps client certificate
fingerprints to roles. A valid certificate with no binding is denied
(fail-closed: no implicit admin).

```yaml
admin:
  bind: 127.0.0.1:2019
  tls:
    cert_file: /etc/dwara/admin.crt.pem
    key_file: /etc/dwara/admin.key.pem
    client_ca_file: /etc/dwara/admin-clients.ca.pem
  rbac:
    bindings:
      - cert_fingerprint: "a1b2c3..."  # SHA-256 of client cert DER, 64 lowercase hex
        role: admin
      - cert_fingerprint: "d4e5f6..."
        role: readonly
```

The fingerprint is the SHA-256 of the full DER encoding of the client
certificate, as 64 lowercase hex characters. Two roles are supported:

- **`admin`** — full access to all admin endpoints (read and mutate).
- **`readonly`** — `GET` endpoints only; `PATCH /config`, `POST
  /cache/purge`, and other mutating actions return 403.

When `rbac` is absent, every CA-valid certificate is treated as `admin`
(the v1 behavior, preserved for backward compatibility).

## API tokens

When the `api_tokens` block is present, the admin API also accepts
`Authorization: Bearer <token>` as an alternative to mTLS. The token
is SHA-256 hashed and compared against the configured `token_hash`
values. Tokens are never logged.

```yaml
admin:
  api_tokens:
    tokens:
      - token_hash: "a1b2c3..."  # SHA-256 of plaintext token, 64 lowercase hex
        role: admin
      - token_hash: "d4e5f6..."
        role: readonly
```

Token authentication complements mTLS rather than replacing it: mTLS
remains the transport requirement (the listener still requires a client
certificate), and the token provides an additional identity layer for
environments where certificate-to-role mapping is impractical. The
`role` field follows the same vocabulary as RBAC (`admin` or
`readonly`).

Token rotation is manual: generate a new token, compute its SHA-256
hash, add it to the config, reload, then remove the old token hash.

## Audit log

When the `audit` block is present and `enabled: true`, all mutating
admin actions (`PATCH /config`, `POST /cache/purge`) are recorded with
the actor identity (cert fingerprint or token hash), the action, the
before/after config hash, and a timestamp.

```yaml
admin:
  audit:
    enabled: true
```

Audit entries are emitted as structured log events with the
`dwara::admin::audit` target. Configure log retention and collection
through your standard log pipeline (see
[Observability](./observability)). Audit storage grows unbounded;
configure retention at the log collector, not in the gateway.

## Endpoints

| Method & path | Purpose |
| --- | --- |
| `GET /config` | current published config as normalized YAML, with secret values redacted (see [Secrets](./secrets#reading-get-config)); `x-dwara-config-generation` / `x-dwara-config-hash` headers identify the generation |
| `PATCH /config` | full-document YAML replacement (no partial merge); dry-run parsed/validated/compiled first — any issue returns 400 with every problem; on success, written atomically to the config file and published |
| `GET /health` | readiness, current generation, per-upstream per-endpoint health labels |
| `GET /stats` | store schema version, per-upstream breaker state, `active_requests`, config generation |
| `GET /stats?format=prometheus` | full Prometheus text-format metric dump — the same output as the `/metrics` endpoint, reachable through the admin surface for Envoy-style tooling |
| `GET /clusters` | Envoy-style cluster dump: per upstream — algorithm, scheme, connection/request counters, breaker state, and per-endpoint health + inflight counts |
| `GET /config_dump` | full published gateway config as redacted JSON with generation/hash headers — the structured equivalent of `GET /config` (which returns YAML) |
| `GET /runtime_info` | process-level runtime info: version, uptime, config generation, config hash, readiness |
| `POST /cache/purge` | response-cache invalidation: `{\"route\": \"<name>\"}` to purge one route's entries (O(1) epoch advance), `{\"all\": true}` to advance the epoch for every cache-enabled route, `{\"tag\": \"<tag>\"}` to delete every entry the upstream tagged with that `Cache-Tags` value, or `{\"url\": \"<path[?query]>\", \"prefix\": false}` to delete entries for an exact or prefix-matched request URL (responses `hit`/`stale` become `miss` on next request) |
| `GET /quotas/usage` | per-consumer request-budget metering: current-window used vs. limit for each budgeted consumer (requires the state store, `DWARA_STATE_DB`; see [Consumer quotas](./quotas)) |
| `GET` / `POST /consumers/{name}/credentials` | list a consumer's credentials (lifecycle stamps only) / issue a new API key, opening the dual-validity window — see [Key rotation workflows](#key-rotation-workflows) |
| `POST /credentials/{id}/retire` | retire (or schedule retirement of) a credential — see [Key rotation workflows](#key-rotation-workflows) |
| `GET /analytics/dashboard`, `GET /analytics/top`, `POST /analytics/query`, `GET /analytics/exports`, `POST /analytics/exports/run` | the embedded analytics store's query surface — see [Analytics](./analytics) |
| `GET /analytics/live`, `GET /analytics/forecast`, `GET /analytics/anomalies` | live sketch snapshot, capacity forecast, and anomaly status — see [Analytics](./analytics#live-sketches) |

`PATCH /config` bodies over 4 MiB are rejected with 413; concurrent
PATCHes are serialized. Errors use the same JSON error envelope as the
dataplane (see [Observability](./observability#error-envelope)),
including `405` for a known path with the wrong method and `404` for
unknown admin paths — one error shape to grep across both surfaces.
The admin listener drains gracefully on shutdown alongside the gateway.

`GET /config` never returns secret values: inline API keys and HMAC
signing secrets appear as
`${redacted:sha256:<prefix>}` fingerprints and `${...}` references
echo unchanged. A `PATCH` that carries a redacted placeholder back is
rejected with `400` naming the field — a placeholder can never become
a live key; re-enter the real key or switch the field to a reference
(see [Secrets](./secrets#reading-get-config)).

## Dev fallback — never in production

`DWARA_ADMIN_DEV=1` serves the admin API as **plaintext**, and refuses
to start unless the admin bind is loopback. It exists purely so you can
`curl` the admin API from a developer machine without generating
certificates. It removes the admin surface's only authentication —
never set it in production or on a shared host.

## Key rotation workflows

The frozen rotation procedure (zero failed requests mid-window):

1. **Issue** `POST /consumers/{name}/credentials {"key": "<new>"}` —
   hashed with the dataplane's pepper (a deployment-wide secret mixed into stored credential hashes) state (16..=512 bytes enforced).
   The dual-validity window OPENS: old and new keys authenticate
   simultaneously from the next request.
2. **Switch clients** to the new key at your leisure. Both keys work.
3. **Retire the old key** `POST /credentials/{id}/retire` — empty body
   for immediate, `{"at_ms": <epoch ms>}` to schedule the far edge.
   Retirement is lazy (no sweeper): the SQL lookup filters it and the
   registry re-checks cached rows, so the boundary lands on time.
   Retirement can only move EARLIER; to postpone, issue another key.
   `GET /consumers/{name}/credentials` lists rows with lifecycle
   stamps only (never selector/hash material).

[JWKS](https://www.rfc-editor.org/rfc/rfc7517) (a JSON document of signing keys) rotation is bridged by `retired_key_grace_secs` (default 24 h,
0 disables, capped 7 days): when a fetch delivers a changed kid (key id — the label that picks which signing key to use) set,
the superseded set keeps verifying dropped kids through the grace —
issuers remove old keys while previously-issued tokens still carry
them. An identical-kid re-fetch never extends the grace. Config-only
deployments rotate by editing the config (two credential entries)
and reloading.

## GeoIP rules

Any [authorization](../reference/configuration-schema) block can gate
on the client's COUNTRY or network ([ASN](https://en.wikipedia.org/wiki/Autonomous_system_(Internet)) (Autonomous System Number — identifies a network)), resolved from a [MaxMind](https://en.wikipedia.org/wiki/MaxMind) (a geo-IP database vendor)
database:

```yaml
geoip:
  path: /var/lib/dwara/GeoLite2-Country.mmdb

routes:
  - name: public
    # ...
    authorization:
      geoip:
        denied_countries: [KP, IR]   # reject these countries
        allowed_countries: []        # empty = any not denied
        denied_asns: [64512]         # reject this network
```

Rules evaluate the EFFECTIVE client IP (the [`X-Forwarded-For`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For)-resolved
address behind trusted proxies — the same address IP ACLs use).
Addresses the database cannot resolve (private ranges, not-in-DB)
count as UNKNOWN: deny lists pass them, allow lists reject them. The
database hot-reloads — replace the file and the watcher swaps the
reader within a couple of seconds, no restart. Geo rules require the
`geoip` block; validation rejects the predicate without one.

## Runnable demo

Run the mTLS admin API against a live gateway: `demos/09-operations/`
in the repository (test script: `test-02-admin-api.sh` -- `/health`,
`/config`, and `/stats` over mTLS, plus a handshake failure without a
client cert). The category README covers prerequisites and teardown.
