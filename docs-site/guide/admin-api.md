# Admin API

The admin API is a separate, small operator surface. It is
**default-off**: no `admin` block in the config means no admin listener
starts at all.

```yaml
admin:
  bind: 127.0.0.1:2019     # default; loopback-only out of the box
  tls:
    cert_file: /etc/dwara/admin.crt.pem
    key_file: /etc/dwara/admin.key.pem
    client_ca_file: /etc/dwara/admin-clients.ca.pem
```

## Authentication: mutual TLS only

The admin listener always terminates TLS and **requires** a client
certificate chaining to `client_ca_file` — there is no token/password
layer. Possession of a valid client certificate is the authorization.
All three TLS files are mandatory; a config with an `admin` block
missing `client_ca_file` is rejected rather than silently serving
no-auth TLS.

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

## Endpoints

| Method & path | Purpose |
| --- | --- |
| `GET /config` | current published config as normalized YAML, with secret values redacted (see [Secrets](./secrets#reading-get-config)); `x-dwara-config-generation` / `x-dwara-config-hash` headers identify the generation |
| `PATCH /config` | full-document YAML replacement (no partial merge); dry-run parsed/validated/compiled first — any issue returns 400 with every problem; on success, written atomically to the config file and published |
| `GET /health` | readiness, current generation, per-upstream per-endpoint health labels |
| `GET /stats` | store schema version, per-upstream breaker state, `active_requests`, config generation |

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

## Key rotation workflows (DW-046)

Source: state store schema v5 + `security::authn` + the admin
credential endpoints. Tests: `authn` rotation cases, `store`
retirement lifecycle, `admin_api` credential endpoints.

The frozen rotation procedure (zero failed requests mid-window):

1. **Issue** `POST /consumers/{name}/credentials {"key": "<new>"}` —
   hashed with the dataplane's pepper state (16..=512 bytes enforced).
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

JWKS rotation is bridged by `retired_key_grace_secs` (default 24 h,
0 disables, capped 7 days): when a fetch delivers a changed kid set,
the superseded set keeps verifying dropped kids through the grace —
issuers remove old keys while previously-issued tokens still carry
them. An identical-kid re-fetch never extends the grace. Config-only
deployments rotate by editing the config (two credential entries)
and reloading.

## GeoIP rules (DW-050)

Any [authorization](../reference/configuration-schema) block can gate
on the client's COUNTRY or network (ASN), resolved from a MaxMind
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

Rules evaluate the EFFECTIVE client IP (the `X-Forwarded-For`-resolved
address behind trusted proxies — the same address IP ACLs use).
Addresses the database cannot resolve (private ranges, not-in-DB)
count as UNKNOWN: deny lists pass them, allow lists reject them. The
database hot-reloads — replace the file and the watcher swaps the
reader within a couple of seconds, no restart. Geo rules require the
`geoip` block; validation rejects the predicate without one.
