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

`GET /config` never returns secret values: inline API keys appear as
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
