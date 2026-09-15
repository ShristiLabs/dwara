# Authentication in detail

## API keys

```yaml
consumers:
  - name: mobile-app
    credentials:
      - type: api_key
        key: ${MOBILE_API_KEY}      # secret refs allowed
```

- Presented via `X-API-Key` header (or a query parameter).
- Stored/compared as **peppered hashes** (`hmac-sha256:<hex>`) - configure
  `DWARA_CREDENTIAL_PEPPER` (and `_PREVIOUS` during rotation) since
  verification needs the same pepper the key was issued under.
- Issue/rotate through the admin API (`POST /consumers/{name}/credentials`,
  16..=512-byte keys; dual-validity window; retire with
  `POST /credentials/{id}/retire`) - see dwara-operations.

## JWT (JWKS)

```yaml
jwt_providers:
  - name: auth0
    jwks_url: https://auth.example.com/.well-known/jwks.json
    issuer: https://auth.example.com        # validated against the token iss
    audience: api-service                   # validated against aud
    consumer: mobile-app                    # resolved consumer on success
    algorithms: [RS256, ES256]
    leeway_secs: 30                         # clock skew tolerance
    refresh_secs: 300                       # key set refresh
    retired_key_grace_secs: 86400           # demoted keys stay valid 24h (cap 7d; 0=off)
```

Keys fetch lazily on first Bearer token - the gateway starts even if the
IdP is unreachable. JWT-scopes/claims feed `required_scopes` /
`required_claims` authz rules (JWT-authenticated routes only; API keys
carry no scopes).

## OIDC (RFC 7662 introspection)

```yaml
oidc_providers:
  - name: keycloak
    issuer: https://idp.example.com         # discovery; issuer mismatch = hard error
    client_id: dwara
    client_secret: ${OIDC_CLIENT_SECRET}
    consumer: mobile-app
    scopes: [openid, profile]
    fail_open: false                        # IdP unreachable: true = let through,
    introspection_cache_ttl_s: 60           # false = 401. `active:false` is
                                            # ALWAYS 401 either way, never cached.
```

`fail_open: true` + `auth_required: true` still 401s on authn failure -
fail-open applies to introspection *availability*, not to missing
credentials.

## HMAC request signing

Client sends five headers: `X-Dwara-Key-Id`, `X-Dwara-Timestamp`,
`X-Dwara-Nonce` (16..=256 bytes), `X-Dwara-Body-Sha256`,
`X-Dwara-Signature`. Canonical string = `dwara-hmac-v1` + 7 lines (key id,
METHOD, path, query, timestamp, nonce, body digest); signature is
HMAC-SHA256 with the consumer's `hmac` credential secret (raw bytes -
HMAC secrets are never hashable).

```yaml
hmac_auth:
  max_clock_skew_secs: 300      # nonce replay window = 2x skew (per-instance)
```

Requests without `X-Dwara-Signature` are treated as unsigned (fall through
to other families). Unknown key id produces the same 401 shape/timing as a
bad signature (no key probing). Challenge header:
`WWW-Authenticate: Dwara-HMAC-SHA256 realm="dwara"`. The signature does not
cover `Host`.

## mTLS client certificates

1. Listener requires client certs: `tls.client_ca_file`.
2. Map certs to consumers - either a per-consumer credential
   (`type: mtls`, `subject: <CN>`), or the authoritative global mapping:

```yaml
mtls_consumer_mapping:
  enabled: true
  subject_cn_mapping:
    partner-cn-name: partner-consumer      # CN checked BEFORE fingerprints
  # consumers:                             # fingerprint entries: lowercase
  #   - name: partner-consumer             # colon-hex SHA-256 of cert DER
  #     fingerprint: ab:cd:...
```

When the mapping is enabled, an unmapped verified cert is `401
mtls_consumer_not_mapped` - **no fall-through** to other families. No cert
at all falls through (TLS cert presence is a listener concern; authn can
still come from API key/JWT).

Forward cert metadata upstream (audit-only, never authentication):

```yaml
mtls_forward_headers:
  enabled: true
  prefix: X-Client-Cert     # -> -Fingerprint, -Subject-CN, -Issuer-CN, -Not-After
```

Inbound headers carrying the prefix are stripped (anti-spoof).

## Basic

`Authorization: Basic` entries live in the **state store**, not the config
file - seed/rotate them via the admin API. Suitable for internal tooling;
prefer API keys or JWT for anything external.

## Authn/authz interplay reminders

- `auth_required: true` on a route: no recognized credential -> 401 before
  authz runs. It is an authn-phase switch and is never muted by `dry_run`.
- A credential resolves exactly one consumer; multiple families on one
  consumer are alternatives, not conjunctions.
- Effective client IP (after `trusted_proxies`/XFF resolution) is what IP
  ACLs, GeoIP, and rate-limit `ip` selectors see.
