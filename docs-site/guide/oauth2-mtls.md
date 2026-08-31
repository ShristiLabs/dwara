# OAuth2 client-credentials and mTLS consumer mapping

The gateway can authenticate to an upstream with an [OAuth2](https://en.wikipedia.org/wiki/OAuth) (an authorization framework) access token
it obtains itself (the client-credentials grant), and it can map a
client's [mTLS](https://en.wikipedia.org/wiki/Mutual_authentication) (mutual TLS — both sides present certificates) certificate to a consumer at the gateway level without an
API key or JWT. Together these cover two service-to-service patterns:
the gateway as an OAuth2 client to the upstream, and the certificate as
the credential.

## When to use this

Two patterns are covered here. OAuth2 client-credentials is for when
an upstream requires a [Bearer token](https://www.rfc-editor.org/rfc/rfc6750) (a token presented in the Authorization header) the gateway must obtain itself
(service-to-service), and mTLS consumer mapping is for when a client's
certificate should identify the consumer at the gateway without a
separate API key or JWT. Use the former when the upstream speaks
OAuth2; use the latter when your clients already present client
certificates and you want the cert to be the credential.

## OAuth2 client-credentials proxying

Add an `oauth2_client_credentials` block to an upstream. The gateway
obtains an access token from the token endpoint using the
client-credentials grant ([RFC 6749](https://www.rfc-editor.org/rfc/rfc6749) [section 4.4](https://www.rfc-editor.org/rfc/rfc6749#section-4.4) (a grant where a machine client gets a token using its own credentials, no user)) and forwards it to the
upstream as `Authorization: Bearer <token>`, replacing any
client-supplied `Authorization` header:

```yaml
upstreams:
  - name: api
    endpoints:
      - address: 10.0.0.5
        port: 8443
    oauth2_client_credentials:
      token_endpoint: https://idp.example.com/oauth2/token
      client_id: dwara-gateway
      client_secret: ${IDP_CLIENT_SECRET}
      scopes: ["read", "write"]
      token_cache_ttl_s: 300
```

The client authenticates to the token endpoint with HTTP Basic auth
(`client_id:client_secret`, [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749) section 2.3.1). The secret may be
inline or a `${...}` reference (see [Secrets](./secrets)).

### Token caching

Tokens are cached per upstream and refreshed lazily — on the first
request after expiry, with no background refresh task. The cache TTL is
`min(expires_in - 60s, token_cache_ttl_s)` (or just `expires_in - 60s`
when no override is set), clamped to at least 1 second. The 60-second
skew avoids using a token that expires while an in-flight request is
still streaming. The cache survives config reloads.

Concurrent requests that need a token coalesce into one token-endpoint
POST (a per-upstream fetch lock), so a burst of traffic does not drive a
fetch-storm.

### mTLS to the token endpoint

If the token endpoint requires a client certificate ([RFC 8705](https://www.rfc-editor.org/rfc/rfc8705) (OAuth 2.0 mTLS)
`tls_client_auth`), add an `mtls` block:

```yaml
oauth2_client_credentials:
  token_endpoint: https://idp.example.com/oauth2/token
  client_id: dwara-gateway
  client_secret: ${IDP_CLIENT_SECRET}
  mtls:
    client_cert: /certs/gateway-client.crt.pem
    client_key: /certs/gateway-client.key.pem
```

The cert and key files are loaded at startup; a broken bundle disables
that upstream's OAuth2 (the upstream still proxies, just without the
Bearer token).

### Failure behavior

A token-endpoint failure (network error, non-2xx response, malformed
body) returns 502 `oauth2_token_unavailable` to the client. The gateway
never forwards without a token. The error response does not leak the
token endpoint's body or headers.

## Gateway-level mTLS consumer mapping

A listener with `client_ca_file` verifies client certificates at the
TLS layer. By default, a verified certificate is matched to a consumer
through that consumer's `mtls` credential (by subject CN ([CommonName](https://en.wikipedia.org/wiki/X.509) (the subject name field of a certificate)) or
fingerprint). The gateway-level `mtls_consumer_mapping` is an
alternative: a single table that maps certificates to consumers
independent of the per-consumer credential registry.

```yaml
mtls_consumer_mapping:
  enabled: true
  consumers:
    - fingerprint: "ab:cd:ef:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc"
      consumer: acme
  subject_cn_mapping:
    acme-client: acme
```

Two mapping strategies, checked in order:

1. **Subject CN** (`subject_cn_mapping`): maps the certificate's subject
   [CommonName](https://en.wikipedia.org/wiki/X.509) (the subject name field of a certificate) to a consumer. Binding by subject CN survives certificate
   re-issue under the same CN.
2. **Fingerprint** (`consumers[].fingerprint`): the [SHA-256](https://en.wikipedia.org/wiki/SHA-2) of the
   certificate [DER](https://en.wikipedia.org/wiki/X.690#DER_encoding) (a binary encoding of an X.509 certificate) as lowercase colon-separated hex. An exact DER match
   — a re-issued certificate needs a new entry.

When the mapping is enabled with entries but a verified certificate
matches no entry, the gateway returns 401 `mtls_consumer_not_mapped`.
The mapping is authoritative when enabled: it does not fall through to
the per-consumer `mtls` credential registry. When the mapping is absent
or disabled, certificates are matched only through consumers' `mtls`
credentials.

A client that presents no certificate on a listener with the mapping
enabled falls through to the other authentication families (or 401 if
the route requires auth and no family resolves).

## X-Client-Cert-* identity forwarding

When mTLS client auth is used, the gateway can forward certificate
metadata to the upstream as `X-Client-Cert-*` headers:

```yaml
mtls_forward_headers:
  enabled: true
  prefix: X-Client-Cert          # default; configurable
```

The gateway adds four headers from the verified client certificate:

| Header | Content |
|---|---|
| `X-Client-Cert-Fingerprint` | [SHA-256](https://en.wikipedia.org/wiki/SHA-2) of the cert DER, colon-separated hex |
| `X-Client-Cert-Subject-CN` | Subject [CommonName](https://en.wikipedia.org/wiki/X.509) (the subject name field of a certificate) |
| `X-Client-Cert-Issuer-CN` | Issuer [CommonName](https://en.wikipedia.org/wiki/X.509) (the subject name field of a certificate) |
| `X-Client-Cert-Not-After` | Certificate expiry as an RFC 3339 timestamp |

Absent metadata (e.g. a certificate with no decodable CN) is simply not
injected — the upstream sees fewer headers, never an empty value.

### Spoofing prevention

These headers are gateway-set. Any inbound headers whose names start
with the configured prefix are stripped from the client request before
the gateway adds its own. A client cannot claim certificate identity
upstream — the upstream always sees the gateway's computed values.

## Security notes

- The OAuth2 `client_secret` is resolved at config-compile time (inline
  or `${...}` reference) and never logged, never appears in `Debug`
  output, and never appears in error text. See [Secrets](./secrets).
- The token cache is per-instance (M2 is a single-process deployment).
  A multi-instance fleet would re-fetch tokens per instance; a shared
  token cache is the enterprise/Redis seam, not this feature.
- The `X-Client-Cert-*` headers carry metadata the upstream uses for
  audit/logging, not for authentication. The gateway's authn already
  resolved the consumer; these headers are a convenience for the
  upstream that cannot see the TLS handshake.
- mTLS consumer mapping is per-instance: the certificate-to-consumer
  table is config-declared and identical across instances, but the
  mapping is only as current as the config reload.
