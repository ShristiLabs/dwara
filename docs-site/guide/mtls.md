# mTLS

[mTLS](https://en.wikipedia.org/wiki/Mutual_authentication) (mutual
TLS -- both sides present certificates) appears in Dwara in three
places. At the gateway, a listener verifies client certificates and
maps them to consumers, so the certificate is the credential -- no
API key or JWT needed. On upstream connections, the gateway presents
a client certificate to an upstream TLS server that requires one. And
either way, certificate metadata can be forwarded to the upstream as
`X-Client-Cert-*` headers.

This page covers client-certificate authentication at the gateway and
upstream mTLS where the gateway presents the client cert. The related
OAuth2 flow -- where the gateway presents a client certificate to a
token endpoint -- is covered in [OAuth2](./oauth2).

## When to use this

Use gateway-level mTLS when your clients already present client
certificates and you want the cert to be the credential: zero-trust
internal meshes and high-assurance deployments with no secret in the
request at all. Use upstream mTLS when an upstream TLS server
requires the gateway to authenticate with a client certificate. If
the upstream accepts a Bearer token instead, [OAuth2](./oauth2)
client credentials are the simpler fit.

## Configuration

A listener with `client_ca_file` verifies client certificates at the
TLS layer. By default, a verified certificate is matched to a
consumer through that consumer's `mtls` credential (by subject CN
([CommonName](https://en.wikipedia.org/wiki/X.509) (the subject name
field of a certificate)) or fingerprint). The gateway-level
`mtls_consumer_mapping` is an alternative: a single table that maps
certificates to consumers independent of the per-consumer credential
registry.

```yaml
mtls_consumer_mapping:
  enabled: true
  consumers:
    - fingerprint: "ab:cd:ef:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc"
      consumer: acme
  subject_cn_mapping:
    acme-client: acme
```

| Field | Default | Description |
|---|---|---|
| `enabled` | `false` | Enables the mapping table. |
| `consumers[].fingerprint` | required | [SHA-256](https://en.wikipedia.org/wiki/SHA-2) of the certificate [DER](https://en.wikipedia.org/wiki/X.690#DER_encoding) as lowercase colon-separated hex. |
| `consumers[].consumer` | required | Consumer the fingerprint maps to. |
| `subject_cn_mapping` | none | Map of certificate subject [CommonName](https://en.wikipedia.org/wiki/X.509) (the subject name field of a certificate) to consumer. Checked before fingerprints. |

The other mTLS blocks -- `mtls_forward_headers` for identity
forwarding and the per-upstream `mtls` block for upstream client
certificates -- are shown in their sections below.

## How it works

Two mapping strategies, checked in order:

1. **Subject CN** (`subject_cn_mapping`): maps the certificate's
   subject [CommonName](https://en.wikipedia.org/wiki/X.509) (the
   subject name field of a certificate) to a consumer. Binding by
   subject CN survives certificate re-issue under the same CN.
2. **Fingerprint** (`consumers[].fingerprint`): the
   [SHA-256](https://en.wikipedia.org/wiki/SHA-2) of the certificate
   [DER](https://en.wikipedia.org/wiki/X.690#DER_encoding) (a binary
   encoding of an X.509 certificate) as lowercase colon-separated
   hex. An exact DER match -- a re-issued certificate needs a new
   entry.

When the mapping is enabled with entries but a verified certificate
matches no entry, the gateway returns 401 `mtls_consumer_not_mapped`.
The mapping is authoritative when enabled: it does not fall through
to the per-consumer `mtls` credential registry. When the mapping is
absent or disabled, certificates are matched only through consumers'
`mtls` credentials.

A client that presents no certificate on a listener with the mapping
enabled falls through to the other authentication families (or 401
if the route requires auth and no family resolves).

## X-Client-Cert-* identity forwarding

When mTLS client auth is used, the gateway can forward certificate
metadata to the upstream as `X-Client-Cert-*` headers:

```yaml
mtls_forward_headers:
  enabled: true
  prefix: X-Client-Cert          # default; configurable
```

| Field | Default | Description |
|---|---|---|
| `enabled` | `false` | Enables forwarding of certificate metadata headers. |
| `prefix` | `X-Client-Cert` | Header-name prefix for the forwarded headers. |

The gateway adds four headers from the verified client certificate:

| Header | Content |
|---|---|
| `X-Client-Cert-Fingerprint` | [SHA-256](https://en.wikipedia.org/wiki/SHA-2) of the cert DER, colon-separated hex |
| `X-Client-Cert-Subject-CN` | Subject [CommonName](https://en.wikipedia.org/wiki/X.509) (the subject name field of a certificate) |
| `X-Client-Cert-Issuer-CN` | Issuer [CommonName](https://en.wikipedia.org/wiki/X.509) (the subject name field of a certificate) |
| `X-Client-Cert-Not-After` | Certificate expiry as an RFC 3339 timestamp |

Absent metadata (e.g. a certificate with no decodable CN) is simply
not injected -- the upstream sees fewer headers, never an empty
value.

### Spoofing prevention

These headers are gateway-set. Any inbound headers whose names start
with the configured prefix are stripped from the client request
before the gateway adds its own. A client cannot claim certificate
identity upstream -- the upstream always sees the gateway's computed
values.

## Upstream mTLS client certificates

The gateway can present a client certificate when connecting to
upstream TLS servers that require client authentication. This is
separate from the OAuth2 mTLS flow: it applies to the upstream TLS
handshake itself, not to a token endpoint (for that, see
[OAuth2](./oauth2)).

Add an `mtls` block to an `https` or `http2` upstream:

```yaml
upstreams:
  - name: secure-backend
    protocol: https
    mtls:
      client_cert_file: /path/to/client.crt
      client_key_file: /path/to/client.key
    endpoints:
      - address: 10.0.0.1
        port: 8443
```

| Field | Default | Description |
|---|---|---|
| `client_cert_file` | required | PEM-encoded client certificate chain. |
| `client_key_file` | required | PEM-encoded private key for the client certificate. |

The cert and key files are loaded at config compile time using rustls
`with_client_auth_cert`. If the files cannot be loaded, the gateway
logs an error and the upstream's TLS handshake will fail (the
upstream rejects the connection if it requires mTLS).

mTLS is only valid for `https` and `http2` upstreams. Validation
rejects `mtls` on `http1` upstreams (no TLS is negotiated). The cert
and key files must exist and be readable at compile time; validation
names the offending field if not.

### Interaction with certificate pinning

When both `mtls` and `cert_pinning` are configured on the same
upstream, pinning takes precedence in the current implementation: the
custom pinning verifier is used and the client certificate is not
presented. This is a known limitation; a future change will combine
the custom pinning verifier with client auth.

### Alternatives

- **OAuth2 client credentials:** if the upstream accepts a Bearer
  token instead of a client certificate, use
  `oauth2_client_credentials` (see [OAuth2](./oauth2)) instead of
  mTLS.
- **Service mesh (Istio, Linkerd):** delegate mTLS to the service
  mesh sidecar. The gateway connects plaintext to the sidecar, which
  handles mTLS.
- **SPIFFE/SPIRE:** use SPIFFE SVIDs instead of static client
  certificates for automatic rotation.

## Security notes

- The `X-Client-Cert-*` headers carry metadata the upstream uses for
  audit/logging, not for authentication. The gateway's authn already
  resolved the consumer; these headers are a convenience for the
  upstream that cannot see the TLS handshake.
- mTLS consumer mapping is per-instance: the certificate-to-consumer
  table is config-declared and identical across instances, but the
  mapping is only as current as the config reload.

## Where to go next

- [OAuth2](./oauth2) - the gateway as an OAuth2 client-credentials
  client to upstreams, including mTLS to the token endpoint.
- [Authentication methods](./authentication-methods) - how the mTLS
  client-cert family compares to API keys, JWT, HMAC, and OIDC.
- [Security and identity](./security) - the broader security model.
- [Service mesh](./service-mesh) - delegating mTLS to a mesh
  sidecar.
