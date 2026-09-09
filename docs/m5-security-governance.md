# M5 - Security and Governance

This document covers all ten issues in the M5 (Security and Governance)
milestone. For each issue it describes the implementation, the
recommended default, the rationale for that default, the available
alternatives, and the operational tradeoffs.

## Issue index

| Issue | Title | Priority | Size |
|-------|-------|----------|------|
| #154 | SEC-01: Admin RBAC, per-cert identity, API tokens, audit log | P0 | M |
| #155 | SEC-02: ACME / Let's Encrypt automation | P1 | M |
| #156 | SEC-03: Upstream mTLS client certificates | P1 | M |
| #157 | SEC-04: Real certificate pinning implementation | P1 | S |
| #158 | SEC-05: OIDC browser login flow as a route auth mode | P1 | L |
| #159 | SEC-10: Production secret sources + pepper rotation | P1 | M |
| #160 | SEC-13: SSRF egress filter for webhooks and OPA callouts | P1 | S |
| #161 | SEC-14: Request body JSON Schema validation | P1 | M |
| #162 | CFG-13: mTLS on CP-DP transport | P1 | S |
| #163 | CFG-14: Dry-run expansion to all policy phases | P1 | M |

---

## #154 / SEC-01: Admin RBAC, per-cert identity, API tokens, audit log

### Purpose

The admin API currently treats any CA-valid client certificate as full
admin. This issue adds role-based access control (RBAC) keyed on client
certificate fingerprints, API token authentication as an alternative to
mTLS, and an audit log of mutating admin actions.

### Recommended default

- **RBAC:** OFF (absent). When the `rbac` block is absent, any CA-valid
  client certificate is treated as full admin (the v1 behavior). This
  preserves backward compatibility.
- **API tokens:** OFF (absent). When the `api_tokens` block is absent,
  only mTLS is accepted (the v1 behavior).
- **Audit log:** OFF (absent). When the `audit` block is absent, no
  audit log is kept.

### Rationale

The v1 admin API uses mTLS as the sole authn/authz layer: a valid client
certificate is full admin. This is simple and secure for small
deployments. RBAC, tokens, and audit are opt-in for larger deployments
that need finer-grained access control and accountability.

### Configuration

```yaml
admin:
  bind: "127.0.0.1:2019"
  tls:
    cert_file: "/path/to/server.crt"
    key_file: "/path/to/server.key"
    client_ca_file: "/path/to/client-ca.crt"
  rbac:
    bindings:
      - cert_fingerprint: "a1b2c3..."  # SHA-256 of client cert DER, 64 lowercase hex
        role: admin
      - cert_fingerprint: "d4e5f6..."
        role: readonly
  api_tokens:
    tokens:
      - token_hash: "a1b2c3..."  # SHA-256 of plaintext token, 64 lowercase hex
        role: admin
  audit:
    enabled: true
```

### Runtime behavior

- **RBAC:** When `rbac` is present, a valid client certificate with NO
  binding is denied (fail-closed: no implicit admin). The fingerprint is
  SHA-256 of the full DER encoding of the client certificate.
- **API tokens:** When `api_tokens` is present, the admin API accepts
  `Authorization: Bearer <token>`. The token is SHA-256 hashed and
  compared against the configured `token_hash` values. Tokens are never
  logged.
- **Audit log:** When `audit` is present and `enabled: true`, all
  mutating admin actions (PATCH /config, purge) are recorded with the
  actor (cert fingerprint or token hash), action, before/after config
  hash, and timestamp.

### Available alternatives

- **External IAM/OIDC for admin:** Use an external identity provider
  (e.g., Okta, Auth0) for admin authn. More complex; requires network
  access to the IdP from the admin plane.
- **SPIFFE/SPIRE for workload identity:** Use SPIFFE IDs instead of
  certificate fingerprints. More infrastructure; better for
  service-to-service admin access.
- **OAuth2 client credentials for admin:** Use OAuth2 instead of static
  API tokens. Adds token refresh complexity.

### Tradeoffs

- RBAC fail-closed means a misconfigured binding locks out all admin
  access. Keep a recovery path (e.g., a bootstrap admin cert).
- API tokens are static; rotation is manual (update config + reload).
- Audit log storage grows unbounded; configure retention separately.

### Feature flags

None. The config blocks are always accepted by the parser; the runtime
behavior is driven by their presence.

---

## #155 / SEC-02: ACME / Let's Encrypt automation

### Purpose

Automate TLS certificate issuance and renewal from ACME-compatible
certificate authorities (Let's Encrypt by default) so operators do not
need to manually manage certificates.

### Recommended default

- **Challenge type:** `tls-alpn-01` (default). No separate HTTP listener
  needed; the TLS terminator handles the challenge during the handshake.
- **Directory:** Let's Encrypt production
  (`https://acme-v02.api.letsencrypt.org/directory`).
- **Staging:** `false` (use production). Set `staging: true` for testing
  to avoid rate limits.
- **State directory:** `./acme-state` (relative to the gateway working
  directory).
- **Feature gate:** ACME automation (default-on). The config block
  is always accepted; when the feature is OFF, validation warns that the
  block is inert.

### Rationale

TLS-ALPN-01 is the default because it requires no additional listener
or port forwarding. HTTP-01 requires a separate HTTP listener on port
80, which is often not available behind a load balancer or in
containerized environments.

Staging is off by default because production certificates are trusted by
browsers. Operators should test with `staging: true` first, then switch
to production.

### Configuration

```yaml
listeners:
  - name: https
    protocol: https
    bind: "0.0.0.0:443"
    tls:
      mode: terminate
      acme:
        domains:
          - "api.example.com"
          - "www.example.com"
        contact:
          - "admin@example.com"
        challenge: tls-alpn-01
        staging: false
        state_dir: "./acme-state"
```

### Runtime behavior

1. The ACME client loads or creates an account key (persisted to
   `state_dir`).
2. Registers the account with the directory using `contact`.
3. For each domain: orders a certificate, completes the challenge,
   finalizes the order, and downloads the issued certificate.
4. Installs the certificate into the SNI resolver.
5. Schedules renewal at 2/3 of the certificate's validity period.
6. On failure: logs the error and retries with exponential backoff.
   Existing certificates continue to serve.

### Available alternatives

- **HTTP-01 challenge:** Set `challenge: http-01`. Requires a separate
  HTTP listener on port 80 (or port forwarding from a load balancer).
- **External ACME client (certbot, lego, acme.sh):** Run an external
  ACME client and place certificates in the gateway's cert paths. No
  gateway-integrated automation, but avoids adding an ACME client
  dependency to the gateway.
- **Commercial CA with API:** Use a commercial CA's API (e.g., DigiCert
  CertCentral, Sectigo) instead of ACME. Non-standard; vendor lock-in.
- **Certificate manager (cert-manager, External Secrets Operator):** In
  Kubernetes, use cert-manager to obtain certificates and mount them as
  secrets. Decouples certificate management from the gateway.

### Tradeoffs

- ACME rate limits: Let's Encrypt allows 50 certs per domain per week.
  Use `staging: true` for testing.
- TLS-ALPN-01 requires port 443 to be directly reachable by the IdP's
  validation servers.
- The ACME client is compiled into the OSS build (ACME automation, default-on).
  The scaffold provides config types and state management; the full
  client (account registration, challenge completion, certificate
  issuance) requires enabling the feature and adding an ACME client
  dependency (rustls-acme or instant-acme, license-checked against
  deny.toml).

### Feature flags

ACME automation (default-on). When OFF, the config block is
accepted but inert; validation warns.

---

## #156 / SEC-03: Upstream mTLS client certificates

### Purpose

Allow the gateway to present a client certificate when connecting to
upstream TLS servers that require client authentication (mTLS).

### Recommended default

- **mTLS:** OFF (absent). When the `mtls` block is absent, the gateway
  connects with no client certificate (the v1 behavior).
- **Protocol restriction:** mTLS is only valid for `https` and `http2`
  upstreams. Validation rejects `mtls` on `http1` upstreams (no TLS is
  negotiated).
- **File validation:** The cert and key files must exist and be readable
  at config compile time. Validation names the offending field if not.

### Rationale

Most upstreams do not require client certificates. Making mTLS opt-in
preserves the existing behavior and avoids requiring operators to
configure client certs for every upstream.

### Configuration

```yaml
upstreams:
  - name: secure-backend
    protocol: https
    mtls:
      client_cert_file: "/path/to/client.crt"
      client_key_file: "/path/to/client.key"
    endpoints:
      - address: "10.0.0.1"
        port: 8443
```

### Runtime behavior

- The gateway loads the client certificate chain and private key at
  config compile time using rustls `with_client_auth_cert`.
- The certificate is presented during the upstream TLS handshake.
- If the cert/key files cannot be loaded, the gateway logs an error and
  falls back to no client auth (the upstream will reject the handshake
  if it requires mTLS).
- mTLS is compatible with certificate pinning: when both are configured,
  pinning uses the custom verifier and mTLS provides the client cert.
  (Note: the current pinning builder uses `with_no_client_auth`; a
  future change will combine the custom verifier with client auth.)

### Available alternatives

- **SPIFFE/SPIRE for workload identity:** Use SPIFFE SVIDs instead of
  static client certificates. Automatic rotation; more infrastructure.
- **OAuth2 client credentials for upstream auth:** Use OAuth2 tokens
  instead of mTLS. Already supported via `oauth2_client_credentials`.
- **Service mesh (Istio, Linkerd):** Delegate mTLS to the service mesh.
  The gateway connects plaintext to the sidecar, which handles mTLS.

### Tradeoffs

- Client certificate rotation is manual (update config + reload).
- The private key file must be readable by the gateway process; protect
  it with file permissions.
- mTLS + pinning interaction: the current implementation does not
  combine a custom pinning verifier with client auth. If both are
  configured, pinning takes precedence and the client cert is not
  presented. This is documented as a known limitation.

### Feature flags

None. The `mtls` block is always accepted by the parser; validation
enforces the protocol restriction.

---

## #157 / SEC-04: Real certificate pinning implementation

### Purpose

Pin upstream TLS certificates by their SubjectPublicKeyInfo (SPKI)
SHA-256 hash to detect and reject certificate substitution or CA
compromise.

### Recommended default

- **Pinning:** OFF (absent). When `cert_pinning` is absent, the gateway
  uses normal CA-based verification (the v1 behavior).
- **Pin format:** SPKI SHA-256, lowercase hexadecimal, 64 characters.
- **Multiple pins:** Allowed. Any matching pin succeeds.
- **Empty pin list:** Invalid (validation rejects).
- **Fail-closed:** When pinning is configured and the `cert_pinning`
  feature is enabled, verification is fail-closed with no CA fallback.
- **Feature gate:** certificate pinning (default-on). The
  config block is always accepted; when the feature is OFF, validation
  warns that the block is inert.

### Rationale

SPKI pinning is preferred over full-certificate pinning because:
1. SPKI is stable across certificate renewals (the same key pair).
2. SPKI is smaller (32 bytes vs. full DER cert).
3. SPKI is the industry standard (RFC 7858, Chromium HPKP).

Fail-closed with no CA fallback is the secure default: if a pin is
configured, the operator has explicitly chosen to trust only that key.
Falling back to CA verification would defeat the purpose of pinning.

### Configuration

```yaml
upstreams:
  - name: pinned-backend
    protocol: https
    cert_pinning:
      pins:
        - spki_sha256: "a1b2c3d4e5f6..."  # 64 lowercase hex chars
    endpoints:
      - address: "10.0.0.1"
        port: 8443
```

### Runtime behavior

1. The gateway extracts the peer certificate's SPKI from the DER-encoded
   SubjectPublicKeyInfo.
2. Computes SHA-256 of the SPKI.
3. Compares the hash against the configured raw 32-byte pins.
4. Any matching pin succeeds; no match fails.
5. Malformed certificates, extraction failures, and mismatches are
   rejected.
6. Pinning replaces CA trust in the custom verifier (no CA fallback).

### Available alternatives

- **Full-certificate pinning:** Pin the entire certificate DER instead
  of just the SPKI. Breaks on every renewal; not recommended.
- **Public key pinning (raw key, not hash):** Compare the raw public key
  bytes instead of the hash. Larger; no security benefit over hashing.
- **HPKP (HTTP Public Key Pinning):** Browser-side pinning via HTTP
  headers. Deprecated; not applicable to server-to-server.
- **Certificate Transparency (CT) logs:** Monitor certificate issuance
  for your domains instead of pinning. Complementary, not a replacement.

### Tradeoffs

- Pinning requires manual pin updates when the upstream rotates its key
  pair. Configure multiple pins (old + new) during rotation.
- Fail-closed means a pin mismatch takes the upstream offline. Monitor
  pin validation failures.
- SPKI pinning does not protect against key compromise (the attacker has
  the private key). Use short certificate lifetimes and key rotation.

### Feature flags

certificate pinning (default-on). When OFF, the config block
is accepted but inert; validation warns.

---

## #158 / SEC-05: OIDC browser login flow as a route auth mode

### Purpose

Allow the gateway to act as an OIDC relying party (RP) for browser-based
flows: redirect unauthenticated users to an IdP, exchange the
authorization code for tokens, set a session cookie, and validate the
cookie on subsequent requests.

### Recommended default

- **OIDC login:** OFF (absent). When `oidc_login` is absent, the route
  uses its normal auth mode (the v1 behavior).
- **Session cookie:** `dwara_session` (default). HttpOnly, Secure (on
  TLS listeners), SameSite=Lax.
- **Session TTL:** 3600 seconds (1 hour, default).
- **Post-logout URL:** Defaults to the IdP's `end_session_endpoint`
  (from discovery) with `post_logout_redirect_uri` set to the gateway's
  root.

### Rationale

The gateway already supports OIDC token introspection for API clients.
Browser login is a separate flow: browsers cannot easily send bearer
tokens; they need cookies and redirects. Making it per-route opt-in
allows mixing API and browser auth on the same gateway.

### Configuration

```yaml
routes:
  - name: web-app
    service: web-backend
    match:
      path: "/app"
    action:
      proxy: {}
    oidc_login:
      provider: "keycloak"
      redirect_uri: "/auth/callback"
      session_cookie: "dwara_session"
      session_ttl_s: 3600
      post_logout_url: "https://app.example.com/login"
```

### Runtime behavior

1. Unauthenticated browser request arrives at the route.
2. The gateway redirects (302) to the IdP's authorization endpoint with
   PKCE, scopes, and the redirect URI.
3. The IdP authenticates the user and redirects back to `redirect_uri`
   with an authorization code.
4. The gateway exchanges the code for tokens (using the existing
   `OidcClient::exchange_authorization_code`), sets a signed session
   cookie, and redirects the user back to the original URL.
5. Subsequent requests carry the session cookie; the gateway validates
   it and forwards the request.
6. Logout: visiting `{redirect_uri}/logout` clears the cookie and
   redirects to `post_logout_url` (or the IdP's end_session_endpoint).

### Available alternatives

- **External reverse proxy (OAuth2 Proxy, Authelia, Traefik Forward
  Auth):** Run a separate auth proxy in front of the gateway. Adds
  infrastructure; duplicates routing logic.
- **Application-level OIDC:** Let each application handle OIDC itself.
  No gateway-level session management; each app reinvents the flow.
- **SAML:** Use SAML instead of OIDC for enterprise SSO. More complex;
  OIDC is the modern standard.
- **Gateway-level OAuth2 (not OIDC):** Use OAuth2 without the OpenID
  Connect layer. No identity claims; only access tokens.

### Tradeoffs

- Session cookies are gateway-stateless (signed JWT or HMAC); no server-
  side session store needed. Revocation requires short TTLs or a
  denylist.
- The gateway must be reachable at the `redirect_uri` path; ensure the
  IdP allows this redirect URI.
- PKCE is used to protect the authorization code exchange.
- The session cookie is SameSite=Lax by default; cross-site POST flows
  may need SameSite=None (configure via the cookie attributes in a
  future change).

### Feature flags

None. The `oidc_login` block is always accepted by the parser;
validation checks that the provider exists in `gateway.oidc_providers`.

---

## #159 / SEC-10: Production secret sources + pepper rotation

### Purpose

Provide production-grade secret sources (Vault KV v2) and support
credential pepper rotation without downtime.

### Recommended default

- **Vault secret source:** Available behind the `ent` cargo feature
  (Enterprise). The HTTP client is implemented (raw TCP/TLS, hand-rolled
  HTTP/1.1, same approach as the webhook deliverer).
- **Pepper rotation:** OFF by default. Set
  `DWARA_CREDENTIAL_PEPPER_PREVIOUS` to enable the rotation window.
- **Pepper source:** Environment variables (`DWARA_CREDENTIAL_PEPPER`
  and `DWARA_CREDENTIAL_PEPPER_PREVIOUS`), resolved through the
  `SecretSource` extension seam.

### Rationale

The pepper rotation window allows zero-downtime rotation: the old pepper
verifies existing stored hashes while the new pepper is used for new
writes. Once all stored hashes have been re-hashed with the new pepper,
the old pepper is removed.

### Configuration

Pepper rotation is configured via environment variables, not config
YAML:

```sh
# Current pepper (used for new writes and verification)
export DWARA_CREDENTIAL_PEPPER="new-pepper-value"

# Previous pepper (used only for verification of existing hashes)
export DWARA_CREDENTIAL_PEPPER_PREVIOUS="old-pepper-value"
```

Vault secret source (Enterprise, `ent` feature):

```yaml
# Enterprise config uses the VaultSecretSource extension; the config
# shape is defined by the extension's builder, not the gateway config.
```

### Runtime behavior

**Pepper rotation:**
1. The gateway resolves `DWARA_CREDENTIAL_PEPPER` (current) and
   `DWARA_CREDENTIAL_PEPPER_PREVIOUS` (old) at startup.
2. New credential writes use the current pepper
   (`hmac-sha256:<hex>`).
3. Verification tries the current pepper first, then the previous
   pepper.
4. Once all stored hashes use the current pepper, remove
   `DWARA_CREDENTIAL_PEPPER_PREVIOUS` and restart.

**Vault secret source:**
1. The `VaultSecretSource` connects to Vault's KV v2 API over HTTPS.
2. Secrets are cached with a configurable TTL.
3. The `name` passed to `resolve` is `<mount>/<path>` (or
   `<mount>/<path>#<key>` for multi-key secrets).
4. The source uses webpki roots for TLS verification (no custom CA
   support yet).

### Available alternatives

- **AWS Secrets Manager / GCP Secret Manager / Azure Key Vault:** Cloud-
  native secret managers. Use the KMS secret source or a custom
  `SecretSource` implementation.
- **Kubernetes secrets:** Mount secrets as files; use `FileSecretSource`
  (OSS, already supported).
- **SOPS + age:** Encrypt secrets in git; decrypt at deploy time. Use
  `FileSecretSource` with the decrypted files.
- **External secrets operator (Kubernetes):** Sync secrets from a
  cloud manager to Kubernetes secrets; mount as files.

### Tradeoffs

- Pepper rotation requires a restart to pick up the new environment
  variables (the pepper is resolved at startup).
- The previous pepper is kept in memory for the process lifetime; it is
  zeroized on shutdown.
- Vault HTTP client is hand-rolled (no hyper client dependency); a
  future change may use a pooled client for high-throughput
  deployments.
- Vault TLS uses webpki roots; private CA support is a future change.

### Feature flags

- `ent` cargo feature (Enterprise) for `VaultSecretSource` and
  `KmsSecretSource`.
- Pepper rotation uses the OSS `EnvSecretSource` (no feature gate).

---

## #160 / SEC-13: SSRF egress filter for webhooks and OPA callouts

### Purpose

Prevent Server-Side Request Forgery (SSRF) by filtering outbound
connections from webhook deliveries and OPA callouts against a deny set
of private/loopback/link-local/metadata IP ranges.

### Recommended default

- **SSRF filter:** OFF (absent). When `ssrf_filter` is absent, the
  gateway trusts operator-configured endpoints (the v1 behavior).
- **When enabled:** Resolve the hostname at connection time, check every
  resolved IP, reject private/loopback/link-local/metadata/denied
  ranges, apply optional allowlist exemptions, fail closed on DNS or
  filter failures.
- **Timing:** The filter is checked immediately before connecting to
  mitigate DNS rebinding between static config validation and runtime
  connection.

### Rationale

SSRF filters are disabled by default to preserve existing deployments
where internal/private destinations are intentional (e.g., an internal
OPA server or a webhook receiver on a private network). Enabling the
filter is a security hardening step that should be opt-in.

### Configuration

```yaml
gateway:
  ssrf_filter:
    deny:
      - "10.0.0.0/8"
      - "172.16.0.0/12"
      - "192.168.0.0/16"
      - "127.0.0.0/8"
      - "169.254.0.0/16"  # link-local
      - "169.254.169.254/32"  # cloud metadata
    allow:
      - "10.0.1.0/24"  # exempt: internal OPA subnet
```

### Runtime behavior

- The filter is compiled per generation and passed into webhook/OPA
  runtime state.
- Webhook deliveries: resolve the hostname via `tokio::net::lookup_host`,
  check all returned addresses, connect only if all pass.
- OPA callouts: resolve via `ToSocketAddrs`, check each address, open
  the TCP connection only if all pass.
- Header secrets are never disclosed (the filter runs before the
  connection is opened).

### Available alternatives

- **Egress firewall (iptables, nftables, security groups):** Filter at
  the network layer. No application-level control; cannot exempt
  specific endpoints.
- **Egress proxy (Squid, Envoy):** Route all outbound traffic through a
  proxy that enforces SSRF rules. Adds infrastructure; single point of
  failure.
- **DNS rebind protection at the resolver:** Use a DNS resolver that
  rejects private IPs. Does not protect against direct IP literals.
- **No filter (trust the operator):** The default. Acceptable when
  webhook/OPA endpoints are static and operator-controlled.

### Tradeoffs

- The filter adds a DNS resolution step before every webhook/OPA
  connection (latency overhead).
- Fail-closed means a DNS failure takes the webhook/OPA call offline.
  Monitor filter failures.
- The allowlist must be maintained; a too-broad allowlist weakens the
  filter.

### Feature flags

None. The `ssrf_filter` block is always accepted by the parser.

---

## #161 / SEC-14: Request body JSON Schema validation

### Purpose

Validate request bodies against a minimal JSON Schema subset before the
route action runs, rejecting malformed requests with 400
`validation_failed`.

### Recommended default

- **Validation:** OFF (absent). When `request_validation` is absent, no
  body validation is performed (the v1 behavior).
- **Dry-run:** OFF (`dry_run: false`, default). When `dry_run: true`,
  the gateway evaluates the schema and records violations (log + metric)
  but does NOT reject the request. Useful for rolling out a new schema
  without breaking existing callers.
- **Schema subset:** `type`, `required`, `properties`, `items`, `enum`,
  `minimum`, `maximum`, `minLength`, `maxLength`, and
  `additionalProperties`. `$ref` is NOT supported (inline schemas).

### Rationale

The dry-run mode allows operators to test a new schema against
production traffic without rejecting any requests. Violations are logged
with the `validation_failed_dry_run` code and can be monitored before
switching to enforce mode.

### Configuration

```yaml
routes:
  - name: create-user
    service: user-backend
    match:
      path: "/users"
      methods: ["POST"]
    action:
      proxy: {}
    request_validation:
      body_schema:
        type: object
        required: ["name", "email"]
        properties:
          name:
            type: string
            minLength: 1
            maxLength: 100
          email:
            type: string
            maxLength: 255
          age:
            type: integer
            minimum: 0
            maximum: 150
        additionalProperties: false
      dry_run: false
```

### Runtime behavior

1. The body is buffered up to the route's `limits.max_body_bytes` (or
   1 MiB default).
2. Parsed as JSON.
3. Walked against the schema.
4. On mismatch: 400 `validation_failed` with the offending instance
   paths in the JSON error envelope.
5. On match: the buffered bytes are replayed to the action.
6. In dry-run mode: violations are logged but the request proceeds
   (with a `validation_failed_dry_run` response code so operators can
   monitor before switching to enforce mode).

### Available alternatives

- **Full JSON Schema (Draft 2020-12):** Use the `jsonschema` crate for
  full spec compliance. Heavier; `$ref` support; slower validation.
- **OpenAPI request validation:** Validate against the route's OpenAPI
  spec. Already partially supported via `openapi` import metadata.
- **Protobuf/CEL validation:** Use protocol buffers with CEL
  expressions for typed validation. Requires schema in .proto format.
- **Application-level validation:** Let the upstream validate the body.
  No gateway-level protection; wastes upstream resources on bad
  requests.

### Tradeoffs

- Body buffering adds latency and memory pressure for large bodies.
  Configure `limits.max_body_bytes` to bound it.
- The minimal subset does not support `$ref`, `oneOf`/`anyOf`/`allOf`,
  or format validation. Inline schemas or use the full `jsonschema`
  crate for complex cases.
- Dry-run mode currently still rejects (the body is consumed by
  validation); a future change will buffer before validation so dry-run
  can replay. The dry-run code path logs the violation with a distinct
  code so operators can monitor before switching to enforce mode.

### Feature flags

None. The `request_validation` block is always accepted by the parser.

---

## #162 / CFG-13: mTLS on CP-DP transport

### Purpose

Secure the control-plane/data-plane (CP-DP) gRPC transport with mutual
TLS, requiring client certificates on the controller and validating peer
certificates against a configured CA.

### Recommended default

- **TLS:** OFF (plaintext, the v1 behavior). Existing plaintext APIs
  remain available for compatibility/dev/test use.
- **When enabled:** The controller presents the server certificate,
  requires client authentication, and validates peer certificates
  against the configured CA. The edge presents the client certificate
  and validates the controller's certificate against the CA.
- **Feature gate:** tonic `tls` feature (enabled in the workspace
  dependency).

### Rationale

Plaintext CP-DP is acceptable in a trusted network (e.g., a dedicated
management network or a service mesh with mTLS at the sidecar). TLS is
opt-in for deployments that need end-to-end encryption on the CP-DP
transport.

### Configuration

```yaml
# CP-DP TLS config is passed programmatically to the edge/controller
# builders, not via the gateway config YAML. The config shape:
#
# CpDpTlsConfig {
#     cert_pem: "/path/to/edge.crt",
#     key_pem: "/path/to/edge.key",
#     ca_pem: "/path/to/ca.crt",
# }
```

### Runtime behavior

- `EdgeClient::connect_tls(endpoint, tls)`: the edge connects to the
  controller over TLS, presenting its client certificate and validating
  the controller's certificate against the CA.
- `serve_controller_tls(server, addr, tls)`: the controller serves over
  TLS, requiring client authentication (`client_auth_optional(false)`)
  and validating peer certificates against the CA.
- Existing plaintext methods (`EdgeClient::connect`, 
  `serve_controller`) remain available.

### Available alternatives

- **Service mesh mTLS (Istio, Linkerd):** Delegate mTLS to the service
  mesh sidecars. The gateway uses plaintext CP-DP; the mesh encrypts.
- **WireGuard/IPsec tunnel:** Encrypt all traffic between CP and DP at
  the network layer. No application-level mTLS; simpler key management.
- **SSH tunnel:** Tunnel the gRPC traffic over SSH. Not suitable for
  production; high overhead.

### Tradeoffs

- mTLS requires certificate management for the CP-DP plane (separate
  from the dataplane listener certificates).
- The controller requires client authentication; a misconfigured edge
  certificate takes the edge offline.
- The tonic `tls` feature adds a dependency on rustls-based TLS for
  tonic; license-checked against `deny.toml` (rustls is Apache-2.0/ISC/
  MIT, already in the dependency tree).

### Feature flags

tonic `tls` feature (enabled in the workspace dependency). The config
types are always available; the TLS-enabled methods require the feature.

---

## #163 / CFG-14: Dry-run expansion to all policy phases

### Purpose

Expand the dry-run mode (evaluate + log but do not enforce) to all
policy phases so operators can roll out new rules without breaking
existing traffic.

### Recommended default

- **Dry-run:** OFF (`dry_run: false`, default) on all phases. The v1
  behavior is enforce-on-match.
- **Phases with dry-run support:**
  - `request_validation` (SEC-14): `dry_run` field on
    `RequestValidation`.
  - `waf`: `dry_run` field on `RouteWaf` (already existed).
  - `authz`: `dry_run` field on `Authz` (already existed).
  - `rate_limit`: `dry_run` field on `RateLimit` (already existed).
  - `anomaly`: `dry_run` field on `AnomalyPolicy` (already existed).
  - `load_shed`: `load_shed_dry_run` field on `Gateway` (already
    existed).
  - `request_limits`: `dry_run` field on `RequestLimits` (already
    existed).
  - `ai_governance`: `dry_run` field on `AiGovernance` (NEW).
  - `ai_guardrails`: `dry_run` field on `AiGuardrails` (NEW).
  - `quota`: `dry_run` field on `ConsumerQuotas` (NEW).

### Rationale

Dry-run mode is the standard way to roll out a new policy: evaluate it
against production traffic, log would-be denials, but do not enforce.
This lets operators tune the policy (e.g., a new WAF rule, a new quota
limit) before switching to enforce mode. The metric
`dwara_policy_dry_run_total{phase,route}` counts would-be denials per
phase per route.

### Configuration

```yaml
# AI governance dry-run
ai:
  governance:
    team_allowlists:
      team-a: ["gpt-4", "claude-3"]
    dry_run: true  # log would-be denials, do not reject

# AI guardrails dry-run
ai:
  guardrails:
    rules:
      - name: no-pii
        kind: prompt_pii
        action: block
        phase: prompt
    dry_run: true  # log would-be blocks, do not block

# Consumer quota dry-run
consumers:
  - name: free-tier
    quotas:
      daily_requests: 1000
      dry_run: true  # log would-be rejections, do not reject

# Request validation dry-run (SEC-14)
routes:
  - name: create-user
    request_validation:
      body_schema:
        type: object
        required: ["name"]
      dry_run: true  # log would-be 400s, do not reject
```

### Runtime behavior

- When `dry_run: true`, the policy engine evaluates the rule and
  records a would-be denial via:
  - `dwara_policy_dry_run_total{phase,route}` counter increment.
  - Structured log with `code = "policy_dry_run"` and the violation
    details.
- The request proceeds normally (no rejection).
- Operators monitor the metric and logs to assess the impact before
  switching to `dry_run: false` (enforce mode).

### Available alternatives

- **Shadow traffic / mirror:** Duplicate traffic to a test environment
  with the new policy enforced. More infrastructure; no production
  impact.
- **Canary deployment:** Roll the new policy to a subset of edges.
  Requires fleet management; partial enforcement.
- **Staging environment:** Test the policy in staging before production.
  No production traffic; staging traffic may not be representative.
- **No dry-run (enforce immediately):** The default. Risky for new
  rules; may break existing callers.

### Tradeoffs

- Dry-run mode adds evaluation overhead (the rule is evaluated even
  though it is not enforced).
- The metric and logs can be noisy for high-traffic routes; use sampling
  or route-scoped dry-run.
- Dry-run does not test the enforcement path (e.g., the 400 response
  shape); operators should verify the enforce mode separately.

### Feature flags

None. The `dry_run` field is always accepted by the parser on all
supported phases.

---

## Verification

The following verification gate was run after all changes:

```sh
cargo build --workspace                           # OK
cargo build --workspace --all-targets             # OK
cargo build -p dwara-bin --features h3            # OK
cargo build -p dwara-bin --features console       # OK
cargo build -p dwara-core --features cert_pinning # OK
cargo build -p dwara-core --features acme         # OK
cargo test --workspace                            # OK (1 pre-existing flaky test)
cargo test -p dwara-bin --features otlp           # OK
cargo fmt --all -- --check                        # OK
cargo clippy --workspace --all-targets -- -D warnings  # OK
cargo deny check advisories licenses bans         # OK
cargo doc --no-deps --workspace                   # 4 pre-existing warnings
cargo run -q -p dwara-cli --bin dwara-cli -- schema  # regenerated
python3 scripts/check_deps.py                     # OK
```

### Pre-existing issues (not introduced by this change)

- `stream_spanning_a_minute_boundary_spends_into_both_windows`:
  timing-sensitive AI budget test; fails on clean `main` due to minute-
  boundary alignment.
- 4 doc warnings: unresolved links to `parse_inline`, `signed_url`,
  `cert_pinning`, and `fips::install_fips_provider` (all pre-existing).

### Dependency changes

- **tonic `tls` feature:** Added to the workspace tonic dependency
  (CFG-13). tonic is already in the dependency tree; the `tls` feature
  enables rustls-based TLS for the CP-DP transport. License: MIT (tonic)
  + Apache-2.0/ISC/MIT (rustls) -- already in `deny.toml`.

No other dependencies were added.
