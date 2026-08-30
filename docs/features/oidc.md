# OpenID Connect: discovery, introspection, revocation, token exchange, auth-code+PKCE (DW-034)

> Implements issue DW-034 (M2, `edition/oss`, effort L) over the
> authentication foundation shipped by DW-019 (#124). Sources:
> `crates/dwara-core/src/security/oidc.rs` (the OIDC client, discovery
> cache, introspection cache, connector, PKCE helpers), the
> `CompositeAuthenticator` integration in
> `crates/dwara-core/src/security/authn.rs` (`authenticate_oidc`, the
> Bearer dispatch chain), the dataplane cache wiring in
> `crates/dwara-core/src/dataplane/proxy.rs`
> (`oidc_introspection_cache`), validation in `snapshot/mod.rs`
> (`validate_oidc_providers`), config types in `config/mod.rs`
> (`OidcProvider`), and validation bounds in `config/limits.rs`. Tests:
> `crates/dwara-core/tests/oidc.rs` (end to end: active token allowed,
> inactive token 401, introspection caching, fail-closed on IdP error,
> fail-open when configured, fail-closed when IdP unreachable, token
> exchange, revocation invalidates cache, auth-code+PKCE flow,
> pass-through with no provider, explicit consumer binding). Operator
> docs: [docs-site OIDC guide](../../docs-site/guide/oidc.md).

DW-019 (#124) gave the gateway local JWT verification via JWKS: a
presented `Authorization: Bearer` token is verified against the
configured JWT providers' JWKS, and the claims map to a consumer. This
works for JWT access tokens from issuers whose JWKS the gateway can
fetch. It does not work for:

- **Opaque access tokens** — tokens that are not JWTs and cannot be
  verified locally. The gateway must ask the IdP whether the token is
  active.
- **Immediate revocation** — a JWT is valid until its `exp` claim. If
  the IdP revokes a token before its expiry, the gateway will keep
  accepting it until the JWT expires. Token introspection (RFC 7662)
  asks the IdP on every request (with caching), so revocation is
  noticed within the cache TTL.

DW-034 adds OIDC token introspection as the **second Bearer family** in
the `CompositeAuthenticator`'s dispatch chain. A Bearer token that did
not verify against any JWT provider (or when no JWT provider is
configured) is introspected against each configured OIDC provider in
order. The first `active: true` result resolves an `Identity`.

## The flow

```
Authorization: Bearer <token>
        |
        v
  JWT verification (DW-019)
        |
   Ok(Some(id)) ----> done (identity resolved)
   Ok(None)    ----> no JWT provider configured, fall through
   Err(Invalid) ---> token is not a valid JWT, try OIDC
   Err(Unavailable) -> 503 (JWT provider down)
        |
        v
  OIDC introspection (DW-034)
        |
   Ok(Some(id)) ----> done (identity resolved)
   Ok(None)    ----> no OIDC provider configured, pass-through
   Err(Invalid) ---> 401 (fail-closed or active:false)
        |
        v
  mTLS client cert (DW-019) / HMAC (DW-036) / anonymous
```

## Discovery

The provider's discovery document is fetched from
`{issuer}/.well-known/openid-configuration` (OIDC Discovery 1.0) and
cached for one hour on the `OidcClient`. The document supplies the
introspection, revocation, authorization, and token endpoints.
Config-level overrides (`introspection_endpoint`,
`revocation_endpoint`) take precedence over the discovered values.

The discovery document's `issuer` field is checked against the
configured `issuer` for defense against token confusion (OIDC Discovery
1.0 section 3). A mismatch is a hard error — the provider is disabled.

Concurrent discovery fetches coalesce into one GET (a
`tokio::sync::Mutex` discovery lock, the JWKS refresh-lock precedent).

## Introspection and caching

Introspection (RFC 7662) POSTs the token to the IdP's introspection
endpoint with HTTP Basic auth (`client_id:client_secret`). The
response's `active` field determines whether the token is valid.

The introspection cache (`OidcIntrospectionCache`) lives on the
dataplane (carried across generation swaps, the `jwks_caches` /
`oauth2_token_cache` precedent). Entries are keyed by
`{provider_name}:{sha256_hex(token)}` and expire after
`introspection_cache_ttl_s`. Only `active: true` results are cached;
`active: false` is re-checked on every request so a revoked token is
noticed promptly.

The token is hashed in the cache key so the plaintext never lives in
the cache (the selector-redaction precedent — a debug print of the
cache must not leak tokens).

## Fail-open vs fail-closed

When the IdP is unreachable (network error, non-2xx, malformed
response), the `fail_open` config controls the posture:

- **Fail-closed (default, `fail_open: false`):** 401. The gateway
  refuses to authenticate a token it cannot introspect. Every IdP
  failure shape (network, non-2xx, malformed, inactive) maps to 401 —
  the operator chose to reject, so a down IdP does not surface as
  500.
- **Fail-open (`fail_open: true`):** anonymous (pass-through). The
  gateway treats the failure as if no identity was resolved. On an
  `auth_required: true` route, this still 401s (no identity); on an
  optional-auth route, the request proceeds without an identity.

An `active: false` result is always 401 regardless of `fail_open` (the
token was explicitly rejected, not a gateway-side failure).

## Authorization-code + PKCE

The gateway can act as an OIDC relying party for browser-based login.
The `OidcClient` exposes:

- `authorization_url(redirect_uri, state, code_challenge)` — builds the
  authorization request URL with `response_type=code`,
  `code_challenge_method=S256`, and the PKCE challenge.
- `exchange_code(code, redirect_uri, code_verifier)` — exchanges the
  authorization code for a `TokenSet` (access, refresh, ID token).

PKCE helpers:

- `pkce_code_verifier(seed: &[u8; 32])` — generates a 43-character
  verifier from a 32-byte random seed (base64url-encoded).
- `pkce_code_challenge(verifier)` — derives the S256 challenge
  (`base64url(sha256(verifier))`).

The caller provides the random seed (the gateway does not pull in a
crypto RNG crate; tests pass a fixed seed for determinism, production
callers use the OS RNG).

## Token exchange (RFC 8693)

`exchange_token(subject_token, audience)` exchanges a subject token
(the client's Bearer token) for an actor token for an upstream
audience, using the `urn:ietf:params:oauth:grant-type:token-exchange`
grant type. This extends the OAuth2 client-credentials proxying pattern
(DW-035) to delegation scenarios.

## Token revocation (RFC 7009)

`revoke(token, cache)` POSTs to the IdP's revocation endpoint and
invalidates the introspection cache entry for that token. Revocation is
an admin/CLI operation, not on the hot request path.

## HTTP

All IdP HTTP calls use the `OidcConnector` (plain-or-TLS, the
`JwksConnector`/`OAuth2Connector` pattern), reusing the workspace
rustls stack with no new HTTP dependencies. A `trusted_ca_file`
replaces the webpki public roots for an IdP behind a private CA (the
same trust model as `JwtProvider::trusted_ca_file`).

## Error posture

The error envelope never leaks the IdP's response body or headers. An
introspection failure is logged via the `OidcError`'s `Display` text
(with the provider name and a `code = "oidc_introspection_failed"` tag)
and surfaced to the client as 401 (fail-closed) or pass-through
(fail-open).

## Config validation

`validate_oidc_providers` in `snapshot/mod.rs` checks:

- Provider names are unique.
- `issuer` is an absolute `http(s)://` URL.
- `introspection_cache_ttl_s` is in `1..=3600`.
- `consumer` (when set) references a known consumer.
- `trusted_ca_file` (when set) is a readable PEM bundle and only
  applies to an `https://` issuer.
- `introspection_endpoint` and `revocation_endpoint` overrides (when
  present) are absolute `http(s)://` URLs.
