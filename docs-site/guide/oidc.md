# OpenID Connect

[OpenID Connect](https://en.wikipedia.org/wiki/OpenID) (OIDC — an identity layer on top of OAuth2) support lets the gateway validate [Bearer](https://www.rfc-editor.org/rfc/rfc6750) tokens
by **token introspection** ([RFC 7662](https://www.rfc-editor.org/rfc/rfc7662) (asking the IdP (Identity Provider) whether a token is valid, rather than checking it locally)) rather than local JWT signature
verification. This is the right choice when your identity provider
issues **opaque** tokens (tokens that are meaningless to the gateway without introspection — not self-describing JWTs), or when you want the IdP to
be the single source of truth for token validity (revocation is
immediate, no key-rotation lag).

The gateway also acts as an OIDC **relying party** ([the app that relies on the IdP for login](https://en.wikipedia.org/wiki/Relying_party)) for the
**authorization-code** ([the OAuth2 flow where a browser is redirected to log in](https://www.rfc-editor.org/rfc/rfc6749#section-4.1)) + [PKCE](https://www.rfc-editor.org/rfc/rfc7636) (Proof Key for Code Exchange — protects the authorization-code flow from interception) flow (the browser login redirect), and
supports **token exchange** ([RFC 8693](https://www.rfc-editor.org/rfc/rfc8693)) for delegation and
**token revocation** ([RFC 7009](https://www.rfc-editor.org/rfc/rfc7009)) for session logout.

## When to use this

OIDC introspection is the right choice when the IdP issues opaque
(non-JWT) tokens or you want revocation to be immediate (the IdP is
the single source of truth). The relying-party flow is for browser
login redirects; token exchange is for delegation (exchanging a
client token for an actor token scoped to an upstream audience).

## How it fits

A presented `Authorization: Bearer <token>` header is processed in
this order:

1. **JWT verification** — if JWT providers are configured, the
   token is verified locally against the [JWKS](https://www.rfc-editor.org/rfc/rfc7517) (a JSON document of signing keys).
2. **OIDC introspection** — if the token did not verify as a
   JWT (or no JWT provider is configured), and OIDC providers are
   configured, the token is introspected against each OIDC provider in
   order. The first `active: true` result resolves an identity.
3. **Pass-through** — if neither JWT nor OIDC is configured, the Bearer
   header is forwarded upstream uninterpreted (the gateway does not
   own that credential).

## Configuring an OIDC provider

Declare one or more `oidc_providers` at the gateway level:

```yaml
oidc_providers:
  - name: keycloak
    issuer: https://idp.example.com
    client_id: dwara-gateway
    client_secret: ${env:OIDC_CLIENT_SECRET}
    introspection_cache_ttl_s: 60
    fail_open: false
```

| Field | Required | Default | Description |
|---|---|---|---|
| `name` | yes | — | A stable identifier (used in logs and cache keys). |
| `issuer` | yes | — | The OIDC issuer URL. The [discovery document](https://openid.net/specs/openid-connect-discovery-1_0.html) (a standard JSON document at .well-known/openid-configuration listing an IdP's endpoints) is fetched from `{issuer}/.well-known/openid-configuration`. Must be an absolute `http(s)://` URL. |
| `client_id` | yes | — | The gateway's client identifier at the IdP. |
| `client_secret` | yes | — | The gateway's client secret. Inline (redacted in config echo) or a `${...}` secret reference (recommended, see [Secrets](./secrets)). |
| `scopes` | no | `[]` | Scopes to request in the authorization-code and token-exchange flows. |
| `introspection_cache_ttl_s` | no | `60` | Cache TTL for `active: true` introspection results. Range: 1..=3600. `active: false` results are never cached (re-checked on every request so revocation is noticed promptly). |
| `introspection_endpoint` | no | from discovery | Override the discovery-discovered introspection endpoint URL. |
| `revocation_endpoint` | no | from discovery | Override the discovery-discovered revocation endpoint URL. |
| `consumer` | no | `sub` claim | Consumer this provider's tokens authenticate. When set, every successfully introspected token resolves to this consumer regardless of the `sub` claim. |
| `trusted_ca_file` | no | webpki roots | Path to a PEM CA bundle for an IdP behind a private CA (https only). |
| `fail_open` | no | `false` | Fail-open posture when the IdP is unreachable. See below. |

## Consumer binding

By default, an introspected token's `sub` claim becomes the consumer
name. For a fixed mapping (all tokens from this IdP belong to one
consumer), set `consumer`:

```yaml
consumers:
  - name: acme
oidc_providers:
  - name: keycloak
    issuer: https://idp.example.com
    client_id: dwara-gateway
    client_secret: ${env:OIDC_CLIENT_SECRET}
    consumer: acme
```

Every successfully introspected token from `keycloak` resolves to the
`acme` consumer, and the consumer's groups and policies apply.

## Caching

Introspection results are cached per-provider, keyed by the [SHA-256](https://en.wikipedia.org/wiki/SHA-2)
hash of the token. A cached `active: true` result short-circuits the
IdP call for `introspection_cache_ttl_s` seconds. The cache lives on
the dataplane and survives config reloads (a reload never discards a
cached result).

`active: false` results are **never** cached — the token is
re-introspected on every request so a revoked token is noticed
promptly.

## Fail-open vs fail-closed

When the IdP is unreachable (network error, non-2xx response, malformed
body), the `fail_open` flag controls the gateway's posture:

- **`false` (default, fail-closed):** the request is rejected with 401.
  The gateway refuses to authenticate a token it cannot introspect.
  This is the secure default.
- **`true` (fail-open):** the gateway treats the failure as anonymous
  (pass-through). The request proceeds without an identity. Use this
  only when availability is more important than authentication, and
  the route's `auth_required` is `false` (a fail-open token on an
  `auth_required: true` route still 401s — no identity was resolved).

An `active: false` result is **always** 401 regardless of `fail_open`
(the token was explicitly rejected, not a gateway-side failure).

## Authorization-code + PKCE flow

The gateway can act as an OIDC [relying party](https://en.wikipedia.org/wiki/Relying_party) (the app that relies on the IdP for login) for browser-based login.
The flow uses [PKCE](https://www.rfc-editor.org/rfc/rfc7636) (RFC 7636) with the S256 method:

1. The gateway generates a PKCE code verifier and challenge.
2. The gateway redirects the user agent to the IdP's authorization
   endpoint with `code_challenge` and `state`.
3. The IdP authenticates the user and redirects back to the gateway's
   callback URL with an authorization code.
4. The gateway exchanges the code (plus the PKCE verifier) for access,
   refresh, and ID tokens at the token endpoint.

The authorization URL is built from the discovery document's
`authorization_endpoint`; the code exchange uses the `token_endpoint`.

## Token exchange (RFC 8693)

The gateway can exchange a subject token (the client's [Bearer](https://www.rfc-editor.org/rfc/rfc6750) token)
for an actor token for an upstream audience, using the
`urn:ietf:params:oauth:grant-type:token-exchange` grant type. This
extends the OAuth2 client-credentials proxying pattern to
delegation scenarios.

## Token revocation (RFC 7009)

The gateway can revoke a token by POSTing to the IdP's revocation
endpoint. After a successful revocation, the introspection cache entry
for that token is invalidated so the next request re-introspects (or
fails 401). Revocation is an admin/CLI operation, not on the hot
request path.

## Discovery

The gateway fetches the OIDC [discovery document](https://openid.net/specs/openid-connect-discovery-1_0.html) (a standard JSON document at .well-known/openid-configuration listing an IdP's endpoints) from
`{issuer}/.well-known/openid-configuration` (OIDC Discovery 1.0) and
caches it for one hour. The document supplies the introspection,
revocation, authorization, and token endpoints. Config-level overrides
(`introspection_endpoint`, `revocation_endpoint`) take precedence over
the discovered values.

The discovery document's `issuer` field is checked against the
configured `issuer` for defense against token confusion (an attack where a token for one issuer is accepted for another) (OIDC Discovery
1.0 section 3). A mismatch is a hard error.

## Private-CA IdPs

For an IdP behind a private CA, set `trusted_ca_file` to a PEM bundle
of the CA certificates. This replaces the webpki public roots for this
provider only (the same trust model as `jwt_providers[].trusted_ca_file`).
The field is only meaningful for an `https://` issuer.
