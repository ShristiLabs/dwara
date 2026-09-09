# Authentication methods

How a consumer proves identity to Dwara. Each method is a credential
family: a consumer holds one or more, and the gateway verifies the
presented credential against the configured material. This page is the
quick-reference for choosing a method; each method's detail lives on
its own page.

For the broader security model -- secrets, authorization, upstream
authn -- see [Security and identity](./security).

## Method reference

| Method | What it checks | Best for | Guide |
|---|---|---|---|
| API key | a shared secret in a header or query parameter | simple service-to-service, internal APIs | [Security](./security) |
| HTTP Basic | RFC 7617 username/password | legacy clients, quick prototypes | [Security](./security) |
| JWT (JWKS) | a Bearer token verified against a JWKS endpoint | stateless auth, OAuth2 resource servers | [Security](./security) |
| mTLS client cert | a verified client certificate mapped to a consumer | zero-trust internal mesh, high-assurance | [OAuth2 and mTLS](./oauth2-mtls) |
| HMAC request signing | per-request HMAC-SHA256 over a canonical request | machine-to-machine integrity, replay protection | [HMAC signing](./hmac-signing) |
| OIDC | Bearer introspection (RFC 7662) or browser login + PKCE | user-facing apps, delegated access | [OpenID Connect](./oidc) |

## Choosing a method

- **Service-to-service, internal**: an API key is the simplest. Add
  HMAC request signing when you need per-request integrity and replay
  protection without a shared bearer token.
- **Stateless, externally issued tokens**: JWT via JWKS. The gateway
  fetches and caches the JWKS, verifies the signature and claims, and
  maps the token to a consumer. No shared secret with the issuer.
- **High-assurance internal**: mTLS client certificates. Each client
  presents a cert; the gateway maps the cert's subject or SPIFFE ID to
  a consumer. No credential in the request body at all.
- **User-facing applications**: OIDC. The gateway acts as a relying
  party (authorization-code + PKCE) for browser login, or introspects
  a Bearer token via RFC 7662 for API access.

A single consumer can hold multiple credential families, so you can
migrate methods without reissuing identity -- add the new family,
shift traffic, then remove the old.

## Upstream authentication

Separately from consumer authn, the gateway can authenticate *itself*
to an upstream as an OAuth2 client-credentials client, or present an
mTLS client certificate. That is upstream authn, not consumer authn;
see [OAuth2 and mTLS](./oauth2-mtls).

## Where to go next

- [Authorization rules](./authorization) - the *what may this caller
  do* layer that runs after authentication.
- [Secrets and references](./secrets) - the `${...}` form that keeps
  credential material out of config files.
- [Concepts: identity and access](./concepts#identity-and-access) -
  the consumer and credential model.
