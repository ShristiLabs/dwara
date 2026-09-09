# Security and authentication

How callers prove who they are to the gateway, and how the gateway
proves who it is to upstreams. Dwara authenticates consumers with API
keys, Basic, JWT (JWKS), mTLS client certificates, or HMAC request
signing, and can itself obtain OAuth2 tokens or act as an OIDC relying
party for upstream and browser flows.

Credential and secret material is never logged; see [Secrets](./secrets)
for the reference-based secret resolution that keeps secret bytes out of
your config files entirely.

## In this section

- [Authentication methods](./authentication-methods) - quick-reference
  for choosing among API key, Basic, JWT/JWKS, mTLS, HMAC, and OIDC.
- [Secrets](./secrets) - inline values vs. resolvable references, and
  the redaction model that keeps secrets out of logs and admin output.
- [HMAC request signing](./hmac-signing) - a credential family for
  machine-to-machine request integrity instead of a static shared key.
- [OAuth2](./oauth2) - the gateway as an OAuth2 client-credentials
  client to an upstream: token fetch, caching, and refresh.
- [mTLS](./mtls) - mTLS consumer mapping at the listener and upstream
  mTLS client certificates.
- [OpenID Connect](./oidc) - Bearer-token introspection (RFC 7662), the
  authorization-code + PKCE relying-party flow, token exchange, and
  per-route browser login.
- [Authorization rules](./authorization) - the built-in allow/deny
  model: consumers, groups, JWT scopes and claims, IP ACLs, and GeoIP
  gates at five precedence levels.
- [Cedar authorization](./cedar-authz) - delegating authorization
  decisions to the in-process Cedar policy engine.
- [OPA authorization](./opa-authz) - delegating authorization
  decisions to an OPA policy server over Rego policies.
- [ACME certificate automation](./acme) - automated TLS certificate
  issuance and renewal from Let's Encrypt and other ACME-compatible
  certificate authorities.
- [Post-quantum TLS](./post-quantum-tls) - hybrid key exchange for
  forward secrecy against future quantum attacks.
- [FIPS mode](./fips-mode) - FIPS 140-3 validated cryptography.
