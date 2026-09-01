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

- [Secrets](./secrets) - inline values vs. resolvable references, and
  the redaction model that keeps secrets out of logs and admin output.
- [HMAC request signing](./hmac-signing) - a credential family for
  machine-to-machine request integrity instead of a static shared key.
- [OAuth2 and mTLS](./oauth2-mtls) - the gateway as an OAuth2
  client-credentials client to an upstream, and mTLS certificate-to-
  consumer mapping.
- [OpenID Connect](./oidc) - Bearer-token introspection (RFC 7662), the
  authorization-code + PKCE relying-party flow, and token exchange.
- [Authorization rules](./authorization) - the built-in allow/deny
  model: consumers, groups, JWT scopes and claims, IP ACLs, and GeoIP
  gates at five precedence levels.
- [Cedar and OPA authorization](./cedar-opa-authz) - delegating
  authorization decisions to external policy engines.
