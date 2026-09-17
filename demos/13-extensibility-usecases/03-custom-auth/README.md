# Demo 03: custom request authentication

The
[custom-auth recipe](../../../docs-site/guide/use-cases/custom-request-auth.md):
a proprietary token scheme (not JWT, not API keys) must be verified
per request. The demo builds the SHIPPED
[`static-auth`](../../../../plugins/examples/static-auth)
example plugin by path -- constant-time compare, 401 with a
`WWW-Authenticate` challenge short-circuited from the plugin itself
(`send_http_response`; the upstream is never dialed) -- and runs it
against a mock protected upstream.

## What runs

- `protected-upstream.py` -- an echo backend (so the demo proves
  authenticated traffic actually reached it)
- `dwara.yaml` -- `/protected/*` with the plugin
  (`Bearer dwara-demo-secret`) and the sibling plugin-less `/public/*`
  control route.

## What test.sh asserts

1. missing credential -> 401 + `WWW-Authenticate: Bearer realm=...`
2. wrong token -> 401
3. wrong scheme (Basic when Bearer is configured) -> 401
4. correct token -> 200 + the upstream's echo body
5. the sibling unprotected route serves with no credential throughout

## Run

```sh
./test.sh          # builds plugins/examples/static-auth by path,
                   # starts the upstream + gateway, asserts
```

Ports: gateway 18221, protected upstream 18222.

## Notes

Check the built-ins first (API keys, JWT/JWKS, HMAC, OIDC cover the
standard schemes with zero code); a plugin is for schemes only you
speak. Secret rotation here is a plugin-config reload -- never bake
long-lived secrets into the module.
