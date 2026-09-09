# CORS

[CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS) (Cross-Origin Resource Sharing) is how browsers allow a page on one
origin to call an API on another. The gateway answers the browser's
preflight checks itself and decorates actual responses with the right
`Access-Control-*` headers, so a web app served from a different
origin can call your routes without the browser blocking the
response.

CORS is configured per route with a `cors` block and is off by
default. The block is a plain part of the route (exactly one per
route), not a reusable `policies` attachment like
[retries](./retries) or [rate limiting](./rate-limiting) -- the same
holds for its sibling edge blocks, [compression](./compression) and
[request limits](./request-limits). For the exhaustive field list see
the [configuration schema](../reference/configuration-schema).

## When to use this

Any route called from browser JavaScript on a different origin needs
a `cors` block -- without one the browser blocks the response.
Typical cases are a SPA frontend calling its API, embedded widgets,
and any web client you do not serve from the same origin as the API.
Server-to-server clients do not enforce CORS, so they never trigger
preflights or require these headers.

## Configuration

```yaml
routes:
  - name: api
    service: api-service
    match:
      path:
        type: prefix
        value: /api/
      methods: [GET, POST, PUT, DELETE, OPTIONS]
    action:
      type: proxy
    cors:
      allowed_origins:
        - https://app.example.com
      allowed_methods: [GET, POST, PUT, DELETE]
      allowed_headers: [content-type, x-api-key]
      expose_headers: [x-request-id]
      allow_credentials: true
      max_age_secs: 600
```

| Field | Default | Description |
|---|---|---|
| `allowed_origins` | none | Origins allowed to call the route. Matched exactly after normalization (see [origin matching](#origin-matching)); subdomains are not matched implicitly. The single entry `*` allows any origin. |
| `allowed_methods` | none | Methods the policy allows; checked against a preflight's `Access-Control-Request-Method`. |
| `allowed_headers` | none | Request headers the policy allows; checked against the headers a preflight requests. |
| `expose_headers` | none | Response headers the browser is allowed to read; sent as `Access-Control-Expose-Headers` on actual responses. |
| `allow_credentials` | `false` | Sends `Access-Control-Allow-Credentials: true` on actual responses when enabled. Validation rejects combining `*` (origins or headers) with `true`. |
| `max_age_secs` | none | How long the browser may cache the preflight response (`Access-Control-Max-Age`). |

**[Preflight](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS#preflighted_requests)
requests (a browser's pre-flight OPTIONS check before the real
request) need `OPTIONS` in `match.methods`.** The method list is part
of route matching, which runs before any CORS logic -- a route whose
method list excludes `OPTIONS` never matches a preflight and the
browser gets a 404.

## How it works

With a `cors` block on the matched route:

1. **Preflights** (`OPTIONS` carrying `Origin` and
   `Access-Control-Request-Method`) are answered by the gateway
   itself with `204` -- never forwarded to the upstream, and not
   subject to authentication or rate limiting (browsers send
   preflights without credentials). A preflight the policy rejects
   -- origin, method, or requested header not allowed -- is still
   answered `204`, but with no CORS headers, which the browser
   reports as a failed preflight.
2. **A plain `OPTIONS`** without the preflight markers is not
   intercepted; it proxies like any other request.
3. **Actual responses** on the route carry
   `Access-Control-Allow-Origin` (the echoed request origin, or `*`
   under a wildcard policy), `Access-Control-Allow-Credentials: true`
   when configured, `Access-Control-Expose-Headers` when configured,
   and [`Vary: Origin`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Vary)
   (tells caches to key on the Origin header). Requests whose
   `Origin` is not allowed get no CORS headers -- the response
   passes through unchanged.

## Origin matching

Origins match exactly, after normalization: scheme and host are
compared case-insensitively and a default port (`:443` on https,
`:80` on http) may be omitted. `https://APP.Example.com:443` and
`https://app.example.com` are the same origin. Origins with userinfo
(`https://user@example.com`) are rejected -- browsers never send
them. Subdomains are NOT matched implicitly -- list each origin. The
single entry `*` allows any origin, but validation rejects combining
`*` (origins or headers) with `allow_credentials: true`, per the
[Fetch spec](https://fetch.spec.whatwg.org/).

## Errors without CORS headers

One debugging note: responses the gateway generates itself before
the route's action runs -- a 401 from authentication, a 429 from
rate limiting, a 413/431 from [request limits](./request-limits) --
do not carry CORS headers. A browser may then show a generic
network/CORS error for what is really an auth or limit rejection;
check the gateway's access log for the real status.

## gRPC-Web routes

gRPC-Web routes have their own CORS variant: the `cors` block inside
`grpc_web` is the same shape as this route-level config but is
scoped to the gRPC-Web handshake, so preflight responses carry the
right `Access-Control-Allow-Headers` for gRPC-Web automatically. See
[gRPC-Web](./grpc-web).

## Pipeline order and reload

For a matched request the stages run in a fixed order: route limits,
then CORS preflight handling, then authentication, authorization,
rate limiting, and admission, then the route's action, and finally
the response gains [compression](./compression) and CORS headers. See
the [request pipeline](../architecture/overview#request-pipeline)
for the full picture. The `cors` block reloads live with the rest of
the config -- an atomic snapshot swap, no restart.

## Runnable demo

Run CORS against a live gateway: `demos/05-request-response/` (test
script: `test-05-cors.sh`) in the repository. The script sends an
`OPTIONS` preflight with an `Origin` and an
`Access-Control-Request-Method`, then asserts the
`Access-Control-Allow-Origin` headers come back. The category README
covers prerequisites and teardown.
