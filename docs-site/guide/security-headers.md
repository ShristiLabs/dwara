# Security headers

The `security_headers` block stamps standard hardening headers --
[Strict-Transport-Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security),
`X-Content-Type-Options`, `Content-Security-Policy`, and
`X-Frame-Options` -- on every response a route emits, replacing any
value the upstream sent. At its edge, the gateway is the source of
truth: one route-level block enforces a consistent hardening policy
even when the upstreams behind a service disagree.

The block is off by default -- a route without it forwards upstream
headers untouched. To rewrite headers, query strings, or JSON bodies
instead, see [Transforms](./transforms).

## When to use this

Use security headers when every response from a route should carry
standard security hardening -- not just upstream answers, but also
Dwara's own error responses and CORS preflights. Response [header
transforms](./transforms) cannot do this job: they apply only to
upstream answers (and `respond` / `redirect` actions), so the
`security_headers` block is the one way to harden every response a
route can emit.

## Configuration

Security headers are configured per-route, inside the
`security_headers` block:

```yaml
routes:
  - name: api
    service: api-service
    match:
      path:
        type: prefix
        value: /api/
    security_headers:
      hsts_max_age_secs: 31536000
      hsts_include_subdomains: true
      nosniff: true
      frame_options: sameorigin
      content_security_policy: default-src 'none'
```

| Field | Default | Description |
|---|---|---|
| `hsts_max_age_secs` | unset | Emits [Strict-Transport-Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security): max-age=`<n>` (RFC 6797). Must be non-zero. |
| `hsts_include_subdomains` | unset | Appends `; includeSubDomains` to HSTS. Requires `hsts_max_age_secs`. |
| `hsts_preload` | unset | Appends `; preload` to HSTS. Requires `hsts_max_age_secs` and `hsts_include_subdomains`. |
| `nosniff` | unset | Emits [X-Content-Type-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options): nosniff. |
| `content_security_policy` | unset | Emits [Content-Security-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP): `<policy>` verbatim. Must be non-empty. |
| `frame_options` | unset | Emits [X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options): `DENY` or `SAMEORIGIN`; set to `deny` or `sameorigin`. |

## How it works

The block stamps headers on EVERY response the route emits --
including Dwara's own `401`/`403`/`413`/`429`/`503` answers and
[CORS](./cors) preflights, not just upstream responses -- replacing
any value the upstream sent: at its edge, the gateway is the source
of truth. The two responses emitted before a route is matched -- the
framing `400` and the unrouted `404` -- carry none.

Stamping runs last in the response pipeline -- after response
[transforms](./transforms), [field masking](./masking),
[compression](./compression), and [versioning
stamps](./api-versioning) -- so the edge policy has the final word
on every response.

The block never touches a body: Server-Sent Events, WebSocket
upgrades, and large downloads pass a hardened route exactly as
through an unhardened one.

## Validation

- The block must enable at least one header (omit the block to
  disable injection).
- `hsts_max_age_secs` must be non-zero (`max-age=0` is the spec's
  "delete this policy" signal -- delete the field instead).
- `hsts_include_subdomains` and `hsts_preload` require
  `hsts_max_age_secs`; `hsts_preload` additionally requires
  `hsts_include_subdomains` (the [HSTS](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security)
  preload list rejects entries without it).
- `content_security_policy` must be non-empty.

Validation follows the standard [config pipeline](./configuration):
a rejected config never replaces the running one, and every issue is
reported at once. The exhaustive field list is the generated
[configuration schema](../reference/configuration-schema).
