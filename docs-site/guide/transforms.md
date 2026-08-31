# Transforms and security headers

Dwara can rewrite the headers, query string, and JSON bodies crossing
a route, and stamp standard security headers on every response it
emits — configured as two optional blocks on the route. Both are
off by default: a route without them forwards traffic untouched.

## When to use this

Transforms shape what the upstream sees (injecting headers, dropping consumer identity) and what the client sees (rewriting response JSON, stamping security headers). Use them when an upstream needs a header the client does not send, when consumer identity must be stripped before the upstream, or when every response from a route should carry standard security hardening. Both transform blocks are off by default.

```yaml
routes:
  - name: api
    service: api-service
    match:
      path:
        type: prefix
        value: /api/
    transforms:
      request:
        headers:
          set:
            X-Gateway: dwara
          remove:
            - X-Consumer-Id
        query:
          add:
            source: gateway
        body:
          json:
            max_bytes: 65536
            ops:
              - op: set
                path: /meta/via
                value: dwara
      response:
        body:
          json:
            max_bytes: 131072
            ops:
              - op: remove
                path: /internal
    security_headers:
      hsts_max_age_secs: 31536000
      hsts_include_subdomains: true
      nosniff: true
      frame_options: sameorigin
      content_security_policy: default-src 'none'
```

## Streaming is preserved

Dwara proxies end-to-end without buffering. Header, query, and
security-header operations never touch a body: Server-Sent Events,
WebSocket upgrades, and large downloads pass through a transformed
route exactly as through an untransformed one. The single exception is
the JSON body transform below — it is the one operation that buffers,
and only up to the `max_bytes` you give it.

## Header operations

`request.headers` and `response.headers` each take four maps, applied
in one fixed order regardless of how you order them in YAML:

1. `set` — replace every value of the header with one value (inserts
   it if absent)
2. `add` — append one value, keeping any existing values
3. `rename` — move every value of the key onto the new name
4. `remove` — drop every value of the header

On the request side the operations run after Dwara adds its own
`X-Forwarded-*` and consumer-identity headers, so you can `remove` or
`rename` those — useful when an upstream must not see consumer
identity. Some names are never yours to set: framing headers (headers that describe the body's boundaries, like Content-Length) and [hop-by-hop headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers#hop-by-hop_headers) (headers meant for one connection, not forwarded)
(`content-length`, `transfer-encoding`, `connection`,
`keep-alive`, `te`, `trailer`, `upgrade`, `proxy-connection`,
`proxy-authenticate`, `proxy-authorization`) are rejected by
validation in both directions, plus `host` on requests (Dwara names
the origin it dials) and `content-encoding` on responses (the
[compression pipeline](./edge-policies) owns it). This is a
[request-smuggling](https://owasp.org/www-community/attacks/HTTP_Request_Smuggling) (an attack that desyncs how two proxies parse a request) guard, not a convenience: a config that forced a
framing header disagreeing with the actual body would corrupt the hop.

Response header operations apply to upstream answers (and `respond` /
`redirect` actions), not to Dwara's own error responses — those are
covered by security headers below.

## Query operations

`request.query` takes the same four maps, applied to the forwarded
query string. Untouched parameters survive byte-for-byte — including
their exact percent-encoding — and only parameters an operation names
are re-encoded. `set` replaces every occurrence of a key with one pair
at the end of the query; `rename` relabels pairs in place; `add`
appends; `remove` drops every occurrence. The request path itself is
changed by the route's `rewrite`, not here.

## JSON body transforms

`request.body.json` and `response.body.json` apply a list of
[RFC 6901](https://www.rfc-editor.org/rfc/rfc6901) JSON pointer (a string syntax for pointing at a field inside a JSON document) operations,
in order, to JSON bodies:

- `op: set` writes any JSON value at `path` (an empty path `""`
  replaces the whole document)
- `op: remove` deletes the value at `path` (the root path is not
  valid for remove)

The transform engages only when the body declares a JSON content type
(`application/json` and `application/*+json`; parameters ignored) and
carries no `Content-Encoding`. Anything else — non-JSON bodies, empty
bodies, already-compressed bodies — passes through untouched. When it
does engage, the body is buffered up to `max_bytes` and the forwarded
`Content-Length` is rewritten to the transformed length.

Failures are deliberate and closed, never a silent skip:

| What happened | Request body | Response body |
| --- | --- | --- |
| body larger than `max_bytes` | `413` | `502` |
| body is not valid JSON | `400` | `502` |
| a pointer does not resolve in the document | `400` | `502` |

An unresolved pointer is treated as a contract violation on purpose:
in the redaction direction (remove the secret field), silently
skipping a miss would be exactly the leak the transform was written to
prevent. On the request side, retries replay the transformed bytes,
and authentication that signs the body (see [HMAC signing](./hmac-signing))
still verifies against the client's original bytes before the
transform runs.

`max_bytes` must be at least 1 and has no upper bound — it is your
route's memory budget, like the route's [request
limits](./edge-policies). Both body transforms log the offending
pointer server-side; the client error stays generic.

## Security headers

The `security_headers` block stamps standard hardening headers on
EVERY response the route emits — including Dwara's own 401/403/413/
429/503 answers and CORS preflights, not just upstream responses —
replacing any value the upstream sent: at its edge, the gateway is the
source of truth. (The two responses emitted before a route is matched
— the framing `400` and the unrouted `404` — carry none.)

| Field | Header emitted |
| --- | --- |
| `hsts_max_age_secs: <n>` | [Strict-Transport-Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security): max-age=`<n>` (RFC 6797) |
| `hsts_include_subdomains: true` | appends `; includeSubDomains` to HSTS |
| `hsts_preload: true` | appends `; preload` to HSTS |
| `nosniff: true` | [X-Content-Type-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options): nosniff |
| `content_security_policy: <policy>` | [Content-Security-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP): `<policy>` verbatim |
| `frame_options: deny \| sameorigin` | [X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options): DENY / `SAMEORIGIN` |

Validation rules: the block must enable at least one header (omit the
block to disable injection); `hsts_max_age_secs` must be non-zero
(`max-age=0` is the spec's "delete this policy" signal — delete the
field instead); `hsts_include_subdomains` and `hsts_preload` require
`hsts_max_age_secs`; `hsts_preload` additionally requires
`hsts_include_subdomains` (the [HSTS](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security) preload list rejects entries
without it); `content_security_policy` must be non-empty.

## Where transforms run

Order matters when combining features. Request transforms run after
routing, authentication, and rate limiting — every policy evaluated
the request the client sent; transforms shape what the upstream
receives. Response transforms run after [field
masking](./masking) (a transform sees — and may rewrite or remove —
the `"***"` sentinel masking left) and before
[compression](./edge-policies) (a body transform rewrites the bytes
compression then encodes) and
before [versioning stamps](./api-versioning); security headers apply
last, so the edge policy has the final word.

Validation follows the standard [config pipeline](./configuration): a
rejected config never replaces the running one, empty transform blocks
are rejected as authoring mistakes, and every issue is reported at
once. The exhaustive field list is the generated [configuration
schema](../reference/configuration-schema).
