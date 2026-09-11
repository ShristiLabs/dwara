# Request and response control

The application-level shaping that runs once a route has matched: how
Dwara adjusts the request before it reaches the upstream and the
response before it reaches the client. Each of these is a single
optional block on the route itself -- they are not policy
attachments.

## In this section

- [CORS](./cors) - cross-origin policy with preflight handling.
- [Compression](./compression) - response body compression at the
  edge.
- [Request limits and validation](./request-limits) - request size
  and header count limits, plus JSON Schema body validation.
- [Transforms](./transforms) - RFC 6901 JSON pointer-based request
  and response transforms over headers, query, and JSON bodies.
- [Security headers](./security-headers) - the security headers
  block (HSTS, X-Content-Type-Options, CSP, and friends).
- [Response field masking](./masking) - fail-closed, per-consumer-group
  redaction of response fields so secrets never leak to callers who
  should not see them.
- [Response caching](./caching) - local TTL/ETag/stale-while-revalidate
  caching with cache keys and invalidation. Distributed cache (Redis)
  is an enterprise feature; see
  [Distributed cache](./distributed-cache).
- [API versioning](./api-versioning) - path, header, query, and
  Accept-header versioning with HTTP-date Deprecation and Sunset
  signaling.

These features run inside the shared request pipeline -- see
[Filter-chain ordering](./filter-chain-ordering) for the phase order
all of them participate in and how to override it.

## Runnable demo

The [`demos/05-request-response/`](https://github.com/shristilabs/dwara/tree/main/demos/05-request-response) directory in the repository runs a
live stack for the features in this section; its README covers
prerequisites, test scripts, and teardown.

## Where to go next

- [Protocol translation and API management](./protocol-translation) -
  cross-protocol bridging and API composition, which also shape what
  a client sees.
- [Traffic policy and resilience](./traffic-policy) - the protective
  layer that runs alongside shaping.
