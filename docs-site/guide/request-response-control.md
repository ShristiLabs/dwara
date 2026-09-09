# Request and response control

The application-level shaping that runs once a route has matched: how
Dwara adjusts the request before it reaches the upstream and the
response before it reaches the client. Each of these is a single
optional block on the route itself -- they are not policy
attachments.

## In this section

- [CORS, compression, and request limits](./edge-policies) - the
  edge-level controls: cross-origin policy, body compression, and
  request size and header count limits.
- [Transforms and security headers](./transforms) - RFC 6901 JSON
  pointer-based request and response transforms, plus the security
  headers block (HSTS, X-Content-Type-Options, CSP, and friends).
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

## Where to go next

- [Protocol translation and API management](./protocol-translation) -
  cross-protocol bridging and API composition, which also shape what
  a client sees.
- [Traffic policy and resilience](./traffic-policy) - the protective
  layer that runs alongside shaping.
